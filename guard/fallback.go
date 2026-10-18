package guard

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/tacyhq/tacy/harness"
	"github.com/tacyhq/tacy/proto"
	"github.com/tacyhq/tacy/vault"
)

// Slow and overloaded models (docs/27; approved 2026-10-18). A model call that gets no first token (reasoning,
// text or a tool call) within SlowThreshold, or that the provider answers 503, 429 or "overloaded", is slow: people
// see model_slow. On Auto (RunRequest.AutoFallback) the call is given up and the step runs again, once, on the
// first fallback the policy and this guard allow (model_switched); the run's later steps go straight to it. A
// hand-picked model is waited for when slow, and ends the run with CodeModelOverloaded when overloaded. Billing is
// unchanged: the relay charges the run's X-Agent-Model whatever model answered.

// DefaultSlowAfter is the base of SlowThreshold: the chat's own first-token wait.
const DefaultSlowAfter = 20 * time.Second

// maxSlowAfter caps SlowThreshold, as the chat does.
const maxSlowAfter = 120 * time.Second

// MaxFallbacks caps a run's fallback models (RunRequest.FallbackModels).
const MaxFallbacks = 5

// CodeModelOverloaded is proto.Event.Code when a hand-picked model was overloaded (the provider's side).
const CodeModelOverloaded = "model_overloaded"

// SlowThreshold is how long a model call may go without a first token, scaled by the request body's size exactly
// as the chat scales it: base, plus a second for every 32 KiB (or part) past 64 KiB, at most 120 s.
func SlowThreshold(base time.Duration, bytes int) time.Duration {
	extra := 0
	if over := bytes - 64<<10; over > 0 {
		extra = (over + 32<<10 - 1) / (32 << 10)
	}
	return min(maxSlowAfter, base+time.Duration(extra)*time.Second)
}

// StatusError is an upstream's non-200 answer: its status and the error message it gave (capped). The message is
// the provider's text: it may go into a run's error for most statuses (as before), never for an overloaded one.
type StatusError struct {
	Status int
	Msg    string
}

func (e *StatusError) Error() string { return fmt.Sprintf("model returned %d: %s", e.Status, e.Msg) }

// errOverloadedStream: the provider said "overloaded" inside the stream, before any token.
var errOverloadedStream = errors.New("model stream: overloaded")

// overloaded: the upstream answered 503 or 429, or its error says "overloaded".
func overloaded(err error) bool {
	if errors.Is(err, errOverloadedStream) {
		return true
	}
	var se *StatusError
	return errors.As(err, &se) && (se.Status == 503 || se.Status == 429 || strings.Contains(strings.ToLower(se.Msg), "overloaded"))
}

// OverloadedText is what people read when a hand-picked model is overloaded: our words, never the provider's.
func OverloadedText(model string) string {
	return model + " is overloaded at the moment. This is on the model provider's side (Tinfoil). Try again in a minute or pick another model."
}

// overloadedError is the harness error for it: "model_overloaded: <OverloadedText>" (agentd's safety checks turn the
// prefix into the error event's code, app/safety.go).
func overloadedError(model string) error {
	return harness.Errf(harness.CodeInternal, "%s: %s", CodeModelOverloaded, OverloadedText(model))
}

// fallbackModels keeps the fallbacks this guard runs, in the order given: not the run's model, no duplicates, at
// most MaxFallbacks. The rest are dropped silently.
func fallbackModels(model string, in []string) []string {
	var out []string
	for _, m := range in {
		if len(out) == MaxFallbacks {
			break
		}
		if _, ok := models[m]; !ok || m == model || slices.Contains(out, m) {
			continue
		}
		out = append(out, m)
	}
	return out
}

// effortFor is effort if model accepts it, else "" (the model's own default).
func effortFor(model, effort string) string {
	if effort != "" && slices.Contains(models[model], effort) {
		return effort
	}
	return ""
}

// modelAllowed: this guard runs m and the signed policy allows it in space now.
func (g *Guard) modelAllowed(space, m string) bool {
	_, ok := models[m]
	return ok && g.checkSafety(space, &harness.ModelCall{Model: m}) == nil
}

// route is the model a call for asked goes to (the model the task switched to, if it did and it is still
// allowed), and the fallback it may switch to if that one is slow ("" when none: not on Auto, switched already,
// or no allowed fallback).
func (g *Guard) route(t *task, asked string) (model, fallback string) {
	t.mu.Lock()
	switched := t.switched
	t.mu.Unlock()
	if switched != "" {
		if switched != asked && g.modelAllowed(t.opts.Space, switched) {
			return switched, ""
		}
		return asked, ""
	}
	if !t.opts.AutoFallback {
		return asked, ""
	}
	for _, fb := range t.opts.Fallbacks {
		if fb != asked && g.modelAllowed(t.opts.Space, fb) {
			return asked, fb
		}
	}
	return asked, ""
}

// attempt is one try of a step's model call.
type attempt struct {
	res     *stepResult // with the leased key redacted
	err     error
	abandon string // "": not given up; "abandoned_slow" | "overloaded": given up for the fallback
}

var errAbandoned = errors.New("model call given up as slow")

// try makes one streamed model call for step. Without a first token by the slow threshold it emits model_slow;
// with a fallback it then gives the call up (cancels it: nothing more of it is shown) and says so (abandon),
// without one it keeps waiting. An overloaded answer before any token is model_slow too, then abandon with a
// fallback, or overloadedError without. onDelta gets each delta (after the first token) with the stream's leased
// secrets.
func (g *Guard) try(ctx context.Context, t *task, step int, model string, raw []byte, fallback string,
	onDelta func(kind, delta string, leased []*vault.Secret) error) attempt {
	callCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	t0 := time.Now()
	var mu sync.Mutex
	first, said, abandoned, over := false, false, false, false
	slow := func(waited time.Duration) { // under mu
		if !said {
			said = true
			t.emit(proto.Event{Type: "model_slow", Step: step, Model: model, WaitedMs: waited.Milliseconds(), Fallback: fallback})
		}
	}
	base := g.cfg.SlowAfter
	if base <= 0 {
		base = DefaultSlowAfter
	}
	timer := time.AfterFunc(SlowThreshold(base, len(raw)), func() {
		mu.Lock()
		defer mu.Unlock()
		if first || abandoned || over || ctx.Err() != nil {
			return
		}
		slow(time.Since(t0))
		if fallback != "" {
			abandoned = true
			cancel()
		}
	})
	defer func() { // a timer firing as the call ends says nothing
		timer.Stop()
		mu.Lock()
		over = true
		mu.Unlock()
	}()
	gaveUp := func() bool {
		mu.Lock()
		defer mu.Unlock()
		return abandoned
	}
	// overloadedEnd: an overloaded answer before any token.
	overloadedEnd := func(err error) attempt {
		mu.Lock()
		defer mu.Unlock()
		if first || ctx.Err() != nil {
			return attempt{err: err}
		}
		slow(time.Since(t0))
		abandoned = true // no slow event after this
		if fallback != "" {
			return attempt{abandon: "overloaded"}
		}
		return attempt{err: overloadedError(model)}
	}
	stream, err := g.cfg.Up.Stream(callCtx, raw)
	if err != nil {
		switch {
		case gaveUp():
			return attempt{abandon: "abandoned_slow"}
		case overloaded(err) && ctx.Err() == nil:
			return overloadedEnd(err)
		}
		return attempt{err: err}
	}
	defer stream.Close()
	leased := leasedOf(stream)
	res, err := readStream(stream, func(kind, delta string) error {
		mu.Lock()
		if abandoned {
			mu.Unlock()
			return errAbandoned
		}
		first = true
		mu.Unlock()
		return onDelta(kind, delta, leased)
	})
	switch {
	case gaveUp() && (err != nil || res == nil || res.firstAt.IsZero()):
		// Given up before a token: whatever the stream did after that, nothing of it was shown.
		return attempt{abandon: "abandoned_slow"}
	case err != nil && errors.Is(err, errOverloadedStream) && ctx.Err() == nil:
		return overloadedEnd(err)
	case err != nil:
		return attempt{err: err}
	}
	// The key this call was made with never comes back out, in any encoding, in the whole message the brain
	// gets either (a key split across deltas is caught here). Before Close, which wipes it.
	if leased != nil {
		res.text = string(exactRedact([]byte(res.text), leased))
		res.reasoning = string(exactRedact([]byte(res.reasoning), leased))
		for i := range res.calls {
			res.calls[i].Function.Arguments = string(exactRedact([]byte(res.calls[i].Function.Arguments), leased))
		}
	}
	return attempt{res: res}
}

// ---- e2e only: fake slow and overloaded models ----------------------------------------------------------------

// Model faults (gatewayd's -e2e-model-fault, set only by cmd/e2e's overlay): calls to a faulted model are slow
// (nothing before the slow threshold has passed by 10 s; then the real call) or overloaded (503 at once, no
// request made). The flag is on the command line, which the attested compose hash covers, so a release can't have
// it on without the verifier seeing another compose.
const (
	FaultSlow       = "slow"
	FaultOverloaded = "overloaded"
)

// ParseModelFaults reads "model=slow|overloaded,..." (known models only).
func ParseModelFaults(s string) (map[string]string, error) {
	out := map[string]string{}
	for _, f := range strings.Split(s, ",") {
		if f = strings.TrimSpace(f); f == "" {
			continue
		}
		m, kind, ok := strings.Cut(f, "=")
		if _, known := models[m]; !ok || !known || kind != FaultSlow && kind != FaultOverloaded {
			return nil, fmt.Errorf("model fault %q: want <model>=slow|overloaded with a known model", f)
		}
		out[m] = kind
	}
	return out, nil
}

// WithModelFaults wraps up with faults (ParseModelFaults); none: up itself.
func WithModelFaults(up Upstream, faults map[string]string) Upstream {
	if len(faults) == 0 {
		return up
	}
	return &faultUpstream{Upstream: up, faults: faults}
}

type faultUpstream struct {
	Upstream
	faults map[string]string
}

func (f *faultUpstream) Stream(ctx context.Context, body []byte) (io.ReadCloser, error) {
	var b struct {
		Model string `json:"model"`
	}
	json.Unmarshal(body, &b)
	switch f.faults[b.Model] {
	case FaultOverloaded:
		return nil, &StatusError{Status: 503, Msg: "e2e fault: model is overloaded. Retry after 60 seconds."}
	case FaultSlow:
		select {
		case <-time.After(SlowThreshold(DefaultSlowAfter, len(body)) + 10*time.Second):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return f.Upstream.Stream(ctx, body)
}
