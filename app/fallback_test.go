package main

import (
	"context"
	"encoding/json"
	"io"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/tacyhq/tacy/guard"
	"github.com/tacyhq/tacy/proto"
	"github.com/tacyhq/tacy/safety"
)

// Slow and overloaded models in agentd (guard/fallback.go): the policy drops fallbacks it doesn't allow, the start
// record lists the models the run may call, the given-up call is on the record, and a hand-picked overloaded model
// ends the run with code model_overloaded and our words.

// faultyUp: calls to slow models wait until cancelled; calls to overloaded ones answer 503 with the provider's text.
type faultyUp struct {
	guard.Upstream
	slow, overloaded []string
}

func (f *faultyUp) Stream(ctx context.Context, body []byte) (io.ReadCloser, error) {
	var b struct {
		Model string `json:"model"`
	}
	json.Unmarshal(body, &b)
	switch {
	case slices.Contains(f.slow, b.Model):
		<-ctx.Done()
		return nil, ctx.Err()
	case slices.Contains(f.overloaded, b.Model):
		return nil, &guard.StatusError{Status: 503, Msg: "Model is overloaded. Retry after 60 seconds."}
	}
	return f.Upstream.Stream(ctx, body)
}

func newFaultEnv(t *testing.T, f *faultyUp, replies ...string) *safeEnv {
	return newSafeEnvWith(t, safeOpts{slowAfter: 80 * time.Millisecond,
		wrapUp: func(u guard.Upstream) guard.Upstream { f.Upstream = u; return f }}, replies...)
}

func TestFallbackPolicyRecordAndMetrics(t *testing.T) {
	e := newFaultEnv(t, &faultyUp{slow: []string{"deepseek-v4-1-flash"}}, pText("Hi."))
	// The policy allows the run's model and gpt-oss-120b, not kimi-k3.
	e.mustPost(e.policy(1, func(p *safety.Policy) { p.Models = []string{"deepseek-v4-1-flash", "gpt-oss-120b", "glm-5-3"} }), e.heartbeat())
	priv, _ := recipientKey(t)
	key := e.rec.Signer.Public()
	evs := runParity(t, e.s, e.recorded(priv, proto.RunRequest{Permissions: guard.AllowAll(), Model: "deepseek-v4-1-flash",
		ReasoningEffort: "none", Tools: []string{}, AutoFallback: true,
		FallbackModels: []string{"kimi-k3", "nope", "deepseek-v4-1-flash", "gpt-oss-120b", "glm-5-3"}, Messages: user1("hi")}))
	if evs[len(evs)-1].Type != "done" {
		t.Fatalf("events %s", types(evs))
	}
	var slow, sw *proto.Event
	var ms []proto.Metric
	for i, ev := range evs {
		switch ev.Type {
		case "model_slow":
			slow = &evs[i]
		case "model_switched":
			sw = &evs[i]
		case "metrics":
			if ev.Metrics.Kind == "model" {
				ms = append(ms, *ev.Metrics)
			}
		}
	}
	if slow == nil || slow.Fallback != "gpt-oss-120b" || sw == nil || sw.From != "deepseek-v4-1-flash" || sw.To != "gpt-oss-120b" {
		t.Fatalf("events %s: slow %+v switched %+v", types(evs), slow, sw)
	}
	if len(ms) != 2 || ms[0].Outcome != "slow_switched" || ms[0].Model != "deepseek-v4-1-flash" || ms[1].Model != "gpt-oss-120b" || ms[1].Outcome != "ok" {
		t.Fatalf("metrics %+v", ms)
	}
	runs := openedActivity(t, evs, priv, key)
	if len(runs) != 2 {
		t.Fatalf("%d records", len(runs))
	}
	if want := []string{"deepseek-v4-1-flash", "gpt-oss-120b", "glm-5-3"}; !slices.Equal(runs[0].Models, want) {
		t.Fatalf("start record's models %v, want %v", runs[0].Models, want)
	}
	calls := runs[1].Calls
	if len(calls) != 2 {
		t.Fatalf("calls %+v", calls)
	}
	a, b := calls[0], calls[1]
	if a.Kind != "model" || a.Name != "deepseek-v4-1-flash" || a.Outcome != "abandoned_slow" || a.Ms < 80 || a.Prompt != 0 || a.Completion != 0 {
		t.Fatalf("given-up call %+v", a)
	}
	if b.Kind != "model" || b.Name != "gpt-oss-120b" || b.Outcome != "ok" || b.Prompt == 0 || b.ID != a.ID || b.AtMs < a.AtMs+a.Ms {
		t.Fatalf("the call that answered %+v (given up %+v)", b, a)
	}
	if runs[1].Status.State != "succeeded" {
		t.Fatalf("end %+v", runs[1].Status)
	}
}

func TestOverloadedHandPickedCode(t *testing.T) {
	e := newFaultEnv(t, &faultyUp{overloaded: []string{"glm-5-3"}})
	e.mustPost(e.policy(1, nil), e.heartbeat())
	priv, _ := recipientKey(t)
	evs := runParity(t, e.s, e.recorded(priv, proto.RunRequest{Permissions: guard.AllowAll(), Model: "glm-5-3", Tools: []string{},
		FallbackModels: []string{"gpt-oss-120b"}, Messages: user1("hi")}))
	er, ok := lastError(evs)
	if !ok || er.Code != guard.CodeModelOverloaded || er.Error != guard.OverloadedText("glm-5-3") {
		t.Fatalf("error %+v (events %s)", er, types(evs))
	}
	if b, _ := json.Marshal(evs); strings.Contains(string(b), "Retry after") || strings.Contains(string(b), "model_switched") {
		t.Fatalf("the provider's text or a switch in the events: %s", types(evs))
	}
	runs := openedActivity(t, evs, priv, e.rec.Signer.Public())
	end := runs[len(runs)-1]
	if end.Status.State != "failed" || end.Status.Code != guard.CodeModelOverloaded || !slices.Equal(runs[0].Models, []string{"glm-5-3"}) {
		t.Fatalf("records: start models %v, end %+v", runs[0].Models, end.Status)
	}
	if len(end.Calls) != 1 || end.Calls[0].Outcome != "overloaded" || end.Calls[0].Code != guard.CodeModelOverloaded {
		t.Fatalf("calls %+v", end.Calls)
	}
}

// A run whose fallbacks the policy all refuses still runs (nothing to switch to); none is a refusal.
func TestFallbacksNeverRefuseTheRun(t *testing.T) {
	e := newFaultEnv(t, &faultyUp{}, pText("Hi."))
	e.mustPost(e.policy(1, func(p *safety.Policy) { p.Models = []string{"gpt-oss-120b"} }), e.heartbeat())
	priv, _ := recipientKey(t)
	evs := runParity(t, e.s, e.recorded(priv, proto.RunRequest{Permissions: guard.AllowAll(), Tools: []string{}, AutoFallback: true,
		FallbackModels: []string{"kimi-k3", "glm-5-3", "unknown"}, Messages: user1("hi")}))
	if evs[len(evs)-1].Type != "done" {
		t.Fatalf("events %s", types(evs))
	}
	runs := openedActivity(t, evs, priv, e.rec.Signer.Public())
	if !slices.Equal(runs[0].Models, []string{"gpt-oss-120b"}) {
		t.Fatalf("start models %v", runs[0].Models)
	}
}
