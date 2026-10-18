package guard

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tacyhq/tacy/proto"
)

// Slow and overloaded models (fallback.go), through the brain and the runtime with a scripted upstream per model.

// modelUp answers per model: "slow" waits until the call is cancelled, "slow:<d>" waits d then answers, "503",
// "429" and "500overloaded" refuse, "streamoverloaded" sends an error chunk; anything else answers at once.
// Answers are replies[model] in order (then a plain text).
type modelUp struct {
	mu      sync.Mutex
	behave  map[string]string
	replies map[string][]string
	calls   []string         // models, in call order
	bodies  []map[string]any // request bodies, in call order
}

func (m *modelUp) Meta(context.Context) (*proto.Meta, error) {
	return &proto.Meta{TinfoilEnclave: "test"}, nil
}

func (m *modelUp) Stream(ctx context.Context, body []byte) (io.ReadCloser, error) {
	var b map[string]any
	json.Unmarshal(body, &b)
	model, _ := b["model"].(string)
	m.mu.Lock()
	m.calls = append(m.calls, model)
	m.bodies = append(m.bodies, b)
	behave := m.behave[model]
	var reply string
	if r := m.replies[model]; len(r) > 0 {
		reply, m.replies[model] = r[0], r[1:]
	} else {
		reply = textSSE("from " + model)
	}
	m.mu.Unlock()
	switch {
	case behave == "slow":
		<-ctx.Done()
		return nil, ctx.Err()
	case strings.HasPrefix(behave, "slow:"):
		d, _ := time.ParseDuration(strings.TrimPrefix(behave, "slow:"))
		select {
		case <-time.After(d):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	case behave == "503":
		return nil, &StatusError{Status: 503, Msg: "Model is overloaded. Retry after 60 seconds."}
	case behave == "429":
		return nil, &StatusError{Status: 429, Msg: "Too many requests. Retry after 60 seconds."}
	case behave == "500overloaded":
		return nil, &StatusError{Status: 500, Msg: "upstream overloaded, Retry after 60 seconds"}
	case behave == "streamoverloaded":
		return io.NopCloser(strings.NewReader(`data: {"error":{"message":"The model is overloaded. Retry after 60 seconds."}}` + "\n\ndata: [DONE]\n\n")), nil
	}
	return io.NopCloser(strings.NewReader(reply)), nil
}

func (m *modelUp) called() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return slices.Clone(m.calls)
}

func (m *modelUp) body(i int) map[string]any {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.bodies[i]
}

const testSlowAfter = 80 * time.Millisecond

func newFallbackE2E(t *testing.T, up *modelUp) *e2e {
	return newE2E(t, func(c *Config) { c.Up, c.SlowAfter = up, testSlowAfter })
}

func ofType(evs []proto.Event, typ string) []proto.Event {
	var out []proto.Event
	for _, e := range evs {
		if e.Type == typ {
			out = append(out, e)
		}
	}
	return out
}

func modelMetrics(evs []proto.Event) []proto.Metric {
	var out []proto.Metric
	for _, e := range evs {
		if e.Type == "metrics" && e.Metrics.Kind == "model" {
			out = append(out, *e.Metrics)
		}
	}
	return out
}

func noRawProviderText(t *testing.T, evs []proto.Event) {
	t.Helper()
	b, _ := json.Marshal(evs)
	if strings.Contains(string(b), "Retry after") || strings.Contains(string(b), "Too many requests") {
		t.Fatalf("the provider's text reached the events: %s", b)
	}
}

func TestSlowThreshold(t *testing.T) {
	const k = 1 << 10
	for _, c := range []struct {
		bytes int
		want  time.Duration
	}{{0, 20 * time.Second}, {64 * k, 20 * time.Second}, {64*k + 1, 21 * time.Second}, {96 * k, 21 * time.Second},
		{96*k + 1, 22 * time.Second}, {64*k + 100*32*k, 120 * time.Second}, {1 << 30, 120 * time.Second}} {
		if got := SlowThreshold(DefaultSlowAfter, c.bytes); got != c.want {
			t.Errorf("%d bytes: %s, want %s", c.bytes, got, c.want)
		}
	}
	if got := SlowThreshold(time.Second, 64*k+32*k+1); got != 3*time.Second {
		t.Errorf("injected base: %s", got)
	}
}

// Fallbacks are kept in the chat's order, without the run's model, unknown models or duplicates, at most 5; none
// without Auto. The start lists the run's model and its fallbacks.
func TestStartForFallbacks(t *testing.T) {
	r := proto.RunRequest{Model: "deepseek-v4-1-flash", Messages: user("q"), AutoFallback: true,
		FallbackModels: []string{"kimi-k3", "nope", "deepseek-v4-1-flash", "kimi-k3", "gpt-oss-120b", "glm-5-3", "gemma4-31b", "llama3-3-70b"}}
	s, opts, err := StartFor(&r, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"kimi-k3", "gpt-oss-120b", "glm-5-3", "gemma4-31b", "llama3-3-70b"}
	if !slices.Equal(opts.Fallbacks, want) || !opts.AutoFallback || !slices.Equal(s.Models, append([]string{"deepseek-v4-1-flash"}, want...)) {
		t.Fatalf("models %v, fallbacks %v", s.Models, opts.Fallbacks)
	}
	r = proto.RunRequest{Model: "kimi-k3", Messages: user("q"), FallbackModels: []string{"gpt-oss-120b"}}
	s, opts, err = StartFor(&r, time.Now())
	if err != nil || len(opts.Fallbacks) != 0 || opts.AutoFallback || !slices.Equal(s.Models, []string{"kimi-k3"}) {
		t.Fatalf("hand-picked: models %v, fallbacks %v, %v", s.Models, opts.Fallbacks, err)
	}
}

// Auto, no first token in time: model_slow names the fallback, the slow call is given up (slow_switched metric
// with its model), model_switched, and the step runs on the fallback (its own effort: the run's isn't valid for it).
func TestSlowSwitchesOnAuto(t *testing.T) {
	up := &modelUp{behave: map[string]string{"deepseek-v4-1-flash": "slow"}}
	e := newFallbackE2E(t, up)
	evs, err := e.run(proto.RunRequest{Permissions: AllowAll(), Model: "deepseek-v4-1-flash", ReasoningEffort: "xhigh", Tools: []string{},
		AutoFallback: true, FallbackModels: []string{"gpt-oss-120b"}, Messages: user("q")})
	if err != nil {
		t.Fatal(err)
	}
	if got := types(evs); got != "meta,step,model_slow,metrics,model_switched,text,usage,metrics,done" {
		t.Fatalf("events %s", got)
	}
	slow, sw := ofType(evs, "model_slow")[0], ofType(evs, "model_switched")[0]
	if slow.Step != 1 || slow.Model != "deepseek-v4-1-flash" || slow.Fallback != "gpt-oss-120b" || slow.WaitedMs < testSlowAfter.Milliseconds() {
		t.Fatalf("model_slow %+v", slow)
	}
	if sw.Step != 1 || sw.From != "deepseek-v4-1-flash" || sw.To != "gpt-oss-120b" {
		t.Fatalf("model_switched %+v", sw)
	}
	ms := modelMetrics(evs)
	if len(ms) != 2 || ms[0].Outcome != "slow_switched" || ms[0].Model != "deepseek-v4-1-flash" || ms[0].Prompt != 0 ||
		ms[1].Outcome != "ok" || ms[1].Model != "gpt-oss-120b" || ms[1].Prompt == 0 {
		t.Fatalf("metrics %+v", ms)
	}
	if !slices.Equal(up.called(), []string{"deepseek-v4-1-flash", "gpt-oss-120b"}) {
		t.Fatalf("calls %v", up.called())
	}
	if _, ok := up.body(1)["reasoning_effort"]; ok {
		t.Fatalf("the fallback got the run's effort, which it doesn't accept: %v", up.body(1)["reasoning_effort"])
	}
	if ofType(evs, "text")[0].Delta != "from gpt-oss-120b" {
		t.Fatalf("answer %+v", ofType(evs, "text"))
	}
}

// Hand-picked (no Auto, even with fallbacks sent): a slow model gets one model_slow without a fallback and is
// waited for; its answer is the run's.
func TestSlowHandPickedKeepsWaiting(t *testing.T) {
	up := &modelUp{behave: map[string]string{"kimi-k3": "slow:400ms"}}
	e := newFallbackE2E(t, up)
	evs, err := e.run(proto.RunRequest{Permissions: AllowAll(), Model: "kimi-k3", Tools: []string{},
		FallbackModels: []string{"gpt-oss-120b"}, Messages: user("q")})
	if err != nil {
		t.Fatal(err)
	}
	if got := types(evs); got != "meta,step,model_slow,text,usage,metrics,done" {
		t.Fatalf("events %s", got)
	}
	if s := ofType(evs, "model_slow")[0]; s.Model != "kimi-k3" || s.Fallback != "" {
		t.Fatalf("model_slow %+v", s)
	}
	if !slices.Equal(up.called(), []string{"kimi-k3"}) || ofType(evs, "text")[0].Delta != "from kimi-k3" {
		t.Fatalf("calls %v", up.called())
	}
	if m := modelMetrics(evs); len(m) != 1 || m[0].Outcome != "ok" || m[0].Model != "kimi-k3" || m[0].FirstMs < testSlowAfter.Milliseconds() {
		t.Fatalf("metrics %+v", m)
	}
}

// 503, 429, "overloaded" in the error or in the stream: on Auto, the step switches at once.
func TestOverloadedSwitchesOnAuto(t *testing.T) {
	for _, b := range []string{"503", "429", "500overloaded", "streamoverloaded"} {
		t.Run(b, func(t *testing.T) {
			up := &modelUp{behave: map[string]string{"glm-5-3": b}}
			e := newFallbackE2E(t, up)
			evs, err := e.run(proto.RunRequest{Permissions: AllowAll(), Model: "glm-5-3", ReasoningEffort: "low", Tools: []string{},
				AutoFallback: true, FallbackModels: []string{"gpt-oss-120b"}, Messages: user("q")})
			if err != nil {
				t.Fatal(err)
			}
			if got := types(evs); got != "meta,step,model_slow,metrics,model_switched,text,usage,metrics,done" {
				t.Fatalf("events %s", got)
			}
			if s := ofType(evs, "model_slow")[0]; s.Model != "glm-5-3" || s.Fallback != "gpt-oss-120b" {
				t.Fatalf("model_slow %+v", s)
			}
			if m := modelMetrics(evs); m[0].Outcome != "slow_switched" || m[0].Model != "glm-5-3" {
				t.Fatalf("metrics %+v", m)
			}
			if up.body(1)["reasoning_effort"] != "low" {
				t.Fatalf("the fallback lost an effort it accepts: %v", up.body(1)["reasoning_effort"])
			}
			noRawProviderText(t, evs)
		})
	}
}

// Hand-picked and overloaded: one model_slow, then the run ends with our words (model_overloaded), never the
// provider's.
func TestOverloadedHandPickedEnds(t *testing.T) {
	for _, b := range []string{"503", "429", "500overloaded"} {
		t.Run(b, func(t *testing.T) {
			up := &modelUp{behave: map[string]string{"glm-5-3": b}}
			e := newFallbackE2E(t, up)
			evs, _ := e.run(proto.RunRequest{Permissions: AllowAll(), Model: "glm-5-3", Tools: []string{}, Messages: user("q")})
			if got := types(evs); got != "meta,step,model_slow,metrics,error" {
				t.Fatalf("events %s", got)
			}
			er := evs[len(evs)-1]
			// Without agentd's safety checks (app/safety.go) the code stays in the message's prefix.
			if er.Error != CodeModelOverloaded+": "+OverloadedText("glm-5-3") {
				t.Fatalf("error %+v", er)
			}
			if m := modelMetrics(evs); len(m) != 1 || m[0].Outcome != "error" || m[0].Model != "glm-5-3" {
				t.Fatalf("metrics %+v", m)
			}
			if !slices.Equal(up.called(), []string{"glm-5-3"}) {
				t.Fatalf("calls %v", up.called())
			}
			noRawProviderText(t, evs)
		})
	}
}

// Once switched, the run's later steps go straight to the fallback (no new wait); one switch per step at most: a
// fallback that is slow too is waited for (model_slow without a fallback), never switched again.
func TestSwitchedStaysAndSwitchesOnce(t *testing.T) {
	up := &modelUp{behave: map[string]string{"deepseek-v4-1-flash": "slow"},
		replies: map[string][]string{"gpt-oss-120b": {toolCallSSE("c1", "web_search", `{"query":"x"}`), textSSE("done [1]")}}}
	e := newFallbackE2E(t, up)
	evs, err := e.run(proto.RunRequest{Permissions: AllowAll(), Model: "deepseek-v4-1-flash", Tools: []string{"web_search"},
		AutoFallback: true, FallbackModels: []string{"gpt-oss-120b", "kimi-k3"}, Messages: user("q")})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(up.called(), []string{"deepseek-v4-1-flash", "gpt-oss-120b", "gpt-oss-120b"}) {
		t.Fatalf("calls %v", up.called())
	}
	if len(ofType(evs, "model_slow")) != 1 || len(ofType(evs, "model_switched")) != 1 || evs[len(evs)-1].Type != "done" {
		t.Fatalf("events %s", types(evs))
	}
	if m := modelMetrics(evs); len(m) != 3 || m[2].Model != "gpt-oss-120b" || m[2].Step != 2 || m[2].Outcome != "ok" {
		t.Fatalf("metrics %+v", m)
	}

	// The fallback is slow too: no second switch (kimi-k3 is never called); it is waited for.
	up = &modelUp{behave: map[string]string{"deepseek-v4-1-flash": "slow", "gpt-oss-120b": "slow:400ms"}}
	e = newFallbackE2E(t, up)
	evs, err = e.run(proto.RunRequest{Permissions: AllowAll(), Model: "deepseek-v4-1-flash", Tools: []string{},
		AutoFallback: true, FallbackModels: []string{"gpt-oss-120b", "kimi-k3"}, Messages: user("q")})
	if err != nil {
		t.Fatal(err)
	}
	if got := types(evs); got != "meta,step,model_slow,metrics,model_switched,model_slow,text,usage,metrics,done" {
		t.Fatalf("events %s", got)
	}
	if s := ofType(evs, "model_slow")[1]; s.Model != "gpt-oss-120b" || s.Fallback != "" {
		t.Fatalf("second model_slow %+v", s)
	}
	if !slices.Equal(up.called(), []string{"deepseek-v4-1-flash", "gpt-oss-120b"}) {
		t.Fatalf("calls %v", up.called())
	}

	// The fallback is overloaded: the run ends with model_overloaded naming it.
	up = &modelUp{behave: map[string]string{"deepseek-v4-1-flash": "slow", "gpt-oss-120b": "503"}}
	e = newFallbackE2E(t, up)
	evs, _ = e.run(proto.RunRequest{Permissions: AllowAll(), Model: "deepseek-v4-1-flash", Tools: []string{},
		AutoFallback: true, FallbackModels: []string{"gpt-oss-120b", "kimi-k3"}, Messages: user("q")})
	if er := evs[len(evs)-1]; er.Type != "error" || !strings.Contains(er.Error, OverloadedText("gpt-oss-120b")) {
		t.Fatalf("events %s, last %+v", types(evs), er)
	}
	noRawProviderText(t, evs)
}

// A fast first token is never slow, whatever the fallbacks.
func TestNoSwitchWhenFast(t *testing.T) {
	up := &modelUp{}
	e := newFallbackE2E(t, up)
	evs, err := e.run(proto.RunRequest{Permissions: AllowAll(), Model: "kimi-k3", Tools: []string{}, AutoFallback: true,
		FallbackModels: []string{"gpt-oss-120b"}, Messages: user("q")})
	if err != nil || types(evs) != "meta,step,text,usage,metrics,done" {
		t.Fatalf("events %s %v", types(evs), err)
	}
	if !slices.Equal(up.called(), []string{"kimi-k3"}) {
		t.Fatalf("calls %v", up.called())
	}
}

func TestParseModelFaults(t *testing.T) {
	f, err := ParseModelFaults("deepseek-v4-1-flash=slow, llama3-3-70b=overloaded")
	if err != nil || f["deepseek-v4-1-flash"] != FaultSlow || f["llama3-3-70b"] != FaultOverloaded || len(f) != 2 {
		t.Fatal(f, err)
	}
	for _, bad := range []string{"nope=slow", "kimi-k3=fast", "kimi-k3"} {
		if _, err := ParseModelFaults(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if f, err := ParseModelFaults(""); err != nil || len(f) != 0 {
		t.Fatal(f, err)
	}
	up := &modelUp{}
	if WithModelFaults(up, nil) != Upstream(up) {
		t.Fatal("no faults: not the upstream itself")
	}
	_, err = WithModelFaults(up, map[string]string{"kimi-k3": FaultOverloaded}).Stream(context.Background(), []byte(`{"model":"kimi-k3"}`))
	if !overloaded(err) || len(up.called()) != 0 {
		t.Fatalf("overloaded fault: %v, calls %v", err, up.called())
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := WithModelFaults(up, map[string]string{"kimi-k3": FaultSlow}).Stream(ctx, []byte(`{"model":"kimi-k3"}`)); !errors.Is(err, context.Canceled) {
		t.Fatalf("slow fault: %v", err)
	}
}
