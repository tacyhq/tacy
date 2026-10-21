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
	"github.com/tacyhq/tacy/harness"
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
	// The call and its three tries after a wait (guard/fallback.go overloadWait): every request on the record, the
	// last with the run's code.
	if len(end.Calls) != 4 || end.Calls[3].Code != guard.CodeModelOverloaded {
		t.Fatalf("calls %+v", end.Calls)
	}
	for _, c := range end.Calls {
		if c.Outcome != "overloaded" || c.Name != "glm-5-3" || c.Prompt+c.Completion != 0 {
			t.Fatalf("calls %+v", end.Calls)
		}
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

// A fallback is priced: the call's reservation covers the dearest model it may run on (the asked one and the first
// allowed fallback on Auto), the guard is told which (guard.WithPriced), and what it used is counted at the price of
// the model that answered, so a switch to a dearer model can't pass the run's cost budget.
func TestModelCallPricesTheFallback(t *testing.T) {
	e := newSafeEnv(t)
	e.mustPost(e.policy(1, func(p *safety.Policy) { p.Models = []string{"deepseek-v4-1-flash", "kimi-k3", "glm-5-3"} }), e.heartbeat())
	sg := e.s.agent.(*recGateway).safeGateway
	for _, c := range []struct {
		name      string
		opts      guard.TaskOptions
		answered  string
		priced    []string
		priceWith string
	}{
		{"auto, switched", guard.TaskOptions{AutoFallback: true, Fallbacks: []string{"gpt-oss-120b", "kimi-k3", "glm-5-3"}}, "kimi-k3",
			[]string{"deepseek-v4-1-flash", "kimi-k3"}, "kimi-k3"}, // gpt-oss-120b: not in the policy
		{"auto, not switched", guard.TaskOptions{AutoFallback: true, Fallbacks: []string{"glm-5-3"}}, "deepseek-v4-1-flash",
			[]string{"deepseek-v4-1-flash", "glm-5-3"}, "deepseek-v4-1-flash"},
		{"auto, answer's model unknown", guard.TaskOptions{AutoFallback: true, Fallbacks: []string{"glm-5-3"}}, "",
			[]string{"deepseek-v4-1-flash", "glm-5-3"}, "glm-5-3"},
		{"hand-picked", guard.TaskOptions{Fallbacks: []string{"kimi-k3"}}, "",
			[]string{"deepseek-v4-1-flash"}, "deepseek-v4-1-flash"},
	} {
		t.Run(c.name, func(t *testing.T) {
			stub := &pricedStub{answered: c.answered}
			l := &safety.Ledger{}
			g := &safeGateway{inner: stub, st: sg.st, ledger: l}
			c.opts.Space, c.opts.Agent = testSpace, guard.AgentResearch
			raw, _ := json.Marshal(c.opts)
			l.Begin("tk_p", testSpace, "")
			ti := &harness.TaskInfo{ID: "tk_p", Options: raw, Start: &harness.Start{Space: testSpace}}
			if _, err := g.ModelCall(context.Background(), ti, &harness.ModelCall{Model: "deepseek-v4-1-flash",
				Messages: []harness.Message{{Role: "user", Content: "q"}}}); err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(stub.priced, c.priced) {
				t.Fatalf("priced %v, want %v", stub.priced, c.priced)
			}
			// The output cap is what the dearest priced model's cost left can pay for (a_research's $1).
			dear := c.priced[len(c.priced)-1]
			if c.name == "auto, switched" && stub.maxTokens != min(int64(safety.CompletionReserve), safety.CompletionFor(dear, stub.prompt, 1_000_000)) {
				t.Fatalf("output cap %d", stub.maxTokens)
			}
			used, _ := l.Used("tk_p")
			if want := safety.ModelCost(c.priceWith, 1000, 500); used.CostMicros != want {
				t.Fatalf("counted %d micro-USD, want %d (%s's price)", used.CostMicros, want, c.priceWith)
			}
		})
	}
}

// pricedStub is gatewayd for TestModelCallPricesTheFallback: it notes what agentd sent and answers on `answered`.
type pricedStub struct {
	guard.Gateway
	answered  string
	priced    []string
	maxTokens int64
	prompt    int64
}

func (p *pricedStub) ModelCall(ctx context.Context, ti *harness.TaskInfo, req *harness.ModelCall) (*harness.ModelResult, error) {
	p.priced, p.maxTokens = guard.PricedFrom(ctx), guard.MaxTokensFrom(ctx)
	n := 0
	for _, m := range req.Messages {
		n += len(m.Content) + 64
	}
	p.prompt = safety.EstimateTokens(n)
	if p.answered != "" {
		guard.FactsFrom(ctx).Merge(guard.FactsData{Model: p.answered})
	}
	return &harness.ModelResult{Message: harness.Message{Role: "assistant", Content: "a"}, Usage: harness.Usage{Prompt: 1000, Completion: 500}}, nil
}
