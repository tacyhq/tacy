package brain

import (
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tacyhq/tacy/harness"
	"github.com/tacyhq/tacy/harness/conformance"
)

// The whole brain suite (kill and resume, replayed action, steering, cancel, malformed frames).
func TestConformance(t *testing.T) { conformance.RunBrain(t, Run) }

// run starts the brain against a fake runtime, runs one task and returns its outcome and the model calls the
// fake got.
func run(t *testing.T, f *harness.Fake, s harness.Start) (harness.Outcome, []*harness.ModelCall) {
	t.Helper()
	var mu sync.Mutex
	var calls []*harness.ModelCall
	model := f.Model
	if model == nil {
		model = harness.Script(harness.Text("ok"))
	}
	f.Model = func(ctx context.Context, ti *harness.TaskInfo, mc *harness.ModelCall) (*harness.ModelResult, error) {
		mu.Lock()
		c := *mc
		calls = append(calls, &c)
		mu.Unlock()
		return model(ctx, ti, mc)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	rc, bc := net.Pipe()
	go f.Serve(ctx, rc)
	go Run(ctx, bc)
	if err := f.Start("t1", s); err != nil {
		t.Fatal(err)
	}
	o, err := f.Wait(ctx, "t1")
	if err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	return o, calls
}

func task(maxSteps int, tools ...string) harness.Start {
	s := conformance.Task(tools...)
	s.Limits.MaxSteps = maxSteps
	return s
}

func call(id, name, args string) harness.ToolCall {
	return harness.ToolCall{ID: id, Name: name, Args: jsontext.Value(args)}
}

func toolMessages(mc *harness.ModelCall) map[string]string {
	out := map[string]string{}
	for _, m := range mc.Messages {
		if m.Role == "tool" {
			out[m.ToolCallID] = m.Content
		}
	}
	return out
}

// As app/agent.go: at most 4 calls run per step, unknown tools and unparsable arguments are refused without an
// action, the tool's output reaches the model unchanged, a failed tool reads {"error": ...}, and every action
// names the model call it carries out.
func TestToolCalls(t *testing.T) {
	f := harness.NewFake()
	var calls []harness.ToolCall
	for i := range 5 {
		calls = append(calls, call(fmt.Sprintf("c%d", i), "web.search", fmt.Sprintf(`{"query":"q%d"}`, i)))
	}
	bad := call("c5", "web.search", `{}`)
	bad.BadArgs, bad.RawArgs = true, `{"query":`
	calls = append(calls, bad, call("c6", "rm_rf", `{}`), call("c7", "web.fetch", `{"url":"x"}`))
	f.Model = harness.Script(harness.Calls(calls...), harness.Text("answer"))
	var mu sync.Mutex
	var seen []string
	f.Actions["web.search"] = func(_ context.Context, _ *harness.TaskInfo, args jsontext.Value) (*harness.ActionResult, error) {
		mu.Lock()
		seen = append(seen, string(args))
		mu.Unlock()
		return &harness.ActionResult{Status: harness.ActionDone, Output: jsontext.Value(`{"note":"untrusted","results":[]}`)}, nil
	}
	f.Actions["web.fetch"] = func(context.Context, *harness.TaskInfo, jsontext.Value) (*harness.ActionResult, error) {
		return &harness.ActionResult{Status: harness.ActionDenied, Error: "refused: the URL contains personal data (email)"}, nil
	}
	var actions []harness.Action
	f.Observe = func(in bool, e *harness.Envelope) {
		if in && e.Type == harness.TypeAction {
			var a harness.Action
			if json.Unmarshal(e.Body, &a) == nil {
				mu.Lock()
				actions = append(actions, a)
				mu.Unlock()
			}
		}
	}
	o, mcs := run(t, f, task(6, "web.search", "web.fetch"))
	if o.State != harness.OutcomeSucceeded || o.Done.Text != "answer" {
		t.Fatalf("outcome %+v", o)
	}
	if len(seen) != 4 || f.ActionRuns("t1", "web.fetch") != 0 {
		t.Fatalf("searches %v, fetches %d: want 4 and 0 (the fetch is the 8th call)", seen, f.ActionRuns("t1", "web.fetch"))
	}
	got := toolMessages(mcs[1])
	if len(got) != 8 || got["c0"] != `{"note":"untrusted","results":[]}` ||
		!strings.Contains(got["c4"], "at most 4 tool calls per step") || !strings.Contains(got["c7"], "at most 4") {
		t.Fatalf("tool messages %v", got)
	}
	for _, a := range actions {
		if !strings.HasPrefix(a.Call, "c") || a.Name != "web.search" {
			t.Errorf("action %+v doesn't name its model call", a)
		}
	}

	// Within the cap: the refusals app/ told the model, and a denied action's error.
	f = harness.NewFake()
	f.Model = harness.Script(harness.Calls(bad, call("c6", "rm_rf", `{}`), call("c7", "web.fetch", `{"url":"x"}`)), harness.Text("ok"))
	f.Actions["web.fetch"] = func(context.Context, *harness.TaskInfo, jsontext.Value) (*harness.ActionResult, error) {
		return &harness.ActionResult{Status: harness.ActionDenied, Error: "refused: the URL contains personal data (email)"}, nil
	}
	_, mcs = run(t, f, task(6, "web.search", "web.fetch"))
	got = toolMessages(mcs[1])
	if got["c5"] != `{"error":"arguments aren't valid JSON"}` || got["c6"] != `{"error":"tool rm_rf isn't available"}` ||
		got["c7"] != `{"error":"refused: the URL contains personal data (email)"}` {
		t.Fatalf("tool messages %v", got)
	}
	if f.ActionRuns("t1", "web.search") != 0 {
		t.Error("a call with bad arguments ran")
	}
}

// The last step offers no tools, so the model must answer; its tool calls then end the task as they are.
func TestLastStepHasNoTools(t *testing.T) {
	f := harness.NewFake()
	f.Model = harness.Script(harness.Calls(call("c1", "web.search", `{"query":"a"}`)), harness.Calls(call("c2", "web.search", `{"query":"b"}`)))
	o, mcs := run(t, f, task(2, "web.search"))
	// The third call is the retry asking for the answer (TestLastStepToolCallAsksForTheAnswer); here it fails
	// (the script has no more replies), and the task ends as before.
	if o.State != harness.OutcomeSucceeded || len(mcs) != 3 {
		t.Fatalf("outcome %+v, %d model calls", o, len(mcs))
	}
	if len(mcs[0].Tools) != 1 || len(mcs[1].Tools) != 0 {
		t.Fatalf("tools offered %v then %v", mcs[0].Tools, mcs[1].Tools)
	}
	if f.ActionRuns("t1", "web.search") != 1 {
		t.Error("the last step's tool call ran")
	}
}

// A last step that still asks for a tool and writes nothing (gpt-oss does) gets one more call, without tools and
// without that call, asking for the answer; its text is the outcome.
func TestLastStepToolCallAsksForTheAnswer(t *testing.T) {
	f := harness.NewFake()
	f.Model = harness.Script(harness.Calls(call("c1", "web.search", `{"query":"a"}`)), harness.Calls(call("c2", "web.search", `{"query":"b"}`)), harness.Text("the answer [1]"))
	s := task(2, "web.search")
	s.Limits.MaxModelCalls = 3
	o, mcs := run(t, f, s)
	if o.State != harness.OutcomeSucceeded || o.Done.Text != "the answer [1]" || len(mcs) != 3 {
		t.Fatalf("outcome %+v, %d model calls", o, len(mcs))
	}
	m := mcs[2].Messages
	if len(mcs[2].Tools) != 0 || m[len(m)-1].Role != "user" || m[len(m)-1].Content != finalNudge {
		t.Fatalf("retry: tools %v, last message %+v", mcs[2].Tools, m[len(m)-1])
	}
	for _, x := range m {
		for _, c := range x.ToolCalls {
			if c.ID == "c2" {
				t.Fatal("the retry carries the unanswered tool call")
			}
		}
	}
	if f.ActionRuns("t1", "web.search") != 1 {
		t.Error("the last step's tool call ran")
	}
}

// A last step that writes nothing at all (no text, no tool call: gpt-oss wanting a tool it no longer has) gets the
// same one more call asking for the answer.
func TestLastStepEmptyAsksForTheAnswer(t *testing.T) {
	f := harness.NewFake()
	f.Model = harness.Script(harness.Calls(call("c1", "web.search", `{"query":"a"}`)), harness.Text(""), harness.Text("the answer [1]"))
	s := task(2, "web.search")
	s.Limits.MaxModelCalls = 3
	o, mcs := run(t, f, s)
	if o.State != harness.OutcomeSucceeded || o.Done.Text != "the answer [1]" || len(mcs) != 3 {
		t.Fatalf("outcome %+v, %d model calls", o, len(mcs))
	}
	if m := mcs[2].Messages; len(mcs[2].Tools) != 0 || m[len(m)-1].Content != finalNudge {
		t.Fatalf("retry: tools %v, last message %+v", mcs[2].Tools, m[len(m)-1])
	}
}

// An earlier step with neither text nor a tool call is asked once more, with its tools, the run going on from the
// retry's reply; a second empty step isn't (the task's model calls stay within max_steps + 1).
func TestEmptyStepAsksOnce(t *testing.T) {
	f := harness.NewFake()
	f.Model = harness.Script(harness.Text(""), harness.Calls(call("c1", "web.search", `{"query":"a"}`)), harness.Text("the answer [1]"))
	s := task(3, "web.search")
	s.Limits.MaxModelCalls = 4
	o, mcs := run(t, f, s)
	if o.State != harness.OutcomeSucceeded || o.Done.Text != "the answer [1]" || len(mcs) != 3 {
		t.Fatalf("outcome %+v, %d model calls", o, len(mcs))
	}
	if m := mcs[1].Messages; len(mcs[1].Tools) != 1 || m[len(m)-1].Content != emptyNudge {
		t.Fatalf("retry: tools %v, last message %+v", mcs[1].Tools, m[len(m)-1])
	}
	for _, m := range mcs[2].Messages {
		if m.Content == emptyNudge {
			t.Fatal("the nudge stayed in the conversation")
		}
	}
	if f.ActionRuns("t1", "web.search") != 1 {
		t.Error("the retry's tool call didn't run")
	}

	// Empty again after the retry, and on a later step: the run ends there, with one retry only.
	f = harness.NewFake()
	f.Model = harness.Script(harness.Text(""), harness.Text(""), harness.Text(""))
	o, mcs = run(t, f, s)
	if o.State != harness.OutcomeSucceeded || len(mcs) != 2 {
		t.Fatalf("outcome %+v, %d model calls (want 2: the step and one retry)", o, len(mcs))
	}
}

// Instructions are the system message; the input follows.
func TestInstructions(t *testing.T) {
	f := harness.NewFake()
	s := task(1)
	s.Instructions = "Today is Tuesday."
	_, mcs := run(t, f, s)
	m := mcs[0].Messages
	if len(m) != 2 || m[0].Role != "system" || m[0].Content != "Today is Tuesday." || m[1].Content != "hello" {
		t.Fatalf("messages %+v", m)
	}
}

// A model failure ends the task failed with the gateway's message (people see it as the run's error).
func TestModelFailure(t *testing.T) {
	f := harness.NewFake()
	f.Model = func(context.Context, *harness.TaskInfo, *harness.ModelCall) (*harness.ModelResult, error) {
		return nil, harness.Errf(harness.CodeInternal, "model returned 400: bad request")
	}
	o, _ := run(t, f, task(3))
	if o.State != harness.OutcomeFailed || o.Done.Error != "model returned 400: bad request" {
		t.Fatalf("outcome %+v", o)
	}
}

// A conversation is capped by bytes, not message count: a task given 1,000 short messages runs,
// and one whose state no longer fits a checkpoint fails cleanly before the runtime would refuse it.
func TestConversationSize(t *testing.T) {
	s := task(1)
	s.Input = nil
	for i := range 1000 {
		s.Input = append(s.Input, harness.Message{Role: "user", Content: fmt.Sprintf("m%d", i)})
	}
	o, mcs := run(t, harness.NewFake(), s)
	if o.State != harness.OutcomeSucceeded || len(mcs) != 1 || len(mcs[0].Messages) != 1001 {
		t.Fatalf("outcome %+v, %d model calls", o, len(mcs))
	}

	f := harness.NewFake()
	s = task(1)
	big := strings.Repeat("x", 700<<10)
	s.Input = []harness.Message{{Role: "user", Content: big}, {Role: "user", Content: big}, {Role: "user", Content: big}}
	var mu sync.Mutex
	cps := 0
	f.Observe = func(in bool, e *harness.Envelope) {
		if in && e.Type == harness.TypeCheckpoint {
			mu.Lock()
			cps++
			mu.Unlock()
		}
	}
	o, mcs = run(t, f, s)
	mu.Lock()
	defer mu.Unlock()
	if o.State != harness.OutcomeFailed || o.Done.Error != errTooLong || len(mcs) != 0 || cps != 0 {
		t.Fatalf("outcome %+v, %d model calls, %d checkpoints", o, len(mcs), cps)
	}
}
