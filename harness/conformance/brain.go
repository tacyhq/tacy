// Package conformance checks harness/v1 implementations (docs/20-harness-protocol.md).
//
// RunBrain runs a brain (a harness: our Go loop, a Pi adapter, a builder's SDK) against the fake runtime through
// what every harness must handle: the handshake, a task with a tool call, steering mid-run, cancel, a crash
// while an action runs (the replayed action must not run twice), a crash and resume from a checkpoint, a runtime
// restart mid-task, a request the runtime refuses, arguments the model got wrong, the safety controls (kill switch,
// a budget refusal, a policy refusal), and malformed or oversize frames from the runtime. Every frame the brain sends goes through the runtime's strict decoder; one refusal fails the
// test, as does an action that doesn't name the model tool call it carries out.
//
// RunRuntime plays a hostile brain against a runtime: malformed and oversize frames, wrong order, an unsupported
// version, a reused action id, requests for unknown or closed tasks, checkpoint rules, replay after reconnecting.
package conformance

import (
	"context"
	"encoding/binary"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tacyhq/tacy/harness"
)

// Brain runs one brain on conn until ctx ends or the connection closes. A brain in another language: start its
// process with the socket, kill it when ctx ends.
type Brain func(ctx context.Context, conn net.Conn) error

const wait = 5 * time.Second

// pair is a connected unix socket pair (the real transport), in a short temp dir (unix socket paths are short).
func pair(t testing.TB) (runtimeSide, brainSide net.Conn) {
	dir, err := os.MkdirTemp("", "hv1")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	l, err := net.Listen("unix", filepath.Join(dir, "s"))
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	ch := make(chan net.Conn, 1)
	go func() {
		c, _ := l.Accept()
		ch <- c
	}()
	b, err := net.Dial("unix", filepath.Join(dir, "s"))
	if err != nil {
		t.Fatal(err)
	}
	a := <-ch
	if a == nil {
		t.Fatal("accept failed")
	}
	return a, b
}

type frame struct {
	in bool // from the brain
	e  harness.Envelope
}

// env is one scenario: a fake runtime, the brain under test, and the transcript of every frame.
type env struct {
	t     *testing.T
	f     *harness.Fake
	brain Brain

	mu      sync.Mutex
	frames  []frame
	rejects []error
	changed chan struct{}
	kill    func()
	served  chan struct{} // closed when the current connection's Serve returns
}

func newEnv(t *testing.T, brain Brain) *env {
	e := &env{t: t, brain: brain, changed: make(chan struct{})}
	e.use(harness.NewFake())
	t.Cleanup(func() {
		if e.kill != nil {
			e.kill()
		}
	})
	return e
}

// use makes f the scenario's runtime (a restarted runtime is a new Fake on the old one's store).
func (e *env) use(f *harness.Fake) {
	e.f = f
	e.f.Limits.CancelGraceMs = 2000
	e.f.Observe = func(in bool, env *harness.Envelope) {
		e.mu.Lock()
		e.frames = append(e.frames, frame{in, *env})
		close(e.changed)
		e.changed = make(chan struct{})
		e.mu.Unlock()
	}
	e.f.OnReject = func(err error) {
		e.mu.Lock()
		e.rejects = append(e.rejects, err)
		e.mu.Unlock()
	}
}

// launch starts a brain process on a new connection.
func (e *env) launch() {
	rc, bc := pair(e.t)
	ctx, cancel := context.WithCancel(context.Background())
	served, stopped := make(chan struct{}), make(chan struct{})
	go func() {
		e.f.Serve(ctx, rc)
		close(served)
	}()
	go func() {
		e.brain(ctx, bc)
		close(stopped)
	}()
	e.served = served
	var once sync.Once
	e.kill = func() {
		once.Do(func() {
			cancel()
			bc.Close()
			select {
			case <-stopped:
			case <-time.After(wait):
				e.t.Error("brain didn't return after its context ended and its connection closed")
			}
			<-served
		})
	}
}

// crash kills the brain (a crash: nothing more is sent) and waits until the runtime has noticed.
func (e *env) crash() {
	e.kill()
	e.kill = nil
}

// waitFor waits until pred holds over the transcript.
func (e *env) waitFor(what string, pred func([]frame) bool) {
	e.t.Helper()
	deadline := time.After(wait)
	for {
		e.mu.Lock()
		ok, ch := pred(e.frames), e.changed
		e.mu.Unlock()
		if ok {
			return
		}
		select {
		case <-ch:
		case <-deadline:
			e.t.Fatalf("timed out waiting for %s", what)
		}
	}
}

func (e *env) snapshot() []frame {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]frame(nil), e.frames...)
}

// clean fails the test if the runtime refused any brain frame or answered any request with an error that a
// correct brain never causes.
func (e *env) clean() {
	e.t.Helper()
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, err := range e.rejects {
		e.t.Errorf("runtime refused a frame from the brain: %v", err)
	}
	for _, f := range e.frames {
		if !f.in && f.e.Type == harness.TypeResult && f.e.Error != nil {
			switch f.e.Error.Code {
			case harness.CodeIDConflict, harness.CodeIDInFlight, harness.CodeInvalid, harness.CodeUnknownTask,
				harness.CodeTaskClosed, harness.CodeLimit, harness.CodeNotRequested:
				e.t.Errorf("request %s/%s refused: %v", f.e.Task, f.e.Re, f.e.Error)
			}
		}
	}
}

func (e *env) outcome(task string) harness.Outcome {
	e.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), wait)
	defer cancel()
	o, err := e.f.Wait(ctx, task)
	if err != nil {
		e.t.Fatalf("task %s didn't end: %v", task, err)
	}
	return o
}

// has reports whether a frame of type typ went in or out, for the task, matching ok (nil: any).
func has(fs []frame, in bool, typ, task string, ok func(harness.Envelope) bool) bool {
	for _, f := range fs {
		if f.in == in && f.e.Type == typ && f.e.Task == task && (ok == nil || ok(f.e)) {
			return true
		}
	}
	return false
}

func count(fs []frame, in bool, typ, task string) int {
	n := 0
	for _, f := range fs {
		if f.in == in && f.e.Type == typ && f.e.Task == task {
			n++
		}
	}
	return n
}

func body[T any](t testing.TB, e harness.Envelope) *T {
	t.Helper()
	var v T
	if err := json.Unmarshal(e.Body, &v); err != nil {
		t.Fatalf("%s body: %v", e.Type, err)
	}
	return &v
}

// Task is a test task with the given actions.
func Task(tools ...string) harness.Start {
	s := harness.Start{Space: "s_test", Attempt: 1, Agent: harness.AgentRef{ID: "a_test", Version: "1", Digest: "00"},
		Instructions: "You are a test agent.", Models: []string{"test-model"},
		Input:  []harness.Message{{Role: "user", Content: "hello"}},
		Limits: harness.TaskLimits{MaxSteps: 8, MaxModelCalls: 16}}
	for _, n := range tools {
		s.Tools = append(s.Tools, harness.Tool{Name: n, Description: "test tool " + n, Parameters: jsontext.Value(`{"type":"object"}`)})
	}
	return s
}

func call(id, name, args string) harness.ToolCall {
	return harness.ToolCall{ID: id, Name: name, Args: jsontext.Value(args)}
}

func done(output string) func(context.Context, *harness.TaskInfo, jsontext.Value) (*harness.ActionResult, error) {
	return func(context.Context, *harness.TaskInfo, jsontext.Value) (*harness.ActionResult, error) {
		return &harness.ActionResult{Status: harness.ActionDone, Output: jsontext.Value(output)}, nil
	}
}

// modelCalls returns the bodies of the brain's model calls for a task, in order.
func modelCalls(t testing.TB, fs []frame, task string) []*harness.ModelCall {
	var out []*harness.ModelCall
	for _, f := range fs {
		if f.in && f.e.Type == harness.TypeModelCall && f.e.Task == task {
			out = append(out, body[harness.ModelCall](t, f.e))
		}
	}
	return out
}

// RunBrain runs the brain scenarios. Each starts a fresh fake runtime and brain.
func RunBrain(t *testing.T, brain Brain) {
	t.Run("handshake", func(t *testing.T) {
		e := newEnv(t, brain)
		e.launch()
		e.waitFor("welcome", func(fs []frame) bool { return has(fs, false, harness.TypeWelcome, "", nil) })
		fs := e.snapshot()
		if !fs[0].in || fs[0].e.Type != harness.TypeHello {
			t.Fatalf("first frame is %s, want hello", fs[0].e.Type)
		}
		h := body[harness.Hello](t, fs[0].e)
		if !strings.Contains(strings.Join(h.Protocols, " "), harness.Version) {
			t.Errorf("hello offers %v, not %s", h.Protocols, harness.Version)
		}
		e.clean()
	})

	t.Run("happy path", func(t *testing.T) {
		e := newEnv(t, brain)
		e.f.Model = harness.Script(harness.Calls(call("c1", "web.search", `{"q":"tacy"}`)), harness.Text("the answer"))
		e.f.Actions["web.search"] = done(`{"results":["r-one"]}`)
		e.launch()
		if err := e.f.Start("t1", Task("web.search")); err != nil {
			t.Fatal(err)
		}
		o := e.outcome("t1")
		if o.State != harness.OutcomeSucceeded || o.Done == nil || o.Done.Text != "the answer" {
			t.Fatalf("outcome %+v, want succeeded with the model's answer", o)
		}
		if n := e.f.ActionRuns("t1", "web.search"); n != 1 {
			t.Errorf("web.search ran %d times, want 1", n)
		}
		fs := e.snapshot()
		if !has(fs, true, harness.TypeAction, "t1", func(f harness.Envelope) bool {
			a := body[harness.Action](t, f)
			return a.Name == "web.search" && string(a.Args) == `{"q":"tacy"}`
		}) {
			t.Error("no action web.search with the model's arguments")
		}
		calls := modelCalls(t, fs, "t1")
		if len(calls) != 2 {
			t.Fatalf("%d model calls, want 2", len(calls))
		}
		if !toolResult(calls[1], "c1", "r-one") {
			t.Error("second model call lacks the tool result for c1")
		}
		checkpointsBeforeModelCalls(t, fs, "t1")
		e.clean()
	})

	t.Run("steer mid-run", func(t *testing.T) {
		e := newEnv(t, brain)
		release := make(chan struct{})
		e.f.Model = harness.Script(harness.Calls(call("c1", "slow.op", `{}`)), harness.Text("ok"))
		e.f.Actions["slow.op"] = func(ctx context.Context, _ *harness.TaskInfo, _ jsontext.Value) (*harness.ActionResult, error) {
			select {
			case <-release:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
			return &harness.ActionResult{Status: harness.ActionDone}, nil
		}
		e.launch()
		e.f.Start("t1", Task("slow.op"))
		e.waitFor("the action", func(fs []frame) bool { return has(fs, true, harness.TypeAction, "t1", nil) })
		if _, err := e.f.Steer("t1", "also check Portugal"); err != nil {
			t.Fatal(err)
		}
		e.waitFor("steer sent", func(fs []frame) bool { return has(fs, false, harness.TypeSteer, "t1", nil) })
		close(release)
		if o := e.outcome("t1"); o.State != harness.OutcomeSucceeded {
			t.Fatalf("outcome %+v", o)
		}
		fs := e.snapshot()
		calls := modelCalls(t, fs, "t1")
		last := calls[len(calls)-1]
		found := false
		for _, m := range last.Messages {
			found = found || m.Role == "user" && strings.Contains(m.Content, "also check Portugal")
		}
		if !found {
			t.Error("the model call after the steer doesn't carry it as a user message")
		}
		if !has(fs, true, harness.TypeCheckpoint, "t1", func(f harness.Envelope) bool {
			return body[harness.Checkpoint](t, f).SteerApplied == 1
		}) {
			t.Error("no checkpoint records steer_applied 1")
		}
		e.clean()
	})

	t.Run("cancel", func(t *testing.T) {
		e := newEnv(t, brain)
		e.f.Model = func(ctx context.Context, _ *harness.TaskInfo, _ *harness.ModelCall) (*harness.ModelResult, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		}
		e.launch()
		e.f.Start("t1", Task("web.search"))
		e.waitFor("model call", func(fs []frame) bool { return has(fs, true, harness.TypeModelCall, "t1", nil) })
		e.f.Cancel("t1", "person")
		if o := e.outcome("t1"); o.State != harness.OutcomeCancelled || o.Done == nil || o.Done.Outcome != harness.OutcomeCancelled {
			t.Fatalf("outcome %+v: the brain must send done (cancelled) within the grace period", o)
		}
		if e.f.ActionRuns("t1", "web.search") != 0 {
			t.Error("an action ran after cancel")
		}
		e.clean()
	})

	t.Run("replayed action after crash", func(t *testing.T) {
		e := newEnv(t, brain)
		running, release := make(chan struct{}), make(chan struct{})
		e.f.Model = harness.Script(harness.Calls(call("c1", "mail.send", `{"to":"client"}`)), harness.Text("sent"))
		var once sync.Once
		e.f.Actions["mail.send"] = func(ctx context.Context, _ *harness.TaskInfo, _ jsontext.Value) (*harness.ActionResult, error) {
			once.Do(func() { close(running) })
			<-release
			return &harness.ActionResult{Status: harness.ActionDone, Output: jsontext.Value(`{"message":"m-1"}`)}, nil
		}
		e.launch()
		e.f.Start("t1", Task("mail.send"))
		await(t, running, "mail.send")
		e.crash()      // the brain dies while the guard sends the mail
		close(release) // the send finishes and is journaled; nobody gets the result
		e.launch()
		o := e.outcome("t1")
		if o.State != harness.OutcomeSucceeded {
			t.Fatalf("outcome %+v", o)
		}
		if n := e.f.ActionRuns("t1", "mail.send"); n != 1 {
			t.Errorf("mail.send ran %d times, want 1", n)
		}
		if n := e.f.ModelCalls("t1"); n != 2 {
			t.Errorf("%d model calls reached the model, want 2 (replays come from the journal)", n)
		}
		fs := e.snapshot()
		if count(fs, true, harness.TypeAction, "t1") < 2 {
			t.Error("the resumed brain didn't re-send the action (it can't know it ran)")
		}
		if !has(fs, false, harness.TypeStart, "t1", func(f harness.Envelope) bool { return body[harness.Start](t, f).Attempt == 2 }) {
			t.Error("no resume (attempt 2)")
		}
		e.clean()
	})

	t.Run("crash and resume from checkpoint", func(t *testing.T) {
		e := newEnv(t, brain)
		second, release := make(chan struct{}), make(chan struct{})
		script := harness.Script(harness.Calls(call("c1", "web.search", `{"q":"x"}`)), harness.Text("final"))
		n := 0
		var mu sync.Mutex
		e.f.Model = func(ctx context.Context, ti *harness.TaskInfo, mc *harness.ModelCall) (*harness.ModelResult, error) {
			mu.Lock()
			n++
			k := n
			mu.Unlock()
			if k == 2 {
				close(second)
				<-release
			}
			return script(ctx, ti, mc)
		}
		e.launch()
		e.f.Start("t1", Task("web.search"))
		await(t, second, "the second model call")
		var seq int
		for _, f := range e.snapshot() {
			if f.in && f.e.Type == harness.TypeCheckpoint {
				seq = body[harness.Checkpoint](t, f.e).Seq
			}
		}
		e.crash()
		e.launch()
		e.waitFor("resume", func(fs []frame) bool {
			return has(fs, false, harness.TypeStart, "t1", func(f harness.Envelope) bool {
				s := body[harness.Start](t, f)
				return s.Attempt == 2 && s.Checkpoint != nil && s.Checkpoint.Seq == seq
			})
		})
		close(release)
		o := e.outcome("t1")
		if o.State != harness.OutcomeSucceeded || o.Done.Text != "final" {
			t.Fatalf("outcome %+v", o)
		}
		if n := e.f.ModelCalls("t1"); n != 2 {
			t.Errorf("%d model calls reached the model, want 2", n)
		}
		if n := e.f.ActionRuns("t1", "web.search"); n != 1 {
			t.Errorf("web.search ran %d times, want 1", n)
		}
		e.clean()
	})

	// The runtime process restarts mid-task (a new runtime on the same journal and checkpoints) while an action
	// runs. The brain resumes from its checkpoint: the finished step isn't redone, the action that was running comes
	// back interrupted (it may or may not have happened, so it isn't run again) and goes to the model, and the
	// task finishes. Connectors on the new runtime see the earlier outcomes in the task's journal (TaskInfo.Journal),
	// which is how they rebuild their per-task state.
	t.Run("runtime restart mid-task", func(t *testing.T) {
		e := newEnv(t, brain)
		script := harness.Script(harness.Calls(call("c1", "web.search", `{"q":"one"}`)),
			harness.Calls(call("c2", "mail.send", `{"to":"client"}`)),
			harness.Calls(call("c3", "web.search", `{"q":"three"}`)), harness.Text("final"))
		running, stuck := make(chan struct{}), make(chan struct{})
		t.Cleanup(func() { close(stuck) })
		f1 := e.f
		f1.Model = script
		f1.Actions["web.search"] = done(`{"results":["r-one"]}`)
		f1.Actions["mail.send"] = func(context.Context, *harness.TaskInfo, jsontext.Value) (*harness.ActionResult, error) {
			close(running)
			<-stuck // the runtime process dies while the mail goes out: it never records the outcome
			return nil, harness.Errf(harness.CodeInternal, "the old runtime is gone")
		}
		e.launch()
		f1.Start("t1", Task("web.search", "mail.send"))
		await(t, running, "mail.send")
		e.crash() // the brain's connection goes with the runtime

		f2 := harness.NewFakeWith(f1.Mem)
		f2.Model = script
		f2.Actions["mail.send"] = done(`{"message":"m-2"}`)
		var jmu sync.Mutex
		var journal []harness.Record
		f2.Actions["web.search"] = func(_ context.Context, ti *harness.TaskInfo, _ jsontext.Value) (*harness.ActionResult, error) {
			jmu.Lock()
			journal, _ = ti.Journal()
			jmu.Unlock()
			return &harness.ActionResult{Status: harness.ActionDone, Output: jsontext.Value(`{"results":["r-three"]}`)}, nil
		}
		e.use(f2)
		if ids, err := f2.Restore(); err != nil || len(ids) != 1 || ids[0] != "t1" { // the queue in the store
			t.Fatalf("restored %v, %v", ids, err)
		}
		e.launch()
		o := e.outcome("t1")
		if o.State != harness.OutcomeSucceeded || o.Done.Text != "final" {
			t.Fatalf("outcome %+v", o)
		}
		if n := f1.ActionRuns("t1", "web.search") + f2.ActionRuns("t1", "web.search"); n != 2 {
			t.Errorf("web.search ran %d times, want 2 (once per step that asked)", n)
		}
		if n := f2.ActionRuns("t1", "mail.send"); n != 0 {
			t.Errorf("the interrupted mail.send ran again on the new runtime (%d times)", n)
		}
		if n := f1.ModelCalls("t1") + f2.ModelCalls("t1"); n != 4 {
			t.Errorf("%d model calls reached the model, want 4 (replays come from the journal)", n)
		}
		calls := modelCalls(t, e.snapshot(), "t1")
		if !toolResult(calls[len(calls)-2], "c2", harness.CodeInterrupted) {
			t.Error("the model wasn't told the mail.send was interrupted")
		}
		found := false
		jmu.Lock()
		defer jmu.Unlock()
		for _, r := range journal {
			found = found || r.Kind == harness.TypeAction && r.Done && strings.Contains(string(r.Body), "r-one")
		}
		if !found {
			t.Error("the new runtime's connectors don't see the first search's outcome in the task's journal")
		}
		e.clean()
	})

	// Arguments the model wrote that don't parse come as {} with bad_args and the model's own text (raw_args). The
	// brain doesn't run the action, tells the model, and gives the tool call back unchanged in its next model call,
	// so the model sees what it wrote.
	t.Run("bad arguments", func(t *testing.T) {
		e := newEnv(t, brain)
		bad := call("c1", "web.search", `{}`)
		bad.BadArgs, bad.RawArgs = true, `{"q": tacy`
		e.f.Model = harness.Script(harness.Calls(bad), harness.Text("sorry"))
		e.launch()
		e.f.Start("t1", Task("web.search"))
		if o := e.outcome("t1"); o.State != harness.OutcomeSucceeded {
			t.Fatalf("outcome %+v", o)
		}
		if e.f.ActionRuns("t1", "web.search") != 0 {
			t.Error("an action ran with arguments that didn't parse")
		}
		calls := modelCalls(t, e.snapshot(), "t1")
		if len(calls) != 2 || !toolResult(calls[1], "c1", "") {
			t.Fatal("the model wasn't told about the bad arguments")
		}
		kept := false
		for _, m := range calls[1].Messages {
			for _, c := range m.ToolCalls {
				kept = kept || c.ID == "c1" && c.BadArgs && c.RawArgs == bad.RawArgs
			}
		}
		if !kept {
			t.Error("the next model call doesn't carry the model's raw arguments")
		}
		e.clean()
	})

	t.Run("refused request", func(t *testing.T) {
		e := newEnv(t, brain)
		e.f.Model = harness.Script(harness.Calls(call("c1", "files.delete", `{"path":"/"}`)), harness.Text("couldn't"))
		e.launch()
		e.f.Start("t1", Task("web.search"))
		if o := e.outcome("t1"); o.State != harness.OutcomeSucceeded {
			t.Fatalf("outcome %+v: a refused tool call must go back to the model, not end the task", o)
		}
		calls := modelCalls(t, e.snapshot(), "t1")
		if len(calls) != 2 || !toolResult(calls[1], "c1", "") {
			t.Error("the model wasn't told about the refused call")
		}
		if e.f.ActionRuns("t1", "files.delete") != 0 {
			t.Error("files.delete ran")
		}
		e.clean()
	})

	// Safety controls (step 6, docs/23-safety-controls.md) reach a brain through harness/v1 as it is: the kill
	// switch is a cancel with reason kill_switch, a budget is a limit error, a policy refusal is a denied action.
	t.Run("kill switch", func(t *testing.T) {
		e := newEnv(t, brain)
		e.f.Model = harness.Script(harness.Calls(call("c1", "web.search", `{"q":"x"}`)), harness.Text("never"))
		running := make(chan struct{}, 1)
		e.f.Actions["web.search"] = func(ctx context.Context, _ *harness.TaskInfo, _ jsontext.Value) (*harness.ActionResult, error) {
			running <- struct{}{}
			<-ctx.Done()
			return nil, ctx.Err()
		}
		e.launch()
		e.f.Start("t1", Task("web.search"))
		select {
		case <-running:
		case <-time.After(wait):
			t.Fatal("the action never started")
		}
		e.f.Cancel("t1", "kill_switch")
		if o := e.outcome("t1"); o.State != harness.OutcomeCancelled || o.Done == nil || o.Done.Outcome != harness.OutcomeCancelled {
			t.Fatalf("outcome %+v: the brain must send done (cancelled) after a kill switch", o)
		}
		if n := e.f.ModelCalls("t1"); n != 1 {
			t.Errorf("%d model calls: none may follow the kill switch", n)
		}
		if n := e.f.ActionRuns("t1", "web.search"); n != 1 {
			t.Errorf("web.search ran %d times", n)
		}
		e.clean()
	})

	t.Run("budget refuses a model call", func(t *testing.T) {
		e := newEnv(t, brain)
		var mu sync.Mutex
		n := 0
		e.f.Model = func(context.Context, *harness.TaskInfo, *harness.ModelCall) (*harness.ModelResult, error) {
			mu.Lock()
			n++
			mu.Unlock()
			return nil, harness.Errf(harness.CodeLimit, "budget_exceeded: the run's budget for model tokens is used up")
		}
		e.launch()
		e.f.Start("t1", Task("web.search"))
		o := e.outcome("t1")
		if o.State != harness.OutcomeFailed || o.Done == nil || o.Done.Outcome != harness.OutcomeFailed {
			t.Fatalf("outcome %+v: a refused model call must end the task (failed)", o)
		}
		mu.Lock()
		defer mu.Unlock()
		if n != 1 {
			t.Errorf("%d model calls: the brain must not retry a budget refusal", n)
		}
	})

	t.Run("policy denies an action", func(t *testing.T) {
		e := newEnv(t, brain)
		e.f.Model = harness.Script(harness.Calls(call("c1", "web.fetch", `{"url":"https://elsewhere.example/"}`)), harness.Text("couldn't"))
		e.f.Actions["web.fetch"] = func(context.Context, *harness.TaskInfo, jsontext.Value) (*harness.ActionResult, error) {
			return &harness.ActionResult{Status: harness.ActionDenied, Error: "policy_denied: host not allowed by the policy"}, nil
		}
		e.launch()
		e.f.Start("t1", Task("web.fetch"))
		if o := e.outcome("t1"); o.State != harness.OutcomeSucceeded {
			t.Fatalf("outcome %+v: a policy refusal is an outcome the model sees, not the task's end", o)
		}
		calls := modelCalls(t, e.snapshot(), "t1")
		if len(calls) != 2 || !toolResult(calls[1], "c1", "policy_denied") {
			t.Error("the model wasn't told the policy refused the action")
		}
		e.clean()
	})

	t.Run("malformed frame from runtime", func(t *testing.T) {
		e := newEnv(t, brain)
		e.launch()
		e.waitFor("welcome", func(fs []frame) bool { return has(fs, false, harness.TypeWelcome, "", nil) })
		e.f.SendRaw(withHeader(`{"type":"steer","task":"t1","body":{"n":1,"text":"x"},"extra":true}`))
		e.closes(t)
	})

	t.Run("oversize frame from runtime", func(t *testing.T) {
		e := newEnv(t, brain)
		e.launch()
		e.waitFor("welcome", func(fs []frame) bool { return has(fs, false, harness.TypeWelcome, "", nil) })
		h := body[harness.Hello](t, e.snapshot()[0].e)
		b := binary.BigEndian.AppendUint32(nil, uint32(h.MaxFrame)+1)
		e.f.SendRaw(append(b, `{"type":`...)) // the body never comes: the header alone must be refused
		e.closes(t)
	})
}

// await waits for ch to close: what the brain had to ask for (a broken brain fails the test instead of hanging it).
func await(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(wait):
		t.Fatalf("timed out waiting for %s", what)
	}
}

// closes waits for the brain to close the connection.
func (e *env) closes(t *testing.T) {
	t.Helper()
	select {
	case <-e.served:
	case <-time.After(wait):
		t.Fatal("the brain kept the connection open after a bad frame")
	}
}

func withHeader(s string) []byte {
	return append(binary.BigEndian.AppendUint32(nil, uint32(len(s))), s...)
}

// toolResult reports whether a model call carries a tool message for call id containing want.
func toolResult(mc *harness.ModelCall, id, want string) bool {
	for _, m := range mc.Messages {
		if m.Role == "tool" && m.ToolCallID == id && strings.Contains(m.Content, want) {
			return true
		}
	}
	return false
}

// checkpointsBeforeModelCalls: the brain checkpoints at every step boundary, before that step's model call
// (docs/20, "Replay"), so a resume redoes the step under the same ids.
func checkpointsBeforeModelCalls(t *testing.T, fs []frame, task string) {
	t.Helper()
	cp := false
	for _, f := range fs {
		if !f.in || f.e.Task != task {
			continue
		}
		switch f.e.Type {
		case harness.TypeCheckpoint:
			cp = true
		case harness.TypeModelCall:
			if !cp {
				t.Errorf("model call %s without a checkpoint since the previous one", f.e.ID)
			}
			cp = false
		}
	}
}
