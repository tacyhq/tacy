package harness

import (
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"net"
	"testing"
	"time"
)

// A runtime restart, as the queue in the store sees it: tasks, their options and steering survive; safe
// reads interrupted by the restart run again, anything else stays interrupted (docs/20 "Replay and idempotency", decided
// 2026-10-16).

func restartTask() Start {
	return Start{Space: "s1", Attempt: 1, Agent: AgentRef{ID: "a", Version: "1", Digest: "00"}, Models: []string{"m"},
		Tools:  []Tool{{Name: "web.search", Parameters: jsontext.Value(`{}`)}, {Name: "mail.send", Parameters: jsontext.Value(`{}`)}},
		Limits: TaskLimits{MaxSteps: 4, MaxModelCalls: 4}}
}

// brainOn connects a test brain to f and accepts one task.
func brainOn(t *testing.T, ctx context.Context, f *Fake) (*Client, *Task) {
	t.Helper()
	rc, bc := net.Pipe()
	go f.Serve(ctx, rc)
	c, err := Connect(bc, Hello{Brain: Info{Name: "test", Version: "1"}})
	if err != nil {
		t.Fatal(err)
	}
	task, err := c.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return c, task
}

// The task, its options and its steering come back on a new runtime over the same store; attempts count on.
func TestRestoreKeepsOptions(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	mem := NewMemStore()
	f1 := NewFakeWith(mem)
	opts := jsontext.Value(`{"reasoning_effort":"low","cache_secret":"c","user":"u1"}`)
	if err := f1.StartWith("t1", restartTask(), opts); err != nil {
		t.Fatal(err)
	}
	if err := f1.StartWith("t1", restartTask(), nil); err == nil {
		t.Fatal("a second task t1 was started")
	}
	c1, task1 := brainOn(t, ctx, f1)
	if task1.Start.Attempt != 1 {
		t.Fatalf("attempt %d", task1.Start.Attempt)
	}
	if _, err := f1.Steer("t1", "also this"); err != nil {
		t.Fatal(err)
	}
	c1.Close() // the runtime process dies with its brain

	f2 := NewFakeWith(mem)
	var seen jsontext.Value
	f2.Model = func(_ context.Context, ti *TaskInfo, _ *ModelCall) (*ModelResult, error) {
		seen = ti.Options
		return Text("ok"), nil
	}
	ids, err := f2.Restore()
	if err != nil || len(ids) != 1 || ids[0] != "t1" {
		t.Fatalf("restored %v, %v", ids, err)
	}
	c2, task2 := brainOn(t, ctx, f2)
	defer c2.Close()
	if task2.Start.Attempt != 2 {
		t.Errorf("attempt %d after the restart, want 2", task2.Start.Attempt)
	}
	var st []Steer
	for deadline := time.Now().Add(time.Second); len(st) == 0 && time.Now().Before(deadline); {
		time.Sleep(5 * time.Millisecond)
		st = task2.Steers()
	}
	if len(st) != 1 || st[0].Text != "also this" {
		t.Errorf("steering after the restart: %+v", st)
	}
	if _, err := task2.ModelCall(ctx, "m1", ModelCall{Model: "m", Messages: []Message{{Role: "user", Content: "q"}}}); err != nil {
		t.Fatal(err)
	}
	if string(seen) != string(opts) {
		t.Errorf("the guard got options %s after the restart, want %s", seen, opts)
	}
	if err := task2.Done(ctx, "d", Done{Outcome: OutcomeSucceeded, Text: "ok"}); err != nil {
		t.Fatal(err)
	}
	if o, _ := f2.Wait(ctx, "t1"); o.State != OutcomeSucceeded {
		t.Fatalf("outcome %+v", o)
	}
	if open, _ := mem.OpenTasks(); len(open) != 0 {
		t.Errorf("an ended task is still open: %+v", open)
	}
	if err := f2.Forget("t1"); err != nil {
		t.Fatal(err)
	}
	if recs, _ := mem.Journal("t1"); len(recs) != 0 {
		t.Errorf("forgotten task's journal: %d records", len(recs))
	}
	// A third runtime restores nothing.
	if ids, _ := NewFakeWith(mem).Restore(); len(ids) != 0 {
		t.Errorf("restored %v", ids)
	}
}

// A restored task past its deadline is cancelled.
func TestRestorePastDeadline(t *testing.T) {
	mem := NewMemStore()
	s := restartTask()
	s.Limits.Deadline = time.Now().Add(-time.Minute).UTC().Format(time.RFC3339)
	b, _ := json.Marshal(&s)
	if err := mem.AddTask("t1", b, nil); err != nil { // left open by a runtime that died before the deadline
		t.Fatal(err)
	}
	f2 := NewFakeWith(mem)
	if _, err := f2.Restore(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if o, err := f2.Wait(ctx, "t1"); err != nil || o.State != OutcomeCancelled {
		t.Fatalf("outcome %+v, %v", o, err)
	}
}

// Requests a previous runtime recorded and never finished: a model call and a safe read run again; a mail isn't
// repeated (interrupted). Finished ones are answered from the journal as always.
func TestSafeReplayAfterRestart(t *testing.T) {
	mem := NewMemStore()
	f1 := NewFakeWith(mem)
	if err := f1.Start("t1", restartTask()); err != nil {
		t.Fatal(err)
	}
	begin := func(id, typ string, body any) jsontext.Value {
		b, _ := json.Marshal(body)
		if _, fresh, err := mem.Begin("t1", id, typ, RequestHash(typ, b), b); err != nil || !fresh {
			t.Fatal(err)
		}
		return b
	}
	// The old runtime's journal: m1 finished with two tool calls, then both actions began, then it died. m2 began
	// too (its model call was streaming).
	calls := Calls(ToolCall{ID: "c1", Name: "web.search", Args: jsontext.Value(`{}`)}, ToolCall{ID: "c2", Name: "mail.send", Args: jsontext.Value(`{}`)})
	m1 := ModelCall{Model: "m", Messages: []Message{{Role: "user", Content: "q"}}}
	begin("m1", TypeModelCall, &m1)
	res, _ := json.Marshal(calls)
	mem.Finish("t1", "m1", res, nil)
	search := Action{Name: "web.search", Args: jsontext.Value(`{}`), Call: "c1"}
	mail := Action{Name: "mail.send", Args: jsontext.Value(`{}`), Call: "c2"}
	begin("a1", TypeAction, &search)
	begin("a2", TypeAction, &mail)
	m2 := ModelCall{Model: "m", Messages: []Message{{Role: "user", Content: "q2"}}}
	begin("m2", TypeModelCall, &m2)

	f2 := NewFakeWith(mem)
	f2.Safe = map[string]bool{"web.search": true}
	f2.Model = Script(Text("the answer"))
	if _, err := f2.Restore(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, task := brainOn(t, ctx, f2)
	defer c.Close()
	if r, err := task.ModelCall(ctx, "m1", m1); err != nil || len(r.Message.ToolCalls) != 2 {
		t.Fatalf("m1 replay: %+v %v", r, err)
	}
	if r, err := task.Action(ctx, "a1", search); err != nil || r.Status != ActionDone {
		t.Fatalf("interrupted search: %+v %v, want it run again", r, err)
	}
	_, err := task.Action(ctx, "a2", mail)
	var pe *Error
	if !errors.As(err, &pe) || pe.Code != CodeInterrupted {
		t.Fatalf("interrupted mail: %v, want interrupted", err)
	}
	// Once rerun, the outcome is journaled: a replay doesn't run it a third time.
	if _, err := task.Action(ctx, "a1", search); err != nil || f2.ActionRuns("t1", "web.search") != 1 {
		t.Errorf("replayed rerun: %v, runs %d", err, f2.ActionRuns("t1", "web.search"))
	}
	if r, err := task.ModelCall(ctx, "m2", m2); err != nil || r.Message.Content != "the answer" {
		t.Fatalf("interrupted model call: %+v %v, want it run again", r, err)
	}
	if f2.ActionRuns("t1", "web.search") != 1 || f2.ActionRuns("t1", "mail.send") != 0 || f2.ModelCalls("t1") != 1 {
		t.Errorf("runs: search %d, mail %d, model %d; want 1, 0, 1", f2.ActionRuns("t1", "web.search"),
			f2.ActionRuns("t1", "mail.send"), f2.ModelCalls("t1"))
	}
	recs, _ := mem.Journal("t1")
	for _, r := range recs {
		if !r.Done {
			t.Errorf("%s still pending in the journal", r.ID)
		}
	}
}
