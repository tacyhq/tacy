package harness

import (
	"context"
	"encoding/json"
	"encoding/json/jsontext"
	"sync"
	"testing"
	"time"
)

// Per-task taint (docs/27 section 5, slice 2): once an untrusted result (a web page, search results) reached the
// brain, every request it proposes after that is marked tainted, and the task's state says so, also after a
// runtime restart. Requests proposed before the brain saw it aren't; a failed read taints nothing.
func TestTaint(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	mem := NewMemStore()
	f := NewFakeWith(mem)
	f.Untrusted = map[string]bool{"web.search": true, "web.fetch": true}
	var mu sync.Mutex
	seen := map[string]bool{} // request id -> TaskInfo.Tainted as the guard got it
	note := func(name string, st string) func(context.Context, *TaskInfo, jsontext.Value) (*ActionResult, error) {
		return func(ctx context.Context, ti *TaskInfo, _ jsontext.Value) (*ActionResult, error) {
			mu.Lock()
			seen[RequestID(ctx)] = ti.Tainted
			mu.Unlock()
			if st == ActionFailed {
				return &ActionResult{Status: ActionFailed, Error: "fetch failed: HTTP 404"}, nil
			}
			return &ActionResult{Status: ActionDone, Output: jsontext.Value(`{"ok":true}`)}, nil
		}
	}
	f.Actions["web.search"] = note("web.search", ActionDone)
	f.Actions["web.fetch"] = note("web.fetch", ActionFailed)
	f.Actions["mail.send"] = note("mail.send", ActionDone)
	f.Model = Script(
		Calls(ToolCall{ID: "c1", Name: "web.search", Args: jsontext.Value(`{}`)}, ToolCall{ID: "c2", Name: "mail.send", Args: jsontext.Value(`{}`)},
			ToolCall{ID: "c3", Name: "web.fetch", Args: jsontext.Value(`{}`)}),
		Calls(ToolCall{ID: "c4", Name: "mail.send", Args: jsontext.Value(`{}`)}),
		Text("done"))
	start := restartTask()
	start.Tools = append(start.Tools, Tool{Name: "web.fetch", Parameters: jsontext.Value(`{}`)})
	if err := f.Start("t1", start); err != nil {
		t.Fatal(err)
	}
	c, task := brainOn(t, ctx, f)
	defer c.Close()
	call := ModelCall{Model: "m", Messages: []Message{{Role: "user", Content: "find it and send it"}}}
	if _, err := task.ModelCall(ctx, "s1.m", call); err != nil {
		t.Fatal(err)
	}
	action := func(id, name, callID string) *ActionResult {
		t.Helper()
		r, err := task.Action(ctx, id, Action{Name: name, Args: jsontext.Value(`{}`), Call: callID})
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	// A failed read brings nothing in; a send proposed before any untrusted result is clean.
	if r := action("s1.a2", "web.fetch", "c3"); r.Status != ActionFailed {
		t.Fatalf("fetch %+v", r)
	}
	action("s1.a1", "mail.send", "c2")
	if st, _ := f.Status("t1"); st.Taint != "" {
		t.Fatalf("tainted before any untrusted result: %+v", st)
	}
	action("s1.a0", "web.search", "c1")
	st, _ := f.Status("t1")
	if st.Taint != "s1.a0" {
		t.Fatalf("status %+v, want taint s1.a0", st)
	}
	if s, _ := mem.Task("t1"); s.Taint != "s1.a0" {
		t.Fatalf("stored %+v", s)
	}
	call.Messages = append(call.Messages, Message{Role: "assistant", Content: "", ToolCalls: []ToolCall{{ID: "c1", Name: "web.search", Args: jsontext.Value(`{}`)}}},
		Message{Role: "tool", ToolCallID: "c1", Content: `{"ok":true}`})
	if _, err := task.ModelCall(ctx, "s2.m", call); err != nil {
		t.Fatal(err)
	}
	action("s2.a0", "mail.send", "c4")
	mu.Lock()
	got := map[string]bool{}
	for k, v := range seen {
		got[k] = v
	}
	mu.Unlock()
	want := map[string]bool{"s1.a2": false, "s1.a1": false, "s1.a0": false, "s2.a0": true}
	for id, w := range want {
		if v, ok := got[id]; !ok || v != w {
			t.Errorf("%s: tainted %v (seen %v), want %v", id, v, ok, w)
		}
	}
	if st, _ := f.Status("t1"); st.Taint != "s1.a0" {
		t.Fatalf("taint moved: %+v", st)
	}
	c.Close()

	// A runtime restart keeps the taint: requests after it are still marked.
	f2 := NewFakeWith(mem)
	f2.Untrusted = f.Untrusted
	var after bool
	f2.Actions["mail.send"] = func(_ context.Context, ti *TaskInfo, _ jsontext.Value) (*ActionResult, error) {
		after = ti.Tainted
		return &ActionResult{Status: ActionDone, Output: jsontext.Value(`{}`)}, nil
	}
	f2.Model = Script(Calls(ToolCall{ID: "c5", Name: "mail.send", Args: jsontext.Value(`{}`)}))
	if _, err := f2.Restore(); err != nil {
		t.Fatal(err)
	}
	if st, _ := f2.Status("t1"); st.Taint != "s1.a0" {
		t.Fatalf("after a restart %+v", st)
	}
	c2, task2 := brainOn(t, ctx, f2)
	defer c2.Close()
	if _, err := task2.ModelCall(ctx, "s3.m", call); err != nil {
		t.Fatal(err)
	}
	if r, err := task2.Action(ctx, "s3.a0", Action{Name: "mail.send", Args: jsontext.Value(`{}`), Call: "c5"}); err != nil || r.Status != ActionDone {
		t.Fatalf("%+v %v", r, err)
	}
	if !after {
		t.Error("a send after a restart wasn't marked tainted")
	}
}

// A task whose input already holds untrusted text (an earlier assistant turn of a chat; docs/27 section 5) is
// tainted from its start: its first request is marked, the store has it before the brain gets the task, and a
// restart after a crash that lost it (task stored, taint not) derives it again.
func TestTaintAtStart(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	byHistory := func(s *Start) string {
		for _, m := range s.Input {
			if m.Role == "assistant" {
				return "history"
			}
		}
		return ""
	}
	mem := NewMemStore()
	f := NewFakeWith(mem)
	f.StartTaint = byHistory
	var first bool
	f.Actions["mail.send"] = func(_ context.Context, ti *TaskInfo, _ jsontext.Value) (*ActionResult, error) {
		first = ti.Tainted
		return &ActionResult{Status: ActionDone, Output: jsontext.Value(`{}`)}, nil
	}
	f.Model = Script(Calls(ToolCall{ID: "c1", Name: "mail.send", Args: jsontext.Value(`{}`)}), Text("done"))
	f0 := NewFake()
	f0.StartTaint = byHistory
	if err := f0.Start("t0", restartTask()); err != nil {
		t.Fatal(err)
	}
	if st, _ := f0.Status("t0"); st.Taint != "" {
		t.Fatalf("a task without history tainted: %+v", st)
	}
	start := restartTask()
	start.Input = append([]Message{{Role: "user", Content: "find it"}, {Role: "assistant", Content: "from the web [1]"}}, start.Input...)
	if err := f.Start("t1", start); err != nil {
		t.Fatal(err)
	}
	if st, _ := mem.Task("t1"); st.Taint != "history" {
		t.Fatalf("stored %+v, want taint history", st)
	}
	c, task := brainOn(t, ctx, f)
	defer c.Close()
	call := ModelCall{Model: "m", Messages: []Message{{Role: "user", Content: "send it"}}}
	if _, err := task.ModelCall(ctx, "s1.m", call); err != nil {
		t.Fatal(err)
	}
	if r, err := task.Action(ctx, "s1.a0", Action{Name: "mail.send", Args: jsontext.Value(`{}`), Call: "c1"}); err != nil || r.Status != ActionDone {
		t.Fatalf("%+v %v", r, err)
	}
	if !first {
		t.Error("the first request of a task with history wasn't marked tainted")
	}
	c.Close()

	// A crash between storing the task and its taint: Restore derives it again.
	mem2 := NewMemStore()
	b, _ := json.Marshal(&start)
	if err := mem2.AddTask("t2", b, nil); err != nil {
		t.Fatal(err)
	}
	f2 := NewFakeWith(mem2)
	f2.StartTaint = byHistory
	if _, err := f2.Restore(); err != nil {
		t.Fatal(err)
	}
	if st, _ := f2.Status("t2"); st.Taint != "history" {
		t.Fatalf("after a restart %+v", st)
	}
	if st, _ := mem2.Task("t2"); st.Taint != "history" {
		t.Fatalf("stored after a restart %+v", st)
	}
}
