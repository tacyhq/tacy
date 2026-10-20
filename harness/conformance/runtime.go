package conformance

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/tacyhq/tacy/harness"
)

// Target is a runtime under test. Its guard must run any action with status done, and its model answer each
// task's model calls with the replies given to ScriptModel; the fake runtime does.
type Target interface {
	// Dial opens a new connection to the runtime, as a brain would.
	Dial(t testing.TB) net.Conn
	// Start queues a task.
	Start(id string, s harness.Start) error
	// ActionRuns is how many times the guard ran action name for the task.
	ActionRuns(task, name string) int
	// ScriptModel makes the model answer each task's fresh model calls with replies, in order; the last repeats.
	ScriptModel(replies ...*harness.ModelResult)
}

// HoldTarget is a Target whose guard can hold an action for a person's decision before it runs (approve before
// send, a permission prompt: docs/27 sections 4 and 6). The runtime suite's approval scenarios run only on one.
type HoldTarget interface {
	Target
	// HoldActions makes the guard hold every action named name, with wait sub-state sub.
	HoldActions(name, sub string)
	// Held is the task's requests held now.
	Held(task string) []harness.Held
	// Release decides a held request (allow: run it once; deny: answer it denied without running it).
	Release(task, id string, allow bool, reason string) error
}

// FakeTarget is the fake runtime as a Target.
func FakeTarget(t testing.TB) Target { return FakeTargetOn(t, harness.NewMemStore()) }

// FakeTargetOn is the fake runtime on store as a Target (the runtime engine with another Store: the SQLite queue).
func FakeTargetOn(t testing.TB, store harness.Store) Target {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	return &fakeTarget{f: harness.NewFakeOn(store), ctx: ctx}
}

type fakeTarget struct {
	f   *harness.Fake
	ctx context.Context
}

func (ft *fakeTarget) Dial(t testing.TB) net.Conn {
	rc, bc := pair(t)
	go ft.f.Serve(ft.ctx, rc)
	t.Cleanup(func() { bc.Close() })
	return bc
}
func (ft *fakeTarget) Start(id string, s harness.Start) error { return ft.f.Start(id, s) }
func (ft *fakeTarget) ActionRuns(task, name string) int       { return ft.f.ActionRuns(task, name) }
func (ft *fakeTarget) ScriptModel(replies ...*harness.ModelResult) {
	ft.f.Model = harness.Script(replies...)
}
func (ft *fakeTarget) HoldActions(name, sub string) {
	if ft.f.Holds == nil {
		ft.f.Holds = map[string]string{}
	}
	ft.f.Holds[name] = sub
}
func (ft *fakeTarget) Held(task string) []harness.Held {
	st, _ := ft.f.Status(task)
	return st.Held
}
func (ft *fakeTarget) Release(task, id string, allow bool, reason string) error {
	return ft.f.Release(task, id, allow, reason)
}

// raw is a brain that writes whatever it's told to.
type raw struct {
	t testing.TB
	c net.Conn
}

func (r *raw) bytes(b []byte) {
	r.t.Helper()
	r.c.SetWriteDeadline(time.Now().Add(wait))
	if _, err := r.c.Write(b); err != nil {
		r.t.Fatalf("write: %v", err)
	}
}

func (r *raw) send(s string) { r.t.Helper(); r.bytes(withHeader(s)) }

// next reads and strictly decodes the runtime's next frame.
func (r *raw) next() *harness.Envelope {
	r.t.Helper()
	r.c.SetReadDeadline(time.Now().Add(wait))
	b, err := harness.ReadFrame(r.c, harness.MaxFrame)
	if err != nil {
		r.t.Fatalf("read: %v", err)
	}
	e, _, err := harness.Decode(b, harness.FromRuntime)
	if err != nil {
		r.t.Fatalf("the runtime sent a frame its own decoder refuses: %v", err)
	}
	return e
}

const helloJSON = `{"type":"hello","body":{"protocols":["harness/v1"],"brain":{"name":"hostile","version":"1"},"max_frame":4194304,"max_tasks":4}}`

func (r *raw) hello() {
	r.t.Helper()
	r.send(helloJSON)
	if e := r.next(); e.Type != harness.TypeWelcome {
		r.t.Fatalf("got %s, want welcome", e.Type)
	}
}

// fatal expects an error frame with code, then the connection closing.
func (r *raw) fatal(code string) {
	r.t.Helper()
	e := r.next()
	if e.Type != harness.TypeError || e.Error.Code != code {
		r.t.Fatalf("got %s %v, want error %s", e.Type, e.Error, code)
	}
	r.c.SetReadDeadline(time.Now().Add(wait))
	if _, err := harness.ReadFrame(r.c, harness.MaxFrame); !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) &&
		!strings.Contains(fmt.Sprint(err), "reset") {
		r.t.Fatalf("connection not closed after error: %v", err)
	}
}

// start waits for the task's start frame.
func (r *raw) start(task string) *harness.Start {
	r.t.Helper()
	for {
		if e := r.next(); e.Type == harness.TypeStart && e.Task == task {
			return body[harness.Start](r.t, *e)
		}
	}
}

// result waits for the result answering task/re.
func (r *raw) result(task, re string) *harness.Envelope {
	r.t.Helper()
	for {
		if e := r.next(); e.Type == harness.TypeResult && e.Task == task && e.Re == re {
			return e
		}
	}
}

// expect sends a request and checks its result's error code ("" for success).
func (r *raw) expect(frame, task, id, code string) *harness.Envelope {
	r.t.Helper()
	r.send(frame)
	e := r.result(task, id)
	got := ""
	if e.Error != nil {
		got = e.Error.Code
	}
	if got != code {
		r.t.Fatalf("%s: got error %q, want %q", frame, got, code)
	}
	return e
}

// action is an action carrying out tool call c1 (which connected's first model call asks for).
func action(task, id, name, args string) string { return actionFor(task, id, name, "c1", args) }

// actionFor is an action carrying out tool call call ("" for none).
func actionFor(task, id, name, call, args string) string {
	c := ""
	if call != "" {
		c = fmt.Sprintf(`,"call":%q`, call)
	}
	return fmt.Sprintf(`{"type":"action","task":%q,"id":%q,"body":{"name":%q,"args":%s%s}}`, task, id, name, args, c)
}

func modelCall(task, id string) string {
	return fmt.Sprintf(`{"type":"model.call","task":%q,"id":%q,"body":{"model":"test-model","messages":[{"role":"user","content":"hi"}]}}`, task, id)
}

func checkpoint(task, id string, seq, applied int) string {
	return fmt.Sprintf(`{"type":"checkpoint","task":%q,"id":%q,"body":{"seq":%d,"steer_applied":%d,"state":"e30="}}`, task, id, seq, applied)
}

// RunRuntime runs the hostile-brain scenarios against runtimes made by newTarget.
func RunRuntime(t *testing.T, newTarget func(testing.TB) Target) {
	connect := func(t *testing.T) (Target, *raw) {
		tg := newTarget(t)
		return tg, &raw{t: t, c: tg.Dial(t)}
	}
	// connected starts task t1 (actions test.echo and test.other) on a fresh runtime and connection, and makes
	// model call m0, which asks for test.echo as tool call c1 (actions must name a tool call of the latest model
	// result). Later model calls ask for test.echo as c2.
	connected := func(t *testing.T) (Target, *raw) {
		tg, r := connect(t)
		tg.ScriptModel(harness.Calls(call("c1", "test.echo", `{}`)), harness.Calls(call("c2", "test.echo", `{}`)))
		r.hello()
		if err := tg.Start("t1", Task("test.echo", "test.other")); err != nil {
			t.Fatal(err)
		}
		r.start("t1")
		r.expect(modelCall("t1", "m0"), "t1", "m0", "")
		return tg, r
	}

	t.Run("handshake", func(t *testing.T) {
		_, r := connect(t)
		r.send(helloJSON)
		e := r.next()
		if e.Type != harness.TypeWelcome {
			t.Fatalf("got %s", e.Type)
		}
		if w := body[harness.Welcome](t, *e); w.Protocol != harness.Version {
			t.Errorf("protocol %q", w.Protocol)
		}
	})

	t.Run("unsupported version", func(t *testing.T) {
		_, r := connect(t)
		r.send(strings.Replace(helloJSON, "harness/v1", "harness/v0", 1))
		r.fatal(harness.CodeUnsupportedVersion)
	})

	t.Run("request before hello", func(t *testing.T) {
		_, r := connect(t)
		r.send(action("t1", "a1", "test.echo", `{}`))
		r.fatal(harness.CodeProtocol)
	})

	deep := `{"a":` + strings.Repeat("[", 100) + strings.Repeat("]", 100) + `}`
	malformed := []struct{ name, frame, code string }{
		{"not JSON", `{"type":`, harness.CodeBadFrame},
		{"trailing data", `{"type":"status","task":"t1","body":{"note":"x"}} {}`, harness.CodeBadFrame},
		{"unknown envelope field", `{"type":"status","task":"t1","body":{"note":"x"},"x":1}`, harness.CodeBadFrame},
		{"unknown body field", `{"type":"status","task":"t1","body":{"note":"x","x":1}}`, harness.CodeBadFrame},
		{"status step (dropped from v1)", `{"type":"status","task":"t1","body":{"step":1,"note":"x"}}`, harness.CodeBadFrame},
		{"status without a note", `{"type":"status","task":"t1","body":{}}`, harness.CodeBadFrame},
		{"duplicate key", `{"type":"status","type":"status","task":"t1","body":{"note":"x"}}`, harness.CodeBadFrame},
		{"duplicate key in args", action("t1", "a1", "test.echo", `{"to":"a","to":"b"}`), harness.CodeBadFrame},
		{"key in another case", `{"Type":"status","task":"t1","body":{"note":"x"}}`, harness.CodeBadFrame},
		{"invalid UTF-8", "{\"type\":\"status\",\"task\":\"t1\",\"body\":{\"note\":\"\xff\"}}", harness.CodeBadFrame},
		{"nested too deep", action("t1", "a1", "test.echo", deep), harness.CodeBadFrame},
		{"unknown type", `{"type":"shell","task":"t1","id":"x","body":{}}`, harness.CodeBadFrame},
		{"runtime's type", `{"type":"start","task":"t1","body":{}}`, harness.CodeProtocol},
		{"result from brain", `{"type":"result","task":"t1","re":"x","body":{}}`, harness.CodeProtocol},
		{"second hello", helloJSON, harness.CodeProtocol},
		{"bad id", action("t1", "../etc", "test.echo", `{}`), harness.CodeBadFrame},
		{"missing id", `{"type":"action","task":"t1","body":{"name":"test.echo","args":{}}}`, harness.CodeBadFrame},
		{"body not an object", `{"type":"status","task":"t1","body":[]}`, harness.CodeBadFrame},
		{"args not an object", action("t1", "a1", "test.echo", `[1]`), harness.CodeBadFrame},
		{"bad action name", action("t1", "a1", "Mail Send", `{}`), harness.CodeBadFrame},
		{"note too long", `{"type":"status","task":"t1","body":{"note":"` + strings.Repeat("x", 300) + `"}}`, harness.CodeBadFrame},
		{"raw_args without bad_args", `{"type":"model.call","task":"t1","id":"m1","body":{"model":"m","messages":[{"role":"assistant","content":"","tool_calls":[{"id":"c1","name":"test.echo","args":{},"raw_args":"{"}]}]}}`, harness.CodeBadFrame},
		{"raw_args too long", `{"type":"model.call","task":"t1","id":"m1","body":{"model":"m","messages":[{"role":"assistant","content":"","tool_calls":[{"id":"c1","name":"test.echo","args":{},"bad_args":true,"raw_args":"` + strings.Repeat("x", harness.MaxRawArgs+1) + `"}]}]}}`, harness.CodeBadFrame},
	}
	for _, m := range malformed {
		t.Run("malformed/"+m.name, func(t *testing.T) {
			_, r := connect(t)
			r.hello()
			r.send(m.frame)
			r.fatal(m.code)
		})
	}

	t.Run("malformed/empty frame", func(t *testing.T) {
		_, r := connect(t)
		r.hello()
		r.bytes([]byte{0, 0, 0, 0})
		r.fatal(harness.CodeBadFrame)
	})

	t.Run("oversize frame", func(t *testing.T) {
		_, r := connect(t)
		r.hello()
		// Only the header and a few bytes: the runtime must refuse from the header, not wait for 4 MiB.
		r.bytes(append(binary.BigEndian.AppendUint32(nil, harness.MaxFrame+1), `{"type":`...))
		r.fatal(harness.CodeBadFrame)
	})

	t.Run("duplicate action id", func(t *testing.T) {
		tg, r := connected(t)
		first := r.expect(action("t1", "a1", "test.echo", `{"x":1}`), "t1", "a1", "")
		again := r.expect(action("t1", "a1", "test.echo", `{ "x" : 1 }`), "t1", "a1", "") // same request, other spacing
		if !bytes.Equal(first.Body, again.Body) {
			t.Errorf("replay returned %s, first %s", again.Body, first.Body)
		}
		r.expect(action("t1", "a1", "test.echo", `{"x":2}`), "t1", "a1", harness.CodeIDConflict)
		r.expect(modelCall("t1", "a1"), "t1", "a1", harness.CodeIDConflict)
		if n := tg.ActionRuns("t1", "test.echo"); n != 1 {
			t.Errorf("test.echo ran %d times, want 1", n)
		}
	})

	t.Run("replay after reconnect", func(t *testing.T) {
		tg, r := connected(t)
		first := r.expect(action("t1", "a1", "test.echo", `{"x":1}`), "t1", "a1", "")
		r.c.Close()
		r2 := &raw{t: t, c: tg.Dial(t)}
		r2.hello()
		if st := r2.start("t1"); st.Attempt != 2 {
			t.Errorf("attempt %d, want 2", st.Attempt)
		}
		again := r2.expect(action("t1", "a1", "test.echo", `{"x":1}`), "t1", "a1", "")
		if !bytes.Equal(first.Body, again.Body) || tg.ActionRuns("t1", "test.echo") != 1 {
			t.Errorf("the action ran again after reconnecting")
		}
	})

	// Every action carries out a tool call of the same name in the task's latest model result; anything else is
	// refused (not_requested) and nothing runs. The connection and the task go on.
	t.Run("action not requested", func(t *testing.T) {
		tg, r := connect(t)
		tg.ScriptModel(harness.Calls(call("c1", "test.echo", `{}`)), harness.Calls(call("c2", "test.echo", `{}`)))
		r.hello()
		if err := tg.Start("t1", Task("test.echo", "test.other")); err != nil {
			t.Fatal(err)
		}
		r.start("t1")
		r.expect(actionFor("t1", "a1", "test.echo", "c1", `{}`), "t1", "a1", harness.CodeNotRequested) // no model result yet
		r.expect(modelCall("t1", "m1"), "t1", "m1", "")
		r.expect(actionFor("t1", "a2", "test.echo", "", `{}`), "t1", "a2", harness.CodeNotRequested)    // no call
		r.expect(actionFor("t1", "a3", "test.echo", "c9", `{}`), "t1", "a3", harness.CodeNotRequested)  // no such call
		r.expect(actionFor("t1", "a4", "test.other", "c1", `{}`), "t1", "a4", harness.CodeNotRequested) // another tool
		r.expect(actionFor("t1", "a5", "test.echo", "c1", `{}`), "t1", "a5", "")
		r.expect(modelCall("t1", "m2"), "t1", "m2", "")
		r.expect(actionFor("t1", "a6", "test.echo", "c1", `{}`), "t1", "a6", harness.CodeNotRequested) // an older result
		r.expect(actionFor("t1", "a7", "test.echo", "c2", `{}`), "t1", "a7", "")
		if n, o := tg.ActionRuns("t1", "test.echo"), tg.ActionRuns("t1", "test.other"); n != 2 || o != 0 {
			t.Errorf("test.echo ran %d times, test.other %d: want 2 and 0", n, o)
		}
	})

	// One action per tool call (runtime-side, the protocol is unchanged): a second action naming a call that an
	// action already carries out is refused (not_requested) and nothing runs; a replay of the first is answered
	// from the journal. A replayed model result (reconnect) keeps the call taken.
	t.Run("one action per tool call", func(t *testing.T) {
		tg, r := connected(t)
		first := r.expect(actionFor("t1", "a1", "test.echo", "c1", `{"x":1}`), "t1", "a1", "")
		r.expect(actionFor("t1", "a2", "test.echo", "c1", `{"x":1}`), "t1", "a2", harness.CodeNotRequested) // same call, other id
		r.expect(actionFor("t1", "a3", "test.echo", "c1", `{"x":2}`), "t1", "a3", harness.CodeNotRequested) // other arguments
		again := r.expect(actionFor("t1", "a1", "test.echo", "c1", `{"x":1}`), "t1", "a1", "")              // replay
		if !bytes.Equal(first.Body, again.Body) {
			t.Errorf("replay returned %s, first %s", again.Body, first.Body)
		}
		r.c.Close()
		r2 := &raw{t: t, c: tg.Dial(t)}
		r2.hello()
		r2.start("t1")
		r2.expect(modelCall("t1", "m0"), "t1", "m0", "") // replayed from the journal: c1 again
		r2.expect(actionFor("t1", "a4", "test.echo", "c1", `{"x":1}`), "t1", "a4", harness.CodeNotRequested)
		r2.expect(actionFor("t1", "a1", "test.echo", "c1", `{"x":1}`), "t1", "a1", "")
		r2.expect(modelCall("t1", "m1"), "t1", "m1", "") // a new result: c2 is free
		r2.expect(actionFor("t1", "a5", "test.echo", "c2", `{}`), "t1", "a5", "")
		r2.expect(actionFor("t1", "a6", "test.echo", "c2", `{}`), "t1", "a6", harness.CodeNotRequested)
		if n := tg.ActionRuns("t1", "test.echo"); n != 2 {
			t.Errorf("test.echo ran %d times, want 2 (a1 and a5)", n)
		}
	})

	t.Run("unknown task", func(t *testing.T) {
		tg, r := connected(t)
		r.expect(action("nope", "a1", "test.echo", `{}`), "nope", "a1", harness.CodeUnknownTask)
		r.expect(action("t1", "a1", "test.echo", `{}`), "t1", "a1", "") // the connection survives
		if tg.ActionRuns("nope", "test.echo") != 0 {
			t.Error("ran for an unknown task")
		}
	})

	t.Run("not allowed", func(t *testing.T) {
		tg, r := connected(t)
		r.expect(action("t1", "a1", "mail.send", `{}`), "t1", "a1", harness.CodeNotAllowed)
		r.expect(`{"type":"model.call","task":"t1","id":"m1","body":{"model":"other-model","messages":[{"role":"user","content":"hi"}]}}`,
			"t1", "m1", harness.CodeNotAllowed)
		r.expect(`{"type":"model.call","task":"t1","id":"m2","body":{"model":"test-model","tools":["mail.send"],"messages":[{"role":"user","content":"hi"}]}}`,
			"t1", "m2", harness.CodeNotAllowed)
		r.expect(`{"type":"exec","task":"t1","id":"x1","body":{"argv":["ls"]}}`, "t1", "x1", harness.CodeNotAllowed)
		if tg.ActionRuns("t1", "mail.send") != 0 {
			t.Error("mail.send ran")
		}
	})

	t.Run("checkpoint rules", func(t *testing.T) {
		_, r := connected(t)
		r.expect(checkpoint("t1", "c1", 2, 0), "t1", "c1", harness.CodeInvalid)
		r.expect(checkpoint("t1", "c2", 1, 1), "t1", "c2", harness.CodeInvalid) // no steer was sent
		r.expect(checkpoint("t1", "c3", 1, 0), "t1", "c3", "")
		r.expect(checkpoint("t1", "c4", 1, 0), "t1", "c4", harness.CodeInvalid) // an old checkpoint can't overwrite
	})

	// A task id derived from what makes a start unique (a schedule slot, an event delivery, a retried start's key;
	// docs/27 section 1) can't make a second task: the second start is refused, whatever its content.
	t.Run("derived task id is once-only", func(t *testing.T) {
		tg, _ := connect(t)
		if err := tg.Start("tk_derived", Task("test.echo")); err != nil {
			t.Fatal(err)
		}
		if err := tg.Start("tk_derived", Task("test.other")); err == nil {
			t.Fatal("a second task under the same id was started")
		}
	})

	// Approve before send (docs/27 section 4): a held action doesn't run, and the brain gets no result, until a person
	// decides. Approved, it runs once; its id re-sent gets the journaled result. Denied, it never runs and the brain
	// gets a denied result (a normal outcome the model sees), again on a re-send.
	holds := func(t *testing.T) (HoldTarget, *raw) {
		tg, r := connect(t)
		ht, ok := tg.(HoldTarget)
		if !ok {
			t.Skip("target can't hold actions")
		}
		ht.HoldActions("sink.post", harness.WaitApproval)
		ht.ScriptModel(harness.Calls(call("c1", "sink.post", `{"to":"client"}`), call("c2", "sink.post", `{"to":"other"}`)))
		r.hello()
		if err := ht.Start("t1", Task("sink.post")); err != nil {
			t.Fatal(err)
		}
		r.start("t1")
		r.expect(modelCall("t1", "m0"), "t1", "m0", "")
		return ht, r
	}
	waitHeld := func(t *testing.T, ht HoldTarget, n int) []harness.Held {
		t.Helper()
		for deadline := time.Now().Add(wait); ; time.Sleep(5 * time.Millisecond) {
			if h := ht.Held("t1"); len(h) == n {
				return h
			}
			if time.Now().After(deadline) {
				t.Fatalf("held %+v, want %d", ht.Held("t1"), n)
			}
		}
	}
	noFrame := func(t *testing.T, r *raw, d time.Duration) {
		t.Helper()
		r.c.SetReadDeadline(time.Now().Add(d))
		if b, err := harness.ReadFrame(r.c, harness.MaxFrame); err == nil {
			t.Fatalf("a frame arrived while the action was held: %s", b)
		}
	}
	t.Run("held action runs once, after approval", func(t *testing.T) {
		ht, r := holds(t)
		r.send(actionFor("t1", "a1", "sink.post", "c1", `{"to":"client"}`))
		h := waitHeld(t, ht, 1)
		noFrame(t, r, 200*time.Millisecond)
		if ht.ActionRuns("t1", "sink.post") != 0 {
			t.Fatal("ran before approval")
		}
		if err := ht.Release("t1", h[0].ID, true, ""); err != nil {
			t.Fatal(err)
		}
		r.c.SetReadDeadline(time.Time{})
		first := r.result("t1", "a1")
		if first.Error != nil || !strings.Contains(string(first.Body), `"done"`) {
			t.Fatalf("approved result %s %v", first.Body, first.Error)
		}
		again := r.expect(actionFor("t1", "a1", "sink.post", "c1", `{"to":"client"}`), "t1", "a1", "")
		if !bytes.Equal(first.Body, again.Body) || ht.ActionRuns("t1", "sink.post") != 1 {
			t.Fatalf("re-sent approved action: %s, ran %d times", again.Body, ht.ActionRuns("t1", "sink.post"))
		}
		if err := ht.Release("t1", h[0].ID, true, ""); err == nil {
			t.Error("a decided request was decided again")
		}
	})
	t.Run("denied action never runs", func(t *testing.T) {
		ht, r := holds(t)
		r.send(actionFor("t1", "a2", "sink.post", "c2", `{"to":"other"}`))
		h := waitHeld(t, ht, 1)
		if err := ht.Release("t1", h[0].ID, false, "the person declined"); err != nil {
			t.Fatal(err)
		}
		e := r.result("t1", "a2")
		if e.Error != nil || !strings.Contains(string(e.Body), `"denied"`) || !strings.Contains(string(e.Body), "declined") {
			t.Fatalf("denied result %s %v", e.Body, e.Error)
		}
		again := r.expect(actionFor("t1", "a2", "sink.post", "c2", `{"to":"other"}`), "t1", "a2", "")
		if !bytes.Equal(e.Body, again.Body) || ht.ActionRuns("t1", "sink.post") != 0 {
			t.Fatalf("denied action re-sent: %s, ran %d times", again.Body, ht.ActionRuns("t1", "sink.post"))
		}
	})

	t.Run("after done", func(t *testing.T) {
		tg, r := connected(t)
		r.expect(`{"type":"done","task":"t1","id":"d1","body":{"outcome":"succeeded","text":"ok"}}`, "t1", "d1", "")
		r.expect(action("t1", "a1", "test.echo", `{}`), "t1", "a1", harness.CodeTaskClosed)
		r.expect(checkpoint("t1", "c1", 1, 0), "t1", "c1", harness.CodeTaskClosed)
		if tg.ActionRuns("t1", "test.echo") != 0 {
			t.Error("ran after done")
		}
	})
}
