package harness

import (
	"context"
	"encoding/json/jsontext"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// The task model in the runtime (docs/27 slice 1): lifecycle states as requests are held and decided, held
// requests across runtime restarts, the attempts cap counting brain failures only, and once-only task ids.

// deadStore is a Store whose process can die: after kill, every write is dropped and every read still works (the
// file stays; the process that wrote it is gone). A test's "restart" kills the old runtime's store and opens a
// new runtime on the same one, so nothing the old runtime does afterwards (noticing its brain is gone, a timer)
// reaches the store, as when the process exits.
type deadStore struct {
	Store
	dead atomic.Bool
}

var errDead = errors.New("process gone")

func (d *deadStore) AddTask(id string, start, opts jsontext.Value) error {
	if d.dead.Load() {
		return errDead
	}
	return d.Store.AddTask(id, start, opts)
}
func (d *deadStore) SetAttempt(id string, a, f int) error {
	if d.dead.Load() {
		return errDead
	}
	return d.Store.SetAttempt(id, a, f)
}
func (d *deadStore) SetState(id, state, sub string) error {
	if d.dead.Load() {
		return errDead
	}
	return d.Store.SetState(id, state, sub)
}
func (d *deadStore) SetTaint(id, by string) error {
	if d.dead.Load() {
		return errDead
	}
	return d.Store.SetTaint(id, by)
}
func (d *deadStore) AddSteer(id string, st Steer) error {
	if d.dead.Load() {
		return errDead
	}
	return d.Store.AddSteer(id, st)
}
func (d *deadStore) EndTask(id string, o Outcome) error {
	if d.dead.Load() {
		return errDead
	}
	return d.Store.EndTask(id, o)
}
func (d *deadStore) DeleteTask(id string) error {
	if d.dead.Load() {
		return errDead
	}
	return d.Store.DeleteTask(id)
}
func (d *deadStore) Begin(task, id, kind string, h [32]byte, req jsontext.Value) (Record, bool, error) {
	if d.dead.Load() {
		return Record{}, false, errDead
	}
	return d.Store.Begin(task, id, kind, h, req)
}
func (d *deadStore) Hold(task, id, sub string) error {
	if d.dead.Load() {
		return errDead
	}
	return d.Store.Hold(task, id, sub)
}
func (d *deadStore) Finish(task, id string, body jsontext.Value, e *Error) error {
	if d.dead.Load() {
		return errDead
	}
	return d.Store.Finish(task, id, body, e)
}
func (d *deadStore) SaveCheckpoint(task string, cp *Checkpoint) error {
	if d.dead.Load() {
		return errDead
	}
	return d.Store.SaveCheckpoint(task, cp)
}
func (d *deadStore) AddEvents(task string, evs []StoredEvent) error {
	if d.dead.Load() {
		return errDead
	}
	return d.Store.AddEvents(task, evs)
}

// process is one runtime process on the shared store.
type process struct {
	f     *Fake
	store *deadStore
	ctx   context.Context
	stop  context.CancelFunc
	c     *Client
	task  *Task
}

// boot starts a runtime process on mem (restoring what an earlier one left) with mail.send held for approval.
func boot(t *testing.T, mem *MemStore) *process {
	t.Helper()
	ds := &deadStore{Store: mem}
	f := NewFakeOn(ds)
	f.Holds = map[string]string{"mail.send": WaitApproval}
	f.Model = Script(Calls(ToolCall{ID: "c1", Name: "mail.send", Args: jsontext.Value(`{"to":"client"}`)}), Text("sent"))
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	if _, err := f.Restore(); err != nil {
		t.Fatal(err)
	}
	return &process{f: f, store: ds, ctx: ctx, stop: cancel}
}

// connect gives the process a brain and accepts the task.
func (p *process) connect(t *testing.T) {
	t.Helper()
	p.c, p.task = brainOn(t, p.ctx, p.f)
}

// kill ends the process: its store writes stop, its brain's connection closes.
func (p *process) kill() {
	p.store.dead.Store(true)
	if p.c != nil {
		p.c.Close()
	}
	p.stop()
}

var (
	heldCall = ModelCall{Model: "m", Messages: []Message{{Role: "user", Content: "send it"}}}
	heldMail = Action{Name: "mail.send", Args: jsontext.Value(`{"to":"client"}`), Call: "c1"}
)

// sendHeld replays the brain's steps up to the held action (ids from its own progress, as a brain must), and
// returns the action's result when it comes.
func (p *process) sendHeld(t *testing.T) <-chan error {
	t.Helper()
	if _, err := p.task.ModelCall(p.ctx, "s1.m", heldCall); err != nil {
		t.Fatal(err)
	}
	out := make(chan error, 1)
	go func() {
		r, err := p.task.Action(p.ctx, "s1.a0", heldMail)
		if err == nil && r.Status != ActionDone {
			err = errors.New(r.Status + ": " + r.Error)
		}
		out <- err
	}()
	return out
}

func waitState(t *testing.T, rt *Runtime, id, state, sub string) TaskStatus {
	t.Helper()
	for deadline := time.Now().Add(3 * time.Second); ; time.Sleep(5 * time.Millisecond) {
		st, err := rt.Status(id)
		if err == nil && st.State == state && st.Sub == sub {
			return st
		}
		if time.Now().After(deadline) {
			t.Fatalf("task %s: %+v %v, want %s/%s", id, st, err, state, sub)
		}
	}
}

// A held request survives runtime restarts held, not interrupted, and three restarts while it waits don't fail
// the task (the attempts cap counts brain failures only). Approved after the last restart, the mail goes out once.
func TestHeldSurvivesRestarts(t *testing.T) {
	mem := NewMemStore()
	p := boot(t, mem)
	if err := p.f.Start("t1", restartTask()); err != nil {
		t.Fatal(err)
	}
	if st, _ := p.f.Status("t1"); st.State != StateQueued {
		t.Fatalf("before a brain: %+v", st)
	}
	p.connect(t)
	waitState(t, p.f.Runtime, "t1", StateRunning, "")
	p.sendHeld(t)
	st := waitState(t, p.f.Runtime, "t1", StateWaiting, WaitApproval)
	if len(st.Held) != 1 || st.Held[0].ID != "s1.a0" || st.Held[0].Kind != TypeAction {
		t.Fatalf("held: %+v", st.Held)
	}
	if s, _ := mem.Task("t1"); s.State != StateWaiting || s.Sub != WaitApproval {
		t.Fatalf("stored state %+v", s)
	}
	for restart := 1; restart <= 4; restart++ {
		p.kill()
		p = boot(t, mem)
		// Waiting again at once, before any brain: the queue says why.
		st := waitState(t, p.f.Runtime, "t1", StateWaiting, WaitApproval)
		if len(st.Held) != 1 || st.Failures != 0 {
			t.Fatalf("restart %d: %+v", restart, st)
		}
		p.connect(t)
		if p.task.Start.Attempt != restart+1 {
			t.Fatalf("restart %d: attempt %d", restart, p.task.Start.Attempt)
		}
		res := p.sendHeld(t)
		select {
		case err := <-res:
			t.Fatalf("restart %d: the held mail answered %v", restart, err)
		case <-time.After(50 * time.Millisecond):
		}
		waitState(t, p.f.Runtime, "t1", StateWaiting, WaitApproval)
		if restart == 4 {
			if err := p.f.Release("t1", "s1.a0", true, ""); err != nil {
				t.Fatal(err)
			}
			if err := <-res; err != nil {
				t.Fatalf("approved mail: %v", err)
			}
		}
	}
	waitState(t, p.f.Runtime, "t1", StateRunning, "")
	if n := p.f.ActionRuns("t1", "mail.send"); n != 1 {
		t.Fatalf("mail.send ran %d times", n)
	}
	if err := p.task.Done(p.ctx, "d", Done{Outcome: OutcomeSucceeded, Text: "sent"}); err != nil {
		t.Fatal(err)
	}
	if o, err := p.f.Wait(p.ctx, "t1"); err != nil || o.State != OutcomeSucceeded {
		t.Fatalf("outcome %+v %v", o, err)
	}
	if st, _ := p.f.Status("t1"); st.State != StateDone || st.Outcome == nil {
		t.Fatalf("status %+v", st)
	}
	recs, _ := mem.Journal("t1")
	for _, r := range recs {
		if r.Err != nil && r.Err.Code == CodeInterrupted {
			t.Fatalf("%s came back interrupted", r.ID)
		}
	}
	p.kill()
	if st, _ := boot(t, mem).f.Status("t1"); st.State != StateDone { // from the store, no process holds it
		t.Fatalf("status after the end, from the store: %+v", st)
	}
}

// A decision made after a restart, before the brain re-sent the held request, applies when it does.
func TestReleaseBeforeResend(t *testing.T) {
	mem := NewMemStore()
	p := boot(t, mem)
	p.f.Start("t1", restartTask())
	p.connect(t)
	p.sendHeld(t)
	waitState(t, p.f.Runtime, "t1", StateWaiting, WaitApproval)
	p.kill()
	p = boot(t, mem)
	if err := p.f.Release("t1", "s1.a0", false, "not this one"); err != nil {
		t.Fatal(err)
	}
	if err := p.f.Release("t1", "nope", true, ""); err == nil {
		t.Fatal("a request that isn't held was released")
	}
	p.connect(t)
	if err := <-p.sendHeld(t); err == nil || err.Error() != "denied: not this one" {
		t.Fatalf("denied mail: %v", err)
	}
	if p.f.ActionRuns("t1", "mail.send") != 0 {
		t.Fatal("a denied mail ran")
	}
	waitState(t, p.f.Runtime, "t1", StateRunning, "")
}

// Cancelling a task while a request is held: the request ends cancelled and never runs, the task ends cancelled,
// and a late decision is refused.
func TestCancelWhileHeld(t *testing.T) {
	mem := NewMemStore()
	p := boot(t, mem)
	p.f.Limits.CancelGraceMs = 200
	p.f.Start("t1", restartTask())
	p.connect(t)
	res := p.sendHeld(t)
	waitState(t, p.f.Runtime, "t1", StateWaiting, WaitApproval)
	if err := p.f.Cancel("t1", "person"); err != nil {
		t.Fatal(err)
	}
	var pe *Error
	if err := <-res; !errors.As(err, &pe) || pe.Code != CodeCancelled {
		t.Fatalf("held request after the cancel: %v", err)
	}
	select {
	case <-p.task.Cancelled():
	case <-time.After(2 * time.Second):
		t.Fatal("the brain wasn't told")
	}
	p.task.Done(p.ctx, "d", Done{Outcome: OutcomeCancelled})
	if o, _ := p.f.Wait(p.ctx, "t1"); o.State != OutcomeCancelled {
		t.Fatalf("outcome %+v", o)
	}
	if err := p.f.Release("t1", "s1.a0", true, ""); err == nil {
		t.Fatal("a cancelled task's request was approved")
	}
	if p.f.ActionRuns("t1", "mail.send") != 0 {
		t.Fatal("the held mail ran")
	}
	recs, _ := mem.Journal("t1")
	if len(recs) != 2 || !recs[1].Done || recs[1].Err == nil || recs[1].Err.Code != CodeCancelled || recs[1].Held != WaitApproval {
		t.Fatalf("journal %+v", recs)
	}
	if st, _ := p.f.Status("t1"); st.State != StateCancelled || len(st.Held) != 0 {
		t.Fatalf("status %+v", st)
	}
}

// The attempts cap: the brain failing three times fails the task (a crash each time), while restarts don't count.
func TestBrainFailuresCap(t *testing.T) {
	mem := NewMemStore()
	p := boot(t, mem)
	p.f.Start("t1", restartTask())
	for i := 1; i <= 3; i++ {
		p.connect(t)
		if p.task.Start.Attempt != i {
			t.Fatalf("attempt %d, want %d", p.task.Start.Attempt, i)
		}
		p.c.Close() // the brain crashes
		for deadline := time.Now().Add(2 * time.Second); ; time.Sleep(5 * time.Millisecond) {
			if st, _ := p.f.Status("t1"); st.Failures == i || time.Now().After(deadline) {
				break
			}
		}
	}
	// A runtime restart here doesn't reset the count (it's in the store) and doesn't add to it.
	p.kill()
	p = boot(t, mem)
	if st, _ := p.f.Status("t1"); st.Failures != 3 || st.State != StateRunning {
		t.Fatalf("after the restart: %+v", st)
	}
	rc, bc := net.Pipe()
	go p.f.Serve(p.ctx, rc)
	Connect(bc, Hello{Brain: Info{Name: "test", Version: "1"}})
	o, err := p.f.Wait(p.ctx, "t1")
	if err != nil || o.State != OutcomeFailed || o.Done == nil || o.Done.Error != "the brain stopped too often" {
		t.Fatalf("outcome %+v %v", o, err)
	}
}

// Once-only ids: a task id can't be started twice, ended or not, until it's forgotten.
func TestTaskExists(t *testing.T) {
	mem := NewMemStore()
	p := boot(t, mem)
	id := DeriveTaskID([]byte("k"), "start", "u", "same key")
	if err := p.f.Start(id, restartTask()); err != nil {
		t.Fatal(err)
	}
	if err := p.f.Start(id, restartTask()); !errors.Is(err, ErrTaskExists) {
		t.Fatalf("second start: %v", err)
	}
	p.f.Cancel(id, "person")
	p.f.Wait(p.ctx, id)
	p.kill()
	p = boot(t, mem) // a new process: the task isn't in its memory, only in the queue
	if err := p.f.Start(id, restartTask()); !errors.Is(err, ErrTaskExists) {
		t.Fatalf("start after it ended: %v", err)
	}
	if err := p.f.Forget(id); err != nil {
		t.Fatal(err)
	}
	if err := p.f.Start(id, restartTask()); err != nil {
		t.Fatalf("start after forget: %v", err)
	}
}
