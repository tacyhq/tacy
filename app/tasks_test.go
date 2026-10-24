package main

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	ehbpidentity "github.com/tinfoilsh/encrypted-http-body-protocol/identity"
	ehbpproto "github.com/tinfoilsh/encrypted-http-body-protocol/protocol"

	"github.com/tacyhq/tacy/activity"
	"github.com/tacyhq/tacy/agentclient"
	"github.com/tacyhq/tacy/guard"
	"github.com/tacyhq/tacy/harness"
	"github.com/tacyhq/tacy/proto"
	"github.com/tacyhq/tacy/queue"
	"github.com/tacyhq/tacy/safety"
)

// The task API end to end in agentd (docs/27 slice 1): over EHBP as the relay passes it, on the SQLite queue,
// with the in-process guard and brain. A "restart" kills one agentd process (its queue writes stop, its brain
// goes) and boots another on the same queue file, as an update or a crash followed by a boot does.

// deadQueue is a queue whose process can die: after kill nothing more is written (the file stays).
type deadQueue struct {
	harness.Store
	dead atomic.Bool
}

var errGone = errors.New("process gone")

func (d *deadQueue) w() error {
	if d.dead.Load() {
		return errGone
	}
	return nil
}
func (d *deadQueue) Scrub(id string, o jsontext.Value) error {
	return cmpErr(d.w(), func() error { return d.Store.Scrub(id, o) })
}
func (d *deadQueue) MarkDelivered(id string, at time.Time) error {
	return cmpErr(d.w(), func() error { return d.Store.(harness.DeliveryStore).MarkDelivered(id, at) })
}
func (d *deadQueue) DeliveredBefore(at time.Time) ([]string, error) {
	return d.Store.(harness.DeliveryStore).DeliveredBefore(at)
}
func (d *deadQueue) AddTask(id string, s, o jsontext.Value) error {
	return cmpErr(d.w(), func() error { return d.Store.AddTask(id, s, o) })
}
func (d *deadQueue) SetAttempt(id string, a, f int) error {
	return cmpErr(d.w(), func() error { return d.Store.SetAttempt(id, a, f) })
}
func (d *deadQueue) SetState(id, st, sub string) error {
	return cmpErr(d.w(), func() error { return d.Store.SetState(id, st, sub) })
}
func (d *deadQueue) SetTaint(id, by string) error {
	return cmpErr(d.w(), func() error { return d.Store.SetTaint(id, by) })
}
func (d *deadQueue) AddSteer(id string, st harness.Steer) error {
	return cmpErr(d.w(), func() error { return d.Store.AddSteer(id, st) })
}
func (d *deadQueue) EndTask(id string, o harness.Outcome) error {
	return cmpErr(d.w(), func() error { return d.Store.EndTask(id, o) })
}
func (d *deadQueue) DeleteTask(id string) error {
	return cmpErr(d.w(), func() error { return d.Store.DeleteTask(id) })
}
func (d *deadQueue) Hold(task, id, sub string) error {
	return cmpErr(d.w(), func() error { return d.Store.Hold(task, id, sub) })
}
func (d *deadQueue) Finish(task, id string, b jsontext.Value, e *harness.Error) error {
	return cmpErr(d.w(), func() error { return d.Store.Finish(task, id, b, e) })
}
func (d *deadQueue) SaveCheckpoint(task string, cp *harness.Checkpoint) error {
	return cmpErr(d.w(), func() error { return d.Store.SaveCheckpoint(task, cp) })
}
func (d *deadQueue) AddEvents(task string, evs []harness.StoredEvent) error {
	return cmpErr(d.w(), func() error { return d.Store.AddEvents(task, evs) })
}
func (d *deadQueue) Begin(task, id, kind string, h [32]byte, req jsontext.Value) (harness.Record, bool, error) {
	if err := d.w(); err != nil {
		return harness.Record{}, false, err
	}
	return d.Store.Begin(task, id, kind, h, req)
}

func cmpErr(err error, f func() error) error {
	if err != nil {
		return err
	}
	return f()
}

// taskProc is one agentd process for the task tests.
type taskProc struct {
	s      *server
	q      *deadQueue
	id     *ehbpidentity.Identity
	cancel context.CancelFunc
}

// holdSearch holds every web.search for approval (a stand-in for slice 5's approvals: the runtime's mechanism,
// not a policy).
type holdSearch struct{ *guard.Guard }

func (h holdSearch) Hold(_ *harness.TaskInfo, _ string, req any) string {
	if a, ok := req.(*harness.Action); ok && a.Name == "web.search" {
		return harness.WaitApproval
	}
	return ""
}

// bootTasks starts an agentd process on the queue at path, taking up what an earlier one left there.
func bootTasks(t *testing.T, path string, model http.Handler, fs *fakeSearch, hold bool) *taskProc {
	t.Helper()
	srv := httptest.NewServer(model)
	t.Cleanup(func() {
		if m, ok := model.(*stepModel); ok {
			m.unblock()
		}
		srv.Close()
	})
	q, err := queue.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { q.Close() })
	dq := &deadQueue{Store: q}
	lim := defaultLimits
	g := guard.New(guard.Config{Up: guard.NewPlainUpstream(srv.URL, srv.Client()), Search: fs, Fetcher: guard.NewFetcher(true),
		Limits: &lim, CacheSecret: "boot-secret", Now: func() time.Time { return time.Date(2026, 10, 17, 0, 0, 0, 0, time.UTC) }})
	var rg harness.Guard = g
	if hold {
		rg = holdSearch{g}
	}
	rt := newRuntime(rg, dq, lim)
	ids, err := rt.Restore()
	if err != nil {
		t.Fatal(err)
	}
	id, _ := ehbpidentity.NewIdentity()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	s := &server{platform: local{}, id: id, agent: g, rt: rt, token: "tok", booted: time.Now(), sched: newScheduler(lim), lim: lim,
		quotes: make(chan struct{}, 4), host: &guard.Host{RT: rt, GW: g, IDKey: []byte("the space's task-id key")}}
	s.resumeTasks(ctx, ids, t.Logf)
	// The brain connects only once the restored tasks are resumed, as in main.go: a brain already connected would
	// take a restored task up before its stream was open, and its events would go nowhere.
	go localBrain(ctx, rt)
	return &taskProc{s: s, q: dq, id: id, cancel: cancel}
}

// kill ends the process: no more queue writes, its brain gone.
func (p *taskProc) kill() {
	p.q.dead.Store(true)
	p.cancel()
}

// conn is a client of this process's task API (and /run) over EHBP, as user.
func (p *taskProc) conn(t *testing.T, user string) *agentclient.Conn {
	return connTo(t, p.s, user)
}

func connTo(t *testing.T, s *server, user string) *agentclient.Conn {
	t.Helper()
	mux := http.NewServeMux()
	s.taskRoutes(mux, s.id)
	mux.Handle("POST /run", s.guard(s.id.Middleware()(http.HandlerFunc(s.run))))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	c, err := agentclient.New(srv.URL, "tok", s.id.MarshalPublicKey())
	if err != nil {
		t.Fatal(err)
	}
	c.User = user
	c.Asker = testAsker // the tests' space (testSpace), which they stop and read
	return c
}

type seqEvent struct {
	seq int
	ev  proto.Event
}

// followAll follows a task from after to its end.
func followAll(t *testing.T, c *agentclient.Conn, id string, after int) []seqEvent {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	var out []seqEvent
	if err := c.FollowTask(ctx, id, after, func(seq int, e proto.Event) { out = append(out, seqEvent{seq, e}) }); err != nil {
		t.Fatalf("follow %s after %d: %v", id, after, err)
	}
	return out
}

func waitTask(t *testing.T, c *agentclient.Conn, id string, ok func(*agentclient.Task) bool) *agentclient.Task {
	t.Helper()
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		st, err := c.TaskStatus(context.Background(), id)
		if err == nil && ok(st) {
			return st
		}
		if time.Now().After(deadline) {
			t.Fatalf("task %s: %+v %v", id, st, err)
		}
	}
}

func evTypes(evs []seqEvent) string {
	var out []string
	for _, e := range evs {
		out = append(out, e.ev.Type)
	}
	return strings.Join(out, ",")
}

// contiguous: seqs from first, each once, in order.
func contiguous(t *testing.T, evs []seqEvent, first int) {
	t.Helper()
	for i, e := range evs {
		if e.seq != first+i {
			t.Fatalf("event %d has seq %d, want %d (%s)", i, e.seq, first+i, evTypes(evs))
		}
	}
}

// stepModel answers each model call with the next reply; a reply "block" waits until the test ends (an upstream
// still streaming when the process dies). It counts calls.
type stepModel struct {
	mu      sync.Mutex
	replies []string
	calls   atomic.Int32
	stuck   chan struct{}
	once    sync.Once
}

func newStepModel(t *testing.T, replies ...string) *stepModel {
	return &stepModel{replies: replies, stuck: make(chan struct{})}
}

// unblock lets blocked calls end (before the test's servers close).
func (m *stepModel) unblock() { m.once.Do(func() { close(m.stuck) }) }

func (m *stepModel) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	io.Copy(io.Discard, r.Body)
	i := int(m.calls.Add(1)) - 1
	m.mu.Lock()
	reply := pText("(no more)")
	if i < len(m.replies) {
		reply = m.replies[i]
	}
	m.mu.Unlock()
	if reply == "block" {
		select {
		case <-m.stuck:
		case <-r.Context().Done():
		}
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	io.WriteString(w, reply)
}

func waitCalls(t *testing.T, m *stepModel, n int32) {
	t.Helper()
	for deadline := time.Now().Add(10 * time.Second); m.calls.Load() < n; time.Sleep(5 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("model calls %d, want %d", m.calls.Load(), n)
		}
	}
}

const tasksUser = "0123456789abcdef0123"

// A task outlives its tab and its agentd process: the tab closes mid-task and reconnects to a new process after a
// restart, and sees every event once, in order; the task finishes from its journal (the search that ran before the
// restart isn't run again) with the attempt counted on.
func TestTasksRestartMidTask(t *testing.T) {
	path := filepath.Join(t.TempDir(), "queue.db")
	fs := &fakeSearch{}
	m := newStepModel(t, pCalls([3]string{"c1", "web_search", `{"query":"dstack release"}`}), "block", pText("v0.6.1 [1]."))
	p1 := bootTasks(t, path, m, fs, false)
	c1 := p1.conn(t, tasksUser)
	tk, err := c1.StartTask(context.Background(), proto.RunRequest{Permissions: guard.AllowAll(), Messages: user1("latest dstack?")}, "")
	if err != nil || !harness.ValidTaskID(tk.Task) || tk.Existing {
		t.Fatalf("start: %+v %v", tk, err)
	}
	// The tab follows until the second model call is streaming, then closes.
	ctx, closeTab := context.WithCancel(context.Background())
	var mu sync.Mutex
	var seen []seqEvent
	followed := make(chan error, 1)
	go func() {
		followed <- c1.FollowTask(ctx, tk.Task, 0, func(seq int, e proto.Event) {
			mu.Lock()
			seen = append(seen, seqEvent{seq, e})
			mu.Unlock()
		})
	}()
	waitCalls(t, m, 2)
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		mu.Lock()
		n := len(seen)
		hasResult := strings.Contains(evTypes(seen), "tool_result")
		mu.Unlock()
		if hasResult && n > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the tab saw %s", evTypes(seen))
		}
	}
	closeTab()
	<-followed
	mu.Lock()
	before := append([]seqEvent(nil), seen...)
	mu.Unlock()
	contiguous(t, before, 1)
	if before[0].ev.Type != "meta" {
		t.Fatalf("first event %s", before[0].ev.Type)
	}
	// The task goes on without the tab.
	if st, _ := c1.TaskStatus(context.Background(), tk.Task); st.State != harness.StateRunning {
		t.Fatalf("after the tab closed: %+v", st)
	}

	p1.kill()
	p2 := bootTasks(t, path, m, fs, false)
	c2 := p2.conn(t, tasksUser)
	c2.SetTaskSecret(tk.Task, c1.TaskSecret(tk.Task)) // the tab that started it, on the new process
	last := before[len(before)-1].seq
	rest := followAll(t, c2, tk.Task, last)
	contiguous(t, rest, last+1)
	if rest[len(rest)-1].ev.Type != "done" {
		t.Fatalf("after the restart: %s", evTypes(rest))
	}
	text := ""
	for _, e := range rest {
		text += e.ev.Delta
	}
	if text != "v0.6.1 [1]." {
		t.Fatalf("answer %q", text)
	}
	// From the start, on the new process: every event once, the old process's first.
	all := followAll(t, c2, tk.Task, 0)
	contiguous(t, all, 1)
	if len(all) != last+len(rest) {
		t.Fatalf("%d events from the start, want %d", len(all), last+len(rest))
	}
	for i, e := range before {
		a, _ := json.Marshal(e.ev)
		b, _ := json.Marshal(all[i].ev)
		if !bytes.Equal(a, b) {
			t.Fatalf("event %d changed across the restart: %s vs %s", e.seq, a, b)
		}
	}
	st := waitTask(t, c2, tk.Task, func(s *agentclient.Task) bool { return s.State == harness.StateDone })
	if st.Attempt != 2 || st.Outcome != harness.OutcomeSucceeded || st.Events != len(all) {
		t.Fatalf("status %+v", st)
	}
	fs.mu.Lock()
	searches := len(fs.queries)
	fs.mu.Unlock()
	if searches != 1 || m.calls.Load() != 3 {
		t.Fatalf("searches %d (want 1), model calls %d (want 3: the cut one ran again)", searches, m.calls.Load())
	}
	// Another user can't see it, follow it or cancel it (the same answer as for no task), even with the run's
	// secret; the right user without the secret (the relay sets the tag, never sees the secret) can't either.
	other := p2.conn(t, "fedcba9876543210fedc")
	other.SetTaskSecret(tk.Task, c1.TaskSecret(tk.Task))
	relay := p2.conn(t, tasksUser)
	for _, err := range []error{
		func() error { _, err := relay.TaskStatus(context.Background(), tk.Task); return err }(),
		func() error { _, err := relay.CancelTask(context.Background(), tk.Task); return err }(),
		relay.FollowTask(context.Background(), tk.Task, 0, func(int, proto.Event) {}),
		func() error {
			relay.SetTaskSecret(tk.Task, strings.Repeat("ab", 32))
			_, err := relay.TaskStatus(context.Background(), tk.Task)
			return err
		}(),
	} {
		if err == nil || !strings.Contains(err.Error(), "404") {
			t.Fatalf("no or a wrong MAC: %v", err)
		}
	}
	for _, err := range []error{
		func() error { _, err := other.TaskStatus(context.Background(), tk.Task); return err }(),
		func() error { _, err := other.CancelTask(context.Background(), tk.Task); return err }(),
		other.FollowTask(context.Background(), tk.Task, 0, func(int, proto.Event) {}),
		func() error { _, err := other.TaskStatus(context.Background(), harness.NewTaskID()); return err }(),
	} {
		if err == nil || !strings.Contains(err.Error(), "404") {
			t.Fatalf("another user: %v", err)
		}
	}
	// Kept a day, then deleted.
	if n := p2.s.tasks().Prune(time.Now()); n != 0 {
		t.Fatalf("pruned %d right away", n)
	}
	if n := p2.s.tasks().Prune(time.Now().Add(25 * time.Hour)); n != 1 {
		t.Fatalf("pruned %d after a day", n)
	}
	if _, err := c2.TaskStatus(context.Background(), tk.Task); err == nil {
		t.Fatal("a pruned task is still there")
	}
	if evs, _ := p2.q.Events(tk.Task, 0, 10); len(evs) != 0 {
		t.Fatalf("a pruned task's events: %d", len(evs))
	}
}

// The same start twice (a retry, a double click) with the same key is the same task: nothing runs twice, also
// after a restart. Another user's key, or another key, is another task.
func TestTasksDuplicateStart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "queue.db")
	m := newStepModel(t, pText("one"), pText("two"), pText("three"))
	p1 := bootTasks(t, path, m, &fakeSearch{}, false)
	c := p1.conn(t, tasksUser)
	req := proto.RunRequest{Permissions: guard.AllowAll(), Messages: user1("once please")}
	a, err := c.StartTask(context.Background(), req, "k-1")
	if err != nil || a.Existing {
		t.Fatalf("first: %+v %v", a, err)
	}
	b, err := c.StartTask(context.Background(), req, "k-1")
	if err != nil || !b.Existing || b.Task != a.Task {
		t.Fatalf("again: %+v %v", b, err)
	}
	if evs := followAll(t, c, a.Task, 0); evs[len(evs)-1].ev.Type != "done" {
		t.Fatalf("events %s", evTypes(evs))
	}
	if m.calls.Load() != 1 {
		t.Fatalf("model calls %d after two starts with one key", m.calls.Load())
	}
	p1.kill()
	p2 := bootTasks(t, path, m, &fakeSearch{}, false)
	c = p2.conn(t, tasksUser)
	if again, err := c.StartTask(context.Background(), req, "k-1"); err != nil || !again.Existing || again.Task != a.Task ||
		again.State != harness.StateDone {
		t.Fatalf("after a restart: %+v %v", again, err)
	}
	if m.calls.Load() != 1 {
		t.Fatalf("model calls %d after a restart", m.calls.Load())
	}
	other, err := p2.conn(t, "fedcba9876543210fedc").StartTask(context.Background(), req, "k-1")
	if err != nil || other.Existing || other.Task == a.Task {
		t.Fatalf("another user's key: %+v %v", other, err)
	}
	k2, err := c.StartTask(context.Background(), req, "k-2")
	if err != nil || k2.Existing || k2.Task == a.Task {
		t.Fatalf("another key: %+v %v", k2, err)
	}
	if _, err := c.StartTask(context.Background(), req, "bad key"); err == nil {
		t.Fatal("a key with a space was taken")
	}
}

// A request held for a decision survives an agentd restart held (the task waits, before and after), and
// cancelling the task then ends it without the held search ever running.
func TestTasksCancelDuringHeldRequest(t *testing.T) {
	path := filepath.Join(t.TempDir(), "queue.db")
	fs := &fakeSearch{}
	m := newStepModel(t, pCalls([3]string{"c1", "web_search", `{"query":"dstack release"}`}), pText("never"))
	p1 := bootTasks(t, path, m, fs, true)
	c1 := p1.conn(t, tasksUser)
	tk, err := c1.StartTask(context.Background(), proto.RunRequest{Permissions: guard.AllowAll(), Messages: user1("latest dstack?")}, "")
	if err != nil {
		t.Fatal(err)
	}
	waitTask(t, c1, tk.Task, func(s *agentclient.Task) bool {
		return s.State == harness.StateWaiting && s.Sub == harness.WaitApproval && s.Held == 1
	})
	p1.kill()
	p2 := bootTasks(t, path, m, fs, true)
	c2 := p2.conn(t, tasksUser)
	c2.SetTaskSecret(tk.Task, c1.TaskSecret(tk.Task))
	st := waitTask(t, c2, tk.Task, func(s *agentclient.Task) bool { return s.State == harness.StateWaiting })
	if st.Sub != harness.WaitApproval || st.Held != 1 {
		t.Fatalf("after the restart: %+v", st)
	}
	time.Sleep(200 * time.Millisecond) // the new brain re-sent the held search: it waits, not interrupted
	if st, _ := c2.TaskStatus(context.Background(), tk.Task); st.State != harness.StateWaiting || st.Held != 1 {
		t.Fatalf("held after the brain resumed: %+v", st)
	}
	if _, err := c2.CancelTask(context.Background(), tk.Task); err != nil {
		t.Fatal(err)
	}
	evs := followAll(t, c2, tk.Task, 0)
	if e := evs[len(evs)-1].ev; e.Type != "error" || e.Error != "run cancelled" {
		t.Fatalf("events %s, last %+v", evTypes(evs), e)
	}
	waitTask(t, c2, tk.Task, func(s *agentclient.Task) bool { return s.State == harness.StateCancelled })
	fs.mu.Lock()
	defer fs.mu.Unlock()
	if len(fs.queries) != 0 || m.calls.Load() != 1 {
		t.Fatalf("searches %v, model calls %d", fs.queries, m.calls.Load())
	}
	// The task ended: its journal keeps the held search's id and done mark only (harness.Store.Scrub), so it can't run.
	recs, _ := p2.q.Journal(tk.Task)
	for _, r := range recs {
		if r.Kind == harness.TypeAction && (!r.Done || r.Req != nil || r.Body != nil || r.Held != harness.WaitApproval) {
			t.Fatalf("the held search's journal entry: %+v", r)
		}
	}
}

// startTaskOn starts a task over EHBP on s and follows it to its end.
func runTask(t *testing.T, s *server, req proto.RunRequest) (string, []seqEvent) {
	t.Helper()
	c := connTo(t, s, tasksUser)
	tk, err := c.StartTask(context.Background(), req, "")
	if err != nil {
		t.Fatal(err)
	}
	return tk.Task, followAll(t, c, tk.Task, 0)
}

// The kill switch ends a task as it ends a run: a stop cancels it within seconds, its stream says which control,
// its record names the tk_ id and the stop.
func TestTasksKillSwitch(t *testing.T) {
	block := make(chan struct{})
	page := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-block:
		case <-r.Context().Done():
		}
	}))
	defer page.Close()
	defer close(block)
	e := newSafeEnv(t, pCalls([3]string{"c1", "fetch_page", `{"url":"` + page.URL + `/slow"}`}), pText("never"))
	e.mustPost(e.policy(1, nil), e.heartbeat())
	priv, _ := recipientKey(t)
	type result struct {
		id  string
		evs []seqEvent
	}
	done := make(chan result, 1)
	go func() {
		id, evs := runTask(t, e.s, e.recorded(priv, proto.RunRequest{Permissions: guard.AllowAll(), Messages: user1("read it")}))
		done <- result{id, evs}
	}()
	for deadline := time.Now().Add(5 * time.Second); e.modelReqs.Load() < 1 && time.Now().Before(deadline); {
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(200 * time.Millisecond) // the fetch is running
	t0 := time.Now()
	e.mustPost(e.stop(safety.IssuerFirm, 1, func(l *safety.StopList) { l.Stop = []safety.Target{{Firm: "f_chat", Space: testSpace}} }, e.admin))
	var r result
	select {
	case r = <-done:
	case <-time.After(15 * time.Second):
		t.Fatal("the task didn't stop")
	}
	if d := time.Since(t0); d > 3*time.Second {
		t.Fatalf("stopping took %v", d)
	}
	last := r.evs[len(r.evs)-1].ev
	if last.Type != "error" || last.Code != safety.CodeStopped {
		t.Fatalf("events %s, last %+v", evTypes(r.evs), last)
	}
	if st, _ := e.s.tasks().Status(r.id, tasksUser); st.State != harness.StateCancelled {
		t.Fatalf("status %+v", st)
	}
	runs := openedActivity(t, plainEvents(r.evs), priv, e.rec.Signer.Public())
	if len(runs) != 2 || runs[0].Run != r.id || runs[1].Run != r.id || runs[1].Status.Code != safety.CodeStopped ||
		runs[1].Status.Reason != "kill_switch" {
		t.Fatalf("records: %+v", runs)
	}
	// A new task is refused at the door while the stop holds, with its own record, and nothing runs.
	c := connTo(t, e.s, tasksUser)
	_, err := c.StartTask(context.Background(), e.recorded(priv, proto.RunRequest{Permissions: guard.AllowAll(), Messages: user1("again")}), "")
	if err == nil || !strings.Contains(err.Error(), "403") || !strings.Contains(err.Error(), safety.CodeStopped) {
		t.Fatalf("start while stopped: %v", err)
	}
	if e.modelReqs.Load() != 1 {
		t.Fatal("the model was called after the stop")
	}
}

func plainEvents(evs []seqEvent) []proto.Event {
	var out []proto.Event
	for _, e := range evs {
		out = append(out, e.ev)
	}
	return out
}

// Budgets apply to tasks as to runs: a run budget too small for a model call fails the task with
// budget_exceeded, and the model is never called; a tool-call budget refuses the calls past it.
func TestTasksBudgetExhaustion(t *testing.T) {
	e := newSafeEnv(t, pText("never"))
	e.mustPost(e.policy(1, func(p *safety.Policy) { p.Budget.Run.Tokens = 300 }), e.heartbeat())
	id, evs := runTask(t, e.s, proto.RunRequest{Permissions: guard.AllowAll(), Messages: user1("hi")})
	last := evs[len(evs)-1].ev
	if last.Type != "error" || last.Code != safety.CodeBudgetExceeded || e.modelReqs.Load() != 0 {
		t.Fatalf("events %s, last %+v, model calls %d", evTypes(evs), last, e.modelReqs.Load())
	}
	if st, _ := e.s.tasks().Status(id, tasksUser); st.State != harness.StateFailed {
		t.Fatalf("status %+v", st)
	}

	calls := [][3]string{}
	for _, c := range []string{"c1", "c2", "c3"} {
		calls = append(calls, [3]string{c, "web_search", `{"query":"q ` + c + `"}`})
	}
	e = newSafeEnv(t, pCalls(calls...), pText("done"))
	e.mustPost(e.policy(1, func(p *safety.Policy) { p.Budget.Run.ToolCalls = 2 }), e.heartbeat())
	_, evs = runTask(t, e.s, proto.RunRequest{Permissions: guard.AllowAll(), Messages: user1("search a lot")})
	refused := 0
	for _, ev := range evs {
		if ev.ev.Type == "tool_result" && strings.Contains(string(ev.ev.Result), safety.CodeBudgetExceeded) {
			refused++
		}
	}
	if evs[len(evs)-1].ev.Type != "done" || refused != 1 {
		t.Fatalf("events %s, %d refused", evTypes(evs), refused)
	}
}

// A task's budget survives a restart: what the journal shows it used counts again (journalUsage), so a restart
// can't hand a task a fresh budget.
func TestTasksBudgetAfterRestart(t *testing.T) {
	model := harness.ModelCall{Model: "gpt-oss-120b", Messages: []harness.Message{{Role: "user", Content: "q"}}}
	mreq, _ := jsonv2.Marshal(model)
	mres, _ := jsonv2.Marshal(harness.ModelResult{Message: harness.Message{Role: "assistant"}, Usage: harness.Usage{Prompt: 100, Completion: 50}})
	search, _ := jsonv2.Marshal(harness.Action{Name: "web.search", Args: jsontext.Value(`{}`), Call: "c1"})
	fetch, _ := jsonv2.Marshal(harness.Action{Name: "web.fetch", Args: jsontext.Value(`{}`), Call: "c2"})
	held, _ := jsonv2.Marshal(harness.Action{Name: "web.search", Args: jsontext.Value(`{}`), Call: "c3"})
	ok, _ := jsonv2.Marshal(harness.ActionResult{Status: harness.ActionDone})
	no, _ := jsonv2.Marshal(harness.ActionResult{Status: harness.ActionDenied})
	recs := []harness.Record{
		{ID: "m1", Kind: harness.TypeModelCall, Req: mreq, Done: true, Body: mres},
		{ID: "a1", Kind: harness.TypeAction, Req: search, Done: true, Body: ok},
		{ID: "a2", Kind: harness.TypeAction, Req: fetch, Done: false},               // may have run: counted
		{ID: "a3", Kind: harness.TypeAction, Req: fetch, Done: true, Body: no},      // denied: used nothing
		{ID: "a4", Kind: harness.TypeAction, Req: held, Held: harness.WaitApproval}, // held, never ran
		{ID: "m2", Kind: harness.TypeModelCall, Req: mreq},                          // cut mid-stream: its prompt
	}
	u := journalUsage(recs)
	prompt := safety.EstimateTokens(len(mreq))
	want := safety.Usage{Tokens: 150 + prompt, ToolCalls: 2,
		CostMicros: safety.ModelCost("gpt-oss-120b", 100, 50) + safety.SearchCost + safety.ModelCost("gpt-oss-120b", prompt, 0)}
	if u != want {
		t.Fatalf("usage %+v, want %+v", u, want)
	}
	l := &safety.Ledger{}
	sg := &safeGateway{ledger: l}
	started := time.Now().Add(-time.Minute)
	sg.ResumeTask("tk_x", &harness.Start{Space: testSpace}, guard.TaskOptions{Space: testSpace}, started, recs)
	if got, ok := l.Used("tk_x"); !ok || got != want {
		t.Fatalf("ledger after resume: %+v %v", got, ok)
	}
	if el, _ := l.Elapsed("tk_x"); el < time.Minute {
		t.Fatalf("running time %v: counted from the restart, not the start", el)
	}
	b := safety.Budgets{Run: safety.Limits{ToolCalls: 2}}
	if _, err := l.Reserve("tk_x", safety.Usage{ToolCalls: 1}, b); err == nil {
		t.Fatal("a third tool call fit a budget of 2 after the restart")
	}
}

// /run is a shim over the task model and keeps its old contract: tk_ ids on the record, nothing left in the queue
// when it ends, and a /run task can't be followed or cancelled through the task API.
func TestRunShimLeavesNothing(t *testing.T) {
	e := newSafeEnv(t, pText("hello"))
	e.mustPost(e.policy(1, nil), e.heartbeat())
	priv, _ := recipientKey(t)
	evs := runParity(t, e.s, e.recorded(priv, proto.RunRequest{Permissions: guard.AllowAll(), Messages: user1("hi")}))
	if evs[len(evs)-1].Type != "done" {
		t.Fatalf("events %s", types(evs))
	}
	runs := openedActivity(t, evs, priv, e.rec.Signer.Public())
	if len(runs) != 2 || !harness.ValidTaskID(runs[0].Run) {
		t.Fatalf("records %+v", runs)
	}
	id := runs[0].Run
	if st, err := e.s.rt.Store.Task(id); err != nil || st != nil {
		t.Fatalf("the /run task is still in the queue: %+v %v", st, err)
	}
	if evs, _ := e.s.rt.Store.Events(id, 0, 10); len(evs) != 0 {
		t.Fatalf("its events are still in the queue: %d", len(evs))
	}
	if _, err := e.s.tasks().Status(id, ""); !errors.Is(err, guard.ErrNoTask) {
		t.Fatalf("status of a /run task: %v", err)
	}
	// A refused run's record has a tk_ id too.
	e.mustPost(e.stop(safety.IssuerFirm, 1, func(l *safety.StopList) { l.Stop = []safety.Target{{Firm: "f_chat", Space: testSpace}} }, e.admin))
	evs = runParity(t, e.s, e.recorded(priv, proto.RunRequest{Permissions: guard.AllowAll(), Messages: user1("hi")}))
	var refused []*activity.Run
	for _, ev := range evs {
		if ev.Type == "activity" {
			for _, raw := range ev.Activity {
				var s activity.Sealed
				json.Unmarshal(raw, &s)
				_, body, err := activity.Open(s, priv, func(string) bool { return true })
				if err != nil {
					t.Fatal(err)
				}
				refused = append(refused, body)
			}
		}
	}
	if len(refused) != 1 || refused[0].Event != activity.EventRefused || !harness.ValidTaskID(refused[0].Run) {
		t.Fatalf("refused record %+v", refused)
	}
}

// The task calls need a user tag (the grant doesn't: its MAC is enough), a start needs a run secret (the later calls
// carry a MAC with it), and one user can hold at most maxUserFollowers event streams of the 64.
func TestTasksAuthAndStreamCaps(t *testing.T) {
	s := &server{token: "tok"}
	reached := false
	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached = true })
	call := func(needTag bool, tag string) int {
		r := httptest.NewRequest("POST", "/tasks/status", strings.NewReader("x"))
		r.Header.Set("Authorization", "Bearer tok")
		r.Header.Set(ehbpproto.EncapsulatedKeyHeader, strings.Repeat("ab", 32))
		if tag != "" {
			r.Header.Set("X-Agent-User", tag)
		}
		w := httptest.NewRecorder()
		s.taskGuard(false, needTag, next).ServeHTTP(w, r)
		return w.Code
	}
	if code := call(true, ""); code != 400 || reached {
		t.Fatalf("no tag: %d", code)
	}
	if code := call(true, tasksUser); code != 200 || !reached {
		t.Fatalf("with a tag: %d", code)
	}
	reached = false
	if code := call(false, ""); code != 200 || !reached {
		t.Fatalf("grant without a tag: %d", code)
	}
	w := httptest.NewRecorder()
	s.taskStart(w, httptest.NewRequest("POST", "/tasks", strings.NewReader(`{"messages":[{"role":"user","content":"hi"}]}`)))
	if w.Code != 400 || !strings.Contains(w.Body.String(), "run_secret_required") {
		t.Fatalf("start without a run secret: %d %s", w.Code, w.Body)
	}
	s.tasks()
	for i := range maxUserFollowers {
		if !s.followSlot("a") {
			t.Fatalf("slot %d refused", i)
		}
	}
	if s.followSlot("a") {
		t.Fatal("one user took more than its share of streams")
	}
	if !s.followSlot("b") {
		t.Fatal("another user was refused")
	}
	s.followDone("a")
	if !s.followSlot("a") {
		t.Fatal("a freed slot wasn't given back")
	}
}

// The billing witness the relay reads (plaintext headers; the bodies stay encrypted): a start says new or existing
// and the task's bill id; a cancel before any model output is refundable once, and never after output.
func TestTasksBillingWitness(t *testing.T) {
	path := filepath.Join(t.TempDir(), "queue.db")
	m := newStepModel(t, "block")
	p := bootTasks(t, path, m, &fakeSearch{}, false)
	c := p.conn(t, tasksUser)
	ctx := context.Background()
	req := proto.RunRequest{Permissions: guard.AllowAll(), Messages: user1("a slow one")}
	tk, err := c.StartTask(ctx, req, "key-1")
	if err != nil || tk.Billing.Start != "new" || len(tk.Billing.Bill) != 32 {
		t.Fatalf("start: %+v %v", tk, err)
	}
	again, err := c.StartTask(ctx, req, "key-1")
	if err != nil || again.Task != tk.Task || again.Billing.Start != "existing" || again.Billing.Bill != tk.Billing.Bill {
		t.Fatalf("repeated start: %+v %v", again, err)
	}
	if p.s.tasks().Bill(tk.Task) == p.s.tasks().Bill("tk_other") {
		t.Fatal("bill ids must differ per task")
	}
	waitCalls(t, m, 1) // the model call is waiting: no output yet
	if n := p.s.tasks().Open(); n != 1 {
		t.Fatalf("open tasks %d, want 1", n)
	}
	got, err := c.CancelTask(ctx, tk.Task)
	if err != nil || !got.Billing.Refundable || got.Billing.Bill != tk.Billing.Bill {
		t.Fatalf("first cancel: %+v %v", got, err)
	}
	if got, err := c.CancelTask(ctx, tk.Task); err != nil || got.Billing.Refundable {
		t.Fatalf("second cancel must not be refundable: %+v %v", got, err)
	}
	waitTask(t, c, tk.Task, func(s *agentclient.Task) bool { return s.Outcome != "" })
	for deadline := time.Now().Add(5 * time.Second); p.s.tasks().Open() != 0; time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("open tasks %d after the cancel, want 0", p.s.tasks().Open())
		}
	}

	// After model output (a tool call), a cancel is never refundable.
	m2 := newStepModel(t, pCalls([3]string{"c1", "web_search", `{"query":"x"}`}), "block")
	p2 := bootTasks(t, filepath.Join(t.TempDir(), "queue.db"), m2, &fakeSearch{}, false)
	c2 := p2.conn(t, tasksUser)
	tk2, err := c2.StartTask(ctx, req, "")
	if err != nil {
		t.Fatal(err)
	}
	waitCalls(t, m2, 2)
	if got, err := c2.CancelTask(ctx, tk2.Task); err != nil || got.Billing.Refundable {
		t.Fatalf("cancel after output: %+v %v", got, err)
	}
}

// GET /tasks/open: the relay's bearer token only, and a count only.
func TestTasksOpenEndpoint(t *testing.T) {
	p := bootTasks(t, filepath.Join(t.TempDir(), "queue.db"), newStepModel(t, "block"), &fakeSearch{}, false)
	mux := http.NewServeMux()
	p.s.taskRoutes(mux, p.s.id)
	for _, tc := range []struct {
		auth string
		code int
		body string
	}{{"", 401, ""}, {"Bearer nope", 401, ""}, {"Bearer tok", 200, `{"open":0,"schedules":0,"next_run":null}`}} {
		r := httptest.NewRequest("GET", "/tasks/open", nil)
		if tc.auth != "" {
			r.Header.Set("Authorization", tc.auth)
		}
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		if w.Code != tc.code || tc.body != "" && strings.TrimSpace(w.Body.String()) != tc.body {
			t.Fatalf("%q: %d %s", tc.auth, w.Code, w.Body.String())
		}
	}
}

// The billing witness outlives an agentd restart: a task that had model output before it isn't refundable after it.
func TestTasksBillingWitnessAfterRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "queue.db")
	fs := &fakeSearch{}
	m := newStepModel(t, pCalls([3]string{"c1", "web_search", `{"query":"x"}`}), "block", "block")
	p1 := bootTasks(t, path, m, fs, false)
	c1 := p1.conn(t, tasksUser)
	tk, err := c1.StartTask(context.Background(), proto.RunRequest{Permissions: guard.AllowAll(), Messages: user1("q")}, "")
	if err != nil {
		t.Fatal(err)
	}
	waitCalls(t, m, 2)
	// Its events (the tool call among them) are in the queue before the process dies.
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(20 * time.Millisecond) {
		st, err := c1.TaskStatus(context.Background(), tk.Task)
		if err == nil && st.Events >= 3 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("events not stored: %+v %v", st, err)
		}
	}
	p1.kill()
	p2 := bootTasks(t, path, m, fs, false)
	c2 := p2.conn(t, tasksUser)
	c2.SetTaskSecret(tk.Task, c1.TaskSecret(tk.Task))
	got, err := c2.CancelTask(context.Background(), tk.Task)
	if err != nil || got.Billing.Refundable {
		t.Fatalf("cancel after a restart, with output before it: %+v %v", got, err)
	}
}
