package harness

import (
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"net"
	"slices"
	"sync"
	"time"
)

// Guard does what a brain asks for, after the runtime's own checks (task state, tool and model lists, limits).
// The real one is the model gateway, the connectors and the hands runner; Fake's is scripted.
// It runs with the task's context, which ends when the task is cancelled or done. An *Error goes to the brain as
// it is; any other error becomes "internal".
type Guard interface {
	ModelCall(ctx context.Context, t *TaskInfo, req *ModelCall) (*ModelResult, error)
	Action(ctx context.Context, t *TaskInfo, id string, req *Action) (*ActionResult, error)
	Exec(ctx context.Context, t *TaskInfo, id string, req *Exec) (*ExecResult, error)
}

type requestIDKey struct{}

// WithRequestID is ctx carrying the id of the request a Guard call serves (the runtime sets it; gatewayd sets it
// from gateway/v0).
func WithRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, requestIDKey{}, id)
}

// RequestID is the id of the request a Guard call serves (from the ctx the runtime passes it): the brain's id for
// the model call, action or exec, as journaled. A connector ties its records (a vault lease, an egress decision)
// to it. "" outside a runtime call.
func RequestID(ctx context.Context) string {
	id, _ := ctx.Value(requestIDKey{}).(string)
	return id
}

// ReplayGuard is a Guard that says which requests are "replay: safe" (decided 2026-10-16, docs/20 open question 3):
// reads that send or change nothing (a model call, a web search). A safe request a previous runtime process
// recorded but never finished is run again after a restart instead of answered "interrupted". Anything else (a
// mail sent, an exec) is never repeated. A Guard that isn't a ReplayGuard has nothing safe.
type ReplayGuard interface {
	Guard
	// ReplaySafe reports whether req (*ModelCall, *Action or *Exec) may run again after an interruption.
	ReplaySafe(t *TaskInfo, req any) bool
}

// TaskInfo is what the guard gets to know about the task a request belongs to. Read-only.
type TaskInfo struct {
	ID    string
	Start *Start
	// Options is the runtime side's own data for the task, given to StartWith and stored with the task (the
	// person's choices for it: reasoning effort, prompt-cache scope, whose tool caps). Never sent to the brain.
	Options jsontext.Value
	// Journal returns the task's journal so far, in the order requests were recorded. A connector rebuilds its
	// per-task state from it (citation numbers, image slots, site icons seen) when this runtime process hasn't
	// seen the task before: after a runtime restart, nothing else remembers it.
	Journal func() ([]Record, error)
}

// Store holds the runtime's queue: the tasks (with their start, options, attempts and steering), the journal (the
// outbox: every model call, action and exec by task and request id) and the brain's checkpoints. The real one is
// the space's SQLite on the VM's encrypted disk (../queue; the runtime is the only writer); MemStore keeps them in
// memory. Each method is one transaction.
type Store interface {
	// AddTask records a new task: its start as first given (attempt 1, no checkpoint) and the runtime side's
	// options (TaskInfo.Options). It fails if the id exists.
	AddTask(id string, start jsontext.Value, opts jsontext.Value) error
	// SetAttempt records that a brain was given the task for the nth time (attempts count across restarts).
	SetAttempt(id string, n int) error
	// AddSteer records a steering message.
	AddSteer(id string, st Steer) error
	// EndTask records how the task ended. Ended tasks aren't restored.
	EndTask(id string, o Outcome) error
	// OpenTasks returns the tasks that haven't ended, oldest first, with their steering.
	OpenTasks() ([]StoredTask, error)
	// DeleteTask removes a task and everything recorded for it: steering, journal, checkpoints.
	DeleteTask(id string) error

	// Begin records a request (its type, hash and body) as pending before it runs. If (task, id) was recorded
	// before, it records nothing and returns that record with fresh false.
	Begin(task, id, kind string, hash [32]byte, req jsontext.Value) (rec Record, fresh bool, err error)
	// Finish stores a request's outcome: its result body or its error.
	Finish(task, id string, body jsontext.Value, e *Error) error
	// Journal returns the task's records in the order they were begun.
	Journal(task string) ([]Record, error)
	SaveCheckpoint(task string, cp *Checkpoint) error
	// Checkpoint returns the task's latest checkpoint, or nil.
	Checkpoint(task string) (*Checkpoint, error)
}

// StoredTask is a task as the Store keeps it: enough for a restarted runtime to queue it again (Restore).
type StoredTask struct {
	ID      string
	Start   jsontext.Value // the Start, as AddTask got it
	Options jsontext.Value
	Attempt int // brain starts so far
	Steers  []Steer
}

// Record is one journal entry.
type Record struct {
	ID   string // the request id
	Kind string
	Hash [32]byte
	Req  jsontext.Value // the request body
	Done bool           // false: recorded, not finished (still running, or the runtime stopped while it ran)
	Body jsontext.Value
	Err  *Error
}

// Task states the runtime keeps (waiting-for-approval and paused live in the guard: the brain just waits
// for a result). Ended tasks have an Outcome.
const (
	stateQueued  = "queued"
	stateRunning = "running"
	stateEnded   = "ended"
)

// Outcome is how a task ended. State is succeeded, failed or cancelled, decided by the runtime (a cancelled task
// is cancelled whatever the brain says).
type Outcome struct {
	State string
	Done  *Done // what the brain sent, if it sent done
}

// Runtime is the runtime side of harness/v1: it serves one brain connection at a time (a new one replaces the
// old), starts and resumes tasks on it, checks every frame and request, journals requests in the Store before
// the Guard runs them, and answers a repeated id from the journal. Set the exported fields before Serve.
type Runtime struct {
	Guard       Guard
	Store       Store
	Info        Info
	Limits      Limits // zero: DefaultLimits
	MaxAttempts int    // brain starts per task before it fails; 0: 3
	// OnReject, when set, is told about every frame from the brain the runtime refused (and closed for).
	OnReject func(error)
	// Observe, when set, sees every frame read from (in) or written to the brain: tests, a dev transcript.
	Observe func(in bool, e *Envelope)

	once  sync.Once
	mu    sync.Mutex
	tasks map[string]*task
	order []*task // queued and running, oldest first
	sess  *session
	calls map[string]*call // requests running in this process, by task\x00id
}

type task struct {
	id         string
	start      Start
	info       TaskInfo
	state      string
	outcome    Outcome
	finished   chan struct{}
	ctx        context.Context
	stop       context.CancelFunc
	sess       *session // connection it was last started on; nil when none
	attempt    int
	steers     []Steer // all steering, n = index + 1
	sent       int     // highest steer n sent on sess
	applied    int     // steer_applied of the latest checkpoint
	cpSeq      int
	modelCalls int // fresh model calls (replays don't count)
	cancelled  string
	// requested is the tool calls of the task's latest model result (fresh or replayed), id -> action name: what
	// an action's call must name.
	requested map[string]string
	// claimed is which action carries out each of those tool calls, call id -> action request id: one action per
	// tool call (a second id naming the same call is refused). Rebuilt from the journal with every model result.
	claimed map[string]string
}

// call is a request running in this process; a repeat of its id waits for it.
type call struct {
	done chan struct{}
	body jsontext.Value
	err  *Error
}

type session struct {
	conn       net.Conn
	peerMax    int
	maxTasks   int
	out        chan outItem
	closed     chan struct{}
	closeOnce  sync.Once
	writerDone chan struct{}
	inflight   map[string]bool // task\x00id; guarded by Runtime.mu
	perTask    map[string]int
}

type outItem struct {
	e   *Envelope
	raw []byte // written as is (Fake.SendRaw)
}

func (s *session) close() { s.closeOnce.Do(func() { close(s.closed) }) }

// send queues a frame without blocking; a brain that lets 1024 frames pile up is dropped.
func (s *session) send(it outItem) {
	select {
	case <-s.closed:
	case s.out <- it:
	default:
		s.close()
	}
}

func (s *session) reply(req *Envelope, body jsontext.Value, e *Error) {
	if e != nil {
		body = nil
	}
	s.send(outItem{e: &Envelope{Type: TypeResult, Task: req.Task, Re: req.ID, Body: body, Error: e}})
}

func (r *Runtime) init() {
	r.once.Do(func() {
		r.tasks = map[string]*task{}
		r.calls = map[string]*call{}
	})
}

func (r *Runtime) limits() Limits {
	l, d := r.Limits, DefaultLimits
	for _, f := range []struct{ v, d *int }{{&l.MaxFrame, &d.MaxFrame}, {&l.MaxTasks, &d.MaxTasks},
		{&l.MaxInflight, &d.MaxInflight}, {&l.IdleTimeoutMs, &d.IdleTimeoutMs}, {&l.CancelGraceMs, &d.CancelGraceMs},
		{&l.MaxCheckpoint, &d.MaxCheckpoint}} {
		if *f.v <= 0 {
			*f.v = *f.d
		}
	}
	l.MaxFrame = min(max(l.MaxFrame, MinFrame), MaxFrame)
	l.MaxCheckpoint = min(max(l.MaxCheckpoint, 1), MaxCheckpoint)
	return l
}

func (r *Runtime) observe(in bool, e *Envelope) {
	if r.Observe != nil {
		r.Observe(in, e)
	}
}

func (r *Runtime) reject(err error) *Error {
	var pe *Error
	if !errors.As(err, &pe) {
		pe = Errf(CodeBadFrame, "%v", err)
	}
	if r.OnReject != nil {
		r.OnReject(pe)
	}
	return pe
}

// ---- tasks: what the queue calls ----------------------------------------------------------------------------

// Start queues a task without options. It is sent to the brain when one is connected and has room.
func (r *Runtime) Start(id string, s Start) error { return r.StartWith(id, s, nil) }

// StartWith queues a task with the runtime side's options for it (TaskInfo.Options; a JSON value or nil). The
// task is in the Store before StartWith returns, so a restarted runtime picks it up again (Restore).
func (r *Runtime) StartWith(id string, s Start, opts jsontext.Value) error {
	r.init()
	s.Attempt, s.Checkpoint = 1, nil
	if !ValidID(id) {
		return errf("bad task id")
	}
	if err := s.validate(); err != nil {
		return err
	}
	if opts != nil && !opts.IsValid() {
		return errf("bad task options")
	}
	b, err := json.Marshal(&s)
	if err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.tasks[id] != nil {
		return errf("task %s exists", id)
	}
	if err := r.Store.AddTask(id, b, opts); err != nil {
		return Errf(CodeInternal, "task not stored: %v", err)
	}
	r.addLocked(id, s, opts.Clone(), 0, nil)
	r.dispatchLocked()
	return nil
}

// addLocked puts a task in memory: queued (attempt 0) or running without a brain (resumed by the next dispatch).
func (r *Runtime) addLocked(id string, s Start, opts jsontext.Value, attempt int, steers []Steer) {
	t := &task{id: id, start: s, state: stateQueued, finished: make(chan struct{}), attempt: attempt, steers: steers}
	if attempt > 0 {
		t.state = stateRunning
	}
	t.info = TaskInfo{ID: id, Start: &t.start, Options: opts, Journal: func() ([]Record, error) { return r.Store.Journal(id) }}
	t.ctx, t.stop = context.WithCancel(context.Background())
	r.tasks[id] = t
	r.order = append(r.order, t)
	if s.Limits.Deadline != "" {
		d, _ := time.Parse(time.RFC3339, s.Limits.Deadline)
		time.AfterFunc(time.Until(d), func() { r.Cancel(id, "deadline") })
	}
}

// Restore queues again the tasks a previous runtime process left open in the Store (call it once, before Serve):
// with their options and steering, resumed from their latest checkpoint, attempts counted on. A task past its
// deadline is cancelled at once. It returns the ids restored, oldest first.
func (r *Runtime) Restore() ([]string, error) {
	r.init()
	open, err := r.Store.OpenTasks()
	if err != nil {
		return nil, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	var ids []string
	for _, st := range open {
		var s Start
		if r.tasks[st.ID] != nil || json.Unmarshal(st.Start, &s) != nil || s.validate() != nil {
			r.Store.EndTask(st.ID, Outcome{State: OutcomeFailed, Done: &Done{Outcome: OutcomeFailed, Error: "task unreadable"}})
			continue
		}
		r.addLocked(st.ID, s, st.Options, st.Attempt, st.Steers)
		ids = append(ids, st.ID)
	}
	r.dispatchLocked()
	return ids, nil
}

// Forget deletes an ended task from the Store: its start, options, steering, journal and checkpoints. A task
// still running can't be forgotten.
func (r *Runtime) Forget(id string) error {
	r.init()
	r.mu.Lock()
	defer r.mu.Unlock()
	if t := r.tasks[id]; t != nil {
		if t.state != stateEnded {
			return errf("task %s hasn't ended", id)
		}
		delete(r.tasks, id)
	}
	return r.Store.DeleteTask(id)
}

// Connected reports whether a brain is connected.
func (r *Runtime) Connected() bool {
	r.init()
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.sess != nil
}

// Steer adds a steering message to a queued or running task and returns its n.
func (r *Runtime) Steer(id, text string) (int, error) {
	r.init()
	r.mu.Lock()
	defer r.mu.Unlock()
	t := r.tasks[id]
	switch {
	case t == nil:
		return 0, Errf(CodeUnknownTask, "")
	case t.state == stateEnded:
		return 0, Errf(CodeTaskClosed, "")
	case t.cancelled != "":
		return 0, Errf(CodeCancelled, "")
	case len(t.steers)-t.applied >= MaxPendingSteers:
		return 0, Errf(CodeLimit, "too many steering messages waiting")
	}
	st := Steer{N: len(t.steers) + 1, Text: text}
	if err := st.validate(); err != nil {
		return 0, err
	}
	if err := r.Store.AddSteer(id, st); err != nil {
		return 0, Errf(CodeInternal, "steering not stored")
	}
	t.steers = append(t.steers, st)
	if t.sess != nil {
		r.sendLocked(t.sess, TypeSteer, t.id, &st)
		t.sent = st.N
	}
	return st.N, nil
}

// Cancel cancels a task: requests in flight end with "cancelled", the brain gets cancel and has the grace period
// to send done; after that, or at once when no brain has the task, it ends as cancelled.
func (r *Runtime) Cancel(id, reason string) error {
	r.init()
	r.mu.Lock()
	defer r.mu.Unlock()
	t := r.tasks[id]
	switch {
	case t == nil:
		return Errf(CodeUnknownTask, "")
	case t.state == stateEnded:
		return Errf(CodeTaskClosed, "")
	case t.cancelled != "":
		return nil
	}
	t.cancelled = reason
	t.stop()
	if t.sess == nil {
		r.endLocked(t, Outcome{State: OutcomeCancelled})
		r.dispatchLocked()
		return nil
	}
	r.sendLocked(t.sess, TypeCancel, t.id, &Cancel{Reason: reason})
	time.AfterFunc(time.Duration(r.limits().CancelGraceMs)*time.Millisecond, func() {
		r.mu.Lock()
		defer r.mu.Unlock()
		if t.state != stateEnded {
			r.endLocked(t, Outcome{State: OutcomeCancelled})
			r.dispatchLocked()
		}
	})
	return nil
}

// Wait returns the task's outcome once it ends.
func (r *Runtime) Wait(ctx context.Context, id string) (Outcome, error) {
	r.init()
	r.mu.Lock()
	t := r.tasks[id]
	r.mu.Unlock()
	if t == nil {
		return Outcome{}, Errf(CodeUnknownTask, "")
	}
	select {
	case <-t.finished:
		r.mu.Lock()
		defer r.mu.Unlock()
		return t.outcome, nil
	case <-ctx.Done():
		return Outcome{}, ctx.Err()
	}
}

func (r *Runtime) endLocked(t *task, o Outcome) {
	if t.state == stateEnded {
		return
	}
	t.state, t.outcome, t.sess = stateEnded, o, nil
	r.Store.EndTask(t.id, o) // best effort: a task the store still has open is restored and resumed once more
	t.stop()
	close(t.finished)
	r.order = slices.DeleteFunc(r.order, func(x *task) bool { return x == t })
}

// dispatchLocked starts queued tasks and resumes running ones whose brain went away, as far as the connected
// brain has room.
func (r *Runtime) dispatchLocked() {
	s := r.sess
	if s == nil {
		return
	}
	running := 0
	for _, t := range r.order {
		if t.state == stateRunning && t.sess == s {
			running++
		}
	}
	maxAttempts := r.MaxAttempts
	if maxAttempts <= 0 {
		maxAttempts = 3
	}
	for _, t := range slices.Clone(r.order) {
		if running >= s.maxTasks {
			return
		}
		switch {
		case t.state == stateQueued:
			t.state, t.attempt = stateRunning, 1
		case t.state == stateRunning && t.sess == nil:
			if t.attempt++; t.attempt > maxAttempts {
				r.endLocked(t, Outcome{State: OutcomeFailed, Done: &Done{Outcome: OutcomeFailed, Error: "the brain stopped too often"}})
				continue
			}
		default:
			continue
		}
		r.Store.SetAttempt(t.id, t.attempt) // best effort, like EndTask
		if !r.sendStartLocked(s, t) {
			continue
		}
		running++
	}
}

// sendStartLocked sends start (with the latest checkpoint), then steering after the checkpoint, then cancel if the
// task was cancelled meanwhile.
func (r *Runtime) sendStartLocked(s *session, t *task) bool {
	cp, err := r.Store.Checkpoint(t.id)
	if err != nil {
		r.endLocked(t, Outcome{State: OutcomeFailed, Done: &Done{Outcome: OutcomeFailed, Error: "checkpoint unreadable"}})
		return false
	}
	st := t.start
	st.Attempt, st.Checkpoint = t.attempt, cp
	t.cpSeq, t.applied = 0, 0
	if cp != nil {
		t.cpSeq, t.applied = cp.Seq, cp.SteerApplied
	}
	t.sess = s
	r.sendLocked(s, TypeStart, t.id, &st)
	for _, m := range t.steers[min(t.applied, len(t.steers)):] {
		r.sendLocked(s, TypeSteer, t.id, &m)
	}
	t.sent = len(t.steers)
	if t.cancelled != "" {
		r.sendLocked(s, TypeCancel, t.id, &Cancel{Reason: t.cancelled})
	}
	return true
}

func (r *Runtime) sendLocked(s *session, typ, task string, body any) {
	b, err := json.Marshal(body)
	if err != nil {
		s.close()
		return
	}
	s.send(outItem{e: &Envelope{Type: typ, Task: task, Body: b}})
}

// ---- the connection -----------------------------------------------------------------------------------------

// Serve runs one brain connection until it closes, ctx ends, the brain breaks the protocol (the runtime sends
// error and closes) or a newer connection replaces it. Tasks outlive the connection: requests in flight finish
// and are journaled, and the next connection resumes the tasks from their checkpoints.
func (r *Runtime) Serve(ctx context.Context, conn net.Conn) error {
	r.init()
	lim := r.limits()
	defer conn.Close()
	direct := func(pe *Error) error {
		conn.SetWriteDeadline(time.Now().Add(time.Second))
		if b, err := Encode(&Envelope{Type: TypeError, Error: pe}, nil); err == nil {
			WriteFrame(conn, b, MinFrame)
		}
		return pe
	}
	conn.SetReadDeadline(time.Now().Add(HandshakeTimeout))
	frame, err := ReadFrame(conn, lim.MaxFrame)
	if err != nil {
		var pe *Error
		if errors.As(err, &pe) {
			return direct(r.reject(pe))
		}
		return err
	}
	e, body, err := Decode(frame, FromBrain)
	if err == nil && e.Type != TypeHello {
		err = Errf(CodeProtocol, "the first frame must be hello")
	}
	if err != nil {
		return direct(r.reject(err))
	}
	r.observe(true, e)
	h := body.(*Hello)
	if !slices.Contains(h.Protocols, Version) {
		return direct(Errf(CodeUnsupportedVersion, "this runtime speaks %s", Version))
	}
	lim.MaxTasks = min(lim.MaxTasks, h.MaxTasks)
	s := &session{conn: conn, peerMax: h.MaxFrame, maxTasks: lim.MaxTasks, out: make(chan outItem, 1024),
		closed: make(chan struct{}), writerDone: make(chan struct{}), inflight: map[string]bool{}, perTask: map[string]int{}}
	go r.writer(s)
	stop := context.AfterFunc(ctx, s.close)
	defer stop()
	info := r.Info
	if info.Name == "" {
		info = Info{Name: "tacy-runtime", Version: "dev"}
	}
	w, _ := json.Marshal(&Welcome{Protocol: Version, Runtime: info, Limits: lim})
	s.send(outItem{e: &Envelope{Type: TypeWelcome, Body: w}})

	r.mu.Lock()
	if old := r.sess; old != nil {
		old.close()
		r.detachLocked(old)
	}
	r.sess = s
	r.dispatchLocked()
	r.mu.Unlock()

	err = r.readLoop(s, lim)
	r.mu.Lock()
	r.detachLocked(s)
	r.mu.Unlock()
	s.close()
	<-s.writerDone
	return err
}

// detachLocked leaves s's tasks running without a brain; the next connection resumes them.
func (r *Runtime) detachLocked(s *session) {
	for _, t := range r.order {
		if t.sess == s {
			t.sess = nil
		}
	}
	if r.sess == s {
		r.sess = nil
	}
}

func (r *Runtime) readLoop(s *session, lim Limits) error {
	idle := time.Duration(lim.IdleTimeoutMs) * time.Millisecond
	for {
		s.conn.SetReadDeadline(time.Now().Add(idle))
		frame, started, err := readFrame(s.conn, lim.MaxFrame)
		if err != nil {
			var ne net.Error
			var pe *Error
			switch {
			case errors.As(err, &pe):
				s.send(outItem{e: &Envelope{Type: TypeError, Error: r.reject(pe)}})
				return pe
			case !started && errors.As(err, &ne) && ne.Timeout():
				if r.hung(s) {
					return errors.New("harness: brain silent with tasks running")
				}
				continue
			}
			return nil // closed
		}
		e, body, err := Decode(frame, FromBrain)
		if err == nil && e.Type == TypeError {
			r.observe(true, e)
			return e.Error // the brain gave up on the connection
		}
		if err == nil {
			r.observe(true, e)
			err = r.handle(s, e, body)
		}
		if err != nil {
			pe := r.reject(err)
			s.send(outItem{e: &Envelope{Type: TypeError, Error: pe}})
			return pe
		}
	}
}

// hung: tasks running on s and nothing waiting for a result (an approval wait is a request in flight).
func (r *Runtime) hung(s *session) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(s.inflight) > 0 {
		return false
	}
	for _, t := range r.order {
		if t.sess == s && t.state == stateRunning {
			return true
		}
	}
	return false
}

func (r *Runtime) writer(s *session) {
	defer close(s.writerDone)
	defer s.conn.Close()
	write := func(it outItem) bool {
		s.conn.SetWriteDeadline(time.Now().Add(writeTimeout))
		if it.raw != nil {
			_, err := s.conn.Write(it.raw)
			return err == nil
		}
		b, err := json.Marshal(it.e)
		if err != nil {
			return false
		}
		if len(b) > s.peerMax {
			if it.e.Type != TypeResult {
				return false
			}
			it.e = &Envelope{Type: TypeResult, Task: it.e.Task, Re: it.e.Re, Error: Errf(CodeLimit, "result over the brain's max_frame")}
			b, _ = json.Marshal(it.e)
		}
		if WriteFrame(s.conn, b, s.peerMax) != nil {
			return false
		}
		r.observe(false, it.e)
		return true
	}
	for {
		select {
		case it := <-s.out:
			if !write(it) {
				s.close()
				return
			}
		case <-s.closed:
			for { // flush what's queued (an error frame, typically), then close
				select {
				case it := <-s.out:
					if !write(it) {
						return
					}
				default:
					return
				}
			}
		}
	}
}

// taskFor finds the task a request names, which must be running on this connection.
func (r *Runtime) taskFor(s *session, id string, allowCancelled bool) (*task, *Error) {
	t := r.tasks[id]
	switch {
	case t == nil:
		return nil, Errf(CodeUnknownTask, "")
	case t.state == stateEnded:
		return nil, Errf(CodeTaskClosed, "")
	case t.sess != s:
		return nil, Errf(CodeUnknownTask, "not started on this connection")
	case t.cancelled != "" && !allowCancelled:
		return nil, Errf(CodeCancelled, "")
	}
	return t, nil
}

// handle acts on one valid frame. A returned error is fatal (protocol); request errors go back as results.
func (r *Runtime) handle(s *session, e *Envelope, body any) error {
	switch b := body.(type) {
	case *Hello:
		return Errf(CodeProtocol, "hello twice")
	case *Status:
		return nil // display-only; a recorder would take it from Observe
	case *Checkpoint:
		r.checkpoint(s, e, b)
	case *Done:
		r.done(s, e, b)
	case *ModelCall, *Action, *Exec:
		r.request(s, e, body)
	default:
		return Errf(CodeProtocol, "%s isn't expected here", e.Type)
	}
	return nil
}

func (r *Runtime) checkpoint(s *session, e *Envelope, cp *Checkpoint) {
	lim := r.limits()
	r.mu.Lock()
	t, pe := r.taskFor(s, e.Task, false)
	switch {
	case pe != nil:
	case cp.Seq != t.cpSeq+1:
		pe = Errf(CodeInvalid, "checkpoint seq must be %d", t.cpSeq+1)
	case cp.SteerApplied < t.applied || cp.SteerApplied > t.sent:
		pe = Errf(CodeInvalid, "steer_applied must be %d to %d", t.applied, t.sent)
	case cp.check(lim.MaxCheckpoint) != nil:
		pe = Errf(CodeLimit, "checkpoint state over %d bytes", lim.MaxCheckpoint)
	default:
		if err := r.Store.SaveCheckpoint(t.id, cp); err != nil {
			pe = Errf(CodeInternal, "checkpoint not stored")
		} else {
			t.cpSeq, t.applied = cp.Seq, cp.SteerApplied
		}
	}
	r.mu.Unlock()
	s.reply(e, jsontext.Value(`{}`), pe)
}

func (r *Runtime) done(s *session, e *Envelope, d *Done) {
	r.mu.Lock()
	t, pe := r.taskFor(s, e.Task, true)
	if pe == nil {
		o := Outcome{State: d.Outcome, Done: d}
		if t.cancelled != "" {
			o.State = OutcomeCancelled
		}
		r.endLocked(t, o)
	}
	r.mu.Unlock()
	s.reply(e, jsontext.Value(`{}`), pe)
	if pe == nil {
		r.mu.Lock()
		r.dispatchLocked()
		r.mu.Unlock()
	}
}

// allowed is the runtime's check against the task's start (models, tools, hands) and, for an action, against the
// task's latest model result: it must carry out one of its tool calls, and the only action for that call. id is
// the request's id (a replay of the action that took the call is allowed: the journal answers it).
func allowed(t *task, id string, body any) *Error {
	tools := func(name string) bool {
		return slices.ContainsFunc(t.start.Tools, func(x Tool) bool { return x.Name == name })
	}
	switch b := body.(type) {
	case *ModelCall:
		if !slices.Contains(t.start.Models, b.Model) {
			return Errf(CodeNotAllowed, "model %s isn't allowed for this task", b.Model)
		}
		for _, n := range b.Tools {
			if !tools(n) {
				return Errf(CodeNotAllowed, "tool %s isn't allowed for this task", n)
			}
		}
	case *Action:
		if !tools(b.Name) {
			return Errf(CodeNotAllowed, "action %s isn't allowed for this task", b.Name)
		}
		// Every action carries out a tool call the model asked for in the task's latest model result.
		if b.Call == "" || t.requested[b.Call] != b.Name {
			return Errf(CodeNotRequested, "call must name a %s tool call of the latest model result", b.Name)
		}
		// One action per tool call: runtime-side only, the protocol is unchanged.
		if prev, ok := t.claimed[b.Call]; ok && prev != id {
			return Errf(CodeNotRequested, "tool call %s already has an action", b.Call)
		}
	case *Exec:
		if !t.start.Hands {
			return Errf(CodeNotAllowed, "this task has no hands sandbox")
		}
	}
	return nil
}

func (r *Runtime) request(s *session, e *Envelope, body any) {
	lim := r.limits()
	key := e.Task + "\x00" + e.ID
	r.mu.Lock()
	t, pe := r.taskFor(s, e.Task, false)
	switch {
	case pe != nil:
	case s.inflight[key]:
		pe = Errf(CodeIDInFlight, "")
	case s.perTask[e.Task] >= lim.MaxInflight:
		pe = Errf(CodeLimit, "%d requests in flight", lim.MaxInflight)
	default:
		pe = allowed(t, e.ID, body)
	}
	if pe != nil {
		r.mu.Unlock()
		s.reply(e, nil, pe)
		return
	}
	if a, ok := body.(*Action); ok {
		if t.claimed == nil {
			t.claimed = map[string]string{}
		}
		t.claimed[a.Call] = e.ID // before the next frame is read: a second action for the call is refused
	}
	s.inflight[key] = true
	s.perTask[e.Task]++
	r.mu.Unlock()
	go func() {
		body, pe := r.run(s, t, e, body, key)
		var calls, claimed map[string]string
		if e.Type == TypeModelCall && pe == nil && body != nil {
			calls = requestedCalls(body)
			claimed = r.claimedAfter(t.id, e.ID, calls)
		}
		r.mu.Lock()
		delete(s.inflight, key)
		s.perTask[e.Task]--
		if calls != nil {
			t.requested, t.claimed = calls, claimed // before the brain sees the result, so its actions find them
		}
		r.mu.Unlock()
		if body != nil || pe != nil {
			s.reply(e, body, pe) // dropped if the brain is gone: the outcome is journaled for its successor
		}
	}()
}

// claimedAfter is which journaled actions already carry out the tool calls of model call modelID's result: those
// recorded after it whose call is one of calls (call id -> action request id). A replayed model result (a brain
// restart, or a runtime restart) so keeps the actions its calls already have, even from an earlier process. On a
// journal error every call counts as taken (fail closed: no action runs for this result).
func (r *Runtime) claimedAfter(task, modelID string, calls map[string]string) map[string]string {
	claimed := map[string]string{}
	recs, err := r.Store.Journal(task)
	if err != nil {
		for c := range calls {
			claimed[c] = "\x00"
		}
		return claimed
	}
	after := false
	for _, rec := range recs {
		if rec.Kind == TypeModelCall && rec.ID == modelID {
			after = true
			continue
		}
		if !after || rec.Kind != TypeAction {
			continue
		}
		var a Action
		if json.Unmarshal(rec.Req, &a) == nil && calls[a.Call] == a.Name {
			if _, ok := claimed[a.Call]; !ok {
				claimed[a.Call] = rec.ID
			}
		}
	}
	return claimed
}

// requestedCalls is a model result's tool calls, id -> action name (empty, not nil, when it has none).
func requestedCalls(body jsontext.Value) map[string]string {
	var m ModelResult
	calls := map[string]string{}
	if json.Unmarshal(body, &m) == nil {
		for _, c := range m.Message.ToolCalls {
			calls[c.ID] = c.Name
		}
	}
	return calls
}

// run answers one request: from the journal when its id was seen, else by recording it, running it through the
// guard and recording the outcome. Ids are once-only: the guard never sees the same (task, id) twice.
func (r *Runtime) run(s *session, t *task, e *Envelope, body any, key string) (jsontext.Value, *Error) {
	hash := RequestHash(e.Type, e.Body)
	r.mu.Lock()
	rec, fresh, err := r.Store.Begin(t.id, e.ID, e.Type, hash, e.Body)
	var c *call
	over, rerun := false, false
	if err == nil && !fresh {
		c = r.calls[key]
		// Recorded by an earlier runtime process that stopped before it finished (pending, nothing running it
		// here): a safe read runs again, under this process's call so a repeat of the id waits for it.
		rerun = c == nil && !rec.Done && rec.Kind == e.Type && rec.Hash == hash && r.replaySafe(t, body)
	}
	if err == nil && (fresh || rerun) {
		c = &call{done: make(chan struct{})}
		r.calls[key] = c
		if e.Type == TypeModelCall {
			t.modelCalls++
			over = t.modelCalls > t.start.Limits.MaxModelCalls
		}
	}
	r.mu.Unlock()
	switch {
	case err != nil:
		return nil, Errf(CodeInternal, "journal unavailable")
	case rerun:
	case !fresh && (rec.Kind != e.Type || rec.Hash != hash):
		return nil, Errf(CodeIDConflict, "id %s was used for another request", e.ID)
	case !fresh && rec.Done:
		return rec.Body, rec.Err
	case !fresh && c != nil:
		select {
		case <-c.done:
			return c.body, c.err
		case <-s.closed:
			return nil, nil
		}
	case !fresh:
		// Recorded by an earlier runtime process that stopped before it finished, and not a safe read: it may or
		// may not have happened, so it isn't run again.
		pe := Errf(CodeInterrupted, "the runtime restarted while this ran")
		r.Store.Finish(t.id, e.ID, nil, pe)
		return nil, pe
	}
	var out jsontext.Value
	var pe *Error
	if over {
		pe = Errf(CodeLimit, "model call limit reached")
	} else {
		out, pe = r.guard(t, e.ID, body)
	}
	if err := r.Store.Finish(t.id, e.ID, out, pe); err != nil {
		out, pe = nil, Errf(CodeInternal, "outcome not recorded")
	}
	c.body, c.err = out, pe
	close(c.done)
	r.mu.Lock()
	delete(r.calls, key)
	r.mu.Unlock()
	return out, pe
}

// replaySafe: whether the guard declares req safe to run again after an interruption.
func (r *Runtime) replaySafe(t *task, req any) bool {
	g, ok := r.Guard.(ReplayGuard)
	return ok && g.ReplaySafe(&t.info, req)
}

// guard runs a request through the Guard and encodes its result, checking it as a brain would.
func (r *Runtime) guard(t *task, id string, body any) (jsontext.Value, *Error) {
	var res validator
	var err error
	ctx := WithRequestID(t.ctx, id)
	switch b := body.(type) {
	case *ModelCall:
		var m *ModelResult
		if m, err = r.Guard.ModelCall(ctx, &t.info, b); m != nil {
			res = m
		}
	case *Action:
		var a *ActionResult
		if a, err = r.Guard.Action(ctx, &t.info, id, b); a != nil {
			res = a
		}
	case *Exec:
		var x *ExecResult
		if x, err = r.Guard.Exec(ctx, &t.info, id, b); x != nil {
			res = x
		}
	}
	if err != nil {
		var pe *Error
		switch {
		case t.ctx.Err() != nil:
			return nil, Errf(CodeCancelled, "")
		case errors.As(err, &pe):
			return nil, pe
		default:
			return nil, Errf(CodeInternal, "")
		}
	}
	if res == nil || res.validate() != nil {
		return nil, Errf(CodeInternal, "bad result from the guard")
	}
	b, err := json.Marshal(res)
	if err != nil {
		return nil, Errf(CodeInternal, "")
	}
	return b, nil
}
