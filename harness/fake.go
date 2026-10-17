package harness

import (
	"context"
	"encoding/json/jsontext"
	"net"
	"sync"
)

// MemStore is a Store in memory: the fake runtime's, and the reference for the SQLite one (../queue). Several
// runtimes may share one (tests: a runtime restart keeps the store).
type MemStore struct {
	mu     sync.Mutex
	tasks  map[string]*memTask
	torder []string // task ids, in the order added
	recs   map[string]*Record
	order  map[string][]string // request ids per task, in the order begun
	cps    map[string]*Checkpoint
}

type memTask struct {
	st    StoredTask
	ended bool
}

func NewMemStore() *MemStore {
	return &MemStore{tasks: map[string]*memTask{}, recs: map[string]*Record{}, order: map[string][]string{},
		cps: map[string]*Checkpoint{}}
}

func (m *MemStore) AddTask(id string, start, opts jsontext.Value) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.tasks[id] != nil {
		return errf("task %s exists", id)
	}
	m.tasks[id] = &memTask{st: StoredTask{ID: id, Start: start.Clone(), Options: opts.Clone()}}
	m.torder = append(m.torder, id)
	return nil
}

func (m *MemStore) SetAttempt(id string, n int) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if t := m.tasks[id]; t != nil {
		t.st.Attempt = n
	}
	return nil
}

func (m *MemStore) AddSteer(id string, st Steer) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if t := m.tasks[id]; t != nil {
		t.st.Steers = append(t.st.Steers, st)
	}
	return nil
}

func (m *MemStore) EndTask(id string, _ Outcome) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if t := m.tasks[id]; t != nil {
		t.ended = true
	}
	return nil
}

func (m *MemStore) OpenTasks() ([]StoredTask, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []StoredTask
	for _, id := range m.torder {
		if t := m.tasks[id]; t != nil && !t.ended {
			st := t.st
			st.Steers = append([]Steer(nil), t.st.Steers...)
			out = append(out, st)
		}
	}
	return out, nil
}

func (m *MemStore) DeleteTask(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.tasks, id)
	for i, x := range m.torder {
		if x == id {
			m.torder = append(m.torder[:i:i], m.torder[i+1:]...)
			break
		}
	}
	for _, rid := range m.order[id] {
		delete(m.recs, id+"\x00"+rid)
	}
	delete(m.order, id)
	delete(m.cps, id)
	return nil
}

func (m *MemStore) Begin(task, id, kind string, hash [32]byte, req jsontext.Value) (Record, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if r := m.recs[task+"\x00"+id]; r != nil {
		return *r, false, nil
	}
	r := &Record{ID: id, Kind: kind, Hash: hash, Req: req.Clone()}
	m.recs[task+"\x00"+id] = r
	m.order[task] = append(m.order[task], id)
	return *r, true, nil
}

func (m *MemStore) Journal(task string) ([]Record, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Record
	for _, id := range m.order[task] {
		out = append(out, *m.recs[task+"\x00"+id])
	}
	return out, nil
}

func (m *MemStore) Finish(task, id string, body jsontext.Value, e *Error) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if r := m.recs[task+"\x00"+id]; r != nil {
		r.Done, r.Body, r.Err = true, body.Clone(), e
	}
	return nil
}

func (m *MemStore) SaveCheckpoint(task string, cp *Checkpoint) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	c := *cp
	c.State = append([]byte(nil), cp.State...)
	m.cps[task] = &c
	return nil
}

func (m *MemStore) Checkpoint(task string) (*Checkpoint, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if c := m.cps[task]; c != nil {
		cp := *c
		return &cp, nil
	}
	return nil, nil
}

// Fake is the runtime for local development (no gVisor, no network, no model) and for the conformance suite: the
// real protocol engine (Runtime) with a MemStore and a scripted guard. Replace Model, Actions and Exec to script
// it; the defaults echo.
type Fake struct {
	*Runtime
	Mem *MemStore
	// Model answers fresh model calls (replays come from the journal). Default: echoes the last user message.
	Model func(ctx context.Context, t *TaskInfo, req *ModelCall) (*ModelResult, error)
	// Actions run actions by name. A name without one returns done with {"ok":true}.
	Actions map[string]func(ctx context.Context, t *TaskInfo, args jsontext.Value) (*ActionResult, error)
	// Exec runs exec requests. Default: exit 0 with "stub" on stdout.
	Exec func(ctx context.Context, t *TaskInfo, req *Exec) (*ExecResult, error)
	// Safe names the actions that are "replay: safe" (rerun after a runtime restart interrupted them). Model calls
	// always are; exec never.
	Safe map[string]bool

	mu     sync.Mutex
	runs   map[string]int // actions run, by task\x00name
	models map[string]int // fresh model calls, by task
}

func NewFake() *Fake { return NewFakeWith(NewMemStore()) }

// NewFakeWith is a fake runtime on an existing store: a runtime process restarted with its journal and checkpoints.
func NewFakeWith(mem *MemStore) *Fake {
	f := NewFakeOn(mem)
	f.Mem = mem
	return f
}

// NewFakeOn is a fake runtime on any Store (the SQLite one, in its tests). Mem is nil.
func NewFakeOn(store Store) *Fake {
	f := &Fake{Actions: map[string]func(context.Context, *TaskInfo, jsontext.Value) (*ActionResult, error){},
		runs: map[string]int{}, models: map[string]int{}}
	f.Runtime = &Runtime{Guard: fakeGuard{f}, Store: store, Info: Info{Name: "fake-runtime", Version: "dev"}}
	return f
}

// ActionRuns is how many times the guard ran action name for the task.
func (f *Fake) ActionRuns(task, name string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.runs[task+"\x00"+name]
}

// ModelCalls is how many model calls of the task reached the model (replays answered from the journal don't).
func (f *Fake) ModelCalls(task string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.models[task]
}

// SendRaw writes b as is to the connected brain (tests: malformed and oversize frames). False when none.
func (f *Fake) SendRaw(b []byte) bool {
	f.init()
	f.Runtime.mu.Lock()
	defer f.Runtime.mu.Unlock()
	if f.sess == nil {
		return false
	}
	f.sess.send(outItem{raw: append([]byte(nil), b...)})
	return true
}

// Listen serves brains connecting to a unix socket at path until ctx ends (local dev: point a brain at it).
func (f *Fake) Listen(ctx context.Context, path string) error {
	l, err := net.Listen("unix", path)
	if err != nil {
		return err
	}
	context.AfterFunc(ctx, func() { l.Close() })
	for {
		c, err := l.Accept()
		if err != nil {
			return ctx.Err()
		}
		go f.Serve(ctx, c)
	}
}

type fakeGuard struct{ f *Fake }

func (g fakeGuard) ModelCall(ctx context.Context, t *TaskInfo, req *ModelCall) (*ModelResult, error) {
	g.f.mu.Lock()
	g.f.models[t.ID]++
	g.f.mu.Unlock()
	if g.f.Model != nil {
		return g.f.Model(ctx, t, req)
	}
	last := ""
	for _, m := range req.Messages {
		if m.Role == "user" {
			last = m.Content
		}
	}
	return Text("echo: " + last), nil
}

func (g fakeGuard) Action(ctx context.Context, t *TaskInfo, _ string, req *Action) (*ActionResult, error) {
	g.f.mu.Lock()
	g.f.runs[t.ID+"\x00"+req.Name]++
	fn := g.f.Actions[req.Name]
	g.f.mu.Unlock()
	if fn != nil {
		return fn(ctx, t, req.Args)
	}
	return &ActionResult{Status: ActionDone, Output: jsontext.Value(`{"ok":true}`)}, nil
}

func (g fakeGuard) ReplaySafe(_ *TaskInfo, req any) bool {
	switch b := req.(type) {
	case *ModelCall:
		return true
	case *Action:
		g.f.mu.Lock()
		defer g.f.mu.Unlock()
		return g.f.Safe[b.Name]
	}
	return false
}

func (g fakeGuard) Exec(ctx context.Context, t *TaskInfo, _ string, req *Exec) (*ExecResult, error) {
	if g.f.Exec != nil {
		return g.f.Exec(ctx, t, req)
	}
	return &ExecResult{Stdout: "stub"}, nil
}

// Script returns a Model that answers each task's fresh model calls with replies in order; the last repeats.
func Script(replies ...*ModelResult) func(context.Context, *TaskInfo, *ModelCall) (*ModelResult, error) {
	var mu sync.Mutex
	next := map[string]int{}
	return func(_ context.Context, t *TaskInfo, _ *ModelCall) (*ModelResult, error) {
		mu.Lock()
		defer mu.Unlock()
		i := min(next[t.ID], len(replies)-1)
		next[t.ID]++
		r := *replies[i]
		return &r, nil
	}
}

// Text is a model reply that answers without tools.
func Text(s string) *ModelResult {
	return &ModelResult{Message: Message{Role: "assistant", Content: s}, FinishReason: "stop"}
}

// Calls is a model reply that asks for tools.
func Calls(calls ...ToolCall) *ModelResult {
	return &ModelResult{Message: Message{Role: "assistant", ToolCalls: calls}, FinishReason: "tool_calls"}
}
