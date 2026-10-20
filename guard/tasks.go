package guard

import (
	"context"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	jsonv2 "encoding/json/v2"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/tacyhq/tacy/harness"
	"github.com/tacyhq/tacy/proto"
)

// The task model's front (docs/27 section 1, slice 1). A task no longer belongs to the tab that started it: Host
// starts a chat request as a task on the runtime, keeps the events the guard emits for it in the queue (the events
// table, on the VM's encrypted disk) until it ends plus a day, lets the person who started it follow it from any
// event, cancel it and see its state, and ends it (its activity record, then done or error) whether or not anyone
// is following. A task survives an agentd restart: the runtime restores it from the queue and Resume takes it up
// again. POST /run is a shim over it (Run): start on the built-in chat definition, then follow; it cancels the task
// when its tab goes away and deletes it when it ends, as /run always did.

// Via says how a task was started (TaskOptions.Via).
const (
	ViaRun   = "run"   // POST /run's shim: followed by its one request, deleted when it ends, abandoned at a restart
	ViaTasks = "tasks" // POST /tasks: kept until it ends plus Keep, followed by its starter, resumed after a restart
	// ViaTrigger: started by a schedule or an inbound event for its sponsor (StartTriggered); kept and resumed like
	// ViaTasks.
	ViaTrigger = "trigger"
)

// TaskResumer is a Gateway with per-task state of its own that must be taken up again when a task is resumed after
// an agentd restart (agentd's safety ledger: what the task already used of its budget; its recorder: a new start
// record). started is when the task was first started; journal its requests so far.
type TaskResumer interface {
	ResumeTask(task string, start *harness.Start, opts TaskOptions, started time.Time, journal []harness.Record)
}

// TaskFollower is a Gateway told when a resumed task's stream is live again (after TaskResumer.ResumeTask), so it
// can add to it (agentd: the permission prompts its held actions still wait for).
type TaskFollower interface {
	TaskResumed(task string, start *harness.Start, opts TaskOptions, journal []harness.Record)
}

// Host runs people's tasks on one runtime and gateway. Set the exported fields before use.
type Host struct {
	RT *harness.Runtime
	GW Gateway
	// IDKey derives once-only task ids (a per-space key from dstack's KMS, "tacy/task-ids/v1"): a start that names a
	// key gets tk_ + HMAC(IDKey, space, user, key), so a repeated start finds the first task instead of making a
	// second. nil: starts with a key are refused.
	IDKey []byte
	// Keep is how long an ended task's events and journal stay for its followers; 0: a day (docs/27 section 1). A
	// built-in agent's task may say longer (guard.AgentKeep: a_research's result stays until the browser collected
	// it, POST /tasks/delete, at most 7 days; docs/30 decision 5).
	Keep time.Duration
	// FlushEvery is how long events wait before they are written to the queue together; 0: 100 ms. A process that
	// dies loses at most that much of a stream; the task's outcome and its journal are written as they happen.
	FlushEvery time.Duration
	// MaxOpen caps the tasks one user may have open through POST /tasks (not ended); 0: 8.
	MaxOpen int
	// Forgotten, when set, is told each task Prune deleted (agentd deletes its approval records with it).
	Forgotten func(id string)
	// TriggeredDone, when set, is told when an unattended task (ViaTrigger) ended, once its last event is in the
	// queue (agentd seals its result to the space's seal key and forgets the task: schedules.go).
	TriggeredDone func(id string, opts TaskOptions)

	once    sync.Once
	mu      sync.Mutex
	live    map[string]*hosted // tasks this process serves (started here, or resumed)
	billKey []byte             // Bill's key (from IDKey, or random per process without one)
}

// hosted is one task this process serves: its guard session and its event stream.
type hosted struct {
	id    string
	user  string
	via   string
	start harness.Start
	opts  TaskOptions
	sess  Session
	// stored: the task is in the queue (its events may be written there); false until the runtime took it.
	stored bool
	st     harness.Store

	mu      sync.Mutex
	base    int // events up to this seq are in the queue from an earlier process; this one's start after it
	evs     []hostedEvent
	flushed int  // events up to this seq are written to the queue
	ended   bool // the last event is in (done or error)
	changed chan struct{}
	timer   *time.Timer
	flushMu sync.Mutex
	// sources: each citation number's address, as the task's events showed them to the person (Sources).
	sources map[int]string
	// output: a model call of the task sent something (reasoning, text or a tool call). cancelled: a person's
	// cancel came in. Both are the billing witness Cancel gives (refundable: cancelled before any output).
	output    bool
	cancelled bool
	// deleted: its starter deleted it while it ran (Delete); finished: finish is done with it. The one of finish and
	// Delete that comes second forgets it.
	deleted, finished bool
}

type hostedEvent struct {
	seq  int
	ev   proto.Event
	data []byte
}

// ErrNoTask: no task with that id that this person may see (the same answer whether or not it exists).
var ErrNoTask = errors.New("no such task")

// ErrTooMany: the person has as many open tasks as they may.
var ErrTooMany = errors.New("too many open tasks")

func (h *Host) init() {
	h.once.Do(func() {
		h.live = map[string]*hosted{}
		if len(h.IDKey) > 0 {
			h.billKey, _ = hkdf.Key(sha256.New, h.IDKey, nil, "tacy/task-bill/v1", 32)
		}
		if len(h.billKey) == 0 {
			h.billKey = make([]byte, 32)
			rand.Read(h.billKey)
		}
	})
}

// Bill is a task's opaque billing id for the relay (32 hex): HMAC(a key derived from IDKey, the task id), so it
// stays the same across agentd restarts, names the task without revealing its id, and only the VM can make it.
// The relay binds a run's charge to it, so a refund for one task can't be claimed with another's (docs/27).
func (h *Host) Bill(id string) string {
	h.init()
	m := hmac.New(sha256.New, h.billKey)
	m.Write([]byte("tacy-bill/v1\x00" + id))
	return hex.EncodeToString(m.Sum(nil)[:16])
}

// Open is how many tasks this process serves that haven't ended (POST /tasks and /run ones): the relay's idle
// timer keeps the VM on while there are any, also when nobody follows them (metadata only: a count).
func (h *Host) Open() int {
	h.init()
	h.mu.Lock()
	ls := make([]*hosted, 0, len(h.live))
	for _, l := range h.live {
		ls = append(ls, l)
	}
	h.mu.Unlock()
	n := 0
	for _, l := range ls {
		if !l.isEnded() {
			n++
		}
	}
	return n
}

// modelOutput: event types that are a model's output (the billing witness: a run cancelled before any of these
// may be refunded by the relay).
func modelOutput(t string) bool { return t == "reasoning" || t == "text" || t == "tool_call" }

func (h *Host) keep() time.Duration {
	if h.Keep > 0 {
		return h.Keep
	}
	return 24 * time.Hour
}

// keepFor is how long an ended task of agent is kept: its agent's keep (guard.AgentKeep), else Keep.
func (h *Host) keepFor(agent string) time.Duration {
	if k := AgentKeep(agent); k > 0 {
		return k
	}
	return h.keep()
}

// minAgentKeep is the shortest keep any built-in agent has (Keep for those without one of their own).
func (h *Host) minAgentKeep() time.Duration {
	m := h.keep()
	for _, id := range AgentIDs() {
		m = min(m, h.keepFor(id))
	}
	return m
}

// ---- events -------------------------------------------------------------------------------------------------

// emit appends one event to the task's stream. It never fails: nobody watching is fine.
func (l *hosted) emit(e proto.Event, flushEvery time.Duration) {
	data, err := json.Marshal(e)
	if err != nil {
		return
	}
	l.mu.Lock()
	if l.ended {
		l.mu.Unlock()
		return
	}
	seq := l.base + len(l.evs) + 1
	if e.Type == "metrics" && e.Metrics != nil && !IsChat(l.opts.Agent) { // whose metric: the agent id (metadata only)
		m := *e.Metrics
		m.Agent = l.opts.Agent
		e.Metrics = &m
		data, _ = json.Marshal(e)
	}
	l.evs = append(l.evs, hostedEvent{seq: seq, ev: e, data: data})
	if modelOutput(e.Type) {
		l.output = true
	}
	l.addSources(e.Citations)
	if l.stored && l.timer == nil {
		l.timer = time.AfterFunc(flushEvery, l.flush)
	}
	close(l.changed)
	l.changed = make(chan struct{})
	l.mu.Unlock()
}

// addSources records citations' addresses by number (l.mu held).
func (l *hosted) addSources(cs []proto.Citation) {
	for _, c := range cs {
		if c.URL == "" {
			continue
		}
		if l.sources == nil {
			l.sources = map[int]string{}
		}
		l.sources[c.Index] = c.URL
	}
}

// Sources is a task's sources by citation number ([n] -> address) as its events showed them to the person: what a
// fetch of "[n]" asks about (Prompts.Sources). nil for a task this process doesn't serve.
func (h *Host) Sources(id string) map[int]string {
	h.init()
	h.mu.Lock()
	l := h.live[id]
	h.mu.Unlock()
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make(map[int]string, len(l.sources))
	for n, u := range l.sources {
		out[n] = u
	}
	return out
}

// flush writes the events not yet in the queue, in one transaction.
func (l *hosted) flush() {
	l.flushMu.Lock()
	defer l.flushMu.Unlock()
	l.mu.Lock()
	l.timer = nil
	if !l.stored {
		l.mu.Unlock()
		return
	}
	var out []harness.StoredEvent
	for _, e := range l.evs {
		if e.seq > l.flushed {
			out = append(out, harness.StoredEvent{Seq: e.seq, Data: e.data})
		}
	}
	l.mu.Unlock()
	if len(out) == 0 {
		return
	}
	if err := l.store().AddEvents(l.id, out); err != nil {
		return // kept in memory; the next flush tries again from here
	}
	l.mu.Lock()
	l.flushed = out[len(out)-1].Seq
	close(l.changed) // durable followers see these now
	l.changed = make(chan struct{})
	l.mu.Unlock()
}

// store is set by the host when the task becomes stored (the runtime's).
func (l *hosted) store() harness.Store { return l.st }

// end marks the stream complete (after its done or error) and writes what's left.
func (l *hosted) end() {
	l.mu.Lock()
	l.ended = true
	if l.timer != nil {
		l.timer.Stop()
		l.timer = nil
	}
	close(l.changed)
	l.changed = make(chan struct{})
	l.mu.Unlock()
	l.flush()
}

// ---- starting -----------------------------------------------------------------------------------------------

// StartRequest is a person's request to start a task.
type StartRequest struct {
	User string // the relay's opaque per-user tag: whose task, whose tool caps
	Req  *proto.RunRequest
	// Key, when set, makes the start once-only: the same user, space and key always name the same task, so a
	// repeated start (a retry, a double click, a replayed request) finds the first one instead of making another.
	Key string
	Via string // ViaRun or ViaTasks
}

// Start checks a chat request and starts it as a task, returning its id. existed: the key named a task that was
// already started (nothing new happened). A request the checks refuse returns no id and the error (a
// *safety.Error says which control). Once there is an id, the task's stream has everything people see, also when
// the start failed after it was made (no verified model: an error event; the runtime refused it: activity, error).
func (h *Host) Start(ctx context.Context, sr StartRequest) (id string, existed bool, err error) {
	h.init()
	start, opts, err := h.GW.StartFor(sr.Req)
	if err != nil {
		return "", false, err
	}
	if sr.Via != ViaTasks && !IsChat(opts.Agent) { // a /run task goes with its tab; an agent's task outlives it
		return "", false, fmt.Errorf("%s starts through POST /tasks", opts.Agent)
	}
	opts.User, opts.Space, opts.Via = sr.User, start.Space, sr.Via
	id = harness.NewTaskID()
	if sr.Key != "" {
		if len(h.IDKey) == 0 {
			return "", false, errors.New("this VM can't make once-only task ids")
		}
		id = harness.DeriveTaskID(h.IDKey, "start", start.Space, sr.User, sr.Key)
	}
	l := &hosted{id: id, user: sr.User, via: sr.Via, start: start, opts: opts, changed: make(chan struct{}), st: h.RT.Store}
	h.mu.Lock()
	if h.live[id] != nil {
		h.mu.Unlock()
		return id, true, nil
	}
	if st, err := h.RT.Store.Task(id); err != nil || st != nil {
		h.mu.Unlock()
		if err != nil {
			return "", false, err
		}
		return id, true, nil
	}
	if sr.Via == ViaTasks {
		max, open := h.MaxOpen, 0
		if max <= 0 {
			max = 8
		}
		for _, x := range h.live {
			if x.via == ViaTasks && x.user == sr.User && !x.isEnded() {
				open++
			}
		}
		if open >= max {
			h.mu.Unlock()
			return "", false, ErrTooMany
		}
	}
	h.live[id] = l
	h.mu.Unlock()
	existed, err = h.launch(ctx, l, sr.Req.Model, sr.Req.Tools, "")
	if err != nil {
		return h.failed(l, err)
	}
	if existed {
		return id, true, nil
	}
	return id, false, nil
}

// launch opens the task's guard session, emits its meta and hands it to the runtime (StartTainted with taint), then
// follows it to its end. existed: another process made the task meanwhile. On an error the stream has it and l is
// ended; the caller drops or keeps l (failed).
func (h *Host) launch(ctx context.Context, l *hosted, model string, tools []string, taint string) (existed bool, err error) {
	id, start, opts := l.id, l.start, l.opts
	optsJSON, err := json.Marshal(opts)
	if err != nil {
		h.drop(l)
		return false, err
	}
	l.sess = h.GW.Open(id, opts, func(e proto.Event) error { l.emit(e, h.flushEvery()); return nil })
	meta, err := l.sess.Meta(ctx)
	if err != nil {
		err = fmt.Errorf("model enclave not verified: %w", err)
		l.emit(proto.Event{Type: "error", Error: err.Error()}, 0)
		l.sess.Close()
		l.end()
		return false, err
	}
	meta.Model, meta.Tools = model, tools
	if !IsChat(opts.Agent) {
		meta.Agent = opts.Agent
	}
	obs, _ := h.GW.(RunObserver)
	if obs != nil {
		obs.RunStarted(id, &start, opts, meta)
	}
	l.emit(proto.Event{Type: "meta", Meta: meta}, 0)
	if err := h.RT.StartTainted(id, start, optsJSON, taint); err != nil {
		h.ended(l, RunEnd{State: harness.OutcomeFailed, Msg: "the task wasn't started"})
		l.emit(proto.Event{Type: "error", Error: err.Error()}, 0)
		l.sess.Close()
		l.end()
		if errors.Is(err, harness.ErrTaskExists) { // made by another process meanwhile
			h.drop(l)
			return true, nil
		}
		return false, err
	}
	l.mu.Lock()
	l.stored = true
	if len(l.evs) > 0 && l.timer == nil {
		l.timer = time.AfterFunc(h.flushEvery(), l.flush)
	}
	l.mu.Unlock()
	go h.finish(l)
	return false, nil
}

// failed ends a start that failed after it had an id: a /run shim still follows its stream (an error event, as
// /run always sent); anything else just gets the error.
func (h *Host) failed(l *hosted, err error) (string, bool, error) {
	if l.via == ViaRun {
		return l.id, false, err
	}
	h.drop(l)
	return "", false, err
}

func (h *Host) flushEvery() time.Duration {
	if h.FlushEvery > 0 {
		return h.FlushEvery
	}
	return 100 * time.Millisecond
}

func (l *hosted) isEnded() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.ended
}

// drop forgets a task this process serves.
func (h *Host) drop(l *hosted) {
	h.mu.Lock()
	if h.live[l.id] == l {
		delete(h.live, l.id)
	}
	h.mu.Unlock()
}

// ended tells the observer (agentd's recorder) how the task ended and appends what it returns (the activity
// event), exactly once per task in this process.
func (h *Host) ended(l *hosted, e RunEnd) {
	if obs, ok := h.GW.(RunObserver); ok {
		for _, ev := range obs.RunEnded(l.id, e) {
			l.emit(ev, h.flushEvery())
		}
	}
}

// finish waits for the task to end, then ends its stream as POST /run always ended a run: the site icons' grace,
// the activity record, then done or error (which control ended it, if one did).
func (h *Host) finish(l *hosted) {
	o, err := h.RT.Wait(context.Background(), l.id)
	if err != nil {
		h.ended(l, RunEnd{State: harness.OutcomeFailed, Msg: "the run ended without an outcome"})
		l.emit(proto.Event{Type: "error", Error: "the agent stopped"}, 0)
		h.close(l)
		return
	}
	step, finish := l.sess.End()
	if o.State == harness.OutcomeSucceeded {
		h.ended(l, RunEnd{State: o.State, Steps: step, Finish: finish})
		l.emit(proto.Event{Type: "done", Step: step, FinishReason: finish}, 0)
		h.close(l)
		return
	}
	msg := "the agent stopped" // untrusted when the brain says why: display only
	code := ""
	if w, ok := h.GW.(interface {
		Why(task string) (string, string)
	}); ok {
		if c, m := w.Why(l.id); c != "" { // a safety control ended it: say which (step 6)
			code, msg = c, m
		}
	}
	reason := ""
	switch {
	case code != "":
		if o.State == harness.OutcomeCancelled {
			reason = "kill_switch"
		}
	case o.State == harness.OutcomeCancelled && (pastDeadline(l.start.Limits.Deadline) || h.timedOut(l.id)):
		msg, reason = "run timed out", "deadline" // as the old loop (app/agent.go) said at its 5-minute cap
	case o.State == harness.OutcomeCancelled:
		msg, reason = "run cancelled", "person"
	case o.Done != nil && o.Done.Error != "":
		msg = o.Done.Error
	}
	// The brain's own error text is untrusted and may quote content: the record keeps the control's words only.
	detail := ""
	if code != "" {
		detail = msg
	}
	h.ended(l, RunEnd{State: o.State, Code: code, Reason: reason, Msg: detail, Steps: step, Finish: finish})
	l.emit(proto.Event{Type: "error", Error: msg, Code: code}, 0)
	h.close(l)
}

// timedOut: the gateway (agentd's safety checks) ended the task at the run's running-time limit, before its
// deadline (time waiting for the person doesn't count, so that limit isn't a fixed time; guard.RunTimeout).
func (h *Host) timedOut(task string) bool {
	t, ok := h.GW.(interface{ TimedOut(task string) bool })
	return ok && t.TimedOut(task)
}

// close ends a task's stream once its last event is in. A POST /tasks task's events are all in the queue then, so
// this process stops holding them (followers read the queue); a /run task's shim forgets it. A task its starter
// deleted while it ran is deleted now.
func (h *Host) close(l *hosted) {
	l.sess.Close()
	l.end()
	if l.via == ViaTasks || l.via == ViaTrigger {
		h.drop(l)
	}
	l.mu.Lock()
	l.finished = true
	deleted := l.deleted
	l.mu.Unlock()
	if deleted {
		h.RT.Forget(l.id)
	}
	if l.via == ViaTrigger && h.TriggeredDone != nil {
		h.TriggeredDone(l.id, l.opts)
	}
}

// Events is every event of a task kept in the queue, in order (an ended task's whole stream).
func (h *Host) Events(id string) ([]proto.Event, error) {
	var out []proto.Event
	after := 0
	for {
		evs, err := h.stored(id, after, 0)
		if err != nil {
			return nil, err
		}
		if len(evs) == 0 {
			return out, nil
		}
		for _, e := range evs {
			out = append(out, *e.Ev)
			after = e.Seq
		}
	}
}

// Emit adds an event to a task's stream (the permission prompts agentd shows, guard.Prompts). A task this process
// doesn't serve is ignored.
func (h *Host) Emit(id string, e proto.Event) {
	h.init()
	h.mu.Lock()
	l := h.live[id]
	h.mu.Unlock()
	if l != nil {
		l.emit(e, h.flushEvery())
	}
}

// ---- following ----------------------------------------------------------------------------------------------

// Event is one event of a task's stream as Follow hands it on: its number, and the event (as it was emitted, or
// read back from the queue).
type Event struct {
	Seq  int
	Ev   *proto.Event
	Data []byte // the event as JSON
}

// Follow hands on the task's events after seq after, in order and each once, as they come, until the stream ends
// (after its done or error) or ctx ends; fn's error stops it. A follower that reconnects with the last seq it saw
// continues where it was, also after an agentd restart: it only ever gets events already written to the queue (at
// most FlushEvery late), so no number it saw can be given to another event after a crash. user must be the task's
// starter (ErrNoTask otherwise, as for an unknown task); a /run task can't be followed this way.
func (h *Host) Follow(ctx context.Context, id, user string, after int, fn func(Event) error) error {
	if err := h.owned(id, user); err != nil {
		return err
	}
	return h.follow(ctx, id, after, true, fn)
}

// follow: durable hands on only events in the queue; else every event as it's emitted (the /run shim, whose task
// never outlives its process).
func (h *Host) follow(ctx context.Context, id string, after int, durable bool, fn func(Event) error) error {
	h.init()
	for {
		h.mu.Lock()
		l := h.live[id]
		h.mu.Unlock()
		var batch []Event
		var wait <-chan struct{}
		done := false
		if l != nil {
			l.mu.Lock()
			base, upto := l.base, l.base+len(l.evs)
			if durable {
				upto = l.flushed
			}
			if after >= base {
				for _, e := range l.evs {
					if e.seq > after && e.seq <= upto {
						ev := e.ev
						batch = append(batch, Event{Seq: e.seq, Ev: &ev, Data: e.data})
					}
				}
				done, wait = l.ended && upto == l.base+len(l.evs), l.changed
			}
			l.mu.Unlock()
			if after < base { // an earlier process's events, from the queue
				evs, err := h.stored(id, after, base)
				if err != nil {
					return err
				}
				batch = evs
			}
		} else {
			evs, err := h.stored(id, after, 0)
			if err != nil {
				return err
			}
			batch = evs
			if len(batch) == 0 {
				st, err := h.RT.Status(id)
				if err != nil || harness.Terminal(st.State) {
					return nil // ended (or gone) and nothing more to read
				}
				t := time.NewTimer(200 * time.Millisecond) // a task no process serves yet: being taken up or abandoned
				select {
				case <-ctx.Done():
					t.Stop()
					return ctx.Err()
				case <-t.C:
				}
				continue
			}
		}
		for _, e := range batch {
			if err := fn(e); err != nil {
				return err
			}
			after = e.Seq
		}
		if len(batch) > 0 {
			continue
		}
		if done {
			return nil
		}
		if wait != nil {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-wait:
			}
		}
	}
}

// stored reads up to 256 events after seq after from the queue (below upto, when it's > 0).
func (h *Host) stored(id string, after, upto int) ([]Event, error) {
	evs, err := h.RT.Store.Events(id, after, 256)
	if err != nil {
		return nil, err
	}
	var out []Event
	for _, e := range evs {
		if upto > 0 && e.Seq > upto {
			break
		}
		var ev proto.Event
		if json.Unmarshal(e.Data, &ev) != nil {
			continue
		}
		out = append(out, Event{Seq: e.Seq, Ev: &ev, Data: e.Data})
	}
	return out, nil
}

// owned checks that id is a task user started through POST /tasks.
func (h *Host) owned(id, user string) error {
	if !harness.ValidTaskID(id) {
		return ErrNoTask
	}
	st, err := h.RT.Status(id)
	if err != nil {
		return ErrNoTask
	}
	var o TaskOptions
	if json.Unmarshal(st.Options, &o) != nil || o.Via != ViaTasks || o.User != user {
		return ErrNoTask
	}
	return nil
}

// Authorize checks a call on a task (op: status, events, cancel, delete): the task is user's, started through POST /tasks
// with a run secret, and mac is TaskMAC with that secret for op and this task. Anything else is ErrNoTask (the same
// answer as for an unknown task), so the relay, which sets the user tag but never sees the secret, can't read,
// follow or cancel a task by itself.
func (h *Host) Authorize(id, user, op, mac string) error {
	if err := h.owned(id, user); err != nil {
		return err
	}
	st, err := h.RT.Status(id)
	if err != nil {
		return ErrNoTask
	}
	var o TaskOptions
	if json.Unmarshal(st.Options, &o) != nil || !validRunSecret(o.RunSecret) || len(mac) != 64 ||
		!hmac.Equal([]byte(TaskMAC(o.RunSecret, op, id)), []byte(strings.ToLower(mac))) {
		return ErrNoTask
	}
	return nil
}

// TaskState is what the starter may see of a task.
type TaskState struct {
	Task     string `json:"task"`
	State    string `json:"state"`         // queued | running | waiting | paused | done | failed | cancelled
	Sub      string `json:"sub,omitempty"` // why it waits or is paused
	Attempt  int    `json:"attempt"`
	Events   int    `json:"events"` // the last event's seq so far
	Held     int    `json:"held,omitempty"`
	Outcome  string `json:"outcome,omitempty"` // succeeded | failed | cancelled, once ended
	Existing bool   `json:"existing,omitempty"`
	// Tainted: the task received outside content (web pages, search results); what it proposes from then on is
	// marked tainted, and a tainted change or send will need a person's approval (docs/27 sections 4 and 5).
	Tainted bool `json:"tainted,omitempty"`
}

// Status is the task's state for its starter.
func (h *Host) Status(id, user string) (TaskState, error) {
	if err := h.owned(id, user); err != nil {
		return TaskState{}, err
	}
	st, err := h.RT.Status(id)
	if err != nil {
		return TaskState{}, ErrNoTask
	}
	out := TaskState{Task: id, State: st.State, Sub: st.Sub, Attempt: st.Attempt, Held: len(st.Held), Tainted: st.Taint != ""}
	if st.Outcome != nil {
		out.Outcome = st.Outcome.State
	}
	h.mu.Lock()
	l := h.live[id]
	h.mu.Unlock()
	if l != nil {
		l.mu.Lock()
		out.Events = l.flushed // what Follow can hand on now
		l.mu.Unlock()
	} else {
		out.Events = h.lastSeq(id, 0)
	}
	return out, nil
}

// Cancel cancels the starter's task ("person"). refundable is the billing witness for the relay: this was the
// first cancel of a task this process serves, it hadn't ended, and none of its model calls had sent anything
// (no reasoning, text or tool call). Only one cancel per task can be refundable, so a repeated cancel can't
// claim a second refund; a task that ended by itself, or answered anything, never is.
func (h *Host) Cancel(id, user string) (refundable bool, err error) {
	if err := h.owned(id, user); err != nil {
		return false, err
	}
	h.init()
	h.mu.Lock()
	l := h.live[id]
	h.mu.Unlock()
	if l != nil {
		l.mu.Lock()
		refundable = !l.ended && !l.output && !l.cancelled
		l.cancelled = true
		l.mu.Unlock()
	}
	if err := h.RT.Cancel(id, "person"); err != nil {
		var pe *harness.Error
		if errors.As(err, &pe) && pe.Code == harness.CodeTaskClosed {
			return false, nil // already ended: nothing to do
		}
		return false, err
	}
	return refundable, nil
}

// Delete deletes the starter's task and everything kept for it (its start, journal, events: the result), as the
// browser asks once it saved the result, or when the person deletes the conversation (docs/30). A task still running
// is cancelled ("person") first and deleted as soon as it ended. refundable is Cancel's billing witness. Activity
// records aren't touched: they are the space's history, sealed to its key.
func (h *Host) Delete(id, user string) (refundable bool, err error) {
	if err := h.owned(id, user); err != nil {
		return false, err
	}
	h.init()
	h.mu.Lock()
	l := h.live[id]
	h.mu.Unlock()
	if l != nil {
		l.mu.Lock()
		running := !l.finished
		l.deleted = true
		l.mu.Unlock()
		if running {
			return h.Cancel(id, user) // close deletes it when it ended
		}
	}
	st, err := h.RT.Status(id)
	if err == nil && !harness.Terminal(st.State) {
		// Not ended, and no process here serves it (being taken up after a restart): cancel, then delete once ended.
		refundable, err = h.Cancel(id, user)
		if err != nil {
			return false, err
		}
		go func() {
			if _, err := h.RT.Wait(context.Background(), id); err == nil {
				h.RT.Forget(id)
			}
		}()
		return refundable, nil
	}
	if err := h.RT.Forget(id); err != nil {
		return false, err
	}
	h.mu.Lock()
	delete(h.live, id)
	h.mu.Unlock()
	return false, nil
}

// lastSeq is the last event's seq in the queue (from after on).
func (h *Host) lastSeq(id string, after int) int {
	for {
		evs, err := h.RT.Store.Events(id, after, 1024)
		if err != nil || len(evs) == 0 {
			return after
		}
		after = evs[len(evs)-1].Seq
	}
}

// ---- restarts and retention ---------------------------------------------------------------------------------

// Resume takes up the tasks the runtime restored after a restart (Runtime.Restore's ids): a POST /tasks task goes
// on (its guard session opened again, its budget and record taken up, its stream continued after its last stored
// event); a /run task is abandoned, as before (its person's stream and the per-boot key died with the old process):
// cancelled, then deleted. Returns how many it resumed and abandoned.
func (h *Host) Resume(ids []string) (resumed, abandoned int) {
	h.init()
	for _, id := range ids {
		st, err := h.RT.Store.Task(id)
		var opts TaskOptions
		var start harness.Start
		if err != nil || st == nil || json.Unmarshal(st.Options, &opts) != nil || (opts.Via != ViaTasks && opts.Via != ViaTrigger) ||
			jsonv2.Unmarshal(st.Start, &start) != nil {
			h.RT.Cancel(id, "restart")
			go func() {
				if _, err := h.RT.Wait(context.Background(), id); err == nil {
					h.RT.Forget(id)
				}
			}()
			abandoned++
			continue
		}
		journal, _ := h.RT.Store.Journal(id)
		if r, ok := h.GW.(TaskResumer); ok {
			r.ResumeTask(id, &start, opts, st.Created, journal)
		}
		base := h.lastSeq(id, 0)
		l := &hosted{id: id, user: opts.User, via: opts.Via, start: start, opts: opts, changed: make(chan struct{}),
			st: h.RT.Store, stored: true, base: base, flushed: base}
		for after := 0; after < base; { // its sources (and whether a model sent anything), from the events an earlier process showed
			evs, err := h.stored(id, after, base)
			if err != nil || len(evs) == 0 {
				break
			}
			for _, e := range evs {
				l.addSources(e.Ev.Citations)
				if modelOutput(e.Ev.Type) { // the billing witness survives a restart: output before it counts
					l.output = true
				}
				after = e.Seq
			}
		}
		h.mu.Lock()
		h.live[id] = l
		h.mu.Unlock()
		l.sess = h.GW.Open(id, opts, func(e proto.Event) error { l.emit(e, h.flushEvery()); return nil })
		if r, ok := h.GW.(TaskFollower); ok { // its stream is live again: e.g. its permission prompts are shown again
			r.TaskResumed(id, &start, opts, journal)
		}
		go h.finish(l)
		resumed++
	}
	return resumed, abandoned
}

// Prune deletes the tasks that ended more than their keep ago (their start, journal and events: Keep, or their
// agent's, guard.AgentKeep), and forgets the ended ones this process no longer needs to serve. Run it now and then.
func (h *Host) Prune(now time.Time) int {
	h.init()
	ids, err := h.RT.Store.EndedBefore(now.Add(-min(h.keep(), h.minAgentKeep())))
	if err != nil {
		return 0
	}
	n := 0
	for _, id := range ids {
		if st, err := h.RT.Store.Task(id); err == nil && st != nil {
			var o TaskOptions
			json.Unmarshal(st.Options, &o)
			if !st.Ended.IsZero() && st.Ended.After(now.Add(-h.keepFor(o.Agent))) {
				continue // its agent keeps it longer
			}
		}
		if h.RT.Forget(id) == nil {
			n++
			if h.Forgotten != nil {
				h.Forgotten(id)
			}
		}
		h.mu.Lock()
		delete(h.live, id)
		h.mu.Unlock()
	}
	return n
}

// ---- POST /run, the shim --------------------------------------------------------------------------------------

// Run serves one chat request the way POST /run always has, as a shim over the task model: it starts the request
// as a task (the built-in chat definition) and follows it from its first event, handing each to emit. The person
// going away (ctx ending, or emit failing) cancels the task; once it ended and its stream was handed on, the task
// and everything recorded for it are deleted (the chat keeps no conversation in the VM). user keys the per-user
// tool caps (the relay's opaque X-Agent-User tag).
func (h *Host) Run(ctx context.Context, user string, r *proto.RunRequest, emit func(proto.Event) error) error {
	h.init()
	id, _, err := h.Start(ctx, StartRequest{User: user, Req: r, Via: ViaRun})
	if id == "" {
		return err
	}
	defer h.forget(id)
	stop := context.AfterFunc(ctx, func() { h.RT.Cancel(id, "person") })
	defer stop()
	var last *proto.Event
	gone := false
	h.follow(context.Background(), id, 0, false, func(e Event) error {
		last = e.Ev
		if gone {
			return nil // the person is gone: the task was cancelled; its stream is drained, not shown
		}
		if err := emit(*e.Ev); err != nil {
			gone = true
			h.RT.Cancel(id, "person")
		}
		return nil
	})
	switch {
	case last == nil:
		return errors.New("the run ended without an outcome")
	case last.Type == "error":
		return errors.New(last.Error)
	case err != nil:
		return err
	}
	return nil
}

// forget deletes a /run task once it ended (and its stream was handed on).
func (h *Host) forget(id string) {
	h.mu.Lock()
	l := h.live[id]
	delete(h.live, id)
	h.mu.Unlock()
	if l != nil && l.stored {
		h.RT.Forget(id)
	}
}
