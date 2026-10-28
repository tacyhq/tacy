package guard

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/tacyhq/tacy/harness"
	"github.com/tacyhq/tacy/proto"
	"github.com/tacyhq/tacy/safety"
)

// Prompts is agentd's side of the permission prompts (docs/27 section 6): it holds each action that would send data out until the
// person answered (the runtime's HoldGuard: waiting, sub-state permission), shows them the prompt in the task's
// stream, takes their grant (POST /tasks/grant), and hands the action on with it, or denies it. A kind the person
// always allows isn't held; a kind set to Never (or capped to it by the policy) is denied without asking; no answer
// in Timeout is a deny. gatewayd checks the grant again itself (permit) before anything is sent.
//
// Every held action is released to the guard (allowed or not), and Attach answers a denied one with
// PermissionDenial: the model always gets a result, and the activity record sees every prompt's outcome.
type Prompts struct {
	// Release decides a held request (the runtime's Release). Required.
	Release func(task, id string, allow bool, reason string) error
	// Emit adds an event to a task's stream (Host.Emit). Required.
	Emit func(task string, e proto.Event)
	// Cap is the policy's cap on a kind's setting for a space (safety.Effective.PermissionCap); nil: none.
	Cap func(space, kind string) string
	// Timeout is how long a prompt waits for an answer; 0: 10 minutes. A prompt never waits past the task's deadline
	// (its overall cap, RunCap) less Grace, so the model can still answer after a timeout.
	Timeout time.Duration
	// Grace is the time kept before a task's deadline for the answer; 0: a minute.
	Grace time.Duration
	// OnWait is told when a prompt of a task opens (true) and when it closes (answered, timed out or dropped):
	// agentd stops the run's running-time clock while one is open (safety.Ledger.Pause). nil: nobody is told.
	// Called with the prompts' lock held: it must not call back into Prompts.
	OnWait func(task string, open bool)
	// Sources is a task's sources by number ([n] -> address), as its events showed them to the person (Host.Sources):
	// a fetch of "[n]" is asked about with the address it names. nil: none.
	Sources func(task string) map[int]string

	mu       sync.Mutex
	open     map[string]*prompt           // waiting for the person, by task\x00request
	always   map[string]map[string]*Grant // task -> kind -> the grant that allowed the kind for the run
	grants   map[string]*Grant            // task\x00request -> the grant its action runs with
	outcomes map[string]PermissionOutcome // task\x00request -> how its permission was given
	steps    map[string]step              // task -> its latest model call (ModelCalled)
}

// step is a task's latest model call as the taint of its tool calls sees it: whether the task was tainted when the
// call was made, and the ids of the tool calls it proposed.
type step struct {
	tainted bool
	calls   map[string]bool
}

// ModelCalled tells the prompts a model call of the task answered (agentd, after each one): its tool calls were
// proposed with the task as tainted as it was when the call was made (ti.Tainted then), so calls proposed together
// don't taint each other however their requests arrive.
func (p *Prompts) ModelCalled(ti *harness.TaskInfo, res *harness.ModelResult) {
	if res == nil {
		return
	}
	st := step{tainted: ti.Tainted, calls: map[string]bool{}}
	for _, c := range res.Message.ToolCalls {
		st.calls[c.ID] = true
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.init()
	p.steps[ti.ID] = st
}

// tainted is whether action call (an id from the model's tool calls) was proposed after outside content: the
// taint of the model call that proposed it, or, for any other request, the task's taint as it arrived (p.mu held).
func (p *Prompts) tainted(ti *harness.TaskInfo, call string) bool {
	if st, ok := p.steps[ti.ID]; ok && call != "" && st.calls[call] {
		return st.tainted
	}
	return ti.Tainted
}

// PermissionOutcome is how an action's permission was given (one of the Perm* outcomes), for the record.
type PermissionOutcome struct {
	Outcome string
	Edited  bool
}

type prompt struct {
	task, request, call, kind, value, secret string
	sent                                     string // allowed: the value that goes out ("": value)
	timer                                    *time.Timer
}

// Errors of Answer.
var (
	ErrNoPrompt  = errors.New("no such prompt") // never asked, already answered, timed out, or the task ended
	ErrBadGrant  = errors.New("bad grant")      // the MAC doesn't check with the run's secret, or the kind is wrong
	ErrBadValue  = errors.New("bad value")      // what the person would send isn't acceptable (CheckGrantValue)
	errNoRelease = errors.New("prompts: no release")
)

// DefaultPromptTimeout is how long a prompt waits for the person (docs/27 section 6).
const DefaultPromptTimeout = 10 * time.Minute

func (p *Prompts) init() {
	if p.open == nil {
		p.open = map[string]*prompt{}
		p.always = map[string]map[string]*Grant{}
		p.grants = map[string]*Grant{}
		p.outcomes = map[string]PermissionOutcome{}
		p.steps = map[string]step{}
	}
}

func (p *Prompts) cap(space, kind string) string {
	if p.Cap == nil {
		return ""
	}
	return p.Cap(space, kind)
}

// sources is the task's sources for a fetch's [n] (nil for other kinds, or without Sources).
func (p *Prompts) sources(task, kind string) map[int]string {
	if kind != "web.fetch" || p.Sources == nil {
		return nil
	}
	return p.Sources(task)
}

func optionsOf(ti *harness.TaskInfo) TaskOptions {
	var o TaskOptions
	if ti.Options != nil && json.Unmarshal(ti.Options, &o) != nil {
		return TaskOptions{}
	}
	return o
}

// timeout is how long a prompt of this task may wait now (<= 0: no time left to ask).
func (p *Prompts) timeout(ti *harness.TaskInfo) time.Duration {
	d := cmp.Or(p.Timeout, DefaultPromptTimeout)
	if ti.Start != nil && ti.Start.Limits.Deadline != "" {
		if end, err := time.Parse(time.RFC3339, ti.Start.Limits.Deadline); err == nil {
			d = min(d, time.Until(end)-cmp.Or(p.Grace, time.Minute))
		}
	}
	return d
}

func key(task, id string) string { return task + "\x00" + id }

// Hold is the runtime's HoldGuard: an action of a permission kind waits for the person (WaitPermission) unless their
// setting already decides it (Always allow, Never), an Always allow earlier in the run covers its kind, or the run
// can't ask (no run secret: denied). On a tainted task a fetch of an address the model composed (ComposedFetch: not
// a result's [n], not in the person's messages) is refused without asking, under Always allow or Ask
// (PermNotFromResults); before taint it goes as any fetch. A value with hidden characters is denied without asking.
// Actions that send nothing out, and model calls, aren't held.
func (p *Prompts) Hold(ti *harness.TaskInfo, id string, req any) string {
	a, ok := req.(*harness.Action)
	if !ok {
		return ""
	}
	kind := PermissionKind(a.Name)
	if kind == "" {
		return ""
	}
	sources := p.sources(ti.ID, kind)
	value, ok := Outgoing(a.Name, a.Args, sources)
	if !ok {
		return "" // unusable arguments: the connector refuses them, nothing is sent
	}
	opts := optionsOf(ti)
	k := key(ti.ID, id)
	p.mu.Lock()
	p.init()
	composed := ComposedFetch(a.Name, a.Args, sources, opts.Links, p.tainted(ti, a.Call))
	setting := PermissionSetting(opts, kind, p.cap(opts.Space, kind))
	switch {
	case HiddenChars(value): // never sent, so never asked about (whatever the setting)
		p.outcomes[k] = PermissionOutcome{Outcome: PermHidden}
	case setting == safety.PermNever:
		p.outcomes[k] = PermissionOutcome{Outcome: PermNeverSetting}
	case composed: // never opened, so never asked about
		p.outcomes[k] = PermissionOutcome{Outcome: PermNotFromResults}
	case setting == safety.PermAlways:
		p.outcomes[k] = PermissionOutcome{Outcome: PermAlwaysSetting}
	case p.always[ti.ID][kind] != nil:
		p.grants[k] = p.always[ti.ID][kind]
		p.outcomes[k] = PermissionOutcome{Outcome: PermAllowedAlways}
	case !validRunSecret(opts.RunSecret):
		p.outcomes[k] = PermissionOutcome{Outcome: PermUnavailable}
	default:
		timeout := p.timeout(ti)
		if timeout <= 0 {
			p.outcomes[k] = PermissionOutcome{Outcome: PermTimedOut}
			break
		}
		pr := &prompt{task: ti.ID, request: id, call: cmp.Or(a.Call, id), kind: kind, value: value, secret: opts.RunSecret}
		p.open[k] = pr
		if p.OnWait != nil {
			p.OnWait(ti.ID, true)
		}
		pr.timer = time.AfterFunc(timeout, func() { p.expire(ti.ID, id) })
		p.mu.Unlock()
		p.Emit(ti.ID, proto.Event{Type: "permission", ID: pr.call, Permission: &proto.Permission{Task: ti.ID, Request: id,
			Kind: kind, Value: value, TimeoutS: int(timeout.Round(time.Second) / time.Second)}})
		return harness.WaitPermission
	}
	p.mu.Unlock()
	return ""
}

// Answer takes the person's grant for a waiting prompt: its MAC must check with the run's secret, its kind must be
// the prompt's, and a value to send must be acceptable. A prompt is answered once (a replayed grant finds none).
// Allow once lets this action go with the value the person sent; Always allow too, and every action of the kind
// in this run, those waiting now included; Deny denies it. Returns the outcome.
func (p *Prompts) Answer(g Grant) (string, error) {
	k := key(g.Task, g.Request)
	p.mu.Lock()
	p.init()
	pr := p.open[k]
	if pr == nil {
		p.mu.Unlock()
		return "", ErrNoPrompt
	}
	if g.Kind != pr.kind || !g.Verify(pr.secret) {
		p.mu.Unlock()
		return "", ErrBadGrant
	}
	switch g.Decision {
	case DecideOnce, DecideAlways:
		if CheckGrantValue(pr.kind, g.Value) != nil || isMailAction(pr.kind) && g.Value != pr.value { // mail: not editable
			p.mu.Unlock()
			return "", ErrBadValue
		}
	case DecideDeny:
	default:
		p.mu.Unlock()
		return "", ErrBadGrant
	}
	gr := g
	settled := []settle{{pr, PermissionOutcome{}}}
	if g.Decision != DecideDeny {
		pr.sent = g.Value // what goes out: the person's value
	}
	p.close(k, pr)
	switch g.Decision {
	case DecideDeny:
		settled[0].o = PermissionOutcome{Outcome: PermDenied}
	case DecideOnce:
		settled[0].o = PermissionOutcome{Outcome: PermAllowedOnce, Edited: g.Value != pr.value}
		p.grants[k] = &gr
	case DecideAlways:
		settled[0].o = PermissionOutcome{Outcome: PermAllowedAlways, Edited: g.Value != pr.value}
		p.grants[k] = &gr
		if p.always[g.Task] == nil {
			p.always[g.Task] = map[string]*Grant{}
		}
		p.always[g.Task][g.Kind] = &gr
		for k2, o := range p.open { // the run's other prompts of this kind: allowed too
			if o.task == g.Task && o.kind == g.Kind {
				p.close(k2, o)
				p.grants[k2] = &gr
				settled = append(settled, settle{o, PermissionOutcome{Outcome: PermAllowedAlways}})
			}
		}
	}
	for _, s := range settled {
		p.outcomes[key(s.pr.task, s.pr.request)] = s.o
	}
	p.mu.Unlock()
	for _, s := range settled {
		p.settled(s.pr, s.o)
	}
	return settled[0].o.Outcome, nil
}

type settle struct {
	pr *prompt
	o  PermissionOutcome
}

// close removes a waiting prompt (p.mu held).
func (p *Prompts) close(k string, pr *prompt) {
	delete(p.open, k)
	if pr.timer != nil {
		pr.timer.Stop()
	}
	if p.OnWait != nil {
		p.OnWait(pr.task, false)
	}
}

// expire: no answer in time is a deny.
func (p *Prompts) expire(task, id string) {
	k := key(task, id)
	p.mu.Lock()
	pr := p.open[k]
	if pr == nil {
		p.mu.Unlock()
		return
	}
	p.close(k, pr)
	o := PermissionOutcome{Outcome: PermTimedOut}
	p.outcomes[k] = o
	p.mu.Unlock()
	p.settled(pr, o)
}

// settled tells the person how a prompt ended and lets the runtime hand its action on (Attach denies it when it
// wasn't allowed).
func (p *Prompts) settled(pr *prompt, o PermissionOutcome) {
	p.Emit(pr.task, proto.Event{Type: "permission", ID: pr.call, Permission: &proto.Permission{Task: pr.task, Request: pr.request,
		Kind: pr.kind, Value: cmp.Or(pr.sent, pr.value), Decision: o.Outcome, Edited: o.Edited}})
	go p.release(pr.task, pr.request)
}

// release hands a held request on to the guard. A grant can come in a moment before the runtime holds the request
// (the prompt is shown from Hold): it waits a little for the hold.
func (p *Prompts) release(task, id string) error {
	if p.Release == nil {
		return errNoRelease
	}
	for i := 0; ; i++ {
		err := p.Release(task, id, true, "")
		var pe *harness.Error
		if err == nil || !errors.As(err, &pe) || pe.Code != harness.CodeUnknownTask || i >= 500 {
			return err
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// Attach is called with each action the runtime hands on: an action whose permission was denied (by the person, a
// timeout, the setting, a run that can't ask, or a composed address on a tainted task) is answered with the denial
// (the person sees it under the tool call); an allowed one goes on with its grant (WithGrant), for gatewayd to check.
func (p *Prompts) Attach(ctx context.Context, ti *harness.TaskInfo, id string, a *harness.Action) (context.Context, *harness.ActionResult) {
	kind := PermissionKind(a.Name)
	if kind == "" {
		return ctx, nil
	}
	k := key(ti.ID, id)
	p.mu.Lock()
	p.init()
	o, asked := p.outcomes[k]
	g := p.grants[k]
	p.mu.Unlock()
	if !asked {
		return ctx, nil // not held here (unusable arguments, or a rerun after a restart): gatewayd decides
	}
	switch o.Outcome {
	case PermDenied, PermTimedOut, PermNeverSetting, PermUnavailable, PermHidden, PermNotFromResults:
		deny := PermissionDenial(kind, o.Outcome)
		call := cmp.Or(a.Call, id)
		if o.Outcome == PermNeverSetting || o.Outcome == PermUnavailable || o.Outcome == PermNotFromResults { // never asked: say why under the call
			value, _ := Outgoing(a.Name, a.Args, p.sources(ti.ID, kind))
			p.Emit(ti.ID, proto.Event{Type: "permission", ID: call, Permission: &proto.Permission{Task: ti.ID, Request: id,
				Kind: kind, Value: value, Decision: o.Outcome}})
		}
		res, _ := json.Marshal(map[string]string{"error": deny.Error})
		p.Emit(ti.ID, proto.Event{Type: "tool_result", ID: call, Name: eventName(a.Name), Args: json.RawMessage(a.Args), Result: res})
		return ctx, deny
	}
	return WithGrant(ctx, g), nil
}

// Approved records a permission the person gave in their tab before the task started (the plain chat's search,
// POST /search: the prompt is shown in the tab, and only an allowed query is sent): the request runs with grant g
// (Attach), and the activity record says how the person allowed it (Outcome).
func (p *Prompts) Approved(task, id string, g *Grant, o PermissionOutcome) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.init()
	k := key(task, id)
	p.grants[k], p.outcomes[k] = g, o
}

// Outcome is how a task's request got its permission (false: it needed none, or wasn't held here).
func (p *Prompts) Outcome(task, id string) (PermissionOutcome, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	o, ok := p.outcomes[key(task, id)]
	return o, ok
}

// Waiting is how many prompts of a task wait for the person.
func (p *Prompts) Waiting(task string) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	n := 0
	for _, pr := range p.open {
		if pr.task == task {
			n++
		}
	}
	return n
}

// Forget drops a task's prompts, grants and outcomes (it ended).
func (p *Prompts) Forget(task string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.init()
	prefix := task + "\x00"
	for k, pr := range p.open {
		if strings.HasPrefix(k, prefix) {
			p.close(k, pr)
		}
	}
	for k := range p.grants {
		if strings.HasPrefix(k, prefix) {
			delete(p.grants, k)
		}
	}
	for k := range p.outcomes {
		if strings.HasPrefix(k, prefix) {
			delete(p.outcomes, k)
		}
	}
	delete(p.always, task)
	delete(p.steps, task)
}

// Resume asks again for the actions a task had waiting for permission when agentd restarted (they stay held):
// each prompt is shown again with a fresh timeout. Grants given before the restart are gone with it; nothing is
// allowed without asking again. The task counts as tainted if it was from its start or a web action of its
// journal finished (what the runtime's taint says).
func (p *Prompts) Resume(ti *harness.TaskInfo, journal []harness.Record) {
	if !ti.Tainted {
		c := *ti
		c.Tainted = ti.Start != nil && StartTaint(ti.Start) != "" || journalTainted(journal)
		ti = &c
	}
	for _, r := range journal {
		if r.Kind != harness.TypeAction || r.Held != harness.WaitPermission || r.Done {
			continue
		}
		var a harness.Action
		if json.Unmarshal(r.Req, &a) != nil {
			continue
		}
		if p.Hold(ti, r.ID, &a) == "" { // decided without asking now (the setting changed, no time left): go on
			p.release(ti.ID, r.ID)
		}
	}
}

// journalTainted: a web action of the journal finished, so its result (outside content) reached the brain.
func journalTainted(journal []harness.Record) bool {
	for _, r := range journal {
		if r.Kind != harness.TypeAction || !r.Done {
			continue
		}
		var a harness.Action
		if json.Unmarshal(r.Req, &a) == nil && Untrusted(&a) {
			return true
		}
	}
	return false
}
