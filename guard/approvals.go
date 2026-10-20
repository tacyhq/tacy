package guard

import (
	"cmp"
	"context"
	"encoding/json"
	jsonv2 "encoding/json/v2"
	"errors"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/tacyhq/tacy/approval"
	"github.com/tacyhq/tacy/harness"
	"github.com/tacyhq/tacy/proto"
)

// Approvals is agentd's side of approve before send (docs/27 section 4), built on the same plumbing as the permission
// prompts (Prompts): the runtime's HoldGuard holds an action whose class needs a person's approval (waiting,
// sub-state approval), the effect is computed and recorded (approval.Store, on the encrypted disk) and shown in the
// task's stream and to its approvers (List), a person's passkey decides it (Answer, POST /approvals), and the
// action goes on with the approval for gatewayd to check again (Attach), or is denied. No answer before the expiry
// is a deny (fail closed). For an unattended task the approver is its sponsor: the task waits, its running-time
// clock stopped, until they answer in the chat.
//
// An approval is single use and binds one effect: the payload names the approval, the task, the request and the
// effect's hash, so changing anything needs a new one. The effect's record moves held → approved → sending (before
// the connector runs) → sent or failed; one found sending after a restart becomes unknown and is never sent again
// by the VM (Recover).
type Approvals struct {
	// Release decides a held request (the runtime's Release). Required.
	Release func(task, id string, allow bool, reason string) error
	// Emit adds an event to a task's stream (Host.Emit). Required.
	Emit func(task string, e proto.Event)
	// Store keeps the records. Required.
	Store approval.Store
	// Check is how a submission is verified: the identity directory, the pinned origin and rpId, the clock. A nil
	// Check.Dir verifies nothing (no approval can be given: fail closed).
	Check approval.Config
	// IDKey derives approval ids (agentd's per-firm key, as Host.IDKey). Required.
	IDKey []byte
	// TTL is how long an approval may wait; 0: approval.DefaultTTL (24 hours).
	TTL time.Duration
	// Listed says whether the space's policy lists the action for approval (safety.Effective.NeedsApproval). nil:
	// none listed.
	Listed func(space, action string) bool
	// OnWait is told when an approval of a task opens and closes (the running-time clock stops meanwhile, as for
	// a permission prompt). Called with the lock held: it must not call back into Approvals.
	OnWait func(task string, open bool)

	mu       sync.Mutex
	open     map[string]*held                // waiting for a person, by task\x00request
	byID     map[string]string               // ap_ -> task\x00request, for the open ones
	outcomes map[string]string               // task\x00request -> approval state (approved, denied, expired, unavailable)
	subs     map[string]*approval.Submission // task\x00request -> the approval it runs with
}

type held struct {
	rec   approval.Record
	call  string
	timer *time.Timer
	taint bool
}

// Errors of Answer.
var (
	ErrNoApproval  = errors.New("no such approval") // not held: never, already decided, expired, or the task ended
	ErrBadApproval = errors.New("bad approval")     // the submission doesn't verify (approval.Check)
)

// Outcomes for actions denied without asking.
const (
	ApprovalUnavailable = "unavailable" // no approver for the task, or the effect can't be shown
)

func (a *Approvals) init() {
	if a.open == nil {
		a.open, a.byID, a.outcomes, a.subs = map[string]*held{}, map[string]string{}, map[string]string{}, map[string]*approval.Submission{}
	}
}

func (a *Approvals) now() time.Time {
	if a.Check.Now != nil {
		return a.Check.Now()
	}
	return time.Now()
}

// Needs reports whether the action needs a person's approval for this task now: its class (approval.ClassOf), the
// task's taint when it was proposed, and whether the policy lists it.
func (a *Approvals) Needs(ti *harness.TaskInfo, act *harness.Action) bool {
	listed := false
	if a.Listed != nil {
		listed = a.Listed(optionsOf(ti).Space, act.Name)
	}
	return approval.Needs(approval.ClassOf(act.Name), ti.Tainted, listed)
}

// Hold is the runtime's HoldGuard for approvals: an action that needs one waits (WaitApproval) with its effect
// recorded and shown; decided is true when the action was decided here without asking (no approver, an effect
// that can't be computed, a record already decided before a restart): Attach answers it then.
func (a *Approvals) Hold(ti *harness.TaskInfo, id string, req any) (sub string, decided bool) {
	return a.hold(ti, id, req, false)
}

// hold is Hold; held says an earlier process already held the request for approval (its journal says so), so it
// needs one whatever the task's taint looks like now.
func (a *Approvals) hold(ti *harness.TaskInfo, id string, req any, held bool) (sub string, decided bool) {
	act, ok := req.(*harness.Action)
	if !ok || !held && !a.Needs(ti, act) {
		return "", false
	}
	k := key(ti.ID, id)
	opts := optionsOf(ti)
	eff, err := EffectOf(act.Name, act.Args)
	a.mu.Lock()
	a.init()
	h, decided := a.holdLocked(ti, id, act, k, opts, eff, err)
	a.mu.Unlock()
	if h == nil {
		return "", decided
	}
	a.Emit(ti.ID, a.event(h, "")) // the person sees exactly what would happen, and who may approve it
	return harness.WaitApproval, false
}

// holdLocked records the held effect and opens it (a.mu held); nil with decided when it was decided without asking.
func (a *Approvals) holdLocked(ti *harness.TaskInfo, id string, act *harness.Action, k string, opts TaskOptions, eff []byte, err error) (*held, bool) {
	if err != nil || len(opts.Approvers) == 0 || a.Store == nil || len(a.IDKey) == 0 {
		a.outcomes[k] = ApprovalUnavailable
		return nil, true
	}
	now := a.now()
	rec, _, err := a.Store.PutApproval(approval.Record{ID: approval.ID(a.IDKey, ti.ID, id), Firm: opts.Firm, Space: opts.Space,
		Task: ti.ID, Request: id, Action: act.Name, Effect: eff, EffectHash: approval.EffectHash(eff),
		Approvers: slices.Clone(opts.Approvers), ExpiresAt: now.Add(cmp.Or(a.TTL, approval.DefaultTTL)).UTC().Truncate(time.Second).Add(time.Second), // whole seconds, never early
		CreatedAt: now.UTC()})
	if err != nil {
		a.outcomes[k] = ApprovalUnavailable
		return nil, true
	}
	switch rec.State {
	case approval.StateHeld:
	case approval.StateApproved: // decided before a restart, not yet handed on
		var s approval.Submission
		if jsonv2.Unmarshal(rec.Decision, &s) == nil && now.Before(rec.ExpiresAt) {
			a.outcomes[k], a.subs[k] = approval.StateApproved, &s
			return nil, true
		}
		a.Store.MoveApproval(rec.ID, approval.StateApproved, approval.StateExpired, nil)
		a.outcomes[k] = approval.StateExpired
		return nil, true
	default: // denied, expired, or it went out (or may have) before: never again
		a.outcomes[k] = rec.State
		return nil, true
	}
	if !now.Before(rec.ExpiresAt) {
		a.Store.MoveApproval(rec.ID, approval.StateHeld, approval.StateExpired, nil)
		a.outcomes[k] = approval.StateExpired
		return nil, true
	}
	if old := a.open[k]; old != nil { // shown already (a resumed task's brain re-sent it): keep the first
		return old, false
	}
	h := &held{rec: rec, call: cmp.Or(act.Call, id), taint: ti.Tainted}
	a.open[k], a.byID[rec.ID] = h, k
	if a.OnWait != nil {
		a.OnWait(ti.ID, true)
	}
	h.timer = time.AfterFunc(rec.ExpiresAt.Sub(now), func() { a.expire(k) })
	return h, false
}

func (a *Approvals) event(h *held, state string) proto.Event {
	r := h.rec
	return proto.Event{Type: "approval", ID: h.call, Approval: &proto.Approval{ID: r.ID, Task: r.Task, Request: r.Request,
		Action: r.Action, Firm: r.Firm, Space: r.Space, Effect: json.RawMessage(r.Effect), EffectHash: r.EffectHash,
		Approvers: slices.Clone(r.Approvers), ExpiresAt: r.ExpiresAt, Tainted: h.taint, State: state}}
}

// List is the approvals waiting for identity (one of their approvers), oldest first: what the chat shows a sponsor
// or a starter to decide. space "" lists every space.
func (a *Approvals) List(identity, space string) []proto.Approval {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.init()
	var out []proto.Approval
	for _, h := range a.open {
		if slices.Contains(h.rec.Approvers, identity) && (space == "" || h.rec.Space == space) {
			out = append(out, *a.event(h, "").Approval)
		}
	}
	slices.SortFunc(out, func(x, y proto.Approval) int { return strings.Compare(x.ID, y.ID) })
	return out
}

// Answer takes a person's decision: the submission must verify against the held record (approval.Check: payload,
// approver, certificate, WebAuthn) and the record must still be held (a decision is taken once; the store's
// compare-and-swap makes a racing second one fail). Returns the new state.
func (a *Approvals) Answer(sub *approval.Submission) (string, error) {
	var head approval.Payload
	if sub == nil || jsonv2.Unmarshal(sub.Payload, &head) != nil {
		return "", ErrBadApproval
	}
	a.mu.Lock()
	a.init()
	k, ok := a.byID[head.Approval]
	h := a.open[k]
	if !ok || h == nil {
		a.mu.Unlock()
		return "", ErrNoApproval
	}
	rec := h.rec
	a.mu.Unlock()
	p, err := approval.Check(sub, rec.Expect(), a.Check)
	if errors.Is(err, approval.ErrExpired) {
		a.expire(k)
		return "", ErrNoApproval
	}
	if err != nil {
		return "", ErrBadApproval
	}
	state := approval.StateDenied
	if p.Decision == approval.Approve {
		state = approval.StateApproved
	}
	b, err := json.Marshal(sub)
	if err != nil {
		return "", ErrBadApproval
	}
	if err := a.Store.MoveApproval(rec.ID, approval.StateHeld, state, b); err != nil {
		return "", ErrNoApproval
	}
	a.mu.Lock()
	h = a.open[k]
	if h == nil { // closed meanwhile (the task ended): the store took the decision, but nothing will use it
		a.mu.Unlock()
		if state == approval.StateApproved {
			a.Store.MoveApproval(rec.ID, approval.StateApproved, approval.StateExpired, nil)
		}
		return "", ErrNoApproval
	}
	a.closeLocked(k, h)
	a.outcomes[k] = state
	if state == approval.StateApproved {
		a.subs[k] = sub
	}
	a.mu.Unlock()
	a.settled(h, state)
	return state, nil
}

// closeLocked removes an open approval (a.mu held).
func (a *Approvals) closeLocked(k string, h *held) {
	delete(a.open, k)
	delete(a.byID, h.rec.ID)
	if h.timer != nil {
		h.timer.Stop()
	}
	if a.OnWait != nil {
		a.OnWait(h.rec.Task, false)
	}
}

// expire: no decision in time is a deny. The record moves first (compare and swap), so an approval that won the
// race in the store isn't closed as expired here: Answer finishes it.
func (a *Approvals) expire(k string) {
	a.mu.Lock()
	h := a.open[k]
	a.mu.Unlock()
	if h == nil || a.Store.MoveApproval(h.rec.ID, approval.StateHeld, approval.StateExpired, nil) != nil {
		return
	}
	a.mu.Lock()
	if a.open[k] != h {
		a.mu.Unlock()
		return
	}
	a.closeLocked(k, h)
	a.outcomes[k] = approval.StateExpired
	a.mu.Unlock()
	a.settled(h, approval.StateExpired)
}

// settled tells the people following the task and lets the runtime hand the action on (Attach answers it).
func (a *Approvals) settled(h *held, state string) {
	a.Emit(h.rec.Task, a.event(h, state))
	go a.release(h.rec.Task, h.rec.Request)
}

func (a *Approvals) release(task, id string) error {
	for i := 0; ; i++ {
		err := a.Release(task, id, true, "")
		var pe *harness.Error
		if err == nil || !errors.As(err, &pe) || pe.Code != harness.CodeUnknownTask || i >= 500 {
			return err
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// Attach is called with each action the runtime hands on: an action decided here (denied, expired, unavailable,
// or gone before) is answered with the denial; an approved one is marked sending (before the connector runs, so a
// restart can never send it again) and goes on with its approval for gatewayd to check. An action not held here
// goes on as it is (gatewayd refuses one that needs an approval and has none).
func (a *Approvals) Attach(ctx context.Context, ti *harness.TaskInfo, id string, act *harness.Action) (context.Context, *harness.ActionResult) {
	k := key(ti.ID, id)
	a.mu.Lock()
	a.init()
	state, decided := a.outcomes[k]
	sub := a.subs[k]
	a.mu.Unlock()
	if !decided {
		return ctx, nil
	}
	deny := func(why string) (context.Context, *harness.ActionResult) {
		res := approvalDenial(why)
		out, _ := json.Marshal(map[string]string{"error": res.Error})
		a.Emit(ti.ID, proto.Event{Type: "tool_result", ID: cmp.Or(act.Call, id), Name: eventName(act.Name), Args: json.RawMessage(act.Args), Result: out})
		return ctx, res
	}
	if na := optionsOf(ti).NotAfter; state == approval.StateApproved && !na.IsZero() && !a.now().Before(na) {
		return deny("the sponsor's authority for this agent has ended")
	}
	switch state {
	case approval.StateApproved:
		if sub == nil || a.Store.MoveApproval(approval.ID(a.IDKey, ti.ID, id), approval.StateApproved, approval.StateSending, nil) != nil {
			return deny("the approval was already used")
		}
		return WithApproval(ctx, sub), nil
	case approval.StateDenied:
		return deny("the person declined")
	case approval.StateExpired:
		return deny("the approval expired before anyone answered")
	case ApprovalUnavailable:
		return deny("nobody can approve this here (no approver for this task, or its effect can't be shown)")
	case approval.StateSent, approval.StateSending, approval.StateUnknown, approval.StateFailed:
		return deny("it was already handled before a restart (it may have gone out); it's never sent twice")
	}
	return deny("not approved")
}

// Done records how an approved effect ended (after the connector answered): sent, or failed. A result the
// connector never gave (the runtime died) leaves it sending, which Recover turns into unknown.
func (a *Approvals) Done(task, id string, res *harness.ActionResult, err error) {
	a.mu.Lock()
	state := a.outcomes[key(task, id)]
	a.mu.Unlock()
	if state != approval.StateApproved {
		return
	}
	// Only a definite answer from the connector is sent or failed: a lost connection or a cancel while it ran may
	// have let it go out, so that's unknown (never sent again, the person told it may have gone).
	to := approval.StateUnknown
	switch {
	case err == nil && res != nil && res.Status == harness.ActionDone:
		to = approval.StateSent
	case err == nil && res != nil:
		to = approval.StateFailed
	}
	ap := approval.ID(a.IDKey, task, id)
	a.Store.MoveApproval(ap, approval.StateSending, to, nil)
	if rec, _ := a.Store.Approval(ap); rec != nil {
		a.Emit(task, a.event(&held{rec: *rec}, to))
	}
}

// Recover is called once at boot, before any task resumes: every effect still sending may or may not have happened
// (the process died during the connector's call), so it becomes unknown and is never sent again by the VM (docs/27
// section 4). It returns them, for the person to be told.
func (a *Approvals) Recover() ([]approval.Record, error) {
	recs, err := a.Store.Approvals(approval.StateSending)
	if err != nil {
		return nil, err
	}
	var out []approval.Record
	for _, r := range recs {
		if a.Store.MoveApproval(r.ID, approval.StateSending, approval.StateUnknown, nil) == nil {
			r.State = approval.StateUnknown
			out = append(out, r)
		}
	}
	return out, nil
}

// Resume shows a resumed task's waiting approvals again (they stay held across a restart) with their first
// expiry, and tells its followers about effects Recover found unknown.
func (a *Approvals) Resume(ti *harness.TaskInfo, journal []harness.Record) {
	for _, r := range journal {
		if r.Kind != harness.TypeAction || r.Held != harness.WaitApproval || r.Done {
			continue
		}
		var act harness.Action
		if json.Unmarshal(r.Req, &act) != nil {
			continue
		}
		c := *ti
		c.Tainted = ti.Tainted || journalTainted(journal)
		if sub, _ := a.hold(&c, r.ID, &act, true); sub == "" {
			a.release(ti.ID, r.ID) // decided meanwhile (expired, or decided before the restart): Attach answers it
		}
	}
	if a.Store == nil {
		return
	}
	if rec, _ := a.Store.Approvals(approval.StateUnknown); rec != nil {
		for _, r := range rec {
			if r.Task == ti.ID {
				a.Emit(ti.ID, a.event(&held{rec: r}, approval.StateUnknown))
			}
		}
	}
}

// Outcome is the approval state an action ran (or was denied) with ("" when it needed none here).
func (a *Approvals) Outcome(task, id string) string {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.init()
	return a.outcomes[key(task, id)]
}

// Waiting is how many approvals of a task wait for a person.
func (a *Approvals) Waiting(task string) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	n := 0
	for _, h := range a.open {
		if h.rec.Task == task {
			n++
		}
	}
	return n
}

// Forget drops a task's open approvals and outcomes (it ended): one still waiting can't be decided any more (its
// record says expired). The records stay until the task is deleted (Host.Forgotten: DeleteApprovals).
func (a *Approvals) Forget(task string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.init()
	prefix := task + "\x00"
	for k, h := range a.open {
		if strings.HasPrefix(k, prefix) {
			a.closeLocked(k, h)
			a.Store.MoveApproval(h.rec.ID, approval.StateHeld, approval.StateExpired, nil)
		}
	}
	for k := range a.outcomes {
		if strings.HasPrefix(k, prefix) {
			delete(a.outcomes, k)
			delete(a.subs, k)
		}
	}
}
