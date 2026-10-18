package harness

import "fmt"

// The task lifecycle (docs/27 section 1). The runtime owns the state; a sub-state says why a task waits
// or is paused and is metadata only. harness/v1 doesn't change on the wire: to the brain, waiting and paused are
// "the result is late".
//
//	queued ──dispatch──▶ running ◀──release (last hold)── waiting(sub) ◀──hold── running
//	   │                    │  ▲                              │
//	   │                    │  └──────resume──── paused(sub) ◀┘ pause (from running or waiting)
//	   │                    └──end──▶ done | failed | cancelled ◀── end (from running, waiting, paused)
//	   └──end (cancelled, failed)──▶                           ◀── cancel (from any state not ended)
//
// A task can have several requests held at once (Holds); it waits until the last is released. A pause keeps the
// holds and their sub-state, so a resume returns to waiting while any are left. A task waiting for a key holder
// (a fresh VM must resume an attended task) hasn't started: it goes back to queued when a holder re-seals its key.

// Task states.
const (
	StateQueued    = "queued"
	StateRunning   = "running"
	StateWaiting   = "waiting"
	StatePaused    = "paused"
	StateDone      = "done"
	StateFailed    = "failed"
	StateCancelled = "cancelled"
)

// Why a task waits (StateWaiting).
const (
	WaitApproval   = "approval"   // an effect is held for a person's approval
	WaitPermission = "permission" // a permission kind is on Ask
	WaitAnswer     = "answer"     // the brain called person.ask
	WaitChildren   = "children"   // task.wait
	WaitKeyHolder  = "key_holder" // a fresh VM must resume an attended task (not started)
)

// Why a task is paused (StatePaused).
const (
	PauseStop        = "stop"         // a firm or operator stop
	PauseSponsorGone = "sponsor_gone" // the sponsor was revoked or left the space
	PauseStale       = "stale"        // the stop list went stale before an effect
	PauseDayBudget   = "day_budget"   // the space's day is used up
)

var (
	waitSubs  = map[string]bool{WaitApproval: true, WaitPermission: true, WaitAnswer: true, WaitChildren: true}
	pauseSubs = map[string]bool{PauseStop: true, PauseSponsorGone: true, PauseStale: true, PauseDayBudget: true}
)

// Lifecycle is a task's state as the runtime keeps it.
type Lifecycle struct {
	State string
	Sub   string // why it waits or is paused; "" otherwise
	Holds int    // requests held (waiting for a person or for children)
	// WaitSub is the sub-state of the holds: the first held request's, kept through a pause.
	WaitSub string
}

// Event kinds a Lifecycle takes.
const (
	EvDispatch     = "dispatch"      // a brain with room gets the task (queued → running)
	EvHold         = "hold"          // a request is held (Sub: a wait sub-state)
	EvRelease      = "release"       // a held request was decided (approved, denied, expired, cancelled)
	EvPause        = "pause"         // Sub: a pause sub-state
	EvResume       = "resume"        // the pause's cause cleared
	EvAwaitHolder  = "await_holder"  // queued → waiting(key_holder)
	EvHolderSealed = "holder_sealed" // waiting(key_holder) → queued
	EvEnd          = "end"           // Outcome: succeeded, failed or cancelled
)

// LifecycleEvent is one input to Next.
type LifecycleEvent struct {
	Kind    string
	Sub     string // EvHold, EvPause
	Outcome string // EvEnd
}

// Terminal reports whether state is an ended one (done, failed, cancelled): nothing leaves it.
func Terminal(state string) bool {
	return state == StateDone || state == StateFailed || state == StateCancelled
}

// Started reports whether a brain has been given the task (running, waiting on a request, or paused).
func (l Lifecycle) Started() bool {
	return l.State == StateRunning || l.State == StatePaused || l.State == StateWaiting && l.Sub != WaitKeyHolder
}

// EndState is the task state an outcome ends in.
func EndState(outcome string) string {
	switch outcome {
	case OutcomeSucceeded:
		return StateDone
	case OutcomeCancelled:
		return StateCancelled
	}
	return StateFailed
}

// NewLifecycle is a new task's: queued.
func NewLifecycle() Lifecycle { return Lifecycle{State: StateQueued} }

// Next is the lifecycle after ev, or an error (and cur unchanged) when ev isn't allowed in cur's state.
func Next(cur Lifecycle, ev LifecycleEvent) (Lifecycle, error) {
	bad := func() (Lifecycle, error) {
		return cur, fmt.Errorf("harness: %s isn't allowed while %s", ev.Kind, cur.State)
	}
	if Terminal(cur.State) {
		return bad()
	}
	n := cur
	switch ev.Kind {
	case EvDispatch:
		if cur.State != StateQueued {
			return bad()
		}
		n.State, n.Sub = StateRunning, ""
	case EvHold:
		if !waitSubs[ev.Sub] || !cur.Started() {
			return bad()
		}
		n.Holds++
		if cur.Holds == 0 {
			n.WaitSub = ev.Sub
		}
		if cur.State != StatePaused {
			n.State, n.Sub = StateWaiting, n.WaitSub
		}
	case EvRelease:
		if cur.Holds == 0 || !cur.Started() {
			return bad()
		}
		if n.Holds--; n.Holds == 0 {
			n.WaitSub = ""
			if cur.State == StateWaiting {
				n.State, n.Sub = StateRunning, ""
			}
		}
	case EvPause:
		if !pauseSubs[ev.Sub] || !cur.Started() {
			return bad()
		}
		if cur.State != StatePaused {
			n.State, n.Sub = StatePaused, ev.Sub
		}
	case EvResume:
		if cur.State != StatePaused {
			return bad()
		}
		n.State, n.Sub = StateRunning, ""
		if n.Holds > 0 {
			n.State, n.Sub = StateWaiting, n.WaitSub
		}
	case EvAwaitHolder:
		if cur.State != StateQueued {
			return bad()
		}
		n.State, n.Sub = StateWaiting, WaitKeyHolder
	case EvHolderSealed:
		if cur.State != StateWaiting || cur.Sub != WaitKeyHolder {
			return bad()
		}
		n.State, n.Sub = StateQueued, ""
	case EvEnd:
		end := EndState(ev.Outcome)
		switch {
		case ev.Outcome != OutcomeSucceeded && ev.Outcome != OutcomeFailed && ev.Outcome != OutcomeCancelled:
			return bad()
		case !cur.Started() && end == StateDone: // a task that never ran can't have succeeded
			return bad()
		}
		n = Lifecycle{State: end}
	default:
		return bad()
	}
	return n, nil
}

// Valid reports whether l is a lifecycle Next can produce: a known state, a sub-state that fits it, holds only on a
// started task, and the holds' sub-state with them.
func (l Lifecycle) Valid() bool {
	if l.Holds < 0 || (l.Holds > 0) != (l.WaitSub != "") || l.WaitSub != "" && !waitSubs[l.WaitSub] {
		return false
	}
	switch l.State {
	case StateQueued:
		return l.Sub == "" && l.Holds == 0
	case StateRunning:
		return l.Sub == "" && l.Holds == 0
	case StateWaiting:
		if l.Sub == WaitKeyHolder {
			return l.Holds == 0
		}
		return l.Holds > 0 && l.Sub == l.WaitSub
	case StatePaused:
		return pauseSubs[l.Sub]
	case StateDone, StateFailed, StateCancelled:
		return l.Sub == "" && l.Holds == 0
	}
	return false
}
