package harness

import (
	"math/rand/v2"
	"strings"
	"testing"
)

// The lifecycle state machine (docs/27 section 1): one test per row of the table, then properties over random
// event sequences.

func ev(kind string, x ...string) LifecycleEvent {
	e := LifecycleEvent{Kind: kind}
	switch {
	case kind == EvEnd && len(x) > 0:
		e.Outcome = x[0]
	case len(x) > 0:
		e.Sub = x[0]
	}
	return e
}

func must(t *testing.T, l Lifecycle, evs ...LifecycleEvent) Lifecycle {
	t.Helper()
	for _, e := range evs {
		n, err := Next(l, e)
		if err != nil {
			t.Fatalf("%+v + %+v: %v", l, e, err)
		}
		l = n
	}
	return l
}

func refused(t *testing.T, l Lifecycle, e LifecycleEvent) {
	t.Helper()
	if n, err := Next(l, e); err == nil {
		t.Fatalf("%+v + %+v gave %+v, want refused", l, e, n)
	} else if n != l {
		t.Fatalf("a refused event changed the state: %+v -> %+v", l, n)
	}
}

// Every row of the table: how a state is entered and left.
func TestLifecycleTable(t *testing.T) {
	q := NewLifecycle()
	if q.State != StateQueued || !q.Valid() || q.Started() {
		t.Fatalf("new: %+v", q)
	}
	run := must(t, q, ev(EvDispatch))
	if run.State != StateRunning || run.Sub != "" {
		t.Fatalf("dispatched: %+v", run)
	}
	// waiting: each sub-state a request can be held for, left when it's decided.
	for _, sub := range []string{WaitApproval, WaitPermission, WaitAnswer, WaitChildren} {
		w := must(t, run, ev(EvHold, sub))
		if w.State != StateWaiting || w.Sub != sub || w.Holds != 1 {
			t.Fatalf("held for %s: %+v", sub, w)
		}
		if back := must(t, w, ev(EvRelease)); back != run {
			t.Fatalf("released: %+v", back)
		}
	}
	// Two holds: waits until both are decided; the first's sub-state shows.
	w2 := must(t, run, ev(EvHold, WaitApproval), ev(EvHold, WaitPermission))
	if w2.Sub != WaitApproval || w2.Holds != 2 {
		t.Fatalf("two holds: %+v", w2)
	}
	if w1 := must(t, w2, ev(EvRelease)); w1.State != StateWaiting || w1.Holds != 1 {
		t.Fatalf("one of two released: %+v", w1)
	}
	// waiting for a key holder: a task not started yet.
	kh := must(t, q, ev(EvAwaitHolder))
	if kh.State != StateWaiting || kh.Sub != WaitKeyHolder || kh.Started() {
		t.Fatalf("key holder: %+v", kh)
	}
	if back := must(t, kh, ev(EvHolderSealed)); back.State != StateQueued {
		t.Fatalf("key re-sealed: %+v", back)
	}
	refused(t, kh, ev(EvHold, WaitApproval))
	refused(t, kh, ev(EvEnd, OutcomeSucceeded))
	// paused: each cause; a pause keeps the holds, and a resume returns to them.
	for _, sub := range []string{PauseStop, PauseSponsorGone, PauseStale, PauseDayBudget} {
		p := must(t, run, ev(EvPause, sub))
		if p.State != StatePaused || p.Sub != sub {
			t.Fatalf("paused for %s: %+v", sub, p)
		}
		if back := must(t, p, ev(EvResume)); back != run {
			t.Fatalf("resumed: %+v", back)
		}
	}
	pw := must(t, run, ev(EvHold, WaitApproval), ev(EvPause, PauseStop))
	if pw.State != StatePaused || pw.Holds != 1 {
		t.Fatalf("paused while waiting: %+v", pw)
	}
	if back := must(t, pw, ev(EvResume)); back.State != StateWaiting || back.Sub != WaitApproval {
		t.Fatalf("resumed while held: %+v", back)
	}
	if back := must(t, pw, ev(EvRelease), ev(EvResume)); back != run {
		t.Fatalf("released while paused, then resumed: %+v", back)
	}
	// done, failed, cancelled.
	for _, c := range []struct {
		from Lifecycle
		out  string
		want string
	}{{run, OutcomeSucceeded, StateDone}, {run, OutcomeFailed, StateFailed}, {w2, OutcomeCancelled, StateCancelled},
		{pw, OutcomeCancelled, StateCancelled}, {q, OutcomeCancelled, StateCancelled}, {q, OutcomeFailed, StateFailed},
		{kh, OutcomeCancelled, StateCancelled}} {
		if e := must(t, c.from, ev(EvEnd, c.out)); e.State != c.want || e.Holds != 0 || e.Sub != "" {
			t.Fatalf("%+v ended %s: %+v", c.from, c.out, e)
		}
	}
	// What isn't allowed.
	refused(t, q, ev(EvEnd, OutcomeSucceeded)) // never ran
	refused(t, q, ev(EvHold, WaitApproval))
	refused(t, q, ev(EvPause, PauseStop))
	refused(t, run, ev(EvDispatch))
	refused(t, run, ev(EvRelease))
	refused(t, run, ev(EvResume))
	refused(t, run, ev(EvHold, WaitKeyHolder))
	refused(t, run, ev(EvHold, PauseStop))
	refused(t, run, ev(EvPause, WaitApproval))
	refused(t, run, ev(EvEnd, "maybe"))
	refused(t, run, ev("teleport"))
}

var allEvents = func() []LifecycleEvent {
	var out []LifecycleEvent
	for _, k := range []string{EvDispatch, EvRelease, EvResume, EvAwaitHolder, EvHolderSealed, "bogus"} {
		out = append(out, ev(k))
	}
	for _, s := range []string{WaitApproval, WaitPermission, WaitAnswer, WaitChildren, WaitKeyHolder, PauseStop, ""} {
		out = append(out, ev(EvHold, s))
	}
	for _, s := range []string{PauseStop, PauseSponsorGone, PauseStale, PauseDayBudget, WaitApproval, ""} {
		out = append(out, ev(EvPause, s))
	}
	for _, o := range []string{OutcomeSucceeded, OutcomeFailed, OutcomeCancelled, ""} {
		out = append(out, ev(EvEnd, o))
	}
	return out
}()

// allowedEdges is the table as edges: every transition Next makes must be one of them.
var allowedEdges = map[[2]string]bool{
	{StateQueued, StateRunning}: true, {StateQueued, StateWaiting}: true, {StateWaiting, StateQueued}: true,
	{StateRunning, StateWaiting}: true, {StateWaiting, StateRunning}: true, {StateWaiting, StateWaiting}: true,
	{StateRunning, StatePaused}: true, {StateWaiting, StatePaused}: true, {StatePaused, StateRunning}: true,
	{StatePaused, StateWaiting}: true, {StatePaused, StatePaused}: true,
	{StateQueued, StateCancelled}: true, {StateQueued, StateFailed}: true,
	{StateRunning, StateDone}: true, {StateRunning, StateFailed}: true, {StateRunning, StateCancelled}: true,
	{StateWaiting, StateDone}: true, {StateWaiting, StateFailed}: true, {StateWaiting, StateCancelled}: true,
	{StatePaused, StateDone}: true, {StatePaused, StateFailed}: true, {StatePaused, StateCancelled}: true,
}

// Properties over random event sequences (fixed seeds, so a failure reproduces): every reachable lifecycle is
// valid; refused events change nothing; every transition is an edge of the table; an ended task stays ended;
// cancel is always possible before the end (the kill switch can't be blocked by any state); a task is waiting
// exactly while it has holds and isn't paused; holds go up and down by one; the queue is only re-entered from a
// key holder's wait.
func TestLifecycleProperties(t *testing.T) {
	for seed := uint64(1); seed <= 400; seed++ {
		rng := rand.New(rand.NewPCG(seed, 0x7a51c))
		l := NewLifecycle()
		holds := 0
		var trail []string
		for step := 0; step < 120; step++ {
			e := allEvents[rng.IntN(len(allEvents))]
			n, err := Next(l, e)
			trail = append(trail, e.Kind+":"+e.Sub+e.Outcome)
			fail := func(format string, args ...any) {
				t.Helper()
				t.Fatalf("seed %d step %d (%s): "+format, append([]any{seed, step, strings.Join(trail, " ")}, args...)...)
			}
			if !Terminal(l.State) {
				if c, err := Next(l, ev(EvEnd, OutcomeCancelled)); err != nil || c.State != StateCancelled || !c.Valid() {
					fail("cancel refused in %+v: %v", l, err)
				}
			}
			if err != nil {
				if n != l {
					fail("refused %+v changed %+v to %+v", e, l, n)
				}
				continue
			}
			if !n.Valid() {
				fail("invalid lifecycle %+v after %+v from %+v", n, e, l)
			}
			if Terminal(l.State) {
				fail("left the end state %+v with %+v", l, e)
			}
			if n.State != l.State || n.Sub != l.Sub {
				if !allowedEdges[[2]string{l.State, n.State}] {
					fail("edge %s -> %s isn't in the table", l.State, n.State)
				}
			}
			if n.State == StateQueued && l.State != StateQueued && l.Sub != WaitKeyHolder {
				fail("back to queued from %+v", l)
			}
			switch e.Kind {
			case EvHold:
				holds++
			case EvRelease:
				holds--
			case EvEnd:
				holds = 0
			}
			if n.Holds != holds || holds < 0 {
				fail("holds %d, counted %d", n.Holds, holds)
			}
			if !Terminal(n.State) && n.Sub != WaitKeyHolder {
				if waiting := n.State == StateWaiting; waiting != (n.Holds > 0 && n.State != StatePaused) {
					fail("waiting %v with %d holds in %+v", waiting, n.Holds, n)
				}
			}
			if Terminal(n.State) {
				for _, e2 := range allEvents {
					if _, err := Next(n, e2); err == nil {
						fail("%+v left the end state %s", e2, n.State)
					}
				}
			}
			l = n
		}
	}
}

func TestTaskIDs(t *testing.T) {
	seen := map[string]bool{}
	for range 1000 {
		id := NewTaskID()
		if !ValidTaskID(id) || !ValidID(id) || len(id) != 29 || seen[id] {
			t.Fatalf("id %q", id)
		}
		seen[id] = true
	}
	k1, k2 := []byte("space key one"), []byte("space key two")
	a := DeriveTaskID(k1, "start", "user", "key")
	if a != DeriveTaskID(k1, "start", "user", "key") || !ValidTaskID(a) {
		t.Fatalf("derived %q isn't stable or valid", a)
	}
	for _, other := range []string{DeriveTaskID(k2, "start", "user", "key"), DeriveTaskID(k1, "start", "userkey"),
		DeriveTaskID(k1, "start", "use", "rkey"), DeriveTaskID(k1, "start", "user", "key", "")} {
		if other == a {
			t.Fatalf("different key or parts gave the same id %q", a)
		}
	}
	for _, bad := range []string{"t_" + a[3:], "tk_" + strings.ToUpper(a[3:]), a + "a", a[:28], "tk_" + a[3:28] + "1", "tk_" + a[3:28] + "b"} {
		if ValidTaskID(bad) {
			t.Errorf("%q accepted", bad)
		}
	}
}
