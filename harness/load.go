package harness

import (
	"slices"
	"time"
)

// Load is how busy the runtime is now, for the VM's GET /load (app/load.go, docs/41 §9): counts and durations only,
// never a task's id, input, person or space.
type Load struct {
	Running int // tasks a brain has (running, paused, or waiting on a request): the slots in use
	Waiting int // of Running, the ones waiting on a request's decision or an answer (a person, a child task)
	Queued  int // tasks no brain has yet (queued, or waiting for a key holder)
	Ended   int // tasks this process started that ended within the window
	// P50 and P95 are those tasks' times from their start to their end (0 when none ended in the window).
	P50, P95 time.Duration
}

// endsKept bounds the end records kept for Load's percentiles: a VM ends far fewer tasks than this in five minutes.
const endsKept = 1024

type taskEnd struct {
	at   time.Time
	took time.Duration
}

// noteEndLocked records an ending task's duration (r.mu held). A task restored from the Store has no start time in
// this process (added is zero) and isn't measured.
func (r *Runtime) noteEndLocked(t *task) {
	if t.added.IsZero() {
		return
	}
	now := time.Now()
	if len(r.ends) >= endsKept {
		r.ends = slices.Delete(r.ends, 0, len(r.ends)-endsKept+1)
	}
	r.ends = append(r.ends, taskEnd{at: now, took: now.Sub(t.added)})
}

// Load counts the tasks not ended by state, and the durations of those that ended within window.
func (r *Runtime) Load(window time.Duration) Load {
	r.init()
	r.mu.Lock()
	defer r.mu.Unlock()
	var l Load
	for _, t := range r.order {
		switch {
		case t.lc.Started():
			l.Running++
			if t.lc.State == StateWaiting {
				l.Waiting++
			}
		case t.lc.State == StateQueued || t.lc.State == StateWaiting: // waiting for a key holder: not started
			l.Queued++
		}
	}
	since := time.Now().Add(-window)
	var took []time.Duration
	for _, e := range r.ends {
		if e.at.After(since) {
			took = append(took, e.took)
		}
	}
	l.Ended = len(took)
	if len(took) > 0 {
		slices.Sort(took)
		l.P50, l.P95 = rank(took, 50), rank(took, 95)
	}
	return l
}

// rank is the nearest-rank percentile p of sorted (non-empty).
func rank(sorted []time.Duration, p int) time.Duration {
	i := (p*len(sorted) + 99) / 100
	return sorted[max(0, min(len(sorted), i)-1)]
}
