package harness

import (
	"testing"
	"time"
)

// Load counts tasks by state only: slots in use, waiting ones among them, and queued ones (a task waiting for a key
// holder hasn't started, so it is queued).
func TestLoadCounts(t *testing.T) {
	r := &Runtime{}
	r.init()
	for _, lc := range []Lifecycle{
		{State: StateRunning},
		{State: StateWaiting, Sub: WaitApproval},
		{State: StatePaused},
		{State: StateQueued},
		{State: StateWaiting, Sub: WaitKeyHolder},
	} {
		r.order = append(r.order, &task{lc: lc})
	}
	l := r.Load(5 * time.Minute)
	if l.Running != 3 || l.Waiting != 1 || l.Queued != 2 || l.Ended != 0 || l.P50 != 0 || l.P95 != 0 {
		t.Fatalf("load %+v", l)
	}
}

// Durations: only tasks this process started, only those ended within the window, nearest-rank percentiles; the
// record is bounded.
func TestLoadDurations(t *testing.T) {
	r := &Runtime{}
	r.init()
	r.noteEndLocked(&task{}) // restored from the Store: no start time here, not measured
	if len(r.ends) != 0 {
		t.Fatal("a restored task was measured")
	}
	for i := 1; i <= 20; i++ {
		r.noteEndLocked(&task{added: time.Now().Add(-time.Duration(i) * time.Second)})
	}
	r.ends = append([]taskEnd{{at: time.Now().Add(-10 * time.Minute), took: time.Hour}}, r.ends...) // outside the window
	l := r.Load(5 * time.Minute)
	if l.Ended != 20 {
		t.Fatalf("ended %d, want 20", l.Ended)
	}
	if l.P50 < 10*time.Second || l.P50 > 11*time.Second || l.P95 < 19*time.Second || l.P95 > 20*time.Second {
		t.Fatalf("p50 %v p95 %v", l.P50, l.P95)
	}
	for i := 0; i < endsKept+50; i++ {
		r.noteEndLocked(&task{added: time.Now()})
	}
	if len(r.ends) != endsKept {
		t.Fatalf("kept %d end records, want %d", len(r.ends), endsKept)
	}
	if got := rank([]time.Duration{7}, 95); got != 7 {
		t.Fatalf("rank of one: %v", got)
	}
}
