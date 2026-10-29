package trigger

import (
	"testing"
	"time"
)

// NextRun, for the relay's wake-up: the earliest run still to start, to the minute, in UTC. Before today's time it's
// today's; once it fired, the next day's. A run due while the VM was off keeps its own (past) time until it fires,
// so the relay doesn't stop the VM before it does; it fires once, however many ticks come after.
func TestNextRunDailyAndCatchUp(t *testing.T) {
	lis := mustZone(t, "Europe/Lisbon")
	w, _ := dailyWorld(t, "07:00", "Europe/Lisbon", time.Date(2026, 10, 20, 12, 0, 0, 0, lis))
	want := func(at time.Time, exp time.Time) {
		t.Helper()
		w.set(at)
		if got := w.e.NextRun(); !got.Equal(exp) || got.Location() != time.UTC {
			t.Fatalf("at %s: next run %s, want %s", at, got, exp.UTC())
		}
	}
	day21 := time.Date(2026, 10, 21, 7, 0, 0, 0, lis)
	want(time.Date(2026, 10, 20, 12, 0, 0, 0, lis), day21)
	want(time.Date(2026, 10, 21, 6, 59, 30, 0, lis), day21)
	// The VM was off at 07:00 and is up at 07:20, its clock not trusted yet: the run is still owed (past time).
	w.set(time.Date(2026, 10, 21, 7, 20, 0, 0, lis))
	w.mu.Lock()
	w.fresh = false
	w.mu.Unlock()
	if f, _ := w.e.Due(); len(f) != 0 {
		t.Fatalf("fired without operator time: %+v", f)
	}
	want(time.Date(2026, 10, 21, 7, 20, 0, 0, lis), day21)
	w.mu.Lock()
	w.fresh = true
	w.mu.Unlock()
	// Clock trusted: it catches up once, and the next run is tomorrow's.
	if f := w.tick(time.Date(2026, 10, 21, 7, 20, 30, 0, lis)); len(f) != 1 || DayOf(f[0].Slot) != "2026-10-21" {
		t.Fatalf("catch-up: %+v", f)
	}
	for _, at := range []time.Time{time.Date(2026, 10, 21, 7, 21, 0, 0, lis), time.Date(2026, 10, 21, 9, 0, 0, 0, lis)} {
		if f := w.tick(at); len(f) != 0 {
			t.Fatalf("fired twice: %+v", f)
		}
	}
	want(time.Date(2026, 10, 21, 9, 0, 0, 0, lis), time.Date(2026, 10, 22, 7, 0, 0, 0, lis))
	// Off past 3 h late: that day is skipped, not owed, and the next run is the day after.
	want(time.Date(2026, 10, 22, 10, 1, 0, 0, lis), time.Date(2026, 10, 23, 7, 0, 0, 0, lis))
	if f := w.tick(time.Date(2026, 10, 22, 10, 1, 0, 0, lis)); len(f) != 0 {
		t.Fatalf("fired 3 h late: %+v", f)
	}
	// Stopped: none.
	if _, err := w.e.Stop(w.agent, false); err != nil {
		t.Fatal(err)
	}
	want(time.Date(2026, 10, 22, 11, 0, 0, 0, lis), time.Time{})
}

// A one-time run: its time until it fired, then none (ended). An interval schedule: the current slot's start while it
// hasn't fired, then the next slot's. Floored to the minute; nothing past not_after.
func TestNextRunOnceIntervalAndNotAfter(t *testing.T) {
	w, d := dailyWorld(t, "07:00", "UTC", time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC))
	d.Version = 2
	d.Triggers[0].Daily, d.Triggers[0].At = "", "2026-10-20T15:30"
	if _, err := w.install(d, w.sponsorK); err != nil {
		t.Fatal(err)
	}
	if got := w.e.NextRun(); !got.Equal(time.Date(2026, 10, 20, 15, 30, 0, 0, time.UTC)) {
		t.Fatalf("one-time: %s", got)
	}
	if f := w.tick(time.Date(2026, 10, 20, 15, 30, 10, 0, time.UTC)); len(f) != 1 {
		t.Fatalf("one-time fire: %+v", f)
	}
	if got := w.e.NextRun(); !got.IsZero() {
		t.Fatalf("ended one-time: %s", got)
	}

	w2 := newWorld(t)
	def := w2.def(1)
	def.Triggers[0].Anchor = time.Date(2026, 10, 18, 0, 0, 30, 0, time.UTC) // seconds: floored to the minute
	if _, err := w2.install(def, w2.authorK, w2.sponsorK); err != nil {
		t.Fatal(err)
	}
	// 12:07: slot 12 (from 12:00:30) is still to fire.
	if got := w2.e.NextRun(); !got.Equal(time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)) {
		t.Fatalf("interval, unfired: %s", got)
	}
	if f := w2.tick(w2.now); len(f) != 1 {
		t.Fatalf("interval fire: %+v", f)
	}
	if got := w2.e.NextRun(); !got.Equal(time.Date(2026, 10, 18, 13, 0, 0, 0, time.UTC)) {
		t.Fatalf("interval, fired: %s", got)
	}
	// Its next slot would be at or past not_after: none.
	def.Version, def.NotAfter = 2, time.Date(2026, 10, 18, 13, 0, 30, 0, time.UTC)
	if _, err := w2.install(def, w2.authorK, w2.sponsorK); err != nil {
		t.Fatal(err)
	}
	if got := w2.e.NextRun(); !got.IsZero() {
		t.Fatalf("past not_after: %s", got)
	}
}
