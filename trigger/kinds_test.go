package trigger

import (
	"errors"
	"slices"
	"strings"
	"testing"
	"time"
)

// Schedules on chosen weekdays and one-time schedules (v0.14.0; SCHEDULES.md "Triggers").

func TestKindTriggerChecks(t *testing.T) {
	bad := []Trigger{
		{Kind: Schedule, Daily: "07:00", Zone: "UTC", Days: []string{}},                                                // empty days
		{Kind: Schedule, Daily: "07:00", Zone: "UTC", Days: []string{"mon", "tue", "wed", "thu", "fri", "sat", "sun"}}, // all seven: no days
		{Kind: Schedule, Daily: "07:00", Zone: "UTC", Days: []string{"tue", "tue"}},
		{Kind: Schedule, Daily: "07:00", Zone: "UTC", Days: []string{"thu", "tue"}}, // out of week order
		{Kind: Schedule, Daily: "07:00", Zone: "UTC", Days: []string{"Tue"}},
		{Kind: Schedule, Daily: "07:00", Zone: "UTC", Days: []string{"tuesday"}},
		{Kind: Schedule, Daily: "07:00", Zone: "UTC", Days: []string{""}},
		{Kind: Schedule, Zone: "UTC", Days: []string{"tue"}}, // days without a time
		{Kind: Schedule, Days: []string{"tue"}, Every: "1h", Anchor: time.Now()},
		{Kind: Schedule, At: "2026-10-21T19:10"},                                     // no zone
		{Kind: Schedule, At: "2026-10-21T19:10", Zone: "Mars/Olympus"},               // bad zone
		{Kind: Schedule, At: "2026-10-21T19:10", Zone: "UTC", Daily: "19:10"},        // at with daily
		{Kind: Schedule, At: "2026-10-21T19:10", Zone: "UTC", Days: []string{"wed"}}, // at with days
		{Kind: Schedule, At: "2026-10-21T19:10", Zone: "UTC", Every: "1h", Anchor: time.Now()},
		{Kind: Schedule, At: "2026-02-30T19:10", Zone: "UTC"}, // not a date
		{Kind: Schedule, At: "2026-10-21T24:00", Zone: "UTC"},
		{Kind: Schedule, At: "2026-10-21 19:10", Zone: "UTC"},
		{Kind: Schedule, At: "2026-10-21T19:10:00", Zone: "UTC"},
		{Kind: Schedule, At: "2026-10-21T19:10Z", Zone: "UTC"},
		{Kind: Schedule, At: "26-10-21T19:10", Zone: "UTC"},
		{Kind: Event, At: "2026-10-21T19:10", Sender: "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="},
		{Kind: Event, Days: []string{"tue"}, Sender: "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="},
	}
	for _, tr := range bad {
		tr.ID = "tr_aaaaaaaaaaaaaaaaaaaaaaaaaa"
		if tr.check() == nil {
			t.Errorf("accepted %+v", tr)
		}
	}
	for _, tr := range []Trigger{
		{Kind: Schedule, Daily: "07:00", Zone: "Europe/Lisbon", Days: []string{"tue", "thu"}},
		{Kind: Schedule, Daily: "07:00", Zone: "Europe/Lisbon", Days: []string{"mon", "tue", "wed", "thu", "fri"}},
		{Kind: Schedule, Daily: "07:00", Zone: "UTC", Days: []string{"sun"}},
		{Kind: Schedule, At: "2026-10-21T19:10", Zone: "Europe/Lisbon"},
		{Kind: Schedule, At: "2028-02-29T00:00", Zone: "UTC"},
	} {
		tr.ID = "tr_aaaaaaaaaaaaaaaaaaaaaaaaaa"
		if err := tr.check(); err != nil {
			t.Errorf("%+v: %v", tr, err)
		}
	}
}

// kindWorld is a personal-style world whose definition has the one trigger tr (its id set), issued at issued.
func kindWorld(t *testing.T, tr Trigger, issued time.Time) (*world, Definition) {
	w := newWorld(t)
	w.set(issued)
	tr.ID, tr.Kind = w.sched, Schedule
	d := Definition{Firm: firm, Space: w.space, Agent: w.agent, Version: 1, Instructions: "Digest of https://news.ycombinator.com/",
		Seal: testSeal, Models: []string{"deepseek-v4-1-flash"}, Tools: []string{"web.fetch"}, MaxSteps: 20,
		Triggers: []Trigger{tr}, Allow: map[string]string{"web.fetch": "always"},
		Author: w.sponsor, Sponsor: w.sponsor, IssuedAt: issued, NotAfter: issued.Add(DefaultSponsorship)}
	if _, err := w.install(d, w.sponsorK); err != nil {
		t.Fatal(err)
	}
	if err := Personal(&d, w.space, testSeal, w.sponsor); err != nil {
		t.Fatalf("personal rules: %v", err)
	}
	return w, d
}

// run ticks every step from from to to and returns each fire as "local time zone-abbrev day", checking each task id is
// new, its due instant is its slot's, and the next run said just before it was it.
func (w *world) run(from, to time.Time, step time.Duration, loc *time.Location) []string {
	var got []string
	tasks := map[string]bool{}
	var next time.Time
	for at := from; at.Before(to); at = at.Add(step) {
		in := w.e.Get(w.agent)
		for _, f := range w.tick(at) {
			got = append(got, f.Due.In(loc).Format("Mon 01-02 15:04 MST")+" "+DayOf(f.Slot))
			if tasks[f.Task] {
				w.t.Fatalf("task %s twice", f.Task)
			}
			tasks[f.Task] = true
			if !f.Due.Equal(f.Trigger.SlotAt(f.Slot)) || f.At.Sub(f.Due) < 0 || f.At.Sub(f.Due) >= step {
				w.t.Fatalf("due %s, fired %s", f.Due, f.At)
			}
			if !next.Equal(f.Due) {
				w.t.Fatalf("next run said %s, it fired for %s", next, f.Due)
			}
		}
		next = in.Def.Triggers[0].NextRun(at)
	}
	return got
}

// Tuesdays and Thursdays at 07:00 in Lisbon, across the October change: each of those days once at 07:00 local
// (06:00 UTC before, 07:00 UTC after), no other day.
func TestWeeklyFiresOnItsDaysAcrossFallBack(t *testing.T) {
	lis := mustZone(t, "Europe/Lisbon")
	from := time.Date(2026, 10, 19, 12, 0, 0, 0, lis) // a Monday
	w, _ := kindWorld(t, Trigger{Daily: "07:00", Days: []string{"tue", "thu"}, Zone: "Europe/Lisbon"}, from)
	got := w.run(from, time.Date(2026, 11, 6, 12, 0, 0, 0, lis), time.Minute, lis)
	want := []string{
		"Tue 10-20 07:00 WEST 2026-10-20", "Thu 10-22 07:00 WEST 2026-10-22",
		"Tue 10-27 07:00 WET 2026-10-27", "Thu 10-29 07:00 WET 2026-10-29",
		"Tue 11-03 07:00 WET 2026-11-03", "Thu 11-05 07:00 WET 2026-11-05",
	}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("fires %q\nwant %q", got, want)
	}
}

// Sundays at 02:30 in New York: the Sunday the clocks skip 02:00-03:00 fires once at 03:00 EDT. Weekends at 01:30:
// the Sunday the clocks repeat 01:00-02:00 fires once, at the first 01:30.
func TestWeeklyAcrossSpringForwardAndFallBack(t *testing.T) {
	ny := mustZone(t, "America/New_York")
	from := time.Date(2026, 2, 28, 12, 0, 0, 0, ny)
	w, _ := kindWorld(t, Trigger{Daily: "02:30", Days: []string{"sun"}, Zone: "America/New_York"}, from)
	got := w.run(from, time.Date(2026, 3, 16, 0, 0, 0, 0, ny), time.Minute, ny)
	want := "Sun 03-01 02:30 EST 2026-03-01|Sun 03-08 03:00 EDT 2026-03-08|Sun 03-15 02:30 EDT 2026-03-15"
	if strings.Join(got, "|") != want {
		t.Fatalf("fires %q, want %q", strings.Join(got, "|"), want)
	}
	from = time.Date(2026, 10, 29, 12, 0, 0, 0, ny)
	w, _ = kindWorld(t, Trigger{Daily: "01:30", Days: []string{"sat", "sun"}, Zone: "America/New_York"}, from)
	got = w.run(from, time.Date(2026, 11, 3, 0, 0, 0, 0, ny), time.Minute, ny)
	want = "Sat 10-31 01:30 EDT 2026-10-31|Sun 11-01 01:30 EDT 2026-11-01" // the repeated 01:30: once, the first
	if strings.Join(got, "|") != want {
		t.Fatalf("fires %q, want %q", strings.Join(got, "|"), want)
	}
}

// Weekdays at 07:00: Monday to Friday, not the weekend; the next run said on Friday after it ran is Monday's.
func TestWeekdaysSkipTheWeekend(t *testing.T) {
	lis := mustZone(t, "Europe/Lisbon")
	from := time.Date(2026, 10, 22, 12, 0, 0, 0, lis) // a Thursday
	w, d := kindWorld(t, Trigger{Daily: "07:00", Days: []string{"mon", "tue", "wed", "thu", "fri"}, Zone: "Europe/Lisbon"}, from)
	got := w.run(from, time.Date(2026, 10, 28, 12, 0, 0, 0, lis), time.Minute, lis)
	want := "Fri 10-23 07:00 WEST 2026-10-23|Mon 10-26 07:00 WET 2026-10-26|Tue 10-27 07:00 WET 2026-10-27|Wed 10-28 07:00 WET 2026-10-28"
	if strings.Join(got, "|") != want {
		t.Fatalf("fires %q, want %q", strings.Join(got, "|"), want)
	}
	if n := d.Triggers[0].NextRun(time.Date(2026, 10, 23, 8, 0, 0, 0, lis)); !n.Equal(time.Date(2026, 10, 26, 7, 0, 0, 0, lis)) {
		t.Fatalf("next run after Friday's: %s", n)
	}
}

// The same rules as daily: installed on a Tuesday after 07:00, it first runs Thursday; a Tuesday run more than 3 h late
// is skipped (and never fires later that day or on Wednesday); 2 h 59 late fires.
func TestWeeklyNotBeforeIssuedAndLateSkip(t *testing.T) {
	lis := mustZone(t, "Europe/Lisbon")
	issued := time.Date(2026, 10, 20, 9, 0, 0, 0, lis) // Tuesday 09:00
	w, d := kindWorld(t, Trigger{Daily: "07:00", Days: []string{"tue", "thu"}, Zone: "Europe/Lisbon"}, issued)
	tr := d.Triggers[0]
	if f := w.tick(issued.Add(30 * time.Second)); len(f) != 0 {
		t.Fatalf("fired at install for a time before it: %+v", f)
	}
	if f := w.tick(time.Date(2026, 10, 21, 7, 0, 30, 0, lis)); len(f) != 0 { // Wednesday
		t.Fatalf("fired on a Wednesday: %+v", f)
	}
	if f := w.tick(time.Date(2026, 10, 22, 9, 59, 0, 0, lis)); len(f) != 1 || DayOf(f[0].Slot) != "2026-10-22" { // Thu, 2 h 59 late
		t.Fatalf("Thursday 2 h 59 late: %+v", f)
	}
	if f := w.tick(time.Date(2026, 10, 27, 10, 1, 0, 0, lis)); len(f) != 0 { // Tue, 3 h 1 late
		t.Fatalf("fired 3 h late: %+v", f)
	}
	for _, at := range []time.Time{time.Date(2026, 10, 27, 23, 0, 0, 0, lis), time.Date(2026, 10, 28, 7, 0, 30, 0, lis)} {
		if f := w.tick(at); len(f) != 0 {
			t.Fatalf("skipped Tuesday fired later (%s): %+v", at, f)
		}
	}
	if ran, skipped := w.e.LastRan(&tr); DayOf(ran) != "2026-10-22" || DayOf(skipped) != "2026-10-27" {
		t.Fatalf("ran %s skipped %s", DayOf(ran), DayOf(skipped))
	}
	if w.e.StateOf(w.e.Get(w.agent)) != StateActive || w.e.Active() != 1 {
		t.Fatal("a weekly schedule doesn't end")
	}
}

// Moving a weekly schedule's days in a new version can't make a day fire twice (one count per trigger, as daily).
func TestWeeklyEditCantRefireADay(t *testing.T) {
	lis := mustZone(t, "Europe/Lisbon")
	issued := time.Date(2026, 10, 20, 6, 0, 0, 0, lis)
	w, d := kindWorld(t, Trigger{Daily: "07:00", Days: []string{"tue"}, Zone: "Europe/Lisbon"}, issued)
	if f := w.tick(time.Date(2026, 10, 20, 7, 0, 10, 0, lis)); len(f) != 1 {
		t.Fatalf("Tuesday: %+v", f)
	}
	d.Version, d.Triggers[0].Daily, d.Triggers[0].Days = 2, "08:00", []string{"tue", "wed"}
	w.set(time.Date(2026, 10, 20, 7, 30, 0, 0, lis))
	if _, err := w.install(d, w.sponsorK); err != nil {
		t.Fatal(err)
	}
	if f := w.tick(time.Date(2026, 10, 20, 8, 0, 10, 0, lis)); len(f) != 0 {
		t.Fatalf("Tuesday fired twice after an edit: %+v", f)
	}
	if f := w.tick(time.Date(2026, 10, 21, 8, 0, 10, 0, lis)); len(f) != 1 {
		t.Fatalf("Wednesday: %+v", f)
	}
}

// A one-time schedule fires once at its local time, then has ended: no next run, not active (the keep-on count drops),
// not counted against the live schedules, and still ended after a restart.
func TestOnceFiresThenEnds(t *testing.T) {
	lis := mustZone(t, "Europe/Lisbon")
	issued := time.Date(2026, 10, 21, 9, 0, 0, 0, lis)
	w, d := kindWorld(t, Trigger{At: "2026-10-21T19:10", Zone: "Europe/Lisbon"}, issued)
	tr := d.Triggers[0]
	in := w.e.Get(w.agent)
	if w.e.StateOf(in) != StateActive || w.e.Active() != 1 {
		t.Fatal("not active before its run")
	}
	if n := tr.NextRun(issued); !n.Equal(time.Date(2026, 10, 21, 19, 10, 0, 0, lis)) {
		t.Fatalf("next run %s", n)
	}
	got := w.run(issued, time.Date(2026, 10, 23, 12, 0, 0, 0, lis), 30*time.Second, lis)
	if strings.Join(got, "|") != "Wed 10-21 19:10 WEST 2026-10-21" {
		t.Fatalf("fires %q", got)
	}
	if w.e.StateOf(in) != StateEnded || w.e.Active() != 0 || !tr.NextRun(w.clock()).IsZero() {
		t.Fatalf("after its run: state %s, active %d", w.e.StateOf(in), w.e.Active())
	}
	if live, all := w.e.SpaceCount(w.space); live != 0 || all != 1 {
		t.Fatalf("counts %d %d", live, all)
	}
	if ran, skipped := w.e.LastRan(&tr); DayOf(ran) != "2026-10-21" || skipped != -1 {
		t.Fatalf("ran %d skipped %d", ran, skipped)
	}
	// A restart: still ended, nothing fires.
	e2 := New(Config{Firm: firm, Dir: &w.dir, Store: w.store, IDKey: []byte("id key"), Now: w.clock,
		Trusted: func() (time.Time, bool) { return w.clock().Add(-time.Minute), true }})
	if n, err := e2.Load(); n != 1 || err != nil || e2.StateOf(e2.Get(w.agent)) != StateEnded || e2.Active() != 0 {
		t.Fatalf("after a restart: %d %v %s", n, err, e2.StateOf(e2.Get(w.agent)))
	}
	if f, err := e2.Due(); len(f) != 0 || err != nil {
		t.Fatalf("fired again after a restart: %+v %v", f, err)
	}
	// The same envelope again is still the no-op it was (not refused as past); stopping and removing work as usual.
	env, _ := SignDefinition(d, w.sponsorK)
	if _, err := w.e.Install(env); err != nil {
		t.Fatalf("the same envelope again: %v", err)
	}
	if _, err := w.e.Stop(w.agent, true); err != nil || w.e.Get(w.agent) != nil {
		t.Fatal(err)
	}
}

// A one-time time that has passed is refused at install with a clear error; one before issued_at or not before
// not_after is a bad definition whatever the clock. A new version may move an ended run to a new time (it runs
// again, once); the same time again can't.
func TestOncePastAndBounds(t *testing.T) {
	lis := mustZone(t, "Europe/Lisbon")
	now := time.Date(2026, 10, 21, 19, 11, 0, 0, lis)
	w := newWorld(t)
	w.set(now)
	mk := func(version uint64, at string, issued time.Time) Definition {
		return Definition{Firm: firm, Space: w.space, Agent: w.agent, Version: version, Instructions: "Digest", Seal: testSeal,
			Models: []string{"deepseek-v4-1-flash"}, Tools: []string{"web.fetch"},
			Triggers: []Trigger{{ID: w.sched, Kind: Schedule, At: at, Zone: "Europe/Lisbon"}}, Allow: map[string]string{"web.fetch": "always"},
			Author: w.sponsor, Sponsor: w.sponsor, IssuedAt: issued, NotAfter: issued.Add(DefaultSponsorship)}
	}
	issued := now.Add(-2 * time.Minute)
	for _, at := range []string{"2026-10-21T19:10", "2026-10-21T19:11", "2026-10-20T19:10"} {
		_, err := w.install(mk(1, at, issued), w.sponsorK)
		if err == nil || !strings.Contains(err.Error(), "already passed") || (at != "2026-10-20T19:10") != errors.Is(err, ErrPast) {
			t.Fatalf("%s at %s: %v", at, now, err)
		}
	}
	for _, c := range []struct {
		at     string
		issued time.Time
	}{
		{"2026-10-21T19:12", now.Add(3 * time.Minute)},  // before issued_at (issued 5 min ahead is allowed)
		{"2027-01-19T19:13", now.Add(-2 * time.Minute)}, // past not_after (90 days)
	} {
		if _, err := w.install(mk(1, c.at, c.issued), w.sponsorK); err == nil || errors.Is(err, ErrPast) {
			t.Fatalf("%s: %v", c.at, err)
		}
	}
	if w.e.Get(w.agent) != nil {
		t.Fatal("installed after refusals")
	}
	if _, err := w.install(mk(1, "2026-10-21T19:12", issued), w.sponsorK); err != nil {
		t.Fatal(err)
	}
	if f := w.tick(time.Date(2026, 10, 21, 19, 12, 5, 0, lis)); len(f) != 1 {
		t.Fatalf("a minute later: %+v", f)
	}
	if _, err := w.install(mk(2, "2026-10-21T19:12", issued), w.sponsorK); !errors.Is(err, ErrPast) {
		t.Fatalf("version 2 at the same, passed time: %v", err)
	}
	if _, err := w.install(mk(2, "2026-10-22T08:00", issued), w.sponsorK); err != nil {
		t.Fatalf("moved to tomorrow: %v", err)
	}
	if w.e.StateOf(w.e.Get(w.agent)) != StateActive || w.e.Active() != 1 {
		t.Fatal("the moved run isn't active")
	}
	if f := w.tick(time.Date(2026, 10, 22, 8, 0, 5, 0, lis)); len(f) != 1 || DayOf(f[0].Slot) != "2026-10-22" {
		t.Fatalf("the moved run: %+v", f)
	}
	if w.e.StateOf(w.e.Get(w.agent)) != StateEnded {
		t.Fatal("not ended after the moved run")
	}
}

// A one-time run more than 3 h late is skipped, and the schedule ends without running; 2 h 59 late it runs.
func TestOnceLateSkip(t *testing.T) {
	lis := mustZone(t, "Europe/Lisbon")
	issued := time.Date(2026, 10, 21, 9, 0, 0, 0, lis)
	w, d := kindWorld(t, Trigger{At: "2026-10-21T19:10", Zone: "Europe/Lisbon"}, issued)
	tr := d.Triggers[0]
	if f := w.tick(time.Date(2026, 10, 21, 22, 11, 0, 0, lis)); len(f) != 0 {
		t.Fatalf("fired 3 h 1 late: %+v", f)
	}
	if ran, skipped := w.e.LastRan(&tr); ran != -1 || DayOf(skipped) != "2026-10-21" {
		t.Fatalf("ran %d skipped %s", ran, DayOf(skipped))
	}
	if w.e.StateOf(w.e.Get(w.agent)) != StateEnded || w.e.Active() != 0 {
		t.Fatal("not ended after its skip")
	}
	if f := w.tick(time.Date(2026, 10, 22, 19, 10, 0, 0, lis)); len(f) != 0 {
		t.Fatalf("a skipped one-time run fired later: %+v", f)
	}
	w2, _ := kindWorld(t, Trigger{At: "2026-10-21T19:10", Zone: "Europe/Lisbon"}, issued)
	if f := w2.tick(time.Date(2026, 10, 21, 22, 9, 0, 0, lis)); len(f) != 1 {
		t.Fatalf("2 h 59 late: %+v", f)
	}
	// The clock can't be set back to fire it again.
	w2.set(time.Date(2026, 10, 21, 19, 10, 30, 0, lis))
	if f, err := w2.e.Due(); len(f) != 0 || !errors.Is(err, ErrClock) {
		t.Fatalf("rewound clock: %+v %v", f, err)
	}
}

// A one-time time in a DST gap fires at the change; one in the repeated hour fires once, at its first occurrence.
func TestOnceAcrossDST(t *testing.T) {
	lis := mustZone(t, "Europe/Lisbon")
	for _, c := range []struct{ at, want string }{
		{"2026-03-29T01:30", "2026-03-29T01:00:00Z"}, // 01:30 doesn't exist: at the change (02:00 WEST)
		{"2026-10-25T01:30", "2026-10-25T00:30:00Z"}, // 01:30 twice: the first (WEST)
	} {
		day, _ := time.Parse(time.DateOnly, c.at[:10])
		issued := day.In(lis).Add(-12 * time.Hour)
		w, _ := kindWorld(t, Trigger{At: c.at, Zone: "Europe/Lisbon"}, issued)
		var got []string
		for at := issued; at.Before(issued.Add(48 * time.Hour)); at = at.Add(30 * time.Second) {
			for _, f := range w.tick(at) {
				got = append(got, f.Due.UTC().Format(time.RFC3339)+" "+DayOf(f.Slot))
			}
		}
		if len(got) != 1 || got[0] != c.want+" "+c.at[:10] {
			t.Errorf("%s: fires %q, want %s", c.at, got, c.want)
		}
	}
}

// The keep-on count is per definition and only active ones: a daily one and an ended one-time one count 1.
func TestActiveLeavesOutEnded(t *testing.T) {
	lis := mustZone(t, "Europe/Lisbon")
	issued := time.Date(2026, 10, 21, 9, 0, 0, 0, lis)
	w, d := kindWorld(t, Trigger{At: "2026-10-21T10:00", Zone: "Europe/Lisbon"}, issued)
	d2 := d
	d2.Agent, d2.Triggers = id(t, "a"), []Trigger{{ID: id(t, "tr"), Kind: Schedule, Daily: "07:00", Days: []string{"tue", "thu"}, Zone: "Europe/Lisbon"}}
	if _, err := w.install(d2, w.sponsorK); err != nil {
		t.Fatal(err)
	}
	if w.e.Active() != 2 {
		t.Fatalf("active %d", w.e.Active())
	}
	w.tick(time.Date(2026, 10, 21, 10, 0, 30, 0, lis))
	if live, all := w.e.SpaceCount(w.space); w.e.Active() != 1 || live != 1 || all != 2 {
		t.Fatalf("active %d, counts %d %d", w.e.Active(), live, all)
	}
	states := []string{}
	for _, in := range w.e.Installed() {
		states = append(states, w.e.StateOf(in))
	}
	slices.Sort(states)
	if strings.Join(states, ",") != "active,ended" {
		t.Fatalf("states %v", states)
	}
}
