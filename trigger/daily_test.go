package trigger

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func mustZone(t *testing.T, name string) *time.Location {
	loc, err := time.LoadLocation(name)
	if err != nil {
		t.Fatal(err)
	}
	return loc
}

// The daily rule follows DST: the wall-clock time stays, the UTC instant moves. A time the spring-forward change
// skips fires at the change; a time the fall-back change repeats fires once, at its first occurrence.
func TestDailyInstantsAcrossDST(t *testing.T) {
	cases := []struct {
		zone, at string
		day      string
		want     string // UTC
	}{
		{"Europe/Lisbon", "07:00", "2026-10-24", "2026-10-24T06:00:00Z"},    // WEST (+1)
		{"Europe/Lisbon", "07:00", "2026-10-25", "2026-10-25T07:00:00Z"},    // the change was at 02:00 local: WET (+0)
		{"Europe/Lisbon", "07:00", "2026-03-29", "2026-03-29T06:00:00Z"},    // spring forward at 01:00 local
		{"Europe/Lisbon", "01:30", "2026-03-29", "2026-03-29T01:00:00Z"},    // 01:30 doesn't exist: at the change (02:00 WEST)
		{"Europe/Lisbon", "01:30", "2026-10-25", "2026-10-25T00:30:00Z"},    // 01:30 twice: the first (WEST)
		{"America/New_York", "02:30", "2026-03-08", "2026-03-08T07:00:00Z"}, // skipped: 03:00 EDT
		{"America/New_York", "01:30", "2026-11-01", "2026-11-01T05:30:00Z"}, // repeated: the first, EDT
		{"America/New_York", "07:00", "2026-11-01", "2026-11-01T12:00:00Z"}, // EST
		{"America/New_York", "07:00", "2026-10-31", "2026-10-31T11:00:00Z"}, // EDT
		{"Asia/Kolkata", "07:00", "2026-10-25", "2026-10-25T01:30:00Z"},     // no DST, half-hour offset
		{"UTC", "00:00", "2026-12-31", "2026-12-31T00:00:00Z"},
		{"Australia/Lord_Howe", "02:15", "2026-10-04", "2026-10-03T15:30:00Z"}, // a 30-minute change: 02:00 -> 02:30
	}
	for _, c := range cases {
		tr := Trigger{ID: "tr_x", Kind: Schedule, Daily: c.at, Zone: c.zone}
		d, _ := time.Parse(time.DateOnly, c.day)
		slot := dayNumber(d.Date())
		got := tr.SlotAt(slot)
		if got.UTC().Format(time.RFC3339) != c.want {
			t.Errorf("%s %s on %s: %s, want %s", c.zone, c.at, c.day, got.UTC().Format(time.RFC3339), c.want)
			continue
		}
		// The slot at that instant is that day; a second before, the day before.
		if s, inst := tr.DailySlot(got); s != slot || !inst.Equal(got) {
			t.Errorf("%s %s: slot at its instant %d (%s), want %d", c.zone, c.at, s, DayOf(s), slot)
		}
		if s, _ := tr.DailySlot(got.Add(-time.Second)); s != slot-1 {
			t.Errorf("%s %s: slot just before %s, want the day before", c.zone, c.at, DayOf(s))
		}
		if n := tr.NextRun(got.Add(-time.Second)); !n.Equal(got) {
			t.Errorf("%s %s: next run %s, want %s", c.zone, c.at, n, got)
		}
		if DayOf(slot) != c.day {
			t.Errorf("DayOf %s", DayOf(slot))
		}
	}
}

func TestDailyTriggerChecks(t *testing.T) {
	for _, tr := range []Trigger{
		{Kind: Schedule, Daily: "7:00", Zone: "UTC"},
		{Kind: Schedule, Daily: "24:00", Zone: "UTC"},
		{Kind: Schedule, Daily: "07:60", Zone: "UTC"},
		{Kind: Schedule, Daily: "07:00"},
		{Kind: Schedule, Daily: "07:00", Zone: "Local"},
		{Kind: Schedule, Daily: "07:00", Zone: "Mars/Olympus"},
		{Kind: Schedule, Daily: "07:00", Zone: "../../etc/passwd"},
		{Kind: Schedule, Zone: "UTC"},
		{Kind: Schedule, Daily: "07:00", Zone: "UTC", Every: "24h", Anchor: time.Now()},
		{Kind: Event, Daily: "07:00", Zone: "UTC", Sender: "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="},
	} {
		tr.ID = "tr_aaaaaaaaaaaaaaaaaaaaaaaaaa"
		if tr.check() == nil {
			t.Errorf("accepted %+v", tr)
		}
	}
	ok := Trigger{ID: "tr_aaaaaaaaaaaaaaaaaaaaaaaaaa", Kind: Schedule, Daily: "23:59", Zone: "Europe/Lisbon"}
	if err := ok.check(); err != nil {
		t.Fatal(err)
	}
}

// dailyWorld is a world whose definition is a personal one: one daily trigger, author = sponsor, web reads only.
func dailyWorld(t *testing.T, at, zone string, issued time.Time) (*world, Definition) {
	w := newWorld(t)
	w.set(issued)
	d := Definition{Firm: firm, Space: w.space, Agent: w.agent, Version: 1, Instructions: "Digest of https://news.ycombinator.com/",
		Seal: testSeal, Models: []string{"deepseek-v4-1-flash"}, Tools: []string{"web.fetch"}, MaxSteps: 20,
		Triggers: []Trigger{{ID: w.sched, Kind: Schedule, Daily: at, Zone: zone}}, Allow: map[string]string{"web.fetch": "always"},
		Author: w.sponsor, Sponsor: w.sponsor, IssuedAt: issued, NotAfter: issued.Add(DefaultSponsorship)}
	if _, err := w.install(d, w.sponsorK); err != nil {
		t.Fatal(err)
	}
	return w, d
}

// tick runs the engine at t: the fires, each recorded as started.
func (w *world) tick(t time.Time) []Fire {
	w.set(t)
	fires, err := w.e.Due()
	if err != nil {
		w.t.Fatalf("due at %s: %v", t, err)
	}
	for _, f := range fires {
		w.e.Fired(f)
	}
	return fires
}

// Every 30 s for days across the October change in Lisbon: one run a day at 07:00 local, whatever the offset; the
// repeated hour of the change fires nothing twice.
func TestDailyFiresOncePerDayAcrossFallBack(t *testing.T) {
	lis := mustZone(t, "Europe/Lisbon")
	w, _ := dailyWorld(t, "07:00", "Europe/Lisbon", time.Date(2026, 10, 23, 12, 0, 0, 0, lis))
	var got []string
	tasks := map[string]bool{}
	for at := time.Date(2026, 10, 23, 12, 0, 0, 0, lis); at.Before(time.Date(2026, 10, 27, 12, 0, 0, 0, lis)); at = at.Add(30 * time.Second) {
		for _, f := range w.tick(at) {
			got = append(got, f.At.In(lis).Format("2006-01-02 15:04")+" "+DayOf(f.Slot))
			if tasks[f.Task] {
				t.Fatalf("task %s twice", f.Task)
			}
			tasks[f.Task] = true
			if !f.Due.Equal(f.Trigger.SlotAt(f.Slot)) {
				t.Fatalf("due %s", f.Due)
			}
		}
	}
	want := []string{"2026-10-24 07:00 2026-10-24", "2026-10-25 07:00 2026-10-25", "2026-10-26 07:00 2026-10-26", "2026-10-27 07:00 2026-10-27"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("fires %q, want %q", got, want)
	}
}

// Spring forward in New York: 02:30 doesn't exist on March 8; it fires once, at 03:00 EDT, and at 02:30 on the days
// around it.
func TestDailyFiresOnceAcrossSpringForward(t *testing.T) {
	ny := mustZone(t, "America/New_York")
	w, _ := dailyWorld(t, "02:30", "America/New_York", time.Date(2026, 3, 6, 12, 0, 0, 0, ny))
	var got []string
	for at := time.Date(2026, 3, 6, 12, 0, 0, 0, ny); at.Before(time.Date(2026, 3, 10, 0, 0, 0, 0, ny)); at = at.Add(30 * time.Second) {
		for _, f := range w.tick(at) {
			got = append(got, f.At.In(ny).Format("01-02 15:04 MST"))
		}
	}
	want := "03-07 02:30 EST|03-08 03:00 EDT|03-09 02:30 EDT"
	if strings.Join(got, "|") != want {
		t.Fatalf("fires %q, want %q", strings.Join(got, "|"), want)
	}
}

// A run that can't start within 3 h of its time (the VM was off, or its clock couldn't be checked) is skipped for
// that day, and never fires later that day; the next day fires as usual. 2 h 59 late still fires.
func TestDailyLateSkip(t *testing.T) {
	lis := mustZone(t, "Europe/Lisbon")
	w, d := dailyWorld(t, "07:00", "Europe/Lisbon", time.Date(2026, 10, 20, 12, 0, 0, 0, lis))
	tr := d.Triggers[0]
	// Day 1: the VM comes up at 10:01 (3 h 1 min late).
	if f := w.tick(time.Date(2026, 10, 21, 10, 1, 0, 0, lis)); len(f) != 0 {
		t.Fatalf("fired 3 h late: %+v", f)
	}
	if f := w.tick(time.Date(2026, 10, 21, 23, 0, 0, 0, lis)); len(f) != 0 {
		t.Fatalf("fired later that day: %+v", f)
	}
	if ran, skipped := w.e.LastRan(&tr); ran != -1 || DayOf(skipped) != "2026-10-21" {
		t.Fatalf("ran %d skipped %s", ran, DayOf(skipped))
	}
	// Day 2: up at 09:59 (2 h 59 late): fires.
	if f := w.tick(time.Date(2026, 10, 22, 9, 59, 0, 0, lis)); len(f) != 1 || DayOf(f[0].Slot) != "2026-10-22" {
		t.Fatalf("2 h 59 late: %+v", f)
	}
	// Day 3: the operator's time is stale from 06:55 to 10:30: nothing fires, then it's too late.
	w.set(time.Date(2026, 10, 23, 7, 0, 0, 0, lis))
	w.mu.Lock()
	w.fresh = false
	w.mu.Unlock()
	if f, err := w.e.Due(); len(f) != 0 || !errors.Is(err, ErrClock) {
		t.Fatalf("fired without operator time: %+v %v", f, err)
	}
	w.mu.Lock()
	w.fresh = true
	w.mu.Unlock()
	if f := w.tick(time.Date(2026, 10, 23, 10, 30, 0, 0, lis)); len(f) != 0 {
		t.Fatalf("fired 3.5 h late: %+v", f)
	}
	if ran, skipped := w.e.LastRan(&tr); DayOf(skipped) != "2026-10-23" || DayOf(ran) != "2026-10-22" {
		t.Fatalf("ran %s skipped %s", DayOf(ran), DayOf(skipped))
	}
	// The clock can't be set back to fire the skipped day.
	w.set(time.Date(2026, 10, 23, 7, 1, 0, 0, lis))
	if f, err := w.e.Due(); len(f) != 0 || !errors.Is(err, ErrClock) {
		t.Fatalf("rewound clock: %+v %v", f, err)
	}
}

// A schedule installed after today's time first runs tomorrow (no instant run at install).
func TestDailyNotBeforeIssued(t *testing.T) {
	lis := mustZone(t, "Europe/Lisbon")
	w, _ := dailyWorld(t, "07:00", "Europe/Lisbon", time.Date(2026, 10, 21, 9, 0, 0, 0, lis))
	if f := w.tick(time.Date(2026, 10, 21, 9, 0, 30, 0, lis)); len(f) != 0 {
		t.Fatalf("fired at install: %+v", f)
	}
	if f := w.tick(time.Date(2026, 10, 22, 7, 0, 10, 0, lis)); len(f) != 1 {
		t.Fatalf("next morning: %+v", f)
	}
}

// A schedule lasts until its not_after (the chat's default: 90 days). The last day before it fires; after it, nothing
// fires, it counts as expired, and the keep-on count drops. A renewal (the next version, one signature, a later
// not_after) brings it back, without firing a day twice.
func TestDailyExpiryAndRenewal(t *testing.T) {
	lis := mustZone(t, "Europe/Lisbon")
	issued := time.Date(2026, 10, 21, 9, 0, 0, 0, lis)
	w, d := dailyWorld(t, "07:00", "Europe/Lisbon", issued)
	if w.e.Active() != 1 {
		t.Fatal("not active")
	}
	end := issued.Add(DefaultSponsorship) // 2027-01-19 09:00 (WET)
	if f := w.tick(time.Date(2027, 1, 19, 7, 0, 30, 0, lis)); len(f) != 1 {
		t.Fatalf("last day: %+v", f)
	}
	w.set(end.Add(time.Minute))
	in := w.e.Get(w.agent)
	if w.e.StateOf(in) != StateExpired || w.e.Active() != 0 {
		t.Fatalf("state %s active %d", w.e.StateOf(in), w.e.Active())
	}
	if f := w.tick(time.Date(2027, 1, 20, 7, 0, 30, 0, lis)); len(f) != 0 {
		t.Fatalf("fired after not_after: %+v", f)
	}
	// Over a year is refused.
	long := d
	long.Version, long.IssuedAt, long.NotAfter = 2, w.clock(), w.clock().Add(367*24*time.Hour)
	if _, err := w.install(long, w.sponsorK); err == nil {
		t.Fatal("a sponsorship over a year installed")
	}
	renew := d
	renew.Version, renew.IssuedAt, renew.NotAfter = 2, time.Date(2027, 1, 20, 6, 0, 0, 0, lis), time.Date(2027, 1, 20, 6, 0, 0, 0, lis).Add(DefaultSponsorship)
	w.set(time.Date(2027, 1, 20, 6, 0, 0, 0, lis))
	if _, err := w.install(renew, w.sponsorK); err != nil {
		t.Fatal(err)
	}
	if w.e.Active() != 1 {
		t.Fatal("renewed not active")
	}
	if f := w.tick(time.Date(2027, 1, 20, 7, 0, 30, 0, lis)); len(f) != 1 {
		t.Fatalf("after renewal: %+v", f)
	}
	// A version that moves the time later the same day doesn't fire that day again.
	later := renew
	later.Version, later.Triggers = 3, []Trigger{{ID: w.sched, Kind: Schedule, Daily: "21:00", Zone: "Europe/Lisbon"}}
	if _, err := w.install(later, w.sponsorK); err != nil {
		t.Fatal(err)
	}
	if f := w.tick(time.Date(2027, 1, 20, 21, 0, 30, 0, lis)); len(f) != 0 {
		t.Fatalf("a day fired twice: %+v", f)
	}
}

// Stop keeps it listed and fires nothing; the same version can't come back, the next one can. Remove takes it off
// the list and keeps the floor, also across a restart.
func TestStopAndRemove(t *testing.T) {
	lis := mustZone(t, "Europe/Lisbon")
	issued := time.Date(2026, 10, 21, 9, 0, 0, 0, lis)
	w, d := dailyWorld(t, "07:00", "Europe/Lisbon", issued)
	env, _ := SignDefinition(d, w.sponsorK)
	in, err := w.e.Stop(w.agent, false)
	if err != nil || in.State != StateStopped || w.e.Active() != 0 || w.e.SpaceCount(w.space) != 1 {
		t.Fatalf("stop: %+v %v", in, err)
	}
	if f := w.tick(time.Date(2026, 10, 22, 7, 0, 30, 0, lis)); len(f) != 0 {
		t.Fatalf("stopped fired: %+v", f)
	}
	if _, err := w.e.Install(env); !errors.Is(err, ErrStale) {
		t.Fatalf("stopped version reinstalled: %v", err)
	}
	if _, err := w.e.Stop(w.agent, false); err != nil {
		t.Fatalf("stop twice: %v", err)
	}
	e2 := New(Config{Firm: firm, Dir: &w.dir, Store: w.store, IDKey: []byte("id key"), Now: w.clock})
	if n, _ := e2.Load(); n != 1 || e2.Get(w.agent).State != StateStopped {
		t.Fatal("stopped state lost at restart")
	}
	if _, err := w.e.Stop(w.agent, true); err != nil || w.e.Get(w.agent) != nil || w.e.SpaceCount(w.space) != 0 {
		t.Fatalf("remove: %v", err)
	}
	if _, err := w.e.Stop(w.agent, true); !errors.Is(err, ErrNoAgent) {
		t.Fatalf("remove twice: %v", err)
	}
	e3 := New(Config{Firm: firm, Dir: &w.dir, Store: w.store, IDKey: []byte("id key"), Now: w.clock})
	if n, _ := e3.Load(); n != 0 {
		t.Fatal("removed loaded at restart")
	}
	if _, err := e3.Install(env); !errors.Is(err, ErrStale) {
		t.Fatalf("removed version reinstalled after a restart: %v", err)
	}
	d.Version = 2
	if _, err := w.install(d, w.sponsorK); err != nil {
		t.Fatalf("next version after removal: %v", err)
	}
}

func TestPersonalRules(t *testing.T) {
	lis := mustZone(t, "Europe/Lisbon")
	w, d := dailyWorld(t, "07:00", "Europe/Lisbon", time.Date(2026, 10, 21, 9, 0, 0, 0, lis))
	if err := Personal(&d, w.space, testSeal, w.sponsor); err != nil {
		t.Fatal(err)
	}
	other := "x25519:" + strings.Repeat("A", 42) + "E="
	for name, f := range map[string]func(*Definition) (string, string, string){
		"another space":  func(x *Definition) (string, string, string) { return id(t, "s"), testSeal, w.sponsor },
		"another seal":   func(x *Definition) (string, string, string) { return w.space, other, w.sponsor },
		"another signer": func(x *Definition) (string, string, string) { return w.space, testSeal, w.author },
		"author not sponsor": func(x *Definition) (string, string, string) {
			x.Author = w.author
			return w.space, testSeal, w.sponsor
		},
		"every schedule": func(x *Definition) (string, string, string) {
			x.Triggers = []Trigger{{ID: w.sched, Kind: Schedule, Every: "1h", Anchor: x.IssuedAt}}
			return w.space, testSeal, w.sponsor
		},
		"event": func(x *Definition) (string, string, string) {
			x.Triggers = append(x.Triggers, Trigger{ID: w.event, Kind: Event, Sender: "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="})
			return w.space, testSeal, w.sponsor
		},
		"a sending tool": func(x *Definition) (string, string, string) {
			x.Tools = []string{"web.fetch", "sink.post"}
			return w.space, testSeal, w.sponsor
		},
	} {
		x := d
		x.Triggers = append([]Trigger(nil), d.Triggers...)
		sp, seal, who := f(&x)
		if Personal(&x, sp, seal, who) == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// No seal: refused for any definition (no runs without records).
	x := d
	x.Seal, x.Version = "", 2
	if _, err := w.install(x, w.sponsorK); err == nil {
		t.Fatal("a definition without a seal key installed")
	}
}
