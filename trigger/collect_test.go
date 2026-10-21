package trigger

import (
	"bytes"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"testing"
	"time"

	"github.com/tacyhq/tacy/proto"
	"github.com/tacyhq/tacy/safety"
	"github.com/tacyhq/tacy/storedfiles"
)

// collectWorld is dailyWorld's personal daily schedule (07:00 UTC) on an engine that counts uncollected results.
func collectWorld(t *testing.T, edit func(*Definition)) (*world, *MemResults, Definition) {
	w := newWorld(t)
	rs := &MemResults{}
	issued := time.Date(2026, 10, 1, 6, 0, 0, 0, time.UTC)
	w.set(issued)
	w.e = New(Config{Firm: firm, Dir: &w.dir, Store: w.store, IDKey: []byte("id key"), Now: w.clock, Collect: rs,
		Trusted: func() (time.Time, bool) { w.mu.Lock(); defer w.mu.Unlock(); return w.trusted, w.fresh }})
	d := Definition{Firm: firm, Space: w.space, Agent: w.agent, Version: 1, Instructions: "Digest of https://news.ycombinator.com/",
		Seal: testSeal, Models: []string{"deepseek-v4-1-flash"}, Tools: []string{"web.fetch"}, MaxSteps: 20,
		Triggers: []Trigger{{ID: w.sched, Kind: Schedule, Daily: "07:00", Zone: "UTC"}}, Allow: map[string]string{"web.fetch": "always"},
		Author: w.sponsor, Sponsor: w.sponsor, IssuedAt: issued, NotAfter: issued.Add(DefaultSponsorship)}
	if edit != nil {
		edit(&d)
	}
	if _, err := w.install(d, w.sponsorK); err != nil {
		t.Fatal(err)
	}
	return w, rs, d
}

// runDay ticks day n (days after the 1st) at 07:00:30 and, when it fires, stores the run's result. It returns the
// fired task ("" when nothing fired).
func runDay(w *world, rs *MemResults, n int, quiet bool) string {
	fires := w.tick(time.Date(2026, 10, 1+n, 7, 0, 30, 0, time.UTC))
	if len(fires) == 0 {
		return ""
	}
	f := fires[0]
	end := w.now.Add(time.Minute)
	if _, err := rs.PutResult(Result{Task: f.Task, Space: f.Def.Space, Seal: f.Def.Seal, Agent: f.Def.Agent, Version: f.Def.Version,
		Trigger: f.Trigger.ID, Day: DayOf(f.Slot), EndedAt: end, State: "succeeded", Quiet: quiet}); err != nil {
		w.t.Fatal(err)
	}
	return f.Task
}

// Seven runs whose results nobody collects: the eighth doesn't run and the schedule stops itself, saying why. Results
// pruned past their keep weren't collected either. A Resume (the next version) runs again, its count from 0.
func TestUncollectedResultsStopTheSchedule(t *testing.T) {
	w, rs, d := collectWorld(t, nil)
	for n := 1; n <= MaxUncollected; n++ {
		if runDay(w, rs, n, n == 3) == "" { // a quiet run counts like any
			t.Fatalf("day %d didn't run", n)
		}
		rs.PruneResults(w.now.Add(-24 * time.Hour)) // the hourly prune: drops nothing it counted back
	}
	if got, _ := rs.Uncollected(w.agent); got != MaxUncollected {
		t.Fatalf("uncollected %d", got)
	}
	if w.e.Active() != 1 {
		t.Fatal("not active before its next run")
	}
	if task := runDay(w, rs, MaxUncollected+1, false); task != "" {
		t.Fatal("the 8th run fired with 7 results uncollected")
	}
	in := w.e.Get(w.agent)
	if in.State != StateStopped || w.e.StateOf(in) != StateStopped || w.e.StopReason(in) != StopUncollected || w.e.Active() != 0 {
		t.Fatalf("not stopped for it: %s %q active %d", in.State, w.e.StopReason(in), w.e.Active())
	}
	// Stopped across a restart, with its reason.
	e2 := New(Config{Firm: firm, Dir: &w.dir, Store: w.store, IDKey: []byte("id key"), Now: w.clock, Collect: rs})
	if n, _ := e2.Load(); n != 1 || e2.StopReason(e2.Get(w.agent)) != StopUncollected {
		t.Fatal("stop reason lost at restart")
	}
	if runDay(w, rs, MaxUncollected+2, false) != "" {
		t.Fatal("stopped schedule ran")
	}
	// Resume: version 2. Its count starts again and it runs; the reason is gone.
	d.Version, d.IssuedAt = 2, w.now
	if _, err := w.install(d, w.sponsorK); err != nil {
		t.Fatal(err)
	}
	in = w.e.Get(w.agent)
	if in.State != StateActive || w.e.StopReason(in) != "" {
		t.Fatalf("resumed: %s %q", in.State, w.e.StopReason(in))
	}
	if got, _ := rs.Uncollected(w.agent); got != 0 {
		t.Fatalf("count after resume %d", got)
	}
	if runDay(w, rs, MaxUncollected+3, false) == "" {
		t.Fatal("resumed schedule didn't run")
	}
	// Stopping it by hand at version 2 isn't "uncollected".
	w.e.Stop(w.agent, false)
	if r := w.e.StopReason(w.e.Get(w.agent)); r != "" {
		t.Fatalf("a person's stop has reason %q", r)
	}
}

// The everyday case: a daily schedule whose result the chat collects and deletes after each run never stops itself,
// over 60 days, also when collecting waits up to 6 runs (a few days away from Tacy).
func TestCollectedDailyNeverStops(t *testing.T) {
	w, rs, d := collectWorld(t, nil)
	var waiting []string
	for n := 1; n <= 60; n++ {
		task := runDay(w, rs, n, n%5 == 0)
		if task == "" {
			t.Fatalf("day %d didn't run (uncollected %d)", n, func() int { k, _ := rs.Uncollected(w.agent); return k }())
		}
		waiting = append(waiting, task)
		// Days 20-38: collected every 6th day only (6 runs waiting at most). Otherwise right after each run.
		if n < 20 || n > 38 || n%6 == 0 {
			if k, _ := rs.DeleteResults(d.Space, d.Seal, waiting); k != len(waiting) {
				t.Fatalf("day %d: deleted %d of %d", n, k, len(waiting))
			}
			waiting = nil
		}
	}
	if in := w.e.Get(w.agent); in.State != StateActive || w.e.StopReason(in) != "" {
		t.Fatalf("stopped: %s", in.State)
	}
}

// A count the store can't read fires nothing (fail closed); the next tick that can read it runs.
func TestUncollectedUnreadableFiresNothing(t *testing.T) {
	w, _, _ := collectWorld(t, nil)
	bad := &failingCollect{MemResults: &MemResults{}, fail: true}
	w.e.cfg.Collect = bad
	w.set(time.Date(2026, 10, 2, 7, 0, 30, 0, time.UTC))
	fires, err := w.e.Due()
	if err == nil || len(fires) != 0 {
		t.Fatalf("fired with the count unreadable: %v %v", fires, err)
	}
	if w.e.Get(w.agent).State != StateActive {
		t.Fatal("stopped on an unreadable count")
	}
	bad.fail = false
	if fires := w.tick(time.Date(2026, 10, 2, 7, 1, 0, 0, time.UTC)); len(fires) != 1 {
		t.Fatalf("not fired once readable: %d", len(fires))
	}
}

type failingCollect struct {
	*MemResults
	fail bool
}

func (f *failingCollect) Uncollected(agent string) (int, error) {
	if f.fail {
		return 0, errors.New("disk")
	}
	return f.MemResults.Uncollected(agent)
}

func TestMemCollectStore(t *testing.T) { RunCollectStoreTests(t, &MemResults{}) }

// testStoredFile is a valid stored file for a definition (no URL), its key all 7s.
func testStoredFile(t *testing.T) proto.StoredFile {
	padded, err := storedfiles.PaddedFor(1000)
	if err != nil {
		t.Fatal(err)
	}
	return proto.StoredFile{Object: "ob_aaaaaaaaaaaaaaaaaaaaaaaaaa", File: "fl_aaaaaaaaaaaaaaaaaaaaaaaaaa", Owner: "ow_aaaaaaaaaaaaaaaaaaaaaaaaaa",
		Epoch: 1, Padded: padded, Size: 1000, Name: "notes.md", Type: "text/markdown", Key: bytes.Repeat([]byte{7}, 32)}
}

const testGrant = "g1.eyJvIjpbIm9iX2FhYWEiXX0.c2lnbmF0dXJlc2lnbmF0dXJlc2ln"

// A schedule with stored files loses their keys and read grant when it expires, in the store and in memory, before
// any removal; it stays listed as expired; the same version can't come back, the next one (fresh keys) installs.
// One without files at not_after is left as it was (expired by its time, as before).
func TestExpiredScheduleDropsItsFileKeys(t *testing.T) {
	w, _, d := collectWorld(t, func(d *Definition) {
		d.Files, d.FilesGrant = []proto.StoredFile{testStoredFile(t)}, testGrant
		d.NotAfter = d.IssuedAt.Add(48 * time.Hour)
	})
	plain := d
	plain.Agent, plain.Files, plain.FilesGrant = id(t, "a"), nil, ""
	plain.Triggers = []Trigger{{ID: id(t, "tr"), Kind: Schedule, Daily: "08:00", Zone: "UTC"}}
	if _, err := w.install(plain, w.sponsorK); err != nil {
		t.Fatal(err)
	}
	key := bytes.Repeat([]byte{7}, 32)
	stored := func(agent string) []byte {
		defs, _ := w.store.Definitions()
		for _, s := range defs {
			var env safety.Envelope
			json.Unmarshal(s.Env, &env)
			var x Definition
			json.Unmarshal(env.Payload, &x)
			if x.Agent == agent {
				return append(append(s.Env, 0), env.Payload...) // the envelope as stored and its payload decoded
			}
		}
		return nil
	}
	if !bytes.Contains(stored(w.agent), []byte(base64.StdEncoding.EncodeToString(key))) {
		t.Fatal("the key isn't in the stored definition before (test broken)")
	}
	plainBefore := stored(plain.Agent)
	// Before its end: nothing changes.
	w.set(d.NotAfter.Add(-time.Minute))
	if err := w.e.ExpireFiles(); err != nil || w.e.Get(w.agent).State != StateActive {
		t.Fatal("expired early")
	}
	w.set(d.NotAfter)
	if err := w.e.ExpireFiles(); err != nil {
		t.Fatal(err)
	}
	in := w.e.Get(w.agent)
	if in.State != StateExpired || w.e.StateOf(in) != StateExpired || in.Def.FilesGrant != "" || len(in.Def.Files) != 1 || in.Def.Files[0].Key != nil ||
		in.Def.Files[0].Object != d.Files[0].Object {
		t.Fatalf("installed copy: %+v", in.Def.Files)
	}
	env := stored(w.agent)
	if bytes.Contains(env, []byte(base64.StdEncoding.EncodeToString(key))) || bytes.Contains(env, key) || bytes.Contains(env, []byte(testGrant)) ||
		bytes.Contains(env, []byte("files_grant")) {
		t.Fatalf("the key or grant is still stored: %s", env)
	}
	if !bytes.Equal(stored(plain.Agent), plainBefore) || w.e.StateOf(w.e.Get(plain.Agent)) != StateExpired || w.e.Get(plain.Agent).State != StateActive {
		t.Fatal("a schedule without files changed")
	}
	if err := w.e.ExpireFiles(); err != nil { // again: nothing to do
		t.Fatal(err)
	}
	// A restart lists it expired (not verified: its signature no longer covers it); it never fires.
	e2 := New(Config{Firm: firm, Dir: &w.dir, Store: w.store, IDKey: []byte("id key"), Now: w.clock, Collect: &MemResults{},
		Trusted: func() (time.Time, bool) { return w.now.Add(-time.Minute), true }})
	if n, err := e2.Load(); err != nil || n != 2 || e2.Get(w.agent).State != StateExpired || e2.Get(w.agent).Def.Files[0].Key != nil {
		t.Fatalf("load: %d %v", n, err)
	}
	if fires, _ := e2.Due(); len(fires) != 0 {
		t.Fatal("expired fired")
	}
	if _, err := e2.Stop(w.agent, false); err != nil || e2.Get(w.agent).State != StateExpired {
		t.Fatal("stopping an expired one changed it")
	}
	// The same version again: refused. The next version, with fresh keys: active.
	same := d
	same.NotAfter = w.now.Add(24 * time.Hour) // still the same version, so refused (and its old bytes are past their end)
	if _, err := w.install(same, w.sponsorK); !errors.Is(err, ErrStale) {
		t.Fatalf("expired version reinstalled: %v", err)
	}
	d2 := d
	d2.Version, d2.IssuedAt, d2.NotAfter = 2, w.now, w.now.Add(DefaultSponsorship)
	if _, err := w.install(d2, w.sponsorK); err != nil || w.e.Get(w.agent).State != StateActive {
		t.Fatalf("next version: %v", err)
	}
	// Removed: gone, as any.
	if _, err := w.e.Stop(w.agent, true); err != nil {
		t.Fatal(err)
	}
}

// A schedule that expires while agentd is down loses its keys when agentd loads.
func TestExpiredAtLoadDropsFileKeys(t *testing.T) {
	w, _, d := collectWorld(t, func(d *Definition) {
		d.Files, d.FilesGrant = []proto.StoredFile{testStoredFile(t)}, testGrant
		d.NotAfter = d.IssuedAt.Add(48 * time.Hour)
	})
	w.set(d.NotAfter.Add(time.Hour))
	e2 := New(Config{Firm: firm, Dir: &w.dir, Store: w.store, IDKey: []byte("id key"), Now: w.clock})
	if n, err := e2.Load(); err != nil || n != 1 || e2.Get(w.agent).State != StateExpired {
		t.Fatalf("load: %d %v", n, err)
	}
	defs, _ := w.store.Definitions()
	if len(defs) != 1 || defs[0].State != StateExpired || bytes.Contains(defs[0].Env, []byte(testGrant)) {
		t.Fatalf("stored: %+v", defs)
	}
}
