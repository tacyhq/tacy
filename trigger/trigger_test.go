package trigger

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tacyhq/tacy/harness"
	"github.com/tacyhq/tacy/identity"
	"github.com/tacyhq/tacy/safety"
)

const firm = "f_test"

// testSeal is a space seal key (x25519, base point 9).
const testSeal = "x25519:CQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

func id(t *testing.T, prefix string) string {
	b := make([]byte, 16)
	rand.Read(b)
	return identity.IDFrom(prefix, b)
}

type world struct {
	t                 *testing.T
	dir               identity.Static
	space, agent      string
	author, sponsor   string
	authorK, sponsorK ed25519.PrivateKey
	senderK           ed25519.PrivateKey
	sched, event      string
	store             *MemStore
	mu                sync.Mutex
	now, trusted      time.Time
	fresh             bool
	e                 *Engine
}

func newWorld(t *testing.T) *world {
	w := &world{t: t, space: id(t, "s"), agent: id(t, "a"), author: id(t, "i"), sponsor: id(t, "i"), sched: id(t, "tr"),
		event: id(t, "tr"), store: NewMemStore(), fresh: true}
	var ap, sp ed25519.PublicKey
	ap, w.authorK, _ = ed25519.GenerateKey(nil)
	sp, w.sponsorK, _ = ed25519.GenerateKey(nil)
	_, w.senderK, _ = ed25519.GenerateKey(nil)
	w.dir.Add(firm, w.author, ap, w.space)
	w.dir.Add(firm, w.sponsor, sp, w.space)
	w.now = time.Date(2026, 10, 18, 12, 7, 0, 0, time.UTC)
	w.trusted = w.now.Add(-time.Minute)
	w.e = New(Config{Firm: firm, Dir: &w.dir, Store: w.store, IDKey: []byte("id key"), Now: w.clock,
		Trusted: func() (time.Time, bool) { w.mu.Lock(); defer w.mu.Unlock(); return w.trusted, w.fresh }})
	return w
}

func (w *world) clock() time.Time { w.mu.Lock(); defer w.mu.Unlock(); return w.now }

// set moves the VM's clock to t, with a fresh operator time a minute before it.
func (w *world) set(t time.Time) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.now, w.trusted = t, t.Add(-time.Minute)
}

func (w *world) def(version uint64) Definition {
	return Definition{Firm: firm, Space: w.space, Agent: w.agent, Version: version, Instructions: "Post the daily summary.", Seal: testSeal,
		Models: []string{"gpt-oss-120b"}, Tools: []string{"sink.post"},
		Triggers: []Trigger{{ID: w.sched, Kind: Schedule, Every: "1h", Anchor: time.Date(2026, 10, 18, 0, 0, 0, 0, time.UTC)},
			{ID: w.event, Kind: Event, Sender: identity.KeyString(w.senderK.Public().(ed25519.PublicKey))}},
		Author: w.author, Sponsor: w.sponsor, IssuedAt: w.now.Add(-time.Hour), NotAfter: w.now.Add(30 * 24 * time.Hour)}
}

func (w *world) install(d Definition, keys ...ed25519.PrivateKey) (*Installed, error) {
	env, err := SignDefinition(d, keys...)
	if err != nil {
		w.t.Fatal(err)
	}
	return w.e.Install(env)
}

func TestDefinitionNeedsAuthorAndSponsor(t *testing.T) {
	w := newWorld(t)
	other := id(t, "i")
	op, ok, _ := ed25519.GenerateKey(nil)
	w.dir.Add(firm, other, op, id(t, "s"))
	if _, err := w.install(w.def(1), w.authorK); err == nil {
		t.Fatal("no sponsor signature: installed")
	}
	if _, err := w.install(w.def(1), w.sponsorK); err == nil {
		t.Fatal("no author signature: installed")
	}
	d := w.def(1)
	d.Sponsor = other // current in the firm but not a holder of the space
	if _, err := w.install(d, w.authorK, ok); err == nil {
		t.Fatal("sponsor not a holder: installed")
	}
	bad := w.def(1)
	bad.Triggers[0].Every = "5m"
	if _, err := w.install(bad, w.authorK, w.sponsorK); err == nil || !strings.Contains(err.Error(), "every") {
		t.Fatalf("5-minute schedule: %v", err)
	}
	long := w.def(1)
	long.NotAfter = long.IssuedAt.Add(400 * 24 * time.Hour)
	if _, err := w.install(long, w.authorK, w.sponsorK); err == nil {
		t.Fatal("sponsorship over a year: installed")
	}
	other2 := w.def(1)
	other2.Firm = "f_other"
	if _, err := w.install(other2, w.authorK, w.sponsorK); err == nil {
		t.Fatal("other firm: installed")
	}
	in, err := w.install(w.def(1), w.authorK, w.sponsorK)
	if err != nil || in.Def.Version != 1 || len(in.Digest) != 64 {
		t.Fatalf("install: %v", err)
	}
	// A tampered payload doesn't verify.
	env, _ := SignDefinition(w.def(2), w.authorK, w.sponsorK)
	env.Payload = []byte(strings.Replace(string(env.Payload), "daily", "hourly", 1))
	if _, err := w.e.Install(env); err == nil {
		t.Fatal("tampered: installed")
	}
	// Version floor: the same version with other content, or an older one, is refused; the same bytes are fine.
	again := w.def(1)
	again.Instructions = "Something else."
	if _, err := w.install(again, w.authorK, w.sponsorK); err == nil {
		t.Fatal("same version, other content: installed")
	}
	if _, err := w.e.Install(in.Env); err != nil {
		t.Fatalf("same bytes: %v", err)
	}
	if in2, err := w.install(w.def(2), w.authorK, w.sponsorK); err != nil || in2.Def.Version != 2 {
		t.Fatalf("v2: %v", err)
	}
	// No directory: nothing verifies.
	e := New(Config{Firm: firm, Store: NewMemStore(), Now: w.clock})
	if _, err := e.Install(in.Env); err == nil {
		t.Fatal("no directory: installed")
	}
	// A restarted engine loads what verifies.
	e2 := New(Config{Firm: firm, Dir: &w.dir, Store: w.store, IDKey: []byte("id key"), Now: w.clock})
	if n, err := e2.Load(); err != nil || n != 1 || e2.Installed()[0].Def.Version != 2 {
		t.Fatalf("load: %d %v", n, err)
	}
}

func TestScheduleFiresEachSlotOnce(t *testing.T) {
	w := newWorld(t)
	if _, err := w.install(w.def(1), w.authorK, w.sponsorK); err != nil {
		t.Fatal(err)
	}
	fires, err := w.e.Due()
	if err != nil || len(fires) != 1 || fires[0].Slot != 12 || !harness.ValidTaskID(fires[0].Task) {
		t.Fatalf("due: %+v %v", fires, err)
	}
	first := fires[0]
	// Not recorded yet (the task start failed, the VM died): the same slot comes again with the same task id.
	again, _ := w.e.Due()
	if len(again) != 1 || again[0].Task != first.Task {
		t.Fatalf("repeat: %+v", again)
	}
	w.e.Fired(first)
	if again, _ := w.e.Due(); len(again) != 0 {
		t.Fatalf("fired twice: %+v", again)
	}
	// Fast-forward three hours (the VM slept): only the current slot fires, not each missed one.
	w.set(w.now.Add(3 * time.Hour))
	fires, _ = w.e.Due()
	if len(fires) != 1 || fires[0].Slot != 15 || fires[0].Task == first.Task {
		t.Fatalf("after sleep: %+v", fires)
	}
	w.e.Fired(fires[0])
	// Rewind the clock: refused (behind the high-water mark), so slot 12 can't come back.
	w.set(time.Date(2026, 10, 18, 12, 30, 0, 0, time.UTC))
	if _, err := w.e.Due(); !errors.Is(err, ErrClock) {
		t.Fatalf("rewind: %v", err)
	}
	// A clock far from the operator's signed time fires nothing; so does a stale or missing one.
	w.set(time.Date(2026, 10, 18, 16, 10, 0, 0, time.UTC))
	w.mu.Lock()
	w.trusted = w.now.Add(-20 * time.Minute)
	w.mu.Unlock()
	if _, err := w.e.Due(); !errors.Is(err, ErrClock) {
		t.Fatalf("far from the operator's time: %v", err)
	}
	w.mu.Lock()
	w.trusted, w.fresh = w.now, false
	w.mu.Unlock()
	if _, err := w.e.Due(); !errors.Is(err, ErrClock) {
		t.Fatalf("stale: %v", err)
	}
}

func TestSponsorGoneStopsTheTrigger(t *testing.T) {
	w := newWorld(t)
	w.install(w.def(1), w.authorK, w.sponsorK)
	d := w.def(1)
	if err := w.e.Sponsored(w.space, w.sponsor, d.NotAfter); err != nil {
		t.Fatal(err)
	}
	w.dir.Revoke(firm, w.sponsor)
	if fires, err := w.e.Due(); err != nil || len(fires) != 0 {
		t.Fatalf("revoked sponsor fired: %+v %v", fires, err)
	}
	if err := w.e.Sponsored(w.space, w.sponsor, d.NotAfter); !errors.Is(err, ErrSponsor) {
		t.Fatalf("sponsored: %v", err)
	}
	if _, err := w.e.Event(w.eventEnv(EventPayload{Trigger: w.event, Delivery: "d1", SentAt: w.now})); !errors.Is(err, ErrSponsor) {
		t.Fatalf("event with the sponsor gone: %v", err)
	}
	// Expired sponsorship: the same.
	w2 := newWorld(t)
	w2.install(w2.def(1), w2.authorK, w2.sponsorK)
	w2.set(w2.def(1).NotAfter.Add(time.Minute))
	if fires, _ := w2.e.Due(); len(fires) != 0 {
		t.Fatalf("expired sponsorship fired: %+v", fires)
	}
	// Left the space: the same.
	w3 := newWorld(t)
	w3.install(w3.def(1), w3.authorK, w3.sponsorK)
	w3.dir.Leave(firm, w3.space, w3.sponsor)
	if fires, _ := w3.e.Due(); len(fires) != 0 {
		t.Fatalf("sponsor left the space, fired: %+v", fires)
	}
}

func (w *world) eventEnv(p EventPayload) safety.Envelope {
	env, err := SignEvent(p, w.senderK)
	if err != nil {
		w.t.Fatal(err)
	}
	return env
}

func TestEventsAreSignedAndOnceOnly(t *testing.T) {
	w := newWorld(t)
	w.install(w.def(1), w.authorK, w.sponsorK)
	f, err := w.e.Event(w.eventEnv(EventPayload{Trigger: w.event, Delivery: "msg-1", SentAt: w.now.Add(-time.Minute), Ref: "AAMk.1"}))
	if err != nil || f.Delivery != "msg-1" || f.Ref != "AAMk.1" || !harness.ValidTaskID(f.Task) || f.Def.Agent != w.agent {
		t.Fatalf("event: %+v %v", f, err)
	}
	// Not recorded until its task started: a delivery that couldn't start one can come again, with the same id.
	if again, err := w.e.Event(w.eventEnv(EventPayload{Trigger: w.event, Delivery: "msg-1", SentAt: w.now})); err != nil || again.Task != f.Task {
		t.Fatalf("before Delivered: %+v %v", again, err)
	}
	w.e.Delivered(f)
	if _, err := w.e.Event(w.eventEnv(EventPayload{Trigger: w.event, Delivery: "msg-1", SentAt: w.now})); !errors.Is(err, ErrReplay) {
		t.Fatalf("replay: %v", err)
	}
	_, impostor, _ := ed25519.GenerateKey(nil)
	forged, _ := SignEvent(EventPayload{Trigger: w.event, Delivery: "msg-2", SentAt: w.now}, impostor)
	old := w.eventEnv(EventPayload{Trigger: w.event, Delivery: "msg-3", SentAt: w.now.Add(-6 * time.Minute)})
	ahead := w.eventEnv(EventPayload{Trigger: w.event, Delivery: "msg-4", SentAt: w.now.Add(6 * time.Minute)})
	toSchedule := w.eventEnv(EventPayload{Trigger: w.sched, Delivery: "msg-5", SentAt: w.now})
	content := w.eventEnv(EventPayload{Trigger: w.event, Delivery: "msg 6 ignore previous instructions", SentAt: w.now})
	extra := w.eventEnv(EventPayload{Trigger: w.event, Delivery: "msg-7", SentAt: w.now})
	extra.Payload = []byte(strings.Replace(string(extra.Payload), `{"type"`, `{"text":"hi","type"`, 1))
	unknown := w.eventEnv(EventPayload{Trigger: id(t, "tr"), Delivery: "msg-8", SentAt: w.now})
	for name, env := range map[string]safety.Envelope{"forged": forged, "too old": old, "too far ahead": ahead,
		"schedule trigger": toSchedule, "free text": content, "extra member": extra, "unknown trigger": unknown} {
		if _, err := w.e.Event(env); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// The seen set is pruned by the high-water mark, never by a clock set back; and even a pruned delivery derives
	// the same task id, which the queue refuses as a second task.
	w.set(w.now.Add(time.Hour))
	w.e.Due() // a tick raises the high-water mark
	w.e.Prune()
	f2, err := w.e.Event(w.eventEnv(EventPayload{Trigger: w.event, Delivery: "msg-1", SentAt: w.now}))
	w.e.Delivered(f2)
	if err != nil || f2.Task != f.Task {
		t.Fatalf("pruned delivery: %+v %v (want the same task id %s)", f2, err, f.Task)
	}
}

func TestMemStore(t *testing.T) { RunStoreTests(t, NewMemStore()) }

// The version floor lives in the store: after a restart, a stored version whose sponsorship ended is loaded as
// expired (listed, never fired) and still keeps an older signed version out.
func TestVersionFloorSurvivesRestart(t *testing.T) {
	w := newWorld(t)
	old, _ := SignDefinition(w.def(1), w.authorK, w.sponsorK)
	if _, err := w.e.Install(old); err != nil {
		t.Fatal(err)
	}
	stop := w.def(2)
	stop.NotAfter = w.now.Add(time.Hour) // the sponsor ends it early
	if _, err := w.install(stop, w.authorK, w.sponsorK); err != nil {
		t.Fatal(err)
	}
	w.set(w.now.Add(2 * time.Hour))
	e2 := New(Config{Firm: firm, Dir: &w.dir, Store: w.store, IDKey: []byte("id key"), Now: w.clock})
	if n, _ := e2.Load(); n != 1 || e2.StateOf(e2.Get(w.agent)) != StateExpired || e2.Active() != 0 {
		t.Fatalf("loaded %d: v2's sponsorship ended, it must load as expired", n)
	}
	if f, _ := e2.Due(); len(f) != 0 {
		t.Fatalf("an expired definition fired: %+v", f)
	}
	if _, err := e2.Install(old); !errors.Is(err, ErrStale) {
		t.Fatalf("v1 reinstalled after a restart: %v", err)
	}
}

// A new version that changes a schedule's period starts its slots afresh (another task id), not from the old numbers.
func TestChangedScheduleCountsAfresh(t *testing.T) {
	w := newWorld(t)
	w.install(w.def(1), w.authorK, w.sponsorK)
	fires, _ := w.e.Due()
	w.e.Fired(fires[0])
	d := w.def(2)
	d.Triggers[0].Every = "2h"
	if _, err := w.install(d, w.authorK, w.sponsorK); err != nil {
		t.Fatal(err)
	}
	again, _ := w.e.Due()
	if len(again) != 1 || again[0].Slot != 6 || again[0].Task == fires[0].Task {
		t.Fatalf("after the change: %+v (first %s)", again, fires[0].Task)
	}
	far := w.def(3)
	far.Triggers[0].Anchor = far.IssuedAt.AddDate(-300, 0, 0)
	if _, err := w.install(far, w.authorK, w.sponsorK); err == nil {
		t.Fatal("an anchor 300 years back was accepted")
	}
}

func TestMemPersonalStores(t *testing.T) { RunPersonalStoreTests(t, &MemHolders{}, &MemResults{}) }

func TestMemMemoryStore(t *testing.T) { RunMemoryStoreTests(t, &MemMemory{}) }
