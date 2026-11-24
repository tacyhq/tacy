package main

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tacyhq/tacy/sealstate"
	"github.com/tacyhq/tacy/unlock"
)

// leaseRow is the Worker's lease row (the chat Worker's serveLease rule: written when there is none, it is the
// claimant's, or it lapsed and was the same app's; never "legacy"; until < now lapses), on a shared clock.
type leaseRow struct {
	mu     sync.Mutex
	holder string
	until  int64
	now    time.Time
	down   bool // the Worker doesn't answer
	none   bool // an older Worker: no route
}

func (r *leaseRow) clock() time.Time { r.mu.Lock(); defer r.mu.Unlock(); return r.now }
func (r *leaseRow) advance(d time.Duration) {
	r.mu.Lock()
	r.now = r.now.Add(d)
	r.mu.Unlock()
}

// assign is the Worker's switch giving the row to holder (vm-lease.ts assignLease).
func (r *leaseRow) assign(holder string) {
	r.mu.Lock()
	r.holder, r.until = holder, r.now.Unix()+60
	r.mu.Unlock()
}

func appOfHolder(h string) string { return strings.SplitN(h, "/", 2)[0] }

func (r *leaseRow) claimFor(holder string) func(context.Context, string, time.Duration) (unlock.LeaseRow, bool, error) {
	return func(_ context.Context, from string, ttl time.Duration) (unlock.LeaseRow, bool, error) {
		r.mu.Lock()
		defer r.mu.Unlock()
		if r.none {
			return unlock.LeaseRow{}, false, unlock.ErrNoOwnerRoute
		}
		if r.down {
			return unlock.LeaseRow{}, false, errors.New("no answer")
		}
		now := r.now.Unix()
		if from != "" { // a takeover the Worker ordered: compare and set on the holder it names
			if r.holder == "" || r.holder == from || r.holder == holder {
				r.holder, r.until = holder, now+int64(ttl/time.Second)
			}
		} else if r.holder == "" || r.holder == holder || (r.until < now && r.holder != "legacy" && appOfHolder(r.holder) == appOfHolder(holder)) {
			r.holder, r.until = holder, now+int64(ttl/time.Second)
		}
		return unlock.LeaseRow{Holder: r.holder, Until: r.until}, r.holder == holder && r.until > now, nil
	}
}

type leaseVM struct {
	l        *stateLease
	standby  atomic.Bool
	drained  atomic.Bool
	open     atomic.Int32
	inflight atomic.Int64
	stale    atomic.Bool
	flushes  atomic.Int32
	releases atomic.Int32
	restarts []string
	mu       sync.Mutex
}

func newLeaseVM(r *leaseRow, holder string) *leaseVM {
	v := &leaseVM{}
	v.l = &stateLease{
		holder:   holder,
		claim:    r.claimFor(holder),
		stale:    func(context.Context) (bool, error) { return v.stale.Load(), nil },
		flush:    func(context.Context) error { v.flushes.Add(1); return nil },
		open:     func() int { return int(v.open.Load()) },
		inflight: v.inflight.Load,
		drained:  v.drained.Load,
		standby:  v.standby.Store,
		released: func() { v.releases.Add(1) },
		restart:  func(reason string) { v.mu.Lock(); v.restarts = append(v.restarts, reason); v.mu.Unlock() },
		now:      r.clock,
		logf:     func(string, ...any) {},
	}
	return v
}

func (v *leaseVM) restarted() int { v.mu.Lock(); defer v.mu.Unlock(); return len(v.restarts) }

// undrainSettled is the switch asking /undrain until the background claim answered.
func undrainSettled(t *testing.T, v *leaseVM) string {
	t.Helper()
	return undrainTake(t, v, "")
}

// undrainTake is the switch asking /undrain (with its order) again and again, as vm-switch.ts does, until the answer
// isn't "checking": each ask goes through undrained, as the Worker's polls do.
func undrainTake(t *testing.T, v *leaseVM, take string) string {
	t.Helper()
	st := v.l.undrained(context.Background(), take)
	for i := 0; st == leaseChecking && i < 200; i++ {
		time.Sleep(5 * time.Millisecond)
		st = v.l.undrained(context.Background(), take)
	}
	return st
}

const (
	holderA  = "appA/instA/0000000000000001"
	holderA2 = "appA/instA/0000000000000002" // A's next boot
	holderB  = "appB/instB/0000000000000003"
)

func TestLeaseOneWriter(t *testing.T) {
	ctx := context.Background()
	r := &leaseRow{now: time.Unix(1_800_000_000, 0)}
	a, b := newLeaseVM(r, holderA), newLeaseVM(r, holderB)
	if st := a.l.boot(ctx); st != leaseHeld || a.standby.Load() {
		t.Fatalf("A at boot: %s standby=%v, want held", st, a.standby.Load())
	}
	// B boots beside A (a standby, a rollback VM, a failover's original powered on again): a standby, no saves.
	if st := b.l.boot(ctx); st != leaseStandby || !b.standby.Load() {
		t.Fatalf("B at boot: %s standby=%v, want standby", st, b.standby.Load())
	}
	if !a.l.Writer(ctx) || b.l.Writer(ctx) {
		t.Fatal("only A may save")
	}
	for i := 0; i < 10; i++ {
		r.advance(leaseRenew)
		a.l.try(ctx)
		b.l.try(ctx)
		if !a.l.Writer(ctx) || b.l.Writer(ctx) {
			t.Fatalf("round %d: two writers or none", i)
		}
	}
	// A's agentd restarts within its boot (the hourly container restart: the same holder from the tmpfs) while B keeps
	// trying: A again, never B (review H1: no release on a plain stop).
	a2 := newLeaseVM(r, holderA)
	r.advance(5 * time.Second)
	b.l.try(ctx)
	if st := a2.l.boot(ctx); st != leaseHeld || b.l.Writer(ctx) {
		t.Fatalf("A's restarted agentd: %s, B writer=%v; want A held", st, b.l.Writer(ctx))
	}
	// A idle-stops (its row lapses): B, another VM, never takes it on its own; A's next boot (same app) does.
	r.advance(2 * leaseTTL)
	b.l.try(ctx)
	if b.l.Writer(ctx) {
		t.Fatal("a standby took another VM's lapsed lease (it must wait for the Worker's switch)")
	}
	a3 := newLeaseVM(r, holderA2)
	if st := a3.l.boot(ctx); st != leaseHeld {
		t.Fatalf("A's next boot after its lease lapsed: %s, want held (a wake)", st)
	}
}

func TestLeaseDrainedHandover(t *testing.T) {
	ctx := context.Background()
	r := &leaseRow{now: time.Unix(1_800_000_000, 0)}
	a, b := newLeaseVM(r, holderA), newLeaseVM(r, holderB)
	a.l.boot(ctx)
	b.l.boot(ctx)
	// The switch drains A with a task open, then with a start being admitted: A keeps the lease and says so.
	a.drained.Store(true)
	a.open.Store(1)
	if st := a.l.drainedNow(ctx); st != leaseHeld {
		t.Fatalf("drained with a task open: %s, want held", st)
	}
	a.open.Store(0)
	a.inflight.Store(1)
	if st := a.l.drainedNow(ctx); st != leaseHeld {
		t.Fatalf("drained with a start being admitted: %s, want held (review M2)", st)
	}
	a.inflight.Store(0)
	before := a.flushes.Load()
	if st := a.l.drainedNow(ctx); st != leaseReleased || a.flushes.Load() != before+1 || a.releases.Load() != 1 {
		t.Fatalf("drained, nothing open: %s (flushes %d, owner rows released %d), want released after one save", st, a.flushes.Load()-before, a.releases.Load())
	}
	if a.l.Writer(ctx) || !a.standby.Load() {
		t.Fatal("a released VM may not save or take work")
	}
	// B undrained: the row is still A's, so a standby; the Worker's switch gives it to B; B's state is the stored one.
	if st := undrainSettled(t, b); st != leaseStandby {
		t.Fatalf("B before the switch gives it the lease: %s, want standby", st)
	}
	if st := undrainTake(t, b, holderA); st != leaseHeld || b.standby.Load() || !b.l.Writer(ctx) {
		t.Fatalf("B after the switch gave it the lease: %s, want held", st)
	}
	// A, released and drained, doesn't try again; nor does it take it back if undrained (B's now).
	r.advance(leaseRetry * 2)
	a.l.try(ctx)
	if a.l.Writer(ctx) {
		t.Fatal("two writers after the handover")
	}
}

func TestLeaseStaleStandbyReloads(t *testing.T) {
	ctx := context.Background()
	r := &leaseRow{now: time.Unix(1_800_000_000, 0)}
	a, b := newLeaseVM(r, holderA), newLeaseVM(r, holderB)
	a.l.boot(ctx)
	b.l.boot(ctx)
	// A saved while B stood by: when B gets the lease it must load again (a restart), never save over A's.
	b.stale.Store(true)
	a.drained.Store(true)
	a.l.drainedNow(ctx)
	if st := undrainTake(t, b, holderA); st != leaseReloading {
		t.Fatalf("B, stale: %s, want reloading", st)
	}
	if b.l.Writer(ctx) {
		t.Fatal("a stale VM may not save")
	}
	time.Sleep(700 * time.Millisecond) // the restart waits for the answer to go out
	if b.restarted() != 1 {
		t.Fatalf("restarts %d, want 1", b.restarted())
	}
	// Its next process (the same boot: the same holder) loads the stored state and holds the lease.
	b2 := newLeaseVM(r, holderB)
	if st := b2.l.boot(ctx); st != leaseHeld {
		t.Fatalf("B after the reload: %s, want held", st)
	}
}

func TestLeaseTakenOverStops(t *testing.T) {
	ctx := context.Background()
	r := &leaseRow{now: time.Unix(1_800_000_000, 0)}
	a := newLeaseVM(r, holderA)
	a.l.boot(ctx)
	// A failover's forced switch gives the row to B while A still runs (unreachable through its tunnel only).
	r.assign(holderB)
	// A's next save renews first once its last renewal is leaseFresh old: refused, A stops (no save). Its saves in
	// between are the Worker's fence's to refuse (the chat Worker's lease route and its tests).
	r.advance(leaseFresh)
	if a.l.Writer(ctx) {
		t.Fatal("A saved after the takeover")
	}
	if a.restarted() != 1 {
		t.Fatalf("restarts %d, want 1 (A comes back as a standby)", a.restarted())
	}
}

func TestLeaseNoAnswerStopsWorkBeforeItLapses(t *testing.T) {
	ctx := context.Background()
	r := &leaseRow{now: time.Unix(1_800_000_000, 0)}
	a := newLeaseVM(r, holderA)
	a.l.boot(ctx)
	r.down = true
	r.advance(leaseFresh)
	if !a.l.Writer(ctx) || a.standby.Load() {
		t.Fatal("a writer with time left on its lease keeps saving while the Worker is away")
	}
	r.advance(leaseTTL - leaseMargin - leaseFresh)
	if a.l.Writer(ctx) || !a.standby.Load() {
		t.Fatal("a writer within the margin of its lease's end without a renewal still saves or takes work (review M8)")
	}
	if a.restarted() != 0 {
		t.Fatal("no answer isn't a refusal: no restart")
	}
	r.down = false
	if !a.l.Writer(ctx) || a.standby.Load() {
		t.Fatal("renewed: saves and takes work again")
	}
}

func TestLeaseOlderWorkerWritesAsBefore(t *testing.T) {
	ctx := context.Background()
	r := &leaseRow{now: time.Unix(1_800_000_000, 0), none: true}
	a := newLeaseVM(r, holderA)
	if st := a.l.boot(ctx); st != leaseNone || a.standby.Load() || !a.l.Writer(ctx) {
		t.Fatalf("no lease route at boot: %s standby=%v, want none and a writer", st, a.standby.Load())
	}
	r.none = false
	a.l.try(ctx)
	if st := a.l.State(); st != leaseHeld || a.restarted() != 0 {
		t.Fatalf("after the route appears: %s, restarts %d", st, a.restarted())
	}
	// A 404 once the route answered is no answer at first (review M7): the writer while its lease lasts...
	r.none = true
	r.advance(leaseFresh)
	if !a.l.Writer(ctx) || a.l.State() == leaseNone {
		t.Fatal("a 404 right after an answer turned the lease off")
	}
	// ...and after a whole TTL of 404s (a Worker rolled back past the lease: go-live review H2), it writes on as before
	// instead of stopping (nobody can hold the row: no Worker reads it).
	r.advance(leaseTTL)
	a.l.try(ctx)
	if st := a.l.State(); st != leaseNone || !a.l.Writer(ctx) || a.standby.Load() {
		t.Fatalf("after a TTL of 404s: %s (standby %v), want none and a writer", st, a.standby.Load())
	}
	// The Worker rolled forward again: the next try holds the lease again, no reload (re-check N1).
	r.none = false
	a.l.try(ctx)
	if st := a.l.State(); st != leaseHeld || a.restarted() != 0 {
		t.Fatalf("after the roll forward: %s, restarts %d; want held", st, a.restarted())
	}
}

func TestLeaseBootKeptInTmpfs(t *testing.T) {
	dir := t.TempDir()
	a, b := leaseBoot(dir), leaseBoot(dir)
	if len(a) != 16 || a != b {
		t.Fatalf("boot ids %q %q: one per boot, kept for a restarted agentd", a, b)
	}
	if c := leaseBoot(""); c == a || len(c) != 16 {
		t.Fatalf("no tmpfs: a fresh one (%q)", c)
	}
}

// The keeper's gate (sealstate.Keeper.Writer): a standby saves nothing, and an asked save says why.
func TestKeeperWriterGate(t *testing.T) {
	ctx := context.Background()
	st, err := sealstate.New(&sealstate.Mem{}, make([]byte, 32), "agent-vm")
	if err != nil {
		t.Fatal(err)
	}
	k := &sealstate.Keeper{Store: st}
	slot := sealstate.NewSlot(nil)
	if err := k.Add("notify", slot); err != nil {
		t.Fatal(err)
	}
	var writer atomic.Bool
	k.Writer = func(context.Context) bool { return writer.Load() }
	if err := slot.Save([]byte("on")); err != nil {
		t.Fatal(err)
	}
	if err := k.Flush(ctx); err != nil || st.Gen("notify") != 0 {
		t.Fatalf("a standby's flush saved (gen %d, err %v)", st.Gen("notify"), err)
	}
	if err := k.SaveNow(ctx, "notify"); !errors.Is(err, sealstate.ErrNotWriter) {
		t.Fatalf("a standby's SaveNow: %v, want ErrNotWriter", err)
	}
	writer.Store(true)
	if err := k.Flush(ctx); err != nil || st.Gen("notify") != 1 {
		t.Fatalf("the writer's flush: gen %d, err %v", st.Gen("notify"), err)
	}
	// Stale: another instance saved since this Store loaded.
	other, _ := sealstate.New(st.Backend(), make([]byte, 32), "agent-vm")
	if s, err := st.Stale(ctx, []string{"notify"}); err != nil || s {
		t.Fatalf("fresh: stale=%v err=%v", s, err)
	}
	if _, err := other.Load(ctx, "notify"); err != nil {
		t.Fatal(err)
	}
	if err := other.Save(ctx, "notify", []byte("off")); err != nil {
		t.Fatal(err)
	}
	if s, err := st.Stale(ctx, []string{"notify"}); err != nil || !s {
		t.Fatalf("after another's save: stale=%v err=%v", s, err)
	}
}

// A switch undone after the old VM released: undrained again, it holds its own row at once, with no stale check
// (nobody else could have saved), so its users' work isn't refused meanwhile (the gad2 drill, try 1).
func TestLeaseUndoneSwitchNoStaleCheck(t *testing.T) {
	ctx := context.Background()
	r := &leaseRow{now: time.Unix(1_800_000_000, 0)}
	a := newLeaseVM(r, holderA)
	a.l.boot(ctx)
	a.drained.Store(true)
	if st := a.l.drainedNow(ctx); st != leaseReleased {
		t.Fatal(st)
	}
	a.drained.Store(false)
	a.stale.Store(true) // would force a reload if it were checked
	if st := undrainSettled(t, a); st != leaseHeld || a.restarted() != 0 {
		t.Fatalf("undone: %s, restarts %d; want held at once", st, a.restarted())
	}
}
