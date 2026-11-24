package main

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tacyhq/tacy/gateway"
	"github.com/tacyhq/tacy/sealstate"
	"github.com/tacyhq/tacy/unlock"
)

// worldVM is one agentd of the app in the kms world (two CVMs of one app: the gad drills' pha and goog), with its
// sealed state, its writer lease at the Worker's twin (kmsvm.StateAPI, the stand-in) through gatewayd's fixed calls,
// and every save carrying its holder (the fence).
type worldVM struct {
	b       *booted
	lease   *stateLease
	standby atomic.Bool
	drained atomic.Bool
	stopped atomic.Int32
}

func (w *kmsWorld) bootLeased(t *testing.T, instance, holder string) *worldVM {
	t.Helper()
	k := w.release(t, instance, agentPurposes...)
	be := w.relayBackend(t, k, PurposeState)
	be.Writer = func() string { return holder }
	b, err := bootState(context.Background(), unlockKeys{k.Keys}, be, nil, "f_chat")
	if err != nil {
		t.Fatal(err)
	}
	auth, err := k.StoreAuth(PurposeState, nil)
	if err != nil {
		t.Fatal(err)
	}
	owner := &unlock.Owner{Client: gateway.StateHTTP{D: w.gw}, Auth: auth, ID: holder[:len(holder)-17]}
	name := unlock.LeaseName(leaseScope)
	v := &worldVM{b: b}
	keeper := b.kept.keeper
	v.lease = &stateLease{
		holder: holder,
		claim: func(ctx context.Context, from string, ttl time.Duration) (unlock.LeaseRow, bool, error) {
			return owner.ClaimLease(ctx, name, holder, from, ttl)
		},
		stale:    func(ctx context.Context) (bool, error) { return keeper.Store.Stale(ctx, keeper.Names()) },
		flush:    keeper.Flush,
		open:     func() int { return 0 },
		inflight: func() int64 { return 0 },
		drained:  v.drained.Load,
		standby:  v.standby.Store,
		restart:  func(string) { v.stopped.Add(1) },
		logf:     t.Logf,
	}
	keeper.Writer = v.lease.Writer
	v.lease.boot(context.Background())
	return v
}

func settle(t *testing.T, l *stateLease, take string) string {
	t.Helper()
	st := l.undrained(context.Background(), take)
	for i := 0; st == leaseChecking && i < 400; i++ {
		time.Sleep(10 * time.Millisecond)
		st = l.undrained(context.Background(), take) // asked again, as the Worker's switch does
	}
	return st
}

// Two VMs of one app up at once, as in the gad drills (failover, then the original powered on again for the switch
// back): only the lease's holder saves, the other saves nothing and its forced save is fenced; the switch's handover
// moves the writer, and the VM taking over reloads what the old one saved. Over the production paths (gatewayd's
// fixed calls, the state API's twin).
func TestLeaseTwoVMsOneApp(t *testing.T) {
	ctx := context.Background()
	w := newKMSWorld(t)
	goog := w.bootLeased(t, "goog-1", "appG/instG/00000000000000a1")
	pha := w.bootLeased(t, "pha-2", "appP/instP/00000000000000b2")
	if goog.lease.State() != leaseHeld || pha.lease.State() != leaseStandby || !pha.standby.Load() {
		t.Fatalf("goog %s, pha %s (standby %v): want held and standby", goog.lease.State(), pha.lease.State(), pha.standby.Load())
	}
	// Runs on goog change its state; its keeper saves them. pha changes something too (a safety floor): not saved.
	if err := goog.b.kept.notify.Set("s_a", true); err != nil {
		t.Fatal(err)
	}
	if err := goog.b.kept.keeper.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	if err := pha.b.kept.notify.Set("s_b", true); err != nil {
		t.Fatal(err)
	}
	if err := pha.b.kept.keeper.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	gen := goog.b.kept.keeper.Store.Gen(stateNotify)
	if gen != 1 || pha.b.kept.keeper.Store.Gen(stateNotify) != 0 {
		t.Fatalf("gens goog %d pha %d: only goog saved", gen, pha.b.kept.keeper.Store.Gen(stateNotify))
	}
	// A save that skips the gate (a VM that hasn't noticed it lost the lease) is fenced at the Worker: refused, the
	// stored state is goog's.
	if err := pha.b.kept.keeper.Store.Save(ctx, stateNotify, []byte("x")); !errors.Is(err, sealstate.ErrFailed) {
		t.Fatalf("pha's ungated save: %v, want refused (the fence)", err)
	}
	// The switch back: goog drained, nothing open: its last save, released. pha undrained with the switch's order
	// (take it from goog): its state is behind goog's, so it reloads (restarts) rather than saving over it.
	goog.drained.Store(true)
	if st := goog.lease.drainedNow(ctx); st != leaseReleased {
		t.Fatalf("goog drained: %s", st)
	}
	if st := settle(t, pha.lease, ""); st != leaseStandby {
		t.Fatalf("pha's own claim while goog's row stands: %s, want standby (never takes another VM's row)", st)
	}
	if st := settle(t, pha.lease, "appG/instG/00000000000000a1"); st != leaseReloading {
		t.Fatalf("pha with the switch's order: %s, want reloading (behind goog's saves)", st)
	}
	time.Sleep(700 * time.Millisecond)
	if pha.stopped.Load() != 1 {
		t.Fatal("pha didn't restart to reload")
	}
	// pha's next process (the same boot) loads goog's state and holds the lease; goog's saves are fenced now.
	pha2 := w.bootLeased(t, "pha-2", "appP/instP/00000000000000b2")
	if pha2.lease.State() != leaseHeld {
		t.Fatalf("pha after its reload: %s, want held", pha2.lease.State())
	}
	if !pha2.b.kept.notify.On("s_a") {
		t.Fatal("pha's reload doesn't have what goog saved")
	}
	if err := goog.b.kept.keeper.Store.Save(ctx, stateNotify, []byte("y")); !errors.Is(err, sealstate.ErrFailed) {
		t.Fatalf("goog's save after the handover: %v, want refused (the fence)", err)
	}
}
