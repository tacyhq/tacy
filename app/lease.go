package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"log"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tacyhq/tacy/unlock"
)

// The sealed state's writer lease (host adapter issue 12, 2026-11-23; its independent design review before the build:
// H1-H5, M1-M10). Every v1 VM of the app saves the same sealed states (state.go: side, activity, safety, budget,
// notify) at the Worker, compare-and-set on their generations. Two VMs up at once (a standby beside the active one, a
// switch, a rollback, a failover and its switch back) both saved, the second save conflicted and that agentd stopped
// and restarted (a new key: tasks cut, vm_restarted): seen live in the gad drills. So only the lease's holder saves:
//
//   - The lease is one row at the Worker (POST /api/vm/lease/<unlock.LeaseName(leaseScope)>, the chat Worker's lease route),
//     held by this boot's holder id, "<app id>/<instance id>/<boot>" (boot: random, kept in the task queue's tmpfs so
//     the hourly container restart keeps it; every VM boot differs, also two VMs of one Google target). The Worker
//     gives it on a claim only when there is none, it is this holder's, or it lapsed and was the same app's (this VM's
//     earlier boot: a wake after an idle stop, a crash). Any other move is the Worker's switch (it knows where it
//     routes): a standby never drifts into the lease (review H1).
//   - The fence: every save carries the holder (X-Tacy-Writer, sealstate.Relay); once the app has a lease row the
//     Worker refuses a save from anyone else (review H2), so timing only decides how early a VM notices, never
//     whether two can write. A refused save stops the process (sealstate ErrConflict), as any conflict did.
//   - TTL leaseTTL, renewed every leaseRenew; before a save, renewed if the last renewal is older than leaseFresh. A
//     renewal refused (the Worker gave it away: a failover): the process stops and comes back a standby. One that
//     doesn't get through: no new work and no save once the lease could have lapsed (leaseMargin, review M8).
//   - Without it the VM is a standby: drained to its routes (drain.go: no new work, no schedule, no timed write) and
//     no save. It claims again every leaseRetry unless the Worker drained it (a claim never takes another's row).
//   - Drained by the Worker (a switch): once no task is open and no new-work request is in flight (drain.go
//     admissions, review M2), it saves a last time and stops saving: "released" (the row stays its own; the switch
//     gives it to the next VM). Its schedules' ownership rows go too (review L4). A plain stop (SIGTERM, an idle stop)
//     saves and keeps the row: the same VM's next boot takes it back, nobody else can (review H1).
//   - Undrained (the VM a switch moves to): it claims, in the background (the stale check reads the stored states:
//     review M6), answering "checking" until it knows: "held" (its state is the stored one), "standby" (another holds
//     it: the switch gives it to this one, then asks again), "reloading" (it holds it, but another VM saved since this
//     one loaded: it restarts to load that, and the switch waits).
//   - A Worker or stand-in without the lease route at boot (404 before any answer): writes as before the lease
//     ("none"). A 404 later is no answer (fail closed, review M7).
//
// The scope is the whole app's state today (v1). docs/41's shards take one lease each ("state/s07"): the same route,
// rows, fence and switch handover per shard; what changes is that a shard reloads in place instead of the process
// restarting, and the switch moves shards one at a time.
const (
	leaseScope = "state/all"
	leaseTTL   = 60 * time.Second
	leaseRenew = 20 * time.Second
	leaseFresh = 10 * time.Second
	leaseRetry = 5 * time.Second
	// leaseMargin: no new work and no save this close to the lease's end without a renewal.
	leaseMargin = 15 * time.Second
)

// Lease states, as /drain and /undrain answer them.
const (
	leaseHeld      = "held"      // this VM is the writer
	leaseReleased  = "released"  // drained, saved a last time, saves nothing more (the row stays its own)
	leaseStandby   = "standby"   // another VM holds it, or it couldn't be claimed yet
	leaseChecking  = "checking"  // an undrain's claim and stale check under way
	leaseReloading = "reloading" // claimed, but another VM saved since this one loaded: restarting to load it
	leaseNone      = "none"      // no lease route (an older Worker): this VM writes as before the lease
)

type stateLease struct {
	holder   string                                                                                   // this boot's holder id
	claim    func(ctx context.Context, from string, ttl time.Duration) (unlock.LeaseRow, bool, error) // from: a takeover's
	handoff  func(ctx context.Context) error                                                          // the row to the legacy holder
	stale    func(ctx context.Context) (bool, error)                                                  // the stored state moved past what this process loaded
	flush    func(ctx context.Context) error                                                          // the keeper's save of everything changed
	open     func() int                                                                               // open tasks
	inflight func() int64                                                                             // new-work requests being admitted (drain.go)
	drained  func() bool                                                                              // drained by the Worker (drain.go's own flag, not standby)
	standby  func(bool)                                                                               // drain.go: refuse new work while not the writer
	released func()                                                                                   // after the release: the schedules' ownership rows go
	restart  func(reason string)                                                                      // stop the process (it reloads at boot)
	now      func() time.Time
	logf     func(string, ...any)

	mu        sync.Mutex
	state     string
	rowHolder string    // the row's holder as last seen
	until     time.Time // the lease's end by this VM's clock (from before the claim left)
	renewedAt time.Time
	answered  bool // the route answered once (200 or 409): a later 404 is no answer
	// the last undrain's check: its order and when it ended (undrained)
	checkedTake string
	checkedAt   time.Time
	claimMu     sync.Mutex // one claim at a time; never held across a save
	checking    atomic.Bool
}

func (l *stateLease) clock() time.Time {
	if l.now != nil {
		return l.now()
	}
	return time.Now()
}

func (l *stateLease) log(f string, a ...any) {
	if l.logf != nil {
		l.logf(f, a...)
		return
	}
	log.Printf(f, a...)
}

// State is the lease as /drain and /undrain answer it.
func (l *stateLease) State() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.state
}

func (l *stateLease) set(state string) {
	l.mu.Lock()
	l.state = state
	l.mu.Unlock()
	l.standby(!l.serving())
}

// serving: held with time left (or no lease service): new work and saves allowed.
func (l *stateLease) serving() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.state == leaseNone || l.state == leaseHeld && l.clock().Add(leaseMargin).Before(l.until)
}

// try claims (or renews) the lease once: true when this VM holds it after. A newly gained lease counts only if this
// process's state is the stored one (else "reloading" and a restart). from: the holder a takeover the Worker ordered
// takes it from ("": an ordinary claim, which never takes another VM's row).
func (l *stateLease) try(ctx context.Context) bool { return l.tryFrom(ctx, "", false) }

// tryFrom: fresh, this process loaded its state just now (its boot): a lease gained then needs no stale check (the
// generations' compare-and-set still refuses its first save if another VM saved in between, and it restarts).
func (l *stateLease) tryFrom(ctx context.Context, from string, fresh bool) bool {
	l.claimMu.Lock()
	defer l.claimMu.Unlock()
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	sent := l.clock()
	l.mu.Lock()
	lastRow := l.rowHolder // the row's holder before this claim, as this VM last saw it
	l.mu.Unlock()
	row, mine, err := l.claim(cctx, from, leaseTTL)
	l.mu.Lock()
	was, answered := l.state, l.answered
	l.mu.Unlock()
	if errors.Is(err, unlock.ErrNoOwnerRoute) {
		// No lease route at boot (an older Worker): as before the lease. One that answered before and now has none for
		// a whole TTL (a Worker rolled back past the lease: go-live review H2) while this VM held it: nobody else can
		// hold the row (no Worker reads it), so this VM writes on as before rather than stopping. Shorter: no answer.
		l.mu.Lock()
		gone := !answered || (was == leaseHeld && l.clock().Sub(l.renewedAt) >= leaseTTL)
		l.mu.Unlock()
		if gone {
			if was != leaseNone {
				l.log("lease: the Worker has no lease route: writing without a lease (as before it)")
			}
			l.mu.Lock()
			l.answered = false
			l.mu.Unlock()
			l.set(leaseNone)
			return true
		}
	}
	if err != nil {
		if was == leaseHeld {
			l.standby(!l.serving())
			return l.serving()
		}
		l.log("lease: no answer: %v", err)
		return was == leaseNone
	}
	l.mu.Lock()
	l.answered, l.rowHolder = true, row.Holder
	if mine {
		l.until, l.renewedAt = sent.Add(leaseTTL), sent
	}
	l.mu.Unlock()
	if !mine {
		if was == leaseHeld || was == leaseNone {
			// The Worker gave it to another VM (a failover's switch): stop at once, and come back a standby.
			l.restart("the state's writer lease is another VM's now")
			return false
		}
		if was != leaseStandby {
			l.log("lease: another VM holds the state (standby)")
		}
		l.set(leaseStandby)
		return false
	}
	if was == leaseHeld || was == leaseNone {
		l.set(leaseHeld) // renewed (or the Worker gained the route: this VM was the writer)
		return true
	}
	// Newly this VM's: only if nothing was saved since this process loaded; else load again (a restart). The check
	// reads every stored state, through gatewayd: its own time, not the claim's (seen live: over 10 s from Phala).
	// Fresh (its boot), or the row was this boot's own when this VM last saw it (a drained VM undrained again: a
	// switch undone): nobody else could have saved since (the fence admits only the holder), so no stale check (seen
	// live: an undone switch's check kept the old VM a standby for seconds, and its users' tasks were refused).
	if fresh || (lastRow == l.holder && from == "") {
		l.set(leaseHeld)
		l.log("lease: this VM is the state's writer (its own row)")
		return true
	}
	sctx, scancel := context.WithTimeout(ctx, 90*time.Second)
	defer scancel()
	st, err := l.stale(sctx)
	if err != nil {
		l.log("lease: couldn't compare the stored state, staying standby: %v", err)
		l.set(leaseStandby)
		return false
	}
	if st {
		l.set(leaseReloading)
		l.log("lease: another VM saved since this one loaded: restarting to load it")
		go func() {
			time.Sleep(500 * time.Millisecond) // the answer under way goes out first
			l.restart("reloading the state another VM saved")
		}()
		return false
	}
	l.set(leaseHeld)
	l.log("lease: this VM is the state's writer")
	return true
}

// release: drained, nothing open or being admitted: the last save, then nothing more (the row stays this VM's; the
// Worker's switch gives it on). True when released.
func (l *stateLease) release(ctx context.Context) bool {
	if st := l.State(); st != leaseHeld {
		return st == leaseReleased
	}
	if l.open() != 0 || l.inflight() != 0 {
		return false
	}
	cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	if err := l.flush(cctx); err != nil {
		l.log("lease: the last save before the release failed, keeping the lease: %v", err)
		return false
	}
	l.claimMu.Lock()
	if st := l.State(); st != leaseHeld || l.open() != 0 || l.inflight() != 0 {
		l.claimMu.Unlock()
		return st == leaseReleased
	}
	l.set(leaseReleased)
	l.claimMu.Unlock()
	l.log("lease: released (drained, nothing open; last save done)")
	if l.released != nil {
		l.released()
	}
	return true
}

// Writer is the keeper's gate (sealstate.Keeper.Writer): the lease held, renewed within leaseFresh (renewed now if
// not), and not within leaseMargin of its end.
func (l *stateLease) Writer(ctx context.Context) bool {
	l.mu.Lock()
	st, renewed := l.state, l.renewedAt
	l.mu.Unlock()
	if st == leaseNone {
		return true
	}
	if st != leaseHeld {
		return false
	}
	if l.clock().Sub(renewed) >= leaseFresh && !l.try(ctx) {
		return false
	}
	return l.State() == leaseHeld && l.serving()
}

// undrained: the Worker's undrain (the VM a switch moves to). take: the holder the switch takes the lease from (its
// signed order: the old VM's, which released it; the legacy row; or, forced, whoever this VM last saw holding it);
// "": an ordinary claim. A claim and stale check in the background; the answer is the state now ("checking" while it
// runs: the switch asks again).
func (l *stateLease) undrained(ctx context.Context, take string) string {
	switch st := l.State(); st {
	case leaseHeld, leaseNone, leaseReloading:
		return st
	}
	// The switch asks again until the check is done: a check that just ended for the same order is its answer, not a
	// reason for another (seen live: each ask restarted it, so the switch only ever saw "checking").
	l.mu.Lock()
	recent := l.checkedTake == take && !l.checkedAt.IsZero() && l.clock().Sub(l.checkedAt) < leaseRetry
	l.mu.Unlock()
	if recent && !l.checking.Load() {
		return l.State()
	}
	if l.checking.CompareAndSwap(false, true) {
		l.mu.Lock()
		l.state = leaseChecking
		l.mu.Unlock()
		go func() {
			defer l.checking.Store(false)
			l.tryFrom(context.WithoutCancel(ctx), take, false)
			l.mu.Lock()
			if l.state == leaseChecking {
				l.state = leaseStandby
			}
			l.checkedTake, l.checkedAt = take, l.clock()
			l.mu.Unlock()
			l.standby(!l.serving())
		}()
	}
	return l.State()
}

// RowHolder is the row's holder as this VM last saw it (the switch's forced takeover names it).
func (l *stateLease) RowHolder() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.rowHolder
}

// toLegacy: the Worker switches to a VM built before the lease (a rollback): this released VM hands the row to the
// legacy holder, so that VM's saves pass the fence. Only once released (its last save done).
func (l *stateLease) toLegacy(ctx context.Context) string {
	if l.State() != leaseReleased || l.handoff == nil {
		return l.State()
	}
	l.claimMu.Lock()
	defer l.claimMu.Unlock()
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := l.handoff(cctx); err != nil {
		l.log("lease: the handoff to the legacy holder failed: %v", err)
		return l.State()
	}
	l.log("lease: handed to the legacy holder (a switch to an older VM)")
	return "legacy"
}

// drainedNow: the Worker's drain: released at once when nothing is open, else once the last task ends (run).
func (l *stateLease) drainedNow(ctx context.Context) string {
	l.release(ctx)
	return l.State()
}

// run keeps the lease until ctx ends: renewals, the standby's claims, the drained VM's release, the margin.
func (l *stateLease) run(ctx context.Context) {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	var lastTry time.Time
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		st := l.State()
		now := l.clock()
		l.mu.Lock()
		due := now.Sub(l.renewedAt) >= leaseRenew
		l.mu.Unlock()
		switch {
		case st == leaseHeld && l.drained():
			if !l.release(ctx) && due {
				l.try(ctx)
			}
		case st == leaseHeld:
			if due {
				l.try(ctx)
			}
			l.standby(!l.serving())
		case st == leaseStandby && !l.drained() && now.Sub(lastTry) >= leaseRetry:
			lastTry = now
			l.try(ctx)
		case st == leaseNone && now.Sub(lastTry) >= time.Minute:
			// No lease route (an older Worker): asked again each minute, so a Worker rolled forward again gives this
			// VM its lease back (go-live re-check N1).
			lastTry = now
			l.try(ctx)
		}
	}
}

// boot claims the lease before agentd serves: the writer if there's no row, it's this boot's, or this VM's earlier
// boot's that lapsed; else a standby until the Worker's switch gives it the lease.
func (l *stateLease) boot(ctx context.Context) string {
	l.set(leaseStandby)
	if !l.drained() {
		l.tryFrom(ctx, "", true)
	}
	l.mu.Lock()
	st, h := l.state, l.rowHolder
	l.mu.Unlock()
	l.log("lease: %s at boot (row %s, this boot %s)", st, h, l.holder)
	return st
}

// leaseBoot is this boot's part of the holder id: random, kept in dir (the task queue's host tmpfs, memory and
// agentd's alone) so a restarted agentd of the same boot keeps it; "" dir: this process's own.
func leaseBoot(dir string) string {
	if dir != "" {
		if b, err := os.ReadFile(dir + "/lease-boot"); err == nil {
			if v := strings.TrimSpace(string(b)); len(v) == 16 {
				if _, err := hex.DecodeString(v); err == nil {
					return v
				}
			}
		}
	}
	r := make([]byte, 8)
	rand.Read(r)
	v := hex.EncodeToString(r)
	if dir != "" {
		if err := os.WriteFile(dir+"/lease-boot", []byte(v+"\n"), 0o600); err != nil {
			log.Printf("lease: the boot id isn't kept in the tmpfs (a restart is a new holder): %v", err)
		}
	}
	return v
}
