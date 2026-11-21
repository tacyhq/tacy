package main

import (
	"context"
	"crypto/hkdf"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/tacyhq/tacy/activity"
	"github.com/tacyhq/tacy/approval"
	"github.com/tacyhq/tacy/harness"
	"github.com/tacyhq/tacy/queue"
	"github.com/tacyhq/tacy/runauth"
	"github.com/tacyhq/tacy/safety"
	"github.com/tacyhq/tacy/sealstate"
	"github.com/tacyhq/tacy/trigger"
)

// agentState is everything agentd keeps, all of it in this process's memory (the keys plan §3.1): the CVM's disk is under
// Phala's disk key, so nothing is written to it ("Keys: never a provider's"; internal/nowrite_test.go and
// plaintext_disk_test.go check it).
//
// Memory only (newAgentState, the quick path): a restart loses it. Running tasks end, activity starts a new chain,
// approvals waiting for a person are gone, spaces' seal keys are pinned again on first use, budgets' day counters
// start over (the relay charges each run anyway); schedules are off.
//
// Sealed (newSealedState, the keys plan Stage C): the same stores in memory, and what must outlive a restart saved as
// sealed snapshots (sealstate, under the key service's state/v1 key, stored outside the VM): the side store
// (schedules: definitions, memory, holders, results, fired slots, seen deliveries, the clock, pins), the activity
// chains, the safety floors and documents, the budgets' day counters and the notification switches. The approvals
// stay memory only (an effect waiting for approval is never kept).
//
// The task queue (V1-DESIGN §6.2): in this process's memory, or with -tasks-dir in the host tmpfs made for agentd
// alone (useTasksQueue, queue.OpenTmpfs): TD memory, so open tasks survive the hourly container restart and end with
// a real boot.
type agentState struct {
	queue harness.Store
	// queueBoot names the queue (guard.Host.Boot): new with each memory queue, kept with a tmpfs one.
	queueBoot string
	activity  activity.Store
	side      sideStore
	ledger    *safety.Ledger
	notify    *notifier
	// safety is the signed controls' persistence (nil: memory only).
	safety safety.Persister
	// keeper saves the sealed snapshots (nil: memory only); schedules: the side store is kept, so schedules run.
	keeper    *sealstate.Keeper
	schedules bool
}

// sideStore is what the side store holds: approvals, triggers' definitions and their marks, personal spaces'
// holders, scheduled runs' results and memory, pinned seal keys.
type sideStore interface {
	approval.Store
	trigger.Store
	trigger.HolderStore
	trigger.ResultStore
	trigger.MemoryStore
	trigger.CollectStore
	runauth.PinStore
}

func newAgentState() *agentState {
	n, _ := openNotifier(nil) // memory: never fails
	return &agentState{
		queue:     harness.NewMemStore(),
		queueBoot: queue.NewBoot(),
		activity:  activity.NewMemStore(),
		side: memSide{approval.NewMemStore(), trigger.NewMemStore(), &trigger.MemHolders{}, &trigger.MemResults{}, &trigger.MemMemory{},
			&runauth.MemPins{}},
		ledger: &safety.Ledger{},
		notify: n,
	}
}

// The sealed states' names (sealstate, at the relay).
const (
	stateSide     = "side"
	stateActivity = "activity"
	stateSafety   = "safety"
	stateBudget   = "budget"
	stateNotify   = "notify"
)

// sealedSide is the side store in memory, kept as a snapshot, with its approvals in memory only (an effect waiting
// for a person's approval is never kept: the keys plan §3.1).
type sealedSide struct {
	*queue.Side
	ap *approval.MemStore
}

func (s sealedSide) PutApproval(r approval.Record) (approval.Record, bool, error) {
	return s.ap.PutApproval(r)
}
func (s sealedSide) Approval(id string) (*approval.Record, error) { return s.ap.Approval(id) }
func (s sealedSide) MoveApproval(id, from, to string, d []byte) error {
	return s.ap.MoveApproval(id, from, to, d)
}
func (s sealedSide) Approvals(states ...string) ([]approval.Record, error) {
	return s.ap.Approvals(states...)
}
func (s sealedSide) DeleteApprovals(task string) error { return s.ap.DeleteApprovals(task) }

// newSealedState loads every sealed state from st and returns the stores, with a Keeper that saves them (run it, and
// flush it on SIGTERM). A state that is there and doesn't open (another key or lease, tampered, rolled back) is an
// error: agentd doesn't start over someone's schedules silently.
func newSealedState(ctx context.Context, st *sealstate.Store) (*agentState, error) {
	load := func(name string) ([]byte, error) {
		b, err := st.Load(ctx, name)
		if err != nil {
			return nil, fmt.Errorf("state %s: %w", name, err)
		}
		return b, nil
	}
	k := &sealstate.Keeper{Store: st}
	kept := &agentState{queue: harness.NewMemStore(), queueBoot: queue.NewBoot(), keeper: k, schedules: true}

	b, err := load(stateSide)
	if err != nil {
		return nil, err
	}
	side, err := queue.OpenSideMemory(b)
	clear(b)
	if err != nil {
		return nil, fmt.Errorf("state %s: %w", stateSide, err)
	}
	kept.side = sealedSide{Side: side, ap: approval.NewMemStore()}
	k.Add(stateSide, side)

	b, err = load(stateActivity)
	if err != nil {
		return nil, err
	}
	act := activity.NewMemStore()
	if len(b) > 0 {
		if act, err = activity.LoadMemStore(b); err != nil {
			return nil, err
		}
	}
	clear(b)
	kept.activity = act
	k.Add(stateActivity, act)

	for _, x := range []struct {
		name string
		set  func(*sealstate.Slot) error
	}{
		{stateSafety, func(s *sealstate.Slot) error { kept.safety = s; return nil }},
		{stateBudget, func(s *sealstate.Slot) error { kept.ledger = &safety.Ledger{Persist: s}; return nil }},
		{stateNotify, func(s *sealstate.Slot) (err error) { kept.notify, err = openNotifier(s); return err }},
	} {
		b, err := load(x.name)
		if err != nil {
			return nil, err
		}
		slot := sealstate.NewSlot(b)
		clear(b)
		if err := x.set(slot); err != nil {
			return nil, fmt.Errorf("state %s: %w", x.name, err)
		}
		k.Add(x.name, slot)
	}
	return kept, nil
}

// useTasksQueue puts the task queue in the host tmpfs t names (-tasks-dir; queue.OpenTmpfs refuses a directory that
// isn't memory or isn't agentd's alone). Call it before the runtime restores the queue.
func (k *agentState) useTasksQueue(t queue.Tmpfs) error {
	q, boot, err := queue.OpenTmpfs(t)
	if err != nil {
		return err
	}
	k.queue, k.queueBoot = q, boot
	return nil
}

// booted is what agentd's keys and state are after boot (bootState).
type booted struct {
	kept   *agentState
	signer *activity.Signer
	rec    *activity.Recorder
	idKey  []byte // once-only task ids' key, per firm
}

// bootState makes agentd's state and keys: sealed state on backend under keys' state key when both are lasting
// (the key service), memory otherwise; the activity signer and the task-id key from keys. Nothing here comes from
// the platform: a CVM with other provider keys (a fresh disk, a new app id) gets the same state back.
func bootState(ctx context.Context, keys KeySource, backend sealstate.Backend, reg sealstate.Register, firm string) (*booted, error) {
	kept := newAgentState()
	if backend != nil {
		if !keys.Lasting() {
			return nil, errors.New("sealed state needs lasting keys (the Tacy key service): boot keys could never open it again")
		}
		sk, err := keys.Key(ctx, PurposeState)
		if err != nil {
			return nil, fmt.Errorf("state key: %w", err)
		}
		st, err := sealstate.New(backend, sk, keys.Binding())
		clear(sk)
		if err != nil {
			return nil, err
		}
		if reg != nil { // the key service's generation register: no older blob opens, every save is committed
			st.WithRegister(reg)
		}
		if f, ok := keys.(interface{ floors() map[string]uint64 }); ok { // the rollback witness's head (unlockd)
			for name, gen := range f.floors() {
				st.Floor(name, gen)
			}
		}
		if kept, err = newSealedState(ctx, st); err != nil {
			return nil, err
		}
	}
	ikm, err := keys.Key(ctx, PurposeActivity)
	if err != nil {
		return nil, fmt.Errorf("activity signing key: %w", err)
	}
	signer, err := activity.DeriveSigner(ikm, firm)
	clear(ikm)
	if err != nil {
		return nil, err
	}
	rec := &activity.Recorder{Signer: signer, Store: kept.activity}
	tk, err := keys.Key(ctx, PurposeTaskIDs)
	if err != nil {
		return nil, fmt.Errorf("task id key: %w", err)
	}
	idKey, err := hkdf.Key(sha256.New, tk, nil, "tacy/task-ids/v1\x00"+firm, 32)
	clear(tk)
	if err != nil {
		return nil, err
	}
	return &booted{kept: kept, signer: signer, rec: rec, idKey: idKey}, nil
}
