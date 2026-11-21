package main

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/tacyhq/tacy/guard"
	"github.com/tacyhq/tacy/harness"
	"github.com/tacyhq/tacy/proto"
	"github.com/tacyhq/tacy/queue"
	"github.com/tacyhq/tacy/sealstate"
)

// The durable start claim with the release's side store (queue.Side, snapshotted as the sealed state is) rather than
// trigger.MemStore: the claim survives the snapshot and a fresh open, so the start sent again after the reboot is
// task_unknown_after_restart.
func TestStartClaimSurvivesSideSnapshot(t *testing.T) {
	side, err := queue.OpenSideMemory(nil)
	if err != nil {
		t.Fatal(err)
	}
	var saved []byte
	save := func(context.Context, string) error {
		b, err := side.Snapshot()
		saved = b
		return err
	}
	m := newStepModel(t, "block")
	p1 := bootTasksOn(t, harness.NewMemStore(), "qb_1", m, &fakeSearch{}, false)
	p1.s.starts, p1.s.saveState = side, save
	p1.s.host.ClaimStart = p1.s.claimStart
	req := proto.RunRequest{Permissions: guard.AllowAll(), Messages: user1("research the dstack release")}
	if tk, err := p1.conn(t, tasksUser).StartTask(context.Background(), req, "k1"); err != nil || tk.Existing {
		t.Fatalf("start: %+v %v", tk, err)
	}
	waitCalls(t, m, 1)
	p1.kill()
	side2, err := queue.OpenSideMemory(saved) // the next boot: the sealed side state back from the Worker
	if err != nil {
		t.Fatal(err)
	}
	p2 := bootTasksOn(t, harness.NewMemStore(), "qb_2", m, &fakeSearch{}, false)
	p2.s.starts, p2.s.saveState = side2, func(context.Context, string) error { return nil }
	p2.s.host.ClaimStart = p2.s.claimStart
	_, err = p2.conn(t, tasksUser).StartTask(context.Background(), req, "k1")
	if err == nil || !strings.Contains(err.Error(), "task_unknown_after_restart") {
		t.Fatalf("after the reboot: %v (want task_unknown_after_restart)", err)
	}
}

// The same through the release's sealed state: newSealedState over a backend, the claim saved by Keeper.SaveNow (as
// main.go wires saveState), the next process's newSealedState loading it back.
func TestStartClaimSurvivesSealedState(t *testing.T) {
	be := &sealstate.Mem{}
	key := bytes.Repeat([]byte{7}, 32)
	open := func() *agentState {
		st, err := sealstate.New(be, key, "app")
		if err != nil {
			t.Fatal(err)
		}
		kept, err := newSealedState(context.Background(), st)
		if err != nil {
			t.Fatal(err)
		}
		return kept
	}
	k1 := open()
	sc, ok := k1.side.(startClaimStore)
	if !ok {
		t.Fatal("the sealed side store can't record start keys")
	}
	m := newStepModel(t, "block")
	p1 := bootTasksOn(t, harness.NewMemStore(), "qb_1", m, &fakeSearch{}, false)
	p1.s.starts, p1.s.saveState = sc, k1.keeper.SaveNow
	p1.s.host.ClaimStart = p1.s.claimStart
	req := proto.RunRequest{Permissions: guard.AllowAll(), Messages: user1("research the dstack release")}
	if tk, err := p1.conn(t, tasksUser).StartTask(context.Background(), req, "k1"); err != nil || tk.Existing {
		t.Fatalf("start: %+v %v", tk, err)
	}
	waitCalls(t, m, 1)
	p1.kill()
	k2 := open()
	sc2 := k2.side.(startClaimStore)
	p2 := bootTasksOn(t, harness.NewMemStore(), "qb_2", m, &fakeSearch{}, false)
	p2.s.starts, p2.s.saveState = sc2, k2.keeper.SaveNow
	p2.s.host.ClaimStart = p2.s.claimStart
	_, err := p2.conn(t, tasksUser).StartTask(context.Background(), req, "k1")
	if err == nil || !strings.Contains(err.Error(), "task_unknown_after_restart") {
		t.Fatalf("after the restart: %v (want task_unknown_after_restart)", err)
	}
}
