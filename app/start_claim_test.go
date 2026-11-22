package main

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/tacyhq/tacy/guard"
	"github.com/tacyhq/tacy/harness"
	"github.com/tacyhq/tacy/proto"
	"github.com/tacyhq/tacy/trigger"
)

// claimOn wires p's start claims to side (the sealed side state, which outlives a reboot) and save (Keeper.SaveNow),
// as main.go does.
func claimOn(p *taskProc, side *trigger.MemStore, save func(context.Context, string) error) {
	p.s.starts, p.s.saveState = side, save
	p.s.host.ClaimStart = p.s.claimStart
}

// Review 2, M2: a start sent again after an unknown outcome when the VM has lost its queue (a real reboot, or
// agentd's restart with the queue in memory, as in the KMS fallback). The first start's key was recorded, and saved,
// before its task ran; the second start with that key finds the record, answers task_unknown_after_restart and runs
// nothing (no task, no model call). A claim that can't be saved starts nothing and leaves the key unused.
func TestStartResentAfterLostQueueNeverRunsTwice(t *testing.T) {
	side := trigger.NewMemStore() // the sealed side state: saved at the Worker, back after the reboot
	saves := 0
	save := func(context.Context, string) error { saves++; return nil }
	m := newStepModel(t, "block")
	p1 := bootTasksOn(t, harness.NewMemStore(), "qb_1", m, &fakeSearch{}, false)
	claimOn(p1, side, save)
	req := proto.RunRequest{Permissions: guard.AllowAll(), Messages: user1("research the dstack release")}
	tk, err := p1.conn(t, tasksUser).StartTask(context.Background(), req, "k1")
	if err != nil || tk.Existing {
		t.Fatalf("start: %+v %v", tk, err)
	}
	if saves != 1 {
		t.Fatalf("the start's claim was saved %d times before its task ran, want 1", saves)
	}
	waitCalls(t, m, 1) // the task runs; the VM reboots; the Worker answered outcome_unknown
	p1.kill()

	// The new boot: the queue is gone (memory), the side state is back.
	p2 := bootTasksOn(t, harness.NewMemStore(), "qb_2", m, &fakeSearch{}, false)
	claimOn(p2, side, save)
	_, err = p2.conn(t, tasksUser).StartTask(context.Background(), req, "k1")
	if err == nil || !strings.Contains(err.Error(), "409") || !strings.Contains(err.Error(), `"error":"task_unknown_after_restart"`) {
		t.Fatalf("the same start after the reboot: %v (want 409 task_unknown_after_restart: never a second run)", err)
	}
	time.Sleep(200 * time.Millisecond)
	if open, _ := p2.s.rt.Store.OpenTasks(); len(open) != 0 || m.calls.Load() != 1 {
		t.Fatalf("after the resent start: %d tasks, %d model calls (want 0 and 1)", len(open), m.calls.Load())
	}

	// The claim can't be saved (the Worker unreachable): nothing starts, the key stays unused.
	p2.s.saveState = func(context.Context, string) error { return errors.New("the Worker is unreachable") }
	if _, err := p2.conn(t, tasksUser).StartTask(context.Background(), req, "k2"); err == nil || !strings.Contains(err.Error(), "start_not_recorded") {
		t.Fatalf("a start whose claim can't be saved: %v", err)
	}
	if open, _ := p2.s.rt.Store.OpenTasks(); len(open) != 0 {
		t.Fatalf("a start whose claim wasn't saved made %d tasks", len(open))
	}
	p2.s.saveState = save
	tk2, err := p2.conn(t, tasksUser).StartTask(context.Background(), req, "k2")
	if err != nil || tk2.Existing {
		t.Fatalf("the same start once saving works: %+v %v", tk2, err)
	}
	// And sent again while its task is in the queue: the task, as before (existing), no second claim.
	again, err := p2.conn(t, tasksUser).StartTask(context.Background(), req, "k2")
	if err != nil || !again.Existing || again.Task != tk2.Task {
		t.Fatalf("the same key while its task is there: %+v %v", again, err)
	}
}
