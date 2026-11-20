package main

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/tacyhq/tacy/harness"
	"github.com/tacyhq/tacy/runauth"
	"github.com/tacyhq/tacy/trigger"
)

// sealedSchedEnv is a schedules server on boot b's sealed state (agentd -kms-key -state relay): the side store, its
// holders, results, memory and marks, the task-id key, as main wires them.
func sealedSchedEnv(t *testing.T, b *booted, me *runauth.Asker, replies ...string) *schedEnv {
	t.Helper()
	e := &schedEnv{safeEnv: newSafeEnvWith(t, safeOpts{}, replies...), me: me}
	e.mustPost(e.policy(1, nil), e.heartbeat())
	s := e.s
	side := b.kept.side
	dir := &trigger.HolderDirectory{Firm: "f_chat", Store: side}
	s.dir, s.holders, s.results, s.memory = dir, side, side, side
	s.triggers = trigger.New(trigger.Config{Firm: "f_chat", Dir: dir, Store: side, IDKey: b.idKey, Trusted: s.safety.OperatorTime,
		Collect: side})
	if _, err := s.triggers.Load(); err != nil {
		t.Fatal(err)
	}
	s.tasks().TriggeredDone = s.triggeredDone
	s.tasks().Allows = s.policyAllows
	return e
}

// A schedule end to end across boots, locally, on the production code paths: the real key service, the Worker's
// sealed-state API and gatewayd's fixed calls (kmsWorld). Boot 1 installs a daily schedule and stops (its last
// save, the lease dropped). Boot 2, another instance on a fresh host, finds the definition in the sealed state, fires
// it at the tick, and seals its result to the person's key; it stops. Boot 3 finds the result (the person opens it)
// and the day's fired mark (no second run). The Worker held only sealed blobs throughout.
func TestScheduleInstallFireResultAcrossBoots(t *testing.T) {
	ctx := context.Background()
	w := newKMSWorld(t)
	me, err := runauth.NewAsker()
	if err != nil {
		t.Fatal(err)
	}
	stop := func(b *booted, k interface{ Drop(context.Context) error }) {
		t.Helper()
		if err := b.kept.keeper.Flush(ctx); err != nil {
			t.Fatal(err)
		}
		if err := k.Drop(ctx); err != nil {
			t.Fatal(err)
		}
	}

	// ---- boot 1: install ----
	b1, k1 := w.bootAgent(t, "inst-1")
	e1 := sealedSchedEnv(t, b1, me)
	d := e1.daily(me, nil)
	if code, out := e1.install(me, e1.sign(d, me.Key)); code != 200 {
		t.Fatalf("install %d %v", code, out)
	}
	stop(b1, k1)
	side := w.state.Blobs()["agent-vm/state/"+stateSide]
	if len(side) == 0 || bytes.Contains(side, []byte("news.ycombinator.com")) || bytes.Contains(side, []byte(me.Space)) {
		t.Fatal("the side state isn't at the Worker, or isn't sealed")
	}

	// ---- boot 2: another instance finds the schedule and fires it ----
	b2, k2 := w.bootAgent(t, "inst-2")
	e2 := sealedSchedEnv(t, b2, me, pText("Today's digest: the sealed state came back across the boot."))
	e2.s.triggerTick(ctx)
	tasks := e2.s.tasks().Triggered()
	if len(tasks) != 1 {
		t.Fatalf("%d tasks after boot 2's tick", len(tasks))
	}
	var task string
	for id := range tasks {
		task = id
	}
	r := e2.waitResult(task)
	if r.State != harness.OutcomeSucceeded || r.Agent != d.Agent {
		t.Fatalf("result %+v", r)
	}
	stop(b2, k2)

	// ---- boot 3: the result and the fired mark are there ----
	b3, k3 := w.bootAgent(t, "inst-3")
	e3 := sealedSchedEnv(t, b3, me)
	code, body := e3.openResult(me, task)
	if code != 200 || body == nil {
		t.Fatalf("result after boot 3: %d", code)
	}
	text := ""
	for _, ev := range body.Events {
		if ev.Type == "text" {
			text += ev.Delta
		}
	}
	if !strings.Contains(text, "came back across the boot") {
		t.Fatalf("result text %q", text)
	}
	e3.s.triggerTick(ctx)
	if n := len(e3.s.tasks().Triggered()); n != 0 {
		t.Fatalf("the schedule fired again on boot 3 (%d tasks): its mark wasn't kept", n)
	}
	stop(b3, k3)
	for k, blob := range w.state.Blobs() {
		if bytes.Contains(blob, []byte("came back across the boot")) || bytes.Contains(blob, []byte(me.Space)) {
			t.Errorf("%s holds plaintext", k)
		}
	}
}
