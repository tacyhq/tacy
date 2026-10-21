package main

import (
	"context"
	"testing"
	"time"

	"github.com/tacyhq/tacy/runauth"
	"github.com/tacyhq/tacy/trigger"
)

// A schedule whose last 7 results nobody collected stops itself at its next run (no task started) and the list says
// why; a Resume (version 2) is active again, without the reason, and its results' count starts from 0. Collecting
// (the person's delete) sets the count back to 0 through the route.
func TestScheduleStopsWhenResultsGoUncollected(t *testing.T) {
	e := newSchedEnv(t)
	d := e.daily(e.me, nil)
	if code, out := e.install(e.me, e.sign(d, e.me.Key)); code != 200 {
		t.Fatalf("install %d %v", code, out)
	}
	// Seven earlier runs' results, never collected.
	for i := range trigger.MaxUncollected {
		e.s.results.PutResult(trigger.Result{Task: randID("tk"), Space: e.me.Space, Seal: e.me.SealString(), Agent: d.Agent, Version: 1,
			Trigger: d.Triggers[0].ID, Day: time.Now().AddDate(0, 0, i-7).Format(time.DateOnly), EndedAt: time.Now(), State: "succeeded",
			Enc: []byte{1}, CT: []byte{2}})
	}
	e.s.triggerTick(context.Background())
	if n := len(e.s.tasks().Triggered()); n != 0 {
		t.Fatalf("%d runs started with 7 results uncollected", n)
	}
	list := func() map[string]any {
		_, lo := e.call(e.s.scheduleList, e.where(e.me, runauth.ListLabel))
		return lo["schedules"].([]any)[0].(map[string]any)
	}
	if s := list(); s["state"] != "stopped" || s["stop_reason"] != "uncollected" {
		t.Fatalf("list %v", s)
	}
	if e.s.triggers.Active() != 0 {
		t.Fatal("still keeps the VM on")
	}
	// Resume: the next version.
	d.Version, d.IssuedAt = 2, time.Now().Add(-5*time.Minute)
	if code, out := e.install(e.me, e.sign(d, e.me.Key)); code != 200 {
		t.Fatalf("resume %d %v", code, out)
	}
	if s := list(); s["state"] != "active" || s["stop_reason"] != nil {
		t.Fatalf("after resume %v", s)
	}
	if n, _ := e.s.results.(trigger.CollectStore).Uncollected(d.Agent); n != 0 {
		t.Fatalf("count after resume %d", n)
	}
	// A result, then the person's delete through the route: back to 0.
	task := randID("tk")
	e.s.results.PutResult(trigger.Result{Task: task, Space: e.me.Space, Seal: e.me.SealString(), Agent: d.Agent, Version: 2,
		Trigger: d.Triggers[0].ID, EndedAt: time.Now(), State: "succeeded", Enc: []byte{1}, CT: []byte{2}})
	if n, _ := e.s.results.(trigger.CollectStore).Uncollected(d.Agent); n != 1 {
		t.Fatalf("count %d", n)
	}
	if code, out := e.call(e.s.scheduleResultsDelete, tasksRequest{Where: e.where(e.me, runauth.ResultsDeleteLabel, task), Tasks: []string{task}}); code != 200 || out["deleted"] != float64(1) {
		t.Fatalf("delete %d %v", code, out)
	}
	if n, _ := e.s.results.(trigger.CollectStore).Uncollected(d.Agent); n != 0 {
		t.Fatalf("count after collecting %d", n)
	}
}
