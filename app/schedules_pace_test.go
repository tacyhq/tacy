package main

import (
	"context"
	"strings"
	"testing"

	"github.com/tacyhq/tacy/guard"
	"github.com/tacyhq/tacy/harness"
	"github.com/tacyhq/tacy/safety"
	"github.com/tacyhq/tacy/trigger"
)

// A scheduled digest's parallel first searches (2026-11-23: a Pro user's digest said its searches ran out after the
// first batch). Each search reserves its reader at its largest (about $0.15 of the run's $0.40) and settles at what it
// used, so with the answer's reserve kept only two fit in flight at once. The others wait for one of them to settle
// instead of being told the budget is used up: all four go out and the run answers, with no budget refusal.
func TestScheduledParallelSearchesWait(t *testing.T) {
	e := newSchedEnv(t,
		pCalls([3]string{"c1", "web_search", `{"query":"world news"}`}, [3]string{"c2", "web_search", `{"query":"business news"}`},
			[3]string{"c3", "web_search", `{"query":"politics news"}`}, [3]string{"c4", "web_search", `{"query":"tech news"}`}),
		pText("The digest [1]."))
	d := e.daily(e.me, func(d *trigger.Definition) {
		d.Instructions = "Morning news digest: the most important news of the last day."
		d.Tools = []string{"web.fetch", "web.search"}
		d.Allow = map[string]string{"web.fetch": safety.PermAlways, "web.search": safety.PermAlways}
	})
	if t1, c1, _ := guard.ReaderReserveFor(guard.AgentScheduled, nil, "web.search", nil); t1 == 0 ||
		3*(c1+safety.SearchCost)+guard.FinalReserve(guard.AgentScheduled) <= guard.RunBudget(guard.AgentScheduled).CostMicros {
		t.Fatalf("the test needs three searches in flight to pass the keep: reserve %d", c1)
	}
	if code, out := e.install(e.me, e.sign(d, e.me.Key)); code != 200 {
		t.Fatalf("install %d %v", code, out)
	}
	e.s.triggerTick(context.Background())
	var task string
	for id := range e.s.tasks().Triggered() {
		task = id
	}
	r := e.waitResult(task)
	if r.State != harness.OutcomeSucceeded {
		t.Fatalf("result %+v", r)
	}
	if len(e.fs.queries) != 4 {
		t.Fatalf("%d searches went out (%v), want all 4", len(e.fs.queries), e.fs.queries)
	}
	evs, _ := e.s.rt.Store.Events(task, 0, 10_000)
	for _, se := range evs {
		if strings.Contains(string(se.Data), "the rest is kept for the answer") {
			t.Fatalf("a search was refused for the budget: %s", se.Data)
		}
	}
}
