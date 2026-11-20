package main

import (
	"github.com/tacyhq/tacy/activity"
	"github.com/tacyhq/tacy/approval"
	"github.com/tacyhq/tacy/harness"
	"github.com/tacyhq/tacy/runauth"
	"github.com/tacyhq/tacy/safety"
	"github.com/tacyhq/tacy/trigger"
)

// agentState is everything agentd keeps, all of it in this process's memory (the keys plan §3.1): the CVM's disk is under
// Phala's disk key, so nothing is written to it ("Keys: never a provider's"; internal/nowrite_test.go and
// plaintext_disk_test.go check it). A restart loses it: running tasks end, activity starts a new chain, approvals
// waiting for a person are gone, spaces' seal keys are pinned again on first use, budgets' day counters start over
// (the relay charges each run anyway). Lasting state comes back as sealed snapshots under the Tacy key service
// (the keys plan §3.2, Stage C).
type agentState struct {
	queue    harness.Store
	activity activity.Store
	side     memSide
	ledger   *safety.Ledger
	notify   *notifier
}

func newAgentState() *agentState {
	n, _ := openNotifier("") // memory: never fails
	return &agentState{
		queue:    harness.NewMemStore(),
		activity: activity.NewMemStore(),
		side: memSide{approval.NewMemStore(), trigger.NewMemStore(), &trigger.MemHolders{}, &trigger.MemResults{}, &trigger.MemMemory{},
			&runauth.MemPins{}},
		ledger: &safety.Ledger{},
		notify: n,
	}
}
