package safety

import (
	"testing"
	"time"
)

// Scheduled runs' cost by UTC day, all schedules together: today's and yesterday's, never another member's, and it
// survives a restart (the day counters are on disk).
func TestMembersCost(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 10, 21, 23, 30, 0, 0, time.UTC)
	l := &Ledger{Dir: dir, Now: func() time.Time { return now }}
	spend := func(task, member string, micros int64) {
		t.Helper()
		l.Begin(task, "s_space", member)
		commit, err := l.Reserve(task, Usage{CostMicros: micros}, Budgets{})
		if err != nil {
			t.Fatal(err)
		}
		commit(Usage{CostMicros: micros})
		l.End(task)
	}
	spend("t1", "schedule:ag_one", 1_000)
	spend("t2", "schedule:ag_two", 2_500)
	spend("t3", "0123456789abcdef", 99_000) // a person's run (the relay's tag): the relay charged it
	now = now.Add(time.Hour)                // past midnight UTC
	spend("t4", "schedule:ag_one", 400)
	got := l.MembersCost("schedule:")
	if len(got) != 2 || got["2026-10-21"] != 3_500 || got["2026-10-22"] != 400 {
		t.Fatalf("MembersCost: %v", got)
	}
	again := &Ledger{Dir: dir, Now: func() time.Time { return now }}
	if g := again.MembersCost("schedule:"); g["2026-10-21"] != 3_500 || g["2026-10-22"] != 400 {
		t.Fatalf("after a restart: %v", g)
	}
	// Two days on: nothing of theirs (only today and yesterday are reported).
	now = now.Add(48 * time.Hour)
	if g := l.MembersCost("schedule:"); g["2026-10-24"] != 0 || g["2026-10-23"] != 0 || len(g) != 2 {
		t.Fatalf("later: %v", g)
	}
}

// PriceRank orders the models as their prices do; an unknown model ranks as the dearest.
func TestPriceRank(t *testing.T) {
	order := []string{"gpt-oss-120b", "gemma4-31b", "deepseek-v4-1-flash", "llama3-3-70b", "glm-5-3", "kimi-k3"}
	for i := 1; i < len(order); i++ {
		if PriceRank(order[i-1]) >= PriceRank(order[i]) {
			t.Fatalf("%s not cheaper than %s", order[i-1], order[i])
		}
	}
	if PriceRank("no-such-model") < PriceRank("kimi-k3") {
		t.Fatal("an unknown model must rank as the dearest")
	}
}
