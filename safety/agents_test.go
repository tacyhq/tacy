package safety

import "testing"

// Built-in agents: an agent's own run budget narrows the policy's (never widens it), and a small
// cost budget sizes a model call's completion instead of refusing it.

func TestNarrowRun(t *testing.T) {
	agent := Limits{Tokens: 8_000_000, ToolCalls: 60, WallSeconds: 900, CostMicros: 1_000_000}
	// The release ceiling allows more: the agent's own limits apply.
	b := Budgets{Run: Limits{Tokens: 8_000_000, ToolCalls: 64, WallSeconds: 900, CostMicros: 20_000_000}, Day: Limits{Tokens: 1}}
	if got := b.NarrowRun(agent); got.Run != agent || got.Day != b.Day {
		t.Fatalf("ceiling: %+v", got)
	}
	// A signed policy that is lower wins (f_chat's v1 policy: 300 s per run).
	p := Budgets{Run: Limits{Tokens: 8_000_000, ToolCalls: 64, WallSeconds: 300, CostMicros: 500_000}}
	if got := p.NarrowRun(agent).Run; got != (Limits{Tokens: 8_000_000, ToolCalls: 60, WallSeconds: 300, CostMicros: 500_000}) {
		t.Fatalf("policy lower: %+v", got)
	}
	// A policy without a run budget of its own leaves the agent's.
	if got := (Budgets{}).NarrowRun(agent).Run; got != agent {
		t.Fatalf("no policy budget: %+v", got)
	}
}

func TestCostLeftAndCompletionFor(t *testing.T) {
	l := &Ledger{}
	b := Budgets{Run: Limits{CostMicros: 1_000_000}, Day: Limits{CostMicros: 600_000}}
	if l.CostLeft("t", b) != 0 {
		t.Fatal("unknown run")
	}
	l.Begin("t", "s_a", "m")
	if got := l.CostLeft("t", b); got != 600_000 { // the day's is the tighter
		t.Fatalf("left %d", got)
	}
	commit, err := l.Reserve("t", Usage{CostMicros: 100_000}, b)
	if err != nil {
		t.Fatal(err)
	}
	if got := l.CostLeft("t", b); got != 500_000 { // reserved counts
		t.Fatalf("left %d", got)
	}
	commit(Usage{CostMicros: 40_000})
	if got := l.CostLeft("t", b); got != 560_000 {
		t.Fatalf("left %d", got)
	}
	if got := l.CostLeft("t", Budgets{}); got != -1 {
		t.Fatalf("no cost limit: %d", got)
	}
	// The completion a cost pays for, the prompt first; ModelCost of it stays within the cost.
	for _, c := range []struct {
		model          string
		prompt, cost   int64
		wantAtLeastOne bool
	}{{"kimi-k3", 50_000, 250_000, true}, {"gpt-oss-120b", 30_000, 10_000, true}, {"kimi-k3", 100_000, 300_000, false}, {"nope", 1000, 1_000_000, true}} {
		n := CompletionFor(c.model, c.prompt, c.cost)
		if (n > 0) != c.wantAtLeastOne || n > 0 && ModelCost(c.model, c.prompt, n) > c.cost {
			t.Errorf("%+v: completion %d costs %d", c, n, ModelCost(c.model, c.prompt, n))
		}
		if n > 0 && ModelCost(c.model, c.prompt, n+2) <= c.cost {
			t.Errorf("%+v: completion %d isn't the most", c, n)
		}
	}
}
