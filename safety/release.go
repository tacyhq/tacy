package safety

import "time"

// ChatRelease is the release's ceiling and default policy for the chat agent's connectors: the given models, the
// web connector with its three tools and any public host, the providers' hosts for the keys, reads go on while
// the stop list is stale. A signed policy can only narrow it. Budgets and rates are generous ceilings today's runs
// stay well under (6-10 steps, runSeconds). The vault passes no models (it never checks them).
func ChatRelease(firm, tinfoilHost string, models []string, runSeconds int64) *Policy {
	if tinfoilHost == "" {
		tinfoilHost = "inference.tinfoil.sh"
	}
	return &Policy{Type: PolicyType, Firm: firm, Version: 1, IssuedAt: time.Date(2026, 10, 17, 0, 0, 0, 0, time.UTC),
		Models: models,
		Connectors: map[string]Connector{
			"model": {Hosts: []string{tinfoilHost}},
			"web": {Tools: []string{"web.search", "web.fetch", "web.images"}, Hosts: []string{"api.tavily.com", "api.search.brave.com"},
				Fetch: []string{"*"}},
		},
		StaleReads: true,
		Budget: Budgets{
			Run: Limits{Tokens: 8_000_000, ToolCalls: 64, WallSeconds: runSeconds, CostMicros: 20_000_000},
			Day: Limits{Tokens: 200_000_000, ToolCalls: 5_000, WallSeconds: 24 * 3600, CostMicros: 200_000_000},
		},
		Rates: Rates{Key: Rate{PerMinute: 600, Burst: 120}, Connector: Rate{PerMinute: 600, Burst: 120},
			Space: Rate{PerMinute: 900, Burst: 180}},
	}
}
