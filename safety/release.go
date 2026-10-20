package safety

import "time"

// ChatPolicyV1 is the hash of the chat VM's first signed policy (policies/chat-v1.json, signed 2026-10-18 by our
// offline admin key, live since v0.6.0). With keys v2 slice 5 that key becomes f_chat's recovery kit and
// signs no new documents; a release that moves f_chat to its key log carries this one (Config.Carry, docs/26 decision 6)
// until a key admin re-signs it.
const ChatPolicyV1 = "e6f08a761337f9a367594c3ed43a07723ac50cbf790f5b740e25442d9a8c7496"

// ChatPolicyV2 is the hash of the chat VM's second signed policy (policies/chat-v2.json: api.exa.ai and the run's
// wall_seconds 900), signed 2026-10-18 by the same offline admin key and in force since v0.8.11. A VM that took it
// keeps its version floor (2), so a release that moves f_chat to its key log carries it too: carrying v1 alone
// would leave that VM with no policy it can take (v2 not carried, v1 below the floor).
const ChatPolicyV2 = "b1cf194b7246c31a565f7c11de8416f16c377a461976dd9eb8a4e290cef1fe1a"

// ChatRelease is the release's ceiling and default policy for the built-in agents' connectors: the given models, the
// web connector with its three tools and any public host, the providers' hosts for the keys, reads go on while
// the stop list is stale. A signed policy can only narrow it. Budgets and rates are generous ceilings today's runs
// stay well under; runSeconds is the longest running time any built-in agent may use (each agent's own limits
// narrow the run budget per task: guard/agents.go). The vault passes no models (it never checks them).
func ChatRelease(firm, tinfoilHost string, models []string, runSeconds int64) *Policy {
	if tinfoilHost == "" {
		tinfoilHost = "inference.tinfoil.sh"
	}
	return &Policy{Type: PolicyType, Firm: firm, Version: 1, IssuedAt: time.Date(2026, 10, 17, 0, 0, 0, 0, time.UTC),
		Models: models,
		Connectors: map[string]Connector{
			"model": {Hosts: []string{tinfoilHost}},
			"web": {Tools: []string{"web.search", "web.fetch", "web.images"}, Hosts: []string{"api.tavily.com", "api.search.brave.com", "api.exa.ai"},
				Fetch: []string{"*"}},
		},
		StaleReads: true,
		Budget: Budgets{
			Run: Limits{Tokens: 8_000_000, ToolCalls: 64, WallSeconds: runSeconds, CostMicros: 20_000_000},
			Day: Limits{Tokens: 200_000_000, ToolCalls: 5_000, WallSeconds: 24 * 3600, CostMicros: 200_000_000},
			// Keys v2 slice 6: one member (on the shared chat VM, one person's daily tag) can use a quarter of the
			// day, and the whole VM no more than one space could before (today's cost cap, now for everyone).
			Member: Limits{Tokens: 50_000_000, ToolCalls: 1_250, WallSeconds: 6 * 3600, CostMicros: 50_000_000},
			VM:     Limits{Tokens: 200_000_000, ToolCalls: 5_000, WallSeconds: 24 * 3600, CostMicros: 200_000_000},
		},
		Rates: Rates{Key: Rate{PerMinute: 600, Burst: 120}, Connector: Rate{PerMinute: 600, Burst: 120},
			Space: Rate{PerMinute: 900, Burst: 180}},
	}
}
