package gateway

import (
	"context"
	"encoding/json"
	"testing"
)

type recordDoer struct{ calls int }

func (r *recordDoer) Fixed(context.Context, *FixedCall) *FixedAnswer {
	r.calls++
	return &FixedAnswer{Status: 200}
}

// M5 (security review 2026-11-20): the key service can't tell agentd from vaultd, so gatewayd holds each socket to
// its own process's purposes and lease holder: agentd never gets conn/v1 (and so never the API keys), vaultd never
// state/v1.
func TestKMSGatePerSocketPurposes(t *testing.T) {
	ctx := context.Background()
	release := func(holder string, purposes ...string) *FixedCall {
		b, _ := json.Marshal(map[string]any{"holder": holder, "purposes": purposes, "nonce": "n"})
		return &FixedCall{Target: TargetKMS, Method: "POST", Path: "/v1/release", Body: b}
	}
	commit := func(holder string) *FixedCall {
		b, _ := json.Marshal(map[string]any{"holder": holder, "name": "state/side"})
		return &FixedCall{Target: TargetKMS, Method: "POST", Path: "/v1/gen/commit", Body: b}
	}
	d := &recordDoer{}
	agent := KMSGate{D: d, Holder: "agentd", Purposes: AgentKMSPurposes}
	vault := KMSGate{D: d, Holder: "vaultd", Purposes: VaultKMSPurposes}
	for name, c := range map[string]struct {
		g    KMSGate
		call *FixedCall
		ok   bool
	}{
		"agentd's own release":          {agent, release("agentd", "state/v1", "activity-sign/v1", "task-ids/v1"), true},
		"agentd asks for conn/v1":       {agent, release("agentd", "state/v1", "conn/v1"), false},
		"agentd as vaultd":              {agent, release("vaultd", "conn/v1"), false},
		"vaultd's own release":          {vault, release("vaultd", "conn/v1"), true},
		"vaultd asks for state/v1":      {vault, release("vaultd", "state/v1"), false},
		"vaultd as agentd":              {vault, release("agentd", "state/v1"), false},
		"no purposes":                   {vault, release("vaultd"), false},
		"not JSON":                      {agent, &FixedCall{Target: TargetKMS, Method: "POST", Path: "/v1/release", Body: []byte("x")}, false},
		"agentd commits as agentd":      {agent, commit("agentd"), true},
		"vaultd commits as agentd":      {vault, commit("agentd"), false},
		"status passes":                 {vault, &FixedCall{Target: TargetKMS, Method: "GET", Path: "/v1/status"}, true},
		"the state target is untouched": {agent, &FixedCall{Target: TargetState, Method: "GET", Path: "/api/vm/state/side"}, true},
	} {
		before := d.calls
		a := c.g.Fixed(ctx, c.call)
		if passed := d.calls > before; passed != c.ok || (!c.ok && a.Error != "bad_call") {
			t.Errorf("%s: passed %v (%+v)", name, passed, a)
		}
	}
}
