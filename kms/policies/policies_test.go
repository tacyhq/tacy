package policies

import (
	"slices"
	"strings"
	"testing"

	"github.com/tacyhq/tacy/kms"
	"github.com/tacyhq/tacy/kms/split/splitdev"
	"github.com/tacyhq/tacy/vault"
)

// The shipped grant is the agent VM's: the dev split's app and firm (resplit's -app and -firm defaults, what the
// epoch certificate names), every purpose, the release's API keys and both tunnel tokens.
func TestAgentVMV1(t *testing.T) {
	apps, err := Load(AgentVMV1)
	if err != nil {
		t.Fatal(err)
	}
	a, ok := apps[splitdev.App]
	if len(apps) != 1 || !ok || a.Firm != splitdev.Firm || a.Floor != "" {
		t.Fatalf("grants %+v", apps)
	}
	if !slices.Equal(a.Purposes, kms.Purposes) {
		t.Fatalf("purposes %v, want %v", a.Purposes, kms.Purposes)
	}
	for _, s := range append([]string{"TINFOIL_API_KEY", "EXA_API_KEY", "TAVILY_API_KEY"}, vault.TunnelSecrets...) {
		if !slices.Contains(a.Secrets, s) {
			t.Errorf("the grant lacks %s", s)
		}
	}
	if len(a.Secrets) != 5 {
		t.Errorf("secrets %v", a.Secrets)
	}
	if !slices.Equal(TunnelSecrets, vault.TunnelSecrets) {
		t.Fatalf("TunnelSecrets %v isn't vault's %v", TunnelSecrets, vault.TunnelSecrets)
	}
}

func TestLoadRefuses(t *testing.T) {
	g := func(secrets, purposes string) string {
		return `{"agent-vm": {"firm": "f_chat", "purposes": [` + purposes + `], "secrets": [` + secrets + `]}}`
	}
	all := `"state/v1", "conn/v1"`
	bad := map[string]string{
		"one tunnel token":       g(`"TINFOIL_API_KEY", "CF_TUNNEL_TOKEN_VMA"`, all),
		"the other one only":     g(`"CF_TUNNEL_TOKEN_VMB"`, all),
		"secrets without conn":   g(`"TINFOIL_API_KEY"`, `"state/v1"`),
		"a secret twice":         g(`"TINFOIL_API_KEY", "TINFOIL_API_KEY"`, all),
		"an unknown member":      `{"agent-vm": {"firm": "f_chat", "purposes": ["conn/v1"], "secret": ["X"]}}`,
		"an unknown purpose":     g(`"X"`, `"conn/v1", "keys/v9"`),
		"no firm":                `{"agent-vm": {"purposes": ["conn/v1"]}}`,
		"none":                   `{}`,
		"not an object":          `[]`,
		"trailing data":          g(`"X"`, all) + ` {}`,
		"the key service's name": `{"kms": {"firm": "f_chat", "purposes": ["conn/v1"]}}`,
	}
	for name, b := range bad {
		if _, err := Load([]byte(b)); err == nil {
			t.Errorf("%s: loaded", name)
		}
	}
	if _, err := Load([]byte(g(`"TINFOIL_API_KEY", "CF_TUNNEL_TOKEN_VMB", "CF_TUNNEL_TOKEN_VMA"`, all))); err != nil {
		t.Fatal(err)
	}
	if _, err := Load([]byte(g(`"TINFOIL_API_KEY"`, all))); err != nil || !strings.Contains(string(AgentVMV1), "CF_TUNNEL_TOKEN_VMB") {
		t.Fatal(err)
	}
}
