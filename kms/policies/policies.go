// Package policies holds the app grants an unlock policy starts from (kmsctl unlock-policy -apps), as reviewed files:
// agent-vm-v1.json is the agent VM's grant for v1 (its firm, the purposes it may ask for and the secrets bundle's
// names it gets). The release gate's staging policy takes the same grant (AgentVMV1), so a throwaway unlocks under
// what production signs.
package policies

import (
	_ "embed"
	"fmt"
	"slices"

	"github.com/tacyhq/tacy/kms"
)

// AgentVMV1 is agent-vm-v1.json.
//
//go:embed agent-vm-v1.json
var AgentVMV1 []byte

// TunnelSecrets are the tunnel tokens' names, one per slot (vault.TunnelSecrets; a release's compose names one).
var TunnelSecrets = []string{"CF_TUNNEL_TOKEN_VMA", "CF_TUNNEL_TOKEN_VMB"}

// Load reads a grants file: a JSON object of app names to grants, unknown members refused, each grant checked as a
// policy checks it. A grant naming a tunnel token names both: the sealed bundle carries both, so a release on the
// other slot needs no new secrets ceremony (a VM unlocks only if the bundle has every name its grant lists).
func Load(b []byte) (map[string]kms.AppPolicy, error) {
	var apps map[string]kms.AppPolicy
	if err := kms.Strict(b, &apps); err != nil {
		return nil, fmt.Errorf("app grants: %w", err)
	}
	if len(apps) == 0 {
		return nil, fmt.Errorf("app grants: none")
	}
	// The policy's own checks, on a policy holding only these grants.
	p := kms.Policy{Seq: 1, Epoch: 1, Floor: "v0.0.0", Apps: apps}
	if err := p.Validate(); err != nil {
		return nil, fmt.Errorf("app grants: %w", err)
	}
	for name, a := range apps {
		n := 0
		for _, s := range TunnelSecrets {
			if slices.Contains(a.Secrets, s) {
				n++
			}
		}
		if n != 0 && n != len(TunnelSecrets) {
			return nil, fmt.Errorf("app grants: %s names one tunnel token: name both %v (a release on the other slot needs its token in the same bundle)",
				name, TunnelSecrets)
		}
		if len(a.Secrets) > 0 && !slices.Contains(a.Purposes, kms.SecretsPurpose) {
			return nil, fmt.Errorf("app grants: %s has secrets but not the %s purpose that carries them", name, kms.SecretsPurpose)
		}
		if len(slices.Compact(slices.Sorted(slices.Values(a.Secrets)))) != len(a.Secrets) {
			return nil, fmt.Errorf("app grants: %s names a secret twice", name)
		}
	}
	return apps, nil
}
