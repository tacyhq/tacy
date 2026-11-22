package unlock

import (
	"fmt"
	"slices"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/tacyhq/tacy/kms"
	"github.com/tacyhq/tacy/kms/policies"
)

// ownTunnel narrows a grant's secrets to this release's own tunnel token (slots review M1, 2026-11-21). The agent
// VM's grant names both slots' tokens, so one sealed bundle serves a release on either slot. A VM keeps, and gives
// vaultd, only the one its gatewayd's -tunnel-secret names in the attested app-compose (the one whose hash the policy
// pins). So no VM holds or can lease the other slot's token: a release on the new slot can't join the live tunnel,
// whatever its gatewayd asks for. A compose naming no tunnel token keeps neither. A grant with no tunnel token is
// returned as it is.
func ownTunnel(names []string, appCompose []byte) ([]string, error) {
	if !slices.ContainsFunc(names, func(n string) bool { return slices.Contains(policies.TunnelSecrets, n) }) {
		return names, nil
	}
	own, err := TunnelSecret(appCompose)
	if err != nil {
		return nil, err
	}
	return slices.DeleteFunc(slices.Clone(names), func(n string) bool {
		return slices.Contains(policies.TunnelSecrets, n) && n != own
	}), nil
}

// TunnelSecret is the vault secret name an app-compose's gatewayd leases its tunnel token by (its -tunnel-secret),
// or "" when no service names one. Two different names are an error.
func TunnelSecret(appCompose []byte) (string, error) {
	dc, err := kms.DockerCompose(appCompose)
	if err != nil {
		return "", err
	}
	var c struct {
		Services map[string]map[string]any `yaml:"services"`
	}
	if err := yaml.Unmarshal([]byte(dc), &c); err != nil {
		return "", fmt.Errorf("unlock: the attested docker compose: %v", err)
	}
	var found []string
	for _, svc := range c.Services {
		var args []string
		for _, k := range []string{"entrypoint", "command"} {
			switch v := svc[k].(type) {
			case string:
				args = append(args, strings.Fields(v)...)
			case []any:
				for _, e := range v {
					args = append(args, fmt.Sprint(e))
				}
			}
		}
		for i, a := range args {
			name, val, eq := strings.Cut(strings.TrimLeft(a, "-"), "=")
			if !strings.HasPrefix(a, "-") || name != "tunnel-secret" {
				continue
			}
			if !eq {
				if i+1 >= len(args) {
					return "", fmt.Errorf("unlock: the attested compose's -tunnel-secret has no value")
				}
				val = args[i+1]
			}
			if !slices.Contains(found, val) {
				found = append(found, val)
			}
		}
	}
	switch len(found) {
	case 0:
		return "", nil
	case 1:
		return found[0], nil
	}
	slices.Sort(found)
	return "", fmt.Errorf("unlock: the attested compose names %d tunnel tokens (%s)", len(found), strings.Join(found, ", "))
}
