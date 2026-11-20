package vault

import (
	"errors"
	"slices"
)

// The API keys (the keys plan §3.6): nothing comes from Phala's encrypted env, and nothing from the chat Worker. vaultd asks
// the Tacy key service for its release (conn/v1 and the app's secrets from the admin-signed secrets bundle: the
// Tinfoil, Exa and Tavily keys), through gatewayd, with a fresh attestation; the reply is signed by the pinned KMS id
// and sealed to this boot's key, so only this process opens it (cmd/vaultd, kmsvm). SetSecrets takes them; they stay
// in this process's memory and are gone with it. Until they arrive, agentd answers "starting".

// SecretsResult is the vault's answer to a status op: the names it holds (never values).
type SecretsResult struct {
	Names []string `json:"names"`
}

// ErrSecretsRefused: a secret from the release isn't one a connector is granted, or is malformed.
var ErrSecretsRefused = errors.New("vault: the key service's secrets aren't ones this vault grants")

// SetSecrets takes the key service's secrets: only names granted to a connector, each replacing the value before (a
// new bundle rotates them). Nothing is taken unless all are valid.
func (v *Vault) SetSecrets(secrets map[string]string) (SecretsResult, error) {
	v.mu.Lock()
	for name, val := range secrets {
		granted := slices.ContainsFunc(v.grants, func(g Grant) bool { return g.Secret == name })
		if !validName(name) || !granted || val == "" || len(val) > 4096 || name == ConnSecret {
			v.mu.Unlock()
			v.recordSecrets("refused")
			return SecretsResult{}, ErrSecretsRefused
		}
	}
	for name, val := range secrets {
		if old, ok := v.secrets[name]; ok {
			clear(old)
		}
		v.secrets[name] = []byte(val)
	}
	v.mu.Unlock()
	v.recordSecrets("")
	return SecretsResult{Names: v.Names()}, nil
}

// SecretsStatus is the names held ("starting" until the key service's release arrived).
func (v *Vault) SecretsStatus() SecretsResult { return SecretsResult{Names: v.Names()} }

// recordSecrets writes a secrets decision (names only, never a value).
func (v *Vault) recordSecrets(reason string) {
	if v.record == nil {
		return
	}
	d := "taken"
	if reason != "" {
		d = "denied"
	}
	v.record(Record{Time: v.now().UTC(), Secret: "", Connector: "key_service", Decision: d, Reason: reason})
}
