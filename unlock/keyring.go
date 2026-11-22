// Package unlock is the agent VM's side of the split-key unlock (the keys plan §11.2): unlockd, the only process that
// rebuilds the root key, and what agentd and vaultd use to get their keys from it.
//
// At a real boot unlockd fetches the newest unlock policy from the chat Worker, rebuilds the root key from t of the
// policy's holders (kms/split: each holder checks the VM's quote, its nonce and the admin's policy itself), derives
// each process's purpose keys and store certificates, opens secrets.sealed (our API keys), drops the root key, and
// keeps the derived keys in a host tmpfs only it mounts (TD memory), so a container restart (dstack's watchdog,
// about hourly) serves them again without asking the holders: only a real boot unlocks. It serves them over one unix
// socket per process, each held to that process's purposes: agentd never gets conn/v1 or an API key, vaultd only
// conn/v1 and the API keys. unlockd also makes agentd's quotes (it alone has dstack's socket), under agentd's own
// report_data label (proto.VersionAgent), so nothing it makes for agentd can ask a holder for a share.
//
// Fail closed and loud: until the keys are there every socket answers a state ("starting", "holder_down",
// "refused") with a reason, retried with backoff; the state goes to the Worker in an unlock report, so people see
// "agents are starting" or "a key holder is down" rather than silence (the no-downtime plan rows 3 and 7).
package unlock

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/tacyhq/tacy/kms"
	"github.com/tacyhq/tacy/kms/split"
)

// Root is what an unlock yields: the epoch root R_e (*split.Root: never M, never the KMS id's key), from which every
// purpose key derives, with the epoch certificate's store certificates and the key of the epoch's secrets bundle.
// Derive, open the secrets, then Drop.
type Root interface {
	Key(app, firm, purpose string) ([]byte, error)
	OpenSecrets(sealed []byte) (*split.SecretsBundle, error)
	StoreCert(purpose string) (kms.StoreCert, error)
	Drop()
}

// Roles: which socket a process asks on, and so what it may have.
const (
	RoleAgent = "agentd"
	RoleVault = "vaultd"
)

// AgentPurposes are the purposes agentd may have (of what the policy grants the app); VaultPurposes vaultd's.
var (
	AgentPurposes = []string{"state/v1", "activity-sign/v1", "task-ids/v1", "notify/v1", "operator/v1", "relay-auth/v1"}
	VaultPurposes = []string{kms.SecretsPurpose}
)

// Keyring is what an unlock derived for this VM: per-purpose keys, store certificates and the app's API keys.
// It lives only in unlockd's memory and its host tmpfs.
type Keyring struct {
	KMSID     string                   `json:"kms_id"`
	Epoch     uint32                   `json:"epoch"`
	App       string                   `json:"app"`
	Firm      string                   `json:"firm"`
	Release   string                   `json:"release"`
	PolicySeq uint64                   `json:"policy_seq"`
	Set       uint32                   `json:"set"` // the share set that unlocked (0: break-glass, or a local dev root)
	Keys      map[string][]byte        `json:"keys"`
	Certs     map[string]kms.StoreCert `json:"certs,omitempty"`
	// Secrets are the app's API keys (its policy's secret names only); SecretsSeq the bundle's seq.
	Secrets    map[string]string `json:"secrets,omitempty"`
	SecretsSeq uint64            `json:"secrets_seq,omitempty"`
	// NeedsSecrets: the app has API keys that aren't in yet (secrets.sealed not fetched or opened yet).
	NeedsSecrets bool      `json:"needs_secrets,omitempty"`
	UnlockedAt   time.Time `json:"unlocked_at"`
	// Floors are the lowest generations of each sealed state, "<tag>/<name>" -> gen (tag "state" for agentd's
	// state/v1, "conn" for vaultd's conn/v1): a process refuses its sealed state below them. Nothing sets them since
	// the legacy rollback witness (its state head in the unlock reply) is removed; the freshness record will.
	Floors map[string]uint64 `json:"floors,omitempty"`
	// Boot is the kernel's boot id when it was derived: a cached keyring serves only the same boot.
	Boot string `json:"boot"`
}

// Grant is the app's grant and pin as the unlock policy gives them.
type Grant struct {
	App, Release string
	Policy       kms.AppPolicy
	PolicySeq    uint64
}

// Derive makes the keyring from an unlocked root: every purpose the app's grant has, and for each of
// kms.StorePurposes the epoch certificate's StoreCert (signed by the KMS id at the ceremony; split.Unlock checked
// it), which must name this purpose key's store-auth key. The caller drops the root after.
func Derive(root Root, kmsID string, epoch, set uint32, g Grant, now time.Time) (*Keyring, error) {
	if g.App == "" || g.Policy.Firm == "" || len(g.Policy.Purposes) == 0 {
		return nil, errors.New("unlock: the policy grants this app nothing")
	}
	k := &Keyring{KMSID: kmsID, Epoch: epoch, App: g.App, Firm: g.Policy.Firm, Release: g.Release, PolicySeq: g.PolicySeq,
		Set: set, Keys: map[string][]byte{}, UnlockedAt: now.UTC()}
	for _, p := range g.Policy.Purposes {
		if !slices.Contains(kms.Purposes, p) {
			return nil, fmt.Errorf("unlock: unknown purpose %q", p)
		}
		key, err := root.Key(g.App, g.Policy.Firm, p)
		if err != nil {
			return nil, err
		}
		k.Keys[p] = key
		if slices.Contains(kms.StorePurposes, p) {
			c, err := root.StoreCert(p)
			if err != nil {
				return nil, err
			}
			sk, err := kms.StoreAuthKey(key)
			if err != nil {
				return nil, err
			}
			pub := kms.IDString(sk.Public().(ed25519.PublicKey))
			clear(sk)
			if c.Key != pub || c.App != g.App || c.Firm != g.Policy.Firm || c.Purpose != p || c.Epoch != epoch {
				return nil, fmt.Errorf("unlock: the epoch certificate's %s store certificate isn't this key's", p)
			}
			if k.Certs == nil {
				k.Certs = map[string]kms.StoreCert{}
			}
			k.Certs[p] = c
		}
	}
	k.NeedsSecrets = len(g.Policy.Secrets) > 0 && slices.Contains(g.Policy.Purposes, kms.SecretsPurpose)
	return k, nil
}

// SetSecrets keeps the bundle's values the grant names (all of them, or an error naming the missing one).
func (k *Keyring) SetSecrets(d *split.SecretsBundle, names []string) error {
	out := map[string]string{}
	for _, n := range names {
		v, ok := d.Values[n]
		if !ok {
			return fmt.Errorf("unlock: the secrets bundle has no %s", n)
		}
		out[n] = v
	}
	k.Secrets, k.SecretsSeq, k.NeedsSecrets = out, d.Seq, false
	return nil
}

// For is what role may have: its purposes' keys and certificates, and the API keys for vaultd only.
func (k *Keyring) For(role string) (*Keys, error) {
	var allowed []string
	switch role {
	case RoleAgent:
		allowed = AgentPurposes
	case RoleVault:
		allowed = VaultPurposes
	default:
		return nil, fmt.Errorf("unlock: unknown role %q", role)
	}
	out := &Keys{KMSID: k.KMSID, Epoch: k.Epoch, App: k.App, Firm: k.Firm, Release: k.Release, Keys: map[string][]byte{},
		Certs: map[string]kms.StoreCert{}}
	for p, v := range k.Keys {
		if slices.Contains(allowed, p) {
			out.Keys[p] = slices.Clone(v)
			if c, ok := k.Certs[p]; ok {
				out.Certs[p] = c
			}
		}
	}
	tag := "state/"
	if role == RoleVault {
		tag = "conn/"
	}
	for n, g := range k.Floors {
		if name, ok := strings.CutPrefix(n, tag); ok {
			if out.Floors == nil {
				out.Floors = map[string]uint64{}
			}
			out.Floors[name] = g
		}
	}
	if role == RoleVault {
		if k.NeedsSecrets {
			return nil, errors.New("the API keys aren't in yet (secrets.sealed)")
		}
		out.Secrets = map[string]string{}
		for n, v := range k.Secrets {
			out.Secrets[n] = v
		}
	}
	return out, nil
}

// Wipe clears the keyring's key material.
func (k *Keyring) Wipe() {
	for _, v := range k.Keys {
		clear(v)
	}
	k.Keys, k.Secrets = nil, nil
}
