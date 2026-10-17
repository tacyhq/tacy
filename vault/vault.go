// Package vault is a spike of the vault as its own process (docs/21-gateway-v0.md): it holds
// the credentials in memory and releases one only to the gateway, for one action, to a host that secret may be
// sent to. The brain and the runtime never talk to it; nothing in it reaches the network.
//
// The gateway asks over a unix socket (Client.Lease); the vault checks the grant (which connector may use the
// secret, and the hosts it may go to: send_only_to), records the decision without the value, and
// answers with the value and a lease id. The gateway uses the value for that one request and drops it. Values
// never appear in records, errors or logs, and Secret prints as "[secret]".
//
// Not imported by ./app, so it isn't part of the attested compose (cmd/compose).
package vault

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/tacyhq/tacy/safety"
)

// Grant says which connector may lease a secret and the hosts the value may be sent to (exact names, lowercase;
// no wildcards in v0). Grants come with the release (each connector's own secrets) and later from the firm's
// signed policy: a secret without a grant is never released.
type Grant struct {
	Secret     string
	Connector  string
	SendOnlyTo []string
}

// Request is the gateway's ask: one secret, for one connector, to one host, for one action of one task. Task and
// action are the harness/v1 ids (docs/20), so the record ties the lease to the journaled action.
type Request struct {
	// Op is "" for a lease, or "names": which granted secrets are set (names only, no values; the gateway picks its
	// search provider by it). A names request needs no other field.
	Op        string `json:"op,omitzero"`
	Secret    string `json:"secret,omitzero"`
	Connector string `json:"connector,omitzero"`
	Host      string `json:"host,omitzero"`
	Task      string `json:"task,omitzero"`
	Action    string `json:"action,omitzero"`
	// Space is the task's space: its stop, policy and rate apply (step 6). Effect: the lease is for an operation
	// that changes something outside (refused while the stop list is stale).
	Space  string `json:"space,omitzero"`
	Effect bool   `json:"effect,omitzero"`
	// Docs (op "safety"): signed policies and stop lists, checked here before they count.
	Docs []safety.Envelope `json:"docs,omitzero"`
}

// Record is what the vault writes for every request: names and ids, never the value. Later these go to the
// recorder (signed, chained, sealed to the firm); here a callback gets them.
type Record struct {
	Time      time.Time `json:"time"`
	Secret    string    `json:"secret"`
	Connector string    `json:"connector"`
	Host      string    `json:"host"`
	Task      string    `json:"task"`
	Action    string    `json:"action"`
	Space     string    `json:"space,omitzero"`
	Decision  string    `json:"decision"` // "released" or "denied"
	Reason    string    `json:"reason,omitzero"`
	Lease     string    `json:"lease,omitzero"`
}

// Errors the gateway sees. They name the rule, never the value.
var (
	ErrNoGrant    = errors.New("vault: no grant for this secret and connector")
	ErrHost       = errors.New("vault: host not in the secret's send_only_to")
	ErrNotSet     = errors.New("vault: secret not set")
	ErrBadRequest = errors.New("vault: bad request")
	// Step 6 (safety controls).
	ErrStopped       = errors.New("vault: stopped by a stop list")
	ErrStale         = errors.New("vault: the stop list isn't fresh")
	ErrPolicyMissing = errors.New("vault: no signed policy for this space")
	ErrPolicy        = errors.New("vault: the policy doesn't allow this connector or host")
	ErrRateLimited   = errors.New("vault: lease rate exceeded")
)

// known are the errors that cross the wire by their text.
var known = []error{ErrNoGrant, ErrHost, ErrNotSet, ErrBadRequest, ErrStopped, ErrStale, ErrPolicyMissing, ErrPolicy, ErrRateLimited}

// Vault holds the secrets and grants. Safe for concurrent use.
type Vault struct {
	mu      sync.Mutex
	secrets map[string][]byte
	grants  []Grant
	record  func(Record)
	now     func() time.Time
	safety  *safety.State // nil: no step 6 checks
	rates   safety.Limiter
}

// SetSafety turns on the step 6 checks: every lease is refused while its space is stopped, without a policy
// (when admin keys are pinned), to a connector or host the policy doesn't list, past the rate per key, connector
// and space, and, while the stop list is stale, when it's for a side effect (or any, if the policy says so).
func (v *Vault) SetSafety(st *safety.State) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.safety = st
}

// Safety is the vault's verified controls (nil: none).
func (v *Vault) Safety() *safety.State {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.safety
}

// New makes a vault. secrets are copied; the caller should wipe its own copies. record may be nil.
func New(secrets map[string][]byte, grants []Grant, record func(Record)) (*Vault, error) {
	v := &Vault{secrets: map[string][]byte{}, record: record, now: time.Now}
	for _, g := range grants {
		if !validName(g.Secret) || !validConnector(g.Connector) || len(g.SendOnlyTo) == 0 {
			return nil, fmt.Errorf("vault: invalid grant for %q", g.Secret)
		}
		for _, h := range g.SendOnlyTo {
			if !validHost(h) {
				return nil, fmt.Errorf("vault: invalid host %q in the grant for %s", h, g.Secret)
			}
		}
		v.grants = append(v.grants, Grant{g.Secret, g.Connector, slices.Clone(g.SendOnlyTo)})
	}
	for name, val := range secrets {
		if !validName(name) {
			return nil, fmt.Errorf("vault: invalid secret name %q", name)
		}
		if len(val) > 0 {
			v.secrets[name] = slices.Clone(val)
		}
	}
	return v, nil
}

// Lease checks r against the grants and returns a copy of the value and a fresh lease id. Every call is recorded.
func (v *Vault) Lease(r Request) ([]byte, string, error) {
	rec := Record{Time: v.now().UTC(), Secret: r.Secret, Connector: r.Connector, Host: r.Host, Task: r.Task,
		Action: r.Action, Space: r.Space, Decision: "denied"}
	val, lease, err := v.lease(r)
	if err == nil {
		rec.Decision, rec.Lease = "released", lease
	} else {
		rec.Reason = err.Error()
	}
	if !validName(rec.Secret) { // a hostile or broken caller's input stays out of the record
		rec.Secret = ""
	}
	if r.Space != "" && !safety.ValidID(r.Space) {
		rec.Space = ""
	}
	if v.record != nil {
		v.record(rec)
	}
	return val, lease, err
}

func (v *Vault) lease(r Request) ([]byte, string, error) {
	if !validName(r.Secret) || !validConnector(r.Connector) || !validHost(r.Host) || !validID(r.Task) || !validID(r.Action) ||
		r.Space != "" && !safety.ValidID(r.Space) || len(r.Docs) > 0 {
		return nil, "", ErrBadRequest
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	granted := false
	for _, g := range v.grants {
		if g.Secret != r.Secret || g.Connector != r.Connector {
			continue
		}
		granted = true
		if slices.Contains(g.SendOnlyTo, r.Host) {
			val, ok := v.secrets[r.Secret]
			if !ok {
				return nil, "", ErrNotSet
			}
			if err := v.checkSafety(r); err != nil {
				return nil, "", err
			}
			return slices.Clone(val), newLease(), nil
		}
	}
	if granted {
		return nil, "", ErrHost
	}
	return nil, "", ErrNoGrant
}

// checkSafety applies the step 6 controls to a granted lease (v.mu held).
func (v *Vault) checkSafety(r Request) error {
	if v.safety == nil {
		return nil
	}
	e, err := v.safety.Check(r.Space, r.Effect)
	switch safety.CodeOf(err) {
	case "":
	case safety.CodeStopped:
		return ErrStopped
	case safety.CodeStale:
		return ErrStale
	default:
		return ErrPolicyMissing
	}
	if !e.AllowsConnector(r.Connector) || !e.AllowsLeaseHost(r.Connector, r.Host) {
		return ErrPolicy
	}
	rt := e.Rates()
	if v.rates.Now == nil {
		v.rates.Now = v.now
	}
	if v.rates.Allow([]string{"key:" + r.Secret, "connector:" + r.Connector, "space:" + r.Space},
		[]safety.Rate{rt.Key, rt.Connector, rt.Space}) != "" {
		return ErrRateLimited
	}
	return nil
}

// Names returns the names of the secrets that are set and have a grant, sorted. Never values.
func (v *Vault) Names() []string {
	v.mu.Lock()
	defer v.mu.Unlock()
	var out []string
	for _, g := range v.grants {
		if _, ok := v.secrets[g.Secret]; ok && !slices.Contains(out, g.Secret) {
			out = append(out, g.Secret)
		}
	}
	slices.Sort(out)
	return out
}

// Drop forgets a secret (the kill switch's "revoke"): later leases fail with ErrNotSet.
func (v *Vault) Drop(name string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if val, ok := v.secrets[name]; ok {
		clear(val)
		delete(v.secrets, name)
	}
}

func newLease() string {
	b := make([]byte, 12)
	rand.Read(b)
	return "l_" + hex.EncodeToString(b)
}

// validName: secret names as environment variables have them, A-Z 0-9 _, up to 64.
func validName(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for _, c := range s {
		if !(c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_') {
			return false
		}
	}
	return true
}

// validConnector: the connector part of an action name (web, mail, model), a-z 0-9, up to 32.
func validConnector(s string) bool {
	if s == "" || len(s) > 32 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9') {
			return false
		}
	}
	return true
}

// validHost: a lowercase DNS name with at least one dot, no port, no trailing dot.
func validHost(s string) bool {
	if len(s) < 3 || len(s) > 253 || !strings.Contains(s, ".") || strings.HasPrefix(s, ".") || strings.HasSuffix(s, ".") ||
		strings.Contains(s, "..") {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '.') {
			return false
		}
	}
	return true
}

// validID: harness/v1 ids, 1-64 of [A-Za-z0-9._:-], starting with a letter or digit.
func validID(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for i, c := range s {
		alnum := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
		if !alnum && (i == 0 || !strings.ContainsRune("._:-", c)) {
			return false
		}
	}
	return true
}

// ChatGrants are the release's grants for the chat agent's connectors (guard/: the model gateway and the web
// connector): each secret to its connector and its provider's host only. tinfoilHost is the model router
// (TINFOIL_ENCLAVE, default inference.tinfoil.sh).
func ChatGrants(tinfoilHost string) []Grant {
	if tinfoilHost == "" {
		tinfoilHost = "inference.tinfoil.sh"
	}
	return []Grant{
		{Secret: "TINFOIL_API_KEY", Connector: "model", SendOnlyTo: []string{tinfoilHost}},
		{Secret: "TAVILY_API_KEY", Connector: "web", SendOnlyTo: []string{"api.tavily.com"}},
		{Secret: "BRAVE_SEARCH_API_KEY", Connector: "web", SendOnlyTo: []string{"api.search.brave.com"}},
	}
}

// FromEnv takes the granted secrets out of the environment (dstack's encrypted env vars, which only the vault's
// container is given) and unsets them, so a child process or a later os.Environ can't see them.
func FromEnv(grants []Grant) map[string][]byte {
	out := map[string][]byte{}
	for _, g := range grants {
		if v, ok := os.LookupEnv(g.Secret); ok {
			if v != "" {
				out[g.Secret] = []byte(v)
			}
			os.Unsetenv(g.Secret)
		}
	}
	return out
}
