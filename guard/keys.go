package guard

import (
	"context"
	"errors"
	"net/url"

	"github.com/tacyhq/tacy/harness"
	"github.com/tacyhq/tacy/vault"
)

// Lease gives a connector one secret for one request (one lease per action, no cache in the gateway): the
// vault's lease in the CVM (VaultLease), fixed keys in tests and local development (StaticKeys). connector is the
// vault's name for the connector ("model", "web") and host the exact host the value goes to. The caller wipes the
// secret when the request is done, and redacts every encoding of it from the response.
type Lease func(ctx context.Context, secret, connector, host string) (*vault.Secret, error)

type taskKey struct{}

// withTask puts the task id in ctx, for the vault's record of a lease.
func withTask(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, taskKey{}, id)
}

func taskFrom(ctx context.Context) string {
	id, _ := ctx.Value(taskKey{}).(string)
	return id
}

// VaultLease leases from the vault (vaultd, over its unix socket), for the task and request ctx carries: the
// vault records the lease with those ids (never the value).
func VaultLease(c *vault.Client) Lease {
	return func(ctx context.Context, secret, connector, host string) (*vault.Secret, error) {
		return c.Lease(ctx, vault.Request{Secret: secret, Connector: connector, Host: host,
			Task: orNone(taskFrom(ctx)), Action: orNone(harness.RequestID(ctx))})
	}
}

func orNone(id string) string {
	if id == "" {
		return "none"
	}
	return id
}

// StaticKeys leases fixed keys by name (get returns "" for one that isn't set): local development and tests only.
func StaticKeys(get func(name string) string) Lease {
	return func(_ context.Context, secret, _, _ string) (*vault.Secret, error) {
		k := get(secret)
		if k == "" {
			return nil, vault.ErrNotSet
		}
		return vault.NewSecret([]byte(k), "static"), nil
	}
}

var errSearchNotConfigured = errors.New("web search isn't configured")

// searchKey leases a search provider's key for one request: "web search isn't configured" when the vault has no
// such key (as before the vault), a short error naming no value otherwise.
func searchKey(ctx context.Context, lease Lease, secret, base string) (*vault.Secret, error) {
	if lease == nil {
		return nil, errSearchNotConfigured
	}
	s, err := lease(ctx, secret, "web", hostOf(base))
	switch {
	case errors.Is(err, vault.ErrNotSet):
		return nil, errSearchNotConfigured
	case err != nil:
		return nil, errors.New("search key unavailable")
	}
	return s, nil
}

func hostOf(base string) string {
	u, err := url.Parse(base)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

// exactRedact replaces every variant of each leased value in b (vault.Redact: raw, base64, hex, percent forms).
// Only the leased values: no credential patterns (model output isn't pattern-scanned, docs/21 section 2).
func exactRedact(b []byte, leased []*vault.Secret) []byte {
	for _, s := range leased {
		if s != nil && len(s.Bytes()) > 0 {
			b, _ = vault.Redact(b, s, "[REDACTED]")
		}
	}
	return b
}
