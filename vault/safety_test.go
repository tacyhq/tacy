package vault

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json/v2"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tacyhq/tacy/safety"
)

// The vault's own step 6 checks: it verifies pushed documents itself, and refuses leases for a stopped space,
// without a policy, to a host the policy doesn't list, past the lease rate, and for side effects while the stop
// list is stale. Records stay names and decisions only.

type vaultSafety struct {
	c               *Client
	admin, operator ed25519.PrivateKey
	mu              sync.Mutex
	recs            []Record
}

func newVaultSafety(t *testing.T) *vaultSafety {
	vs := &vaultSafety{}
	_, vs.admin, _ = ed25519.GenerateKey(rand.Reader)
	_, vs.operator, _ = ed25519.GenerateKey(rand.Reader)
	v, err := New(map[string][]byte{"TINFOIL_API_KEY": []byte(fakeTinfoil), "TAVILY_API_KEY": []byte(fakeTavily)}, ChatGrants(""),
		func(r Record) { vs.mu.Lock(); vs.recs = append(vs.recs, r); vs.mu.Unlock() })
	if err != nil {
		t.Fatal(err)
	}
	st, err := safety.NewState(safety.Config{Firm: "f_chat", Operator: vs.operator.Public().(ed25519.PublicKey),
		Admins: []ed25519.PublicKey{vs.admin.Public().(ed25519.PublicKey)}, Release: safety.ChatRelease("f_chat", "", nil, 300)})
	if err != nil {
		t.Fatal(err)
	}
	v.SetSafety(st)
	dir, _ := os.MkdirTemp("", "vs")
	t.Cleanup(func() { os.RemoveAll(dir) })
	l, err := Listen(filepath.Join(dir, "v.sock"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go v.Serve(l, -1)
	vs.c = &Client{Path: filepath.Join(dir, "v.sock")}
	return vs
}

func (vs *vaultSafety) policy(t *testing.T, version uint64, edit func(*safety.Policy)) safety.Envelope {
	p := safety.ChatRelease("f_chat", "", []string{"gpt-oss-120b"}, 300)
	p.Version, p.IssuedAt = version, time.Now().UTC()
	if edit != nil {
		edit(p)
	}
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	return safety.Sign(safety.KindPolicy, b, vs.admin)
}

func (vs *vaultSafety) stop(seq uint64, issuer string, key ed25519.PrivateKey, edit func(*safety.StopList)) safety.Envelope {
	now := time.Now().UTC()
	l := &safety.StopList{Type: safety.StopType, Issuer: issuer, Seq: seq, IssuedAt: now}
	if issuer == safety.IssuerOperator {
		l.ExpiresAt = now.Add(5 * time.Minute)
	} else {
		l.Firm = "f_chat"
	}
	if edit != nil {
		edit(l)
	}
	b, _ := json.Marshal(l)
	return safety.Sign(safety.KindStop, b, key)
}

func (vs *vaultSafety) lease(space string, effect bool) error {
	s, err := vs.c.Lease(context.Background(), Request{Secret: "TAVILY_API_KEY", Connector: "web", Host: "api.tavily.com",
		Task: "t_1", Action: "s1.a0", Space: space, Effect: effect})
	if s != nil {
		s.Wipe()
	}
	return err
}

func TestVaultSafetyLeases(t *testing.T) {
	vs := newVaultSafety(t)
	ctx := context.Background()
	if err := vs.lease("s_chat", false); !errors.Is(err, ErrPolicyMissing) {
		t.Fatalf("before any policy: %v", err)
	}
	// Forged and wrong-key documents are refused by the vault itself.
	_, stranger, _ := ed25519.GenerateKey(rand.Reader)
	b, _ := json.Marshal(safety.ChatRelease("f_chat", "", nil, 300))
	if err := vs.c.Push(ctx, []safety.Envelope{safety.Sign(safety.KindPolicy, b, stranger)}); err == nil {
		t.Fatal("forged policy accepted")
	}
	if err := vs.lease("s_chat", false); !errors.Is(err, ErrPolicyMissing) {
		t.Fatalf("after a forged policy: %v", err)
	}
	if err := vs.c.Push(ctx, []safety.Envelope{vs.policy(t, 2, nil)}); err != nil {
		t.Fatal(err)
	}
	// Stale (no operator list): a read lease goes on, a side effect's doesn't.
	if err := vs.lease("s_chat", false); err != nil {
		t.Fatalf("read while stale: %v", err)
	}
	if err := vs.lease("s_chat", true); !errors.Is(err, ErrStale) {
		t.Fatalf("side effect while stale: %v", err)
	}
	if err := vs.c.Push(ctx, []safety.Envelope{vs.stop(1, safety.IssuerOperator, vs.operator, nil)}); err != nil {
		t.Fatal(err)
	}
	if err := vs.lease("s_chat", true); err != nil {
		t.Fatalf("side effect with a fresh list: %v", err)
	}
	// Rollback refused.
	if err := vs.c.Push(ctx, []safety.Envelope{vs.policy(t, 1, nil)}); err == nil || !strings.Contains(err.Error(), "rollback") {
		t.Fatalf("v1 after v2: %v", err)
	}
	// A policy without the search host for the web connector's keys.
	if err := vs.c.Push(ctx, []safety.Envelope{vs.policy(t, 3, func(p *safety.Policy) {
		w := p.Connectors["web"]
		w.Hosts = []string{"api.search.brave.com"}
		p.Connectors["web"] = w
	})}); err != nil {
		t.Fatal(err)
	}
	if err := vs.lease("s_chat", false); !errors.Is(err, ErrPolicy) {
		t.Fatalf("host outside the policy: %v", err)
	}
	vs.c.Push(ctx, []safety.Envelope{vs.policy(t, 4, nil)})
	// The firm stops one space: its leases stop, another space's don't.
	if err := vs.c.Push(ctx, []safety.Envelope{vs.stop(1, safety.IssuerFirm, vs.admin, func(l *safety.StopList) {
		l.Stop = []safety.Target{{Firm: "f_chat", Space: "s_chat"}}
	})}); err != nil {
		t.Fatal(err)
	}
	if err := vs.lease("s_chat", false); !errors.Is(err, ErrStopped) {
		t.Fatalf("stopped space: %v", err)
	}
	if err := vs.lease("s_other", false); err != nil {
		t.Fatalf("other space: %v", err)
	}
	if err := vs.lease("S CHAT", false); !errors.Is(err, ErrBadRequest) {
		t.Fatalf("bad space id: %v", err)
	}
	vs.mu.Lock()
	defer vs.mu.Unlock()
	for _, r := range vs.recs {
		b, _ := json.Marshal(r)
		if strings.Contains(string(b), fakeTavily) || strings.Contains(string(b), "S CHAT") {
			t.Fatalf("record carries a value or hostile input: %s", b)
		}
	}
}

func TestVaultRateLimits(t *testing.T) {
	vs := newVaultSafety(t)
	ctx := context.Background()
	if err := vs.c.Push(ctx, []safety.Envelope{vs.policy(t, 1, func(p *safety.Policy) {
		p.Rates.Key = safety.Rate{PerMinute: 60, Burst: 3}
	}), vs.stop(1, safety.IssuerOperator, vs.operator, nil)}); err != nil {
		t.Fatal(err)
	}
	ok, limited := 0, 0
	var wg sync.WaitGroup
	var mu sync.Mutex
	for range 20 { // a stuck loop leasing in parallel
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := vs.lease("s_chat", false)
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				ok++
			case errors.Is(err, ErrRateLimited):
				limited++
			default:
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if ok != 3 || limited != 17 {
		t.Fatalf("ok %d, rate limited %d; want 3 and 17 (burst 3)", ok, limited)
	}
	// The key's bucket is per key: the model key still leases.
	s, err := vs.c.Lease(ctx, Request{Secret: "TINFOIL_API_KEY", Connector: "model", Host: "inference.tinfoil.sh", Task: "t_1", Action: "s1.m", Space: "s_chat"})
	if err != nil {
		t.Fatalf("another key: %v", err)
	}
	s.Wipe()
}
