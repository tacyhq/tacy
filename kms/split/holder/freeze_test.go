package holder

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/tacyhq/tacy/kms/client"
	"github.com/tacyhq/tacy/kms/split"
	"github.com/tacyhq/tacy/safety"
)

// Triage #11a: the release item is the whole pin, so the same compose relabelled with a newer version (to pass a
// floor) is a new item and waits 24 h.
func TestRelabelledPinWaits(t *testing.T) {
	r := agedRig(t)
	r.pol.Seq, r.pol.Floor = 6, "v0.20.0" // the release in use is now below the floor
	r.pol.Releases[0].Version = "v99.0.0" // the same app-compose, relabelled
	r.push(t)
	cfg := r.unlockConfig(r.transports(nil), nil)
	cfg.Release = "v99.0.0"
	if _, rep, err := split.Unlock(context.Background(), cfg); err == nil || !strings.Contains(rep.Outcome["vercel"], "release v99.0.0 was first allowed here at") {
		t.Fatalf("a relabelled pin: %v %v", err, rep.Outcome)
	}
}

// Triage #11b: a change to a field with no item of its own (here dropping start-ticket keys, which loosens) waits
// 24 h through the catch-all item.
func TestCatchAllWaits(t *testing.T) {
	r := agedRig(t)
	wpub, _, _ := ed25519.GenerateKey(rand.Reader)
	r.pol.Seq, r.pol.Witnesses = 6, nil
	r.pol.NextAdminKeys = []string{safety.KeyString(wpub)} // any uncovered field
	r.push(t)
	r.wantOutcome(t, "a change to the policy's other fields")
	r.advance(24*time.Hour + time.Minute)
	if _, rep, err := r.unlock(r.transports(nil), nil); err != nil {
		t.Fatalf("24 h later: %v %v", err, rep.Outcome)
	}
}

// Triage #2: the store's Apply refuses a stale seq itself (no instance may serve under a withdrawn policy), a jump,
// and two documents with one seq.
func TestApplyRefusesStale(t *testing.T) {
	st := &MemoryStore{}
	st.Init("g", 0)
	ctx, now := context.Background(), time.Now()
	if _, _, err := st.Apply(ctx, "g", 2, "h2", []string{"a"}, now); err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]struct {
		seq  uint64
		hash string
		want error
	}{
		"stale":       {1, "h1", ErrStale},
		"jump":        {2 + 1001, "hx", ErrJump},
		"equivocated": {2, "other", ErrEquivocation},
	} {
		_, _, err := st.Apply(ctx, "g", c.seq, c.hash, nil, now)
		var sr *SeqRefusal
		if !errors.Is(err, c.want) || !errors.As(err, &sr) || sr.Top != 2 {
			t.Fatalf("%s: %v", name, err)
		}
	}
	if _, _, err := st.Apply(ctx, "nope", 1, "h", nil, now); !errors.Is(err, ErrUninitialized) {
		t.Fatalf("uninitialized: %v", err)
	}
}

// Triage #4: a reply is bound to the policy the holder served it under: a request whose policy was swapped on the
// way (another valid, newer policy) gives a reply the VM can't open.
func TestReplyBoundToPolicy(t *testing.T) {
	r := newRig(t, twoOfTwo, 2)
	other := r.pol
	other.Seq = 6
	swapped := r.sign(split.KindUnlockPolicy, other)
	swap := func(next client.Transport) client.Transport { return policySwap{next: next, policy: swapped} }
	_, rep, err := r.unlock(r.transports(map[string]func(client.Transport) client.Transport{"vercel": swap}), nil)
	if err == nil || !strings.Contains(rep.Outcome["vercel"], "under another policy") {
		t.Fatalf("a swapped policy: %v %v", err, rep.Outcome)
	}
}

type policySwap struct {
	next   client.Transport
	policy json.RawMessage
}

func (p policySwap) Do(ctx context.Context, method, path string, body []byte) ([]byte, error) {
	if path == "/v1/unlock" {
		var req split.UnlockRequest
		json.Unmarshal(body, &req)
		req.Policy = p.policy
		body, _ = json.Marshal(req)
	}
	return p.next.Do(ctx, method, path, body)
}

// Triage #13c: the ticket claim is keyed on the signed payload: the same ticket with its envelope's JSON re-encoded
// is still the first VM's.
func TestTicketClaimOnPayload(t *testing.T) {
	r := newRig(t, twoOfTwo, 2)
	wpub, wkey, _ := ed25519.GenerateKey(rand.Reader)
	r.pol.StartTicketKeys = []string{safety.KeyString(wpub)}
	b, _ := json.Marshal(split.StartTicket{KMSID: r.kmsID, AppID: r.vmAppID(t), IssuedAt: r.now})
	env := safety.Sign(split.KindStartTicket, b, wkey)
	raw, _ := json.Marshal(env)
	cfg := r.unlockConfig(r.transports(nil), nil)
	cfg.StartTicket = raw
	if _, rep, err := split.Unlock(context.Background(), cfg); err != nil {
		t.Fatalf("first VM: %v %v", err, rep.Outcome)
	}
	var m map[string]any // the same envelope, its keys in another order and indented
	json.Unmarshal(raw, &m)
	re, _ := json.MarshalIndent(m, "", "  ")
	if bytes.Equal(re, raw) {
		t.Fatal("the re-encoding should differ")
	}
	q := editEvents(t, r.recQuote, map[string]string{"compose-hash": r.vmACHash(t), "instance-id": strings.Repeat("cd", 20)})
	other := r.unlockConfig(r.transports(nil), &evidence{quote: q, info: r.vm.info})
	other.StartTicket = re
	if _, rep, err := split.Unlock(context.Background(), other); err == nil || !strings.Contains(rep.Outcome["vercel"], "by another VM") {
		t.Fatalf("a re-encoded ticket at another VM: %v %v", err, rep.Outcome)
	}
}

// Triage #11d: break-glass serves only the policy it was started with, not a newer one.
func TestBreakGlassOnlyItsPolicy(t *testing.T) {
	g := newGlassRig(t)
	req := g.breakGlassRequest()
	newer := g.pol
	newer.Seq = 6
	req.Policy = g.sign(split.KindUnlockPolicy, newer)
	wantRefused(t, g.bg, req, "only the policy it was started with")
}

// Triage #20a, #20b: a grace with min_tcb_eval is refused at validation; an unlock with no usable share set fails
// with ErrNotEnough, never a nil root without an error.
func TestValidationFootguns(t *testing.T) {
	r := newRig(t, twoOfTwo, 2)
	r.pol.TCBGrace = &safety.TCBGrace{Until: r.now.Add(time.Hour), Statuses: []string{"OutOfDate"}, MinTCBEval: 17}
	if _, _, err := r.unlock(r.transports(nil), nil); err == nil || !strings.Contains(err.Error(), "min_tcb_eval") {
		t.Fatalf("min_tcb_eval: %v", err)
	}
	r.pol.TCBGrace = nil
	r.pol.Epoch = 2 // the policy's epoch passes MinEpoch 2, but its only set is of epoch 1
	cert2, _ := r.epochCert(2)
	r.pol.EpochCerts = append(r.pol.EpochCerts, *cert2)
	cfg := r.unlockConfig(r.transports(nil), nil)
	cfg.MinEpoch = 2
	root, _, err := split.Unlock(context.Background(), cfg)
	if root != nil || !errors.Is(err, split.ErrNotEnough) {
		t.Fatalf("no usable set: %v %v", root, err)
	}
}
