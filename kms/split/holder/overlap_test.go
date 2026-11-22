package holder

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/tacyhq/tacy/internal/tdx"
	"github.com/tacyhq/tacy/kms"
	"github.com/tacyhq/tacy/kms/client"
	"github.com/tacyhq/tacy/kms/server"
	"github.com/tacyhq/tacy/kms/split"
	"github.com/tacyhq/tacy/safety"
)

// the no-downtime plan row 6: 2-of-2 to 2-of-3 without a stop. The new set goes beside the old one in the policy; holders keep a
// share of each; the VM tries the new set first and falls back to the old one until enough holders serve the new.
func TestResplitOverlap(t *testing.T) {
	r := newRig(t, twoOfTwo, 2) // set 2: cloudflare + vercel, 2-of-2
	old := r.set
	oldShares := map[string]split.HolderShare{"cloudflare": r.shares["cloudflare"], "vercel": r.shares["vercel"]}
	gk, _ := ecdh.X25519().GenerateKey(rand.Reader)
	r.keys["gcp"] = gk
	newSet, newShares, err := split.Resplit(r.master, r.kmsID, 1, 3, 2, []split.HolderRecipient{
		{Holder: "cloudflare", Recipient: PublicKeyOf(r.keys["cloudflare"])}, {Holder: "gcp", Recipient: PublicKeyOf(gk)},
		{Holder: "vercel", Recipient: PublicKeyOf(r.keys["vercel"])}}, r.now, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ns := map[string]split.HolderShare{}
	for _, s := range newShares {
		ns[s.Holder] = s
	}
	r.ids = twoOfThree
	r.pol.Seq = 6
	all := []split.HolderURL{{Holder: "cloudflare", URL: "https://cloudflare.holder.test"},
		{Holder: "gcp", URL: "https://gcp.holder.test"}, {Holder: "vercel", URL: "https://vercel.holder.test"}}
	r.pol.Holders = all
	r.pol.ShareSets = []split.SignedShareSet{*old, *newSet}
	withShares := func(h string, shares ...split.HolderShare) {
		r.shares[h] = shares[0]
		r.holders[h] = r.newHolder(h, func(c *Config) { c.Shares = shares })
	}

	// Step 1: gcp deployed with its set-3 share; cloudflare and vercel still serve only set 2. Set 3 has one holder
	// serving, so the VM falls back to set 2.
	withShares("gcp", ns["gcp"])
	m, rep, err := r.unlock(r.transports(nil), nil)
	if err != nil || rep.Set != 2 || len(rep.Tried) != 2 {
		t.Fatalf("fallback to the old set: %v %+v", err, rep)
	}
	r.mustMaster(m)

	// Step 2: cloudflare and vercel serve both sets: the new set unlocks.
	withShares("cloudflare", ns["cloudflare"], oldShares["cloudflare"])
	withShares("vercel", ns["vercel"], oldShares["vercel"])
	m, rep, err = r.unlock(r.transports(nil), nil)
	if err != nil || rep.Set != 3 || len(rep.Tried) != 1 {
		t.Fatalf("the new set: %v %+v", err, rep)
	}
	r.mustMaster(m)
	// 2-of-3 now: any one holder down still unlocks on set 3.
	if _, rep, err := r.unlock(r.transports(map[string]func(client.Transport) client.Transport{
		"cloudflare": func(client.Transport) client.Transport { return down{} }}), nil); err != nil || rep.Set != 3 {
		t.Fatalf("set 3 with cloudflare down: %v %+v", err, rep)
	}

	// Step 3: the overlap is inside the newest policy (it lists both sets). A VM that brings the older policy (set 2
	// only) is refused by holders that have seen the newer one: policies don't expire, so the seq store is what
	// withdraws them. The VM fetches the newest policy from the Worker at every unlock.
	newer := r.pol
	r.pol.Seq, r.pol.ShareSets = 5, []split.SignedShareSet{*old}
	r.pol.Holders = []split.HolderURL{all[0], all[2]}
	if _, rep, err := r.unlock(r.transports(nil), nil); err == nil || !strings.Contains(rep.Outcome["vercel"], "older than this holder's seq 6") {
		t.Fatalf("an older policy after the newer was seen: %v %+v", err, rep)
	}

	// Step 4: the old set leaves the policy (seq 7): a request for set 2 is refused even by a holder that still
	// keeps its old share.
	r.pol = newer
	r.pol.Seq, r.pol.ShareSets = 7, []split.SignedShareSet{*newSet}
	req := r.request(r.unlockConfig(nil, nil), nil)
	req.Set = 2
	wantRefused(t, r.holders["cloudflare"], req, "isn't both in the policy and served by this holder")
	if _, rep, err := r.unlock(r.transports(nil), nil); err != nil || rep.Set != 3 {
		t.Fatalf("after the old set is dropped: %v %+v", err, rep)
	}
	if st := r.holders["vercel"].Status(context.Background()); len(st.Sets) != 2 || st.Sets[0].Set != 3 {
		t.Fatalf("status: %+v", st)
	}
	// A policy may not carry three sets, nor one set twice.
	r.pol.ShareSets = []split.SignedShareSet{*old, *newSet, *newSet}
	if _, _, err := r.unlock(r.transports(nil), nil); err == nil {
		t.Fatal("three share sets")
	}
	r.pol.ShareSets = []split.SignedShareSet{*newSet, *newSet}
	if _, _, err := r.unlock(r.transports(nil), nil); err == nil || !strings.Contains(err.Error(), "listed twice") {
		t.Fatalf("one set twice: %v", err)
	}
}

// the no-downtime plan row 13: removing a release takes effect at a holder as soon as the newer policy is pushed to it (policies
// don't expire: the older one, which still pins it, is refused from then on).
func TestPushPolicyRevokes(t *testing.T) {
	r := newRig(t, twoOfTwo, 2)
	h := r.holders["vercel"]
	oldEnv := r.policyEnv()
	newer := r.pol
	newer.Seq = 6
	newer.Releases = []kms.ReleasePin{{App: vmApp, Version: "v0.19.4", AppComposeSHA256: strings.Repeat("1", 64)}}
	b, err := client.Handler{H: h.Handler()}.Do(context.Background(), http.MethodPost, "/v1/policy", r.sign(split.KindUnlockPolicy, newer))
	if err != nil || !strings.Contains(string(b), `"policy_seq":6`) {
		t.Fatalf("push: %s %v", b, err)
	}
	cfg := r.unlockConfig(nil, nil)
	cfg.Policy = oldEnv
	wantRefused(t, h, r.request(cfg, nil), "older than this holder's seq 6")
	if _, err := h.PushPolicy(context.Background(), oldEnv); err == nil {
		t.Fatal("an older policy was taken")
	}
	if _, err := h.PushPolicy(context.Background(), r.sign(split.KindUnlockPolicy, newer, r.otherKey())); err == nil {
		t.Fatal("a policy not signed by the admin was taken")
	}
	noStore := r.config("vercel")
	noStore.Store = nil
	if _, err := New(noStore); err == nil {
		t.Fatal("a holder started without a policy store")
	}
	noNonces := r.config("vercel")
	noNonces.Nonces = nil
	if _, err := New(noNonces); err == nil {
		t.Fatal("a holder started without a nonce store")
	}
}

// the no-downtime plan row 14: a TCB that isn't UpToDate is refused unless the admin's policy grants a grace, only for the
// statuses it names (never Revoked), with the QE status checked too, a minimum TCB date, and only until it ends.
func TestTCBGrace(t *testing.T) {
	r := newRig(t, twoOfTwo, 2)
	tcb := struct{ status, qe, date string }{"OutOfDate", "UpToDate", "2025-06-01T00:00:00Z"}
	stale := func(ctx context.Context, raw []byte) (*tdx.Quote, error) {
		q, err := tdx.Parse(raw)
		if err == nil {
			q.TcbStatus, q.QeStatus, q.TcbDate = tcb.status, tcb.qe, tcb.date
		}
		return q, err
	}
	for _, h := range r.ids {
		r.holders[h] = r.newHolder(h, func(c *Config) { c.Check.AllowStaleTCB, c.Check.VerifyQuote = false, stale })
	}
	_, rep, err := r.unlock(r.transports(nil), nil)
	if err == nil || !strings.Contains(rep.Outcome["cloudflare"], "TCB status OutOfDate") {
		t.Fatalf("stale TCB without grace: %v %v", err, rep.Outcome)
	}
	r.pol.TCBGrace = &safety.TCBGrace{Until: r.now.Add(7 * 24 * time.Hour), Statuses: []string{"OutOfDate"}, MinTCBDate: "2025-01-01"}
	m, rep, err := r.unlock(r.transports(nil), nil)
	if err != nil {
		t.Fatalf("stale TCB in the grace: %v %v", err, rep.Outcome)
	}
	r.mustMaster(m)
	for name, c := range map[string]struct {
		status, qe, date, want string
	}{
		"a status the grace doesn't name": {"ConfigurationNeeded", "UpToDate", "2025-06-01T00:00:00Z", "isn't allowed by the TCB grace"},
		// Refused by the verifier itself (Revoked is never allowed, grace or not), before the grace is read.
		"a revoked QE":                 {"OutOfDate", "Revoked", "2025-06-01T00:00:00Z", "QE TCB status Revoked"},
		"a revoked TCB":                {"Revoked", "UpToDate", "2025-06-01T00:00:00Z", "TCB status Revoked"},
		"a TCB older than the minimum": {"OutOfDate", "UpToDate", "2024-06-01T00:00:00Z", "older than the grace's"},
	} {
		tcb.status, tcb.qe, tcb.date = c.status, c.qe, c.date
		if _, rep, err := r.unlock(r.transports(nil), nil); err == nil || !strings.Contains(rep.Outcome["vercel"], c.want) {
			t.Fatalf("%s: %v %v", name, err, rep.Outcome)
		}
	}
	tcb.status, tcb.qe, tcb.date = "OutOfDate", "UpToDate", "2025-06-01T00:00:00Z"
	r.advance(8 * 24 * time.Hour)
	if _, rep, err := r.unlock(r.transports(nil), nil); err == nil || !strings.Contains(rep.Outcome["vercel"], "TCB status") {
		t.Fatalf("after the grace: %v %v", err, rep.Outcome)
	}
	for name, g := range map[string]*safety.TCBGrace{
		"too long":  {Until: r.pol.IssuedAt.Add(safety.MaxTCBGrace + time.Hour), Statuses: []string{"OutOfDate"}},
		"revoked":   {Until: r.now.Add(time.Hour), Statuses: []string{"Revoked"}},
		"no status": {Until: r.now.Add(time.Hour)},
	} {
		r.pol.TCBGrace = g
		if _, _, err := r.unlock(r.transports(nil), nil); err == nil || !strings.Contains(err.Error(), "tcb grace") {
			t.Fatalf("a grace %s: %v", name, err)
		}
	}
}

// Platforms are pluggable (the no-downtime plan row 9): an attestation on a platform the holder doesn't know, or "local", is
// refused; a registered one is checked by its own verifier.
func TestPlatforms(t *testing.T) {
	r := newRig(t, twoOfTwo, 2)
	withPlatform := func(p string) split.UnlockRequest {
		req := r.request(r.unlockConfig(nil, nil), nil) // the policy as it is now
		var att map[string]any
		json.Unmarshal(req.Attestation, &att)
		att["platform"] = p
		req.Attestation, _ = json.Marshal(att)
		return req
	}
	for _, p := range []string{"local", "sev-snp"} {
		wantRefused(t, r.holders["cloudflare"], withPlatform(p), "isn't one this holder checks")
	}
	called := false
	other := func(context.Context, json.RawMessage, []byte, *kms.Policy, server.CheckOptions) (*server.Attested, error) {
		called = true
		return nil, errors.New("other platform: no such release")
	}
	h := r.newHolder("cloudflare", func(c *Config) { c.Platforms = map[string]Platform{"dstack": Dstack, "other": other} })
	wantRefused(t, h, withPlatform("other"), "isn't one this holder checks under this policy") // the policy names only dstack
	r.pol.Platforms = []string{"dstack", "other"}
	wantRefused(t, h, withPlatform("other"), "other platform: no such release")
	if !called {
		t.Fatal("the registered platform wasn't asked")
	}
	r.pol.Platforms = []string{"other"} // a policy that drops dstack: a dstack VM gets nothing
	wantRefused(t, h, withPlatform("dstack"), "isn't one this holder checks under this policy")
}
