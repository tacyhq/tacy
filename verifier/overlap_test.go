package verifier

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/tacyhq/tacy/internal/tdx"
	"github.com/tacyhq/tacy/proto"
	"github.com/tacyhq/tacy/safety"
)

// The Fix B switch-over (overlap.go, the no-downtime plan row 27) on real quotes.
//
// testdata/attest-r0200.json is a real /attest response from a VM running v0.20.0 on dstack-0.6.5 (a fresh throwaway
// CVM on Phala prod5 made with the release's exact app-compose, as the live CVM is, 2026-11-20; the chat's release
// tests use the same recording), with Intel's answers recorded at the time (intel-collateral-r0200.json, in this
// package's format). testdata/attest-r0200-inplace.json is the same signed compose under
// another app-compose.json (Phala's in-place update of an older CVM: deployer env names, the "kms" and "tproxy-net"
// features), recorded the same day.

var r0200Now = time.Date(2026, 11, 20, 3, 3, 41, 0, time.UTC)

type r0200Rec struct {
	a        *proto.Attestation
	nonce    []byte
	attested []byte // its app-compose.json
	compose  string // the docker compose in it
	vq       func(context.Context, []byte) (*tdx.Quote, error)
}

func loadR0200(t *testing.T, name string, at time.Time) r0200Rec {
	t.Helper()
	raw, err := os.ReadFile("../testdata/attest-" + name + ".json")
	if err != nil {
		t.Fatal(err)
	}
	var a proto.Attestation
	if err := json.Unmarshal(raw, &a); err != nil {
		t.Fatal(err)
	}
	nonce, _ := hex.DecodeString(a.Nonce)
	var info struct {
		TcbInfo string `json:"tcb_info"`
	}
	json.Unmarshal(a.Info, &info)
	var tcb struct {
		AppCompose string `json:"app_compose"`
	}
	json.Unmarshal([]byte(info.TcbInfo), &tcb)
	cb, err := os.ReadFile("../testdata/intel-collateral-" + name + ".json")
	if err != nil {
		t.Fatal(err)
	}
	var c collateral20261121
	if err := json.Unmarshal(cb, &c); err != nil {
		t.Fatal(err)
	}
	vq := func(ctx context.Context, b []byte) (*tdx.Quote, error) {
		return tdx.VerifyWith(ctx, b, tdx.Options{Getter: c, Now: at})
	}
	return r0200Rec{a: &a, nonce: nonce, attested: []byte(tcb.AppCompose), compose: attestedCompose(t, &a), vq: vq}
}

// fixbPolicy is what a Fix B client build checks a VM against in the exact mode: the KMS fallback off. No trust
// list is in force, so the overlap release is refused (TestOverlapNeedsTrustList); listed adds one.
func (r r0200Rec) fixbPolicy() Policy {
	return Policy{VerifyQuote: r.vq, Compose: []byte(r.compose), AppCompose: r.attested}
}

// listed is p with a signed trust list in force (one that adds nothing and doesn't end the overlap), as a client that
// took the Worker's list has: the overlap applies only then (route2 review H1). at is when it is applied.
func listed(t *testing.T, p Policy, at time.Time) Policy {
	t.Helper()
	s := &TrustState{}
	l := safety.TrustList{Seq: 1, IssuedAt: r0200Now.Add(-48 * time.Hour)}
	if info := s.Take(signedList(t, testAdmin(t), l), 0, at); !info.OK {
		t.Fatalf("take: %s", info.Error)
	}
	q, info := s.Apply(p, at)
	if info == nil || !info.OK || q.trust == nil {
		t.Fatalf("apply: %+v", info)
	}
	return q
}

// The recorded v0.20.0 quote and compose pass a Fix B build (KMS fallback off): the whole Intel chain with the
// recorded collateral (UpToDate), prod5's machine certificate, the 0.6.5 boot set, the pinned KMS root, nothing on the
// disk, exactly the release's app-compose and compose, the images by digest. Before the overlap the same policy
// refused it at the key check ("allowed only in the explicit KMS fallback").
func TestOverlapV020Passes(t *testing.T) {
	r := loadR0200(t, "r0200", r0200Now)
	o := KMSOverlapReleases[0]
	if sha256Hex(r.attested) != o.AppComposeSHA256 || sha256Hex([]byte(r.compose)) != o.ComposeSHA256 || o.Version != "v0.20.0" {
		t.Fatalf("the recording isn't the pinned v0.20.0: app-compose %s, compose %s", sha256Hex(r.attested), sha256Hex([]byte(r.compose)))
	}
	res, err := Verify(context.Background(), r.a, r.nonce, listed(t, r.fixbPolicy(), r0200Now))
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range res.Checks {
		if !c.OK {
			t.Fatalf("check %q failed", c.Name)
		}
	}
	if res.HPKEPublicKey == nil || res.Facts["key mode"] != KeyProviderKMS || res.Facts["KMS root"] != "Phala KMS, root since 2026-11-06" ||
		!strings.HasPrefix(res.Facts[KMSOverlapFact], "v0.20.0 ") || !strings.HasPrefix(res.Facts["TCB"], "UpToDate") ||
		res.Facts["OS image"] != "dstack-0.6.5" || res.Facts["app-compose sha256"] != o.AppComposeSHA256 {
		t.Fatalf("facts %v", res.Facts)
	}
	if m := res.Facts[FactMachine]; !strings.Contains(m, "phala prod5") {
		t.Fatalf("machine %q", m)
	}
	var keys Check
	for _, c := range res.Checks {
		if c.Name == KMSCheck {
			keys = c
		}
	}
	if !strings.Contains(keys.Detail, "v0.20.0 by its exact pins") {
		t.Fatalf("key check detail %q", keys.Detail)
	}

	// Without the overlap entry the same build refuses it at the key check, as vm-v1 did before.
	saved := KMSOverlapReleases
	KMSOverlapReleases = nil
	defer func() { KMSOverlapReleases = saved }()
	if _, err := Verify(context.Background(), r.a, r.nonce, listed(t, r.fixbPolicy(), r0200Now)); err == nil || !strings.HasPrefix(err.Error(), KMSCheck+": ") ||
		!strings.Contains(err.Error(), "allowed only in the explicit KMS fallback") {
		t.Fatalf("no overlap: %v", err)
	}
}

// The v1 Fix B release still passes on the genuine none-mode quotes (as TestRecorded065NoneRelease), with no overlap
// fact: the overlap adds nothing to the Fix B path.
func TestOverlapFixBReleaseUnchanged(t *testing.T) {
	compose := composeYAML(t)
	release, err := ReleaseAppCompose(compose, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	pin, o, err := ReleaseModeAppCompose(string(compose), false, time.Now())
	if err != nil || o != nil || string(pin) != string(release) {
		t.Fatalf("release mode's pin for compose.yaml: overlap %v, err %v, same %v", o, err, string(pin) == string(release))
	}
	for _, name := range noneRecordings {
		a, nonce, _, _ := loadNone(t, name)
		setAppComposeRaw(t, a, release)
		rtmr3 := recompose(t, a, release)
		rd := agentLabel(t, a, nonce, true)
		p := Policy{AllowStaleTCB: true, Compose: compose, AppCompose: release, VerifyQuote: changeQuote(func(q *tdx.Quote) { q.Rtmrs[3], q.ReportData = rtmr3, rd })}
		res, err := Verify(context.Background(), a, nonce, p)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if res.Facts["key mode"] != KeyProviderNone || res.Facts[KMSOverlapFact] != "" {
			t.Fatalf("%s: facts %v", name, res.Facts)
		}
	}
}

// Release mode's pin (tacyhq/tacy verifier.go calls ReleaseModeAppCompose): the overlap release's exact compose gets
// exactly the app-compose.json its CVM attested, the Fix B compose its none-mode one, anything else without unlockd
// nothing; a KMS-fallback build is as before.
func TestOverlapReleaseModePin(t *testing.T) {
	r := loadR0200(t, "r0200", r0200Now)
	pin, o, err := ReleaseModeAppCompose(r.compose, false, r0200Now)
	if err != nil || o == nil || o.Version != "v0.20.0" || string(pin) != string(r.attested) {
		t.Fatalf("v0.20.0: overlap %v, err %v, attested bytes %v", o, err, string(pin) == string(r.attested))
	}
	if err := o.CheckVersion("v0.20.0"); err != nil {
		t.Fatal(err)
	}
	if err := o.CheckVersion("v0.21.0"); err == nil {
		t.Fatal("another signed release for the overlap compose passed")
	}
	// One byte more in the compose: another release, without unlockd, so no pin at all.
	if _, o, err := ReleaseModeAppCompose(r.compose+"\n", false, r0200Now); !errors.Is(err, ErrNoUnlockdOutsideOverlap) || o != nil {
		t.Fatalf("edited v0.20.0 compose: %v", err)
	}
	// After the removal date: refused.
	if _, _, err := ReleaseModeAppCompose(r.compose, false, KMSOverlapUntil); err == nil || !strings.Contains(err.Error(), "accepted only until 2027-01-15") {
		t.Fatalf("after the date: %v", err)
	}
	// A KMS-fallback build: ReleaseAppCompose in the KMS mode, as before; no overlap.
	want, _ := ReleaseAppCompose([]byte(r.compose), nil, true)
	if pin, o, err := ReleaseModeAppCompose(r.compose, true, r0200Now); err != nil || o != nil || string(pin) != string(want) {
		t.Fatalf("fallback build: %v %v", o, err)
	}
	// compose.yaml in a KMS-fallback build: whatever ReleaseAppCompose says (today: refused, its task queue's mount
	// isn't memory), the same answer.
	compose := composeYAML(t)
	want, wantErr := ReleaseAppCompose(compose, []byte(MemoryRootScript), true)
	if pin, o, err := ReleaseModeAppCompose(string(compose), true, r0200Now); o != nil || string(pin) != string(want) || (err == nil) != (wantErr == nil) {
		t.Fatalf("fallback build, compose.yaml: %v %v", o, err)
	}
}

// Mixes are refused: each key mode only with its own release's exact pins.
func TestOverlapMixesRefused(t *testing.T) {
	compose := composeYAML(t)
	fixb, err := ReleaseAppCompose(compose, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	// The Fix B compose in the KMS mode (what a KMS-fallback build of it would deploy; its own rules aside).
	fixbKMS, err := appComposeJSON(compose, []byte(MemoryRootScript), true, AppComposeName)
	if err != nil {
		t.Fatal(err)
	}
	v020 := loadR0200(t, "r0200", r0200Now)
	// v0.20.0's compose with the Fix B key settings (none, no gateway), as appComposeJSON writes it.
	v020None, err := appComposeJSON([]byte(v020.compose), nil, false, AppComposeName)
	if err != nil {
		t.Fatal(err)
	}

	type run func(t *testing.T) (*proto.Attestation, []byte, Policy)
	cases := []struct {
		name, check, want string
		run               run
	}{
		{"the KMS quote of v0.20.0 against the Fix B pins", KMSCheck, `key provider "kms", want none`, func(t *testing.T) (*proto.Attestation, []byte, Policy) {
			r := loadR0200(t, "r0200", r0200Now)
			return r.a, r.nonce, Policy{VerifyQuote: r.vq, Compose: compose, AppCompose: fixb}
		}},
		{"the Fix B compose in the KMS mode (its own exact app-compose)", KMSCheck, "allowed only in the explicit KMS fallback", func(t *testing.T) (*proto.Attestation, []byte, Policy) {
			r := loadR0200(t, "r0200", r0200Now)
			setAppComposeRaw(t, r.a, fixbKMS)
			rt := recompose(t, r.a, fixbKMS)
			rd := agentLabel(t, r.a, r.nonce, true)
			return r.a, r.nonce, Policy{VerifyQuote: changeQuote(func(q *tdx.Quote) { q.Rtmrs[3], q.ReportData = rt, rd }), AllowStaleTCB: true,
				Compose: compose, AppCompose: fixbKMS}
		}},
		{"v0.20.0's exact app-compose on a VM whose keys were made in it", KMSCheck, `key provider "none", want a dstack KMS`, func(t *testing.T) (*proto.Attestation, []byte, Policy) {
			a, nonce, _, _ := loadNone(t, noneRecordings[0])
			setAppComposeRaw(t, a, v020.attested)
			rt := recompose(t, a, v020.attested)
			return a, nonce, Policy{VerifyQuote: changeQuote(func(q *tdx.Quote) { q.Rtmrs[3] = rt }), AllowStaleTCB: true,
				Compose: []byte(v020.compose), AppCompose: v020.attested}
		}},
		{"v0.20.0's compose with the Fix B key settings", AppComposeFlagsCheck, "ulimits core 0", func(t *testing.T) (*proto.Attestation, []byte, Policy) {
			a, nonce, _, _ := loadNone(t, noneRecordings[0])
			setAppComposeRaw(t, a, v020None)
			rt := recompose(t, a, v020None)
			return a, nonce, Policy{VerifyQuote: changeQuote(func(q *tdx.Quote) { q.Rtmrs[3] = rt }), AllowStaleTCB: true,
				Compose: []byte(v020.compose), AppCompose: v020None}
		}},
		{"v0.20.0's signed compose under another KMS app-compose (in place, its own pin)", KMSCheck, "allowed only in the explicit KMS fallback", func(t *testing.T) (*proto.Attestation, []byte, Policy) {
			r := loadR0200(t, "r0200-inplace", time.Date(2026, 11, 20, 3, 1, 51, 0, time.UTC))
			return r.a, r.nonce, r.fixbPolicy()
		}},
		{"v0.20.0's signed compose under another KMS app-compose (in place, v0.20.0's pin)", AppComposeCheck, "deployer may set env", func(t *testing.T) (*proto.Attestation, []byte, Policy) {
			r := loadR0200(t, "r0200-inplace", time.Date(2026, 11, 20, 3, 1, 51, 0, time.UTC))
			p := r.fixbPolicy()
			p.AppCompose = v020.attested
			return r.a, r.nonce, p
		}},
		{"v0.20.0 at a key-releasing verifier (kmsd, a holder)", KMSCheck, "allowed only in the explicit KMS fallback", func(t *testing.T) (*proto.Attestation, []byte, Policy) {
			r := loadR0200(t, "r0200", r0200Now)
			p := r.fixbPolicy()
			p.KeyRelease = true
			return r.a, r.nonce, p
		}},
		{"v0.20.0 at a holder", KMSCheck, "allowed only in the explicit KMS fallback", func(t *testing.T) (*proto.Attestation, []byte, Policy) {
			r := loadR0200(t, "r0200", r0200Now)
			p := r.fixbPolicy()
			p.KeyRelease, p.RequireUnlockd = true, true
			return r.a, r.nonce, p
		}},
		{"v0.20.0 pinned by hash (a signed policy without kms_fallback)", KMSCheck, "allowed only in the explicit KMS fallback", func(t *testing.T) (*proto.Attestation, []byte, Policy) {
			r := loadR0200(t, "r0200", r0200Now)
			p := r.fixbPolicy()
			p.AppCompose, p.AppComposeSHA256 = nil, []string{KMSOverlapReleases[0].AppComposeSHA256}
			return r.a, r.nonce, p
		}},
		{"v0.20.0 from a KMS root that isn't pinned", KMSCheck, "isn't a pinned one", func(t *testing.T) (*proto.Attestation, []byte, Policy) {
			r := loadR0200(t, "r0200", r0200Now)
			p := r.fixbPolicy()
			p.KMSRoots = map[string]string{"3059" + strings.Repeat("00", 89): "another root"}
			return r.a, r.nonce, p
		}},
		{"v0.20.0 on the removal date", KMSCheck, "accepted only until 2027-01-15", func(t *testing.T) (*proto.Attestation, []byte, Policy) {
			r := loadR0200(t, "r0200", r0200Now) // Intel's answers checked at their own time; the date at the removal
			p := r.fixbPolicy()
			p.Now = KMSOverlapUntil
			return r.a, r.nonce, p
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a, nonce, p := c.run(t)
			// With a trust list in force (the overlap's precondition), so each refusal is the mix's own.
			at := r0200Now
			if !p.Now.IsZero() {
				at = p.Now
			}
			p = listed(t, p, at)
			res, err := Verify(context.Background(), a, nonce, p)
			if err == nil || !strings.HasPrefix(err.Error(), c.check) || !strings.Contains(err.Error(), c.want) || res.HPKEPublicKey != nil {
				t.Fatalf("want %s (%s): %v", c.check, c.want, err)
			}
		})
	}
}

// An overlap entry can't take the Fix B shape into the KMS mode: an entry naming a compose with unlockd (here the
// Fix B compose's own KMS form) is refused at the key check, though its hashes match exactly.
func TestOverlapEntryWithUnlockdRefused(t *testing.T) {
	compose := composeYAML(t)
	fixbKMS, err := appComposeJSON(compose, nil, true, AppComposeName)
	if err != nil {
		t.Fatal(err)
	}
	saved := KMSOverlapReleases
	KMSOverlapReleases = []KMSOverlapRelease{{Version: "v9.9.9", ComposeSHA256: sha256Hex(compose), AppComposeSHA256: sha256Hex(fixbKMS)}}
	defer func() { KMSOverlapReleases = saved }()
	r := loadR0200(t, "r0200", r0200Now)
	setAppComposeRaw(t, r.a, fixbKMS)
	rt := recompose(t, r.a, fixbKMS)
	rd := agentLabel(t, r.a, r.nonce, true)
	p := Policy{VerifyQuote: changeQuote(func(q *tdx.Quote) { q.Rtmrs[3], q.ReportData = rt, rd }), AllowStaleTCB: true, Compose: compose, AppCompose: fixbKMS}
	if _, err := Verify(context.Background(), r.a, r.nonce, p); err == nil || !strings.HasPrefix(err.Error(), KMSCheck+": ") || !strings.Contains(err.Error(), "has unlockd") {
		t.Fatalf("an overlap entry with unlockd: %v", err)
	}
	if _, _, err := ReleaseModeAppCompose(string(compose), false, r0200Now); err == nil || !strings.Contains(err.Error(), "v9.9.9") {
		t.Fatalf("release mode, an entry with unlockd: %v", err)
	}
}

// The signed end of the overlap (safety/overlapend.go; routing re-review M1): a Fix B build that verified a
// trust list with "overlap_ended": true refuses v0.20.0 at once (no 24 h delay), before KMSOverlapUntil, and for
// good: a later list without the member, the same record given to a fresh verifier, or an older list replayed, never
// bring the overlap back, and a list can't sign it back on.
func TestOverlapEndedBySignedList(t *testing.T) {
	admin := testAdmin(t)
	r := loadR0200(t, "r0200", r0200Now)
	list := func(seq uint64, ended bool) []byte {
		l := safety.TrustList{Seq: seq, IssuedAt: r0200Now.Add(-time.Hour)}
		if ended {
			l.SetOverlapEnded()
		}
		return signedList(t, admin, l)
	}
	verify := func(s *TrustState) (*Result, error) {
		p, info := s.Apply(r.fixbPolicy(), r0200Now)
		if info != nil && !info.OK {
			t.Fatalf("list not applied: %s", info.Error)
		}
		return Verify(context.Background(), r.a, r.nonce, p)
	}
	refused := func(what string, res *Result, err error) {
		t.Helper()
		if err == nil || !strings.HasPrefix(err.Error(), KMSCheck+": ") || !strings.Contains(err.Error(), "a signed trust list ended the overlap") || res.HPKEPublicKey != nil {
			t.Fatalf("%s: want v0.20.0 refused at the key check (overlap ended): %v", what, err)
		}
	}

	// A list without the member: v0.20.0 still passes (the overlap is open until its date).
	s := &TrustState{}
	if info := s.Take(list(1, false), 0, r0200Now); !info.OK || info.OverlapEnded {
		t.Fatalf("take 1: %+v", info)
	}
	if res, err := verify(s); err != nil || res.Facts[KMSOverlapFact] == "" {
		t.Fatalf("v0.20.0 before the end: %v", err)
	}

	// The list that ends it: refused at once, at the same instant it was first seen (an ending isn't delayed).
	info := s.TakeSeen(list(2, true), 1, r0200Now, nil)
	if !info.OK || !info.OverlapEnded || len(info.Pending) != 0 {
		t.Fatalf("take 2: %+v", info)
	}
	res, err := verify(s)
	refused("the list that ends it", res, err)
	seen := []byte(info.Seen)

	// A later list without it, with the record kept: still ended.
	info3 := s.TakeSeen(list(3, false), 2, r0200Now.Add(time.Minute), seen)
	if !info3.OK || !info3.OverlapEnded {
		t.Fatalf("take 3: %+v", info3)
	}
	res, err = verify(s)
	refused("a later list without the member", res, err)

	// A fresh verifier (an app restart) with the device's record, given the later list or the older one: ended.
	for _, env := range [][]byte{list(3, false), list(1, false)} {
		f := &TrustState{}
		if i := f.TakeSeen(env, 0, r0200Now.Add(time.Minute), []byte(info3.Seen)); !i.OK || !i.OverlapEnded {
			t.Fatalf("fresh take: %+v", i)
		}
		res, err = verify(f)
		refused("a fresh verifier with the kept record", res, err)
	}

	// No way to sign it back on: a list naming overlap_ended false (or anything but true) is refused whole.
	l := safety.TrustList{Seq: 4, IssuedAt: r0200Now.Add(-time.Hour)}
	l.SetOverlapEnded()
	l.Optional[safety.TrustOverlapEndedMember] = []byte("false")
	if i := s.TakeSeen(signedList(t, admin, l), 3, r0200Now, []byte(info3.Seen)); i.OK || !strings.Contains(i.Error, "overlap_ended must be true") {
		t.Fatalf("overlap_ended false: %+v", i)
	}

	// The chat Worker's own check of the v0.20.0 target (KeepOverlap, for the old app builds' key push) still passes.
	p, _ := s.Apply(r.fixbPolicy(), r0200Now)
	p.KeepOverlap = true
	if res, err := Verify(context.Background(), r.a, r.nonce, p); err != nil || res.Facts[KMSOverlapFact] == "" {
		t.Fatalf("KeepOverlap: %v", err)
	}
	// KeepOverlap never stretches the date.
	p.Now = KMSOverlapUntil
	if _, err := Verify(context.Background(), r.a, r.nonce, p); err == nil || !strings.Contains(err.Error(), "accepted only until") {
		t.Fatalf("KeepOverlap after the date: %v", err)
	}
}

// The overlap applies only while a signed trust list is in force (route2 review H1): a hostile Cloudflare can't keep
// v0.20.0 open at a v1 build by serving no list, a junk one, or one the device can't read back, whether or not the
// device kept the end. Each case is a verifier as a client builds it (TrustState.Apply on the Fix B policy).
func TestOverlapNeedsTrustList(t *testing.T) {
	admin := testAdmin(t)
	r := loadR0200(t, "r0200", r0200Now)
	list := func(l safety.TrustList) []byte {
		if l.IssuedAt.IsZero() {
			l.IssuedAt = r0200Now.Add(-time.Hour)
		}
		return signedList(t, admin, l)
	}
	ended := safety.TrustList{Seq: 2}
	ended.SetOverlapEnded()
	endInfo := (&TrustState{}).TakeSeen(list(ended), 1, r0200Now, nil)
	if !endInfo.OK || !endInfo.OverlapEnded {
		t.Fatalf("take the end: %+v", endInfo)
	}
	kept := []byte(endInfo.Seen) // the device's record after it took the end
	junk := [][]byte{[]byte("not json"), []byte(`{"kind":"trust-list"}`), list(safety.TrustList{Seq: 1, IssuedAt: r0200Now.Add(-48 * time.Hour), Expires: r0200Now.Add(-time.Hour)})}
	_, other, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	junk = append(junk, signedList(t, other, safety.TrustList{Seq: 1, IssuedAt: r0200Now.Add(-time.Hour)})) // not the pinned admin key

	noList := func(what string, p Policy) {
		t.Helper()
		res, err := Verify(context.Background(), r.a, r.nonce, p)
		if err == nil || !strings.HasPrefix(err.Error(), KMSCheck+": ") || res.HPKEPublicKey != nil || res.Facts[KMSOverlapFact] != "" ||
			!(strings.Contains(err.Error(), "only while a signed trust list is in force") || strings.Contains(err.Error(), "a signed trust list ended the overlap")) {
			t.Fatalf("%s: want v0.20.0 refused at the key check: %v", what, err)
		}
	}
	apply := func(s *TrustState) Policy {
		p, _ := s.Apply(r.fixbPolicy(), r0200Now)
		return p
	}

	// A fresh install: nothing taken, or the Worker serves nothing (the client clears the list: TakeSeen "").
	noList("a fresh verifier, nothing taken", apply(&TrustState{}))
	noList("the bare Fix B policy", r.fixbPolicy())
	s := &TrustState{}
	s.TakeSeen(nil, 0, r0200Now, nil)
	noList("a withheld list", apply(s))
	// The reviewer's probe: the kept end, no list (the saved list text unreadable, or withheld).
	f := &TrustState{}
	f.TakeSeen(nil, 0, r0200Now, kept)
	noList("the kept end and no list", apply(f))
	// A junk list (unparsable, unsigned, expired, signed by another key), with and without the kept end.
	for i, env := range junk {
		for _, seen := range [][]byte{nil, kept} {
			j := &TrustState{}
			if info := j.TakeSeen(env, 0, r0200Now, seen); info.OK {
				t.Fatalf("junk %d taken: %+v", i, info)
			}
			noList("a junk list", apply(j))
		}
	}
	// A list in force that doesn't end it: v0.20.0 passes; the same verifier with its list cleared refuses it again.
	open := &TrustState{}
	if info := open.Take(list(safety.TrustList{Seq: 1}), 0, r0200Now); !info.OK || info.OverlapEnded {
		t.Fatalf("take 1: %+v", info)
	}
	if res, err := Verify(context.Background(), r.a, r.nonce, apply(open)); err != nil || res.Facts[KMSOverlapFact] == "" {
		t.Fatalf("v0.20.0 with a list in force: %v", err)
	}
	open.TakeSeen(nil, 0, r0200Now, nil)
	noList("the list cleared", apply(open))
	// A list in force that has since expired: it no longer holds (Apply), so no list.
	exp := &TrustState{}
	if info := exp.Take(list(safety.TrustList{Seq: 1, Expires: r0200Now.Add(time.Hour)}), 0, r0200Now); !info.OK {
		t.Fatalf("take expiring: %+v", info)
	}
	if p, info := exp.Apply(r.fixbPolicy(), r0200Now.Add(2*time.Hour)); info == nil || info.OK {
		t.Fatalf("an expired list applied: %+v", info)
	} else {
		p.Now = r0200Now.Add(2 * time.Hour)
		if _, err := Verify(context.Background(), r.a, r.nonce, p); err == nil || !strings.Contains(err.Error(), "only while a signed trust list is in force") {
			t.Fatalf("an expired list: %v", err)
		}
	}

	// The chat Worker's own check of the v0.20.0 target (KeepOverlap) needs no list, as before; the date still applies.
	p := r.fixbPolicy()
	p.KeepOverlap = true
	if res, err := Verify(context.Background(), r.a, r.nonce, p); err != nil || res.Facts[KMSOverlapFact] == "" {
		t.Fatalf("KeepOverlap with no list: %v", err)
	}
	p.Now = KMSOverlapUntil
	if _, err := Verify(context.Background(), r.a, r.nonce, p); err == nil || !strings.Contains(err.Error(), "accepted only until") {
		t.Fatalf("KeepOverlap after the date: %v", err)
	}
}
