package verifier

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/tacyhq/tacy/internal/tdx"
	"github.com/tacyhq/tacy/safety"
)

// The signed trust list (safety.KindTrustList): a new OS image, its boot measurements or a Tacy KMS id approved by
// the admin keys' signature, with no rebuild. The VM stands in for one on an OS image this verifier wasn't built
// with: the 0.6.4 recording's os-image-hash event made a new image's (newImage), RTMR3 consistent, so with the
// built-in values only the OS image check fails, and with a list naming the image and its set everything passes.

var (
	newImage = strings.Repeat("6", 64)
	listNow  = time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
)

// testAdmin swaps TrustListKeys for a test key for the test (the production key isn't here).
func testAdmin(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, k, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	old := TrustListKeys
	TrustListKeys = []string{safety.KeyString(k.Public().(ed25519.PublicKey))}
	t.Cleanup(func() { TrustListKeys = old })
	return k
}

func signedList(t *testing.T, k ed25519.PrivateKey, l safety.TrustList) []byte {
	t.Helper()
	if l.Type == "" {
		l.Type = safety.TrustListType
	}
	if l.IssuedAt.IsZero() {
		l.IssuedAt, l.Expires = listNow.Add(-time.Hour), listNow.Add(30*24*time.Hour)
	}
	b, err := json.Marshal(l)
	if err != nil {
		t.Fatal(err)
	}
	env, err := json.Marshal(safety.Sign(safety.KindTrustList, b, k))
	if err != nil {
		t.Fatal(err)
	}
	return env
}

// newOSVM is the release on newImage: its boot registers are the 0.6.4 recording's (set064), the policy the
// built-in one (only dstack-0.6.5).
func newOSVM(t *testing.T, compose []byte) (releaseCase, safety.TrustBoot) {
	t.Helper()
	rc := bootWith(t, compose, false, nil, keyEvent(false))
	img := make([]byte, 32)
	for i := range img {
		img[i] = 0x66
	}
	rtmr3 := setEvent(t, rc.a, "os-image-hash", img)
	rc.p.VerifyQuote = changeQuote(func(q *tdx.Quote) { q.Rtmrs[3] = rtmr3 })
	rc.p.ProdImages, rc.p.Boot = nil, nil
	s := set064(t)
	return rc, safety.TrustBoot{Name: "dstack-0.6.6 (test), tdx.small", OSImage: newImage, MRTD: s.MRTD, RTMR0: s.RTMR0,
		RTMR1: s.RTMR1, RTMR2: s.RTMR2, Source: "test"}
}

func TestTrustListAddsOS(t *testing.T) {
	admin := testAdmin(t)
	rc, set := newOSVM(t, composeYAML(t))

	// Built-in values only: an unknown OS image fails.
	_, err := Verify(context.Background(), rc.a, rc.nonce, rc.p)
	if err == nil || !strings.Contains(err.Error(), "isn't a known production image") {
		t.Fatalf("unknown OS: %v", err)
	}

	// A list naming the image but no boot set for it: the boot measurements fail.
	l, err := ParseTrustList(signedList(t, admin, safety.TrustList{Seq: 3, OSImages: map[string]string{newImage: "dstack-0.6.6 (test)"}}), 0, listNow)
	if err != nil {
		t.Fatal(err)
	}
	p, err := rc.p.WithTrustList(l)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(context.Background(), rc.a, rc.nonce, p); err == nil || !strings.Contains(err.Error(), "boot measurements") {
		t.Fatalf("unknown boot set: %v", err)
	}

	// The next list adds its boot set: verification passes, the built-in image still accepted, no rebuild.
	l, err = ParseTrustList(signedList(t, admin, safety.TrustList{Seq: 4, OSImages: map[string]string{newImage: "dstack-0.6.6 (test)"},
		BootMeasurements: []safety.TrustBoot{set}}), 3, listNow)
	if err != nil {
		t.Fatal(err)
	}
	if p, err = rc.p.WithTrustList(l); err != nil {
		t.Fatal(err)
	}
	res, err := Verify(context.Background(), rc.a, rc.nonce, p)
	if err != nil {
		t.Fatalf("with the signed list: %v", err)
	}
	if res.Facts["OS image"] != "dstack-0.6.6 (test)" || !strings.HasPrefix(res.Facts["trust list"], "signed list 4") ||
		p.ProdImages["4771a29e03e93f0e2d5e37174cd8bb1112942c9689deb36b16c5df9e183d8623"] != "dstack-0.6.5" ||
		len(ProdImages) != 1 || len(BootMeasurements) != 1 {
		t.Fatalf("facts %v; built-in values changed: %v", res.Facts, ProdImages)
	}

	// The older list (3) again, once 4 was taken: refused. An expired one: refused (the built-in values apply).
	if _, err := ParseTrustList(signedList(t, admin, safety.TrustList{Seq: 3}), 4, listNow); err == nil || !strings.Contains(err.Error(), "older") {
		t.Fatalf("lower seq: %v", err)
	}
	if _, err := ParseTrustList(signedList(t, admin, safety.TrustList{Seq: 5}), 4, listNow.Add(31*24*time.Hour)); err == nil ||
		!strings.Contains(err.Error(), "expired") {
		t.Fatalf("expired: %v", err)
	}
	// Signed by another key: refused.
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := ParseTrustList(signedList(t, other, safety.TrustList{Seq: 9}), 0, listNow); err == nil || !strings.Contains(err.Error(), "signed by 0") {
		t.Fatalf("other signer: %v", err)
	}
}

func TestTrustListRefuses(t *testing.T) {
	admin := testAdmin(t)
	for name, l := range map[string]safety.TrustList{
		"a retired image":            {Seq: 1, OSImages: map[string]string{"feff3645893ad910d4f0e06d8f553cf80a7c9fede2ce0698fa63116283260366": "again"}},
		"a set for an unknown image": {Seq: 1, BootMeasurements: []safety.TrustBoot{{Name: "x", OSImage: newImage, MRTD: strings.Repeat("00", 48), RTMR0: strings.Repeat("00", 48), RTMR1: strings.Repeat("00", 48), RTMR2: strings.Repeat("00", 48), Source: "t"}}},
	} {
		parsed, err := ParseTrustList(signedList(t, admin, l), 0, listNow)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := (Policy{}).WithTrustList(parsed); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// It only adds: a name for a built-in image doesn't rename it, and the release floor only goes up.
	parsed, _ := ParseTrustList(signedList(t, admin, safety.TrustList{Seq: 2, VMReleaseFloor: "v0.20.1",
		OSImages: map[string]string{"4771a29e03e93f0e2d5e37174cd8bb1112942c9689deb36b16c5df9e183d8623": "renamed"}}), 0, listNow)
	p, err := (Policy{ReleaseFloor: "v0.21.0"}).WithTrustList(parsed)
	if err != nil || p.ProdImages["4771a29e03e93f0e2d5e37174cd8bb1112942c9689deb36b16c5df9e183d8623"] != "dstack-0.6.5" || p.ReleaseFloor != "v0.21.0" {
		t.Fatalf("%v %v %s", err, p.ProdImages, p.ReleaseFloor)
	}
	if p, _ := (Policy{ReleaseFloor: "v0.19.4"}).WithTrustList(parsed); p.ReleaseFloor != "v0.20.1" {
		t.Fatalf("floor %s", p.ReleaseFloor)
	}
}

// The compose names the Tacy KMS by its id (-kms-key): an unknown one fails, a pinned one or one a signed list adds
// passes; a plain http URL, or a URL without a key, fails.
func TestKMSID(t *testing.T) {
	admin := testAdmin(t)
	_, kms, _ := ed25519.GenerateKey(rand.Reader)
	id := safety.KeyString(kms.Public().(ed25519.PublicKey))
	withKMS := func(args string) []byte {
		c := string(composeYAML(t))
		i := strings.Index(c, `"-runner-socket", "/run/tacy/runner/runner.sock"`) // agentd's command
		if i < 0 {
			t.Fatal("agentd's -runner-socket not in compose.yaml")
		}
		return []byte(c[:i] + args + c[i:])
	}
	ok := withKMS(`"-kms-key", "` + id + `", "-kms-url", "https://kms.tacy.io", `)
	rc := bootWith(t, ok, false, nil, keyEvent(false))
	_, err := Verify(context.Background(), rc.a, rc.nonce, rc.p)
	if err == nil || !strings.HasPrefix(err.Error(), KMSIDCheck+": ") || !strings.Contains(err.Error(), "isn't a pinned one") {
		t.Fatalf("unknown KMS id: %v", err)
	}
	l, err := ParseTrustList(signedList(t, admin, safety.TrustList{Seq: 1, KMSIDs: map[string]string{id: "Tacy KMS genesis (test)"}}), 0, listNow)
	if err != nil {
		t.Fatal(err)
	}
	p, _ := rc.p.WithTrustList(l)
	res, err := Verify(context.Background(), rc.a, rc.nonce, p)
	if err != nil || res.Facts["Tacy KMS"] != id || res.Facts["Tacy KMS url"] != "https://kms.tacy.io" {
		t.Fatalf("listed KMS id: %v %v", err, res.Facts)
	}
	rc.p.KMSIDs = map[string]string{id: "built in"}
	if _, err := Verify(context.Background(), rc.a, rc.nonce, rc.p); err != nil {
		t.Fatalf("built-in KMS id: %v", err)
	}
	for name, args := range map[string]string{
		"http":           `"-kms-key=` + id + `", "-kms-url=http://kms.tacy.io", `,
		"url without id": `"-kms-url", "https://kms.tacy.io", `,
	} {
		rc := bootWith(t, withKMS(args), false, nil, keyEvent(false))
		rc.p.KMSIDs = map[string]string{id: "built in"}
		if _, err := Verify(context.Background(), rc.a, rc.nonce, rc.p); err == nil || !strings.HasPrefix(err.Error(), KMSIDCheck+": ") {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestNewerVersion(t *testing.T) {
	for _, c := range [][3]string{{"v0.20.0", "v0.19.9", "v0.20.0"}, {"v0.9.0", "v0.10.0", "v0.10.0"}, {"", "v1.0.0", "v1.0.0"},
		{"bad", "", ""}, {"v1.2.3", "v1.2.3", "v1.2.3"}} {
		if got := NewerVersion(c[0], c[1]); got != c[2] {
			t.Errorf("NewerVersion(%q, %q) = %q", c[0], c[1], got)
		}
	}
}

// composeWithKMS is compose.yaml with args put in agentd's command (a -kms-key and -kms-url, as a release names them).
func composeWithKMS(t *testing.T, args string) []byte {
	t.Helper()
	c := string(composeYAML(t))
	i := strings.Index(c, `"-runner-socket", "/run/tacy/runner/runner.sock"`)
	if i < 0 {
		t.Fatal("agentd's -runner-socket not in compose.yaml")
	}
	return []byte(c[:i] + args + c[i:])
}

func kmsKey(t *testing.T) string {
	t.Helper()
	_, k, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return safety.KeyString(k.Public().(ed25519.PublicKey))
}

// The release pin of the production KMS id: empty until genesis (then no -kms-key is accepted without a signed
// list), and when filled, exactly that id. An empty or malformed pin never accepts an arbitrary id.
func TestReleaseKMSID(t *testing.T) {
	if ReleaseKMSID != "" {
		if k, err := safety.ParseKey(ReleaseKMSID); err != nil || safety.KeyString(k) != ReleaseKMSID {
			t.Fatalf("ReleaseKMSID %q isn't a canonical ed25519:<base64> key: %v", ReleaseKMSID, err)
		}
		if len(KMSIDs) != 1 || KMSIDs[ReleaseKMSID] != ReleaseKMSName {
			t.Fatalf("KMSIDs %v", KMSIDs)
		}
	} else if len(KMSIDs) != 0 {
		t.Fatalf("no release pin, but KMSIDs %v", KMSIDs)
	}
	id := kmsKey(t)
	for _, bad := range []string{"", "ed25519:nope", strings.TrimSuffix(id, "="), "x25519:" + strings.TrimPrefix(id, "ed25519:")} {
		if m := releaseKMSIDs(bad); len(m) != 0 {
			t.Errorf("releaseKMSIDs(%q) = %v", bad, m)
		}
	}

	// With the built-in values only (no trust list), a compose naming a KMS id: refused unless it is the pin.
	compose := composeWithKMS(t, `"-kms-key", "`+id+`", "-kms-url", "https://kms.tacy.io", `)
	rc := bootWith(t, compose, false, nil, keyEvent(false))
	if _, err := Verify(context.Background(), rc.a, rc.nonce, rc.p); err == nil || !strings.HasPrefix(err.Error(), KMSIDCheck+": ") {
		t.Fatalf("an id that isn't the pin: %v", err)
	}
	rc.p.KMSIDs = releaseKMSIDs(id) // as the build with ReleaseKMSID = id has it
	res, err := Verify(context.Background(), rc.a, rc.nonce, rc.p)
	if err != nil || res.Facts["Tacy KMS"] != id {
		t.Fatalf("the pinned id: %v %v", err, res.Facts)
	}
	other := bootWith(t, composeWithKMS(t, `"-kms-key", "`+kmsKey(t)+`", `), false, nil, keyEvent(false))
	other.p.KMSIDs = releaseKMSIDs(id)
	if _, err := Verify(context.Background(), other.a, other.nonce, other.p); err == nil || !strings.HasPrefix(err.Error(), KMSIDCheck+": ") {
		t.Fatalf("another id under the pin: %v", err)
	}
}

// fakeBundle stands in for a release's Sigstore bundle: the trust list only carries it (a release-mode verifier
// checks it), so its shape is all that is checked here.
func fakeBundle(n int) []byte {
	return []byte(`{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json","pad":"` + strings.Repeat("x", n) + `"}`)
}

func trustRelease(v, compose string, bundle []byte) safety.TrustRelease {
	return safety.TrustRelease{Version: v, Commit: strings.Repeat("e", 40), ComposeSHA256: compose, Bundle: bundle}
}

// VM releases in the signed list: parsed with their bundles, added after the built-in ones (never replacing one, the
// same entry not twice), looked up by compose hash; a list as large as its limits allow (8 releases with bundles of
// a real one's size) is taken, a larger payload refused.
func TestTrustListReleases(t *testing.T) {
	admin := testAdmin(t)
	a, b := strings.Repeat("a", 64), strings.Repeat("b", 64)
	l, err := ParseTrustList(signedList(t, admin, safety.TrustList{Seq: 2, VMReleaseFloor: "v0.20.0",
		Releases: []safety.TrustRelease{trustRelease("v0.21.0", a, fakeBundle(10)), trustRelease("v0.20.0", b, fakeBundle(20))}}), 0, listNow)
	if err != nil {
		t.Fatal(err)
	}
	if len(l.Releases) != 2 || string(l.Releases[0].Bundle) != string(fakeBundle(10)) {
		t.Fatalf("releases %+v", l.Releases)
	}
	builtIn := trustRelease("v0.20.0", b, fakeBundle(30)) // the same release as built in, with its own bundle
	p, err := Policy{Releases: []safety.TrustRelease{builtIn}}.WithTrustList(l)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Releases) != 2 || string(p.Releases[0].Bundle) != string(builtIn.Bundle) || p.Releases[1].Version != "v0.21.0" || p.ReleaseFloor != "v0.20.0" {
		t.Fatalf("merged %+v floor %s", p.Releases, p.ReleaseFloor)
	}
	if got := p.ReleaseBundles(a); len(got) != 1 || string(got[0]) != string(fakeBundle(10)) {
		t.Fatalf("bundles for a: %q", got)
	}
	if got := p.ReleaseBundles(strings.Repeat("c", 64)); got != nil {
		t.Fatalf("bundles for an unlisted compose: %q", got)
	}
	// A later list without releases removes none the verifier was built with.
	l2, _ := ParseTrustList(signedList(t, admin, safety.TrustList{Seq: 3}), 2, listNow)
	if p2, _ := (Policy{Releases: []safety.TrustRelease{builtIn}}).WithTrustList(l2); len(p2.Releases) != 1 {
		t.Fatalf("after a list without releases: %+v", p2.Releases)
	}

	// Limits: 8 releases with 12 KiB bundles fit; a 9th, or a payload over MaxTrustListPayload, doesn't.
	var many []safety.TrustRelease
	for i := range 8 {
		many = append(many, trustRelease("v0.21."+string(rune('0'+i)), a, fakeBundle(12<<10)))
	}
	if _, err := ParseTrustList(signedList(t, admin, safety.TrustList{Seq: 4, Releases: many}), 0, listNow); err != nil {
		t.Fatalf("8 releases: %v", err)
	}
	if _, err := ParseTrustList(signedList(t, admin, safety.TrustList{Seq: 4, Releases: append(many, trustRelease("v0.22.0", a, fakeBundle(1)))}), 0, listNow); err == nil ||
		!strings.Contains(err.Error(), "at most 8 releases") {
		t.Fatalf("9 releases: %v", err)
	}
	big := safety.TrustList{Seq: 4, Releases: many, OSImages: map[string]string{}}
	for i := range 64 {
		big.OSImages[strings.Repeat(string("0123456789abcdef"[i%16]), 63)+string("0123456789abcdef"[i/16])] = strings.Repeat("n", 200)
	}
	for i := range big.Releases {
		big.Releases[i].Bundle = fakeBundle(15 << 10)
	}
	if _, err := ParseTrustList(signedList(t, admin, big), 0, listNow); err == nil || !strings.Contains(err.Error(), "size") {
		t.Fatalf("an oversize list: %v", err)
	}
}

// TrustState is what the WASM's setTrustList and verify run: a list is taken at or above minSeq and reported with its
// release entries; refused, the one taken before stays; at each use it is checked again (expired: the built-in
// values, and why); "" clears it. A compose naming the list's KMS id verifies through it, an unlisted id fails the
// Tacy KMS check (the chat's "kms_id").
func TestTrustState(t *testing.T) {
	admin := testAdmin(t)
	id := kmsKey(t)
	var s TrustState
	if p, info := s.Apply(Policy{}, listNow); info != nil || p.trust != nil {
		t.Fatalf("nothing taken: %+v", info)
	}
	env := signedList(t, admin, safety.TrustList{Seq: 5, KMSIDs: map[string]string{id: "Tacy KMS (test)"}, VMReleaseFloor: "v0.21.0",
		Releases: []safety.TrustRelease{trustRelease("v0.21.0", strings.Repeat("a", 64), fakeBundle(5))}})
	info := s.Take(env, 0, listNow)
	if !info.OK || info.Seq != 5 || info.KMSIDs != 1 || info.Releases != 1 || len(info.ReleaseEntries) != 1 ||
		info.ReleaseEntries[0].Version != "v0.21.0" || info.ReleaseFloor != "v0.21.0" {
		t.Fatalf("taken: %+v", info)
	}
	// An older list once 5 was taken: refused, 5 stays in force.
	if r := s.Take(signedList(t, admin, safety.TrustList{Seq: 4}), 5, listNow); r.OK || !strings.Contains(r.Error, "older") {
		t.Fatalf("older: %+v", r)
	}
	rc := bootWith(t, composeWithKMS(t, `"-kms-key", "`+id+`", "-kms-url", "https://kms.tacy.io", `), false, nil, keyEvent(false))
	p, used := s.Apply(rc.p, listNow)
	if used == nil || !used.OK || used.Seq != 5 || used.ReleaseEntries != nil || len(p.Releases) != 1 || p.ReleaseFloor != "v0.21.0" {
		t.Fatalf("applied: %+v %+v", used, p.Releases)
	}
	if res, err := Verify(context.Background(), rc.a, rc.nonce, p); err != nil || res.Facts["Tacy KMS"] != id {
		t.Fatalf("the listed KMS id: %v", err)
	}
	unlisted := bootWith(t, composeWithKMS(t, `"-kms-key", "`+kmsKey(t)+`", `), false, nil, keyEvent(false))
	q, _ := s.Apply(unlisted.p, listNow)
	if _, err := Verify(context.Background(), unlisted.a, unlisted.nonce, q); err == nil || !strings.HasPrefix(err.Error(), "Tacy KMS:") {
		t.Fatalf("an unlisted KMS id: %v", err)
	}
	// Expired since it was taken: the built-in values (the KMS id refused), and the reason.
	late, why := s.Apply(rc.p, listNow.Add(31*24*time.Hour))
	if why == nil || why.OK || !strings.Contains(why.Error, "expired") || late.KMSIDs != nil {
		t.Fatalf("expired: %+v", why)
	}
	if _, err := Verify(context.Background(), rc.a, rc.nonce, late); err == nil || !strings.HasPrefix(err.Error(), KMSIDCheck+": ") {
		t.Fatalf("expired list, KMS id: %v", err)
	}
	if r := s.Take(nil, 0, listNow); !r.OK || r.Seq != 0 {
		t.Fatalf("clear: %+v", r)
	}
	if _, info := s.Apply(rc.p, listNow); info != nil {
		t.Fatalf("cleared: %+v", info)
	}
	// Refused outright (another signer): nothing taken.
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	if r := s.Take(signedList(t, other, safety.TrustList{Seq: 9}), 0, listNow); r.OK || !strings.Contains(r.Error, "signed by 0") {
		t.Fatalf("other signer: %+v", r)
	}
}
