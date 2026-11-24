package verifier

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"regexp"
	"slices"
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

// newOSVM is the release on newImage: MRTD and RTMR0 are the 0.6.4 recording's (set064), RTMR1 and RTMR2 its own;
// the policy the built-in one (only dstack-0.6.5).
func newOSVM(t *testing.T, compose []byte) (releaseCase, safety.TrustBoot) {
	t.Helper()
	rc := bootWith(t, compose, false, nil, keyEvent(false))
	img := make([]byte, 32)
	for i := range img {
		img[i] = 0x66
	}
	rtmr3 := setEvent(t, rc.a, "os-image-hash", img)
	// A new image's own kernel and command line (a trust list refuses a retired image's under a new label).
	rtmr1, rtmr2 := bytes.Repeat([]byte{0x61}, 48), bytes.Repeat([]byte{0x62}, 48)
	rc.p.VerifyQuote = changeQuote(func(q *tdx.Quote) {
		q.Rtmrs[1], q.Rtmrs[2], q.Rtmrs[3] = rtmr1, rtmr2, rtmr3
		if rc.rd != nil {
			q.ReportData = rc.rd
		}
	})
	rc.p.ProdImages, rc.p.Boot = nil, nil
	s := set064(t)
	return rc, safety.TrustBoot{Name: "dstack-0.6.6 (test), tdx.small", OSImage: newImage, MRTD: s.MRTD, RTMR0: s.RTMR0,
		RTMR1: hex.EncodeToString(rtmr1), RTMR2: hex.EncodeToString(rtmr2), Source: "test"}
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
		len(ProdImages) != 1 || len(BootMeasurements) != 3 {
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
	// Review L2: a retired image's measurements under a current label (in key provider none the label is the matching
	// set's): the whole 0.6.1 set, its kernel alone, its command line and initramfs alone (another VM size).
	cur := BootMeasurements[0]
	for _, r := range RetiredBootMeasurements {
		for what, b := range map[string]safety.TrustBoot{
			"whole set":  {MRTD: r.MRTD, RTMR0: r.RTMR0, RTMR1: r.RTMR1, RTMR2: r.RTMR2},
			"RTMR1 only": {MRTD: cur.MRTD, RTMR0: cur.RTMR0, RTMR1: r.RTMR1, RTMR2: strings.Repeat("11", 48)},
			"RTMR2 only": {MRTD: cur.MRTD, RTMR0: strings.Repeat("22", 48), RTMR1: strings.Repeat("33", 48), RTMR2: r.RTMR2},
		} {
			b.Name, b.OSImage, b.Source = "dstack-0.6.5 (really "+r.Name+")", cur.OSImage, "t"
			parsed, err := ParseTrustList(signedList(t, admin, safety.TrustList{Seq: 1, BootMeasurements: []safety.TrustBoot{b}}), 0, listNow)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := (Policy{}).WithTrustList(parsed); err == nil || !strings.Contains(err.Error(), "retired "+r.Name) {
				t.Errorf("%s, %s: %v", r.Name, what, err)
			}
		}
	}
	// A new set (another VM size of 0.6.5: other RTMR0 and RTMR1, the same RTMR2) is still accepted.
	parsedNew, _ := ParseTrustList(signedList(t, admin, safety.TrustList{Seq: 1, BootMeasurements: []safety.TrustBoot{{Name: "0.6.5, 2 vCPU",
		OSImage: cur.OSImage, MRTD: cur.MRTD, RTMR0: strings.Repeat("44", 48), RTMR1: strings.Repeat("55", 48), RTMR2: cur.RTMR2, Source: "t"}}}), 0, listNow)
	if _, err := (Policy{}).WithTrustList(parsedNew); err != nil {
		t.Fatalf("a new VM size: %v", err)
	}
	// No built-in set shares a kernel or command line with a retired one (so the rule refuses no current image).
	for _, b := range BootMeasurements {
		if why := retiredBoot(b.RTMR1, b.RTMR2); why != "" {
			t.Errorf("built-in %s has %s", b.Name, why)
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
		c := string(composeNoKMS(t))
		i := strings.Index(c, `"-runner-socket", "/run/tacy/runner/runner.sock"`) // agentd's command
		if i < 0 {
			t.Fatal("agentd's -runner-socket not in compose.yaml")
		}
		return []byte(c[:i] + args + c[i:])
	}
	ok := composeWithKMS(t, id)
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
	if err != nil || res.Facts["Tacy KMS"] != id {
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

// composeNoKMS is compose.yaml without the release's own key service flags (-kms-key, -kms-hosts, -kms-url), so a
// test names only the KMS id it puts in.
func composeNoKMS(t *testing.T) []byte {
	t.Helper()
	c := regexp.MustCompile(`"-kms-(key|url|hosts)", "[^"]*", `).ReplaceAllString(string(composeYAML(t)), "")
	if strings.Contains(c, `"-kms-`) {
		t.Fatal("a -kms- flag left in compose.yaml")
	}
	return []byte(c)
}

// composeWithKMS is compose.yaml naming the KMS id id where the release names one (gatewayd's and unlockd's
// -kms-key: a release with unlockd has exactly that shape, ReleaseShape, and no -kms-url).
func composeWithKMS(t *testing.T, id string) []byte {
	t.Helper()
	c := regexp.MustCompile(`"-kms-key", "[^"]*", `).ReplaceAllString(string(composeYAML(t)), `"-kms-key", "`+id+`", `)
	if strings.Count(c, `"-kms-key", "`+id+`", `) != 2 {
		t.Fatal("compose.yaml doesn't name the KMS id in gatewayd and unlockd")
	}
	return []byte(c)
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
	compose := composeWithKMS(t, id)
	rc := bootWith(t, compose, false, nil, keyEvent(false))
	if _, err := Verify(context.Background(), rc.a, rc.nonce, rc.p); err == nil || !strings.HasPrefix(err.Error(), KMSIDCheck+": ") {
		t.Fatalf("an id that isn't the pin: %v", err)
	}
	rc.p.KMSIDs = releaseKMSIDs(id) // as the build with ReleaseKMSID = id has it
	res, err := Verify(context.Background(), rc.a, rc.nonce, rc.p)
	if err != nil || res.Facts["Tacy KMS"] != id {
		t.Fatalf("the pinned id: %v %v", err, res.Facts)
	}
	other := bootWith(t, composeWithKMS(t, kmsKey(t)), false, nil, keyEvent(false))
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
	info := ripen(t, &s, env, 0)
	if !info.OK || info.Seq != 5 || info.KMSIDs != 1 || info.Releases != 1 || len(info.ReleaseEntries) != 1 ||
		info.ReleaseEntries[0].Version != "v0.21.0" || info.ReleaseFloor != "v0.21.0" {
		t.Fatalf("taken: %+v", info)
	}
	// An older list once 5 was taken: refused, 5 stays in force.
	if r := s.Take(signedList(t, admin, safety.TrustList{Seq: 4}), 5, listNow); r.OK || !strings.Contains(r.Error, "older") {
		t.Fatalf("older: %+v", r)
	}
	rc := bootWith(t, composeWithKMS(t, id), false, nil, keyEvent(false))
	p, used := s.Apply(rc.p, listNow)
	if used == nil || !used.OK || used.Seq != 5 || used.ReleaseEntries != nil || len(p.Releases) != 1 || p.ReleaseFloor != "v0.21.0" {
		t.Fatalf("applied: %+v %+v", used, p.Releases)
	}
	if res, err := Verify(context.Background(), rc.a, rc.nonce, p); err != nil || res.Facts["Tacy KMS"] != id {
		t.Fatalf("the listed KMS id: %v", err)
	}
	unlisted := bootWith(t, composeWithKMS(t, kmsKey(t)), false, nil, keyEvent(false))
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

// composeWithService is compose.yaml with one more service, its image pinned by digest.
func composeWithService(t *testing.T, name string) []byte {
	t.Helper()
	c := string(composeYAML(t))
	i := strings.Index(c, "\nvolumes:\n")
	if i < 0 {
		t.Fatal("no top-level volumes: in compose.yaml")
	}
	svc := "\n  " + name + ":\n    image: ghcr.io/tacyhq/tacy/" + name + "@sha256:" + strings.Repeat("a", 64) + "\n    network_mode: none" +
		"\n    ulimits:\n      core: 0"
	return []byte(c[:i] + svc + c[i:])
}

// What a later VM release may need without an app rebuild (clients ship first): unlockd is a
// built-in service; any other new one is accepted once a signed list names it; another provider's dstack KMS root
// once listed (a retired one never); a TCB grace window lets a host whose TCB isn't UpToDate pass only while open.
func TestTrustListForLaterReleases(t *testing.T) {
	admin := testAdmin(t)
	withUnlockd := composeYAML(t) // compose.yaml has unlockd since slice 4 (split-unlockd), with its rules
	if !HasUnlockd(string(withUnlockd)) {
		withUnlockd = composeWithService(t, "unlockd")
	}
	if rc := bootWith(t, withUnlockd, false, nil, keyEvent(false)); true {
		if _, err := Verify(context.Background(), rc.a, rc.nonce, rc.p); err != nil {
			t.Fatalf("unlockd, built in: %v", err)
		}
	}
	rc := bootWith(t, composeWithService(t, "holderprobe"), false, nil, keyEvent(false))
	if _, err := Verify(context.Background(), rc.a, rc.nonce, rc.p); err == nil || !strings.Contains(err.Error(), "holderprobe") {
		t.Fatalf("an unlisted service: %v", err)
	}
	var s TrustState
	if info := ripen(t, &s, signedList(t, admin, safety.TrustList{Seq: 2, Services: []string{"holderprobe"}}), 0); !info.OK || info.Services != 1 {
		t.Fatalf("taken: %+v", info)
	}
	p, _ := s.Apply(rc.p, listNow)
	if _, err := Verify(context.Background(), rc.a, rc.nonce, p); err != nil {
		t.Fatalf("a listed service: %v", err)
	}
	// The tunnel is in-container (vm-v1): the confined variant's cftunnel isn't a release service.
	if !slices.Equal(ReleaseServices, []string{"setup", "agentd", "runner", "agentvm", "vaultd", "unlockd"}) {
		t.Fatalf("built-in services changed: %v", ReleaseServices)
	}

	// KMS roots: added; a retired one refuses the list.
	root := strings.Repeat("3059", 40)
	l, err := ParseTrustList(signedList(t, admin, safety.TrustList{Seq: 3, KMSRoots: map[string]string{root: "dstack KMS (test provider)"}}), 0, listNow)
	if err != nil {
		t.Fatal(err)
	}
	if q, err := (Policy{}).WithTrustList(l); err != nil || q.KMSRoots[root] == "" || len(q.KMSRoots) != len(KMSRoots)+1 {
		t.Fatalf("kms roots %v %v", err, q.KMSRoots)
	}
	for old := range RetiredKMSRoots {
		l, err := ParseTrustList(signedList(t, admin, safety.TrustList{Seq: 4, KMSRoots: map[string]string{old: "again"}}), 0, listNow)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := (Policy{}).WithTrustList(l); err == nil || !strings.Contains(err.Error(), "retired") {
			t.Fatalf("a retired root: %v", err)
		}
	}

	// TCB grace: refused without one, passes while open, refused once it closed.
	staleVM := func(status, date string) releaseCase {
		rc := bootWith(t, composeYAML(t), false, nil, keyEvent(false))
		inner := rc.p.VerifyQuote
		rc.p.AllowStaleTCB = false // the recordings' policy allows it; production's doesn't
		rc.p.VerifyQuote = func(ctx context.Context, raw []byte) (*tdx.Quote, error) {
			q, err := inner(ctx, raw)
			if q != nil {
				q.TcbStatus, q.QeStatus, q.TcbDate = status, "UpToDate", date
			}
			return q, err
		}
		return rc
	}
	stale := staleVM("OutOfDate", "2026-08-01T00:00:00Z")
	if _, err := Verify(context.Background(), stale.a, stale.nonce, stale.p); err == nil || !strings.Contains(err.Error(), "OutOfDate") {
		t.Fatalf("a stale TCB without grace: %v", err)
	}
	grace := &safety.TCBGrace{Until: listNow.Add(7 * 24 * time.Hour), Statuses: []string{"OutOfDate"}, MinTCBDate: "2026-06-01"}
	var g TrustState
	if info := ripen(t, &g, signedList(t, admin, safety.TrustList{Seq: 5, TCBGrace: grace}), 0); !info.OK || info.TCBGraceUntil == "" ||
		!slices.Equal(info.TCBGraceStatuses, []string{"OutOfDate"}) {
		t.Fatalf("grace taken: %+v", info)
	}
	open, _ := g.Apply(stale.p, listNow)
	if _, err := Verify(context.Background(), stale.a, stale.nonce, open); err != nil {
		t.Fatalf("a stale TCB in the grace window: %v", err)
	}
	closed, _ := g.Apply(stale.p, grace.Until.Add(time.Minute))
	if _, err := Verify(context.Background(), stale.a, stale.nonce, closed); err == nil {
		t.Fatal("a stale TCB after the grace window")
	}
	// Only the statuses it names, never Revoked; not below its minimum TCB date.
	for name, rc := range map[string]releaseCase{
		"a status it doesn't name": staleVM("SWHardeningNeeded", "2026-08-01T00:00:00Z"),
		"Revoked":                  staleVM("Revoked", "2026-08-01T00:00:00Z"),
		"an older TCB level":       staleVM("OutOfDate", "2026-01-01T00:00:00Z"),
	} {
		p, _ := g.Apply(rc.p, listNow)
		if _, err := Verify(context.Background(), rc.a, rc.nonce, p); err == nil {
			t.Errorf("%s: passed in the grace window", name)
		}
	}
	// A minimum evaluation number this build can't read: the grace doesn't apply (fail closed).
	var e TrustState
	evalGrace := *grace
	evalGrace.MinTCBEval = 17
	ripen(t, &e, signedList(t, admin, safety.TrustList{Seq: 6, TCBGrace: &evalGrace}), 0)
	if p, _ := e.Apply(stale.p, listNow); p.AllowStaleTCB {
		t.Fatal("a grace with min_tcb_eval applied")
	}
}

// Withdrawn releases leave the policy's releases and are reported to the client, which refuses a
// VM running one (Policy.Revoked, verifier-core.ts); a release for a platform this verifier doesn't check is dropped.
func TestTrustListRevokedAndPlatform(t *testing.T) {
	admin := testAdmin(t)
	a, b, c := strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("c", 64)
	sev := trustRelease("v0.22.0", c, fakeBundle(5))
	sev.Platform = "sev-snp"
	l, err := ParseTrustList(signedList(t, admin, safety.TrustList{Seq: 6, RevokedReleases: []string{"v0.20.0"},
		Releases: []safety.TrustRelease{trustRelease("v0.21.0", a, fakeBundle(5)), sev}}), 0, listNow)
	if err != nil {
		t.Fatal(err)
	}
	p, err := (Policy{Releases: []safety.TrustRelease{trustRelease("v0.20.0", b, fakeBundle(5))}}).WithTrustList(l)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Releases) != 1 || p.Releases[0].Version != "v0.21.0" || p.ReleaseBundles(b) != nil || p.ReleaseBundles(c) != nil {
		t.Fatalf("releases %+v", p.Releases)
	}
	if !p.Revoked("v0.20.0") || p.Revoked("v0.21.0") || (Policy{}).Revoked("v0.20.0") {
		t.Fatal("Revoked")
	}
	if i := TrustInfoOf(l, false); len(i.RevokedReleases) != 1 || i.RevokedReleases[0] != "v0.20.0" {
		t.Fatalf("info %+v", i)
	}
}

// Admin key rotation with no app rebuild: a list signed by the pinned key names a new key; a client
// keeps that rotation and puts it before every later list, which only the new key then signs. A list signed only by
// the rotated-out key is refused once the rotation is in the chain; without it, only the pinned key counts.
func TestTrustListKeyRotation(t *testing.T) {
	admin := testAdmin(t)
	_, next, _ := ed25519.GenerateKey(rand.Reader)
	nextKey := safety.KeyString(next.Public().(ed25519.PublicKey))
	rotation := signedList(t, admin, safety.TrustList{Seq: 3, NextAdminKeys: []string{nextKey}})
	byNew := signedList(t, next, safety.TrustList{Seq: 4, KMSIDs: map[string]string{kmsKey(t): "Tacy KMS (test)"}})
	byOld := signedList(t, admin, safety.TrustList{Seq: 5})
	chain := func(envs ...[]byte) []byte {
		parts := make([]string, len(envs))
		for i, e := range envs {
			parts[i] = string(e)
		}
		return []byte("[" + strings.Join(parts, ",") + "]")
	}
	if _, err := ParseTrustList(byNew, 0, listNow); err == nil {
		t.Fatal("the new key's list without the rotation")
	}
	if l, err := ParseTrustList(chain(rotation, byNew), 0, listNow); err != nil || l.Seq != 4 {
		t.Fatalf("rotation then the new key's list: %v", err)
	}
	if _, err := ParseTrustList(chain(rotation, byOld), 0, listNow); err == nil {
		t.Fatal("the old key's list after the rotation")
	}
	// The rotation itself, as the list (a client given it again): verified with the keys before it.
	if l, err := ParseTrustList(chain(rotation, rotation), 0, listNow); err != nil || l.Seq != 3 {
		t.Fatalf("the rotation as the list: %v", err)
	}
	// A list at or below the rotation's seq after it: refused (it can't predate the keys that signed it).
	if _, err := ParseTrustList(chain(rotation, signedList(t, next, safety.TrustList{Seq: 3})), 0, listNow); err == nil {
		t.Fatal("a list at the rotation's seq")
	}
	// A server can't swap the chain: an attacker's rotation after the real one is signed by the old key only.
	_, evil, _ := ed25519.GenerateKey(rand.Reader)
	swap := signedList(t, admin, safety.TrustList{Seq: 6, NextAdminKeys: []string{safety.KeyString(evil.Public().(ed25519.PublicKey))}})
	if _, err := ParseTrustList(chain(rotation, swap, signedList(t, evil, safety.TrustList{Seq: 7})), 0, listNow); err == nil {
		t.Fatal("a swapped rotation after the real one")
	}
	// Through TrustState (the WASM's setTrustList): taken and applied with the chain, and reported as a rotation.
	var s TrustState
	if info := s.Take(chain(rotation, byNew), 4, listNow); !info.OK || info.Seq != 4 || info.KMSIDs != 1 {
		t.Fatalf("taken: %+v", info)
	}
	if info := s.Take(rotation, 0, listNow); !info.OK || len(info.AdminKeys) != 1 || info.AdminKeys[0] != nextKey {
		t.Fatalf("the rotation alone: %+v", info)
	}
	// No expiry: a list that names none holds until a newer seq, the rotation chain included.
	forever := signedList(t, next, safety.TrustList{Seq: 8, IssuedAt: listNow.Add(-time.Hour)})
	if info := s.Take(chain(rotation, forever), 0, listNow); !info.OK || info.Expires != "" {
		t.Fatalf("no expiry: %+v", info)
	}
	if _, info := s.Apply(Policy{}, listNow.Add(2*365*24*time.Hour)); info == nil || !info.OK || info.Seq != 8 {
		t.Fatalf("a list with no expiry, two years on: %+v", info)
	}
}

// ripen takes env as a verifier that has listed its items for the whole delay already (first seen a day before
// listNow), so a test of what a list adds sees it in force (TestTrustDelay tests the delay itself).
func ripen(t *testing.T, s *TrustState, env []byte, minSeq uint64) TrustInfo {
	t.Helper()
	first := s.Take(env, minSeq, listNow)
	if !first.OK {
		return first
	}
	seen := safety.ParseTrustSeen([]byte(first.Seen))
	for k, v := range seen.Items {
		v.First = listNow.Add(-safety.TrustDelay)
		seen.Items[k] = v
	}
	return s.TakeSeen(env, minSeq, listNow, seen.Marshal())
}
