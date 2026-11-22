package verifier

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/tacyhq/tacy/release"
	"github.com/tacyhq/tacy/release/releasetest"
	"github.com/tacyhq/tacy/safety"
)

// Release mode with the signed trust list's VM releases (Policy.Releases): when the caller gives no bundle, the one a
// taken list names for the attested compose is checked exactly as a given one (the release workflow's identity, the
// Rekor entry, the minimum and the list's floor). A list without that compose, or whose bundle is for another
// compose, gives nothing: the VM is refused. A given bundle is used as before.
func TestReleaseModeTrustListReleases(t *testing.T) {
	admin := testAdmin(t)
	compose := fallbackCompose(t)
	sum := sha256.Sum256(compose)
	sumHex := hex.EncodeToString(sum[:])
	s, err := releasetest.New()
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := s.Bundle(releasetest.Options{Version: "v0.21.0", Subjects: map[string][]byte{release.Subject: sum[:]}})
	if err != nil {
		t.Fatal(err)
	}
	other := sha256.Sum256([]byte("another compose"))
	otherBundle, err := s.Bundle(releasetest.Options{Version: "v0.21.0", Subjects: map[string][]byte{release.Subject: other[:]}})
	if err != nil {
		t.Fatal(err)
	}
	boot := func(t *testing.T) releaseCase {
		rc := bootWith(t, compose, true, nil, keyEvent(true))
		rc.p.Compose, rc.p.AppCompose = nil, nil
		rc.p.Bundle, rc.p.Release = nil, release.Policy{Trusted: s.Trusted()}
		return rc
	}
	verifyWith := func(t *testing.T, l safety.TrustList) (*Result, error) {
		t.Helper()
		var st TrustState
		if info := ripen(t, &st, signedList(t, admin, l), 0); !info.OK { // listed for a day: clients' delay

			t.Fatalf("list not taken: %+v", info)
		}
		rc := boot(t)
		p, used := st.Apply(rc.p, listNow)
		if used == nil || !used.OK {
			t.Fatalf("list not applied: %+v", used)
		}
		return Verify(context.Background(), rc.a, rc.nonce, p)
	}
	entry := func(compose string, b []byte) safety.TrustRelease {
		return safety.TrustRelease{Version: "v0.21.0", Commit: strings.Repeat("c", 40), ComposeSHA256: compose, Bundle: b}
	}

	// No bundle and no list: refused.
	rc := boot(t)
	if _, err := Verify(context.Background(), rc.a, rc.nonce, rc.p); err == nil || !strings.Contains(err.Error(), "no release bundle given") {
		t.Fatalf("no bundle: %v", err)
	}
	// The list names this compose's release: it verifies, and the facts are the release's.
	res, err := verifyWith(t, safety.TrustList{Seq: 3, Releases: []safety.TrustRelease{entry(sumHex, bundle)}})
	if err != nil || res.Facts["release"] != "v0.21.0" || res.HPKEPublicKey == nil {
		t.Fatalf("listed release: %v %v", err, res)
	}
	// The list's floor above it: refused (rollback protection), as for a given bundle.
	if _, err := verifyWith(t, safety.TrustList{Seq: 3, VMReleaseFloor: "v0.21.1", Releases: []safety.TrustRelease{entry(sumHex, bundle)}}); err == nil ||
		!strings.Contains(err.Error(), "trust list's release") {
		t.Fatalf("listed release under the floor: %v", err)
	}
	// Another compose's bundle filed under this compose: it doesn't verify for the attested compose.
	if _, err := verifyWith(t, safety.TrustList{Seq: 3, Releases: []safety.TrustRelease{entry(sumHex, otherBundle)}}); err == nil ||
		!strings.Contains(err.Error(), "trust list's release") {
		t.Fatalf("another compose's bundle: %v", err)
	}
	// Only another compose listed: nothing to look up.
	if _, err := verifyWith(t, safety.TrustList{Seq: 3, Releases: []safety.TrustRelease{entry(hex.EncodeToString(other[:]), otherBundle)}}); err == nil ||
		!strings.Contains(err.Error(), "no release bundle given") {
		t.Fatalf("another compose listed: %v", err)
	}
	// A bad entry first, the good one after: the good one is used.
	if res, err := verifyWith(t, safety.TrustList{Seq: 3, Releases: []safety.TrustRelease{
		{Version: "v0.21.1", Commit: strings.Repeat("d", 40), ComposeSHA256: sumHex, Bundle: otherBundle}, entry(sumHex, bundle)}}); err != nil || res.Facts["release"] != "v0.21.0" {
		t.Fatalf("second entry: %v", err)
	}
	// A given bundle is still what is checked: a wrong one fails though the list has the right one.
	var st TrustState
	st.Take(signedList(t, admin, safety.TrustList{Seq: 3, Releases: []safety.TrustRelease{entry(sumHex, bundle)}}), 0, listNow)
	rc = boot(t)
	rc.p.Bundle = otherBundle
	p, _ := st.Apply(rc.p, listNow)
	if _, err := Verify(context.Background(), rc.a, rc.nonce, p); err == nil {
		t.Fatal("a wrong given bundle passed on the list's")
	}
}
