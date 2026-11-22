package verifier

import (
	"crypto/ed25519"
	"strings"
	"testing"
	"time"

	"github.com/tacyhq/tacy/safety"
)

// Trust lists don't expire (2026-11-20): a list without an expiry is good years later, and a newer seq is
// how anything is withdrawn. The build's floor seq refuses older lists even on a fresh install. A list signed
// earlier with an expiry keeps it.
func TestTrustListNoExpiryAndFloorSeq(t *testing.T) {
	admin := testAdmin(t)
	l := safety.TrustList{Type: safety.TrustListType, Seq: 5, IssuedAt: listNow.Add(-time.Hour),
		KMSIDs: map[string]string{safety.KeyString(make(ed25519.PublicKey, 32)): "Tacy KMS (test)"}}
	env := signedList(t, admin, l)
	if got, err := ParseTrustList(env, 0, listNow.Add(5*365*24*time.Hour)); err != nil || !got.Expires.IsZero() {
		t.Fatalf("a list without expiry, five years on: %v", err)
	}
	if info := TrustInfoOf(&l, false); info.Expires != "" {
		t.Fatalf("no expiry to show: %q", info.Expires)
	}
	if _, err := ParseTrustList(env, 6, listNow); err == nil {
		t.Fatal("an older seq than one taken")
	}
	old := TrustListFloorSeq
	TrustListFloorSeq = 6
	t.Cleanup(func() { TrustListFloorSeq = old })
	if _, err := ParseTrustList(env, 0, listNow); err == nil || !strings.Contains(err.Error(), "older than list 6") {
		t.Fatalf("below the bundled floor seq on a fresh install: %v", err)
	}
	TrustListFloorSeq = old
	dated := l
	dated.Seq, dated.Expires = 7, listNow.Add(24*time.Hour)
	if _, err := ParseTrustList(signedList(t, admin, dated), 0, listNow.Add(48*time.Hour)); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("a list signed with an expiry keeps it: %v", err)
	}
}
