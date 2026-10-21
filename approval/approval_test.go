package approval_test

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/tacyhq/tacy/approval"
	"github.com/tacyhq/tacy/approval/approvaltest"
	"github.com/tacyhq/tacy/identity"
)

func TestClasses(t *testing.T) {
	for _, c := range []struct {
		action          string
		tainted, listed bool
		want            bool
	}{
		{"sink.post", false, false, true},  // a send: always
		{"mail.send", false, false, true},  // unknown to this release: a send (fail closed)
		{"sink.put", false, false, false},  // a change inside scopes, untainted: the policy's call
		{"sink.put", true, false, true},    // tainted change: held
		{"sink.put", false, true, true},    // the policy lists it
		{"web.search", true, false, false}, // a read that sends data out: a permission, not approval
		{"web.search", false, true, true},
		{"task.wait", true, false, false},
	} {
		if got := approval.Needs(approval.ClassOf(c.action), c.tainted, c.listed); got != c.want {
			t.Errorf("%s tainted=%v listed=%v: %v", c.action, c.tainted, c.listed, got)
		}
	}
}

// The effect hash is over canonical JSON: the browser recomputes it from the effect it shows.
func TestEffectHashVector(t *testing.T) {
	a, err := approval.Canonical([]byte(` { "to" : "a@example.com", "body":"hié", "n": 1.0 } `))
	if err != nil {
		t.Fatal(err)
	}
	if string(a) != `{"body":"hié","n":1,"to":"a@example.com"}` {
		t.Fatalf("canonical %s", a)
	}
	h := sha256.Sum256(append([]byte("tacy-effect/v1\x00"), a...))
	if got := approval.EffectHash(a); got != base16(h[:]) {
		t.Fatalf("hash %s", got)
	}
	for _, bad := range []string{``, `[]`, `"x"`, `{"a":1,"a":2}`, `{"a":1} x`, "{\"a\":\"\xff\"}"} {
		if _, err := approval.Canonical([]byte(bad)); err == nil {
			t.Errorf("canonical(%q) accepted", bad)
		}
	}
}

func base16(b []byte) string {
	const hx = "0123456789abcdef"
	out := make([]byte, 0, 2*len(b))
	for _, c := range b {
		out = append(out, hx[c>>4], hx[c&15])
	}
	return string(out)
}

const firm, space = "f_test", "s_test"

func record(t *testing.T, approvers ...string) approval.Record {
	eff, _ := approval.Canonical([]byte(`{"action":"sink.post","to":"client@example.com","body":"hello"}`))
	return approval.Record{ID: approval.ID([]byte("k"), "tk_1", "s2.a0"), Firm: firm, Space: space, Task: "tk_1", Request: "s2.a0",
		Action: "sink.post", Effect: eff, EffectHash: approval.EffectHash(eff), Approvers: approvers,
		ExpiresAt: time.Now().Add(time.Hour).UTC().Truncate(time.Second)}
}

func TestCheck(t *testing.T) {
	var dir identity.Static
	alice := approvaltest.NewPerson(t, &dir, firm, space)
	bob := approvaltest.NewPerson(t, &dir, firm, space)
	cfg := approval.Config{Dir: &dir, RP: approvaltest.RP}
	r := record(t, alice.ID)
	ok := approvaltest.PayloadFor(r, alice.ID, approval.Approve)
	if p, err := approval.Check(alice.Sign(t, ok, approvaltest.Options{}), r.Expect(), cfg); err != nil || p.Decision != approval.Approve {
		t.Fatalf("good approval: %v", err)
	}
	deny := approvaltest.PayloadFor(r, alice.ID, approval.Deny)
	if p, err := approval.Check(alice.Sign(t, deny, approvaltest.Options{}), r.Expect(), cfg); err != nil || p.Decision != approval.Deny {
		t.Fatalf("deny: %v", err)
	}
	changed := ok
	changed.EffectHash = strings.Repeat("0", 64)
	other := ok
	other.Request = "s3.a0"
	byBob := approvaltest.PayloadFor(r, bob.ID, approval.Approve)
	wrongDecision := ok
	wrongDecision.Decision = "maybe"
	expires := ok
	expires.ExpiresAt = ok.ExpiresAt.Add(time.Hour)
	for name, sub := range map[string]*approval.Submission{
		"changed effect":          alice.Sign(t, changed, approvaltest.Options{}),
		"other request":           alice.Sign(t, other, approvaltest.Options{}),
		"not an approver":         bob.Sign(t, byBob, approvaltest.Options{}),
		"bad decision":            alice.Sign(t, wrongDecision, approvaltest.Options{}),
		"another expiry":          alice.Sign(t, expires, approvaltest.Options{}),
		"wrong origin":            alice.Sign(t, ok, approvaltest.Options{Origin: "https://evil.example"}),
		"wrong rpId":              alice.Sign(t, ok, approvaltest.Options{RPID: "evil.example"}),
		"no user verification":    alice.Sign(t, ok, approvaltest.Options{NoUV: true}),
		"registration type":       alice.Sign(t, ok, approvaltest.Options{Type: "webauthn.create"}),
		"bob's passkey":           withCert(bob.Sign(t, ok, approvaltest.Options{}), alice.Cert),
		"alice's cert, bob's key": withCert(bob.SignBytes(t, mustJSON(ok), approvaltest.Options{}), alice.Cert),
		"extra member":            alice.SignBytes(t, []byte(strings.Replace(string(mustJSON(ok)), `{"type"`, `{"x":1,"type"`, 1)), approvaltest.Options{}),
	} {
		if _, err := approval.Check(sub, r.Expect(), cfg); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// A signature over one payload doesn't carry another.
	sub := alice.Sign(t, ok, approvaltest.Options{})
	sub.Payload = mustJSON(deny)
	if _, err := approval.Check(sub, r.Expect(), cfg); err == nil {
		t.Error("swapped payload accepted")
	}
	// Expired: refused even with a good signature.
	late := cfg
	late.Now = func() time.Time { return r.ExpiresAt }
	if _, err := approval.Check(alice.Sign(t, ok, approvaltest.Options{}), r.Expect(), late); !errors.Is(err, approval.ErrExpired) {
		t.Fatalf("expired: %v", err)
	}
	// Revoked or gone from the space: the certificate no longer verifies.
	dir.Revoke(firm, alice.ID)
	if _, err := approval.Check(alice.Sign(t, ok, approvaltest.Options{}), r.Expect(), cfg); err == nil {
		t.Fatal("revoked approver accepted")
	}
	// No directory on the VM: nothing verifies (fail closed).
	if _, err := approval.Check(bob.Sign(t, byBob, approvaltest.Options{}), record(t, bob.ID).Expect(), approval.Config{RP: approvaltest.RP}); err == nil {
		t.Fatal("no directory: accepted")
	}
}

func withCert(s *approval.Submission, c approval.SignedCert) *approval.Submission {
	s.Cert = c
	return s
}

func mustJSON(p approval.Payload) []byte {
	p.Type = approval.PayloadType
	b, _ := json.Marshal(p)
	return b
}

// Ed25519 and RSA passkeys verify too; small RSA keys and other curves don't load.
func TestOtherPasskeyAlgorithms(t *testing.T) {
	challenge := []byte("challenge")
	cd, _ := json.Marshal(map[string]any{"type": "webauthn.get", "challenge": base64.RawURLEncoding.EncodeToString(challenge),
		"origin": approvaltest.Origin})
	rp := sha256.Sum256([]byte(approvaltest.RPID))
	ad := append(rp[:], 0x05, 0, 0, 0, 1)
	cdh := sha256.Sum256(cd)
	signed := append(append([]byte(nil), ad...), cdh[:]...)
	digest := sha256.Sum256(signed)

	epub, epriv, _ := ed25519.GenerateKey(nil)
	a := approval.Assertion{AuthenticatorData: ad, ClientDataJSON: cd, Signature: ed25519.Sign(epriv, signed)}
	spki, _ := x509.MarshalPKIXPublicKey(epub)
	k, err := approval.ParsePasskeyKey(spki)
	if err != nil || a.Verify(k, challenge, approvaltest.RP) != nil {
		t.Fatalf("ed25519: %v", err)
	}
	rk, _ := rsa.GenerateKey(rand.Reader, 2048)
	sig, _ := rsa.SignPKCS1v15(rand.Reader, rk, crypto.SHA256, digest[:])
	a.Signature = sig
	spki, _ = x509.MarshalPKIXPublicKey(&rk.PublicKey)
	k, err = approval.ParsePasskeyKey(spki)
	if err != nil || a.Verify(k, challenge, approvaltest.RP) != nil {
		t.Fatalf("rsa: %v", err)
	}
	if a.Verify(k, []byte("other"), approvaltest.RP) == nil {
		t.Fatal("other challenge")
	}
	small, _ := rsa.GenerateKey(rand.Reader, 1024)
	spki, _ = x509.MarshalPKIXPublicKey(&small.PublicKey)
	if _, err := approval.ParsePasskeyKey(spki); err == nil {
		t.Fatal("1024-bit RSA accepted")
	}
	if _, err := approval.ParsePasskeyKey([]byte("junk")); err == nil {
		t.Fatal("junk accepted")
	}
}

func TestIDsAreDerived(t *testing.T) {
	a, b := approval.ID([]byte("k"), "tk_1", "r1"), approval.ID([]byte("k"), "tk_1", "r1")
	if a != b || !identity.ValidID("ap", a) || a == approval.ID([]byte("k"), "tk_1", "r2") || a == approval.ID([]byte("j"), "tk_1", "r1") {
		t.Fatalf("ids %s %s", a, b)
	}
	if approval.ID([]byte("k"), "ab", "c") == approval.ID([]byte("k"), "a", "bc") {
		t.Fatal("parts not length-prefixed")
	}
}

func TestMemStore(t *testing.T) {
	approvaltest.RunStore(t, func(*testing.T) approval.Store { return approval.NewMemStore() })
}

// Every action the chat release's ceiling allows has its own class: one missing falls to Send, which needs an
// approver, and the chat VM has none (v0.13.0's files.list and files.read were missing: every review was refused).
func TestReleaseActionsClassified(t *testing.T) {
	for _, c := range []struct {
		action string
		want   approval.Class
	}{{"web.search", approval.ReadOut}, {"web.fetch", approval.ReadOut}, {"web.images", approval.ReadOut},
		{"files.list", approval.Read}, {"files.read", approval.Read}} {
		if got := approval.ClassOf(c.action); got != c.want {
			t.Errorf("%s: %s, want %s", c.action, got, c.want)
		}
	}
}
