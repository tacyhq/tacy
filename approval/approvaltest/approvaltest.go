// Package approvaltest has test helpers for approve before send: a virtual authenticator (a passkey with its
// identity and certificate, making WebAuthn assertions the way a browser would) and the shared Store tests. Tests
// only; nothing in the VM's binaries imports it.
package approvaltest

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json/v2"
	"testing"
	"time"

	"github.com/tacyhq/tacy/approval"
	"github.com/tacyhq/tacy/identity"
)

// Origin and RPID the helpers sign for (the release pins https://chat.tacy.io and tacy.io).
const (
	Origin = "https://chat.tacy.io"
	RPID   = "tacy.io"
)

// RP is the relying party the helpers' assertions are for.
var RP = approval.RP{ID: RPID, Origins: []string{Origin}}

// Person is someone with an identity key and one passkey (P-256, as most authenticators make).
type Person struct {
	ID       string // i_
	Identity ed25519.PrivateKey
	Passkey  crypto.Signer
	CredID   string
	Cert     approval.SignedCert
}

// NewPerson makes a person in firm with an identity and a certified passkey, and adds them to dir holding spaces.
func NewPerson(t testing.TB, dir *identity.Static, firm string, spaces ...string) *Person {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	idb := make([]byte, 16)
	rand.Read(idb)
	p := &Person{ID: identity.IDFrom("i", idb), Identity: priv}
	pk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p.Passkey = pk
	cred := make([]byte, 16)
	rand.Read(cred)
	p.CredID = base64.RawURLEncoding.EncodeToString(cred)
	spki, err := x509.MarshalPKIXPublicKey(pk.Public())
	if err != nil {
		t.Fatal(err)
	}
	p.Cert, err = approval.SignCert(approval.Cert{Firm: firm, Identity: p.ID, Credential: p.CredID, Key: spki,
		IssuedAt: time.Now().UTC().Truncate(time.Second)}, priv)
	if err != nil {
		t.Fatal(err)
	}
	if dir != nil {
		dir.Add(firm, p.ID, pub, spaces...)
	}
	return p
}

// Options change what an assertion says (to make bad ones).
type Options struct {
	Origin string // "": Origin
	RPID   string // "": RPID
	NoUV   bool   // user not verified
	Type   string // "": webauthn.get
}

// Sign makes the payload's bytes and a submission for it, as the browser would after the person's touch.
func (p *Person) Sign(t testing.TB, pl approval.Payload, o Options) *approval.Submission {
	t.Helper()
	pl.Type = approval.PayloadType
	b, err := json.Marshal(pl)
	if err != nil {
		t.Fatal(err)
	}
	return p.SignBytes(t, b, o)
}

// SignBytes is Sign for payload bytes as given.
func (p *Person) SignBytes(t testing.TB, payload []byte, o Options) *approval.Submission {
	t.Helper()
	if o.Origin == "" {
		o.Origin = Origin
	}
	if o.RPID == "" {
		o.RPID = RPID
	}
	if o.Type == "" {
		o.Type = "webauthn.get"
	}
	cd, _ := json.Marshal(map[string]any{"type": o.Type, "challenge": base64.RawURLEncoding.EncodeToString(approval.Challenge(payload)),
		"origin": o.Origin, "crossOrigin": false})
	rp := sha256.Sum256([]byte(o.RPID))
	flags := byte(0x01 | 0x04)
	if o.NoUV {
		flags = 0x01
	}
	ad := append(rp[:], flags, 0, 0, 0, 0)
	cdh := sha256.Sum256(cd)
	digest := sha256.Sum256(append(append([]byte(nil), ad...), cdh[:]...))
	sig, err := p.Passkey.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	return &approval.Submission{Payload: payload, Assertion: approval.Assertion{CredentialID: p.CredID, AuthenticatorData: ad,
		ClientDataJSON: cd, Signature: sig}, Cert: p.Cert}
}

// PayloadFor is the payload that decides r.
func PayloadFor(r approval.Record, approver, decision string) approval.Payload {
	return approval.Payload{Approval: r.ID, Firm: r.Firm, Space: r.Space, Task: r.Task, Request: r.Request, Action: r.Action,
		EffectHash: r.EffectHash, Decision: decision, Approver: approver, ExpiresAt: r.ExpiresAt}
}

// RunStore checks a Store: held once per id, compare-and-swap moves, listing by state, deletion per task.
func RunStore(t *testing.T, newStore func(t *testing.T) approval.Store) {
	s := newStore(t)
	exp := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	r := approval.Record{ID: "ap_1", Firm: "f_a", Space: "s_a", Task: "tk_1", Request: "r1", Action: "sink.post",
		Effect: []byte(`{"a":1}`), EffectHash: "ab", Approvers: []string{"i_x"}, ExpiresAt: exp, CreatedAt: exp.Add(-time.Hour)}
	got, fresh, err := s.PutApproval(r)
	if err != nil || !fresh || got.State != approval.StateHeld {
		t.Fatalf("put: %+v %v %v", got, fresh, err)
	}
	r2 := r
	r2.ExpiresAt = exp.Add(time.Hour)
	got, fresh, err = s.PutApproval(r2)
	if err != nil || fresh || !got.ExpiresAt.Equal(exp) {
		t.Fatalf("second put must return the first: %+v %v %v", got, fresh, err)
	}
	if err := s.MoveApproval("ap_1", approval.StateHeld, approval.StateSent, nil); err != approval.ErrState {
		t.Fatalf("held -> sent: %v", err)
	}
	if err := s.MoveApproval("ap_1", approval.StateHeld, approval.StateApproved, []byte(`{"d":1}`)); err != nil {
		t.Fatal(err)
	}
	if err := s.MoveApproval("ap_1", approval.StateHeld, approval.StateApproved, nil); err != approval.ErrState {
		t.Fatalf("decided twice: %v", err)
	}
	if rs, _ := s.Approvals(approval.StateHeld); len(rs) != 0 {
		t.Fatalf("held: %+v", rs)
	}
	for _, mv := range [][2]string{{approval.StateApproved, approval.StateSending}, {approval.StateSending, approval.StateUnknown}} {
		if err := s.MoveApproval("ap_1", mv[0], mv[1], nil); err != nil {
			t.Fatal(mv, err)
		}
	}
	rec, err := s.Approval("ap_1")
	if err != nil || rec == nil || rec.State != approval.StateUnknown || string(rec.Decision) != `{"d":1}` ||
		string(rec.Effect) != `{"a":1}` || len(rec.Approvers) != 1 || rec.Approvers[0] != "i_x" || !rec.ExpiresAt.Equal(exp) {
		t.Fatalf("record %+v %v", rec, err)
	}
	r3 := r
	r3.ID, r3.Task = "ap_2", "tk_2"
	s.PutApproval(r3)
	if rs, _ := s.Approvals(approval.StateHeld, approval.StateUnknown); len(rs) != 2 || rs[0].ID != "ap_1" {
		t.Fatalf("list: %+v", rs)
	}
	if err := s.DeleteApprovals("tk_1"); err != nil {
		t.Fatal(err)
	}
	if rec, _ := s.Approval("ap_1"); rec != nil {
		t.Fatal("not deleted")
	}
	if rec, _ := s.Approval("ap_2"); rec == nil {
		t.Fatal("other task deleted")
	}
}
