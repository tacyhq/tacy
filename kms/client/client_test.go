package client

import (
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"testing"

	"github.com/tacyhq/tacy/kms"
	"github.com/tacyhq/tacy/proto"
)

// fakeKMS answers /v1/challenge and /v1/release as kmsd would, signing with sign (and edit changes the reply after
// signing, as an attacker in the path would).
type fakeKMS struct {
	nonce []byte
	sign  ed25519.PrivateKey
	edit  func(r *kms.ReleaseReply)
	keys  map[string][]byte
	// editCert changes a store certificate after signing (a KMS bug or an attacker inside the payload)
	editCert func(c *kms.StoreCert)
}

func (f *fakeKMS) Do(_ context.Context, method, path string, body []byte) ([]byte, error) {
	switch path {
	case "/v1/challenge":
		return json.Marshal(kms.Challenge{Nonce: hex.EncodeToString(f.nonce), Expires: 1})
	case "/v1/release":
		var req kms.ReleaseRequest
		if err := kms.Strict(body, &req); err != nil {
			return nil, err
		}
		var att proto.Attestation
		json.Unmarshal(req.Attestation, &att)
		kb, _ := hex.DecodeString(att.HPKEPublicKey)
		pub, err := ecdh.X25519().NewPublicKey(kb)
		if err != nil {
			return nil, err
		}
		lease := kms.Lease{ID: "l1", App: "agent-vm", Holder: req.Holder, Instance: "i1", Key: att.HPKEPublicKey, Seq: 1, Expires: 99}
		keys := map[string][]byte{}
		certs := map[string]kms.StoreCert{}
		for _, p := range req.Purposes {
			keys[p] = f.keys[p]
			if sk, err := kms.StoreAuthKey(f.keys[p]); err == nil && slices.Contains(kms.StorePurposes, p) {
				c := kms.StoreCert{App: "agent-vm", Firm: "f_chat", Epoch: 1, Purpose: p, Key: kms.IDString(sk.Public().(ed25519.PublicKey))}
				c.Sig = ed25519.Sign(f.sign, kms.StoreCertMessage(c))
				if f.editCert != nil {
					f.editCert(&c)
				}
				certs[p] = c
			}
		}
		pt, _ := json.Marshal(kms.ReleasePayload{App: "agent-vm", Firm: "f_chat", Release: req.Release, Epoch: 1, Keys: keys,
			Lease: lease, LeaseSecret: make([]byte, 32), Certs: certs})
		sealed, err := kms.Seal(pub, kms.LabelRelease, f.nonce, pt)
		if err != nil {
			return nil, err
		}
		ah := sha256.Sum256(req.Attestation)
		r := kms.ReleaseReply{Sealed: sealed, Lease: lease, LogSeq: 7,
			Sig: ed25519.Sign(f.sign, kms.ReleaseSigMessage(f.nonce, ah[:], sealed.Hash(), lease, 7))}
		if f.edit != nil {
			f.edit(&r)
		}
		return json.Marshal(r)
	}
	return nil, &RefusedError{Status: http.StatusNotFound, Reason: "no"}
}

func evidence(_ context.Context, rd []byte) (json.RawMessage, json.RawMessage, error) {
	return json.RawMessage(`{"quote":"00"}`), json.RawMessage(`{}`), nil
}

func newFake(t *testing.T) (*fakeKMS, ed25519.PublicKey) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	n := make([]byte, 32)
	rand.Read(n)
	k := make([]byte, 32)
	rand.Read(k)
	return &fakeKMS{nonce: n, sign: priv, keys: map[string][]byte{"state/v1": k}}, pub
}

func TestReleaseAcceptsOnlyThePinnedSigner(t *testing.T) {
	f, pinned := newFake(t)
	c, err := New(Config{KMSID: pinned, Transport: f, Evidence: evidence, Release: "v0.19.3"})
	if err != nil {
		t.Fatal(err)
	}
	k, err := c.Release(context.Background(), []string{"state/v1"})
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := k.Key("state/v1"); hex.EncodeToString(got) != hex.EncodeToString(f.keys["state/v1"]) || k.LogSeq != 7 {
		t.Fatal("keys")
	}
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	for name, edit := range map[string]func(r *kms.ReleaseReply){
		"unsigned":                 func(r *kms.ReleaseReply) { r.Sig = nil },
		"zero signature":           func(r *kms.ReleaseReply) { r.Sig = make([]byte, 64) },
		"signed by another key":    func(r *kms.ReleaseReply) { r.Sig = ed25519.Sign(other, []byte("x")) },
		"sealed payload swapped":   func(r *kms.ReleaseReply) { r.Sealed.CT[0] ^= 1 },
		"lease changed after sign": func(r *kms.ReleaseReply) { r.Lease.Instance = "i2" },
		"log seq changed":          func(r *kms.ReleaseReply) { r.LogSeq = 8 },
	} {
		f.edit = edit
		if _, err := c.Release(context.Background(), []string{"state/v1"}); !errors.Is(err, ErrBadSignature) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// A reply a different KMS signed properly is still not the pinned one's.
	f.edit = nil
	f.sign = other
	if _, err := c.Release(context.Background(), []string{"state/v1"}); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("other KMS: %v", err)
	}
}

// A state purpose's release carries the KMS id's certificate for its store-auth key; one that doesn't verify, names
// another key or another app is refused.
func TestReleaseStoreCerts(t *testing.T) {
	f, pinned := newFake(t)
	c, _ := New(Config{KMSID: pinned, Transport: f, Evidence: evidence})
	k, err := c.Release(context.Background(), []string{"state/v1"})
	if err != nil {
		t.Fatal(err)
	}
	sk, _ := kms.StoreAuthKey(f.keys["state/v1"])
	if cert := k.Certs["state/v1"]; cert.Key != kms.IDString(sk.Public().(ed25519.PublicKey)) || CheckStoreCert(cert, pinned) != nil {
		t.Fatalf("cert %+v", cert)
	}
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	otherKey, _, _ := ed25519.GenerateKey(rand.Reader)
	for name, edit := range map[string]func(c *kms.StoreCert){
		"forged": func(c *kms.StoreCert) { c.Sig = ed25519.Sign(other, kms.StoreCertMessage(*c)) },
		"another key": func(c *kms.StoreCert) {
			c.Key = kms.IDString(otherKey)
			c.Sig = ed25519.Sign(f.sign, kms.StoreCertMessage(*c))
		},
		"another app": func(c *kms.StoreCert) { c.App = "other"; c.Sig = ed25519.Sign(f.sign, kms.StoreCertMessage(*c)) },
	} {
		f.editCert = edit
		if _, err := c.Release(context.Background(), []string{"state/v1"}); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestReleaseRefusesOtherPurposes(t *testing.T) {
	f, pinned := newFake(t)
	f.keys["conn/v1"] = make([]byte, 32)
	c, _ := New(Config{KMSID: pinned, Transport: f, Evidence: evidence})
	// The fake answers what is asked; a short key for an asked purpose is refused.
	f.keys["conn/v1"] = make([]byte, 16)
	if _, err := c.Release(context.Background(), []string{"state/v1", "conn/v1"}); err == nil {
		t.Fatal("short key accepted")
	}
}

func TestNewNeedsAPin(t *testing.T) {
	if _, err := New(Config{Transport: &fakeKMS{}, Evidence: evidence}); err == nil {
		t.Fatal("client without a pinned KMS id")
	}
}

func TestStatic(t *testing.T) {
	s := Static{Keys: &Keys{App: "agent-vm", Keys: map[string][]byte{"state/v1": {1}, "conn/v1": {2}}}}
	k, err := s.Release(context.Background(), []string{"state/v1"})
	if err != nil || len(k.Keys) != 1 {
		t.Fatalf("static: %v", err)
	}
	if _, err := s.Release(context.Background(), []string{"notify/v1"}); err == nil {
		t.Fatal("static gave a purpose it doesn't have")
	}
	var _ KeySource = s
	var _ KeySource = (*Client)(nil)
}
