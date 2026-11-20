package kms

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/tacyhq/tacy/safety"
)

func TestShamirEveryThresholdSubset(t *testing.T) {
	secret := make([]byte, 32)
	rand.Read(secret)
	for _, c := range []struct{ n, t int }{{1, 1}, {3, 2}, {3, 3}, {5, 3}, {7, 4}} {
		shares, err := Split(secret, c.n, c.t, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		// Every subset of size >= t rebuilds the secret; every subset of size < t (t > 1) doesn't.
		for mask := 1; mask < 1<<c.n; mask++ {
			var sub []Share
			for i := 0; i < c.n; i++ {
				if mask&(1<<i) != 0 {
					sub = append(sub, shares[i])
				}
			}
			got, err := Combine(sub)
			if err != nil {
				t.Fatal(err)
			}
			if eq := bytes.Equal(got, secret); eq != (len(sub) >= c.t) {
				t.Fatalf("%d-of-%d with %d shares: equal=%v", c.t, c.n, len(sub), eq)
			}
		}
	}
}

func TestShamirRefusesBadInput(t *testing.T) {
	if _, err := Split([]byte{1}, 2, 3, rand.Reader); err == nil {
		t.Fatal("t > n accepted")
	}
	s, _ := Split([]byte{1, 2}, 3, 2, rand.Reader)
	if _, err := Combine([]Share{s[0], s[0]}); err == nil {
		t.Fatal("duplicate share accepted")
	}
	if _, err := Combine([]Share{s[0], {X: 0, Y: []byte{1, 2}}}); err == nil {
		t.Fatal("x = 0 accepted")
	}
}

func TestGFInverse(t *testing.T) {
	for a := 1; a < 256; a++ {
		if gfMul(byte(a), gfInv(byte(a))) != 1 {
			t.Fatalf("inverse of %d", a)
		}
	}
}

func TestDerivations(t *testing.T) {
	m := bytes.Repeat([]byte{7}, 32)
	id1, _ := DeriveID(m)
	id2, _ := DeriveID(m)
	if !bytes.Equal(id1, id2) {
		t.Fatal("KMS id isn't deterministic")
	}
	k, _ := DeriveKey(m, "agent-vm", "f_chat", "state/v1", 1)
	seen := map[string]string{hex.EncodeToString(k): "base"}
	for _, v := range []struct {
		app, firm, purpose string
		e                  uint32
	}{
		{"agent-vm2", "f_chat", "state/v1", 1}, {"agent-vm", "f_other", "state/v1", 1},
		{"agent-vm", "f_chat", "conn/v1", 1}, {"agent-vm", "f_chat", "state/v1", 2},
		// The separators keep "a"+"b\x00c" and "a\x00b"+"c" apart.
		{"agent-vm\x00f_chat", "", "state/v1", 1},
	} {
		k2, _ := DeriveKey(m, v.app, v.firm, v.purpose, v.e)
		if prev, dup := seen[hex.EncodeToString(k2)]; dup {
			t.Fatalf("%v gives the same key as %s", v, prev)
		}
		seen[hex.EncodeToString(k2)] = v.app
	}
	sk, _ := SecretsKey(m)
	if bytes.Equal(sk, k) || bytes.Equal(sk, id1.Seed()) {
		t.Fatal("secrets key isn't separate")
	}
	if _, err := DeriveKey(m[:31], "a", "f", "state/v1", 1); err == nil {
		t.Fatal("short master accepted")
	}
}

func TestSealOpenBothCurves(t *testing.T) {
	for _, c := range []ecdh.Curve{ecdh.X25519(), ecdh.P256()} {
		priv, _ := c.GenerateKey(rand.Reader)
		box, err := Seal(priv.PublicKey(), LabelShare, []byte("aad"), []byte("secret"))
		if err != nil {
			t.Fatal(err)
		}
		pt, err := Open(priv, LabelShare, []byte("aad"), box)
		if err != nil || string(pt) != "secret" {
			t.Fatalf("open: %v", err)
		}
		if _, err := Open(priv, LabelUnlock, []byte("aad"), box); err == nil {
			t.Fatal("opened under another label")
		}
		if _, err := Open(priv, LabelShare, []byte("other"), box); err == nil {
			t.Fatal("opened with other aad")
		}
		other, _ := c.GenerateKey(rand.Reader)
		if _, err := Open(other, LabelShare, []byte("aad"), box); err == nil {
			t.Fatal("opened with another key")
		}
	}
	p, _ := ecdh.P256().GenerateKey(rand.Reader)
	r, err := ParseRecipient(RecipientString(p.PublicKey()))
	if err != nil || !r.Equal(p.PublicKey()) {
		t.Fatal("recipient round trip")
	}
}

func TestAuditChain(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	var log []AuditEntry
	prev := ""
	for i, k := range []string{"start", "genesis", "release"} {
		e := AuditEntry{Seq: uint64(i + 1), Time: 100, Kind: k, OK: true, Detail: "d", Prev: prev}
		e.Hash = AuditHash(e)
		e.Sig = ed25519.Sign(priv, AuditSigMessage(e.Hash))
		prev = e.Hash
		log = append(log, e)
	}
	if head, err := VerifyLog(log, "", pub); err != nil || head != prev {
		t.Fatal(err)
	}
	for name, edit := range map[string]func(l []AuditEntry){
		"detail edited":   func(l []AuditEntry) { l[1].Detail = "x" },
		"entry dropped":   func(l []AuditEntry) { copy(l[1:], l[2:]) },
		"signature wrong": func(l []AuditEntry) { l[2].Sig = make([]byte, 64) },
		"outcome flipped": func(l []AuditEntry) { l[0].OK = false },
		// L6: a signature over the bare hash (no label) is not an audit signature.
		"unlabeled signature": func(l []AuditEntry) { l[1].Sig = ed25519.Sign(priv, []byte(l[1].Hash)) },
	} {
		c := append([]AuditEntry(nil), log...)
		edit(c)
		if _, err := VerifyLog(c, "", pub); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestVersions(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want int
		ok   bool
	}{{"v0.19.3", "v0.20.0", -1, true}, {"v1.0.0", "v0.99.99", 1, true}, {"v0.10.0", "v0.9.0", 1, true},
		{"v0.1.0", "v0.1.0", 0, true}, {"0.1.0", "v0.1.0", 0, false}, {"v0.1", "v0.1.0", 0, false}, {"v01.0.0", "v1.0.0", 0, false}} {
		got, ok := CompareVersions(c.a, c.b)
		if got != c.want || ok != c.ok {
			t.Errorf("%s vs %s: %d %v", c.a, c.b, got, ok)
		}
	}
}

func TestPolicyValidate(t *testing.T) {
	good := func() Policy {
		return Policy{Epoch: 1, Seq: 1, Floor: "v0.19.0", Apps: map[string]AppPolicy{"agent-vm": {Firm: "f_chat", Purposes: []string{"state/v1"}}},
			Releases: []ReleasePin{{App: "agent-vm", Version: "v0.19.3", AppComposeSHA256: strings.Repeat("a", 64)}},
			KMS:      []ReleasePin{{App: "kms", Version: "v0.1.0", AppComposeSHA256: strings.Repeat("b", 64)}}}
	}
	p := good()
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, edit := range map[string]func(p *Policy){
		"seq 0":            func(p *Policy) { p.Seq = 0 },
		"epoch 0":          func(p *Policy) { p.Epoch = 0 },
		"bad kms id":       func(p *Policy) { p.KMSID = "ed25519:short" },
		"bad kms floor":    func(p *Policy) { p.KMSFloor = "one" },
		"bad kms role":     func(p *Policy) { p.KMS[0].Role = "leader" },
		"role on a VM pin": func(p *Policy) { p.Releases[0].Role = RoleStandby },
		"bad floor":        func(p *Policy) { p.Floor = "latest" },
		"unknown purpose":  func(p *Policy) { p.Apps["agent-vm"] = AppPolicy{Firm: "f", Purposes: []string{"disk/v1"}} },
		"pin unknown app":  func(p *Policy) { p.Releases[0].App = "other" },
		"pin bad hash":     func(p *Policy) { p.Releases[0].AppComposeSHA256 = "ab" },
		"kms pin as app":   func(p *Policy) { p.KMS[0].App = "agent-vm" },
		"pinned twice":     func(p *Policy) { p.KMS[0].AppComposeSHA256 = p.Releases[0].AppComposeSHA256 },
		"app named kms":    func(p *Policy) { p.Apps["kms"] = AppPolicy{Firm: "f", Purposes: []string{"state/v1"}} },
		"bad worker key":   func(p *Policy) { p.WorkerKeys = []string{"ed25519:xx"} },
	} {
		p := good()
		edit(&p)
		if p.Validate() == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestAdminOpen(t *testing.T) {
	pub1, k1, _ := ed25519.GenerateKey(rand.Reader)
	pub2, k2, _ := ed25519.GenerateKey(rand.Reader)
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	a := AdminKeys{Keys: []ed25519.PublicKey{pub1, pub2}, Threshold: 2}
	doc := []byte(`{"seq":1,"values":{"A":"b"},"issued_at":"` + time.Now().UTC().Format(time.RFC3339) + `"}`)
	var d SecretsDoc
	e := safety.Sign(KindSecrets, doc, k1, k2)
	if err := a.Open(&e, KindSecrets, &d); err != nil || d.Values["A"] != "b" {
		t.Fatal(err)
	}
	e = safety.Sign(KindSecrets, doc, k1, other)
	if a.Open(&e, KindSecrets, &d) == nil {
		t.Fatal("one admin signature of two accepted")
	}
	e = safety.Sign(KindPolicy, doc, k1, k2)
	if a.Open(&e, KindSecrets, &d) == nil {
		t.Fatal("another kind accepted")
	}
	e = safety.Sign(KindSecrets, []byte(`{"seq":1,"values":{},"extra":1}`), k1, k2)
	if a.Open(&e, KindSecrets, &d) == nil {
		t.Fatal("unknown member accepted")
	}
	// One key signing twice is one signer; safety.Sign's form is what Signers checks.
	if e = safety.Sign(KindSecrets, doc, k1, k1); Signers(&e, a.Keys) != 1 || a.Open(&e, KindSecrets, &d) == nil {
		t.Fatal("a repeated signature counted twice")
	}
	if !a.SameKeys([]string{IDString(pub2), IDString(pub1)}, 2) || a.SameKeys([]string{IDString(pub1)}, 2) {
		t.Fatal("SameKeys")
	}
}
