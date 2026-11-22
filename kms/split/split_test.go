package split

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/tacyhq/tacy/kms"
	"github.com/tacyhq/tacy/safety"
)

func master(t *testing.T) ([]byte, string, ed25519.PublicKey) {
	t.Helper()
	m := make([]byte, kms.MasterSize)
	rand.Read(m)
	id, _ := kms.DeriveID(m)
	pub := id.Public().(ed25519.PublicKey)
	return m, kms.IDString(pub), pub
}

func holders(t *testing.T, ids ...string) ([]HolderRecipient, map[string]*ecdh.PrivateKey) {
	t.Helper()
	keys := map[string]*ecdh.PrivateKey{}
	var out []HolderRecipient
	for i, h := range ids {
		curve := ecdh.X25519()
		if i%2 == 1 {
			curve = ecdh.P256()
		}
		k, _ := curve.GenerateKey(rand.Reader)
		keys[h] = k
		out = append(out, HolderRecipient{Holder: h, Recipient: RecipientString(k.PublicKey())})
	}
	return out, keys
}

// Every threshold subset of a re-split rebuilds the same epoch root R_e (never M); fewer don't; the share set is
// signed by the KMS id and names R_e's root id.
func TestResplitCombines(t *testing.T) {
	for _, c := range []struct {
		ids []string
		t   int
	}{{[]string{"cloudflare", "vercel"}, 2}, {[]string{"cloudflare", "gcp", "vercel"}, 2}, {[]string{"a", "b", "c", "d", "e"}, 3}} {
		m, idStr, idPub := master(t)
		recips, keys := holders(t, c.ids...)
		ss, shares, err := Resplit(m, idStr, 1, 2, c.t, recips, time.Now(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		set, err := ss.Open(idPub)
		if err != nil {
			t.Fatal(err)
		}
		r1, _ := EpochRoot(m, 1)
		if rid, _ := RootID(r1); set.Threshold != c.t || len(set.Holders) != len(c.ids) || set.Root != rid {
			t.Fatalf("share set: %+v", set)
		}
		ys := map[string]kms.Share{}
		for _, s := range shares {
			y, err := OpenHolderShare(keys[s.Holder], s)
			if err != nil {
				t.Fatal(err)
			}
			e, _ := set.Holder(s.Holder)
			if Commitment(idStr, 1, 2, s.Holder, s.Index, y) != e.Commitment {
				t.Fatalf("%s's share doesn't match its commitment", s.Holder)
			}
			if bytes.Contains(ss.Doc, []byte(hex.EncodeToString(y))) {
				t.Fatal("the share set carries a share")
			}
			ys[s.Holder] = kms.Share{X: s.Index, Y: y}
		}
		// Every subset of size t.
		n := len(c.ids)
		for mask := 0; mask < 1<<n; mask++ {
			var parts []kms.Share
			for i := range n {
				if mask&(1<<i) != 0 {
					parts = append(parts, ys[c.ids[i]])
				}
			}
			if len(parts) == 0 {
				continue
			}
			got, _ := kms.Combine(parts)
			if bytes.Equal(got, m) {
				t.Fatal("the shares rebuilt M itself")
			}
			if ok := bytes.Equal(got, r1); ok != (len(parts) >= c.t) {
				t.Fatalf("%d of %d (threshold %d): rebuilt R_1 = %v", len(parts), n, c.t, ok)
			}
		}
		// A share opens only on its own holder's key.
		if len(c.ids) > 1 {
			if _, err := OpenHolderShare(keys[c.ids[1]], shares[0]); err == nil {
				t.Fatal("a share opened on another holder's key")
			}
		}
	}
}

func TestResplitRefuses(t *testing.T) {
	m, idStr, _ := master(t)
	_, otherID, _ := master(t)
	recips, _ := holders(t, "cloudflare", "vercel")
	if _, _, err := Resplit(m, otherID, 1, 2, 2, recips, time.Now(), rand.Reader); err == nil {
		t.Fatal("re-split under another KMS id (that would be a new KMS)")
	}
	if _, _, err := Resplit(m, idStr, 1, 1, 2, recips, time.Now(), rand.Reader); err == nil {
		t.Fatal("set 1 is the genesis's passphrase shares")
	}
	if _, _, err := Resplit(m, idStr, 1, 2, 1, recips, time.Now(), rand.Reader); err == nil {
		t.Fatal("1-of-2: each holder alone would hold M")
	}
	if _, _, err := Resplit(m, idStr, 1, 2, 3, recips, time.Now(), rand.Reader); err == nil {
		t.Fatal("3-of-2")
	}
	dup := []HolderRecipient{recips[0], {Holder: "cloudflare", Recipient: recips[1].Recipient}}
	if _, _, err := Resplit(m, idStr, 1, 2, 2, dup, time.Now(), rand.Reader); err == nil {
		t.Fatal("one holder twice")
	}
	if _, _, err := Resplit(m, idStr, 1, 2, 2, []HolderRecipient{recips[0], {Holder: "vercel", Recipient: "x25519:AAAA"}}, time.Now(), rand.Reader); err == nil {
		t.Fatal("a bad recipient")
	}
}

func TestShareSetTampered(t *testing.T) {
	m, idStr, idPub := master(t)
	recips, _ := holders(t, "cloudflare", "vercel")
	ss, _, err := Resplit(m, idStr, 1, 2, 2, recips, time.Now(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// Re-encoded (indented, as a file writer does) it still opens: the signed bytes are carried as bytes.
	pretty, _ := json.MarshalIndent(ss, "", "  ")
	var back SignedShareSet
	if err := json.Unmarshal(pretty, &back); err != nil {
		t.Fatal(err)
	}
	if _, err := back.Open(idPub); err != nil {
		t.Fatalf("a re-encoded share set: %v", err)
	}
	var set ShareSet
	json.Unmarshal(ss.Doc, &set)
	set.Threshold = 1
	doc, _ := json.Marshal(set)
	if _, err := (SignedShareSet{Doc: doc, Sig: ss.Sig}).Open(idPub); err == nil {
		t.Fatal("an edited share set opened")
	}
	_, _, other := master(t)
	if _, err := ss.Open(other); err == nil {
		t.Fatal("a share set opened under another KMS id")
	}
}

func TestBindAndNonces(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	now := time.Now()
	n1, _ := NewNonce(key, "cloudflare", now.Add(NonceTTL), rand.Reader)
	n2, _ := NewNonce(key, "vercel", now.Add(NonceTTL), rand.Reader)
	a, err := Bind([]HolderNonce{{"cloudflare", n1}, {"vercel", n2}})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := Bind([]HolderNonce{{"cloudflare", n1}})
	if bytes.Equal(a, b) || len(a) != 32 {
		t.Fatal("binding two nonces equals binding one")
	}
	for _, bad := range [][]HolderNonce{nil, {{"vercel", n2}, {"cloudflare", n1}}, {{"cloudflare", n1}, {"cloudflare", n2}},
		{{"cloudflare", strings.ToUpper(n1)}}, {{"Cloudflare", n1}}, {{"cloudflare", n1[:10]}}} {
		if _, err := Bind(bad); err == nil {
			t.Fatalf("Bind(%v) passed", bad)
		}
	}
	if _, err := CheckNonce(key, "cloudflare", n1, now); err != nil {
		t.Fatal(err)
	}
	if _, err := CheckNonce(key, "vercel", n1, now); err == nil {
		t.Fatal("cloudflare's nonce checked as vercel's")
	}
	if _, err := CheckNonce(key, "cloudflare", n1, now.Add(NonceTTL+time.Second)); err == nil {
		t.Fatal("an expired nonce checked")
	}
	other := make([]byte, 32)
	rand.Read(other)
	if _, err := CheckNonce(other, "cloudflare", n1, now); err == nil {
		t.Fatal("a nonce checked under another holder's key")
	}
	far, _ := NewNonce(key, "cloudflare", now.Add(time.Hour), rand.Reader)
	if _, err := CheckNonce(key, "cloudflare", far, now); err == nil {
		t.Fatal("a nonce valid for an hour checked")
	}
}

func TestPolicyValidate(t *testing.T) {
	now := time.Now()
	m, idStr, _ := master(t)
	mc := testMachineCert(t, m, idStr, "3e306e133b7fdaa7bb79f67634cb520c", now)
	base := func() UnlockPolicy {
		return UnlockPolicy{Policy: kms.Policy{KMSID: idStr, Epoch: 1, Seq: 1, IssuedAt: now, Floor: "v0.21.0"},
			Holders:      []HolderURL{{Holder: "cloudflare", URL: "https://keys-cf.tacy.io"}, {Holder: "vercel", URL: "https://x.vercel.app"}},
			MachineCerts: []safety.SignedMachineCert{mc}}
	}
	p := base()
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, edit := range map[string]func(*UnlockPolicy){
		"no KMS id":    func(p *UnlockPolicy) { p.KMSID = "" },
		"no holders":   func(p *UnlockPolicy) { p.Holders = nil },
		"plain http":   func(p *UnlockPolicy) { p.Holders[1].URL = "http://x.vercel.app" },
		"holder twice": func(p *UnlockPolicy) { p.Holders[1].Holder = "cloudflare" },
	} {
		p := base()
		edit(&p)
		if err := p.Validate(); err == nil {
			t.Fatalf("%s: validated", name)
		}
	}
	// Strict JSON: kms.Policy's fields inline, plus holders and the share sets; nothing else.
	b, _ := json.Marshal(base())
	var back UnlockPolicy
	if err := kms.Strict(b, &back); err != nil || back.KMSID != idStr || len(back.Holders) != 2 {
		t.Fatalf("round trip: %v", err)
	}
	if err := kms.Strict([]byte(strings.Replace(string(b), `"holders"`, `"extra":1,"holders"`, 1)), &back); err == nil {
		t.Fatal("an unknown member decoded")
	}
}
