package vault

import (
	"crypto/ecdh"
	"encoding/hex"
	"encoding/json/v2"
	"os"
	"testing"
	"time"
)

// TestRunCredentialGoldenVector: the per-task box the client seals (packages/client-core agent/connections.ts
// sealMailCredential; runauth/testdata/v2-mail-credential-identity.json) opens in the
// vault with the vault key, for its space, identity and start key, at its time; the same box for another start key,
// space, identity (review 2, L5: another person's task in a shared space) or expiry doesn't, and neither does the
// first vector's box (v2-mail-credential.json, made before the identity was in the AAD).
func TestRunCredentialGoldenVector(t *testing.T) {
	b, err := os.ReadFile("../runauth/testdata/v2-mail-credential-identity.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Credential struct {
			VaultPrivate string `json:"vault_private"`
			SealKey      string `json:"seal_key"`
			Space        string `json:"space"`
			Identity     string `json:"identity"`
			Other        string `json:"other_identity"`
			StartKey     string `json:"start_key"`
			StartKeyHash string `json:"start_key_sha256"`
			Now          int64  `json:"now"`
			Expires      int64  `json:"expires"`
			AADHex       string `json:"aad_hex"`
			Wire         struct {
				Connection string `json:"connection"`
				Expires    int64  `json:"expires"`
				Sealed     Sealed `json:"sealed"`
			} `json:"wire"`
		} `json:"credential"`
	}
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	c := f.Credential
	if KeyHash(c.StartKey) != c.StartKeyHash {
		t.Fatalf("key hash %s", KeyHash(c.StartKey))
	}
	if got := hex.EncodeToString(RunCredAAD(c.Space, c.Identity, ConnEmail, c.StartKeyHash, c.Expires)); got != c.AADHex {
		t.Fatalf("aad %s", got)
	}
	pk, _ := hex.DecodeString(c.VaultPrivate)
	k, err := ecdh.X25519().NewPrivateKey(pk)
	if err != nil {
		t.Fatal(err)
	}
	v, _ := New(nil, nil, nil)
	v.now = func() time.Time { return time.UnixMilli(c.Now) }
	if err := v.EnableConnsKey(nil, k); err != nil {
		t.Fatal(err)
	}
	if v.SealKey() != c.SealKey {
		t.Fatalf("seal key %s", v.SealKey())
	}
	g := RunGrant{Task: "tk_golden", Space: c.Space, Identity: c.Identity, Connection: c.Wire.Connection, KeyHash: KeyHash(c.StartKey), Expires: c.Wire.Expires,
		Sealed: c.Wire.Sealed}
	for name, edit := range map[string]func(g *RunGrant){
		"another start key": func(g *RunGrant) { g.KeyHash = KeyHash("another") },
		"another space":     func(g *RunGrant) { g.Space = "s_aebagbafaydqqcikbmga2dqpcb" },
		"another expiry":    func(g *RunGrant) { g.Expires-- },
		"another identity":  func(g *RunGrant) { g.Identity = c.Other },
		"no identity":       func(g *RunGrant) { g.Identity = "" },
	} {
		bad := g
		edit(&bad)
		if _, err := v.RunCredPut(bad); err == nil {
			t.Errorf("%s: opened", name)
		}
	}
	// The first vector (no identity in its AAD): the same keys and login, refused with or without an identity.
	ob, err := os.ReadFile("../runauth/testdata/v2-mail-credential.json")
	if err != nil {
		t.Fatal(err)
	}
	var old struct {
		Credential struct {
			Wire struct {
				Sealed Sealed `json:"sealed"`
			} `json:"wire"`
		} `json:"credential"`
	}
	if err := json.Unmarshal(ob, &old); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{c.Identity, ""} {
		o := g
		o.Sealed, o.Identity = old.Credential.Wire.Sealed, id
		if _, err := v.RunCredPut(o); err == nil {
			t.Errorf("the box made without an identity opened (identity %q)", id)
		}
	}
	info, err := v.RunCredPut(g)
	if err != nil || info.Host != "imap.gmail.com" || info.Username != "person@example.com" {
		t.Fatalf("the client's box: %+v %v", info, err)
	}
}
