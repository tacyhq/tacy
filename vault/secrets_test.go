package vault

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func pushVault(t *testing.T) (*Vault, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	v, err := New(nil, ChatGrants(""), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := v.EnableSecretsPush(pub); err != nil {
		t.Fatal(err)
	}
	return v, priv
}

var pushKeys = map[string]string{"TINFOIL_API_KEY": "tf-canary-0123456789", "EXA_API_KEY": "exa-canary-0123456789",
	"TAVILY_API_KEY": "tvly-canary-0123456789"}

const pushToken = "run-token-canary-0123456789abcdef"

func signer(k ed25519.PrivateKey) func([]byte) []byte {
	return func(m []byte) []byte { return ed25519.Sign(k, m) }
}

// A push signed by the pinned key, sealed to this boot's key, opens: the keys lease, the token's hash comes back.
func TestSecretsPush(t *testing.T) {
	v, k := pushVault(t)
	lease := Request{Secret: "EXA_API_KEY", Connector: "web", Host: "api.exa.ai", Task: "t", Action: "a"}
	if _, _, err := v.Lease(lease); err != ErrNotSet {
		t.Fatalf("before the push: %v, want ErrNotSet", err)
	}
	if st := v.SecretsStatus(); st.TokenSHA256 != "" || len(st.Names) != 0 {
		t.Fatalf("status before the push: %+v", st)
	}
	p, err := SealSecrets(v.SecretsKey(), time.Now().Unix(), pushKeys, pushToken, signer(k))
	if err != nil {
		t.Fatal(err)
	}
	res, err := v.PutSecrets(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Names) != 3 || !TokenMatches(res.TokenSHA256, pushToken) || TokenMatches(res.TokenSHA256, pushToken+"x") {
		t.Fatalf("result %+v", res)
	}
	if bytes.Contains([]byte(res.TokenSHA256), []byte(pushToken)) {
		t.Fatal("the token itself in the result")
	}
	val, _, err := v.Lease(lease)
	if err != nil || string(val) != pushKeys["EXA_API_KEY"] {
		t.Fatalf("lease after the push: %q %v", val, err)
	}
	if st := v.SecretsStatus(); st.TokenSHA256 != res.TokenSHA256 {
		t.Fatalf("status after: %+v", st)
	}
}

// Every push that isn't ours is refused and changes nothing (a push to an unverified or another VM is the
// relay's side, the chat's vm-secrets.test.ts; here: the vault's own checks).
func TestSecretsPushRefused(t *testing.T) {
	v, k := pushVault(t)
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now().Unix()
	other2, _ := pushVault(t) // another boot's key
	cases := []struct {
		name string
		make func() SecretsPush
		want error
	}{
		{"another signer", func() SecretsPush {
			p, _ := SealSecrets(v.SecretsKey(), now, pushKeys, pushToken, signer(other))
			return p
		}, ErrSecretsSig},
		{"another boot's key", func() SecretsPush {
			p, _ := SealSecrets(other2.SecretsKey(), now, pushKeys, pushToken, signer(k))
			return p
		}, ErrSecretsStale},
		{"old", func() SecretsPush {
			p, _ := SealSecrets(v.SecretsKey(), now-3600, pushKeys, pushToken, signer(k))
			return p
		}, ErrSecretsTime},
		{"a secret without a grant", func() SecretsPush {
			p, _ := SealSecrets(v.SecretsKey(), now, map[string]string{"AWS_SECRET": "x"}, pushToken, signer(k))
			return p
		}, ErrSecretsSealed},
		{"a mail password", func() SecretsPush {
			p, _ := SealSecrets(v.SecretsKey(), now, map[string]string{ConnSecret: "x"}, pushToken, signer(k))
			return p
		}, ErrSecretsSealed},
		{"no token", func() SecretsPush {
			p, _ := SealSecrets(v.SecretsKey(), now, pushKeys, "", signer(k))
			return p
		}, ErrSecretsSealed},
		{"tampered ct, signed again", func() SecretsPush {
			p, _ := SealSecrets(v.SecretsKey(), now, pushKeys, pushToken, signer(k))
			p.CT[0] ^= 1
			p.Sig = ed25519.Sign(k, SecretsSignedBytes(p.Key, p.At, p.Enc, p.CT))
			return p
		}, ErrSecretsSealed},
		{"time moved, signature not", func() SecretsPush {
			p, _ := SealSecrets(v.SecretsKey(), now, pushKeys, pushToken, signer(k))
			p.At++
			return p
		}, ErrSecretsSig},
	}
	for _, c := range cases {
		if _, err := v.PutSecrets(c.make()); err != c.want {
			t.Errorf("%s: %v, want %v", c.name, err, c.want)
		}
	}
	if n := v.Names(); len(n) != 0 {
		t.Fatalf("refused pushes set %v", n)
	}
	off, _ := New(nil, ChatGrants(""), nil)
	if _, err := off.PutSecrets(SecretsPush{}); err != ErrSecretsOff {
		t.Fatalf("without EnableSecretsPush: %v", err)
	}
}

// Over the wire, as gatewayd passes it on.
func TestSecretsPushWire(t *testing.T) {
	v, k := pushVault(t)
	path := filepath.Join(t.TempDir(), "v.sock")
	l, err := Listen(path)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go v.Serve(l, -1)
	c := &Client{Path: path}
	ctx := context.Background()
	a := c.Secrets(ctx, &SecretsCall{Op: "key"})
	if a.Error != "" || a.Key != v.SecretsKey() {
		t.Fatalf("key: %+v", a)
	}
	if a := c.Secrets(ctx, &SecretsCall{Op: "status"}); a.Error != "" || a.Secrets == nil || a.Secrets.TokenSHA256 != "" {
		t.Fatalf("status before: %+v", a)
	}
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	bad, _ := SealSecrets(a.Key, time.Now().Unix(), pushKeys, pushToken, signer(other))
	if a := c.Secrets(ctx, &SecretsCall{Op: "put", Push: &bad}); a.Error != ErrSecretsSig.Error() {
		t.Fatalf("forged put: %+v", a)
	}
	p, _ := SealSecrets(a.Key, time.Now().Unix(), pushKeys, pushToken, signer(k))
	if a := c.Secrets(ctx, &SecretsCall{Op: "put", Push: &p}); a.Error != "" || a.Secrets == nil || !TokenMatches(a.Secrets.TokenSHA256, pushToken) {
		t.Fatalf("put: %+v", a)
	}
	if a := c.Secrets(ctx, &SecretsCall{Op: "status"}); a.Secrets == nil || len(a.Secrets.Names) != 3 {
		t.Fatalf("status after: %+v", a)
	}
}

// The bytes the push key signs and the box's AAD, fixed (the chat's test/unit/vm-secrets.test.ts checks the Worker
// builds the same).
func TestSecretsWireVector(t *testing.T) {
	key := "x25519:" + strings.Repeat("A", 43) + "="
	want := "tacy/v2/secrets-push/v1\x00" + key + "\x001763600000\x00" +
		"5fb2ab76ed9bda034b192c48c7069359252fccda168d925acc0ae7d316c0b53e\x00" + // sha256("enc")
		"f8dcb34308e5c69f46a33cafa62bd922476b18c78a114eb144e34a5e374f7d60" // sha256("ct")
	if got := string(SecretsSignedBytes(key, 1763600000, []byte("enc"), []byte("ct"))); got != want {
		t.Fatalf("signed bytes %q", got)
	}
	if string(SecretsAAD(key, 1763600000)) != "tacy/v2/secrets\x00"+key+"\x001763600000" {
		t.Fatal("aad")
	}
}

// -conn-wipe (RELEASE-QUEUE): the old plaintext file and a save's temporaries go; a missing file is fine.
func TestWipeConnFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "connections.json")
	os.WriteFile(path, []byte(`{"version":1,"connections":[{"password":"app-password-canary"}]}`), 0o600)
	os.WriteFile(filepath.Join(dir, ".connections-123"), []byte("app-password-canary"), 0o600)
	os.WriteFile(filepath.Join(dir, "other"), []byte("keep"), 0o600)
	n, err := WipeConnFile(path)
	if err != nil || n != 2 {
		t.Fatalf("wiped %d, %v", n, err)
	}
	es, _ := os.ReadDir(dir)
	if len(es) != 1 || es[0].Name() != "other" {
		t.Fatalf("left %v", es)
	}
	if n, err := WipeConnFile(path); err != nil || n != 0 {
		t.Fatalf("again: %d %v", n, err)
	}
	// Connections stay off: a put is refused.
	v, _ := New(nil, ChatGrants(""), nil)
	if _, _, err := v.ConnPut("s_x", ConnEmail, Sealed{}); err != ErrNoConn {
		t.Fatalf("put with connections off: %v", err)
	}
}
