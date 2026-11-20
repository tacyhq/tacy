package main

import (
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tacyhq/tacy/kms"
	"github.com/tacyhq/tacy/kms/client"
	"github.com/tacyhq/tacy/kms/passshare"
	"github.com/tacyhq/tacy/kms/server"
	"github.com/tacyhq/tacy/safety"
)

type localPlatform struct{ instance string }

func (localPlatform) Name() string { return "local" }
func (l localPlatform) Evidence(context.Context, []byte) (json.RawMessage, json.RawMessage, error) {
	return nil, server.LocalInfo(l.instance), nil
}

// The ceremony and a cold start through kmsctl's own code, against development replicas (platform local: the
// attestation checks run in their development mode; the recorded-quote tests in kms/server cover the real ones).
func TestGenesisUnlockSecretPut(t *testing.T) {
	dir := t.TempDir()
	adminPub, admin, _ := ed25519.GenerateKey(rand.Reader)
	adminFile := filepath.Join(dir, "admin.key")
	os.WriteFile(adminFile, []byte(base64.StdEncoding.EncodeToString(admin.Seed())), 0o600)
	var recips []string
	var recipFiles []string
	for i := range 3 {
		k, _ := ecdh.P256().GenerateKey(rand.Reader)
		f := filepath.Join(dir, "r"+string(rune('1'+i))+".p256")
		os.WriteFile(f, []byte(base64.StdEncoding.EncodeToString(k.Bytes())), 0o600)
		recips = append(recips, kms.RecipientString(k.PublicKey()))
		recipFiles = append(recipFiles, f)
	}
	h := sha256.Sum256([]byte(server.LocalAppCompose))
	pol := kms.Policy{Epoch: 1, Seq: 1, Floor: "v0.1.0", Apps: map[string]kms.AppPolicy{"agent-vm": {Firm: "f_chat", Purposes: []string{"state/v1"}}},
		KMS: []kms.ReleasePin{{App: "kms", Version: "v0.1.0", AppComposeSHA256: hex.EncodeToString(h[:])}}}
	pb, _ := json.Marshal(pol)
	pe := safety.Sign(kms.KindPolicy, pb, admin)
	ak := kms.AdminKeys{Keys: []ed25519.PublicKey{adminPub}, Threshold: 1}
	opts := server.CheckOptions{DevLocal: true}
	ctx := context.Background()

	s1, err := server.New(server.Config{Admin: ak, Platform: localPlatform{"one"}, DevLocal: true})
	if err != nil {
		t.Fatal(err)
	}
	h1 := httptest.NewServer(s1.Handler())
	defer h1.Close()
	genesis(ctx, client.HTTP{Base: h1.URL}, &pol, pe, opts, ak, []ed25519.PrivateKey{admin}, strings.Join(recips, ","), 2, "v0.1.0", dir)
	idb, err := os.ReadFile(filepath.Join(dir, "kms-id.txt"))
	if err != nil {
		t.Fatal(err)
	}
	idStr := strings.TrimSpace(string(idb))
	id, err := kms.ParseID(idStr)
	if err != nil || s1.Status().KMSID != idStr {
		t.Fatalf("kms id %q: %v", idStr, err)
	}
	for i := 1; i <= 3; i++ {
		if b, err := os.ReadFile(filepath.Join(dir, "share-"+string(rune('0'+i))+".json")); err != nil || strings.Contains(string(b), `"y"`) {
			t.Fatalf("share %d: %v", i, err)
		}
	}
	values := filepath.Join(dir, "values.json")
	os.WriteFile(values, []byte(`{"EXA_API_KEY":"exa-value"}`), 0o600)
	sealedPath := filepath.Join(dir, "secrets.sealed")
	secretPut(ctx, client.HTTP{Base: h1.URL}, &pol, opts, idStr, []ed25519.PrivateKey{admin}, 1, values, sealedPath)
	if b, _ := os.ReadFile(sealedPath); len(b) == 0 || strings.Contains(string(b), "exa-value") {
		t.Fatal("secrets.sealed is empty or plaintext")
	}

	// Cold start: a replica pinned to the id, unlocked with shares 2 and 3.
	s2, _ := server.New(server.Config{Admin: ak, KMSID: id, Platform: localPlatform{"two"}, DevLocal: true, Now: time.Now})
	h2 := httptest.NewServer(s2.Handler())
	defer h2.Close()
	var ge safety.Envelope
	readJSON(filepath.Join(dir, "genesis.signed.json"), &ge)
	gp := filepath.Join(dir, "genesis.signed.json")
	var bound safety.Envelope // genesis bound the policy to the new KMS id: what unlock sends from then on
	readJSON(filepath.Join(dir, "policy.signed.json"), &bound)
	unlock(ctx, client.HTTP{Base: h2.URL}, &pol, opts, &ge, &bound, gp, filepath.Join(dir, "share-2.json"), recipFiles[1], true)
	unlock(ctx, client.HTTP{Base: h2.URL}, &pol, opts, &ge, &bound, gp, filepath.Join(dir, "share-3.json"), recipFiles[2], false)
	if st := s2.Status(); st.State != "unlocked" || st.KMSID != idStr {
		t.Fatalf("after unlock: %+v", st)
	}
	b, _ := os.ReadFile(sealedPath)
	if _, err := s2.LoadSecrets(b); err != nil {
		t.Fatalf("secrets.sealed after the cold start: %v", err)
	}
}

// Passphrase shares: the genesis to three pass recipients asks each passphrase twice, prints
// each share as text and writes only sealed text; a cold start with two of the three (one typed back from its paper
// copy) rebuilds M, which derives the same KMS id; a wrong passphrase fails before anything reaches the replica.
func TestGenesisUnlockPassphraseShares(t *testing.T) {
	passParams = passshare.Params{Time: 1, MemLog2: 6, Threads: 1}
	defer func() { passParams = passshare.Default }()
	dir := t.TempDir()
	adminPub, admin, _ := ed25519.GenerateKey(rand.Reader)
	h := sha256.Sum256([]byte(server.LocalAppCompose))
	pol := kms.Policy{Epoch: 1, Seq: 1, Floor: "v0.1.0", Apps: map[string]kms.AppPolicy{"agent-vm": {Firm: "f_chat", Purposes: []string{"state/v1"}}},
		KMS: []kms.ReleasePin{{App: "kms", Version: "v0.1.0", AppComposeSHA256: hex.EncodeToString(h[:])}}}
	pb, _ := json.Marshal(pol)
	pe := safety.Sign(kms.KindPolicy, pb, admin)
	ak := kms.AdminKeys{Keys: []ed25519.PublicKey{adminPub}, Threshold: 1}
	opts := server.CheckOptions{DevLocal: true}
	ctx := context.Background()
	passes := map[string]string{"manager": "manager passphrase, quite long 1", "paper": "paper passphrase, quite long 22",
		"usb": "usb passphrase, also quite long 333"}
	var prompts []string
	answer := ""
	readPassphrase = func(prompt string) ([]byte, error) {
		prompts = append(prompts, prompt)
		for label, p := range passes {
			if strings.Contains(prompt, `"`+label+`"`) {
				return []byte(p), nil
			}
		}
		return []byte(answer), nil
	}
	s1, _ := server.New(server.Config{Admin: ak, Platform: localPlatform{"one"}, DevLocal: true})
	h1 := httptest.NewServer(s1.Handler())
	defer h1.Close()
	genesis(ctx, client.HTTP{Base: h1.URL}, &pol, pe, opts, ak, []ed25519.PrivateKey{admin}, "pass:manager,pass:paper,pass:usb", 2, "v0.1.0", dir)
	if len(prompts) != 6 {
		t.Fatalf("%d passphrase prompts, want two per share", len(prompts))
	}
	idStr := s1.Status().KMSID
	id, _ := kms.ParseID(idStr)
	es, _ := os.ReadDir(dir)
	for _, e := range es {
		b, _ := os.ReadFile(filepath.Join(dir, e.Name()))
		for _, p := range passes {
			if strings.Contains(string(b), p) {
				t.Fatalf("%s holds a passphrase", e.Name())
			}
		}
		if strings.HasPrefix(e.Name(), "share-") && !strings.HasSuffix(e.Name(), ".pass.txt") {
			t.Fatalf("a pass share left %s", e.Name())
		}
	}

	// Cold start with shares 1 (armored, from its file) and 3 (its paper copy, typed back in lower case).
	s2, _ := server.New(server.Config{Admin: ak, KMSID: id, Platform: localPlatform{"two"}, DevLocal: true, Now: time.Now})
	h2 := httptest.NewServer(s2.Handler())
	defer h2.Close()
	var ge safety.Envelope
	gp := filepath.Join(dir, "genesis.signed.json")
	readJSON(gp, &ge)
	readJSON(filepath.Join(dir, "policy.signed.json"), &pe)
	three, _ := os.ReadFile(filepath.Join(dir, "share-3.pass.txt"))
	paper := string(three[strings.Index(string(three), "TACY KMS SHARE 3"):])
	paperPath := filepath.Join(t.TempDir(), "typed.txt")
	os.WriteFile(paperPath, []byte(strings.ToLower(paper)), 0o600)

	// A wrong passphrase: refused here, before the replica hears anything.
	answer = "not the passphrase of any share at all"
	if _, _, err := loadShare(filepath.Join(dir, "share-1.pass.txt"), "pass"); !errors.Is(err, passshare.ErrPassphrase) {
		t.Fatalf("wrong passphrase: %v", err)
	}
	if st := s2.Status(); st.Shares != 0 {
		t.Fatalf("the replica got a share: %+v", st)
	}
	answer = passes["manager"]
	unlock(ctx, client.HTTP{Base: h2.URL}, &pol, opts, &ge, &pe, gp, filepath.Join(dir, "share-1.pass.txt"), "pass", true)
	if st := s2.Status(); st.State != "locked" || st.Shares != 1 {
		t.Fatalf("after one share: %+v", st)
	}
	answer = passes["usb"]
	unlock(ctx, client.HTTP{Base: h2.URL}, &pol, opts, &ge, &pe, gp, paperPath, "pass", false)
	if st := s2.Status(); st.State != "unlocked" || st.KMSID != idStr {
		t.Fatalf("after two shares: %+v", st)
	}
}
