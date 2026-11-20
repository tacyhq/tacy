package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tacyhq/tacy/kms"
	"github.com/tacyhq/tacy/kms/client"
	"github.com/tacyhq/tacy/kms/kmsdev"
	"github.com/tacyhq/tacy/kms/passshare"
	"github.com/tacyhq/tacy/kmsvm"
)

// M7 (security review 2026-11-20): an admin key file is wrapped under a passphrase like the shares; no seed is
// written in the clear, a wrong passphrase opens nothing, and a plaintext file is refused outside development.
func TestReviewM7AdminKeysWrapped(t *testing.T) {
	passParams = passshare.Params{Time: 1, MemLog2: 6, Threads: 1}
	defer func() { passParams = passshare.Default }()
	pass := "an admin passphrase, long enough"
	answer := pass
	readPassphrase = func(string) ([]byte, error) { return []byte(answer), nil }
	dir := t.TempDir()
	keygenAdmin([]string{dir, "admin"})
	path := filepath.Join(dir, "admin.key")
	b, err := os.ReadFile(path)
	if err != nil || !passshare.IsAdminKey(string(b)) {
		t.Fatalf("not a wrapped key file: %v", err)
	}
	keys, err := loadAdminKeys(path)
	if err != nil || len(keys) != 1 {
		t.Fatal(err)
	}
	for _, enc := range []string{base64.StdEncoding.EncodeToString(keys[0].Seed()), string(keys[0].Seed())} {
		if bytes.Contains(b, []byte(enc)) {
			t.Fatal("the seed is in the file")
		}
	}
	answer = "not the passphrase, but long enough"
	if _, err := loadAdminKeys(path); !errors.Is(err, passshare.ErrPassphrase) {
		t.Fatalf("a wrong passphrase: %v", err)
	}
	plain := filepath.Join(dir, "plain.key")
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	os.WriteFile(plain, []byte(base64.StdEncoding.EncodeToString(priv.Seed())), 0o600)
	if _, err := loadAdminKeys(plain); err == nil || !strings.Contains(err.Error(), "isn't a wrapped admin key") {
		t.Fatalf("a plaintext key file: %v", err)
	}
	devPlainKeys = true
	defer func() { devPlainKeys = false }()
	if k, err := loadAdminKeys(plain); err != nil || !k[0].Equal(priv) {
		t.Fatalf("a development key with -dev-plain-keys: %v", err)
	}
}

// M6: after a cold start, the confirmation comes from a register snapshot the KMS id signed, raised only to the
// Worker's generations at or above the snapshot's: a Worker that hands back older ones is a rollback, refused.
func TestReviewM6ConfirmFromSnapshot(t *testing.T) {
	ctx := context.Background()
	d, err := kmsdev.Start(kmsdev.Options{})
	if err != nil {
		t.Fatal(err)
	}
	fx := kmsvm.Config{KMSID: d.KMSID, Hosts: 1, Platform: "local", Purposes: []string{"state/v1"}, Holder: "agentd",
		Transport: func(int) client.Transport { return client.Handler{H: d.Handler()} }, Evidence: kmsvm.LocalEvidence("inst-1"),
		Wait: time.Second, Logf: t.Logf}
	k, err := kmsvm.Boot(ctx, fx)
	if err != nil {
		t.Fatal(err)
	}
	reg := k.Register("state/v1")
	h := func(c string) string { return strings.Repeat(c, 64) }
	for g, c := range []string{"a", "b"} {
		reg.Reserve(ctx, "side", uint64(g+1), h(c))
		reg.Stored(ctx, "side", uint64(g+1), h(c))
	}
	reg.Reserve(ctx, "notify", 1, h("c"))
	reg.Stored(ctx, "notify", 1, h("c"))
	reg.Reserve(ctx, "notify", 2, h("d")) // reserved, not stored, at the snapshot
	ss, err := client.Snapshot(ctx, client.Handler{H: d.Handler()}, d.KMSID)
	if err != nil {
		t.Fatal(err)
	}
	// The cold-started replica, waiting for its confirmation.
	waiting := kms.Status{State: "unlocked", KMSID: kms.IDString(d.KMSID), Epoch: 1, ConfirmNonce: client.NewNonce()}
	now := time.Now().UTC()
	side := func(gen uint64, c string) kms.Gen {
		return kms.Gen{App: kmsdev.App, Name: "state/side", Gen: gen, Hash: h(c)}
	}
	notify := func(gen uint64, c string) kms.Gen {
		return kms.Gen{App: kmsdev.App, Name: "state/notify", Gen: gen, Hash: h(c)}
	}
	newer := kms.Gen{App: kmsdev.App, Name: "state/budget", Gen: 1, Hash: h("e")}
	doc, err := genDoc(ss, d.KMSID, []kms.Gen{side(3, "f"), notify(1, "c"), newer}, waiting, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(doc.Gens) != 3 || doc.Nonce != waiting.ConfirmNonce || doc.KMSID != waiting.KMSID || doc.Gens[0] != newer ||
		doc.Gens[1] != notify(1, "c") || doc.Gens[2] != side(3, "f") {
		t.Fatalf("doc %+v", doc)
	}
	for name, worker := range map[string][]kms.Gen{
		"the Worker below the snapshot":  {side(1, "a"), notify(1, "c")},
		"the snapshot's gen, other hash": {side(2, "9"), notify(1, "c")},
		"a reserved entry, no Worker":    {side(2, "b")},
	} {
		if _, err := genDoc(ss, d.KMSID, worker, waiting, now); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := genDoc(ss, other, []kms.Gen{side(2, "b"), notify(1, "c")}, waiting, now); err == nil {
		t.Fatal("a snapshot checked under another KMS id")
	}
	confirmed := waiting
	confirmed.GensOK, confirmed.ConfirmNonce = true, ""
	if _, err := genDoc(ss, d.KMSID, []kms.Gen{side(2, "b"), notify(1, "c")}, confirmed, now); err == nil {
		t.Fatal("a document for a replica that waits for nothing")
	}
}
