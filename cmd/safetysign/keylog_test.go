package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json/v2"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tacyhq/tacy/keylog"
)

// The f_chat ceremony offline: identity, root, genesis payload, signed by the identity, co-signed by the kit (the
// old admin key), checked; the result replays in the VM's verifier and names the identity as the only key admin.
func TestFchatGenesisCeremony(t *testing.T) {
	dir := t.TempDir()
	id, err := makeIdentity(dir, "owner-fchat", keylog.Placeholder, strings.Repeat("ab", 16), "owner@example.org")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"owner-fchat.key", "owner-fchat.x25519.key"} {
		fi, err := os.Stat(filepath.Join(dir, f))
		if err != nil || fi.Mode().Perm() != 0o600 {
			t.Fatalf("%s: %v", f, err)
		}
	}
	if _, err := makeIdentity(dir, "owner-fchat", keylog.Placeholder, strings.Repeat("ab", 16), "owner@example.org"); err == nil {
		t.Error("overwrote a key file")
	}
	if _, err := makeIdentity(dir, "x", keylog.Placeholder, "not-an-id", "x@example.org"); err == nil {
		t.Error("bad user id")
	}
	if _, err := makeIdentity(dir, "y", keylog.Placeholder, strings.Repeat("ab", 16), "nobody"); err == nil {
		t.Error("bad email")
	}
	if want, _ := keylog.EmailHash(keylog.Placeholder, "owner@example.org"); id.EmailHash != want {
		t.Error("email hash")
	}
	root, err := newX25519(filepath.Join(dir, "fchat-root.x25519.key"))
	if err != nil {
		t.Fatal(err)
	}
	_, kit, _ := ed25519.GenerateKey(rand.Reader)
	kitPub := keylog.EdString(kit.Public().(ed25519.PublicKey))
	p, err := genesisPayload(keylog.Placeholder, id, kitPub, root, time.Unix(1_800_000_000, 0))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := genesisPayload(keylog.Placeholder, id, id.Ed25519, root, time.Now()); err == nil {
		t.Error("the identity's key as the kit")
	}
	seed, _ := os.ReadFile(filepath.Join(dir, "owner-fchat.key"))
	sb, _ := base64.StdEncoding.DecodeString(strings.TrimSpace(string(seed)))
	idKey := ed25519.NewKeyFromSeed(sb)
	e1, err := keylogSign(append(p, '\n'), keylog.KindGenesis, keylog.Placeholder, idKey)
	if err != nil {
		t.Fatal(err)
	}
	b1, _ := json.Marshal(e1)
	if _, err := keylogSign(b1, "", keylog.Placeholder, idKey); err == nil {
		t.Error("the same key signed twice")
	}
	e2, err := keylogSign(b1, "", keylog.Placeholder, kit)
	if err != nil {
		t.Fatal(err)
	}
	st, err := keylog.Replay(keylog.Placeholder, []keylog.Entry{e2})
	if err != nil {
		t.Fatal(err)
	}
	if ks := st.AdminKeys(); len(ks) != 1 || ks[0] != id.Ed25519 || st.Kit != kitPub || st.Genesis != e2.Hash() {
		t.Fatalf("state: %+v", st)
	}
	// One signature isn't a genesis; a tampered entry can't be co-signed.
	if _, err := keylog.Replay(keylog.Placeholder, []keylog.Entry{e1}); err == nil {
		t.Error("a genesis with one signature")
	}
	bad := e1
	bad.Payload = append([]byte{}, e1.Payload...)
	bad.Payload[len(bad.Payload)-2] = '2'
	bb, _ := json.Marshal(bad)
	if _, err := keylogSign(bb, "", keylog.Placeholder, kit); err == nil {
		t.Error("co-signed a tampered entry")
	}
	// keylog-check's reader: one entry per file or an array.
	path := filepath.Join(dir, "genesis.json")
	b2, _ := json.Marshal(e2)
	os.WriteFile(path, b2, 0o644)
	if es, err := readEntries([]string{path}); err != nil || len(es) != 1 || es[0].Hash() != e2.Hash() {
		t.Fatalf("read: %v", err)
	}
}
