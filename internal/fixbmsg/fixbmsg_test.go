package fixbmsg

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/tacyhq/tacy/proto"
)

// vm is one e2epush start: its key, and what it signs.
type vm struct {
	priv        ed25519.PrivateKey
	run, boot   string
	start, seq  int
	quoteBroken bool
}

func newVM(t *testing.T, run, boot string, start int) *vm {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &vm{priv: priv, run: run, boot: boot, start: start}
}

func (v *vm) msg(t *testing.T, title string, body any) []byte {
	t.Helper()
	b, _ := json.Marshal(body)
	p := Payload{Run: v.run, Boot: v.boot, Start: v.start, Seq: v.seq, Title: title, At: "t", Body: b}
	v.seq++
	m, err := Sign(v.priv, p)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// key is the start's key message, with a stand-in attestation whose nonce is KeyNonce (fakeVerify checks it the way
// the verifier checks report_data).
func (v *vm) key(t *testing.T) []byte {
	pub := v.priv.Public().(ed25519.PublicKey)
	n := hex.EncodeToString(KeyNonce(v.run, v.boot, v.start, pub))
	if v.quoteBroken {
		n = strings.Repeat("00", 32)
	}
	return v.msg(t, KeyTitle, KeyBody{Attestation: &proto.Attestation{Version: proto.VersionAgent, Nonce: n, Platform: "dstack"}})
}

// fakeVerify stands in for the full verifier: it accepts an attestation that echoes the nonce and is marked
// genuine (a real one binds the nonce in report_data under Intel's signature).
var genuine = map[string]bool{}

func fakeVerify(a *proto.Attestation, nonce []byte) error {
	if a.Nonce != hex.EncodeToString(nonce) || !genuine[a.Nonce] {
		return errors.New("refused by the verifier")
	}
	return nil
}

func accept(c *Chain, m []byte) error {
	s, p, err := Open(m)
	if err != nil {
		return err
	}
	return c.Accept(s, p, fakeVerify)
}

func markGenuine(t *testing.T, v *vm) {
	pub := v.priv.Public().(ed25519.PublicKey)
	genuine[hex.EncodeToString(KeyNonce(v.run, v.boot, v.start, pub))] = true
}

// Review M1: the results channel is authenticated. A key is taken only after the verifier accepts its quote; then
// only messages it signed, of this run, its boot and start, each exactly the next seq.
func TestChannel(t *testing.T) {
	v := newVM(t, "run1", "boot-a", 1)
	markGenuine(t, v)
	key, m1, m2, m3 := v.key(t), v.msg(t, "attest-1", 1), v.msg(t, "scan-1", map[string]string{"phase": "boot"}), v.msg(t, "loopflip", 3)
	c := &Chain{Run: "run1"}

	// Before its key: pending, not refused.
	if err := accept(c, m1); !errors.Is(err, ErrPending) {
		t.Fatalf("before the key: %v", err)
	}
	if err := accept(c, key); err != nil {
		t.Fatal(err)
	}
	// Out of order: m2 waits for m1; then both, in order.
	if err := accept(c, m2); !errors.Is(err, ErrPending) {
		t.Fatalf("m2 before m1: %v", err)
	}
	for _, m := range [][]byte{m1, m2} {
		if err := accept(c, m); err != nil {
			t.Fatal(err)
		}
	}
	// A replay (the same message posted again), or an earlier one presented after a later one: refused.
	if err := accept(c, m2); err == nil || !strings.Contains(err.Error(), "REPLAY") {
		t.Fatalf("replay: %v", err)
	}
	if err := accept(c, m3); err != nil {
		t.Fatal(err)
	}
	if err := accept(c, m1); err == nil || !strings.Contains(err.Error(), "REPLAY") {
		t.Fatalf("an earlier one after a later one: %v", err)
	}
	if err := accept(c, key); err == nil || !strings.Contains(err.Error(), "REPLAY") {
		t.Fatalf("the key again: %v", err)
	}
	// What was taken reads back verified; a stored copy edited doesn't.
	p, err := c.Verified(m2)
	if err != nil || p.Title != "scan-1" || string(p.Body) != `{"phase":"boot"}` {
		t.Fatalf("verified %v %v", p, err)
	}
	var s Signed
	json.Unmarshal(m2, &s)
	s.Payload = []byte(strings.Replace(string(s.Payload), "scan-1", "scan-2", 1))
	edited, _ := json.Marshal(s)
	if _, err := c.Verified(edited); err == nil {
		t.Fatal("an edited title verified")
	}
	if _, err := c.Verified(key); err == nil {
		t.Fatal("the key message read as a result")
	}
}

// What the host under test can make: it knows the tester's HPKE public key and the topic (both in the compose), so
// it can seal anything. None of it is taken.
func TestChannelForgeries(t *testing.T) {
	v := newVM(t, "run1", "boot-a", 1)
	markGenuine(t, v)
	key := v.key(t)
	c := &Chain{Run: "run1"}
	if err := accept(c, key); err != nil {
		t.Fatal(err)
	}

	// 1. A message of its own, unsigned (the old format), or signed by a key of its own with no quote the verifier
	// accepts.
	if _, _, err := Open([]byte(`{"title":"scan-1","boot":"boot-a","body":{"phase":"boot"}}`)); err == nil {
		t.Fatal("an unsigned message opened")
	}
	host := newVM(t, "run1", "boot-a", 2)
	if err := accept(c, host.key(t)); err == nil || !strings.Contains(err.Error(), "refused by the verifier") {
		t.Fatalf("the host's key: %v", err)
	}
	if err := accept(c, host.msg(t, "scan-1", 1)); !errors.Is(err, ErrPending) {
		t.Fatalf("signed by the host's key: %v", err)
	}
	// 2. A genuine quote reused for another key: the nonce names the key, so it doesn't match.
	host2 := newVM(t, "run1", "boot-a", 2)
	host2.quoteBroken = true
	if err := accept(c, host2.key(t)); err == nil {
		t.Fatal("a quote for another key accepted")
	}
	// 3. Our VM's message with its signature kept and the payload changed (the title, so scan-1 passes as scan-2).
	m := v.msg(t, "scan-1", map[string]string{"phase": "boot"})
	var s Signed
	json.Unmarshal(m, &s)
	s.Payload = []byte(strings.Replace(string(s.Payload), "scan-1", "scan-2", 1))
	re, _ := json.Marshal(s)
	if _, _, err := Open(re); err == nil || !strings.Contains(err.Error(), "signature") {
		t.Fatalf("an edited payload: %v", err)
	}
	// 4. A genuine message from another run (an earlier throwaway on the same topic), or claiming another boot.
	old := newVM(t, "run0", "boot-a", 1)
	markGenuine(t, old)
	if err := accept(c, old.key(t)); err == nil || !strings.Contains(err.Error(), "run") {
		t.Fatalf("another run: %v", err)
	}
	other := &vm{priv: v.priv, run: "run1", boot: "boot-b", start: 1, seq: 1}
	if err := accept(c, other.msg(t, "scan-1", 1)); err == nil || !strings.Contains(err.Error(), "the key's quote bound") {
		t.Fatalf("another boot under the key: %v", err)
	}
	// 5. A second key for a boot and start that already has one.
	dup := newVM(t, "run1", "boot-a", 1)
	markGenuine(t, dup)
	if err := accept(c, dup.key(t)); err == nil || !strings.Contains(err.Error(), "already has a key") {
		t.Fatalf("a second key for the start: %v", err)
	}
	// 6. Seq 0 that isn't a key message, a key message later in the chain.
	z := &vm{priv: v.priv, run: "run1", boot: "boot-a", start: 1, seq: 0}
	if err := accept(c, z.msg(t, "scan-1", 1)); err == nil {
		t.Fatal("seq 0 scan accepted")
	}
	k := &vm{priv: v.priv, run: "run1", boot: "boot-a", start: 1, seq: 1}
	if err := accept(c, k.msg(t, KeyTitle, 1)); err == nil {
		t.Fatal("a key message at seq 1 accepted")
	}
	// The genuine next message still goes through.
	if err := accept(c, m); err != nil {
		t.Fatal(err)
	}
}

func TestKeyNonce(t *testing.T) {
	pub := make([]byte, 32)
	a := KeyNonce("run", "boot", 1, pub)
	for _, b := range [][]byte{KeyNonce("ru", "nboot", 1, pub), KeyNonce("run", "boot", 2, pub), KeyNonce("run", "boot", 1, append([]byte{1}, pub[1:]...))} {
		if hex.EncodeToString(a) == hex.EncodeToString(b) {
			t.Fatal("two inputs, one nonce")
		}
	}
	if len(a) != 32 {
		t.Fatal(len(a))
	}
}
