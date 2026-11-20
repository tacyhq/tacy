package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"os"
	"slices"
	"testing"
	"time"

	jsonv2 "encoding/json/v2"

	"github.com/tacyhq/tacy/identity"
	"github.com/tacyhq/tacy/runauth"
	"github.com/tacyhq/tacy/vault"
)

// forget posts the relay's POST /connections/forget; relayed: as from inside its signed envelope.
func (e *schedEnv) forget(relayed bool, body any) (int, map[string]any) {
	b, _ := jsonv2.Marshal(body)
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/connections/forget", bytes.NewReader(b))
	if relayed {
		r = asRelay(r)
	}
	e.s.connForget(w, r)
	var out map[string]any
	json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

// forgetBy is a forget of space signed with key for identity ident at signedAt (what the browser makes before an
// account deletion).
func forgetBy(key ed25519.PrivateKey, space, ident string, signedAt time.Time) connForgetEntry {
	ms := signedAt.UnixMilli()
	return connForgetEntry{Space: space, Identity: ident, SignedAt: ms, Sig: ed25519.Sign(key, connForgetMessage(space, ident, ms))}
}

func doneOf(out map[string]any) []string {
	var s []string
	for _, x := range out["done"].([]any) {
		s = append(s, x.(string))
	}
	return s
}

// The vector the chat checks too (the chat's test/golden/v2-connection-forget.json, the same file): the message the
// browser signs (client-core agent/connections.ts signMailForget) and its signature verify here.
func TestConnForgetVector(t *testing.T) {
	b, err := os.ReadFile("testdata/v2-connection-forget.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		IdentityKey string `json:"identity_key"`
		Space       string `json:"space"`
		Identity    string `json:"identity"`
		SignedAt    int64  `json:"signed_at"`
		Message     string `json:"message"`
		Sig         []byte `json:"sig"`
	}
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	msg := connForgetMessage(v.Space, v.Identity, v.SignedAt)
	key, err := identity.ParseKey(v.IdentityKey)
	if string(msg) != v.Message || err != nil || !ed25519.Verify(key, msg, v.Sig) {
		t.Fatalf("message %q (want %q), key %v", msg, v.Message, err)
	}
}

// Account deletion removes the person's email connection (v0.21.0): the relay hands over the forget the browser signed
// before the deletion, and the VM removes the space's connection only when the signature is by the identity key the
// space's holder proved at its connect. Nothing else removes it: not the relay alone (unrelayed, or a forget signed by
// anyone else, or for another space), and another person's connection stays. A connection made more than a day after
// the forget was signed stays too.
func TestConnForgetOnAccountDeletion(t *testing.T) {
	e, _, v := newConnEnv(t)
	other, _ := runauth.NewAsker()
	connect := func(a *runauth.Asker) {
		t.Helper()
		_, out := e.connList(a)
		key, _ := out["seal_key"].(string)
		if code, out := e.call(e.s.connPut, e.connPutBody(a, key, connUser, connPass)); code != 200 {
			t.Fatalf("put %d %v", code, out)
		}
	}
	connected := func(a *runauth.Asker) bool {
		_, err := v.ConnGet(a.Space, vault.ConnEmail)
		return err == nil
	}
	connect(e.me)
	connect(other)
	now := time.Now()
	mine := forgetBy(e.me.Key, e.me.Space, e.me.Identity, now)

	// The relay's only: not from a browser's call.
	if code, _ := e.forget(false, connForgetRequest{Forgets: []connForgetEntry{mine}}); code != 401 {
		t.Fatalf("not relayed %d", code)
	}
	for name, body := range map[string]string{
		"not JSON":     `forgets`,
		"unknown":      `{"forgets":[],"all":true}`,
		"not a space":  `{"forgets":[{"space":"u_1","identity":"i_bbbbbbbbbbbbbbbbbbbbbbbbbb","signed_at":1,"sig":"` + base64.StdEncoding.EncodeToString(make([]byte, 64)) + `"}]}`,
		"short sig":    `{"forgets":[{"space":"s_1","identity":"i_bbbbbbbbbbbbbbbbbbbbbbbbbb","signed_at":1,"sig":"AAAA"}]}`,
		"no signed_at": `{"forgets":[{"space":"s_1","identity":"i_bbbbbbbbbbbbbbbbbbbbbbbbbb","sig":"` + base64.StdEncoding.EncodeToString(make([]byte, 64)) + `"}]}`,
	} {
		w := httptest.NewRecorder()
		e.s.connForget(w, asRelay(httptest.NewRequest("POST", "/connections/forget", bytes.NewReader([]byte(body)))))
		if w.Code != 400 {
			t.Fatalf("%s: %d", name, w.Code)
		}
	}

	// Refused, and nothing removed: signed by another person's key (as mine, or as theirs, for my space), or over
	// another time than it says.
	stale := mine
	stale.SignedAt++
	for name, f := range map[string]connForgetEntry{
		"another key":        forgetBy(other.Key, e.me.Space, e.me.Identity, now),
		"another identity":   forgetBy(other.Key, e.me.Space, other.Identity, now),
		"another time":       stale,
		"unsigned (made up)": {Space: e.me.Space, Identity: e.me.Identity, SignedAt: now.UnixMilli(), Sig: make([]byte, 64)},
	} {
		code, out := e.forget(true, connForgetRequest{Forgets: []connForgetEntry{f}})
		if code != 200 || len(doneOf(out)) != 0 || out["refused"] != 1.0 || !connected(e.me) {
			t.Fatalf("%s: %d %v", name, code, out)
		}
	}

	// Mine, signed by my identity: my connection goes (memory and the sealed state with it), the other person's stays.
	code, out := e.forget(true, connForgetRequest{Forgets: []connForgetEntry{mine}})
	if code != 200 || !slices.Equal(doneOf(out), []string{e.me.Space}) || out["refused"] != 0.0 {
		t.Fatalf("forget %d %v", code, out)
	}
	if connected(e.me) || !connected(other) {
		t.Fatalf("after the forget: mine %v, theirs %v", connected(e.me), connected(other))
	}
	if _, out := e.connList(e.me); len(out["connections"].([]any)) != 0 {
		t.Fatalf("still listed %v", out)
	}
	// Sent again (the relay didn't hear the answer): done, nothing else changes.
	if code, out := e.forget(true, connForgetRequest{Forgets: []connForgetEntry{mine}}); code != 200 || !slices.Equal(doneOf(out), []string{e.me.Space}) || !connected(other) {
		t.Fatalf("again %d %v", code, out)
	}
	// A space with nothing connected is done whatever the signature (nothing to remove, nothing learned).
	nobody, _ := runauth.NewAsker()
	junk := connForgetEntry{Space: nobody.Space, Identity: nobody.Identity, SignedAt: 1, Sig: make([]byte, 64)}
	if code, out := e.forget(true, connForgetRequest{Forgets: []connForgetEntry{junk}}); code != 200 || !slices.Equal(doneOf(out), []string{nobody.Space}) {
		t.Fatalf("nothing connected %d %v", code, out)
	}

	// A forget signed two days before the connection (kept from a deletion that didn't go through): the connection
	// stays; the forget is done with.
	connect(e.me)
	old := forgetBy(e.me.Key, e.me.Space, e.me.Identity, now.Add(-48*time.Hour))
	if code, out := e.forget(true, connForgetRequest{Forgets: []connForgetEntry{old}}); code != 200 || !slices.Equal(doneOf(out), []string{e.me.Space}) || !connected(e.me) {
		t.Fatalf("an older forget %d %v, connected %v", code, out, connected(e.me))
	}
	// A browser clock up to a day slow still covers the connection it means.
	slow := forgetBy(e.me.Key, e.me.Space, e.me.Identity, now.Add(-20*time.Hour))
	if code, out := e.forget(true, connForgetRequest{Forgets: []connForgetEntry{slow}}); code != 200 || !slices.Equal(doneOf(out), []string{e.me.Space}) || connected(e.me) {
		t.Fatalf("a slow clock %d %v, connected %v", code, out, connected(e.me))
	}
}
