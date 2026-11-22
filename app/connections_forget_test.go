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

// Account deletion and the relay's forget in v1: the VM keeps no email login (the person's app keeps it, and the
// item goes with the account), so a forget always finds nothing to remove and is done, whatever its signature;
// malformed calls and calls that aren't the relay's are still refused.
func TestConnForgetOnAccountDeletion(t *testing.T) {
	e, _, v := newConnEnv(t)
	now := time.Now()
	mine := forgetBy(e.me.Key, e.me.Space, e.me.Identity, now)
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
	other, _ := runauth.NewAsker()
	junk := connForgetEntry{Space: other.Space, Identity: other.Identity, SignedAt: 1, Sig: make([]byte, 64)}
	code, out := e.forget(true, connForgetRequest{Forgets: []connForgetEntry{mine, junk}})
	if code != 200 || !slices.Equal(doneOf(out), []string{e.me.Space, other.Space}) || out["refused"] != 0.0 {
		t.Fatalf("forget %d %v", code, out)
	}
	if l := v.ConnList(e.me.Space); len(l) != 0 {
		t.Fatalf("listed %v", l)
	}
}
