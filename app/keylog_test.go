package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	jsonv2 "encoding/json/v2"

	"github.com/tacyhq/tacy/keylog"
	"github.com/tacyhq/tacy/proto"
	"github.com/tacyhq/tacy/safety"
)

// Keys v2 slice 5 end to end in agentd: the compose pins f_chat's key log genesis, entries arrive over
// POST /keylog, policies are signed by the log's key admins, and every run's meta announces the log head.

func xkey(t *testing.T) string {
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return "x25519:" + base64.StdEncoding.EncodeToString(k.PublicKey().Bytes())
}

// fchatGenesis is f_chat's first entry: the owner's identity (a legacy hex user id) and the kit.
func fchatGenesis(t *testing.T, owner, kit ed25519.PrivateKey) []safety.Envelope {
	ed, x := keylog.EdString(owner.Public().(ed25519.PublicKey)), xkey(t)
	fp, _ := keylog.Fingerprint(ed, x)
	eh, _ := keylog.EmailHash(keylog.Placeholder, "owner@example.org")
	p := keylog.Payload{EmailHash: eh, Kind: keylog.KindGenesis, Firm: keylog.Placeholder, Seq: 1, Time: 1_792_000_000, Identity: "i_" + strings.Repeat("a", 26),
		Member: "m_" + strings.Repeat("a", 26), User: strings.Repeat("ab", 16), Ed25519: ed, X25519: x, Fingerprint: fp,
		Kit: keylog.EdString(kit.Public().(ed25519.PublicKey)), Root: xkey(t), Threshold: 1}
	b, err := p.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	return []safety.Envelope{envOf(keylog.Sign(keylog.KindGenesis, b, owner, kit))}
}

func envOf(k keylog.Entry) safety.Envelope {
	e := safety.Envelope{Kind: k.Kind, Payload: k.Payload}
	for _, s := range k.Sigs {
		e.Sigs = append(e.Sigs, safety.Sig{Key: s.Key, Sig: s.Sig})
	}
	return e
}

func keylogHash(e safety.Envelope) string {
	k := keylog.Entry{Kind: e.Kind, Payload: e.Payload}
	return k.Hash()
}

// postKeylog sends entries to POST /keylog.
func (e *safeEnv) postKeylog(body []byte) (int, []string, *safety.Keys) {
	w := httptest.NewRecorder()
	e.s.keylogIn(w, httptest.NewRequest("POST", "/keylog", bytes.NewReader(body)))
	var out struct {
		Results []string     `json:"results"`
		Keys    *safety.Keys `json:"keys"`
	}
	json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out.Results, out.Keys
}

func TestKeylogEndToEnd(t *testing.T) {
	e := newSafeEnvWith(t, safeOpts{keylog: true}, pText("ok"))
	// Before the log: a policy signed by the owner's identity isn't verifiable yet, and nothing runs.
	if r := e.post(e.policy(1, nil)); r[0] == "ok" || !strings.Contains(r[0], "key log") {
		t.Fatalf("policy before the log: %v", r)
	}
	// POST /keylog: only key log entries, at most 64, strictly decoded.
	if c, _, _ := e.postKeylog([]byte(`[]`)); c != 400 {
		t.Errorf("empty: %d", c)
	}
	pol := e.policy(1, nil)
	b, _ := jsonv2.Marshal([]safety.Envelope{pol})
	if c, _, _ := e.postKeylog(b); c != 400 {
		t.Errorf("a policy on /keylog: %d", c)
	}
	many := make([]safety.Envelope, 65)
	for i := range many {
		many[i] = e.keylog[0]
	}
	b, _ = jsonv2.Marshal(many)
	if c, _, _ := e.postKeylog(b); c != 400 {
		t.Errorf("65 entries: %d", c)
	}
	b, _ = jsonv2.Marshal(e.keylog)
	c, res, keys := e.postKeylog(b)
	if c != 200 || len(res) != 1 || res[0] != "ok" || keys == nil || keys.Seq != 1 || keys.Head != keylogHash(e.keylog[0]) || keys.Firm != "f_chat" {
		t.Fatalf("POST /keylog: %d %v %+v", c, res, keys)
	}
	// Again: held, ok, nothing changes.
	if c, res, keys = e.postKeylog(b); c != 200 || res[0] != "ok" || keys.Seq != 1 {
		t.Fatalf("again: %d %v %+v", c, res, keys)
	}
	// The kit signs no policy; the owner's identity does.
	kitSigned := func() safety.Envelope {
		p := pol
		p.Sigs = safety.Sign(safety.KindPolicy, pol.Payload, e.kit).Sigs
		return p
	}()
	if r := e.post(kitSigned); r[0] == "ok" {
		t.Error("a kit-signed policy")
	}
	e.mustPost(pol, e.heartbeat())
	evs := runParity(t, e.s, proto.RunRequest{Messages: user1("hi")})
	if evs[len(evs)-1].Type != "done" {
		t.Fatalf("run: %+v", evs)
	}
	var meta *proto.Meta
	for _, ev := range evs {
		if ev.Type == "meta" {
			meta = ev.Meta
		}
	}
	if meta == nil || meta.Keys == nil || meta.Keys.Seq != 1 || meta.Keys.Head != keylogHash(e.keylog[0]) ||
		meta.Keys.Genesis != meta.Keys.Head || meta.Keys.Firm != "f_chat" || meta.Keys.Fork {
		t.Fatalf("meta keys: %+v", meta)
	}
	if st := e.s.safety.StatusOf(testSpace); st.Keys == nil || st.Keys.Seq != 1 || len(st.Policy) != 1 || st.Policy[0] != pol.Hash() {
		t.Fatalf("status: %+v", st)
	}
}

// Without a genesis pin (every release so far, and f_chat until its log is made): no meta.keys, and
// POST /keylog entries are refused by the state (the route isn't served).
func TestNoKeylogMetaUnchanged(t *testing.T) {
	e := newSafeEnv(t, pText("ok"))
	e.mustPost(e.policy(1, nil), e.heartbeat())
	evs := runParity(t, e.s, proto.RunRequest{Messages: user1("hi")})
	for _, ev := range evs {
		if ev.Type == "meta" && (ev.Meta == nil || ev.Meta.Keys != nil) {
			t.Fatalf("meta: %+v", ev.Meta)
		}
	}
	if e.s.safety.KeyLogged() || e.s.safety.StatusOf(testSpace).Keys != nil {
		t.Fatal("a legacy VM reports a key log")
	}
}
