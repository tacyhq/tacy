package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tacyhq/tacy/activity"
	"github.com/tacyhq/tacy/guard"
	"github.com/tacyhq/tacy/proto"
	"github.com/tacyhq/tacy/runauth"
	"github.com/tacyhq/tacy/safety"
)

// Keys v2 spaces and identities in agentd: every run names its space and proves the space's seal key;
// an identity signs it with this boot's key and a fresh nonce; its records go to the space's chain, naming the
// identity; its budget counts for the space, the member and the VM.

// testAsker is the where and who test requests use unless they name their own (runParity, e.recorded, connTo).
var testAsker = func() *runauth.Asker {
	a, err := runauth.NewAsker()
	if err != nil {
		panic(err)
	}
	return a
}()

// testSpace is testAsker's space: what tests stop, and whose status they read.
var testSpace = testAsker.Space

// vmPubOf is the VM key requests to s are made for ("": a server without an EHBP identity, which only reads the space).
func vmPubOf(s *server) []byte {
	if s.id == nil {
		return nil
	}
	return s.id.MarshalPublicKey()
}

// authorizeFor fills req's where and who for s with testAsker, unless req names a space already.
func authorizeFor(t *testing.T, s *server, req *proto.RunRequest) {
	t.Helper()
	if req.Space != "" {
		return
	}
	vm := vmPubOf(s)
	if vm == nil {
		req.Space = testSpace // a guard alone takes the space as named
		return
	}
	if err := testAsker.Authorize(req, vm); err != nil {
		t.Fatal(err)
	}
}

// recorded is a request in testSpace whose records go to priv (the space's seal key in these tests), signed by
// testAsker's identity against the VM's key.
func (e *safeEnv) recorded(priv *ecdh.PrivateKey, req proto.RunRequest) proto.RunRequest {
	if req.Model == "" {
		req.Model = proto.DefaultModel // as clients send it (agentclient fills it before sending a task)
	}
	if req.RunSecret == "" {
		req.RunSecret = strings.Repeat("ab", 32) // signed with it: agentclient adds one to a task only before it signs
	}
	a := &runauth.Asker{Space: testSpace, Seal: priv, Identity: testAsker.Identity, Key: testAsker.Key}
	if err := a.Authorize(&req, e.vmKey.PublicKey().Bytes()); err != nil {
		e.t.Fatal(err)
	}
	return req
}

// postRun sends req as is (no where and who added) to POST /run and returns the status and body.
func postRun(s *server, req proto.RunRequest, user string) (int, string) {
	body, _ := json.Marshal(req)
	r := httptest.NewRequest("POST", "/run", bytes.NewReader(body))
	r.Header.Set(ModelHeader, proto.DefaultModel)
	w := httptest.NewRecorder()
	s.run(w, r.WithContext(withUser(r.Context(), user)))
	return w.Code, w.Body.String()
}

func TestRunAuthRefusals(t *testing.T) {
	e := newSafeEnv(t, pText("ok"), pText("ok"))
	e.mustPost(e.policy(1, nil), e.heartbeat())
	vm := e.vmKey.PublicKey().Bytes()
	seal, _ := ecdh.X25519().GenerateKey(rand.Reader)
	a := &runauth.Asker{Space: testSpace, Seal: seal, Identity: testAsker.Identity, Key: testAsker.Key}
	good := func() proto.RunRequest {
		r := proto.RunRequest{Permissions: guard.AllowAll(), Messages: user1("hi")}
		if err := a.Authorize(&r, vm); err != nil {
			t.Fatal(err)
		}
		return r
	}
	otherVM, _ := ecdh.X25519().GenerateKey(rand.Reader)
	otherSeal, _ := ecdh.X25519().GenerateKey(rand.Reader)
	_, otherKey, _ := ed25519.GenerateKey(rand.Reader)
	cases := []struct {
		name, want string
		edit       func(r *proto.RunRequest)
	}{
		{"no space", "names no space", func(r *proto.RunRequest) { *r = proto.RunRequest{Permissions: guard.AllowAll(), Messages: user1("hi")} }},
		{"the old s_chat", "s_ id", func(r *proto.RunRequest) { r.Space = "s_chat" }},
		{"another space, same proof", "space_proof", func(r *proto.RunRequest) { r.Space = runauth.NewID("s") }},
		{"a proof made with another seal key", "space_proof", func(r *proto.RunRequest) {
			r.SpaceProof, _ = runauth.SpaceProof(otherSeal, e.vmKey.PublicKey(), r.Space, r.SpaceSeal, vm)
		}},
		{"someone else's seal key, no private half", "space_proof", func(r *proto.RunRequest) {
			r.SpaceSeal = runauth.SealString(otherSeal.PublicKey())
		}},
		{"a proof for another VM", "space_proof", func(r *proto.RunRequest) {
			r.SpaceProof, _ = runauth.SpaceProof(seal, otherVM.PublicKey(), r.Space, r.SpaceSeal, otherVM.PublicKey().Bytes())
		}},
		{"signed for another VM", "identity_sig", func(r *proto.RunRequest) {
			b, _ := json.Marshal(r)
			var w proto.RunRequest
			json.Unmarshal(b, &w)
			r.IdentitySig = runauth.Sign(testAsker.Key, &w, otherVM.PublicKey().Bytes())
		}},
		{"signed by another key", "identity_sig", func(r *proto.RunRequest) {
			b, _ := json.Marshal(r)
			var w proto.RunRequest
			json.Unmarshal(b, &w)
			r.IdentitySig = runauth.Sign(otherKey, &w, vm)
		}},
		{"a changed message", "identity_sig", func(r *proto.RunRequest) { r.Messages = user1("hi there") }},
		{"a changed model", "identity_sig", func(r *proto.RunRequest) { r.Tools = []string{"web_search"} }},
		{"too old", "signed_at", func(r *proto.RunRequest) { r.SignedAt -= int64(runauth.MaxSkew/time.Second) + 5 }},
		{"a bad nonce", "nonce", func(r *proto.RunRequest) { r.Nonce = "x" }},
		{"no identity", "identity", func(r *proto.RunRequest) { r.Identity = "" }},
	}
	for _, c := range cases {
		r := good()
		c.edit(&r)
		if code, body := postRun(e.s, r, ""); code != 400 || !strings.Contains(body, c.want) {
			t.Errorf("%s: %d %s (want 400 naming %q)", c.name, code, body, c.want)
		}
	}
	// A good one runs once; the same request again (the relay replaying it) is refused, and so is the replay of a
	// request that was refused for its budget or its stop (the nonce is spent at the door).
	r := good()
	if code, body := postRun(e.s, r, ""); code != 200 || !strings.Contains(body, `"done"`) {
		t.Fatalf("good run: %d %s", code, body)
	}
	if code, body := postRun(e.s, r, ""); code != 400 || !strings.Contains(body, "replayed") {
		t.Fatalf("replay: %d %s", code, body)
	}
	// Nothing was recorded for any refused request: the one chain holds the good run's start and end.
	if _, head, _ := e.rec.Head(testSpace, runauth.SealString(seal.PublicKey())); head.Seq != 2 {
		t.Fatalf("chain head %d, want 2", head.Seq)
	}
	for _, k := range []*ecdh.PrivateKey{otherSeal} {
		if _, head, _ := e.rec.Head(testSpace, runauth.SealString(k.PublicKey())); head.Seq != 0 {
			t.Fatal("a record was written for an unproven key")
		}
	}
}

// Records land in the space's chain (space, seal key) and name the identity that asked; the run's stop is the
// space's.
func TestRunAuthRecordsInTheSpaceChain(t *testing.T) {
	e := newSafeEnv(t, pText("one"), pText("two"))
	e.mustPost(e.policy(1, nil), e.heartbeat())
	key := e.rec.Signer.Public()
	seal, _ := ecdh.X25519().GenerateKey(rand.Reader)
	space := runauth.NewID("s")
	alice, _ := runauth.NewAsker()
	bob, _ := runauth.NewAsker()
	vm := e.vmKey.PublicKey().Bytes()
	var members []string
	for _, who := range []*runauth.Asker{alice, bob} {
		a := &runauth.Asker{Space: space, Seal: seal, Identity: who.Identity, Key: who.Key}
		r := proto.RunRequest{Permissions: guard.AllowAll(), Messages: user1("hi")}
		if err := a.Authorize(&r, vm); err != nil {
			t.Fatal(err)
		}
		evs := runParity(t, e.s, r)
		if m := metaOf(evs); m == nil || m.Activity == nil || m.Activity.Chain != activity.ChainID(space, runauth.SealString(seal.PublicKey())) {
			t.Fatalf("meta: %+v", m)
		}
		for _, b := range openedActivity(t, evs, seal, key) {
			if b.Space != space {
				t.Fatalf("record in space %s", b.Space)
			}
			if b.Event == activity.EventStart {
				members = append(members, b.Member)
			}
		}
	}
	if len(members) != 2 || members[0] != alice.Identity || members[1] != bob.Identity {
		t.Fatalf("start records name %v, want alice then bob", members)
	}
	if _, head, _ := e.rec.Head(space, runauth.SealString(seal.PublicKey())); head.Seq != 4 {
		t.Fatalf("one chain for the space: head %d, want 4", head.Seq)
	}
	// A stop of that space refuses its next run, with a refused record in the same chain naming the member.
	e.mustPost(e.stop(safety.IssuerFirm, 1, func(l *safety.StopList) { l.Stop = []safety.Target{{Firm: "f_chat", Space: space}} }, e.admin))
	a := &runauth.Asker{Space: space, Seal: seal, Identity: alice.Identity, Key: alice.Key}
	r := proto.RunRequest{Permissions: guard.AllowAll(), Messages: user1("hi")}
	a.Authorize(&r, vm)
	evs := runParity(t, e.s, r)
	if ev, ok := lastError(evs); !ok || ev.Code != safety.CodeStopped {
		t.Fatalf("want stopped: %s", types(evs))
	}
	runs := openedActivity(t, evs, seal, key)
	if len(runs) != 1 || runs[0].Event != activity.EventRefused || runs[0].Member != alice.Identity || runs[0].Seq != 5 {
		t.Fatalf("refused record: %+v", runs)
	}
	// Another space isn't stopped.
	if evs := runParity(t, e.s, proto.RunRequest{Permissions: guard.AllowAll(), Messages: user1("hi")}); metaOf(evs) == nil {
		t.Fatalf("another space was stopped too: %s", types(evs))
	}
}

// The shared chat VM's member budget is the relay's per-user tag: one person's runs in many new spaces, in parallel,
// share one member day; another person still has theirs. This is what closes "every chat user shares s_chat, so one
// user can use up the day for everyone".
func TestRunAuthMemberBudgetAcrossSpaces(t *testing.T) {
	// Each reply reports 40,000 prompt tokens: what the member's day counts once the call ends.
	big := `data: {"choices":[{"delta":{"content":"ok"},"finish_reason":"stop"}]}` +
		"\n\ndata: {\"choices\":[],\"usage\":{\"prompt_tokens\":40000,\"completion_tokens\":0,\"total_tokens\":40000}}\n\ndata: [DONE]\n\n"
	var replies []string
	for range 40 {
		replies = append(replies, big)
	}
	e := newSafeEnv(t, replies...)
	// A member day of 100K tokens: a third run still finds room for its reservation (and goes over with its 40K),
	// a fourth doesn't, in parallel or after; the VM's day of 200K leaves room for someone else.
	e.mustPost(e.policy(1, func(p *safety.Policy) {
		p.Budget.Member = safety.Limits{Tokens: 100_000}
		p.Budget.VM = safety.Limits{Tokens: 200_000}
	}), e.heartbeat())
	vm := e.vmKey.PublicKey().Bytes()
	run := func(user string) (ok bool, code string) {
		a, _ := runauth.NewAsker() // a brand-new personal space (and identity) every time
		r := proto.RunRequest{Permissions: guard.AllowAll(), Messages: user1("hi"), MaxSteps: 1}
		if err := a.Authorize(&r, vm); err != nil {
			t.Fatal(err)
		}
		body, _ := json.Marshal(r)
		hr := httptest.NewRequest("POST", "/run", bytes.NewReader(body))
		hr.Header.Set(ModelHeader, proto.DefaultModel)
		w := httptest.NewRecorder()
		e.s.run(w, hr.WithContext(withUser(hr.Context(), user)))
		var evs []proto.Event
		for _, line := range strings.Split(w.Body.String(), "\n") {
			if d, ok := strings.CutPrefix(line, "data: "); ok && d != "[DONE]" {
				var ev proto.Event
				json.Unmarshal([]byte(d), &ev)
				evs = append(evs, ev)
			}
		}
		if ev, bad := lastError(evs); bad {
			return false, ev.Code
		}
		return true, ""
	}
	alice := strings.Repeat("a", 32)
	var ok atomic.Int32
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if done, code := run(alice); done {
				ok.Add(1)
			} else if code != safety.CodeBudgetExceeded {
				t.Errorf("refused with %q", code)
			}
		}()
	}
	wg.Wait()
	if n := ok.Load(); n < 1 || n > 3 {
		t.Fatalf("alice ran %d runs in 8 new spaces, her day fits 3", n)
	}
	if done, code := run(alice); done || code != safety.CodeBudgetExceeded {
		t.Fatal("a new space gave alice a new budget")
	}
	bob := strings.Repeat("b", 32)
	if done, _ := run(bob); !done {
		t.Fatal("alice used up bob's day")
	}
}

// On a firm's VM (no personal spaces) a space runs only under its own signed policy naming its seal key, and only for
// an identity current in the firm key log; the identity is then the member.
func TestRunAuthFirmVM(t *testing.T) {
	e := newSafeEnvWith(t, safeOpts{keylog: true, firmVM: true}, pText("ok"), pText("ok"))
	if errs, _ := e.s.safety.Apply(e.keylog); errs[0] != nil {
		t.Fatal(errs[0])
	}
	seal, _ := ecdh.X25519().GenerateKey(rand.Reader)
	space := runauth.NewID("s")
	// The key log's first owner (e.admin's identity in fchatGenesis) asks.
	owner := &runauth.Asker{Space: space, Seal: seal, Identity: "i_" + strings.Repeat("a", 26), Key: e.admin}
	e.mustPost(e.policy(1, nil), e.heartbeat())
	vm := e.vmKey.PublicKey().Bytes()
	send := func(a *runauth.Asker) (int, string) {
		r := proto.RunRequest{Permissions: guard.AllowAll(), Messages: user1("hi")}
		if err := a.Authorize(&r, vm); err != nil {
			t.Fatal(err)
		}
		return postRun(e.s, r, "")
	}
	if _, body := send(owner); !strings.Contains(body, "policy_missing") {
		t.Fatalf("no space policy: %s", body)
	}
	other, _ := ecdh.X25519().GenerateKey(rand.Reader)
	e.mustPost(e.policy(1, func(p *safety.Policy) { p.Space, p.Seal = space, runauth.SealString(other.PublicKey()) }))
	if _, body := send(owner); !strings.Contains(body, "seal key isn't the one") {
		t.Fatalf("another seal key: %s", body)
	}
	e.mustPost(e.policy(2, func(p *safety.Policy) { p.Space, p.Seal = space, runauth.SealString(seal.PublicKey()) }))
	stranger, _ := runauth.NewAsker()
	stranger.Space, stranger.Seal = space, seal
	if _, body := send(stranger); !strings.Contains(body, "isn't current in the firm key log") {
		t.Fatalf("an identity outside the key log: %s", body)
	}
	if code, body := send(owner); code != 200 || !strings.Contains(body, `"done"`) {
		t.Fatalf("owner: %d %s", code, body)
	}
}
