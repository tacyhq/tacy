package main

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	jsonv2 "encoding/json/v2"

	ehbpidentity "github.com/tinfoilsh/encrypted-http-body-protocol/identity"

	"github.com/tacyhq/tacy/activity"
	"github.com/tacyhq/tacy/guard"
	"github.com/tacyhq/tacy/harness"
	"github.com/tacyhq/tacy/proto"
	"github.com/tacyhq/tacy/runner/runnertest"
	"github.com/tacyhq/tacy/safety"
)

// Step 6 end to end in agentd (the in-process guard, as on -platform local): signed policy, the kill switch,
// budgets, and the adversarial cases (forged and replayed documents, stale stop lists, parallel calls). The kill
// switch and the budgets also run with the brain behind a runnerd (TestSafetyBehindRunner: the CVM's layout since
// v0.4.0; real gVisor when runnertest finds runsc, else the fake sandbox).

type safeEnv struct {
	t               *testing.T
	s               *server
	admin, operator ed25519.PrivateKey
	model           *parityModel
	modelReqs       atomic.Int32
	readerReqs      atomic.Int32
	fs              *fakeSearch
	seq             uint64
	rec             *activity.Recorder
	vmKey           *ecdh.PrivateKey
	kit             ed25519.PrivateKey
	keylog          []safety.Envelope
}

func newSafeEnv(t *testing.T, replies ...string) *safeEnv {
	return newSafeEnvWith(t, safeOpts{}, replies...)
}

// newSafeEnvBrain: behindRunner puts the brain in a sandbox a runnerd starts (runnertest), as on the CVM.
func newSafeEnvBrain(t *testing.T, behindRunner bool, replies ...string) *safeEnv {
	return newSafeEnvWith(t, safeOpts{behindRunner: behindRunner}, replies...)
}

// safeOpts change newSafeEnv's agentd: another search provider (the real one over a test lease), no keys
// pinned (stage 1: the release policy alone, as the live compose), or the brain behind a runnerd (runnertest),
// as on the CVM.
type safeOpts struct {
	search       guard.SearchProvider
	keyless      bool
	behindRunner bool
	// reader turns the quarantined reader on (as gatewayd runs it); the model server answers its calls with
	// reader(prompt) and counts them in readerReqs.
	reader func(prompt string) string
	// keylog: admin signers from a firm key log (keys v2 slice 5) instead of a compose key: genesis pinned (its
	// entries in e.keylog, e.admin the first owner's identity key, e.kit the recovery kit), carry pinned hashes.
	keylog bool
	carry  []string
	// firmVM: a firm's VM (keys v2 slice 6): no personal spaces, so a space runs only under its own signed policy
	// naming its seal key, for an identity current in the key log. Off: the shared chat VM, as f_chat's compose.
	firmVM bool
	// wrapUp wraps the model upstream (fake slow or overloaded models); slowAfter is the guard's first-token wait.
	wrapUp    func(guard.Upstream) guard.Upstream
	slowAfter time.Duration
	// release edits the release's ceiling policy (the trigger tests add the test-only sink connector); sink and check
	// are the guard's sink connector and its approval check (gatewayd's side).
	release func(p *safety.Policy)
	sink    *guard.Sink
	check   *guard.ApprovalCheck
	// stored is the guard's way to the person's stored files (a stand-in bucket in tests); nil: none.
	stored *guard.StoredConfig
	// mail is the guard's way to the person's email (a stand-in IMAP server and an in-process vault); nil: none.
	mail *guard.MailConfig
}

func newSafeEnvWith(t *testing.T, o safeOpts, replies ...string) *safeEnv {
	e := &safeEnv{t: t, model: &parityModel{replies: replies}, fs: &fakeSearch{}}
	_, e.admin, _ = ed25519.GenerateKey(rand.Reader)
	_, e.operator, _ = ed25519.GenerateKey(rand.Reader)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if o.reader != nil {
			body, _ := io.ReadAll(r.Body)
			var req struct {
				Messages []struct{ Content string } `json:"messages"`
			}
			json.Unmarshal(body, &req)
			if len(req.Messages) == 2 && strings.HasPrefix(req.Messages[0].Content, "You are Tacy's quarantined reader.") {
				e.readerReqs.Add(1)
				w.Header().Set("Content-Type", "text/event-stream")
				b, _ := json.Marshal(o.reader(req.Messages[1].Content))
				fmt.Fprintf(w, "data: {\"choices\":[{\"delta\":{\"content\":%s},\"finish_reason\":\"stop\"}]}\n\n", b)
				io.WriteString(w, "data: {\"choices\":[],\"usage\":{\"prompt_tokens\":1500,\"completion_tokens\":400,\"total_tokens\":1900}}\n\ndata: [DONE]\n\n")
				return
			}
			r.Body = io.NopCloser(bytes.NewReader(body))
		}
		e.modelReqs.Add(1)
		e.model.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	cfg := safety.Config{Firm: "f_chat", Operator: e.operator.Public().(ed25519.PublicKey),
		Admins: []ed25519.PublicKey{e.admin.Public().(ed25519.PublicKey)}, Release: guard.ReleasePolicy("f_chat", ""),
		Dir: t.TempDir(), PersonalSpaces: !o.firmVM}
	if o.keyless {
		cfg.Operator, cfg.Admins = nil, nil
	}
	if o.keylog {
		_, e.kit, _ = ed25519.GenerateKey(rand.Reader)
		e.keylog = fchatGenesis(t, e.admin, e.kit)
		cfg.Admins, cfg.Genesis, cfg.Carry = nil, keylogHash(e.keylog[0]), o.carry
	}
	if o.release != nil {
		o.release(cfg.Release)
	}
	st, err := safety.NewState(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var search guard.SearchProvider = e.fs
	if o.search != nil {
		search = o.search
	}
	lim := defaultLimits
	var reader *guard.ReaderConfig
	if o.reader != nil {
		rc := guard.DefaultReader
		reader = &rc
	}
	up := guard.NewPlainUpstream(srv.URL, srv.Client())
	if o.wrapUp != nil {
		up = o.wrapUp(up)
	}
	g := guard.New(guard.Config{Up: up, Search: search, Fetcher: guard.NewFetcher(true),
		Limits: &lim, CacheSecret: "boot-secret", Now: func() time.Time { return time.Date(2026, 10, 17, 0, 0, 0, 0, time.UTC) },
		Safety: st, Reader: reader, SlowAfter: o.slowAfter, OverloadWait: 2 * time.Millisecond, Sink: o.sink, Approvals: o.check,
		Stored: o.stored, Mail: o.mail})
	sg := newSafeGateway(g, st, &safety.Ledger{})
	signer, _ := activity.DeriveSigner(bytes.Repeat([]byte{5}, 32), "f_chat")
	e.rec = &activity.Recorder{Signer: signer, Store: activity.NewMemStore()}
	id, _ := ehbpidentity.NewIdentity()
	skb, _ := id.PrivateKey().Bytes()
	e.vmKey, _ = ecdh.X25519().NewPrivateKey(skb)
	rg := newRecGateway(sg, e.rec, e.vmKey) // the recorder on top, as in main (runs without record_to aren't recorded)
	rt := newRuntime(rg, harness.NewMemStore(), lim)
	sg.cancel = func(id, reason string) { rt.Cancel(id, reason) }
	ctx, cancel := context.WithCancel(context.Background())
	if o.behindRunner {
		env := runnertest.Start(t)
		t.Logf("brain sandbox: %s", env.Kind)
		go runBrains(ctx, rt, env.Client)
	} else {
		go localBrain(ctx, rt)
	}
	t.Cleanup(cancel) // before runnertest's cleanup: the brains stop first
	go sg.enforce(ctx, 200*time.Millisecond)
	e.s = &server{platform: local{}, id: id, agent: rg, rt: rt, rec: e.rec, token: "tok", booted: time.Now(), sched: newScheduler(lim),
		lim: lim, quotes: make(chan struct{}, 4), safety: st, gw: g, safetySlots: make(chan struct{}, 2)}
	return e
}

func (e *safeEnv) policy(version uint64, edit func(p *safety.Policy)) safety.Envelope {
	p := guard.ReleasePolicy("f_chat", "")
	p.Version, p.IssuedAt = version, time.Now().UTC()
	p.Budget, p.Rates = safety.Budgets{}, safety.Rates{} // the release's ceilings apply
	if edit != nil {
		edit(p)
	}
	b, _ := jsonv2.Marshal(p)
	return safety.Sign(safety.KindPolicy, b, e.admin)
}

func (e *safeEnv) stop(issuer string, seq uint64, edit func(l *safety.StopList), key ed25519.PrivateKey) safety.Envelope {
	now := time.Now().UTC()
	l := &safety.StopList{Type: safety.StopType, Issuer: issuer, Seq: seq, IssuedAt: now}
	if issuer == safety.IssuerOperator {
		l.ExpiresAt = now.Add(5 * time.Minute)
	} else {
		l.Firm = "f_chat"
	}
	if edit != nil {
		edit(l)
	}
	b, _ := jsonv2.Marshal(l)
	return safety.Sign(safety.KindStop, b, key)
}

// heartbeat is a fresh operator list with nothing stopped.
func (e *safeEnv) heartbeat() safety.Envelope {
	e.seq++
	return e.stop(safety.IssuerOperator, e.seq, nil, e.operator)
}

// post sends documents to POST /safety and returns the per-document results.
func (e *safeEnv) post(docs ...safety.Envelope) []string {
	b, _ := jsonv2.Marshal(docs)
	w := httptest.NewRecorder()
	e.s.safetyIn(w, httptest.NewRequest("POST", "/safety", bytes.NewReader(b)))
	var out struct {
		Results []string `json:"results"`
	}
	json.Unmarshal(w.Body.Bytes(), &out)
	if w.Code != 200 {
		e.t.Fatalf("POST /safety: %d %s", w.Code, w.Body)
	}
	return out.Results
}

func (e *safeEnv) mustPost(docs ...safety.Envelope) {
	e.t.Helper()
	for i, r := range e.post(docs...) {
		if r != "ok" {
			e.t.Fatalf("document %d refused: %s", i, r)
		}
	}
}

func lastError(evs []proto.Event) (proto.Event, bool) {
	for i := len(evs) - 1; i >= 0; i-- {
		if evs[i].Type == "error" {
			return evs[i], true
		}
	}
	return proto.Event{}, false
}

func TestSafetyPolicyHashInMetaAndNarrowedTools(t *testing.T) {
	e := newSafeEnv(t, pText("ok"))
	// Before any policy: admin keys are pinned, so nothing runs (fail closed), and the model is never called.
	evs := runParity(t, e.s, proto.RunRequest{Permissions: guard.AllowAll(), Messages: user1("hi")})
	if er, ok := lastError(evs); !ok || er.Code != safety.CodePolicyMissing || e.modelReqs.Load() != 0 {
		t.Fatalf("no policy: %+v", evs)
	}
	pol := e.policy(1, func(p *safety.Policy) {
		w := p.Connectors["web"]
		w.Tools = []string{"web.search", "web.fetch"} // no images
		p.Connectors["web"] = w
	})
	e.mustPost(pol, e.heartbeat())
	evs = runParity(t, e.s, proto.RunRequest{Permissions: guard.AllowAll(), Messages: user1("hi")})
	if evs[len(evs)-1].Type != "done" {
		t.Fatalf("run: %+v", evs)
	}
	var meta *proto.Meta
	for _, ev := range evs {
		if ev.Type == "meta" {
			meta = ev.Meta
		}
	}
	if meta == nil || meta.Controls == nil || len(meta.Controls.Policy) != 1 || meta.Controls.Policy[0] != pol.Hash() ||
		!meta.Controls.Fresh || meta.Controls.ReleasePolicy == "" {
		t.Fatalf("meta controls: %+v", meta)
	}
	if strings.Contains(strings.Join(meta.Tools, ","), "image_search") {
		t.Fatalf("image_search wasn't taken out: %v", meta.Tools)
	}
}

func TestSafetyForgedAndReplayedPolicies(t *testing.T) {
	e := newSafeEnv(t, pText("ok"), pText("ok"))
	v2 := e.policy(2, nil)
	e.mustPost(v2, e.heartbeat())
	// Forged: our servers (or anyone) widening the policy without the admin's key.
	_, stranger, _ := ed25519.GenerateKey(rand.Reader)
	wide := e.policy(3, nil)
	b, _ := jsonv2.Marshal(func() *safety.Policy {
		p := guard.ReleasePolicy("f_chat", "")
		p.Version = 3
		p.IssuedAt = time.Now()
		return p
	}())
	forged := []safety.Envelope{
		safety.Sign(safety.KindPolicy, b, stranger),            // an unpinned key
		safety.Sign(safety.KindPolicy, b, e.operator),          // the operator's key can't sign policy
		{Kind: safety.KindPolicy, Payload: b, Sigs: wide.Sigs}, // a real signature over other bytes
	}
	for i, r := range e.post(forged...) {
		if r == "ok" {
			t.Errorf("forged policy %d accepted", i)
		}
	}
	// Replayed: an older, validly signed policy (version rollback).
	if r := e.post(e.policy(1, nil)); r[0] == "ok" || !strings.Contains(r[0], "rollback") {
		t.Fatalf("v1 after v2: %v", r)
	}
	if st := e.s.safety.StatusOf(testSpace); len(st.Policy) != 1 || st.Policy[0] != v2.Hash() {
		t.Fatalf("the policy in force changed: %+v", st)
	}
}

// TestSafetyBehindRunner: the kill switch and the budgets with the brain in its sandbox, as on the CVM.
func TestSafetyBehindRunner(t *testing.T) {
	t.Run("KillSwitch", func(t *testing.T) { testSafetyKillSwitch(t, true) })
	t.Run("BudgetParallelToolCalls", func(t *testing.T) { testSafetyBudgetParallel(t, true) })
	t.Run("TokenBudget", func(t *testing.T) { testSafetyTokenBudget(t, true) })
}

func TestSafetyKillSwitchCancelsRunningRun(t *testing.T) { testSafetyKillSwitch(t, false) }

func testSafetyKillSwitch(t *testing.T, behindRunner bool) {
	e := newSafeEnvBrain(t, behindRunner, pCalls([3]string{"c1", "fetch_page", `{"url":"https://docs.example.org/slow"}`}), pText("never"))
	// A page that never answers: the run is stuck in an action when the stop comes.
	block := make(chan struct{})
	page := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-block:
		case <-r.Context().Done():
		}
	}))
	defer page.Close()
	defer close(block)
	e.model.replies[0] = pCalls([3]string{"c1", "fetch_page", `{"url":"` + page.URL + `/slow"}`})
	e.mustPost(e.policy(1, nil), e.heartbeat())
	done := make(chan []proto.Event, 1)
	go func() {
		done <- runParity(t, e.s, proto.RunRequest{Permissions: guard.AllowAll(), Messages: user1("read it")})
	}()
	deadline := time.Now().Add(5 * time.Second)
	for e.modelReqs.Load() < 1 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(200 * time.Millisecond) // the fetch is running
	t0 := time.Now()
	e.mustPost(e.stop(safety.IssuerFirm, 1, func(l *safety.StopList) { l.Stop = []safety.Target{{Firm: "f_chat", Space: testSpace}} }, e.admin))
	var evs []proto.Event
	select {
	case evs = <-done:
	case <-time.After(15 * time.Second):
		t.Fatal("the run didn't stop")
	}
	if er, ok := lastError(evs); !ok || er.Code != safety.CodeStopped {
		t.Fatalf("events: %+v", evs)
	}
	if d := time.Since(t0); d > 3*time.Second {
		t.Fatalf("stopping took %v", d)
	}
	if e.modelReqs.Load() != 1 {
		t.Fatal("the model was called after the stop")
	}
	// New runs are refused while it holds, without calling the model.
	evs = runParity(t, e.s, proto.RunRequest{Permissions: guard.AllowAll(), Messages: user1("again")})
	if er, ok := lastError(evs); !ok || er.Code != safety.CodeStopped || e.modelReqs.Load() != 1 {
		t.Fatalf("new run while stopped: %+v", evs)
	}
	// Lifted by the firm's newer list (the operator can't lift it).
	e.mustPost(e.stop(safety.IssuerFirm, 2, nil, e.admin))
	e.model.replies = append(e.model.replies, pText("back"))
	e.model.n = 2
	evs = runParity(t, e.s, proto.RunRequest{Permissions: guard.AllowAll(), Messages: user1("again")})
	if evs[len(evs)-1].Type != "done" {
		t.Fatalf("after the stop was lifted: %+v", evs)
	}
}

func TestSafetyGlobalStopAndOperatorCantLiftFirmStop(t *testing.T) {
	e := newSafeEnv(t, pText("ok"))
	e.mustPost(e.policy(1, nil), e.heartbeat())
	e.seq++
	e.mustPost(e.stop(safety.IssuerOperator, e.seq, func(l *safety.StopList) { l.All = true }, e.operator))
	if er, ok := lastError(runParity(t, e.s, proto.RunRequest{Permissions: guard.AllowAll(), Messages: user1("hi")})); !ok || er.Code != safety.CodeStopped {
		t.Fatal("global stop didn't refuse the run")
	}
	// The admin's key can't sign the operator's list (nor lift its stop with one).
	if r := e.post(e.stop(safety.IssuerOperator, e.seq+1, nil, e.admin)); r[0] == "ok" {
		t.Fatal("an operator list signed by the admin was accepted")
	}
	e.mustPost(e.heartbeat(), e.stop(safety.IssuerFirm, 1, func(l *safety.StopList) { l.All = true }, e.admin))
	if er, ok := lastError(runParity(t, e.s, proto.RunRequest{Permissions: guard.AllowAll(), Messages: user1("hi")})); !ok || er.Code != safety.CodeStopped {
		t.Fatal("the operator's newer list lifted the firm's stop")
	}
}

func TestSafetyStaleStopList(t *testing.T) {
	e := newSafeEnv(t, pText("ok"), pText("ok"))
	// No operator list ever arrived (the control plane is down, or someone drops the pull): with an operator key
	// pinned nothing goes out, though the policy allows reads while stale (the release's floor).
	e.mustPost(e.policy(1, nil))
	if er, ok := lastError(runParity(t, e.s, proto.RunRequest{Permissions: guard.AllowAll(), Messages: user1("hi")})); !ok || er.Code != safety.CodeStale {
		t.Fatalf("stale, stale_reads on: %+v", er)
	}
	// A policy that stops reads too while stale.
	e.mustPost(e.policy(2, func(p *safety.Policy) { p.StaleReads = false }))
	evs := runParity(t, e.s, proto.RunRequest{Permissions: guard.AllowAll(), Messages: user1("hi")})
	if er, ok := lastError(evs); !ok || er.Code != safety.CodeStale {
		t.Fatalf("stale, reads not allowed: %+v", evs)
	}
	// An expired operator list doesn't help.
	exp := e.stop(safety.IssuerOperator, 5, func(l *safety.StopList) {
		l.IssuedAt, l.ExpiresAt = time.Now().Add(-30*time.Minute), time.Now().Add(-15*time.Minute)
	}, e.operator)
	if r := e.post(exp); r[0] == "ok" {
		t.Fatal("expired operator list accepted")
	}
	e.mustPost(e.heartbeat())
	if evs := runParity(t, e.s, proto.RunRequest{Permissions: guard.AllowAll(), Messages: user1("hi")}); evs[len(evs)-1].Type != "done" {
		t.Fatalf("fresh again: %+v", evs)
	}
}

func TestSafetyBudgetParallelToolCalls(t *testing.T) { testSafetyBudgetParallel(t, false) }

func testSafetyBudgetParallel(t *testing.T, behindRunner bool) {
	calls := [][3]string{}
	for _, id := range []string{"c1", "c2", "c3", "c4"} {
		calls = append(calls, [3]string{id, "web_search", `{"query":"q ` + id + `"}`})
	}
	e := newSafeEnvBrain(t, behindRunner, pCalls(calls...), pText("done"))
	e.mustPost(e.policy(1, func(p *safety.Policy) { p.Budget.Run.ToolCalls = 2 }), e.heartbeat())
	evs := runParity(t, e.s, proto.RunRequest{Permissions: guard.AllowAll(), Messages: user1("search a lot")})
	if evs[len(evs)-1].Type != "done" {
		t.Fatalf("the run should answer without the refused calls: %+v", evs)
	}
	e.fs.mu.Lock()
	n := len(e.fs.queries)
	e.fs.mu.Unlock()
	if n != 2 {
		t.Fatalf("%d searches ran in parallel; the run's budget is 2", n)
	}
	refused := 0
	for _, ev := range evs {
		if ev.Type == "tool_result" && strings.Contains(string(ev.Result), safety.CodeBudgetExceeded) {
			refused++
		}
	}
	if refused != 2 {
		t.Fatalf("%d tool results say budget_exceeded, want 2", refused)
	}
}

func TestSafetyTokenBudgetEndsRun(t *testing.T) { testSafetyTokenBudget(t, false) }

func testSafetyTokenBudget(t *testing.T, behindRunner bool) {
	e := newSafeEnvBrain(t, behindRunner, pText("never"))
	e.mustPost(e.policy(1, func(p *safety.Policy) { p.Budget.Run.Tokens = 300 }), e.heartbeat())
	evs := runParity(t, e.s, proto.RunRequest{Permissions: guard.AllowAll(), Messages: user1("hi")})
	if er, ok := lastError(evs); !ok || er.Code != safety.CodeBudgetExceeded || e.modelReqs.Load() != 0 {
		t.Fatalf("token budget: %+v (model called %d)", evs, e.modelReqs.Load())
	}
}

func TestSafetyModelAndFetchHostDenied(t *testing.T) {
	var hits atomic.Int32
	page := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1); io.WriteString(w, "secret page") }))
	defer page.Close()
	e := newSafeEnv(t, pCalls([3]string{"c1", "fetch_page", `{"url":"` + page.URL + `/x"}`}), pText("couldn't"))
	e.mustPost(e.policy(1, func(p *safety.Policy) {
		p.Models = []string{"gpt-oss-120b"}
		w := p.Connectors["web"]
		w.Fetch = []string{"docs.tacy.io", "*.example.org"}
		p.Connectors["web"] = w
	}), e.heartbeat())
	evs := runParity(t, e.s, proto.RunRequest{Permissions: guard.AllowAll(), Model: "kimi-k3", Messages: user1("hi")})
	if er, ok := lastError(evs); !ok || er.Code != safety.CodePolicyDenied {
		t.Fatalf("model not in the policy: %+v", evs)
	}
	evs = runParity(t, e.s, proto.RunRequest{Permissions: guard.AllowAll(), Messages: user1("read it")})
	if evs[len(evs)-1].Type != "done" || hits.Load() != 0 {
		t.Fatalf("fetch to a host outside the policy: hits %d, %+v", hits.Load(), evs)
	}
	found := false
	for _, ev := range evs {
		found = found || ev.Type == "tool_result" && strings.Contains(string(ev.Result), "not allowed by the policy")
	}
	if !found {
		t.Fatal("the model wasn't told the host is refused")
	}
}

func TestSafetyApprovalRequiredRefusesAction(t *testing.T) {
	e := newSafeEnv(t, pCalls([3]string{"c1", "web_search", `{"query":"x"}`}), pText("ok"))
	e.mustPost(e.policy(1, func(p *safety.Policy) { p.Approve = []string{"web.search"} }), e.heartbeat())
	runParity(t, e.s, proto.RunRequest{Permissions: guard.AllowAll(), Messages: user1("hi")})
	if len(e.fs.queries) != 0 {
		t.Fatal("an action held for approval ran")
	}
}

func TestSafetyOutputCapAndMissingUsage(t *testing.T) {
	// A long answer against a small budget: the guard ends the call once the output passes what was reserved.
	long := `data: {"choices":[{"delta":{"content":"` + strings.Repeat("word ", 2000) + `"},"finish_reason":"stop"}]}` + "\n\ndata: [DONE]\n\n"
	e := newSafeEnv(t, long)
	e.mustPost(e.policy(1, func(p *safety.Policy) { p.Budget.Run.Tokens = 2000 }), e.heartbeat())
	evs := runParity(t, e.s, proto.RunRequest{Permissions: guard.AllowAll(), Messages: user1("write a lot")})
	if er, ok := lastError(evs); !ok || er.Code != safety.CodeBudgetExceeded {
		t.Fatalf("output past the reservation: %+v", evs)
	}
	// No usage reported (the reply above has none): the whole reservation stays counted.
	e2 := newSafeEnv(t, `data: {"choices":[{"delta":{"content":"hi"},"finish_reason":"stop"}]}`+"\n\ndata: [DONE]\n\n")
	e2.mustPost(e2.policy(1, nil), e2.heartbeat())
	runParity(t, e2.s, proto.RunRequest{Permissions: guard.AllowAll(), Messages: user1("hi")})
	sg := e2.s.agent.(*recGateway).safeGateway
	if _, err := sg.ledger.Admit(testSpace, "", safety.Budgets{Day: safety.Limits{Tokens: safety.CompletionReserve}}); safety.CodeOf(err) != safety.CodeBudgetExceeded {
		t.Fatal("a call without reported usage was counted as less than its reservation")
	}
}

func TestSafetySlowSendersDontBlockStops(t *testing.T) {
	e := newSafeEnv(t)
	srv := httptest.NewServer(http.HandlerFunc(e.s.safetyIn))
	defer srv.Close()
	for range 6 { // more slow senders than slots, each trickling a body it never finishes
		c, err := net.Dial("tcp", strings.TrimPrefix(srv.URL, "http://"))
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		fmt.Fprintf(c, "POST /safety HTTP/1.1\r\nHost: x\r\nContent-Length: 100000\r\n\r\n[")
	}
	time.Sleep(100 * time.Millisecond)
	b, _ := jsonv2.Marshal([]safety.Envelope{e.heartbeat()})
	cl := &http.Client{Timeout: 3 * time.Second}
	res, err := cl.Post(srv.URL+"/safety", "application/json", bytes.NewReader(b))
	if err != nil || res.StatusCode != 200 {
		t.Fatalf("a stop list behind slow senders: %v %v", res, err)
	}
}
