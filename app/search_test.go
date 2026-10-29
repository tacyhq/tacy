package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	ehbpidentity "github.com/tinfoilsh/encrypted-http-body-protocol/identity"

	"github.com/tacyhq/tacy/activity"
	"github.com/tacyhq/tacy/agentclient"
	"github.com/tacyhq/tacy/guard"
	"github.com/tacyhq/tacy/proto"
	"github.com/tacyhq/tacy/runauth"
	"github.com/tacyhq/tacy/safety"
)

// POST /search, the plain chat's web search (search.go): one search the person allowed, through the same
// checks as agent mode's (policy, budgets, gatewayd's permission check, the quarantined reader, the record), and
// nothing else.

// searchOf sends req to the handler behind EHBP (as runParity does for /run) and returns the status and events.
func searchOf(t *testing.T, s *server, body []byte) (int, []proto.Event) {
	t.Helper()
	if s.searchSlots == nil {
		s.searchRoutes(http.NewServeMux(), mustIdentity(t))
	}
	r := httptest.NewRequest("POST", "/search", bytes.NewReader(body))
	w := httptest.NewRecorder()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	s.search(w, r.WithContext(withUser(ctx, "u1")))
	var evs []proto.Event
	sc := bufio.NewScanner(w.Body)
	sc.Buffer(make([]byte, 1<<20), 8<<20)
	for sc.Scan() {
		line, ok := strings.CutPrefix(sc.Text(), "data: ")
		if !ok || line == "[DONE]" {
			continue
		}
		var e proto.Event
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("event %q: %v", line, err)
		}
		evs = append(evs, e)
	}
	return w.Code, evs
}

func mustIdentity(t *testing.T) *ehbpidentity.Identity {
	id, err := ehbpidentity.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func searchBody(req proto.SearchRequest) []byte {
	b, _ := json.Marshal(req)
	return b
}

// recordedSearch is a search in testSpace whose records go to priv (the space's seal key in these tests), signed by
// testAsker's identity against the VM's key (v0.10.0), as e.recorded is for a run.
func (e *safeEnv) recordedSearch(priv *ecdh.PrivateKey, req proto.SearchRequest) proto.SearchRequest {
	a := &runauth.Asker{Space: testSpace, Seal: priv, Identity: testAsker.Identity, Key: testAsker.Key}
	if err := a.AuthorizeSearch(&req, e.vmKey.PublicKey().Bytes()); err != nil {
		e.t.Fatal(err)
	}
	return req
}

// signedSearch is req signed by testAsker for the env's VM.
func (e *safeEnv) signedSearch(req proto.SearchRequest) []byte {
	if err := testAsker.AuthorizeSearch(&req, e.vmKey.PublicKey().Bytes()); err != nil {
		e.t.Fatal(err)
	}
	return searchBody(req)
}

// withPrompts gives the env's agentd its permission prompts, as main does (the record then names the person's answer).
func (e *safeEnv) withPrompts() {
	rg := e.s.agent.(*recGateway)
	rg.prompts = &guard.Prompts{Release: e.s.rt.Release, Emit: func(string, proto.Event) {}, Cap: permissionCap(e.s.safety)}
	e.s.prompts = rg.prompts
}

func eventsOf(evs []proto.Event, typ string) []proto.Event {
	var out []proto.Event
	for _, e := range evs {
		if e.Type == typ {
			out = append(out, e)
		}
	}
	return out
}

func TestSearchRunsTheOneApprovedSearch(t *testing.T) {
	e := newSafeEnvWith(t, safeOpts{reader: readerAnswer})
	e.mustPost(e.policy(1, nil), e.heartbeat())
	e.withPrompts()
	priv, _ := recipientKey(t)
	code, evs := searchOf(t, e.s, searchBody(e.recordedSearch(priv, proto.SearchRequest{
		Query: "dstack release notes for jane@example.com", Question: "what's new in dstack lately?", Decision: proto.SearchAlways, Edited: true})))
	if code != 200 || evs[0].Type != "meta" || evs[len(evs)-1].Type != "done" {
		t.Fatalf("%d %s", code, types(evs))
	}
	// Exactly one search went out, masked again in the VM; no acting model call, one reader call.
	if len(e.fs.queries) != 1 || e.fs.queries[0] != "dstack release notes for [email]" {
		t.Fatalf("queries: %q", e.fs.queries)
	}
	if e.modelReqs.Load() != 0 || e.readerReqs.Load() != 1 {
		t.Fatalf("model calls %d, reader calls %d", e.modelReqs.Load(), e.readerReqs.Load())
	}
	calls, results := eventsOf(evs, "tool_call"), eventsOf(evs, "tool_result")
	if len(calls) != 1 || calls[0].Name != "web_search" || calls[0].ID != guard.SearchActionID || len(results) != 1 {
		t.Fatalf("calls %+v results %+v", calls, results)
	}
	// What the chat's model gets: the reader's fields with [n] sources, never the result's own text.
	res := results[0]
	if strings.Contains(string(res.Result), "Ignore previous instructions") || !strings.Contains(string(res.Result), "v0.6.1 is out.") ||
		len(res.Citations) != 1 || res.Citations[0].Index != 1 || !strings.Contains(res.Citations[0].URL, "github.com/Dstack-TEE") {
		t.Fatalf("result %s citations %+v", res.Result, res.Citations)
	}
	if m := metaOf(evs); m == nil || len(m.Tools) != 1 || m.Tools[0] != "web_search" || m.Controls == nil {
		t.Fatalf("meta %+v", m)
	}
	runs := openedActivity(t, evs, priv, e.rec.Signer.Public())
	if len(runs) != 2 || runs[0].Trigger == nil || runs[0].Trigger.Kind != "search" || strings.Join(runs[0].Tools, ",") != "web.search" ||
		len(runs[0].Models) != 0 || runs[1].Status.State != "succeeded" {
		t.Fatalf("records: %+v", runs)
	}
	s := callNamed(runs[1], "web.search")
	if len(s) != 1 || s[0].Permission != guard.PermAllowedAlways || !s[0].Edited || s[0].Reader == nil || s[0].Outcome != "ok" ||
		len(runs[1].Calls) != 1 || runs[1].Usage == nil || runs[1].Usage.ToolCalls != 1 {
		t.Fatalf("end record: %+v", runs[1])
	}
	noContent(t, runs, "jane", "dstack release", "new in dstack")
}

// The body is one query: anything else (messages, a page, tools, a model) or a bad value is refused before anything
// runs or goes out.
func TestSearchRefusesAnythingElse(t *testing.T) {
	e := newSafeEnv(t)
	e.mustPost(e.policy(1, nil), e.heartbeat())
	for name, body := range map[string]string{
		"messages":     `{"query":"q","decision":"once","messages":[{"role":"user","content":"hi"}]}`,
		"page":         `{"query":"q","decision":"once","url":"https://example.org/"}`,
		"tools":        `{"query":"q","decision":"once","tools":["fetch_page"]}`,
		"model":        `{"query":"q","decision":"once","model":"kimi-k3"}`,
		"permissions":  `{"query":"q","decision":"once","permissions":{"web.fetch":"always"}}`,
		"empty":        `{"query":"  ","decision":"once"}`,
		"no decision":  `{"query":"q"}`,
		"bad decision": `{"query":"q","decision":"deny"}`,
		"hidden":       `{"query":"q​q","decision":"once"}`,
		"count":        `{"query":"q","decision":"once","count":9}`,
		"long":         `{"query":"` + strings.Repeat("a", 301) + `","decision":"once"}`,
		"tag question": `{"query":"q","decision":"once","question":"hi 󠁁"}`,
		"not json":     `query=q`,
		"duplicate":    `{"query":"q","query":"other","decision":"once"}`,
		"bad record":   `{"query":"q","decision":"once","record_to":"x25519:AAAA"}`,
		"unsigned":     `{"query":"q","decision":"once"}`,
	} {
		code, evs := searchOf(t, e.s, []byte(body))
		if code != 400 || len(evs) != 0 {
			t.Errorf("%s: %d %s", name, code, types(evs))
		}
	}
	// Signed (v0.10.0), a bad value is still refused, after the where and who.
	for name, r := range map[string]proto.SearchRequest{
		"empty":        {Query: "  ", Decision: "once"},
		"bad decision": {Query: "q", Decision: "deny"},
		"count":        {Query: "q", Decision: "once", Count: 9},
		"long":         {Query: strings.Repeat("a", 301), Decision: "once"},
		"tag question": {Query: "q", Decision: "once", Question: "hi 󠁁"},
	} {
		code, evs := searchOf(t, e.s, e.signedSearch(r))
		if code != 400 || len(evs) != 0 {
			t.Errorf("signed %s: %d %s", name, code, types(evs))
		}
	}
	if len(e.fs.queries) != 0 || e.modelReqs.Load() != 0 {
		t.Fatalf("something ran: %q, %d model calls", e.fs.queries, e.modelReqs.Load())
	}
}

// v0.10.0: a search carries a run's where and who, under its own label: one signed for another VM, changed after
// signing, replayed, or carrying a run's signature is refused at the door (400, nothing recorded, nothing out).
func TestSearchRunAuth(t *testing.T) {
	e := newSafeEnvWith(t, safeOpts{reader: readerAnswer})
	e.mustPost(e.policy(1, nil), e.heartbeat())
	priv, _ := recipientKey(t)
	ok := e.recordedSearch(priv, proto.SearchRequest{Query: "acme quarterly results", Decision: proto.SearchOnce})
	refused := func(why string, body []byte) {
		t.Helper()
		code, evs := searchOf(t, e.s, body)
		if code != 400 || len(evs) != 0 {
			t.Errorf("%s: %d %s", why, code, types(evs))
		}
	}
	r := ok
	r.Query = "acme quarterly results and more"
	refused("changed after signing", searchBody(r))
	other, _ := ecdh.X25519().GenerateKey(rand.Reader)
	r = proto.SearchRequest{Query: "acme quarterly results", Decision: proto.SearchOnce}
	if err := testAsker.AuthorizeSearch(&r, other.PublicKey().Bytes()); err != nil {
		t.Fatal(err)
	}
	refused("signed for another VM", searchBody(r))
	run := e.recorded(priv, proto.RunRequest{Messages: []proto.Message{{Role: "user", Content: "acme quarterly results"}}})
	r = ok
	r.Nonce, r.SignedAt, r.IdentitySig = run.Nonce, run.SignedAt, run.IdentitySig
	refused("a run's signature", searchBody(r))
	if len(e.fs.queries) != 0 {
		t.Fatalf("searched: %q", e.fs.queries)
	}
	code, evs := searchOf(t, e.s, searchBody(ok))
	if code != 200 || evs[len(evs)-1].Type != "done" || len(e.fs.queries) != 1 {
		t.Fatalf("the signed search: %d %s", code, types(evs))
	}
	// Its records are the space's: sealed to its seal key, naming the identity.
	runs := openedActivity(t, evs, priv, e.rec.Signer.Public())
	if len(runs) != 2 || runs[0].Space != testSpace || runs[0].Member != testAsker.Identity {
		t.Fatalf("records: %+v", runs)
	}
	refused("replayed", searchBody(ok))
	if len(e.fs.queries) != 1 {
		t.Fatalf("the replay searched: %q", e.fs.queries)
	}
	// Nothing was recorded for a refused request: the space's chain holds the search's start and end.
	if _, head, _ := e.rec.Head(testSpace, runauth.SealString(priv.PublicKey())); head.Seq != 2 {
		t.Fatalf("chain head %d, want 2", head.Seq)
	}
}

// The policy, the stop lists and the budgets decide as for any search; nothing goes out when they say no.
func TestSearchPolicyAndBudgets(t *testing.T) {
	ok := proto.SearchRequest{Query: "acme quarterly results", Decision: proto.SearchOnce}
	t.Run("NoPolicy", func(t *testing.T) {
		e := newSafeEnv(t)
		priv, _ := recipientKey(t)
		code, evs := searchOf(t, e.s, searchBody(e.recordedSearch(priv, ok)))
		er, isErr := lastError(evs)
		if code != 200 || !isErr || er.Code != safety.CodePolicyMissing || len(e.fs.queries) != 0 {
			t.Fatalf("%d %+v", code, evs)
		}
		runs := openedActivity(t, evs, priv, e.rec.Signer.Public())
		if len(runs) != 1 || runs[0].Event != activity.EventRefused || runs[0].Trigger.Kind != "search" || runs[0].Status.Code != safety.CodePolicyMissing {
			t.Fatalf("refused record: %+v", runs)
		}
		noContent(t, runs, "acme")
	})
	t.Run("SearchNotAllowed", func(t *testing.T) {
		e := newSafeEnv(t)
		e.mustPost(e.policy(1, func(p *safety.Policy) {
			w := p.Connectors["web"]
			w.Tools = []string{"web.fetch"}
			p.Connectors["web"] = w
		}), e.heartbeat())
		_, evs := searchOf(t, e.s, e.signedSearch(ok))
		if er, isErr := lastError(evs); !isErr || er.Code != safety.CodePolicyDenied || len(e.fs.queries) != 0 {
			t.Fatalf("%+v", evs)
		}
	})
	t.Run("CappedToNever", func(t *testing.T) {
		e := newSafeEnv(t)
		e.mustPost(e.policy(1, func(p *safety.Policy) { p.AskCap = map[string]string{"web.search": safety.PermNever} }), e.heartbeat())
		_, evs := searchOf(t, e.s, e.signedSearch(ok))
		if er, isErr := lastError(evs); !isErr || er.Code != "search_denied" || !strings.Contains(er.Error, "don't allow web search") ||
			len(e.fs.queries) != 0 {
			t.Fatalf("%+v", evs)
		}
	})
	t.Run("RunBudget", func(t *testing.T) {
		e := newSafeEnvWith(t, safeOpts{reader: readerAnswer})
		e.mustPost(e.policy(1, func(p *safety.Policy) { p.Budget.Run.CostMicros = safety.SearchCost / 2 }), e.heartbeat())
		_, evs := searchOf(t, e.s, e.signedSearch(ok))
		if er, isErr := lastError(evs); !isErr || er.Code != safety.CodeBudgetExceeded || len(e.fs.queries) != 0 || e.readerReqs.Load() != 0 {
			t.Fatalf("%+v", evs)
		}
	})
	t.Run("Stopped", func(t *testing.T) {
		e := newSafeEnv(t)
		e.mustPost(e.policy(1, nil), e.heartbeat())
		e.mustPost(e.stop(safety.IssuerOperator, 99, func(l *safety.StopList) { l.All = true }, e.operator))
		_, evs := searchOf(t, e.s, e.signedSearch(ok))
		if er, isErr := lastError(evs); !isErr || er.Code != safety.CodeStopped || len(e.fs.queries) != 0 {
			t.Fatalf("%+v", evs)
		}
	})
}

// Before decryption: the relay's token, an encrypted body and a well-formed user tag; then a slot (two searches at
// once per user). Over EHBP end to end, the query never shows on the wire, and a body encrypted to another key fails.
func TestSearchTokenEHBPAndSlots(t *testing.T) {
	e := newSafeEnv(t)
	e.mustPost(e.policy(1, nil), e.heartbeat())
	id := e.s.id
	mux := http.NewServeMux()
	mux.HandleFunc("GET /attest", e.s.attest)
	e.s.searchRoutes(mux, id)
	var wire bytes.Buffer
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		wire.Write(body)
		mu.Unlock()
		r.Body = io.NopCloser(bytes.NewReader(body))
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, r)
		mu.Lock()
		wire.Write(rec.Body.Bytes())
		mu.Unlock()
		for k, v := range rec.Header() {
			w.Header()[k] = v
		}
		w.WriteHeader(rec.Code)
		w.Write(rec.Body.Bytes())
	}))
	defer srv.Close()
	conn, _ := agentclient.New(srv.URL, "tok", id.MarshalPublicKey())
	var got []proto.Event
	if err := conn.Search(context.Background(), proto.SearchRequest{Query: "private lookup words", Decision: proto.SearchOnce},
		func(ev proto.Event) { got = append(got, ev) }); err != nil || got[len(got)-1].Type != "done" {
		t.Fatalf("search: %v %s", err, types(got))
	}
	if bytes.Contains(wire.Bytes(), []byte("private lookup")) || bytes.Contains(wire.Bytes(), []byte("dstack v0.6.1")) {
		t.Fatal("plaintext on the wire")
	}
	conn.Token = "nope"
	if err := conn.Search(context.Background(), proto.SearchRequest{Query: "q", Decision: proto.SearchOnce}, func(proto.Event) {}); err == nil ||
		!strings.Contains(err.Error(), "401") {
		t.Fatalf("wrong token: %v", err)
	}
	other, _ := ehbpidentity.NewIdentity()
	conn, _ = agentclient.New(srv.URL, "tok", other.MarshalPublicKey())
	if err := conn.Search(context.Background(), proto.SearchRequest{Query: "q", Decision: proto.SearchOnce}, func(proto.Event) {}); err == nil {
		t.Fatal("a body encrypted to another key ran")
	}
	for name, mk := range map[string]func(r *http.Request){
		"plaintext": func(r *http.Request) {},
		"bad tag": func(r *http.Request) {
			r.Header.Set("Ehbp-Encapsulated-Key", "x")
			r.Header.Set("X-Agent-User", "not hex!")
		},
	} {
		r, _ := http.NewRequest("POST", srv.URL+"/search", strings.NewReader(`{"query":"q","decision":"once"}`))
		r.Header.Set("Authorization", "Bearer tok")
		mk(r)
		res, err := http.DefaultClient.Do(r)
		if err != nil || res.StatusCode != 400 {
			t.Fatalf("%s: %v %d", name, err, res.StatusCode)
		}
	}
	if n := len(e.fs.queries); n != 1 {
		t.Fatalf("searches: %d", n)
	}

	// Slots: a user's third search at once is refused before decryption.
	block := make(chan struct{})
	held := make(chan struct{}, 2)
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { held <- struct{}{}; <-block })
	h := e.s.searchGuard(inner)
	do := func() int {
		r := httptest.NewRequest("POST", "/search", strings.NewReader("x"))
		r.Header.Set("Authorization", "Bearer tok")
		r.Header.Set("Ehbp-Encapsulated-Key", "x")
		r.Header.Set("X-Agent-User", "abcdef0123456789")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}
	var wg sync.WaitGroup
	codes := make([]int, 2)
	for i := range 2 {
		wg.Add(1)
		go func() { defer wg.Done(); codes[i] = do() }()
	}
	for range 2 {
		select {
		case <-held:
		case <-time.After(5 * time.Second):
			t.Fatal("a search wasn't let through")
		}
	}
	if c := do(); c != 429 {
		t.Fatalf("third at once: %d", c)
	}
	close(block)
	wg.Wait()
	if !slices.Equal(codes, []int{200, 200}) {
		t.Fatalf("held: %v", codes)
	}
	if c := do(); c != 200 {
		t.Fatalf("after: %d", c)
	}
}

// POST /pictures (v0.10.0): unsigned or replayed is refused at the door with nothing recorded; a signed one runs in
// its proven space (a ticket from another space isn't found there: guard/pictures_test.go) and its records are that
// space's.
func TestPicturesRunAuth(t *testing.T) {
	e := newSafeEnv(t)
	e.mustPost(e.policy(1, nil), e.heartbeat())
	priv, _ := recipientKey(t)
	of := func(body []byte) (int, []proto.Event) {
		t.Helper()
		if e.s.searchSlots == nil {
			e.s.searchRoutes(http.NewServeMux(), mustIdentity(t))
		}
		r := httptest.NewRequest("POST", "/pictures", bytes.NewReader(body))
		w := httptest.NewRecorder()
		e.s.pictures(w, r.WithContext(withUser(context.Background(), "u1")))
		var evs []proto.Event
		for _, line := range strings.Split(w.Body.String(), "\n") {
			if d, ok := strings.CutPrefix(line, "data: "); ok && d != "[DONE]" {
				var ev proto.Event
				if err := json.Unmarshal([]byte(d), &ev); err != nil {
					t.Fatal(err)
				}
				evs = append(evs, ev)
			}
		}
		return w.Code, evs
	}
	ticket := strings.Repeat("ab", 16)
	if code, evs := of([]byte(`{"ticket":"` + ticket + `"}`)); code != 400 || len(evs) != 0 {
		t.Fatalf("unsigned: %d %s", code, types(evs))
	}
	if code, evs := of([]byte(`{"ticket":"` + ticket + `","record_to":"x25519:AAAA"}`)); code != 400 || len(evs) != 0 {
		t.Fatalf("v0.9.0's record_to: %d %s", code, types(evs))
	}
	req := proto.PicturesRequest{Ticket: ticket}
	a := &runauth.Asker{Space: testSpace, Seal: priv, Identity: testAsker.Identity, Key: testAsker.Key}
	if err := a.AuthorizePictures(&req, e.vmKey.PublicKey().Bytes()); err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(req)
	code, evs := of(body)
	if er, isErr := lastError(evs); code != 200 || !isErr || er.Type != "error" {
		t.Fatalf("signed, unknown ticket: %d %s", code, types(evs))
	}
	runs := openedActivity(t, evs, priv, e.rec.Signer.Public())
	if len(runs) != 2 || runs[0].Space != testSpace || runs[0].Member != testAsker.Identity || runs[0].Trigger.Kind != "search" {
		t.Fatalf("records: %+v", runs)
	}
	if code, evs := of(body); code != 400 || len(evs) != 0 {
		t.Fatalf("replayed: %d %s", code, types(evs))
	}
}
