package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdh"
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
	"github.com/tacyhq/tacy/safety"
)

// POST /search, the plain chat's web search (search.go, docs/29): one search the person allowed, through the same
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

// recordedSearch is a search whose records go to priv's key, with the proof.
func (e *safeEnv) recordedSearch(priv *ecdh.PrivateKey, req proto.SearchRequest) proto.SearchRequest {
	r := e.recorded(priv, proto.RunRequest{})
	req.RecordTo, req.RecordProof = r.RecordTo, r.RecordProof
	return req
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
	} {
		code, evs := searchOf(t, e.s, []byte(body))
		if code != 400 || len(evs) != 0 {
			t.Errorf("%s: %d %s", name, code, types(evs))
		}
	}
	if len(e.fs.queries) != 0 || e.modelReqs.Load() != 0 {
		t.Fatalf("something ran: %q, %d model calls", e.fs.queries, e.modelReqs.Load())
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
		_, evs := searchOf(t, e.s, searchBody(ok))
		if er, isErr := lastError(evs); !isErr || er.Code != safety.CodePolicyDenied || len(e.fs.queries) != 0 {
			t.Fatalf("%+v", evs)
		}
	})
	t.Run("CappedToNever", func(t *testing.T) {
		e := newSafeEnv(t)
		e.mustPost(e.policy(1, func(p *safety.Policy) { p.AskCap = map[string]string{"web.search": safety.PermNever} }), e.heartbeat())
		_, evs := searchOf(t, e.s, searchBody(ok))
		if er, isErr := lastError(evs); !isErr || er.Code != "search_denied" || !strings.Contains(er.Error, "don't allow web search") ||
			len(e.fs.queries) != 0 {
			t.Fatalf("%+v", evs)
		}
	})
	t.Run("RunBudget", func(t *testing.T) {
		e := newSafeEnvWith(t, safeOpts{reader: readerAnswer})
		e.mustPost(e.policy(1, func(p *safety.Policy) { p.Budget.Run.CostMicros = safety.SearchCost / 2 }), e.heartbeat())
		_, evs := searchOf(t, e.s, searchBody(ok))
		if er, isErr := lastError(evs); !isErr || er.Code != safety.CodeBudgetExceeded || len(e.fs.queries) != 0 || e.readerReqs.Load() != 0 {
			t.Fatalf("%+v", evs)
		}
	})
	t.Run("Stopped", func(t *testing.T) {
		e := newSafeEnv(t)
		e.mustPost(e.policy(1, nil), e.heartbeat())
		e.mustPost(e.stop(safety.IssuerOperator, 99, func(l *safety.StopList) { l.All = true }, e.operator))
		_, evs := searchOf(t, e.s, searchBody(ok))
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
