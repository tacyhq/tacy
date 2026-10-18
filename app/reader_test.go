package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/tacyhq/tacy/activity"
	"github.com/tacyhq/tacy/guard"
	"github.com/tacyhq/tacy/proto"
	"github.com/tacyhq/tacy/safety"
)

// The quarantined reader in agentd (docs/27 slice 2): its model call is reserved and counted in the run's budget
// with the action it reads for, and recorded on the action in the activity record; the run's taint is on the record
// (the call that brought outside content in, the calls proposed after it); a budget that can't cover the reader
// refuses the action before anything is fetched.

func readerAnswer(prompt string) string {
	quotes := []map[string]any{}
	if strings.Contains(prompt, "Release v0.6.1 is out") {
		quotes = append(quotes, map[string]any{"id": 1, "location": "body", "topic": "release", "text": "Release v0.6.1 is out"})
	}
	b, _ := json.Marshal(map[string]any{"summary": "A release note [Q1].", "facts": []string{"v0.6.1 is out."}, "entities": []string{},
		"dates": []string{}, "amounts": []string{}, "source": map[string]any{"kind": "docs", "title": "Release", "publisher": "", "published": ""},
		"quotes": quotes, "wording": "", "instructions_found": false, "instruction_count": 0})
	return string(b)
}

func TestReaderBudgetAndRecord(t *testing.T) {
	var hits atomic.Int32
	page := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		io.WriteString(w, "<html><head><title>Release</title></head><body><p>Release v0.6.1 is out, with fixes.</p></body></html>")
	}))
	defer page.Close()
	e := newSafeEnvWith(t, safeOpts{reader: readerAnswer},
		pCalls([3]string{"c1", "fetch_page", `{"url":"` + page.URL + `/a"}`}),
		pCalls([3]string{"c2", "fetch_page", `{"url":"` + page.URL + `/b"}`}),
		pText("It is out: [quote 1] [1]."))
	e.mustPost(e.policy(1, nil), e.heartbeat())
	priv, _ := recipientKey(t)
	evs := runParity(t, e.s, e.recorded(priv, proto.RunRequest{Messages: user1("is v0.6.1 out?")}))
	if evs[len(evs)-1].Type != "done" || e.readerReqs.Load() != 2 || hits.Load() < 2 {
		t.Fatalf("run %s; reader calls %d, page hits %d", types(evs), e.readerReqs.Load(), hits.Load())
	}
	runs := openedActivity(t, evs, priv, e.rec.Signer.Public())
	end := runs[1]
	// Budget: three acting model calls (10+5, 10+5, 20+6 tokens) and two reader calls (1500+400 each), two tool calls.
	wantTokens := int64(15 + 15 + 26 + 2*1900)
	wantCost := 2*safety.ModelCost("gpt-oss-120b", 10, 5) + safety.ModelCost("gpt-oss-120b", 20, 6) + 2*safety.ModelCost(guard.ReaderModel, 1500, 400)
	if end.Usage == nil || end.Usage.Tokens != wantTokens || end.Usage.ToolCalls != 2 || end.Usage.CostMicros != wantCost {
		t.Fatalf("usage %+v, want %d tokens, $%d µ", end.Usage, wantTokens, wantCost)
	}
	var actions []activity.Call
	for _, c := range end.Calls {
		if c.Kind == "action" {
			actions = append(actions, c)
		} else if c.Tainted || c.Reader != nil {
			t.Fatalf("model call marked: %+v", c)
		}
	}
	if len(actions) != 2 {
		t.Fatalf("calls %+v", end.Calls)
	}
	first, second := actions[0], actions[1]
	if first.Reader == nil || *first.Reader != (activity.Reader{Model: guard.ReaderModel, Prompt: 1500, Completion: 400, Ms: first.Reader.Ms,
		Outcome: "ok", Quotes: 1}) {
		t.Fatalf("reader on the record: %+v", first.Reader)
	}
	// The first fetch brought outside content in; the second was proposed after the agent had read it.
	if !first.Untrusted || first.Tainted || !second.Untrusted || !second.Tainted || !end.Tainted {
		t.Fatalf("taint on the record: first %+v, second %+v, run %v", first, second, end.Tainted)
	}
	// The reader's request went to the model host, counted on the action's hosts.
	if len(first.Hosts) < 2 {
		t.Fatalf("hosts %+v", first.Hosts)
	}
	b, _ := json.Marshal(runs)
	if strings.Contains(string(b), "Release v0.6.1 is out") {
		t.Fatal("the record holds page text")
	}
}

// A budget that can't cover the reader's reservation refuses the fetch: nothing is fetched, the reader isn't
// called, and the model is told why.
func TestReaderBudgetRefusesFetch(t *testing.T) {
	var hits atomic.Int32
	page := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		io.WriteString(w, "<p>text</p>")
	}))
	defer page.Close()
	e := newSafeEnvWith(t, safeOpts{reader: readerAnswer},
		pCalls([3]string{"c1", "fetch_page", `{"url":"` + page.URL + `/a"}`}), pText("couldn't"))
	e.mustPost(e.policy(1, func(p *safety.Policy) { p.Budget.Run.Tokens = 6000 }), e.heartbeat())
	evs := runParity(t, e.s, proto.RunRequest{Messages: user1("read it")})
	if hits.Load() != 0 || e.readerReqs.Load() != 0 {
		t.Fatalf("page hits %d, reader calls %d", hits.Load(), e.readerReqs.Load())
	}
	refused := false
	for _, ev := range evs {
		refused = refused || ev.Type == "tool_result" && strings.Contains(string(ev.Result), safety.CodeBudgetExceeded)
	}
	if !refused {
		t.Fatalf("the fetch wasn't refused for the budget: %+v", evs)
	}
}

// After an agentd restart, a web action whose output came from the reader counts the reader's reservation again.
func TestJournalUsageCountsReader(t *testing.T) {
	_, p, c, _ := guard.ReaderReserve("web.fetch")
	out := `{"n":1,"note":"x","read":{"summary":"s"},"url":"https://a.example"}`
	if !readOutput([]byte(out)) || readOutput([]byte(`{"n":1,"text":"page"}`)) {
		t.Fatal("readOutput")
	}
	if got := readerUsed([]guard.ReaderUse{{Model: guard.ReaderModel, Sent: true}}, safety.Usage{Tokens: p + c}); got.Tokens != p+c {
		t.Fatalf("a reader call without counts: %+v", got)
	}
	if got := readerUsed([]guard.ReaderUse{{Model: guard.ReaderModel, Outcome: "failed", Why: "policy"}}, safety.Usage{Tokens: p + c}); got.Tokens != 0 {
		t.Fatalf("a reader call never sent: %+v", got)
	}
}

// An earlier assistant turn in the conversation taints the run from its start (docs/27 section 5): the end
// record says tainted although no call brought outside content in, and the first action is marked tainted. A run
// with only the person's message is clean.
func TestHistoryTaint(t *testing.T) {
	page := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "<p>Release v0.6.1 is out</p>")
	}))
	defer page.Close()
	e := newSafeEnvWith(t, safeOpts{reader: readerAnswer}, pText("Hello."), pCalls([3]string{"c1", "fetch_page", `{"url":"` + page.URL + `/a"}`}), pText("ok"))
	e.mustPost(e.policy(1, nil), e.heartbeat())
	priv, _ := recipientKey(t)
	evs := runParity(t, e.s, e.recorded(priv, proto.RunRequest{Messages: user1("hi")}))
	if end := openedActivity(t, evs, priv, e.rec.Signer.Public())[1]; end.Tainted {
		t.Fatalf("a run without history tainted: %+v", end)
	}
	msgs := []proto.Message{{Role: "user", Content: "is v0.6.1 out?"}, {Role: "assistant", Content: "Yes [1]."}, {Role: "user", Content: "read it again"}}
	evs = runParity(t, e.s, e.recorded(priv, proto.RunRequest{Messages: msgs}))
	runs := openedActivity(t, evs, priv, e.rec.Signer.Public())
	end := runs[len(runs)-1]
	if !end.Tainted {
		t.Fatalf("a run with an earlier assistant turn not tainted: %+v", end)
	}
	actions := 0
	for _, c := range end.Calls {
		if c.Kind == "action" {
			actions++
			if !c.Tainted {
				t.Fatalf("the first action of a run with history not marked tainted: %+v", c)
			}
		}
	}
	if actions != 1 {
		t.Fatalf("%d actions on the record, want 1", actions)
	}
}
