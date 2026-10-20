package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/tacyhq/tacy/activity"
	"github.com/tacyhq/tacy/guard"
	"github.com/tacyhq/tacy/proto"
	"github.com/tacyhq/tacy/safety"
	"github.com/tacyhq/tacy/vault"
)

// The safety controls' decisions on the activity record (docs/23, docs/24): refusals at the door (a model the
// policy doesn't allow, a stale stop list), tools held for approval, hosts outside the
// policy, budgets, the vault's lease rate, and the stage 1 release (no keys pinned). Each shows as a code, a
// count or a lease decision: never the query, URL, page, text or a key value.

// noContent fails when any opened record holds one of the strings.
func noContent(t *testing.T, runs []*activity.Run, words ...string) {
	t.Helper()
	for _, r := range runs {
		b, _ := json.Marshal(r)
		for _, w := range words {
			if strings.Contains(strings.ToLower(string(b)), strings.ToLower(w)) {
				t.Fatalf("record %d holds %q: %s", r.Seq, w, b)
			}
		}
	}
}

func callNamed(r *activity.Run, name string) []activity.Call {
	var out []activity.Call
	for _, c := range r.Calls {
		if c.Name == name {
			out = append(out, c)
		}
	}
	return out
}

func TestActivityPolicyDecisionsOnTheRecord(t *testing.T) {
	var hits atomic.Int32
	page := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1); io.WriteString(w, "secret page") }))
	defer page.Close()
	e := newSafeEnv(t,
		pCalls([3]string{"c1", "web_search", `{"query":"acme merger target price"}`}, [3]string{"c2", "fetch_page", `{"url":"` + page.URL + `/deal-room/quarter-three"}`}),
		pText("couldn't"))
	e.mustPost(e.policy(1, func(p *safety.Policy) {
		p.Models = []string{"gpt-oss-120b"}
		w := p.Connectors["web"]
		w.Fetch = []string{"docs.tacy.io"}
		p.Connectors["web"] = w
		p.Approve = []string{"web.search"}
	}), e.heartbeat())
	priv, _ := recipientKey(t)
	key := e.rec.Signer.Public()

	// A model the policy doesn't allow: refused at the door, one refused record with the code.
	evs := runParity(t, e.s, e.recorded(priv, proto.RunRequest{Permissions: guard.AllowAll(), Model: "kimi-k3", Messages: user1("draft the acme memo")}))
	runs := openedActivity(t, evs, priv, key)
	if len(runs) != 1 || runs[0].Event != activity.EventRefused || runs[0].Status.Code != safety.CodePolicyDenied ||
		len(runs[0].Models) != 1 || runs[0].Models[0] != "kimi-k3" {
		t.Fatalf("model refused: %+v", runs)
	}
	noContent(t, runs, "acme", "memo")

	// A search held for approval and a fetch outside the policy's hosts: both on the end record with the code;
	// the fetch counts one refused request to the host and none sent.
	evs = runParity(t, e.s, e.recorded(priv, proto.RunRequest{Permissions: guard.AllowAll(), Messages: user1("look up the acme deal")}))
	runs = openedActivity(t, evs, priv, key)
	if len(runs) != 2 || runs[1].Status.State != "succeeded" {
		t.Fatalf("records: %+v", runs)
	}
	// The search needs approval, so the policy took it out of the run's tools: the start lists what was offered,
	// and the guard never saw a search.
	search, fetch := callNamed(runs[1], "web.search"), callNamed(runs[1], "web.fetch")
	if len(search) != 0 || slices.Contains(runs[0].Tools, "web.search") || !slices.Contains(runs[0].Tools, "web.fetch") {
		t.Fatalf("search held for approval: tools %v, calls %+v", runs[0].Tools, search)
	}
	if len(fetch) != 1 || fetch[0].Outcome != "failed" || fetch[0].Code != safety.CodePolicyDenied || len(fetch[0].Hosts) != 1 ||
		fetch[0].Hosts[0].Refused != 1 || fetch[0].Hosts[0].Requests != 0 || hits.Load() != 0 {
		t.Fatalf("fetch outside the policy: %+v (hits %d)", fetch, hits.Load())
	}
	noContent(t, runs, "acme", "merger", "target price", "deal-room", "quarter-three", "secret page", "couldn't")
}

func TestActivityStaleAndBudgetOnTheRecord(t *testing.T) {
	calls := [][3]string{}
	for _, id := range []string{"c1", "c2", "c3", "c4"} {
		calls = append(calls, [3]string{id, "web_search", `{"query":"matter 7731 ` + id + `"}`})
	}
	e := newSafeEnv(t, pCalls(calls...), pText("done"))
	priv, _ := recipientKey(t)
	key := e.rec.Signer.Public()

	// No operator list and a policy that stops reads while stale: refused at the door.
	e.mustPost(e.policy(1, func(p *safety.Policy) { p.StaleReads = false }))
	runs := openedActivity(t, runParity(t, e.s, e.recorded(priv, proto.RunRequest{Permissions: guard.AllowAll(), Messages: user1("hi")})), priv, key)
	if len(runs) != 1 || runs[0].Event != activity.EventRefused || runs[0].Status.Code != safety.CodeStale {
		t.Fatalf("stale: %+v", runs)
	}

	// Four parallel searches against a run budget of two: two ran, two refused with the code.
	e.mustPost(e.policy(2, func(p *safety.Policy) { p.Budget.Run.ToolCalls = 2 }), e.heartbeat())
	runs = openedActivity(t, runParity(t, e.s, e.recorded(priv, proto.RunRequest{Permissions: guard.AllowAll(), Messages: user1("search matter 7731")})), priv, key)
	if len(runs) != 2 {
		t.Fatalf("records: %+v", runs)
	}
	ok, refused := 0, 0
	for _, c := range callNamed(runs[1], "web.search") {
		switch {
		case c.Outcome == "ok":
			ok++
		case c.Outcome == "refused" && c.Code == safety.CodeBudgetExceeded:
			refused++
		default:
			t.Fatalf("search: %+v", c)
		}
	}
	if ok != 2 || refused != 2 || runs[1].Usage == nil || runs[1].Usage.ToolCalls != 4 && runs[1].Usage.ToolCalls != 2 {
		t.Fatalf("budget: %d ok, %d refused, usage %+v", ok, refused, runs[1].Usage)
	}
	noContent(t, runs, "matter", "7731")
}

func TestActivityRateLimitOnTheRecord(t *testing.T) {
	// The real search provider over a vault that refuses the key's lease for its rate (as gatewayd's lease).
	lease := guard.RecordLeases(func(context.Context, string, string, string) (*vault.Secret, error) { return nil, vault.ErrRateLimited })
	search := guard.NewSearch("tavily", func(string) bool { return false }, lease)
	e := newSafeEnvWith(t, safeOpts{search: search},
		pCalls([3]string{"c1", "web_search", `{"query":"opposing counsel strategy"}`}), pText("try later"))
	e.mustPost(e.policy(1, nil), e.heartbeat())
	priv, _ := recipientKey(t)
	evs := runParity(t, e.s, e.recorded(priv, proto.RunRequest{Permissions: guard.AllowAll(), Messages: user1("search it")}))
	runs := openedActivity(t, evs, priv, e.rec.Signer.Public())
	if len(runs) != 2 {
		t.Fatalf("records: %+v", runs)
	}
	s := callNamed(runs[1], "web.search")
	if len(s) != 1 || s[0].Outcome != "failed" || s[0].Code != safety.CodeRateLimited {
		t.Fatalf("search: %+v", s)
	}
	var l *activity.Lease
	for i := range runs[1].Leases {
		if runs[1].Leases[i].Call == s[0].ID {
			l = &runs[1].Leases[i]
		}
	}
	if l == nil || l.Secret != "TAVILY_API_KEY" || l.Decision != "denied" || l.Reason != "rate_limited" || l.Lease != "" {
		t.Fatalf("lease: %+v", runs[1].Leases)
	}
	if runs[1].Status.State != "succeeded" { // the model was told and answered; the call carries the code
		t.Fatalf("status: %+v", runs[1].Status)
	}
	noContent(t, runs, "opposing", "counsel", "strategy", "search it", "try later")
}

func TestActivityKeylessReleaseOnTheRecord(t *testing.T) {
	// Stage 1 (the live compose): no keys pinned, the release policy alone; the start names it.
	e := newSafeEnvWith(t, safeOpts{keyless: true}, pText("fine"))
	priv, _ := recipientKey(t)
	evs := runParity(t, e.s, e.recorded(priv, proto.RunRequest{Permissions: guard.AllowAll(), Messages: user1("hello")}))
	runs := openedActivity(t, evs, priv, e.rec.Signer.Public())
	rel := e.s.safety.StatusOf(testSpace).Release
	if len(runs) != 2 || runs[1].Status.State != "succeeded" || runs[0].Controls == nil || rel == "" || runs[0].Controls.ReleasePolicy != rel {
		t.Fatalf("keyless: %+v (release %q)", runs, rel)
	}
}
