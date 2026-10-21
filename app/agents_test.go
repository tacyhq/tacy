package main

import (
	"context"
	"crypto/ecdh"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tacyhq/tacy/agentclient"
	"github.com/tacyhq/tacy/approval"
	"github.com/tacyhq/tacy/guard"
	"github.com/tacyhq/tacy/proto"
	"github.com/tacyhq/tacy/runauth"
	"github.com/tacyhq/tacy/safety"
)

// Built-in agents in agentd (docs/30 slice 1): a_research started through POST /tasks with the full stack (signed
// request, policy, budgets, the quarantined reader, permission prompts, activity records), against a stand-in model,
// search provider and pages: it completes within its caps with a cited brief; its caps, the policy's narrowing and
// the brief-only rule hold; a link the model composed still asks under "allow for this task"; a delete removes the
// task and its result; retention keeps a research result up to 7 days.

// standInPages are two sources that disagree (the year the fictional Gullwing light was lit) and a third page no
// search names.
func standInPages(t *testing.T) *httptest.Server {
	pages := map[string]string{
		"/a": "<html><head><title>Gullwing Light history</title></head><body><p>The Gullwing Point light was first lit in 1871 and automated in 1968.</p></body></html>",
		"/b": "<html><head><title>Coast lights register</title></head><body><p>Register: Gullwing Point, first lit 1873, automated 1968.</p></body></html>",
		"/c": "<html><body><p>Unlisted page.</p></body></html>",
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/slow") {
			select {
			case <-time.After(3 * time.Second):
			case <-r.Context().Done():
			}
		}
		w.Header().Set("Content-Type", "text/html")
		io.WriteString(w, cmpStr(pages[r.URL.Path], "<p>slow</p>"))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func cmpStr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// pageSearch answers every search with the stand-in pages /a and /b, and counts the searches.
type pageSearch struct {
	base    string
	mu      sync.Mutex
	queries []string
}

func (p *pageSearch) Name() string { return "fake" }
func (p *pageSearch) Search(_ context.Context, q string, _ int) ([]guard.SearchResult, error) {
	p.mu.Lock()
	p.queries = append(p.queries, q)
	p.mu.Unlock()
	return []guard.SearchResult{
		{Title: "Gullwing Light history", URL: p.base + "/a", Snippet: "first lit in 1871", Age: "2026-09-30"},
		{Title: "Coast lights register", URL: p.base + "/b", Snippet: "first lit 1873", Age: "2025-04-02"},
	}, nil
}

func (p *pageSearch) count() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.queries)
}

type agentEnv struct {
	*permEnv
	pages  *httptest.Server
	search *pageSearch
	seal   *ecdh.PrivateKey // the space's seal key: the records open with it
}

// newAgentEnv is agentd with the reader on, the stand-in search and pages, a policy (edit narrows it), permission prompts.
func newAgentEnv(t *testing.T, edit func(p *safety.Policy), replies ...string) *agentEnv {
	pages := standInPages(t)
	ps := &pageSearch{base: pages.URL}
	e := newSafeEnvWith(t, safeOpts{reader: reviewReader, search: ps}, replies...) // readerAnswer, and a review's file sections
	e.mustPost(e.policy(1, edit), e.heartbeat())
	host := e.s.tasks()
	pe := &permEnv{safeEnv: e, asks: make(chan proto.Permission, 16), settled: make(chan proto.Permission, 16)}
	pe.prompts = &guard.Prompts{Release: e.s.rt.Release, Cap: permissionCap(e.s.safety), Timeout: 10 * time.Second,
		OnWait: e.s.agent.(*recGateway).waiting, Sources: host.Sources,
		Emit: func(task string, ev proto.Event) {
			host.Emit(task, ev)
			if ev.Type == "permission" && ev.Permission.Decision == "" {
				pe.asks <- *ev.Permission
			} else if ev.Type == "permission" {
				pe.settled <- *ev.Permission
			}
		}}
	e.s.agent.(*recGateway).prompts = pe.prompts
	e.s.prompts = pe.prompts
	// Approve before send as main() wires it on the chat VM (v0.12.0): the side store, no approver directory, the
	// policy's approve list. An action the release's approval table doesn't know is a send and is refused here (no
	// approver): the built-in agents' every tool must be known (v0.13.0 shipped files.* unknown and was rolled back).
	rg := e.s.agent.(*recGateway)
	e.s.approvals = &guard.Approvals{Release: e.s.rt.Release, Store: approval.NewMemStore(), IDKey: []byte("agentd id key"),
		OnWait: rg.waiting, Emit: host.Emit, Check: approval.Config{RP: ReleaseRP},
		Listed: func(space, action string) bool {
			p, err := e.s.safety.Policy(space)
			return err == nil && p.NeedsApproval(action)
		}}
	rg.approvals = e.s.approvals
	seal, _ := recipientKey(t)
	return &agentEnv{permEnv: pe, pages: pages, search: ps, seal: seal}
}

// conn is a task API client in the tests' space whose records open with ae.seal.
func (ae *agentEnv) conn(t *testing.T, user string) *agentclient.Conn {
	c := connTo(t, ae.s, user)
	c.Asker = &runauth.Asker{Space: testSpace, Seal: ae.seal, Identity: testAsker.Identity, Key: testAsker.Key}
	return c
}

func research(brief string) proto.RunRequest {
	return proto.RunRequest{Agent: guard.AgentResearch, Model: proto.DefaultModel, RunSecret: permSecret,
		Permissions: map[string]string{"web.search": safety.PermAlways, "web.fetch": safety.PermAlways}, // the start card's "allow for this task"
		Messages:    []proto.Message{{Role: "user", Content: brief}}}
}

// runAgentTask starts req and follows it to its end.
func runAgentTask(t *testing.T, c *agentclient.Conn, req proto.RunRequest) (string, []proto.Event) {
	t.Helper()
	tk, err := c.StartTask(context.Background(), req, "")
	if err != nil {
		t.Fatal(err)
	}
	var evs []proto.Event
	for _, e := range followAll(t, c, tk.Task, 0) {
		evs = append(evs, e.ev)
	}
	return tk.Task, evs
}

func answerText(evs []proto.Event) string {
	var b strings.Builder
	for _, e := range evs {
		if e.Type == "text" {
			b.WriteString(e.Delta)
		}
	}
	return b.String()
}

const researchBrief = "Brief: when was the Gullwing Point light first lit, and do sources agree?"

var researchAnswer = "## Summary\nThe Gullwing Point light was first lit in 1871 [1], though one register says 1873 [2].\n" +
	"## Findings\n- First lit: 1871 [1]; automated 1968 [1][2].\n## Where sources disagree\n- The year first lit: 1871 [1] vs 1873 [2].\n" +
	"## Open questions\n- Which year the original records give.\n## Sources\n[1] Gullwing Light history, 2026-09-30\n[2] Coast lights register, 2025-04-02\n"

// A research run completes within its caps, with a cited brief from the stand-in pages; its meta, metrics and
// records name the agent; nothing is asked (searches and reads allowed for this task); no icon or picture fetches.
func TestResearchTask(t *testing.T) {
	ae := newAgentEnv(t, nil,
		pCalls([3]string{"c1", "web_search", `{"query":"Gullwing Point light first lit"}`}, [3]string{"c2", "web_search", `{"query":"Gullwing light register"}`}),
		pCalls([3]string{"c3", "fetch_page", `{"url":"[1]"}`}, [3]string{"c4", "fetch_page", `{"url":"[2]"}`}),
		pText(researchAnswer))
	c := ae.conn(t, tasksUser)
	id, evs := runAgentTask(t, c, research(researchBrief))
	if evs[len(evs)-1].Type != "done" {
		t.Fatalf("run %s: %+v", types(evs), evs[len(evs)-1])
	}
	ae.noAsk()
	text := answerText(evs)
	cites := regexp.MustCompile(`\[(\d+)\]`).FindAllStringSubmatch(text, -1)
	var meta *proto.Meta
	reads, agentMetrics, otherMetrics := 0, 0, 0
	sources := map[int]string{}
	for _, e := range evs {
		switch {
		case e.Type == "meta":
			meta = e.Meta
		case e.Type == "tool_result" && e.Name == "fetch_page":
			reads++
		case e.Type == "metrics" && e.Metrics.Agent == guard.AgentResearch:
			agentMetrics++
		case e.Type == "metrics":
			otherMetrics++
		case e.Type == "favicon" || e.Type == "image":
			t.Fatalf("a research task fetched %s", e.Type)
		}
		for _, ci := range e.Citations {
			sources[ci.Index] = ci.URL
		}
	}
	if meta == nil || meta.Agent != guard.AgentResearch || !slices.Equal(meta.Tools, []string{"web_search", "fetch_page"}) {
		t.Fatalf("meta %+v", meta)
	}
	if len(cites) < 4 || !strings.Contains(text, "## Where sources disagree") || !strings.Contains(text, "## Sources") ||
		ae.search.count() != 2 || reads != 2 || sources[1] != ae.pages.URL+"/a" || sources[2] != ae.pages.URL+"/b" {
		t.Fatalf("brief: %d cites, %d searches, %d reads, sources %v", len(cites), ae.search.count(), reads, sources)
	}
	if agentMetrics == 0 || otherMetrics != 0 {
		t.Fatalf("metrics: %d with the agent, %d without", agentMetrics, otherMetrics)
	}
	// The model got the research instructions and the brief only.
	if body := ae.model.bodies[0]; !strings.Contains(body, "research agent") || !strings.Contains(body, "Gullwing Point light") {
		t.Fatal("first model call: not the research instructions and brief")
	}
	runs := openedActivity(t, evs, ae.seal, ae.rec.Signer.Public())
	start, end := runs[0], runs[len(runs)-1]
	ref := guard.AgentRef(guard.AgentResearch)
	if start.Agent == nil || start.Agent.ID != guard.AgentResearch || start.Agent.Digest != ref.Digest || start.Limits == nil ||
		start.Limits.MaxSteps != 30 || end.Status.State != "succeeded" || end.Usage.ToolCalls != 4 {
		t.Fatalf("records: start %+v %+v, end %+v %+v", start.Agent, start.Limits, end.Status, end.Usage)
	}
	// Disk: what the queue keeps for the result (the browser deletes it once saved; at most 7 days).
	bytes, n := 0, 0
	evsStored, _ := ae.s.rt.Store.Events(id, 0, 10_000)
	for _, e := range evsStored {
		bytes += len(e.Data)
		n++
	}
	t.Logf("stored: %d events, %d bytes", n, bytes)
}

// The caps hold. Searches: a model that keeps asking (24 in 6 steps) gets 20; the other 4 are refused at the cap
// with words telling it to write the brief, and the task still answers ($1 is well above 20 searches at $0.01 plus
// their reader calls). Page reads: 44 asked for, 40 go out, 4 refused at the cap.
func TestResearchCaps(t *testing.T) {
	steps := func(n int, call func(i, j int) [3]string) []string {
		var out []string
		for i := range n {
			var calls [][3]string
			for j := range 4 {
				calls = append(calls, call(i, j))
			}
			out = append(out, pCalls(calls...))
		}
		return out
	}
	replies := steps(6, func(i, j int) [3]string {
		return [3]string{fmt.Sprintf("c%d_%d", i, j), "web_search", fmt.Sprintf(`{"query":"harbor light %d %d"}`, i, j)}
	})
	ae := newAgentEnv(t, nil, append(replies, pText(researchAnswer))...)
	_, evs := runAgentTask(t, ae.conn(t, tasksUser), research(researchBrief))
	capped, budget := 0, 0
	for _, e := range evs {
		switch {
		case e.Type != "tool_result":
		case strings.Contains(string(e.Result), guard.CapDenied+": this task has used its 20 searches"):
			capped++
		case strings.Contains(string(e.Result), "the rest is kept for the answer"):
			budget++
		}
	}
	if evs[len(evs)-1].Type != "done" || ae.search.count() != 20 || capped != 4 || budget != 0 || !strings.Contains(answerText(evs), "## Sources") {
		t.Fatalf("end %s, %d searches sent, %d refused at the cap, %d for the budget", evs[len(evs)-1].Type, ae.search.count(), capped, budget)
	}

	replies = append([]string{pCalls([3]string{"s", "web_search", `{"query":"harbor"}`})}, steps(11, func(i, j int) [3]string {
		return [3]string{fmt.Sprintf("f%d_%d", i, j), "fetch_page", fmt.Sprintf(`{"url":"[%d]"}`, 1+j%2)}
	})...)
	ae = newAgentEnv(t, nil, append(replies, pText(researchAnswer))...)
	_, evs = runAgentTask(t, ae.conn(t, tasksUser), research(researchBrief))
	read, capped := 0, 0
	for _, e := range evs {
		switch {
		case e.Type != "tool_result" || e.Name != "fetch_page":
		case strings.Contains(string(e.Result), guard.CapDenied+": this task has used its 40 page reads"):
			capped++
		case strings.Contains(string(e.Result), `"read"`):
			read++
		}
	}
	if evs[len(evs)-1].Type != "done" || read != 40 || capped != 4 {
		t.Fatalf("end %s, %d reads, %d refused at the cap", types(evs), read, capped)
	}
}

// The start: unknown agents, history, image search and /run are refused at the door; nothing is queued.
func TestResearchStartRefusals(t *testing.T) {
	ae := newAgentEnv(t, nil, pText("never"))
	c := ae.conn(t, tasksUser)
	for name, edit := range map[string]func(r *proto.RunRequest){
		"unknown agent": func(r *proto.RunRequest) { r.Agent = "a_review" },
		"history": func(r *proto.RunRequest) {
			r.Messages = []proto.Message{{Role: "user", Content: "hi"}, {Role: "assistant", Content: "hello [1]"}, {Role: "user", Content: researchBrief}}
		},
		"image search": func(r *proto.RunRequest) { r.Tools = []string{"web_search", "image_search"} },
		"more steps":   func(r *proto.RunRequest) { r.MaxSteps = 40 },
	} {
		r := research(researchBrief)
		edit(&r)
		if _, err := c.StartTask(context.Background(), r, ""); err == nil || !strings.Contains(err.Error(), "HTTP 400") {
			t.Errorf("%s: %v", name, err)
		}
	}
	// POST /run is the chat's: an agent's task outlives its tab.
	run := research(researchBrief)
	if err := c.Asker.Authorize(&run, c.Key()); err != nil {
		t.Fatal(err)
	}
	if code, body := postRun(ae.s, run, tasksUser); code != 400 || !strings.Contains(body, "starts through POST /tasks") {
		t.Fatalf("/run: %d %s", code, body)
	}
	if ae.model.n != 0 || ae.search.count() != 0 {
		t.Fatal("a refused start reached the model or the search")
	}
	// A signature that doesn't cover the agent field: changing it after signing is refused (runauth).
	r := research(researchBrief)
	r.Agent = ""
	if err := c.Asker.Authorize(&r, c.Key()); err != nil {
		t.Fatal(err)
	}
	r.Agent = guard.AgentResearch
	if _, err := c.StartTask(context.Background(), r, ""); err == nil {
		t.Fatal("an agent added after signing started")
	}
}

// A signed policy narrows an agent's limits, never widens them: f_chat's v1 policy (300 s per run) caps research's
// running time at 5 minutes; a policy with a bigger run budget leaves research at its own 15 minutes and $1.
func TestResearchPolicyNarrows(t *testing.T) {
	sg := func(edit func(p *safety.Policy)) *safeGateway {
		ae := newAgentEnv(t, edit, pText("x"))
		return ae.s.agent.(*recGateway).safeGateway
	}
	g := sg(func(p *safety.Policy) {
		p.Budget.Run = safety.Limits{WallSeconds: 300, ToolCalls: 64, CostMicros: 20_000_000}
	})
	e, _ := g.st.Policy(testSpace)
	if g.runLimit(testSpace, guard.AgentResearch) != 5*time.Minute || g.runLimit(testSpace, "") != 5*time.Minute {
		t.Fatalf("v1-like policy: research %v, chat %v", g.runLimit(testSpace, guard.AgentResearch), g.runLimit(testSpace, ""))
	}
	if b := budget(e, guard.AgentResearch); b.Run.ToolCalls != 60 || b.Run.CostMicros != 1_000_000 || b.Run.WallSeconds != 300 {
		t.Fatalf("research budget %+v", b.Run)
	}
	g = sg(func(p *safety.Policy) {
		p.Budget.Run = safety.Limits{WallSeconds: 3600, ToolCalls: 1000, CostMicros: 50_000_000}
	})
	e, _ = g.st.Policy(testSpace)
	if g.runLimit(testSpace, guard.AgentResearch) != 15*time.Minute || g.runLimit(testSpace, "") != 5*time.Minute {
		t.Fatal("a wider policy widened an agent")
	}
	if b := budget(e, guard.AgentResearch); b.Run.ToolCalls != 60 || b.Run.CostMicros != 1_000_000 || b.Run.WallSeconds != 900 {
		t.Fatalf("research budget %+v", b.Run)
	}
	if b := budget(e, ""); b.Run.WallSeconds != 300 || b.Run.CostMicros != 20_000_000 || b.Run.ToolCalls != 64 {
		t.Fatalf("chat budget %+v", b.Run)
	}
}

// Research's running time is its own (shortened here): a task reading a slow page past it ends "run timed out".
func TestResearchRunningTime(t *testing.T) {
	ae := newAgentEnv(t, nil, pCalls([3]string{"c1", "fetch_page", `{"url":"PAGES/slow"}`}), pText("late"))
	ae.model.replies[0] = strings.ReplaceAll(ae.model.replies[0], "PAGES", ae.pages.URL)
	ae.s.agent.(*recGateway).agentWork = map[string]time.Duration{guard.AgentResearch: time.Second}
	r := research("Brief: read " + ae.pages.URL + "/slow")
	_, evs := runAgentTask(t, ae.conn(t, tasksUser), r)
	if er, ok := lastError(evs); !ok || er.Error != "run timed out" {
		t.Fatalf("end %s %+v", types(evs), evs[len(evs)-1])
	}
}

// The cost budget keeps a reserve for the brief: once a search would eat into it, searches are refused with
// budget_exceeded and the model still writes its answer.
func TestResearchFinalReserve(t *testing.T) {
	ae := newAgentEnv(t, func(p *safety.Policy) { p.Budget.Run = safety.Limits{CostMicros: 180_000} },
		pCalls([3]string{"c1", "web_search", `{"query":"a"}`}), pCalls([3]string{"c2", "web_search", `{"query":"b"}`}),
		pCalls([3]string{"c3", "web_search", `{"query":"c"}`}), pText(researchAnswer))
	_, evs := runAgentTask(t, ae.conn(t, tasksUser), research(researchBrief))
	refused := 0
	for _, e := range evs {
		if e.Type == "tool_result" && strings.Contains(string(e.Result), "the rest is kept for the answer") {
			refused++
		}
	}
	if evs[len(evs)-1].Type != "done" || refused == 0 || ae.search.count() >= 3 || !strings.Contains(answerText(evs), "## Summary") {
		t.Fatalf("end %s, %d refused, %d searches", types(evs), refused, ae.search.count())
	}
}

// "Allow searches and page reads for this task" (decision 2) covers what code gave the task (results by number, the
// brief's own links); a link the model composed after reading the web is refused without asking (not_from_results,
// b75711c), and the task goes on to its brief.
func TestResearchComposedLinkRefused(t *testing.T) {
	ae := newAgentEnv(t, nil,
		pCalls([3]string{"c1", "web_search", `{"query":"Gullwing light"}`}),
		pCalls([3]string{"c2", "fetch_page", `{"url":"PAGES/c"}`}),
		pText(researchAnswer))
	ae.model.replies[1] = strings.ReplaceAll(ae.model.replies[1], "PAGES", ae.pages.URL)
	_, evs := runAgentTask(t, ae.conn(t, tasksUser), research(researchBrief))
	ae.noAsk() // neither the search nor the composed fetch was asked about
	if !strings.Contains(resultOf(evs, "c2"), guard.PermNotFromResults) || evs[len(evs)-1].Type != "done" {
		t.Fatalf("the composed fetch: %s; end %s", resultOf(evs, "c2"), types(evs))
	}
}

// POST /tasks/delete: a finished task's result is gone after it (status and events answer 404); a running task is
// cancelled and deleted once it ended; another user, or a call without the run's secret, deletes nothing.
func TestTaskDelete(t *testing.T) {
	ae := newAgentEnv(t, nil, pText(researchAnswer), "sleep 30s then "+pText("late"))
	c := ae.conn(t, tasksUser)
	id, evs := runAgentTask(t, c, research(researchBrief))
	if evs[len(evs)-1].Type != "done" {
		t.Fatalf("run %s", types(evs))
	}
	other := ae.conn(t, "fedcba9876543210fedc")
	other.SetTaskSecret(id, permSecret)
	if _, _, err := other.DeleteTask(context.Background(), id); err == nil || !strings.Contains(err.Error(), "404") {
		t.Fatalf("another user's delete: %v", err)
	}
	stranger := ae.conn(t, tasksUser) // the same user tag, without the run's secret (the relay alone)
	if _, _, err := stranger.DeleteTask(context.Background(), id); err == nil || !strings.Contains(err.Error(), "404") {
		t.Fatalf("a delete without the secret's MAC: %v", err)
	}
	if st, _ := ae.s.rt.Store.Task(id); st == nil {
		t.Fatal("deleted by a refused call")
	}
	deleted, _, err := c.DeleteTask(context.Background(), id)
	if err != nil || !deleted {
		t.Fatalf("delete: %v %v", deleted, err)
	}
	if st, _ := ae.s.rt.Store.Task(id); st != nil {
		t.Fatal("the task is still in the queue")
	}
	if evs, _ := ae.s.rt.Store.Events(id, 0, 10); len(evs) != 0 {
		t.Fatal("its events are still in the queue")
	}
	if _, err := c.TaskStatus(context.Background(), id); err == nil || !strings.Contains(err.Error(), "404") {
		t.Fatalf("status after delete: %v", err)
	}
	if _, _, err := c.DeleteTask(context.Background(), id); err == nil || !strings.Contains(err.Error(), "404") {
		t.Fatalf("a second delete: %v", err)
	}

	// Running: cancelled (refundable before any output), then deleted once it ended.
	tk, err := c.StartTask(context.Background(), research(researchBrief), "")
	if err != nil {
		t.Fatal(err)
	}
	waitTask(t, c, tk.Task, func(s *agentclient.Task) bool { return s.State == "running" })
	deleted, bill, err := c.DeleteTask(context.Background(), tk.Task)
	if err != nil || !deleted || !bill.Refundable || bill.Bill == "" {
		t.Fatalf("delete running: %v %+v %v", deleted, bill, err)
	}
	for end := time.Now().Add(10 * time.Second); ; time.Sleep(20 * time.Millisecond) {
		if st, _ := ae.s.rt.Store.Task(tk.Task); st == nil {
			break
		}
		if time.Now().After(end) {
			t.Fatal("the cancelled task wasn't deleted")
		}
	}
}

// Retention (decision 5): an ended research task's result stays until collected, at most 7 days; a chat task's for
// the host's day, as before.
func TestAgentRetention(t *testing.T) {
	ae := newAgentEnv(t, nil, pText(researchAnswer), pText("chat answer"))
	c := ae.conn(t, tasksUser)
	rid, _ := runAgentTask(t, c, research(researchBrief))
	chat := proto.RunRequest{Model: proto.DefaultModel, RunSecret: permSecret, Permissions: guard.AllowAll(), Messages: user1("hi")}
	cid, _ := runAgentTask(t, c, chat)
	h := ae.s.tasks()
	gone := func(id string) bool { st, _ := ae.s.rt.Store.Task(id); return st == nil }
	now := time.Now()
	if h.Prune(now.Add(time.Hour)) != 0 || gone(rid) || gone(cid) {
		t.Fatal("pruned within the hour")
	}
	if n := h.Prune(now.Add(2 * 24 * time.Hour)); n != 1 || !gone(cid) || gone(rid) {
		t.Fatalf("after 2 days: %d pruned, chat gone %v, research gone %v", n, gone(cid), gone(rid))
	}
	if n := h.Prune(now.Add(6 * 24 * time.Hour)); n != 0 || gone(rid) {
		t.Fatal("research pruned before 7 days")
	}
	if n := h.Prune(now.Add(7*24*time.Hour + time.Minute)); n != 1 || !gone(rid) {
		t.Fatalf("after 7 days: %d pruned, research gone %v", n, gone(rid))
	}
}
