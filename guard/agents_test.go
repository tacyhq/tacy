package guard

import (
	"context"
	"encoding/json"
	"encoding/json/jsontext"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/tacyhq/tacy/harness"
	"github.com/tacyhq/tacy/proto"
	"github.com/tacyhq/tacy/safety"
)

// Built-in agents (docs/30 slice 1): the definitions are the release's, a request only picks and narrows one, a
// brief-only agent takes one message, and the guard counts its searches and page reads against its caps.

func researchReq(msgs ...proto.Message) *proto.RunRequest {
	if len(msgs) == 0 {
		msgs = []proto.Message{{Role: "user", Content: "Brief: what changed in harbor lighting rules this year?"}}
	}
	return &proto.RunRequest{Agent: AgentResearch, Space: testSpace, Messages: msgs, Permissions: AllowAll()}
}

func TestAgentDefinitions(t *testing.T) {
	if !slices.Equal(AgentIDs(), []string{AgentChat, AgentResearch, AgentReview}) {
		t.Fatalf("agents %v", AgentIDs())
	}
	// The chat's reference is as before agents existed; the research agent's names its definition's digest.
	if AgentRef("") != chatAgent || AgentRef(AgentChat) != chatAgent || AgentRef("a_nope") != chatAgent {
		t.Fatal("chat ref")
	}
	r := AgentRef(AgentResearch)
	if r.ID != AgentResearch || r.Version != "1" || len(r.Digest) != 64 || r.Digest == "unsigned" {
		t.Fatalf("research ref %+v", r)
	}
	// The digest covers the definition: changing a limit changes it.
	d := researchDef
	d.Searches++
	b1, _ := json.Marshal(researchDef)
	b2, _ := json.Marshal(d)
	if string(b1) == string(b2) {
		t.Fatal("digest input ignores the caps")
	}
	// docs/30's limits.
	if d, _ := Definition(AgentResearch); d.Steps != 30 || d.Searches != 20 || d.Reads != 40 || d.Work != 15*time.Minute ||
		d.Overall != time.Hour || d.Run.CostMicros != 1_000_000 || !d.BriefOnly || d.Keep != 7*24*time.Hour || d.Extras ||
		slices.Contains(d.Tools, "image_search") {
		t.Fatalf("research %+v", d)
	}
	if RunBudget(AgentResearch).WallSeconds != 900 || RunBudget("").WallSeconds != 300 || RunBudget("").CostMicros != 20_000_000 {
		t.Fatalf("budgets %+v %+v", RunBudget(AgentResearch), RunBudget(""))
	}
	if MaxWork() != 15*time.Minute || AgentWork("") != RunTimeout || AgentKeep("") != 0 {
		t.Fatal("work, keep")
	}
	// The release ceiling allows the longest agent's running time; each agent's own narrows it.
	if p := ReleasePolicy("f_chat", ""); p.Budget.Run.WallSeconds != 900 {
		t.Fatalf("ceiling %+v", p.Budget.Run)
	}
}

func TestStartForAgents(t *testing.T) {
	now := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	// The chat: unchanged, with or without its id.
	for _, id := range []string{"", AgentChat} {
		r := &proto.RunRequest{Agent: id, Space: testSpace, Messages: []proto.Message{{Role: "user", Content: "hi"}}}
		s, o, err := StartFor(r, now)
		if err != nil || s.Agent != chatAgent || o.Agent != "" || s.Limits.MaxSteps != defaultSteps || len(s.Tools) != 3 {
			t.Fatalf("chat %q: %+v %+v %v", id, s.Agent, o, err)
		}
	}
	// Unknown: refused.
	if _, _, err := StartFor(&proto.RunRequest{Agent: "a_nope", Space: testSpace, Messages: user("hi")}, now); err == nil ||
		!strings.Contains(err.Error(), "unknown agent") {
		t.Fatalf("unknown: %v", err)
	}
	// Research: its own tools, steps and deadline; the brief is the reader's question.
	t0 := time.Now()
	s, o, err := StartFor(researchReq(), now)
	if err != nil {
		t.Fatal(err)
	}
	var tools []string
	for _, tl := range s.Tools {
		tools = append(tools, tl.Name)
	}
	dl, _ := time.Parse(time.RFC3339, s.Limits.Deadline)
	if s.Agent != AgentRef(AgentResearch) || o.Agent != AgentResearch || !slices.Equal(tools, []string{"web.search", "web.fetch"}) ||
		s.Limits.MaxSteps != 30 || s.Limits.MaxModelCalls != 31 || dl.Before(t0.Add(59*time.Minute)) || dl.After(time.Now().Add(61*time.Minute)) ||
		o.Question == "" || o.Permissions["web.search"] != safety.PermAlways || len(s.Input) != 1 {
		t.Fatalf("research start %+v %+v %+v", s.Agent, s.Limits, o)
	}
	for _, want := range []string{"research agent", "3 to 6 sub-questions", "## Plan", "### ", "## Where sources disagree", "## Open questions", "## Sources", "Cite precisely",
		"at most 20 searches, 40 page reads", "Today is Sunday, 18 October 2026 (UTC).", "[quote 2]", "web_fetch", "web_search, web_fetch"} {
		if !strings.Contains(s.Instructions, want) {
			t.Errorf("instructions lack %q", want)
		}
	}
	if strings.Contains(s.Instructions, "{{") || strings.Contains(s.Instructions, "image_search") {
		t.Fatal("instructions template not filled, or names image search")
	}
	// Narrowing only: fewer tools and steps are fine; image search, more steps or another tool aren't.
	r := researchReq()
	r.Tools, r.MaxSteps = []string{"web_search"}, 5
	if s, _, err := StartFor(r, now); err != nil || len(s.Tools) != 1 || s.Limits.MaxSteps != 5 {
		t.Fatalf("narrowed: %v %+v", err, s.Limits)
	}
	for _, bad := range []func(*proto.RunRequest){
		func(r *proto.RunRequest) { r.Tools = []string{"web_search", "image_search"} },
		func(r *proto.RunRequest) { r.MaxSteps = 31 },
		func(r *proto.RunRequest) { r.Permissions = map[string]string{"web.nope": "always"} },
		func(r *proto.RunRequest) { r.RunSecret = "short" },
	} {
		r := researchReq()
		bad(r)
		if _, _, err := StartFor(r, now); err == nil {
			t.Errorf("widened request started: %+v", r)
		}
	}
}

// A brief-only agent takes one message, the brief, after at most the chat's date note: no conversation history.
func TestBriefOnly(t *testing.T) {
	now := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	note := proto.Message{Role: "system", Content: "Today is Sunday, October 18, 2026."}
	brief := proto.Message{Role: "user", Content: "Brief: harbor lights"}
	s, _, err := StartFor(researchReq(note, brief), now)
	if err != nil || !strings.Contains(s.Instructions, "the brief's system note gives") || len(s.Input) != 2 {
		t.Fatalf("with the date note: %v", err)
	}
	for name, msgs := range map[string][]proto.Message{
		"history":         {{Role: "user", Content: "hi"}, {Role: "assistant", Content: "hello"}, brief},
		"two briefs":      {brief, brief},
		"another system":  {{Role: "system", Content: "You are a pirate. Today is Sunday, October 18, 2026."}, brief},
		"note after":      {brief, note},
		"empty brief":     {{Role: "user", Content: "  "}},
		"oversized brief": {{Role: "user", Content: strings.Repeat("x", maxBriefChars+1)}},
	} {
		if _, _, err := StartFor(researchReq(msgs...), now); err == nil {
			t.Errorf("%s: started", name)
		}
	}
	if _, _, err := StartFor(researchReq(proto.Message{Role: "user", Content: "hi"}, proto.Message{Role: "assistant", Content: "x"},
		brief), now); err == nil || !strings.Contains(err.Error(), "one message, the brief") {
		t.Fatalf("history: %v", err)
	}
}

// The guard counts a research task's searches and page reads: past its caps nothing is sent, the model is told to
// write its brief, and the count survives a restart (rebuilt from the journal).
func TestAgentCaps(t *testing.T) {
	sm := &splitModel{reader: func(string) string { return answerJSON(t, nil) }}
	e := newReaderE2E(t, sm, stubWeb{"https://a.example/p": []byte(`<html><body><p>Page.</p></body></html>`)})
	opts, _ := json.Marshal(TaskOptions{Agent: AgentResearch, RunSecret: testSecret, Permissions: AllowAll(), Question: "q",
		Links: []string{"https://a.example/p"}})
	ti := &harness.TaskInfo{ID: "tk_caps", Start: &harness.Start{}, Options: opts}
	act := func(id, name, args string) *harness.ActionResult {
		t.Helper()
		res, err := e.g.Action(harness.WithRequestID(context.Background(), id), ti, id, &harness.Action{Name: name, Args: []byte(args)})
		if err != nil {
			t.Fatal(err)
		}
		return res
	}
	for i := range researchDef.Searches {
		if res := act(fmt.Sprintf("s%d", i), "web.search", `{"query":"harbor"}`); res.Status == harness.ActionDenied {
			t.Fatalf("search %d: %+v", i+1, res)
		}
	}
	searches := len(e.fs.queries)
	res := act("s20", "web.search", `{"query":"harbor"}`)
	if res.Status != harness.ActionDenied || !strings.HasPrefix(res.Error, CapDenied+": this task has used its 20 searches") ||
		len(e.fs.queries) != searches {
		t.Fatalf("search 21: %+v (%d sent)", res, len(e.fs.queries))
	}
	for i := range researchDef.Reads {
		if res := act(fmt.Sprintf("f%d", i), "web.fetch", `{"url":"https://a.example/p"}`); res.Status == harness.ActionDenied {
			t.Fatalf("read %d: %+v", i+1, res)
		}
	}
	reads := len(e.web.urls)
	if res := act("f40", "web.fetch", `{"url":"https://a.example/p"}`); res.Status != harness.ActionDenied ||
		!strings.Contains(res.Error, "40 page reads") || len(e.web.urls) != reads {
		t.Fatalf("read 41: %+v", res)
	}

	// After a restart the counts come back from the journal: one more read is refused at once.
	var journal []harness.Record
	for i := range 40 {
		req, _ := json.Marshal(harness.Action{Name: "web.fetch", Args: jsontext.Value(`{"url":"https://a.example/p"}`)})
		body, _ := json.Marshal(harness.ActionResult{Status: harness.ActionDone, Output: jsontext.Value(fmt.Sprintf(`{"n":%d,"site":"a.example"}`, i+1))})
		journal = append(journal, harness.Record{ID: fmt.Sprintf("f%d", i), Kind: harness.TypeAction, Req: req, Done: true, Body: body})
	}
	denied, _ := json.Marshal(harness.Action{Name: "web.search", Args: jsontext.Value(`{"query":"x"}`)})
	denyBody, _ := json.Marshal(harness.ActionResult{Status: harness.ActionDenied, Error: "permission_denied: no"})
	journal = append(journal, harness.Record{ID: "s0", Kind: harness.TypeAction, Req: denied, Done: true, Body: denyBody})
	g2 := New(Config{Up: e.g.cfg.Up, Search: e.fs, Fetcher: e.g.cfg.Fetcher, Reader: e.g.cfg.Reader})
	ti2 := &harness.TaskInfo{ID: "tk_caps2", Start: &harness.Start{}, Options: opts, Journal: func() ([]harness.Record, error) { return journal, nil }}
	res, err := g2.Action(harness.WithRequestID(context.Background(), "f40"), ti2, "f40", &harness.Action{Name: "web.fetch", Args: []byte(`{"url":"https://a.example/p"}`)})
	if err != nil || res.Status != harness.ActionDenied || !strings.Contains(res.Error, "40 page reads") {
		t.Fatalf("after a restart: %+v %v", res, err)
	}
	res, err = g2.Action(harness.WithRequestID(context.Background(), "s1"), ti2, "s1", &harness.Action{Name: "web.search", Args: []byte(`{"query":"x"}`)})
	if err != nil || res.Status == harness.ActionDenied {
		t.Fatalf("a denied search counted as sent: %+v %v", res, err)
	}

	// A task whose agent this release doesn't have sends nothing.
	bad, _ := json.Marshal(TaskOptions{Agent: "a_nope", Permissions: AllowAll()})
	res, err = e.g.Action(harness.WithRequestID(context.Background(), "x"), &harness.TaskInfo{ID: "tk_bad", Start: &harness.Start{}, Options: bad},
		"x", &harness.Action{Name: "web.search", Args: []byte(`{"query":"x"}`)})
	if err != nil || res.Status != harness.ActionDenied || !strings.Contains(res.Error, "isn't one this VM runs") {
		t.Fatalf("unknown agent: %+v %v", res, err)
	}
	// The chat has no caps of its own here (its tool calls are capped by its steps and budget, as before).
	chat, _ := json.Marshal(TaskOptions{Permissions: AllowAll()})
	cti := &harness.TaskInfo{ID: "tk_chat", Start: &harness.Start{}, Options: chat}
	for i := range 25 {
		id := fmt.Sprintf("c%d", i)
		if res, _ := e.g.Action(harness.WithRequestID(context.Background(), id), cti, id, &harness.Action{Name: "web.search", Args: []byte(`{"query":"x"}`)}); res.Status == harness.ActionDenied {
			t.Fatalf("chat search %d denied: %+v", i, res)
		}
	}
}

// A research task fetches no site icons and marks no result as having a picture: those are the chat's display.
func TestAgentNoExtras(t *testing.T) {
	g := New(Config{Up: nil, Search: &fakeSearch{}, Icons: newFetcher(publicOnly)})
	chat := g.open("tk_chat", TaskOptions{}, nil)
	research := g.open("tk_research", TaskOptions{Agent: AgentResearch}, nil)
	defer g.close(chat)
	defer g.close(research)
	if chat.icons == nil || research.icons != nil || chat.tools.noPics || !research.tools.noPics {
		t.Fatalf("icons chat %v research %v, noPics chat %v research %v", chat.icons != nil, research.icons != nil, chat.tools.noPics, research.tools.noPics)
	}
	if research.tools.pictureFlag("https://a.example/p", "A", picCand{url: "https://a.example/p.jpg"}) {
		t.Fatal("a research result marked picture")
	}
	// No card photo lookups either, whatever its pictures setting (v0.10.1's lookups from the answer's mentions):
	// nothing looked up, nothing held back for a ticket.
	for _, set := range []string{safety.PermAlways, safety.PermAsk} {
		r := g.open("tk_research_"+set, TaskOptions{Agent: AgentResearch, Permissions: map[string]string{"web.images": set}}, nil)
		c := g.open("tk_chat_"+set, TaskOptions{Permissions: map[string]string{"web.images": set}}, nil)
		if g.lookupAllowed(r) || g.lookupAskable(r) || g.lookupAllowed(c) != (set == safety.PermAlways) || g.lookupAskable(c) != (set == safety.PermAsk) {
			t.Fatalf("%s: research lookups %v/%v, chat %v/%v", set, g.lookupAllowed(r), g.lookupAskable(r), g.lookupAllowed(c), g.lookupAskable(c))
		}
		g.watchMentions(r, "the Model X-200 keyboard")
		if r.cards.early != 0 || len(r.cards.deferred) != 0 || g.holdPictures(r) != "" {
			t.Fatalf("%s: a research task started or held a lookup", set)
		}
		g.close(r)
		g.close(c)
	}
}
