package guard

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/tacyhq/tacy/harness"
	"github.com/tacyhq/tacy/proto"
)

type countSearch struct{ queries []string }

func (c *countSearch) Name() string { return "count" }
func (c *countSearch) Search(_ context.Context, q string, _ int) ([]SearchResult, error) {
	c.queries = append(c.queries, q)
	return []SearchResult{{Title: "A", URL: "https://a.example/", Snippet: "s"}}, nil
}

// A search task (POST /search) can make one web.search, with the person's grant, and nothing else: gatewayd refuses
// model calls, other actions and a second search, whatever agentd (or anything else on its socket) asks.
func TestSearchTaskDoesOneSearchOnly(t *testing.T) {
	cs := &countSearch{}
	g := New(Config{Up: &plainUpstream{}, Search: cs, Fetcher: NewFetcher(true), Now: time.Now})
	start, opts, args, err := SearchStart(&proto.SearchRequest{Query: "best kettle 2026", Decision: proto.SearchOnce}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if opts.Via != ViaSearch || len(start.Models) != 0 || len(start.Tools) != 1 || start.Tools[0].Name != "web.search" ||
		!validRunSecret(opts.RunSecret) || opts.Permissions["web.fetch"] != "never" || opts.Permissions["web.images"] != "never" {
		t.Fatalf("start %+v opts %+v", start, opts)
	}
	b, _ := json.Marshal(opts)
	ti := &harness.TaskInfo{ID: "t_search", Start: &start, Options: b}
	sess := g.Open(ti.ID, opts, func(proto.Event) error { return nil })
	defer sess.Close()
	ctx := harness.WithRequestID(context.Background(), SearchActionID)

	// No grant: denied by gatewayd's own check (the setting is Ask), nothing sent.
	res, err := g.Action(ctx, ti, SearchActionID, &harness.Action{Name: "web.search", Args: args})
	if err != nil || res.Status != harness.ActionDenied || len(cs.queries) != 0 {
		t.Fatalf("no grant: %+v %v %q", res, err, cs.queries)
	}
	// A fresh task: a grant made with another secret is refused too.
	start, opts, args, _ = SearchStart(&proto.SearchRequest{Query: "best kettle 2026", Decision: proto.SearchOnce}, time.Now())
	b, _ = json.Marshal(opts)
	ti = &harness.TaskInfo{ID: "t_search2", Start: &start, Options: b}
	sess2 := g.Open(ti.ID, opts, func(proto.Event) error { return nil })
	defer sess2.Close()
	other := opts
	other.RunSecret = "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"
	forged, _ := SearchGrant(ti.ID, other, args)
	if res, err := g.Action(WithGrant(ctx, forged), ti, SearchActionID, &harness.Action{Name: "web.search", Args: args}); err != nil ||
		res.Status != harness.ActionDenied || len(cs.queries) != 0 {
		t.Fatalf("forged grant: %+v %v", res, err)
	}
	// (The forged one used up the task's one search: gatewayd counts a search when it's asked for.)
	start, opts, args, _ = SearchStart(&proto.SearchRequest{Query: "best kettle 2026", Decision: proto.SearchOnce}, time.Now())
	b, _ = json.Marshal(opts)
	ti = &harness.TaskInfo{ID: "t_search3", Start: &start, Options: b}
	sess3 := g.Open(ti.ID, opts, func(proto.Event) error { return nil })
	defer sess3.Close()
	gr, _ := SearchGrant(ti.ID, opts, args)
	gctx := WithGrant(ctx, gr)
	for name, call := range map[string]func() error{
		"model": func() error {
			_, err := g.ModelCall(gctx, ti, &harness.ModelCall{Model: "gpt-oss-120b", Messages: []harness.Message{{Role: "user", Content: "hi"}}})
			return err
		},
		"fetch": func() error {
			_, err := g.Action(gctx, ti, "f1", &harness.Action{Name: "web.fetch", Args: []byte(`{"url":"https://a.example/"}`)})
			return err
		},
		"images": func() error {
			_, err := g.Action(gctx, ti, "i1", &harness.Action{Name: "web.images", Args: []byte(`{"query":"kettle"}`)})
			return err
		},
	} {
		if err := call(); !errors.Is(err, errSearchOnly) {
			t.Errorf("%s: %v", name, err)
		}
	}
	res, err = g.Action(gctx, ti, SearchActionID, &harness.Action{Name: "web.search", Args: args})
	if err != nil || res.Status != harness.ActionDone || len(cs.queries) != 1 || cs.queries[0] != "best kettle 2026" {
		t.Fatalf("the search: %+v %v %q", res, err, cs.queries)
	}
	if _, err := g.Action(gctx, ti, SearchActionID, &harness.Action{Name: "web.search", Args: args}); !errors.Is(err, errSearchOnly) {
		t.Fatalf("second search: %v", err)
	}
	if len(cs.queries) != 1 {
		t.Fatalf("queries: %q", cs.queries)
	}
}

func TestSearchStartChecks(t *testing.T) {
	for name, r := range map[string]proto.SearchRequest{
		"empty":    {Query: " ", Decision: "once"},
		"long":     {Query: string(make([]byte, 301)), Decision: "once"},
		"hidden":   {Query: "a‮b", Decision: "once"},
		"count":    {Query: "q", Count: 9, Decision: "once"},
		"decision": {Query: "q", Decision: "deny"},
		"tag":      {Query: "q", Question: "x\U000E0041", Decision: "once"},
		"cache":    {Query: "q", Decision: "once", CacheSecret: string(make([]byte, 257))},
	} {
		if _, _, _, err := SearchStart(&r, time.Now()); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	_, opts, args, err := SearchStart(&proto.SearchRequest{Query: "  q  ", Decision: "setting"}, time.Now())
	if err != nil || string(args) != `{"count":5,"query":"q"}` || opts.Question != "q" {
		t.Fatalf("%s %+v %v", args, opts, err)
	}
	if SearchOutcome("setting") != PermAlwaysSetting || SearchOutcome("always") != PermAllowedAlways || SearchOutcome("once") != PermAllowedOnce {
		t.Fatal("outcomes")
	}
}
