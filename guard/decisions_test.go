package guard

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/tacyhq/tacy/brain"
	"github.com/tacyhq/tacy/harness"
	"github.com/tacyhq/tacy/proto"
)

// Tests for the harness/v1 choices that live in the guard: the reasoning effort clamp, the
// model's raw arguments, and per-task state rebuilt from the journal after a runtime restart.

// The person's reasoning effort caps the brain's: lower is kept, higher is clamped, none from the person means the
// model's default.
func TestClampEffort(t *testing.T) {
	levels := models["gemma4-31b"] // none, minimal, low, medium, high, xhigh, max
	for _, c := range []struct{ person, asked, want string }{
		{"medium", "low", "low"}, {"medium", "medium", "medium"}, {"medium", "max", "medium"}, {"medium", "", "medium"},
		{"none", "minimal", "none"}, {"", "high", ""}, {"", "", ""},
	} {
		if got := clampEffort(levels, c.person, c.asked); got != c.want {
			t.Errorf("person %q, brain %q: got %q, want %q", c.person, c.asked, got, c.want)
		}
	}
}

// Through the runtime: the brain asks for more effort than the person chose and gets the person's (clamped, not
// refused); the upstream gets the clamped value and the journal keeps both the request and the effort applied.
func TestEffortClampJournaled(t *testing.T) {
	fm := &fakeModel{responses: []string{textSSE("a"), textSSE("b"), textSSE("c")}}
	srv := httptest.NewServer(fm)
	t.Cleanup(srv.Close)
	g := New(Config{Up: &plainUpstream{url: srv.URL, http: srv.Client()}, Now: time.Now})
	store := harness.NewMemStore()
	rt := &harness.Runtime{Guard: g, Store: store}
	start, opts, err := g.StartFor(&proto.RunRequest{Model: "gpt-oss-120b", ReasoningEffort: "medium", Messages: user("q")})
	if err != nil {
		t.Fatal(err)
	}
	opts.User = "u1"
	g.open("t1", opts, nil)
	if err := rt.Start("t1", start); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	rc, bc := net.Pipe()
	go rt.Serve(ctx, rc)
	c, err := harness.Connect(bc, harness.Hello{Brain: harness.Info{Name: "test", Version: "1"}})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	task, err := c.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	mc := func(id, effort string) (*harness.ModelResult, error) {
		return task.ModelCall(ctx, id, harness.ModelCall{Model: "gpt-oss-120b", Messages: start.Input, ReasoningEffort: effort})
	}
	for i, c := range []struct{ asked, want string }{{"high", "medium"}, {"low", "low"}, {"", "medium"}} {
		res, err := mc(fmt.Sprintf("m%d", i), c.asked)
		if err != nil {
			t.Fatalf("asked %q: %v", c.asked, err)
		}
		if res.ReasoningEffort != c.want || fm.request(i)["reasoning_effort"] != c.want {
			t.Errorf("asked %q: applied %q, upstream got %v; want %q", c.asked, res.ReasoningEffort, fm.request(i)["reasoning_effort"], c.want)
		}
	}
	// A level the model doesn't take at all is still refused.
	if _, err := mc("m3", "max"); !isCode(err, harness.CodeNotAllowed) {
		t.Errorf("reasoning_effort max on gpt-oss-120b: %v, want not_allowed", err)
	}
	recs, _ := store.Journal("t1")
	if len(recs) < 1 || recs[0].ID != "m0" || !strings.Contains(string(recs[0].Req), `"reasoning_effort":"high"`) ||
		!strings.Contains(string(recs[0].Body), `"reasoning_effort":"medium"`) {
		t.Fatalf("the journal doesn't show the clamp: %+v", recs)
	}
}

func isCode(err error, code string) bool {
	pe, ok := err.(*harness.Error)
	return ok && pe.Code == code
}

// Arguments that don't parse keep the model's text, capped at 4 KiB with a marker and valid UTF-8, and the next
// model call gives the model back what it wrote.
func TestRawArgs(t *testing.T) {
	toAction := map[string]string{"web_search": "web.search"}
	tc := func(args string) harness.ToolCall {
		var c toolCall
		c.ID, c.Function.Name, c.Function.Arguments = "c1", "web_search", args
		return checkCall(0, c, toAction)
	}
	if c := tc(`{"query":"x"}`); c.BadArgs || c.RawArgs != "" {
		t.Errorf("good arguments: %+v", c)
	}
	if c := tc(`{query: x`); !c.BadArgs || c.RawArgs != `{query: x` || string(c.Args) != `{}` {
		t.Errorf("bad arguments: %+v", c)
	}
	long := tc(`{"query":"` + strings.Repeat("é", 4000))
	if !long.BadArgs || len(long.RawArgs) > harness.MaxRawArgs || !strings.HasSuffix(long.RawArgs, harness.RawArgsCut) ||
		!utf8.ValidString(long.RawArgs) || len(long.RawArgs) < harness.MaxRawArgs-8 {
		t.Errorf("long arguments: %d bytes, ends %q", len(long.RawArgs), long.RawArgs[max(0, len(long.RawArgs)-20):])
	}
	if c := tc("{\xff"); !utf8.ValidString(c.RawArgs) {
		t.Errorf("invalid UTF-8 kept: %q", c.RawArgs)
	}
	m := harness.Message{Role: "assistant", ToolCalls: []harness.ToolCall{tc(`{query: x`)}}
	sent := toModel([]harness.Message{m})[0]["tool_calls"].([]toolCall)[0]
	if sent.Function.Arguments != `{query: x` {
		t.Errorf("the model gets %q back, want what it wrote", sent.Function.Arguments)
	}
}

// restartSearch answers every search, except that the first runtime's second search hangs (the runtime dies then).
type restartSearch struct {
	mu      sync.Mutex
	n       int
	hang    bool
	running chan struct{}
	stuck   chan struct{}
}

func (s *restartSearch) Name() string { return "fake" }
func (s *restartSearch) Search(ctx context.Context, q string, n int) ([]SearchResult, error) {
	s.mu.Lock()
	s.n++
	k := s.n
	s.mu.Unlock()
	if s.hang && k == 2 {
		close(s.running)
		<-s.stuck
		return nil, fmt.Errorf("the old runtime is gone")
	}
	return []SearchResult{{Title: "dstack " + q, URL: "https://github.com/Dstack-TEE/dstack", Snippet: "s"}}, nil
}
func (s *restartSearch) Images(context.Context, string, int) ([]ImageCandidate, error) {
	return []ImageCandidate{{URL: "https://img.example/a.png", Title: "A poster", Source: "https://example.org/poster"}}, nil
}

// The runtime process restarts mid-task (a new runtime and guard on the same store: the queue, the journal and
// the checkpoints) while a search runs. The task comes back from the queue (Restore) with the person's options
// (reasoning effort, prompt-cache scope). The guard's per-task state comes back from the journal: citation numbers
// continue after the ones the model saw, the image slot stays taken, the sites already shown keep their icons (not
// fetched again) and the steps keep counting. The interrupted search is a safe read, so it runs again (decided
// 2026-10-16, docs/20 open question 3) and the task completes.
func TestRuntimeRestartRebuild(t *testing.T) {
	fm := &fakeModel{responses: []string{
		callsSSE([3]string{"c1", "web_search", `{"query":"one"}`}, [3]string{"c2", "web_images", `{"query":"poster","count":1}`}),
		toolCallSSE("c3", "web_search", `{"query":"two"}`),
		toolCallSSE("c4", "web_search", `{"query":"three"}`),
		textSSE("done [1] [2]"),
	}}
	srv := httptest.NewServer(fm)
	t.Cleanup(srv.Close)
	web := stubWeb{"https://img.example/a.png": pngWH(64, 48)}
	cfg := func(s SearchProvider) Config {
		return Config{Up: &plainUpstream{url: srv.URL, http: srv.Client()}, Search: s, Fetcher: &http.Client{Transport: web},
			Now: func() time.Time { return time.Date(2026, 10, 13, 0, 0, 0, 0, time.UTC) }}
	}
	s1 := &restartSearch{hang: true, running: make(chan struct{}), stuck: make(chan struct{})}
	t.Cleanup(func() { close(s1.stuck) })
	store := harness.NewMemStore()
	g1 := New(cfg(s1))
	rt1 := &harness.Runtime{Guard: g1, Store: store}
	start, opts, err := g1.StartFor(&proto.RunRequest{Messages: user("q"), ReasoningEffort: "low", CacheSecret: "person-secret"})
	if err != nil {
		t.Fatal(err)
	}
	opts.User = "u1"
	optsJSON, _ := json.Marshal(opts)
	if err := rt1.StartWith("t1", start, optsJSON); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	launch := func(rt *harness.Runtime) func() {
		rc, bc := net.Pipe()
		bctx, stop := context.WithCancel(ctx)
		stopped := make(chan struct{})
		go rt.Serve(bctx, rc)
		go func() {
			brain.Run(bctx, bc)
			close(stopped)
		}()
		return func() { stop(); bc.Close(); <-stopped }
	}
	kill := launch(rt1)
	<-s1.running
	kill() // the runtime process dies with the brain's connection

	s2 := &restartSearch{}
	g2 := New(cfg(s2))
	rt2 := &harness.Runtime{Guard: g2, Store: store}
	if ids, err := rt2.Restore(); err != nil || len(ids) != 1 {
		t.Fatalf("restored %v, %v", ids, err)
	}
	defer launch(rt2)()
	o, err := rt2.Wait(ctx, "t1")
	if err != nil || o.State != harness.OutcomeSucceeded {
		t.Fatalf("outcome %+v, %v", o, err)
	}
	s2.mu.Lock()
	if s2.n != 2 {
		t.Errorf("the new runtime searched %d times, want 2 (the interrupted c3 again, then c4)", s2.n)
	}
	s2.mu.Unlock()
	if len(fm.requests) != 4 {
		t.Errorf("%d model calls reached the model, want 4", len(fm.requests))
	}
	tools := map[string]string{}
	for _, m := range messages(fm.request(3)) {
		if m["role"] == "tool" {
			tools[m["tool_call_id"].(string)] = m["content"].(string)
		}
	}
	if !strings.Contains(tools["c1"], `"n":1`) || !strings.Contains(tools["c3"], `"n":2`) || !strings.Contains(tools["c4"], `"n":3`) {
		t.Fatalf("tool messages %v: c3 (rerun) and c4 must continue at 2 and 3", tools)
	}
	// The person's options came back with the task: every model call after the restart applies them.
	for i := 2; i < 4; i++ {
		if r := fm.request(i); r["reasoning_effort"] != "low" || r["user_cache_secret"] != "person-secret" {
			t.Errorf("model call %d after the restart: effort %v, cache scope %v", i, r["reasoning_effort"], r["user_cache_secret"])
		}
	}
	g2.mu.Lock()
	ts := g2.tasks["t1"]
	g2.mu.Unlock()
	ts.mu.Lock()
	step := ts.step
	ts.mu.Unlock()
	if step != 4 {
		t.Errorf("step %d after the restart, want 4 (2 before, 2 after)", step)
	}
	if left := ts.tools.reserveImages(maxImagesPerRun); left != maxImagesPerRun-1 {
		t.Errorf("%d image slots left, want %d (one shown before the restart)", left, maxImagesPerRun-1)
	}
}

// After a restart the sites already shown count as seen: their icons aren't fetched again.
func TestRebuildIconsSeen(t *testing.T) {
	g := New(Config{Icons: &http.Client{Transport: stubWeb{}}, Now: time.Now})
	store := harness.NewMemStore()
	add := func(id, name, out string) {
		req := fmt.Sprintf(`{"name":%q,"args":{},"call":"c"}`, name)
		store.Begin("t1", id, harness.TypeAction, [32]byte{}, []byte(req))
		store.Finish("t1", id, []byte(`{"status":"done","output":`+out+`}`), nil)
	}
	add("a1", "web.search", `{"results":[{"n":1,"url":"https://www.example.org/a"},{"n":2,"url":"https://news.example/b"}]}`)
	add("a2", "web.fetch", `{"n":3,"url":"https://docs.example/c"}`)
	add("a3", "web.images", `{"shown":2,"images":[{"n":1,"source":"https://pics.example/p"}]}`)
	ti := &harness.TaskInfo{ID: "t1", Start: &harness.Start{Space: "s_chat"},
		Journal: func() ([]harness.Record, error) { return store.Journal("t1") }}
	ts := g.task(ti)
	defer g.close(ts)
	if ts.tools.cites != 3 {
		t.Errorf("citations continue after %d, want 3", ts.tools.cites)
	}
	ts.icons.mu.Lock()
	defer ts.icons.mu.Unlock()
	for _, k := range []string{"example.org", "news.example", "docs.example", "pics.example"} {
		if !ts.icons.seen[k] {
			t.Errorf("site %s not seen", k)
		}
	}
}

// hangModel answers its first request with first and holds every later one (the runtime dies meanwhile).
type hangModel struct {
	first   string
	mu      sync.Mutex
	n       int
	running chan struct{}
	stuck   chan struct{}
}

func (h *hangModel) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mu.Lock()
	h.n++
	n := h.n
	h.mu.Unlock()
	w.Header().Set("Content-Type", "text/event-stream")
	if n == 1 {
		fmt.Fprint(w, h.first)
		return
	}
	close(h.running)
	select {
	case <-h.stuck:
	case <-r.Context().Done():
	}
}

// The runtime restarts while a model call streams: the model call is a safe read, so the new runtime runs it again
// and the task completes. The search before it finished, so it isn't run again (the journal answers it).
func TestRuntimeRestartMidModelCall(t *testing.T) {
	hm := &hangModel{first: toolCallSSE("c1", "web_search", `{"query":"one"}`), running: make(chan struct{}), stuck: make(chan struct{})}
	srv1 := httptest.NewServer(hm)
	t.Cleanup(func() { close(hm.stuck); srv1.Close() })
	fm := &fakeModel{responses: []string{textSSE("the answer [1]")}}
	srv2 := httptest.NewServer(fm)
	t.Cleanup(srv2.Close)
	now := func() time.Time { return time.Date(2026, 10, 13, 0, 0, 0, 0, time.UTC) }
	s1, s2 := &restartSearch{}, &restartSearch{}
	store := harness.NewMemStore()
	g1 := New(Config{Up: &plainUpstream{url: srv1.URL, http: srv1.Client()}, Search: s1, Now: now})
	rt1 := &harness.Runtime{Guard: g1, Store: store}
	start, opts, err := g1.StartFor(&proto.RunRequest{Messages: user("q")})
	if err != nil {
		t.Fatal(err)
	}
	optsJSON, _ := json.Marshal(opts)
	if err := rt1.StartWith("t1", start, optsJSON); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	launch := func(rt *harness.Runtime) func() {
		rc, bc := net.Pipe()
		bctx, stop := context.WithCancel(ctx)
		stopped := make(chan struct{})
		go rt.Serve(bctx, rc)
		go func() {
			brain.Run(bctx, bc)
			close(stopped)
		}()
		return func() { stop(); bc.Close(); <-stopped }
	}
	kill := launch(rt1)
	<-hm.running
	kill()

	g2 := New(Config{Up: &plainUpstream{url: srv2.URL, http: srv2.Client()}, Search: s2, Now: now})
	rt2 := &harness.Runtime{Guard: g2, Store: store}
	if _, err := rt2.Restore(); err != nil {
		t.Fatal(err)
	}
	defer launch(rt2)()
	o, err := rt2.Wait(ctx, "t1")
	if err != nil || o.State != harness.OutcomeSucceeded || o.Done.Text != "the answer [1]" {
		t.Fatalf("outcome %+v, %v", o, err)
	}
	if len(fm.requests) != 1 || s1.n != 1 || s2.n != 0 {
		t.Errorf("model calls on the new runtime %d (want 1, the rerun), searches %d then %d (want 1 then 0)", len(fm.requests), s1.n, s2.n)
	}
	var tool string
	for _, m := range messages(fm.request(0)) {
		if m["role"] == "tool" {
			tool, _ = m["content"].(string)
		}
	}
	if !strings.Contains(tool, `"n":1`) {
		t.Errorf("the rerun model call lacks the search's result: %q", tool)
	}
}
