package guard

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tacyhq/tacy/proto"
)

func TestToolGates(t *testing.T) {
	l := DefaultLimits
	l.UserTools, l.Searches, l.Fetches, l.SearchesPerMin, l.SearchBurst = 2, 3, 10, 6000, 100
	g := newToolGates(l)
	ctx := context.Background()
	// Per user: two at once, the third waits until one ends; another user isn't affected.
	r1, _ := g.acquire(ctx, "u", "fetch")
	r2, _ := g.acquire(ctx, "u", "search")
	short, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
	if _, err := g.acquire(short, "u", "fetch"); err == nil {
		t.Fatal("third concurrent tool call for one user didn't wait")
	}
	cancel()
	r3, err := g.acquire(ctx, "v", "fetch")
	if err != nil {
		t.Fatal(err)
	}
	// Global search cap (3): u's one search + two more by others fill it.
	r4, _ := g.acquire(ctx, "w", "search")
	r5, _ := g.acquire(ctx, "x", "search")
	short, cancel = context.WithTimeout(ctx, 100*time.Millisecond)
	if _, err := g.acquire(short, "y", "search"); err == nil {
		t.Fatal("search past the global cap didn't wait")
	}
	cancel()
	if _, err := g.acquire(ctx, "y", "fetch"); err != nil { // fetches have their own cap
		t.Fatal(err)
	}
	r2()
	done := make(chan struct{})
	go func() {
		rel, _ := g.acquire(ctx, "y", "search")
		rel()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("freed search slot not handed on")
	}
	r1()
	r3()
	r4()
	r5()
	if len(g.user.m) != 1 { // y still holds a fetch
		t.Fatalf("user entries %v", g.user.m)
	}
}

func TestRateLimiter(t *testing.T) {
	r := newRateLimiter(600, 3) // 10 per second after a burst of 3
	t0 := time.Now()
	for range 3 {
		r.wait(context.Background())
	}
	if time.Since(t0) > 50*time.Millisecond {
		t.Fatal("burst waited")
	}
	for range 5 {
		r.wait(context.Background())
	}
	if d := time.Since(t0); d < 450*time.Millisecond || d > 900*time.Millisecond {
		t.Fatalf("5 past the burst at 10/s took %v", d)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r2 := newRateLimiter(1, 1)
	r2.wait(ctx)
	if r2.wait(ctx) == nil {
		t.Fatal("a cancelled wait should fail")
	}
}

// slowSearch answers after a delay per query and records how many ran at once.
type slowSearch struct {
	delay       map[string]time.Duration
	now, peak   atomic.Int32
	mu          sync.Mutex
	started     []string
	resultsEach int
}

func (f *slowSearch) Name() string { return "slow" }

func (f *slowSearch) Search(ctx context.Context, q string, n int) ([]SearchResult, error) {
	f.mu.Lock()
	f.started = append(f.started, q)
	f.mu.Unlock()
	c := f.now.Add(1)
	defer f.now.Add(-1)
	for {
		p := f.peak.Load()
		if c <= p || f.peak.CompareAndSwap(p, c) {
			break
		}
	}
	select {
	case <-time.After(f.delay[q]):
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	var rs []SearchResult
	for i := range f.resultsEach {
		rs = append(rs, SearchResult{Title: fmt.Sprintf("%s %d", q, i), URL: fmt.Sprintf("https://example.com/%s/%d", q, i)})
	}
	return rs, nil
}

func multiCallSSE(queries ...string) string {
	var b strings.Builder
	for i, q := range queries {
		args, _ := json.Marshal(fmt.Sprintf(`{"query":%q}`, q))
		fmt.Fprintf(&b, `data: {"choices":[{"delta":{"tool_calls":[{"index":%d,"id":"c%d","function":{"name":"web_search","arguments":%s}}]}}]}`+"\n\n", i, i+1, args)
	}
	b.WriteString(`data: {"choices":[{"delta":{},"finish_reason":"tool_calls"}]}` + "\n\ndata: [DONE]\n\n")
	return b.String()
}

// A step's tool calls run concurrently (at most runTools at once). The model gets the results in call order.
// switchover: people get each result as its call finishes, and citation numbers follow the order calls finish
// (decided); app/'s loop held them back to call order. The chat pairs results with calls by id.
func TestParallelToolCallsKeepOrder(t *testing.T) {
	a, fm, _ := newTestAgent(t, multiCallSSE("slow", "fast", "mid", "fast2", "extra"), textSSE("done [1][4]"))
	ss := &slowSearch{resultsEach: 2, delay: map[string]time.Duration{"slow": 400 * time.Millisecond, "fast": 10 * time.Millisecond,
		"mid": 200 * time.Millisecond, "fast2": 10 * time.Millisecond}}
	a.newTools = func() *Tools { return &Tools{search: ss, fetcher: newFetcher(nil)} }
	a.runTools = 3
	t0 := time.Now()
	evs := collect(t, a, proto.RunRequest{Space: testSpace, Permissions: AllowAll(), Messages: []proto.Message{{Role: "user", Content: "q"}}})
	elapsed := time.Since(t0)
	// Sequential would be ~620 ms; 3 at once: slow (400) alongside fast+mid, then fast2.
	if elapsed > 550*time.Millisecond {
		t.Fatalf("tool calls didn't run in parallel: %v", elapsed)
	}
	if p := ss.peak.Load(); p != 3 {
		t.Fatalf("peak concurrency %d, want the cap 3", p)
	}
	var ids []string
	var cites [][]int
	var order []string
	for _, e := range evs {
		switch e.Type {
		case "tool_call":
			order = append(order, "call:"+e.ID)
		case "tool_result":
			order = append(order, "result:"+e.ID)
			ids = append(ids, e.ID)
			var c []int
			for _, x := range e.Citations {
				c = append(c, x.Index)
			}
			cites = append(cites, c)
		}
	}
	// Every call shown first; the slow one's result last of the four that ran, the refused fifth after them.
	if strings.Join(order[:5], ",") != "call:c1,call:c2,call:c3,call:c4,call:c5" || len(order) != 10 ||
		order[8] != "result:c1" || order[9] != "result:c5" {
		t.Fatalf("event order %v", order)
	}
	// Numbers in the order results were shown: unique, two per search, none for the refused call.
	if fmt.Sprint(cites) != "[[1 2] [3 4] [5 6] [7 8] []]" {
		t.Fatalf("citation numbers %v (results %v)", cites, ids)
	}
	// The fifth call is past maxCallsPerStep (4): refused, never run.
	if len(ss.started) != 4 {
		t.Fatalf("searches run: %v", ss.started)
	}
	// The model gets the tool messages in call order.
	msgs := fm.requests[1]["messages"].([]any)
	for i, m := range msgs[3:] {
		mm := m.(map[string]any)
		if mm["tool_call_id"] != fmt.Sprintf("c%d", i+1) {
			t.Fatalf("tool message %d is %v", i, mm["tool_call_id"])
		}
	}
	if !strings.Contains(msgs[7].(map[string]any)["content"].(string), "at most 4") {
		t.Fatal("fifth call not refused")
	}
}

// The tool caps apply across a user's runs: two runs of one user with UserTools 2 never have more than 2 searches
// running at once; the wait shows up in the metrics.
func TestUserToolCapAcrossRuns(t *testing.T) {
	l := DefaultLimits
	l.UserTools = 2
	g := newToolGates(l)
	ss := &slowSearch{resultsEach: 1, delay: map[string]time.Duration{"a": 150 * time.Millisecond, "b": 150 * time.Millisecond, "c": 150 * time.Millisecond}}
	var wg sync.WaitGroup
	var waited atomic.Int64
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			a, _, _ := newTestAgent(t, multiCallSSE("a", "b", "c"), textSSE("ok"))
			a.gates = g
			a.newTools = func() *Tools { return &Tools{search: ss, fetcher: newFetcher(nil)} }
			r := proto.RunRequest{Space: testSpace, Permissions: AllowAll(), Messages: []proto.Message{{Role: "user", Content: "q"}}}
			validate(&r)
			a.Run(withUser(context.Background(), "same-user"), &r, func(e proto.Event) error {
				if e.Type == "metrics" && e.Metrics.Kind == "search" {
					waited.Add(e.Metrics.WaitMs)
				}
				return nil
			})
		}()
	}
	wg.Wait()
	if p := ss.peak.Load(); p != 2 {
		t.Fatalf("peak concurrent searches for one user %d, want 2", p)
	}
	if waited.Load() < 100 {
		t.Fatalf("cap wait not reported: %d ms", waited.Load())
	}
}

func TestSystemPromptAndParallelFlag(t *testing.T) {
	p := systemPrompt(allTools, time.Date(2026, 10, 14, 0, 0, 0, 0, time.UTC))
	for _, want := range []string{"Cite the sources you use inline as plain [n]", "don't end the answer with a list of sources",
		"ask for them together in one step", "run in parallel"} {
		if !strings.Contains(p, want) {
			t.Errorf("system prompt lacks %q", want)
		}
	}
	if strings.Contains(systemPrompt(nil, time.Now()), "parallel") {
		t.Error("no-tools prompt talks about tools")
	}
	a, fm, _ := newTestAgent(t, toolCallSSE("c1", "web_search", `{"query":"a"}`), textSSE("ok"))
	collect(t, a, proto.RunRequest{Space: testSpace, Permissions: AllowAll(), MaxSteps: 2, Messages: []proto.Message{{Role: "user", Content: "q"}}})
	if fm.requests[0]["parallel_tool_calls"] != true {
		t.Fatal("parallel_tool_calls not sent with tools")
	}
	if _, ok := fm.requests[1]["parallel_tool_calls"]; ok {
		t.Fatal("parallel_tool_calls sent without tools (last step)")
	}
}
