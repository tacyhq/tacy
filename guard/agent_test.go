package guard

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/tacyhq/tacy/proto"
)

// All tests here are offline: the model, the search provider and web pages are local fakes.

func TestMaskPII(t *testing.T) {
	cases := []struct {
		in, want string
		kinds    []string
	}{
		{"jane.doe@example.com tax deadline", "[email] tax deadline", []string{"email"}},
		{"call +1 415 555 0134 about it", "call [phone] about it", []string{"phone"}},
		{"(415) 555-0134", "[phone]", []string{"phone"}},
		{"1-800-555-0199 support line", "[phone] support line", []string{"phone"}},
		{"ssn 123-45-6789", "ssn [ssn]", []string{"ssn"}},
		{"card 4111 1111 1111 1111 declined", "card [card] declined", []string{"card"}},
		{"account 12345678 balance", "account [account] balance", []string{"account"}},
		{"IBAN DE89 3704 0044 0532 0130 00", "IBAN [iban]", []string{"iban"}},
		{"server 203.0.113.7 down", "server [ip] down", []string{"ip"}},
		{"router 192.168.1.1 admin login", "router 192.168.1.1 admin login", nil}, // a private address says nothing
		{"https://bob:hunter2@example.com/x", "[url-credentials]example.com/x", []string{"url-credentials"}},
		// Must survive: dates, years, versions, small numbers.
		{"dstack release 2026-10-13", "dstack release 2026-10-13", nil},
		{"go 1.27.2 released in 2026, top 10", "go 1.27.2 released in 2026, top 10", nil},
	}
	for _, c := range cases {
		got, kinds := maskPII(c.in)
		if got != c.want || !slices.Equal(kinds, c.kinds) {
			t.Errorf("maskPII(%q) = %q %v, want %q %v", c.in, got, kinds, c.want, c.kinds)
		}
	}
}

func TestReadStream(t *testing.T) {
	sse := `data: {"choices":[{"delta":{"reasoning":"think"}}]}

data: {"choices":[{"delta":{"content":"Hel"}}]}
data: {"choices":[{"delta":{"content":"lo","tool_calls":[{"index":0,"id":"c1","function":{"name":"web_search","arguments":"{\"qu"}}]}}]}
data: {"choices":[{"delta":{"tool_calls":[{"index":0,"function":{"arguments":"ery\":\"x\"}"}}]},"finish_reason":"tool_calls"}]}
data: {"choices":[],"usage":{"prompt_tokens":3,"completion_tokens":4,"total_tokens":7,"prompt_tokens_details":{"cached_tokens":2}}}
data: [DONE]
`
	var got []string
	res, err := readStream(strings.NewReader(sse), func(k, d string) error { got = append(got, k+":"+d); return nil })
	if err != nil {
		t.Fatal(err)
	}
	// Tool calls' names and arguments come through as "tool_call" deltas (counted for the record and the output
	// cap, never shown).
	if strings.Join(got, ",") != `reasoning:think,text:Hel,text:lo,tool_call:web_search{"qu,tool_call:ery":"x"}` || res.text != "Hello" || res.finish != "tool_calls" {
		t.Fatalf("deltas %v, text %q, finish %q", got, res.text, res.finish)
	}
	if len(res.calls) != 1 || res.calls[0].ID != "c1" || res.calls[0].Function.Arguments != `{"query":"x"}` {
		t.Fatalf("calls %+v", res.calls)
	}
	if res.usage == nil || res.usage.TotalTokens != 7 || res.cached != 2 {
		t.Fatalf("usage %+v, cached %d", res.usage, res.cached)
	}
	if res.firstAt.IsZero() || res.textAt.IsZero() || res.textAt.Before(res.firstAt) {
		t.Fatalf("token times %v %v", res.firstAt, res.textAt)
	}
	if _, err := readStream(strings.NewReader("data: {nope\n"), func(string, string) error { return nil }); err == nil {
		t.Fatal("malformed chunk accepted")
	}
}

func newTestAgent(t *testing.T, responses ...string) (*Agent, *fakeModel, *fakeSearch) {
	fm := &fakeModel{responses: responses}
	srv := httptest.NewServer(fm)
	t.Cleanup(srv.Close)
	fs := &fakeSearch{}
	a := &Agent{up: &plainUpstream{url: srv.URL, http: srv.Client()}, cacheSecret: "boot-secret",
		now:      func() time.Time { return time.Date(2026, 10, 13, 0, 0, 0, 0, time.UTC) },
		newTools: func() *Tools { return &Tools{search: fs, fetcher: newFetcher(nil)} }}
	return a, fm, fs
}

func collect(t *testing.T, a *Agent, r proto.RunRequest) []proto.Event {
	t.Helper()
	if err := validate(&r); err != nil {
		t.Fatal(err)
	}
	var evs []proto.Event
	a.Run(context.Background(), &r, func(e proto.Event) error { evs = append(evs, e); return nil })
	return evs
}

func TestAgentLoop(t *testing.T) {
	a, fm, fs := newTestAgent(t,
		toolCallSSE("c1", "web_search", `{"query":"dstack release for jane@example.com","count":3}`),
		textSSE("dstack v0.6.1 is the latest [1]."))
	evs := collect(t, a, proto.RunRequest{Space: testSpace, Permissions: AllowAll(), Messages: []proto.Message{{Role: "user", Content: "latest dstack?"}}})
	if got := types(evs); got != "meta,step,usage,metrics,tool_call,tool_result,metrics,step,text,usage,metrics,done" {
		t.Fatalf("events %s", got)
	}
	// The query left the VM masked, and the client is told.
	if len(fs.queries) != 1 || fs.queries[0] != "dstack release for [email]" {
		t.Fatalf("search got %q", fs.queries)
	}
	// Timing per model call and per tool call, numbers and fixed names only.
	m1, ms, m2 := evs[3].Metrics, evs[6].Metrics, evs[10].Metrics
	if m1.Kind != "model" || m1.Step != 1 || m1.Prompt != 10 || m1.Completion != 5 || m1.Outcome != "ok" || m1.Ms < m1.FirstMs {
		t.Fatalf("model metric %+v", m1)
	}
	if ms.Kind != "search" || ms.Step != 1 || ms.Provider != "fake" || ms.Results != 1 || ms.Outcome != "ok" {
		t.Fatalf("search metric %+v", ms)
	}
	if m2.Kind != "model" || m2.Step != 2 || m2.Prompt != 20 || m2.TextMs < m2.FirstMs || m2.Outcome != "ok" {
		t.Fatalf("model metric %+v", m2)
	}
	for _, e := range evs {
		if e.Type != "metrics" {
			continue
		}
		b, _ := json.Marshal(e)
		if strings.Contains(string(b), "dstack") || strings.Contains(string(b), "example") || strings.Contains(string(b), "http") || e.Delta != "" {
			t.Fatalf("metrics event carries content: %s", b)
		}
	}
	res := evs[5]
	if !slices.Equal(res.Masked, []string{"email"}) || len(res.Citations) != 1 || res.Citations[0].Index != 1 {
		t.Fatalf("tool_result %+v", res)
	}
	if !strings.Contains(string(res.Result), "Untrusted web content") {
		t.Fatal("tool output isn't labeled untrusted")
	}
	if u := evs[9].Usage; u.TotalTokens != 41 {
		t.Fatalf("usage not summed: %+v", u)
	}
	// Second model call: system prompt, user, assistant tool call, tool result; defaults applied.
	req := fm.requests[1]
	msgs := req["messages"].([]any)
	if len(msgs) != 4 || msgs[3].(map[string]any)["role"] != "tool" || msgs[3].(map[string]any)["tool_call_id"] != "c1" {
		t.Fatalf("messages %v", msgs)
	}
	if req["model"] != "gpt-oss-120b" || req["user_cache_secret"] != "boot-secret" || req["tools"] == nil {
		t.Fatalf("request %v", req)
	}
	if !strings.Contains(msgs[0].(map[string]any)["content"].(string), "13 October 2026") {
		t.Fatal("system prompt lacks the date")
	}
}

func TestAgentLastStepHasNoTools(t *testing.T) {
	a, fm, _ := newTestAgent(t,
		toolCallSSE("c1", "web_search", `{"query":"a"}`),
		toolCallSSE("c2", "web_search", `{"query":"b"}`))
	evs := collect(t, a, proto.RunRequest{Space: testSpace, Permissions: AllowAll(), MaxSteps: 2, CacheSecret: "user-secret",
		Messages: []proto.Message{{Role: "user", Content: "q"}}})
	if _, ok := fm.requests[1]["tools"]; ok {
		t.Fatal("last step was offered tools")
	}
	if fm.requests[0]["user_cache_secret"] != "user-secret" {
		t.Fatal("request cache secret not used")
	}
	// The last step's reply was only a tool call: one more call, without tools, asks for the answer.
	if len(fm.requests) != 3 {
		t.Fatalf("%d model calls, want 3", len(fm.requests))
	}
	if _, ok := fm.requests[2]["tools"]; ok {
		t.Fatal("the retry was offered tools")
	}
	if msgs := fm.requests[2]["messages"].([]any); !strings.Contains(msgs[len(msgs)-1].(map[string]any)["content"].(string), "can't call any more tools") {
		t.Fatalf("retry messages %v", msgs)
	}
	if last := evs[len(evs)-1]; last.Type != "done" || last.Step != 3 {
		t.Fatalf("last event %+v", last)
	}
}

// switchover: the model calls the tool by the name it now sees (web_fetch, web_images: docs/20); people's
// events keep fetch_page and image_search.
func TestAgentBadToolCalls(t *testing.T) {
	a, fm, fs := newTestAgent(t,
		toolCallSSE("c1", "web_fetch", `{"url":"https://example.com/?email=jane@example.com"}`),
		toolCallSSE("c2", "rm_rf", `{}`),
		toolCallSSE("c3", "web_search", `{not json`),
		textSSE("ok"))
	evs := collect(t, a, proto.RunRequest{Space: testSpace, Permissions: AllowAll(), Tools: []string{"web_search", "fetch_page"},
		Messages: []proto.Message{{Role: "user", Content: "q"}}})
	var errs []string
	for _, e := range evs {
		if e.Type == "tool_result" {
			var r struct{ Error string }
			json.Unmarshal(e.Result, &r)
			errs = append(errs, r.Error)
		}
	}
	if len(errs) != 3 || !strings.Contains(errs[0], "personal data") || !strings.Contains(errs[1], "isn't available") ||
		!strings.Contains(errs[2], "valid JSON") {
		t.Fatalf("tool errors %q", errs)
	}
	if len(fs.queries) != 0 || len(fm.requests) != 4 {
		t.Fatalf("searches %v, model calls %d", fs.queries, len(fm.requests))
	}
	// Metrics: one per model call, plus the fetch refused for personal data; calls that never ran a tool have none.
	var kinds []string
	for _, e := range evs {
		if e.Type == "metrics" {
			kinds = append(kinds, e.Metrics.Kind+":"+e.Metrics.Outcome)
		}
	}
	if strings.Join(kinds, ",") != "model:ok,fetch:refused,model:ok,model:ok,model:ok" {
		t.Fatalf("metrics %v", kinds)
	}
}

func TestAgentModelErrorMetric(t *testing.T) {
	a := &Agent{up: &plainUpstream{url: "http://127.0.0.1:1/none", http: &http.Client{Timeout: time.Second}},
		now: time.Now, newTools: func() *Tools { return &Tools{search: &fakeSearch{}, fetcher: newFetcher(nil)} }}
	evs := collect(t, a, proto.RunRequest{Space: testSpace, Permissions: AllowAll(), Messages: []proto.Message{{Role: "user", Content: "q"}}})
	if got := types(evs); got != "meta,step,metrics,error" {
		t.Fatalf("events %s", got)
	}
	if m := evs[2].Metrics; m.Kind != "model" || m.Outcome != "error" || m.Step != 1 {
		t.Fatalf("metric %+v", m)
	}
}

func TestToolMetric(t *testing.T) {
	if toolMetric("web_search", 1, toolOutcome{}, 5) != nil {
		t.Fatal("a call that never ran got a metric")
	}
	m := toolMetric("web_search", 2, toolOutcome{ran: true, provider: "tavily", failed: "error", citations: []proto.Citation{{}}}, 7)
	if m.Kind != "search" || m.Provider != "tavily" || m.Outcome != "error" || m.Results != 0 || m.Ms != 7 || m.Step != 2 {
		t.Fatalf("%+v", m)
	}
	if m := toolMetric("fetch_page", 1, toolOutcome{ran: true}, 3); m.Kind != "fetch" || m.Outcome != "ok" || m.Provider != "" {
		t.Fatalf("%+v", m)
	}
}

func TestValidate(t *testing.T) {
	bad := []proto.RunRequest{
		{},
		{Model: "gpt-4o", Messages: []proto.Message{{Role: "user", Content: "x"}}},
		{Model: "gpt-oss-120b", ReasoningEffort: "none", Messages: []proto.Message{{Role: "user", Content: "x"}}},
		{Messages: []proto.Message{{Role: "tool", Content: "x"}}},
		{Messages: []proto.Message{{Role: "user", Content: "x"}, {Role: "assistant", Content: "y"}}},
		{Tools: []string{"shell"}, Messages: []proto.Message{{Role: "user", Content: "x"}}},
		{MaxSteps: 11, Messages: []proto.Message{{Role: "user", Content: "x"}}},
	}
	for i, r := range bad {
		r.Space = testSpace // every case would fail without one anyway: each fails for its own reason here
		if validate(&r) == nil {
			t.Errorf("case %d accepted", i)
		}
	}
	ok := proto.RunRequest{Space: testSpace, Permissions: AllowAll(), Model: "deepseek-v4-1-flash", ReasoningEffort: "none", Tools: []string{},
		Messages: []proto.Message{{Role: "user", Content: "x"}}}
	if err := validate(&ok); err != nil || len(ok.Tools) != 0 || ok.MaxSteps != defaultSteps {
		t.Fatalf("%v %+v", err, ok)
	}
}

func TestPublicOnly(t *testing.T) {
	for _, addr := range []string{"127.0.0.1:80", "10.0.0.1:443", "169.254.169.254:80", "192.168.1.1:80",
		"100.64.0.1:80", "[::1]:443", "[fd00::1]:80", "0.0.0.0:80", "8.8.8.8:22"} {
		if publicOnly("tcp", addr, nil) == nil {
			t.Errorf("%s allowed", addr)
		}
	}
	if err := publicOnly("tcp", "93.184.215.14:443", nil); err != nil {
		t.Errorf("public address refused: %v", err)
	}
}

func TestFetchPage(t *testing.T) {
	page := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		io.WriteString(w, `<html><head><title>Release v0.6.1</title><script>alert(1)</script></head>
<body><nav>menu</nav><h1>dstack v0.6.1</h1><p>Published   13 Oct.</p><style>p{}</style></body></html>`)
	}))
	defer page.Close()
	tools := &Tools{fetcher: newFetcher(func(string, string, syscall.RawConn) error { return nil })}
	out, _ := tools.Run(context.Background(), "fetch_page", json.RawMessage(`{"url":"`+page.URL+`"}`))
	var r struct {
		Title, Text string
		N           int
	}
	json.Unmarshal([]byte(out.content), &r)
	if r.Title != "Release v0.6.1" || r.Text != "dstack v0.6.1\nPublished 13 Oct." || r.N != 1 {
		t.Fatalf("got %+v", r)
	}
	// The real dialer refuses the local test server.
	tools = &Tools{fetcher: newFetcher(publicOnly)}
	out, _ = tools.Run(context.Background(), "fetch_page", json.RawMessage(`{"url":"`+page.URL+`"}`))
	if !strings.Contains(out.content, "not allowed") {
		t.Fatalf("local address fetched: %s", out.content)
	}
}

// fetch_page sends a page navigation's headers with our own User-Agent: sites behind Shopify's edge turn a GET
// without Sec-Fetch-Mode away (429), whatever the User-Agent. Here a server that does the same.
func TestFetchPageHeaders(t *testing.T) {
	var got http.Header
	page := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
		if r.Header.Get("Sec-Fetch-Mode") != "navigate" {
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusTooManyRequests)
			io.WriteString(w, "local_rate_limited")
			return
		}
		w.Header().Set("Content-Type", "text/html")
		io.WriteString(w, `<html><head><title>K10</title></head><body><h1>Keychron K10</h1></body></html>`)
	}))
	defer page.Close()
	tools := &Tools{fetcher: newFetcher(func(string, string, syscall.RawConn) error { return nil })}
	out, _ := tools.Run(context.Background(), "fetch_page", json.RawMessage(`{"url":"`+page.URL+`"}`))
	if !strings.Contains(out.content, "Keychron K10") {
		t.Fatalf("page not read: %s", out.content)
	}
	want := map[string]string{
		"User-Agent": "Mozilla/5.0 (compatible; sealed-agent/0.1)", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-Dest": "document",
		"Sec-Fetch-Site": "none", "Sec-Fetch-User": "?1", "Upgrade-Insecure-Requests": "1", "Accept-Language": "en-US,en;q=0.9",
	}
	for k, v := range want {
		if got.Get(k) != v {
			t.Errorf("%s = %q, want %q", k, got.Get(k), v)
		}
	}
	if !strings.HasPrefix(got.Get("Accept"), "text/html,") {
		t.Errorf("Accept = %q", got.Get("Accept"))
	}
	// Nothing that identifies the person or the run.
	for _, k := range []string{"Cookie", "Referer", "Authorization"} {
		if got.Get(k) != "" {
			t.Errorf("sent %s", k)
		}
	}
	// gzip is still negotiated (and decoded) by the transport: nothing set by hand.
	if got.Get("Accept-Encoding") != "gzip" {
		t.Errorf("Accept-Encoding = %q", got.Get("Accept-Encoding"))
	}
}
