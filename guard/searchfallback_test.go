package guard

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tacyhq/tacy/activity"
	"github.com/tacyhq/tacy/proto"
	"github.com/tacyhq/tacy/vault"
)

// Exa failing on its side goes to Tavily once (searchfallback.go); refusals never do. The providers are the real
// clients (exa.go, search.go) against a stub transport that answers per host, so the record sees the real hosts.

// fakeProviders answers api.exa.ai and api.tavily.com: exa is the answer per Exa request in order (a status, or
// "ok", "hang" until the request is cancelled, "filter" for Exa's content filter); Tavily answers results.
type fakeProviders struct {
	mu      sync.Mutex
	exa     []string
	exaN    int
	tavilyN int
	bodies  map[string][]string // host -> request bodies
	tavily  int                 // Tavily's status (0: 200)
}

func (f *fakeProviders) RoundTrip(r *http.Request) (*http.Response, error) {
	body, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	if f.bodies == nil {
		f.bodies = map[string][]string{}
	}
	f.bodies[r.URL.Host] = append(f.bodies[r.URL.Host], string(body))
	var behave string
	status := 200
	out := ""
	switch r.URL.Host {
	case "api.exa.ai":
		behave = "ok"
		if f.exaN < len(f.exa) {
			behave = f.exa[f.exaN]
		}
		f.exaN++
		out = `{"results":[{"title":"Exa page","url":"https://exa.example/a","publishedDate":"2026-10-20","highlights":["from exa"]}]}`
	case "api.tavily.com":
		f.tavilyN++
		if f.tavily != 0 {
			status = f.tavily
		}
		out = `{"results":[{"title":"Tavily page","url":"https://tavily.example/a","content":"what the page says about it, at length","published_date":"2026-10-19","images":["https://tavily.example/pic.jpg"]}]}`
	default:
		f.mu.Unlock()
		return nil, errors.New("no such host")
	}
	f.mu.Unlock()
	switch behave {
	case "hang":
		<-r.Context().Done()
		return nil, r.Context().Err()
	case "filter":
		status, out = 403, `{"tag":"CONTENT_FILTER_ERROR","error":"the query `+"quoted"+`"}`
	case "ok", "":
	default:
		json.Unmarshal([]byte(behave), &status)
		out = `{"error":"echo of the query"}`
	}
	h := http.Header{"Content-Type": {"application/json"}}
	if status == 429 {
		h.Set("Retry-After", "0")
	}
	return &http.Response{StatusCode: status, Header: h, Body: io.NopCloser(strings.NewReader(out)), Request: r}, nil
}

func (f *fakeProviders) counts() (int, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.exaN, f.tavilyN
}

// testFallback is Exa with Tavily behind it on the fake providers, keys from lease (static keys when nil), the
// clients' timeout short, the 429 wait short, the breaker's clock now.
func testFallback(fp *fakeProviders, lease Lease, now func() time.Time) *fallbackSearch {
	if lease == nil {
		lease = StaticKeys(func(name string) string { return "k-" + name })
	}
	client := func() *http.Client {
		return recordingClient(&http.Client{Transport: fp, Timeout: 200 * time.Millisecond})
	}
	e, tv := newExa(lease, nil), newTavily(lease)
	e.http, tv.http = client(), client()
	f := newFallbackSearch(e, tv)
	f.retryWait = 10 * time.Millisecond
	if now != nil {
		f.br.now = now
	}
	return f
}

func TestSearchFallback(t *testing.T) {
	for _, c := range []struct {
		name, class string
		exa         []string
		exaCalls    int
	}{
		{"402 no credit", "http_402", []string{"402"}, 1},
		{"500", "http_5xx", []string{"500"}, 1},
		{"503", "http_5xx", []string{"503"}, 1},
		{"401 key revoked", "http_401", []string{"401"}, 1},
		{"timeout", "timeout", []string{"hang"}, 1},
		{"bad answer", "bad_response", []string{"200x"}, 1},
		{"429 twice", "http_429", []string{"429", "429"}, 2},
	} {
		t.Run(c.name, func(t *testing.T) {
			fp := &fakeProviders{exa: c.exa}
			if c.exa[0] == "200x" {
				fp.exa = []string{"ok"}
				// an unparseable 200: replaced below by a transport that breaks the body
			}
			f := testFallback(fp, nil, nil)
			if c.exa[0] == "200x" {
				f.primary.(*exa).http = recordingClient(&http.Client{Transport: badJSON{fp}})
			}
			facts := &Facts{}
			ctx := WithFacts(context.Background(), facts)
			var more int
			rs, info, err := f.SearchInfo(ctx, "masked [email] query", 5, func(context.Context) error { more++; return nil })
			if err != nil {
				t.Fatal(err)
			}
			if info != (SearchInfo{Provider: "tavily", Fallback: c.class}) {
				t.Fatalf("info %+v", info)
			}
			// Tavily's result in the shape the reader and the cards read (as before Exa): title, URL, the page's
			// content as the snippet, its date, its picture.
			want := []SearchResult{{Title: "Tavily page", URL: "https://tavily.example/a", Snippet: "what the page says about it, at length",
				Age: "2026-10-19", Thumbs: []string{"https://tavily.example/pic.jpg"}}}
			if len(rs) != 1 || rs[0].Title != want[0].Title || rs[0].URL != want[0].URL || rs[0].Snippet != want[0].Snippet ||
				rs[0].Age != want[0].Age || !slices.Equal(rs[0].Thumbs, want[0].Thumbs) {
				t.Fatalf("results %+v", rs)
			}
			if e, tv := fp.counts(); e != c.exaCalls || tv != 1 {
				t.Fatalf("exa %d calls, tavily %d", e, tv)
			}
			// Every extra request (the 429's retry, the fallback) took a token of the provider rate.
			if more != c.exaCalls {
				t.Fatalf("%d extra rate tokens, want %d", more, c.exaCalls)
			}
			// The same masked query went to Tavily, and nothing else of ours.
			var tb map[string]any
			json.Unmarshal([]byte(fp.bodies["api.tavily.com"][0]), &tb)
			if tb["query"] != "masked [email] query" || tb["max_results"] != float64(5) {
				t.Fatalf("tavily got %v", tb)
			}
			// On the record: both hosts, both keys leased, no query.
			d := facts.Data()
			var hosts []string
			for _, h := range d.Hosts {
				hosts = append(hosts, h.Host)
			}
			if !slices.Contains(hosts, "api.exa.ai") || !slices.Contains(hosts, "api.tavily.com") {
				t.Fatalf("hosts %v", hosts)
			}
		})
	}
}

// capped refuses every request as a capped lab transport does: its error says NoFallback (the private labs' Exa
// cap returns such an error; its own test checks it does).
type capped struct{}

type capError struct{}

func (capError) Error() string    { return "exa lab cap reached" }
func (capError) NoFallback() bool { return true }

func (capped) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, fmt.Errorf("%w: today's live Exa spend", capError{})
}

// badJSON answers Exa's requests with a 200 that isn't JSON.
type badJSON struct{ fp *fakeProviders }

func (b badJSON) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.Host == "api.exa.ai" {
		b.fp.mu.Lock()
		b.fp.exaN++
		b.fp.mu.Unlock()
		return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("<html>")), Request: r}, nil
	}
	return b.fp.RoundTrip(r)
}

func TestSearchNoFallback(t *testing.T) {
	t.Run("exa answers", func(t *testing.T) {
		fp := &fakeProviders{}
		rs, info, err := testFallback(fp, nil, nil).SearchInfo(context.Background(), "q", 5, nil)
		if err != nil || len(rs) != 1 || rs[0].Title != "Exa page" || info != (SearchInfo{Provider: "exa"}) {
			t.Fatalf("%+v %+v %v", rs, info, err)
		}
		if _, tv := fp.counts(); tv != 0 {
			t.Fatal("tavily called")
		}
	})
	t.Run("429 then ok", func(t *testing.T) {
		fp := &fakeProviders{exa: []string{"429", "ok"}}
		rs, info, err := testFallback(fp, nil, nil).SearchInfo(context.Background(), "q", 5, nil)
		if err != nil || len(rs) != 1 || info != (SearchInfo{Provider: "exa"}) {
			t.Fatalf("%+v %+v %v", rs, info, err)
		}
		if e, tv := fp.counts(); e != 2 || tv != 0 {
			t.Fatalf("exa %d, tavily %d", e, tv)
		}
	})
	t.Run("exa's safety filter", func(t *testing.T) {
		fp := &fakeProviders{exa: []string{"filter"}}
		_, info, err := testFallback(fp, nil, nil).SearchInfo(context.Background(), "q", 5, nil)
		if err == nil || !strings.Contains(err.Error(), "safety filter refused") || info.Fallback != "" {
			t.Fatalf("%+v %v", info, err)
		}
		if _, tv := fp.counts(); tv != 0 {
			t.Fatal("a query Exa's filter refused went to tavily")
		}
	})
	t.Run("the vault refuses exa's key", func(t *testing.T) {
		fp := &fakeProviders{}
		lease := func(_ context.Context, secret, _, _ string) (*vault.Secret, error) {
			if secret == exaKey {
				return nil, vault.ErrPolicy
			}
			return vault.NewSecret([]byte("k"), "static"), nil
		}
		_, info, err := testFallback(fp, lease, nil).SearchInfo(context.Background(), "q", 5, nil)
		if err == nil || !strings.Contains(err.Error(), "policy_denied") || info.Fallback != "" || info.Provider != "exa" {
			t.Fatalf("%+v %v", info, err)
		}
		if e, tv := fp.counts(); e != 0 || tv != 0 {
			t.Fatalf("exa %d, tavily %d", e, tv)
		}
	})
	t.Run("cancelled", func(t *testing.T) {
		fp := &fakeProviders{exa: []string{"hang"}}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
		defer cancel()
		f := testFallback(fp, nil, nil)
		f.primary.(*exa).http = recordingClient(&http.Client{Transport: fp}) // no client timeout: the run's ends it
		_, info, err := f.SearchInfo(ctx, "q", 5, nil)
		if err == nil || info.Fallback != "" {
			t.Fatalf("%+v %v", info, err)
		}
		if _, tv := fp.counts(); tv != 0 {
			t.Fatal("a cancelled search went to tavily")
		}
		if f.br.fails != 0 {
			t.Fatal("a cancelled search counted as exa failing")
		}
	})
	t.Run("the labs' Exa cap", func(t *testing.T) {
		fp := &fakeProviders{}
		f := testFallback(fp, nil, nil)
		f.primary.(*exa).http = recordingClient(&http.Client{Transport: capped{}})
		_, info, err := f.SearchInfo(context.Background(), "q", 5, nil)
		if err == nil || info.Fallback != "" {
			t.Fatalf("%+v %v", info, err)
		}
		if _, tv := fp.counts(); tv != 0 || f.br.fails != 0 {
			t.Fatal("a lab cap went to tavily")
		}
	})
	t.Run("both fail", func(t *testing.T) {
		fp := &fakeProviders{exa: []string{"402"}, tavily: 432}
		_, info, err := testFallback(fp, nil, nil).SearchInfo(context.Background(), "q", 5, nil)
		if err == nil || err.Error() != "search provider returned 432" || info != (SearchInfo{Provider: "tavily", Fallback: "http_402", Status: "http_4xx"}) {
			t.Fatalf("%+v %v", info, err)
		}
	})
	t.Run("the vault refuses tavily's key", func(t *testing.T) {
		fp := &fakeProviders{exa: []string{"402"}}
		lease := func(_ context.Context, secret, _, _ string) (*vault.Secret, error) {
			if secret == tavilyKey {
				return nil, vault.ErrPolicy
			}
			return vault.NewSecret([]byte("k"), "static"), nil
		}
		_, info, err := testFallback(fp, lease, nil).SearchInfo(context.Background(), "q", 5, nil)
		if err == nil || info != (SearchInfo{Provider: "tavily", Fallback: "http_402", Status: "refused"}) {
			t.Fatalf("%+v %v", info, err)
		}
		if _, tv := fp.counts(); tv != 0 {
			t.Fatal("tavily reached without its key")
		}
	})
}

func TestSearchBreaker(t *testing.T) {
	now := time.Date(2026, 10, 21, 2, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	fp := &fakeProviders{exa: []string{"402", "402", "402", "402", "ok"}}
	f := testFallback(fp, nil, clock)
	search := func() SearchInfo {
		t.Helper()
		_, info, err := f.SearchInfo(context.Background(), "q", 5, nil)
		if err != nil {
			t.Fatal(err)
		}
		return info
	}
	for i := range breakerFailures {
		if info := search(); info.Fallback != "http_402" {
			t.Fatalf("search %d: %+v", i+1, info)
		}
	}
	// Open: straight to Tavily, Exa not asked.
	for range 3 {
		if info := search(); info != (SearchInfo{Provider: "tavily", Fallback: "breaker_open"}) {
			t.Fatalf("open: %+v", info)
		}
	}
	if e, _ := fp.counts(); e != breakerFailures {
		t.Fatalf("exa asked %d times while open", e)
	}
	// After the cooldown Exa gets one search; failing again reopens at once.
	now = now.Add(breakerCooldown)
	if info := search(); info.Fallback != "http_402" {
		t.Fatalf("after cooldown: %+v", info)
	}
	if info := search(); info.Fallback != "breaker_open" {
		t.Fatalf("reopened: %+v", info)
	}
	// It answers again: closed, and the count starts over.
	now = now.Add(breakerCooldown)
	if info := search(); info != (SearchInfo{Provider: "exa"}) {
		t.Fatalf("recovered: %+v", info)
	}
	if f.br.fails != 0 || !f.br.allow() {
		t.Fatalf("breaker %+v", f.br)
	}
}

// Through the tool: the masked query, the caps, and what the metrics event and the record say.
func TestSearchFallbackTool(t *testing.T) {
	fp := &fakeProviders{exa: []string{"402"}}
	f := testFallback(fp, nil, nil)
	var kinds []string
	var mu sync.Mutex
	tools := &Tools{search: f, gate: func(_ context.Context, kind string) (func(), error) {
		mu.Lock()
		kinds = append(kinds, kind)
		mu.Unlock()
		return func() {}, nil
	}}
	facts := &Facts{}
	ctx := WithFacts(context.Background(), facts)
	p, _ := tools.Exec(ctx, "web_search", json.RawMessage(`{"query":"flights for jane@example.com","count":3}`))
	out := tools.Finish(p)
	if out.failed != "" || len(out.citations) != 1 || out.citations[0].URL != "https://tavily.example/a" {
		t.Fatalf("outcome %+v", out)
	}
	if !slices.Equal(kinds, []string{"search", searchMoreGate}) {
		t.Fatalf("gates %v", kinds)
	}
	var tb map[string]any
	json.Unmarshal([]byte(fp.bodies["api.tavily.com"][0]), &tb)
	if tb["query"] != "flights for [email]" {
		t.Fatalf("tavily got %v", tb["query"])
	}
	m := toolMetric("web_search", 1, out, 10)
	if m.Kind != "search" || m.Provider != "tavily" || m.Fallback != "http_402" || m.Status != "" || m.Outcome != "ok" || m.Results != 1 {
		t.Fatalf("metric %+v", m)
	}
	b, _ := json.Marshal(m)
	if bytes.Contains(b, []byte("flights")) || bytes.Contains(b, []byte("example")) {
		t.Fatalf("metric carries content: %s", b)
	}
	if s := facts.Data().Search; s == nil || *s != (activity.Search{Provider: "tavily", Fallback: "http_402"}) {
		t.Fatalf("facts search %+v", s)
	}

	// Both failing: an error the model reads as before, and the metric says so.
	fp2 := &fakeProviders{exa: []string{"402"}, tavily: 500}
	tools.search = testFallback(fp2, nil, nil)
	p, _ = tools.Exec(context.Background(), "web_search", json.RawMessage(`{"query":"q"}`))
	out = tools.Finish(p)
	m = toolMetric("web_search", 1, out, 10)
	if out.content != `{"error":"search provider returned 500"}` || m.Outcome != "error" || m.Provider != "tavily" || m.Fallback != "http_402" || m.Status != "http_5xx" {
		t.Fatalf("outcome %+v metric %+v", out, m)
	}

	// A provider alone (no fallback) failing: its class.
	fp3 := &fakeProviders{exa: []string{"402"}}
	e := newExa(StaticKeys(func(string) string { return "k" }), nil)
	e.http = recordingClient(&http.Client{Transport: fp3})
	tools.search = e
	p, _ = tools.Exec(context.Background(), "web_search", json.RawMessage(`{"query":"q"}`))
	m = toolMetric("web_search", 1, tools.Finish(p), 10)
	if m.Outcome != "error" || m.Provider != "exa" || m.Fallback != "" || m.Status != "http_402" {
		t.Fatalf("metric %+v", m)
	}
}

// End to end, offline (e2e_test.go's brain and runtime): Exa out of credit, the run's search answered by Tavily;
// a search the leak scan refuses reaches neither provider.
func TestRunSearchFallback(t *testing.T) {
	fp := &fakeProviders{exa: []string{"402"}}
	e := newE2E(t, func(c *Config) { c.Search = testFallback(fp, nil, nil) },
		toolCallSSE("c1", "web_search", `{"query":"dstack release","count":3}`),
		textSSE("dstack [1]."))
	evs, err := e.run(proto.RunRequest{Space: testSpace, Permissions: AllowAll(), Messages: user("latest dstack?")})
	if err != nil {
		t.Fatal(err)
	}
	var m *proto.Metric
	var res proto.Event
	for _, ev := range evs {
		if ev.Type == "metrics" && ev.Metrics.Kind == "search" {
			m = ev.Metrics
		}
		if ev.Type == "tool_result" {
			res = ev
		}
	}
	if m == nil || m.Provider != "tavily" || m.Fallback != "http_402" || m.Outcome != "ok" || m.Results != 1 {
		t.Fatalf("search metric %+v", m)
	}
	if len(res.Citations) != 1 || res.Citations[0].URL != "https://tavily.example/a" {
		t.Fatalf("tool_result %+v", res)
	}

	fp2 := &fakeProviders{exa: []string{"402"}}
	key := "AKIA" + "QWERTYUIOPASDFGH"
	e2 := newE2E(t, func(c *Config) { c.Search = testFallback(fp2, nil, nil) },
		toolCallSSE("c1", "web_search", `{"query":"is this key valid `+key+`"}`),
		textSSE("Can't."))
	evs, err = e2.run(proto.RunRequest{Space: testSpace, Permissions: AllowAll(), Messages: user("q")})
	if err != nil {
		t.Fatal(err)
	}
	if ex, tv := fp2.counts(); ex != 0 || tv != 0 {
		t.Fatalf("a refused search reached a provider: exa %d, tavily %d", ex, tv)
	}
	for _, ev := range evs {
		if ev.Type == "metrics" && ev.Metrics.Kind == "search" && (ev.Metrics.Outcome != "refused" || ev.Metrics.Fallback != "") {
			t.Fatalf("refused search metric %+v", ev.Metrics)
		}
	}
}

func TestNewSearchFallback(t *testing.T) {
	keys := func(names ...string) func(string) bool {
		return func(n string) bool { return slices.Contains(names, n) }
	}
	if _, ok := NewSearch("", keys(exaKey, tavilyKey), nil).(*fallbackSearch); !ok {
		t.Fatal("exa and tavily keys: no fallback")
	}
	if _, ok := NewSearch("exa", keys(exaKey, tavilyKey), nil).(*fallbackSearch); !ok {
		t.Fatal("SEARCH_PROVIDER=exa with tavily's key: no fallback")
	}
	if _, ok := NewSearch("", keys(exaKey), nil).(*exa); !ok {
		t.Fatal("exa alone")
	}
	s := NewSearch("", keys(exaKey, tavilyKey, braveKey), nil)
	if s.Name() != "exa" || imageProviderName(s) != "brave" {
		t.Fatalf("%s, images %s", s.Name(), imageProviderName(s))
	}
	if _, ok := s.(ImageSearcher); !ok {
		t.Fatal("no image search")
	}
	if _, ok := NewSearch("", keys(tavilyKey), nil).(*tavily); !ok {
		t.Fatal("tavily alone")
	}
}
