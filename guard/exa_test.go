package guard

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tacyhq/tacy/harness"
	"github.com/tacyhq/tacy/vault"
)

const fakeExaKey = "exa-test-" + "not-a-real-key-0123456789ab"

// exaServer is a stand-in for api.exa.ai/search: it keeps each request's headers and body and answers with resp
// (status 200 unless status is set).
type exaServer struct {
	mu      sync.Mutex
	headers []http.Header
	bodies  []map[string]any
	status  int
	resp    func(key string) string
}

func (x *exaServer) start(t *testing.T) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var m map[string]any
		json.Unmarshal(b, &m)
		x.mu.Lock()
		x.headers = append(x.headers, r.Header.Clone())
		x.bodies = append(x.bodies, m)
		x.mu.Unlock()
		if r.Method != "POST" || r.URL.Path != "/search" {
			w.WriteHeader(404)
			return
		}
		if x.status != 0 {
			w.WriteHeader(x.status)
		}
		io.WriteString(w, x.resp(r.Header.Get("x-api-key")))
	}))
	t.Cleanup(srv.Close)
	return srv
}

const exaResults = `{"requestId":"r1","results":[
 {"id":"https://a.example/1","title":"First <b>result</b> &amp; more","url":"https://a.example/1","publishedDate":"2026-10-01T00:00:00.000Z",
  "highlights":["One highlight.","Two highlight."],"image":"https://a.example/pic.jpg","favicon":"https://a.example/favicon.ico"},
 {"id":"x","title":"Not a web page","url":"javascript:alert(1)","highlights":["x"]},
 {"id":"https://b.example/2","title":"Second","url":"https://b.example/2","highlights":[],"image":"https://b.example/logo.png"},
 {"id":"https://c.example/3","title":"Third","url":"https://c.example/3","highlights":["` + "long " + `"]}
],"costDollars":{"total":0.007}}`

func TestExaRequestAndResults(t *testing.T) {
	x := &exaServer{resp: func(string) string { return exaResults }}
	srv := x.start(t)
	e := newExa(StaticKeys(func(n string) string {
		if n == exaKey {
			return fakeExaKey
		}
		return ""
	}), nil)
	e.http = &http.Client{Transport: to{srv}}
	rs, err := e.Search(context.Background(), "masked query [email]", 2)
	if err != nil {
		t.Fatal(err)
	}
	// Exactly what Exa may get: the query, the count, the type, moderation and highlights; nothing about the person.
	if len(x.bodies) != 1 {
		t.Fatalf("requests: %d", len(x.bodies))
	}
	body := x.bodies[0]
	var keys []string
	for k := range body {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	if strings.Join(keys, ",") != "contents,moderation,numResults,query,type" {
		t.Fatalf("body keys: %v", keys)
	}
	if body["query"] != "masked query [email]" || body["numResults"] != float64(2) || body["type"] != exaType || body["moderation"] != true {
		t.Fatalf("body: %v", body)
	}
	if c, _ := json.Marshal(body["contents"]); string(c) != `{"highlights":{"maxCharacters":400}}` {
		t.Fatalf("contents: %s", c)
	}
	h := x.headers[0]
	if h.Get("x-api-key") != fakeExaKey || h.Get("Authorization") != "" || h.Get("Content-Type") != "application/json" {
		t.Fatalf("headers: %v", h)
	}
	for name := range h {
		if strings.HasPrefix(strings.ToLower(name), "x-exa") || strings.EqualFold(name, "Cookie") || strings.EqualFold(name, "X-Forwarded-For") {
			t.Fatalf("header %s sent", name)
		}
	}
	// Mapped, cleaned, the non-web address dropped, capped at the count asked for.
	if len(rs) != 2 {
		t.Fatalf("results: %+v", rs)
	}
	if rs[0].Title != "First result & more" || rs[0].URL != "https://a.example/1" || rs[0].Snippet != "One highlight. … Two highlight." ||
		rs[0].Age != "2026-10-01T00:00:00.000Z" || len(rs[0].Thumbs) != 1 || rs[0].Thumbs[0] != "https://a.example/pic.jpg" {
		t.Fatalf("first: %+v", rs[0])
	}
	if rs[1].Title != "Second" || rs[1].Snippet != "" || len(rs[1].Thumbs) != 0 { // a logo isn't a card picture
		t.Fatalf("second: %+v", rs[1])
	}
}

// Exa's error text quotes the query back: the brain and the person get our words only.
func TestExaErrorsSayOurWords(t *testing.T) {
	for _, c := range []struct {
		status int
		body   string
		want   string
	}{
		{403, `{"requestId":"r","error":"Query 'secret words' does not meet moderation criteria because it contains blocklisted keywords","tag":"CONTENT_FILTER_ERROR"}`,
			"the search provider's safety filter refused this query"},
		{429, `{"error":"Rate limit for query 'secret words'"}`, "search provider returned 429"},
		{200, `not json 'secret words'`, "search provider: bad response"},
	} {
		x := &exaServer{status: c.status, resp: func(string) string { return c.body }}
		srv := x.start(t)
		e := newExa(StaticKeys(func(string) string { return fakeExaKey }), nil)
		e.http = &http.Client{Transport: to{srv}}
		_, err := e.Search(context.Background(), "secret words", 3)
		if err == nil || err.Error() != c.want || strings.Contains(err.Error(), "secret") {
			t.Fatalf("%d: %v", c.status, err)
		}
	}
}

// Through the guard and the vault as in the CVM: the key is leased per call for api.exa.ai only, and an echoed key
// never reaches the brain in any encoding.
func TestExaKeyLeasedPerCallAndRedacted(t *testing.T) {
	vc, records := startVault(t, map[string][]byte{exaKey: []byte(fakeExaKey)})
	x := &exaServer{resp: func(k string) string {
		b, _ := json.Marshal(map[string]any{"results": []map[string]any{{"title": "echo " + base64.StdEncoding.EncodeToString([]byte(k)),
			"url": "https://a.example/", "highlights": []string{"your key is " + k}}}})
		return string(b)
	}}
	srv := x.start(t)
	e := newExa(VaultLease(vc), nil)
	e.http = &http.Client{Transport: to{srv}}
	g := New(Config{Up: &plainUpstream{}, Search: e, Now: time.Now})
	ti := &harness.TaskInfo{ID: "t_exa", Start: &harness.Start{}, Options: []byte(`{"permissions":{"web.search":"always"}}`)}
	for _, id := range []string{"r1", "r2"} {
		res, err := g.Action(harness.WithRequestID(context.Background(), id), ti, id, &harness.Action{Name: "web.search", Args: []byte(`{"query":"q"}`)})
		if err != nil || res.Status != harness.ActionDone {
			t.Fatalf("%s: %+v %v", id, res, err)
		}
		if out := string(res.Output); strings.Contains(out, fakeExaKey) || strings.Contains(out, base64.StdEncoding.EncodeToString([]byte(fakeExaKey))) ||
			!strings.Contains(out, "[REDACTED]") {
			t.Fatalf("%s: the key came back: %s", id, out)
		}
	}
	recs := records()
	if len(recs) != 2 || recs[0].Lease == recs[1].Lease {
		t.Fatalf("records: %+v", recs)
	}
	for _, r := range recs {
		if r.Decision != "released" || r.Secret != exaKey || r.Connector != "web" || r.Host != "api.exa.ai" || r.Task != "t_exa" {
			t.Fatalf("record: %+v", r)
		}
	}
	// Another host gets no key, and Exa never sees a request.
	n := len(x.bodies)
	e.base = "https://api.exa.example/search"
	if _, err := e.Search(context.Background(), "q", 3); err == nil || err.Error() != "search key unavailable" {
		t.Fatalf("other host: %v", err)
	}
	if len(x.bodies) != n {
		t.Fatal("a request went out without a released key")
	}
	if recs := records(); recs[len(recs)-1].Decision != "denied" || recs[len(recs)-1].Reason != vault.ErrHost.Error() {
		t.Fatalf("records: %+v", recs)
	}
}

// The provider's choice: SEARCH_PROVIDER first, else Exa when its key is set (the production default), else Brave,
// else Tavily; with Exa, image_search goes to Brave or Tavily as before.
func TestNewSearchPicksExa(t *testing.T) {
	keys := func(names ...string) func(string) bool {
		return func(n string) bool { return slices.Contains(names, n) }
	}
	for _, c := range []struct {
		provider string
		has      []string
		want     string
		images   string
	}{
		{"", []string{exaKey, tavilyKey}, "exa", "tavily"},
		{"", []string{exaKey, braveKey, tavilyKey}, "exa", "brave"},
		{"", []string{braveKey, tavilyKey}, "brave", "brave"},
		{"", []string{tavilyKey}, "tavily", "tavily"},
		{"tavily", []string{exaKey, tavilyKey}, "tavily", "tavily"}, // the fallback, chosen by name
		{"brave", []string{exaKey}, "brave", "brave"},
		{"exa", []string{tavilyKey}, "exa", "tavily"},
	} {
		s := NewSearch(c.provider, keys(c.has...), nil)
		if s.Name() != c.want || imageProviderName(s) != c.images {
			t.Errorf("%q %v: %s, images %s", c.provider, c.has, s.Name(), imageProviderName(s))
		}
		if _, ok := s.(ImageSearcher); !ok {
			t.Errorf("%s: no image search", s.Name())
		}
	}
}

// image_search with Exa goes to the image provider (Tavily here), and its metric names that provider.
func TestExaImagesGoToTheImageProvider(t *testing.T) {
	var got []string
	img := &fakeImages{name: "tavily", fn: func(q string) { got = append(got, q) }}
	e := newExa(nil, img)
	if _, err := e.Images(context.Background(), "a red kettle", 4); err != nil || len(got) != 1 || got[0] != "a red kettle" {
		t.Fatalf("images: %v %v", got, err)
	}
	if imageProviderName(e) != "tavily" {
		t.Fatal(imageProviderName(e))
	}
	if _, err := newExa(nil, nil).Images(context.Background(), "q", 1); err == nil {
		t.Fatal("no image provider: no error")
	}
}

type fakeImages struct {
	name string
	fn   func(string)
}

func (f *fakeImages) Name() string { return f.name }
func (f *fakeImages) Images(_ context.Context, q string, _ int) ([]ImageCandidate, error) {
	f.fn(q)
	return nil, nil
}
