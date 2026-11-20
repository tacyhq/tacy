package guard

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// Tacy adds no content blocking of its own: Brave's web and image searches ask for
// safesearch off, and Tavily's searches never ask for safe_search (its filter is off unless asked for).
// Exa's moderation: exa_test.go.
func TestSearchProvidersAskForNoContentFilter(t *testing.T) {
	var queries []string
	var bodies []map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			queries = append(queries, r.URL.Path+" "+r.URL.Query().Get("safesearch"))
		} else {
			raw, _ := io.ReadAll(r.Body)
			var b map[string]any
			json.Unmarshal(raw, &b)
			bodies = append(bodies, b)
		}
		w.Write([]byte(`{}`))
	}))
	defer srv.Close()
	ctx := context.Background()
	b := &brave{lease: testLease(), base: srv.URL + "/res/v1/web/search", http: srv.Client()}
	b.Search(ctx, "q", 5)
	b.Images(ctx, "q", 5)
	want := []string{"/res/v1/web/search off", "/res/v1/images/search off"}
	if len(queries) != 2 || queries[0] != want[0] || queries[1] != want[1] {
		t.Fatalf("brave safesearch %q", queries)
	}
	tv := &tavily{lease: testLease(), base: srv.URL, http: srv.Client()}
	tv.Search(ctx, "q", 5)
	tv.Images(ctx, "q", 5)
	tv.ImagesFast(ctx, "q", 5)
	if len(bodies) != 3 {
		t.Fatalf("tavily requests: %d", len(bodies))
	}
	for i, body := range bodies {
		if v, ok := body["safe_search"]; ok && v != false {
			t.Fatalf("tavily request %d: safe_search %v", i, v)
		}
		if body["query"] != "q" {
			t.Fatalf("tavily request %d: %v", i, body)
		}
	}
}
