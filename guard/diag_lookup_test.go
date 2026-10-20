package guard

// Diagnosis lab (from branch diag/photo-lookup-timeout; skipped unless DIAG=1): why two card photo lookups time out at 12 s on the
// live VM (v0.8.22, running shoes, run 1: never_arrived 2 in the run, then the ticket's fill: 12001 ms, unreachable 2,
// tried 0). A fake Tavily answers each item's image search after a set delay; everything else is the production
// path (exa provider wrapping tavily.Images over HTTP, the tool gates at DefaultLimits, cardLookupWait, lookupTime,
// the ticket and the pictures task).

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tacyhq/tacy/harness"
	"github.com/tacyhq/tacy/proto"
)

const shoesRun1 = "Picks [5]:\n```items\n" +
	`{"items":[{"title":"Asics Superblast 3","source":"[5]"},{"title":"Saucony Triumph 24","source":"[5]"},` +
	`{"title":"Mizuno Wave Rider 30","source":"[5]"},{"title":"Brooks Adrenaline GTS 25","source":"[5]"}]}` + "\n```\nDone."

func slowTavily(delays map[string]time.Duration) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var b struct {
			Query string `json:"query"`
		}
		json.NewDecoder(r.Body).Decode(&b)
		select {
		case <-time.After(delays[b.Query]):
		case <-r.Context().Done():
			return
		}
		slug := itemKey(b.Query)
		json.NewEncoder(w).Encode(map[string]any{
			"images":  []map[string]string{{"url": "https://img.example/" + slugify(slug) + ".jpg", "description": b.Query + " running shoe, side view"}},
			"results": []any{},
		})
	}))
}

func slugify(s string) string {
	out := []rune(s)
	for i, r := range out {
		if r == ' ' {
			out[i] = '-'
		}
	}
	return string(out)
}

func TestDiagSlowImageSearch(t *testing.T) {
	if os.Getenv("DIAG") == "" {
		t.Skip("diagnosis lab: DIAG=1")
	}
	if os.Getenv("DIAG_BEFORE") != "" { // v0.8.22's budget: one 12 s for the search and the downloads
		defer func(a, b time.Duration) { lookupSearchTime, lookupFetchTime = a, b }(lookupSearchTime, lookupFetchTime)
		lookupSearchTime, lookupFetchTime = 12*time.Second, 12*time.Second
	}
	items := []string{"Asics Superblast 3", "Saucony Triumph 24", "Mizuno Wave Rider 30", "Brooks Adrenaline GTS 25"}
	answer := shoesRun1
	var search SearchProvider
	var fetcher *http.Client
	if live := os.Getenv("DIAG_LIVE_ITEMS"); live != "" { // the real Tavily (TAVILY_API_KEY) and the real guarded fetcher
		items = strings.Split(live, ",")
		var cards []string
		for _, n := range items {
			cards = append(cards, fmt.Sprintf(`{"title":%q,"source":"[5]"}`, n))
		}
		answer = "Picks [5]:\n```items\n{\"items\":[" + strings.Join(cards, ",") + "]}\n```\nDone."
		ex := NewSearch("exa", func(n string) bool { return os.Getenv(n) != "" }, StaticKeys(os.Getenv)).(*exa)
		search = &timedImages{exa: ex, t: t}
		fetcher = NewFetcher(false)
	} else {
		slowMs := 13000
		fmt.Sscan(os.Getenv("DIAG_SLOW_MS"), &slowMs)
		slow := time.Duration(slowMs) * time.Millisecond
		delays := map[string]time.Duration{items[0]: 500 * time.Millisecond, items[2]: time.Second, items[1]: slow, items[3]: slow}
		srv := slowTavily(delays)
		defer srv.Close()
		tv := newTavily(StaticKeys(func(string) string { return "diag-key-0123456789" }))
		tv.base = srv.URL
		search = &exa{lease: StaticKeys(func(string) string { return "diag-key-0123456789" }), images: tv}
		web := stubWeb{}
		for _, n := range items {
			web["https://img.example/"+slugify(itemKey(n))+".jpg"] = pngWH(600, 600)
		}
		fetcher = &http.Client{Transport: web}
	}
	lim := DefaultLimits
	g := New(Config{Search: search, Fetcher: fetcher, Icons: &http.Client{Transport: stubWeb{}}, Limits: &lim, Now: time.Now})
	var mu sync.Mutex
	var evs []proto.Event
	t0 := time.Now()
	sess := g.Open("t1", TaskOptions{User: "u1", Space: "s_chat", Permissions: map[string]string{"web.images": "always"}}, func(e proto.Event) error {
		mu.Lock()
		evs = append(evs, e)
		mu.Unlock()
		if e.Type == "image" {
			t.Logf("run  %5.1f s  picture for %q: %q %s", time.Since(t0).Seconds(), e.Image.For, e.Image.Title, e.Image.URL)
			diagSave("run", e.Image)
		}
		return nil
	})
	tk := g.task(&harness.TaskInfo{ID: "t1"})
	read := &readerResult{}
	for _, n := range items {
		read.items = append(read.items, keptItem{name: n})
	}
	tk.noteItems("c1", read)
	g.cardText(tk, answer)
	g.cardTextDone(tk)
	sess.End()
	sess.Close()
	ticket := ""
	mu.Lock()
	for _, e := range evs {
		switch {
		case e.Type == "pictures":
			ticket = e.Pictures
		case e.Type == "metrics" && e.Metrics != nil && e.Metrics.Kind == "card_pictures":
			t.Logf("run  %5.1f s  metric: shown %d tried %d reasons %v", time.Since(t0).Seconds(), e.Metrics.Images, e.Metrics.Tried, e.Metrics.Reasons)
		}
	}
	mu.Unlock()
	if ticket == "" {
		t.Logf("no ticket")
		return
	}
	start, opts, args, err := PicturesStart(&proto.PicturesRequest{Ticket: ticket, Space: "s_chat"}, time.Now()) // v0.10.0: every request names its space
	if err != nil {
		t.Fatal(err)
	}
	opts.User, opts.Space = "u1", start.Space
	t1 := time.Now()
	ps := g.Open("p1", opts, func(e proto.Event) error {
		switch {
		case e.Type == "image":
			t.Logf("fill %5.1f s  picture for %q: %q %s", time.Since(t1).Seconds(), e.Image.For, e.Image.Title, e.Image.URL)
			diagSave("fill", e.Image)
		case e.Type == "metrics" && e.Metrics != nil && e.Metrics.Kind == "card_pictures":
			t.Logf("fill metric: ms %d shown %d tried %d failed %d reasons %v", e.Metrics.Ms, e.Metrics.Images, e.Metrics.Tried, e.Metrics.Failed, e.Metrics.Reasons)
		}
		return nil
	})
	res, err := g.Action(context.Background(), &harness.TaskInfo{ID: "p1", Start: &start}, PicturesActionID, &harness.Action{Name: "web.images", Call: PicturesActionID, Args: args})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("fill %5.1f s  action %s %s", time.Since(t1).Seconds(), res.Status, res.Output)
	ps.End()
	ps.Close()
}

// timedImages logs each image search's time and outcome (never the key).
type timedImages struct {
	*exa
	t *testing.T
}

func (s *timedImages) Images(ctx context.Context, q string, n int) ([]ImageCandidate, error) {
	t0 := time.Now()
	cs, err := s.exa.Images(ctx, q, n)
	s.t.Logf("     image search %q: %.1f s, %d candidates, err %v", q, time.Since(t0).Seconds(), len(cs), err)
	return cs, err
}

func diagSave(phase string, im *proto.Image) {
	if d := os.Getenv("DIAG_OUT"); d != "" {
		os.MkdirAll(d, 0o755)
		os.WriteFile(fmt.Sprintf("%s/%s-%s.jpg", d, phase, slugify(itemKey(im.For))), im.Data, 0o644)
	}
}
