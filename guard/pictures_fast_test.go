package guard

// v0.10.1's card photo lookups: started when the answer names a reader item, the fast image search first.

import (
	"context"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tacyhq/tacy/proto"
)

// fastLookupSearch is lookupSearch with a fast image search (ImagesFast) answering from its own table.
type fastLookupSearch struct {
	lookupSearch
	fast  map[string][]ImageCandidate
	order []string // "fast:<q>" and "slow:<q>", in order
}

func (s *fastLookupSearch) ImagesFast(ctx context.Context, q string, _ int) ([]ImageCandidate, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if SpaceFrom(ctx) != "s_chat" || taskFrom(ctx) == "" {
		s.badCtx = true
	}
	s.order = append(s.order, "fast:"+q)
	return s.fast[q], nil
}

func (s *fastLookupSearch) Images(ctx context.Context, q string, n int) ([]ImageCandidate, error) {
	s.mu.Lock()
	s.order = append(s.order, "slow:"+q)
	s.mu.Unlock()
	return s.lookupSearch.Images(ctx, q, n)
}

func (s *fastLookupSearch) calls() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.order)
}

// fastCalls are the fast searches' queries.
func (s *fastLookupSearch) fastCalls() []string {
	var out []string
	for _, c := range s.calls() {
		if q, ok := strings.CutPrefix(c, "fast:"); ok {
			out = append(out, q)
		}
	}
	return out
}

// mentionTask opens a task with pictures on (or the given setting) and the reader items under call c1.
func mentionTask(t *testing.T, s ImageSearcher, web stubWeb, setting string, items ...string) (*Guard, *task, func() []*proto.Image) {
	t.Helper()
	g := New(Config{Search: s.(SearchProvider), Fetcher: &http.Client{Transport: web}, Icons: &http.Client{Transport: stubWeb{}}, Now: time.Now})
	var mu sync.Mutex
	var imgs []*proto.Image
	tk := g.open("t1", TaskOptions{Space: "s_chat", Permissions: map[string]string{"web.search": "always", "web.images": setting}}, func(e proto.Event) error {
		if e.Type == "image" {
			mu.Lock()
			imgs = append(imgs, e.Image)
			mu.Unlock()
		}
		return nil
	})
	read := &readerResult{}
	for _, n := range items {
		read.items = append(read.items, keptItem{name: n})
	}
	tk.noteItems("c1", read)
	return g, tk, func() []*proto.Image {
		mu.Lock()
		defer mu.Unlock()
		return slices.Clone(imgs)
	}
}

func waitFor(t *testing.T, what string, ok func() bool) {
	t.Helper()
	for range 200 {
		if ok() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// A lookup starts when the answer names a reader item, before its card: the card then takes that lookup's picture,
// with no second search. What goes out is the reader's name.
func TestLookupStartsAtMention(t *testing.T) {
	s := &fastLookupSearch{lookupSearch: lookupSearch{answers: map[string][]ImageCandidate{}}, fast: map[string][]ImageCandidate{
		"Profitec GO": {{URL: "https://shop.example/profitec-go.jpg", Title: "Profitec GO Espresso Machine", Source: "https://shop.example/profitec-go"}},
	}}
	web := stubWeb{"https://shop.example/profitec-go.jpg": pngWH(600, 600)}
	g, tk, imgs := mentionTask(t, s, web, "always", "Profitec GO", "Gaggia Classic Pro")
	g.cardText(tk, "For most people, the Profitec GO is ")
	waitFor(t, "the lookup at the mention", func() bool { return len(s.calls()) == 1 })
	if c := s.calls(); c[0] != "fast:Profitec GO" || s.badCtx {
		t.Fatalf("calls %q (bad context %v)", c, s.badCtx)
	}
	if len(imgs()) != 0 {
		t.Fatal("a picture before its card")
	}
	g.cardText(tk, "the pick.\n```items\n{\"items\":[{\"title\":\"Profitec GO Espresso Machine\",\"source\":\"[1]\"}]}\n```\n")
	g.cardTextDone(tk)
	tk.cards.wait(5 * time.Second)
	if c := s.calls(); len(c) != 1 {
		t.Fatalf("calls %q, want the one lookup", c)
	}
	if got := imgs(); len(got) != 1 || got[0].For != "Profitec GO" || got[0].URL != "https://shop.example/profitec-go.jpg" {
		t.Fatalf("pictures %+v", got)
	}
}

// Reasoning names items too (gateway.go feeds it to the watch).
func TestLookupStartsAtMentionInReasoning(t *testing.T) {
	s := &fastLookupSearch{lookupSearch: lookupSearch{answers: map[string][]ImageCandidate{}}, fast: map[string][]ImageCandidate{}}
	g, tk, _ := mentionTask(t, s, stubWeb{}, "always", "Gaggia Classic Pro")
	g.watchMentions(tk, "I'll recommend the Gaggia Classic Pro and ")
	waitFor(t, "the lookup", func() bool { return len(s.calls()) >= 1 })
	if c := s.calls(); c[0] != "fast:Gaggia Classic Pro" {
		t.Fatalf("calls %q", c)
	}
}

// No mention lookups without pictures allowed (Ask or Never): nothing goes out.
func TestMentionNeedsThePicturesSetting(t *testing.T) {
	for _, setting := range []string{"ask", "never", ""} {
		s := &fastLookupSearch{lookupSearch: lookupSearch{answers: map[string][]ImageCandidate{}}, fast: map[string][]ImageCandidate{}}
		g, tk, _ := mentionTask(t, s, stubWeb{}, setting, "Profitec GO")
		g.cardText(tk, "The Profitec GO is the pick. ")
		g.watchMentions(tk, "Profitec GO it is. ")
		time.Sleep(50 * time.Millisecond)
		if c := s.calls(); len(c) != 0 {
			t.Fatalf("setting %q: calls %q", setting, c)
		}
	}
}

// The longest item named wins ("Fellow Stagg EKG Pro", not "Fellow Stagg EKG" too), even while its name streams in;
// single plain words never start one; at most maxEarlyLookups.
func TestMentionLongestAndCapped(t *testing.T) {
	s := &fastLookupSearch{lookupSearch: lookupSearch{answers: map[string][]ImageCandidate{}}, fast: map[string][]ImageCandidate{}}
	g, tk, _ := mentionTask(t, s, stubWeb{}, "always", "Fellow Stagg EKG", "Fellow Stagg EKG Pro", "Stagg", "2P", "Stagg EKG Pro", "Kettle A1", "Kettle B2", "Kettle C3", "Kettle K4", "Kettle E5")
	for _, d := range []string{"The Fellow Stagg ", "EKG", " Pro", " wins (2P); the Stagg line is great. "} {
		g.cardText(tk, d)
	}
	waitFor(t, "one lookup", func() bool { return len(s.fastCalls()) == 1 })
	time.Sleep(30 * time.Millisecond)
	if c := s.fastCalls(); len(c) != 1 || c[0] != "Fellow Stagg EKG Pro" {
		t.Fatalf("calls %q", c)
	}
	g.cardText(tk, "Also Kettle A1, Kettle B2, Kettle C3, Kettle K4 and Kettle E5. ")
	time.Sleep(100 * time.Millisecond)
	if c := s.fastCalls(); len(c) != maxEarlyLookups {
		t.Fatalf("calls %q, want %d", c, maxEarlyLookups)
	}
}

// The fast search first; its candidates that don't pass (a caption that doesn't name the item) go to the slow one,
// where a picture whose caption names the item is tried even though the fast search had it too.
func TestLookupFastThenSlow(t *testing.T) {
	u := "https://img.example/a1b2c3.jpg"
	s := &fastLookupSearch{
		lookupSearch: lookupSearch{answers: map[string][]ImageCandidate{"Gaggia Classic Pro": {{URL: u, Title: "Gaggia Classic Pro espresso machine", Source: "https://gaggia.example/"}}}},
		fast:         map[string][]ImageCandidate{"Gaggia Classic Pro": {{URL: u, Title: "Kitchen deals", Source: "https://deals.example/"}}},
	}
	web := stubWeb{u: pngWH(500, 500)}
	g, tk, imgs := mentionTask(t, s, web, "always", "Gaggia Classic Pro")
	g.cardText(tk, "```items\n{\"items\":[{\"title\":\"Gaggia Classic Pro\",\"source\":\"[1]\"}]}\n```\n")
	g.cardTextDone(tk)
	tk.cards.wait(5 * time.Second)
	if c := s.calls(); !slices.Equal(c, []string{"fast:Gaggia Classic Pro", "slow:Gaggia Classic Pro"}) {
		t.Fatalf("calls %q", c)
	}
	if got := imgs(); len(got) != 1 || got[0].URL != u {
		t.Fatalf("pictures %+v", got)
	}
}

// A fast search with a picture that works: no slow search.
func TestLookupFastEnough(t *testing.T) {
	s := &fastLookupSearch{lookupSearch: lookupSearch{answers: map[string][]ImageCandidate{}}, fast: map[string][]ImageCandidate{
		"Gaggia Classic Pro": {
			{URL: "https://img.example/broken.jpg", Title: "Gaggia Classic Pro", Source: "https://gaggia.example/"},
			{URL: "https://img.example/gaggia.jpg", Title: "Gaggia Classic Pro", Source: "https://gaggia.example/"},
		}}}
	web := stubWeb{"https://img.example/gaggia.jpg": pngWH(500, 500)}
	g, tk, imgs := mentionTask(t, s, web, "always", "Gaggia Classic Pro")
	g.cardText(tk, "```items\n{\"items\":[{\"title\":\"Gaggia Classic Pro\",\"source\":\"[1]\"}]}\n```\n")
	g.cardTextDone(tk)
	tk.cards.wait(5 * time.Second)
	if c := s.calls(); !slices.Equal(c, []string{"fast:Gaggia Classic Pro"}) {
		t.Fatalf("calls %q", c)
	}
	if got := imgs(); len(got) != 1 || got[0].URL != "https://img.example/gaggia.jpg" {
		t.Fatalf("pictures %+v", got)
	}
}

func TestUnitNumber(t *testing.T) {
	for _, c := range []struct {
		w, caption string
		ok         bool
	}{
		{"20", "atomic 20v max", true},
		{"6", "vortex plus 6qt air fryer", true},
		{"9", "pixel 9a", false},
		{"15", "iphone 15pro", false},
		{"2", "superblast 25", false},
		{"1234", "1234v", false},
	} {
		if got := unitNumber(c.w, strings.Fields(c.caption)); got != c.ok {
			t.Errorf("%q in %q: %v", c.w, c.caption, got)
		}
	}
	// In the photo check: the drill's "20" is its caption's "20V" (refused as another model number before v0.10.1).
	c := ImageCandidate{URL: "https://assets.dewalt.example/DCD794B_1.jpg", Title: "ATOMIC 20V MAX Brushless Cordless Drill/Driver"}
	if why := pictureNames("DeWalt Atomic 20-Volt Max Brushless Cordless Drill Driver DCD794B", c); why != "" {
		t.Fatalf("refused: %q", why)
	}
	if why := pictureNames("DeWalt Atomic 18-Volt Max Brushless Cordless Drill Driver DCD794B", c); why != imageNumber {
		t.Fatalf("another voltage: %q", why)
	}
}

func TestParseTavilyImagesFast(t *testing.T) {
	raw := []byte(`{"images":["https://img.example/top.jpg","https://cdn.example/shared.jpg"],
	"results":[{"title":"Gaggia Classic Pro Espresso Machine","url":"https://shop.example/gaggia","images":["https://cdn.example/shared.jpg","https://cdn.example/2.jpg","https://cdn.example/3.jpg","https://cdn.example/4.jpg","https://cdn.example/logo.png"]},
	{"title":"Other","url":"https://other.example/","images":[]}]}`)
	cs, err := parseTavilyImagesFast(raw, 20)
	if err != nil {
		t.Fatal(err)
	}
	want := []ImageCandidate{
		{URL: "https://img.example/top.jpg"},
		{URL: "https://cdn.example/shared.jpg", Title: "Gaggia Classic Pro Espresso Machine", Source: "https://shop.example/gaggia"},
		{URL: "https://cdn.example/2.jpg", Title: "Gaggia Classic Pro Espresso Machine", Source: "https://shop.example/gaggia"},
		{URL: "https://cdn.example/3.jpg", Title: "Gaggia Classic Pro Espresso Machine", Source: "https://shop.example/gaggia"},
	}
	if !slices.Equal(cs, want) {
		t.Fatalf("got %+v", cs)
	}
}
