package guard

// The card photo speed lab (not run by default; v0.10.1): agent runs recorded from the live VM with photos off
// (cmd/photolab: each event's time, the reader's items as the model got them, the answer) are replayed here in real
// time through the guard's production path (noteItems at each search's result, the answer's text and reasoning
// deltas through cardText and the mention watch, cardTextDone, the session's End with its wait and ticket, then the
// ticket's fill as POST /pictures runs it, PHOTOLAB_RELAY_MS after the run's end) against the real image search
// (Tavily, TAVILY_API_KEY) and the real guarded downloads. Per card: when its photo arrived relative to the answer's
// last text, and the photo itself (PHOTOLAB_OUT/<case>-<n>.jpg) for a look.
//
//	set -a; . ../../.env; set +a
//	PHOTOLAB=<traces dir> PHOTOLAB_OUT=<dir> go test ./guard -run TestPhotoLab -v -timeout 30m
//
// Tavily caches a query for a while: replay each trace once per kind of search (the fast search and the one with
// descriptions are cached apart).

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tacyhq/tacy/harness"
	"github.com/tacyhq/tacy/proto"
)

type labEv struct {
	TMs    int64           `json:"t_ms"`
	Phase  string          `json:"phase"`
	Type   string          `json:"type"`
	ID     string          `json:"id"`
	Delta  string          `json:"delta"`
	Result json.RawMessage `json:"result"`
}

type labTrace struct {
	ID      string  `json:"id"`
	TextEnd int64   `json:"text_end_ms"`
	Answer  string  `json:"answer"`
	Events  []labEv `json:"events"`
}

type labCard struct {
	Case, Title, Item, Phase, URL, Caption, File string
	AfterMs                                      *int64 // photo arrival - the answer's last text (nil: none)
}

var labItemRef = regexp.MustCompile(`\s*\[\d+\]\s*$`)

func TestPhotoLab(t *testing.T) {
	dir, out := os.Getenv("PHOTOLAB"), os.Getenv("PHOTOLAB_OUT")
	if dir == "" || os.Getenv("TAVILY_API_KEY") == "" {
		t.Skip("lab only: PHOTOLAB and TAVILY_API_KEY")
	}
	relay := 500 * time.Millisecond
	if v := os.Getenv("PHOTOLAB_RELAY_MS"); v != "" {
		var ms int
		fmt.Sscan(v, &ms)
		relay = time.Duration(ms) * time.Millisecond
	}
	files, _ := filepath.Glob(filepath.Join(dir, "*.json"))
	if only := os.Getenv("PHOTOLAB_ONLY"); only != "" {
		var keep []string
		for _, f := range files {
			for _, id := range strings.Split(only, ",") {
				if strings.TrimSuffix(filepath.Base(f), ".json") == id {
					keep = append(keep, f)
				}
			}
		}
		files = keep
	}
	if out != "" {
		os.MkdirAll(out, 0o755)
	}
	var mu sync.Mutex
	var all []labCard
	sem := make(chan struct{}, 4)
	var wg sync.WaitGroup
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var tr labTrace
		if err := json.Unmarshal(b, &tr); err != nil {
			t.Fatal(f, err)
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			cards := labReplay(t, &tr, relay, out)
			mu.Lock()
			all = append(all, cards...)
			mu.Unlock()
		}()
	}
	wg.Wait()
	sort.Slice(all, func(i, j int) bool { return all[i].Case+all[i].Title < all[j].Case+all[j].Title })
	var times []int64
	none := 0
	for _, c := range all {
		line := fmt.Sprintf("%-14s %-48.48q item %-40.40q", c.Case, c.Title, c.Item)
		if c.AfterMs == nil {
			none++
			t.Logf("%s  NO PHOTO", line)
			continue
		}
		times = append(times, *c.AfterMs)
		t.Logf("%s  %+6.1f s (%s) %q %s %s", line, float64(*c.AfterMs)/1000, c.Phase, c.Caption, c.URL, c.File)
	}
	sort.Slice(times, func(i, j int) bool { return times[i] < times[j] })
	pct := func(p float64) float64 {
		if len(times) == 0 {
			return 0
		}
		// Cards without a photo count as never arriving: the percentile is over all cards.
		i := int(p*float64(len(all))+0.999999) - 1
		if i >= len(times) {
			return 999
		}
		return float64(times[max(i, 0)]) / 1000
	}
	t.Logf("CREDITS fast %d, with descriptions %d: $%.3f at $0.008", labCredits.fast, labCredits.slow, 0.008*float64(labCredits.fast+labCredits.slow))
	t.Logf("SUMMARY cards %d, with photo %d, no photo %d (%.0f%%), median %+.1f s, p90 %+.1f s (over all cards; none = never)",
		len(all), len(times), none, 100*float64(none)/float64(max(len(all), 1)), pct(0.5), pct(0.9))
	if out != "" {
		b, _ := json.MarshalIndent(all, "", " ")
		os.WriteFile(filepath.Join(out, "cards.json"), b, 0o644)
	}
}

// labReplay replays one trace and returns its cards' outcomes.
func labReplay(t *testing.T, tr *labTrace, relay time.Duration, out string) []labCard {
	keys := StaticKeys(os.Getenv)
	search := &labSearch{exa: newExa(keys, newTavily(keys)), t: t, id: tr.ID} // the VM's: Exa for the web, Tavily for images
	lim := DefaultLimits
	g := New(Config{Search: search, Fetcher: NewFetcher(false), Icons: NewFetcher(false), Limits: &lim, Now: time.Now})
	var mu sync.Mutex
	type got struct {
		at    time.Time
		phase string
		im    *proto.Image
	}
	var imgs []got
	phase := "run"
	ticket := ""
	emit := func(e proto.Event) error {
		mu.Lock()
		defer mu.Unlock()
		switch e.Type {
		case "image":
			if e.Image != nil && e.Image.For != "" {
				imgs = append(imgs, got{time.Now(), phase, e.Image})
			}
		case "pictures":
			ticket = e.Pictures
		case "metrics":
			if e.Metrics != nil && e.Metrics.Kind == "card_pictures" {
				t.Logf("%s %s card_pictures: %+v", tr.ID, phase, *e.Metrics)
			}
		}
		return nil
	}
	id := "lab-" + tr.ID
	sess := g.Open(id, TaskOptions{User: "u1", Space: "s_chat", Permissions: map[string]string{"web.search": "always", "web.fetch": "always", "web.images": "always"}}, emit)
	tk := g.task(&harness.TaskInfo{ID: id})
	t0 := time.Now()
	textEnd := t0.Add(time.Duration(tr.TextEnd) * time.Millisecond)
	inCall := false
	for _, e := range tr.Events {
		if e.Phase != "run" {
			continue
		}
		time.Sleep(time.Until(t0.Add(time.Duration(e.TMs) * time.Millisecond)))
		switch e.Type {
		case "step":
			if inCall {
				g.cardTextDone(tk)
			}
			tk.cards.reset()
			inCall = true
		case "tool_result":
			var r struct {
				Read *struct {
					Items []string `json:"items"`
				} `json:"read"`
			}
			if json.Unmarshal(e.Result, &r) == nil && r.Read != nil {
				read := &readerResult{}
				for _, s := range r.Read.Items {
					name := strings.TrimSpace(labItemRef.ReplaceAllString(strings.SplitN(s, " · ", 2)[0], ""))
					if name != "" {
						read.items = append(read.items, keptItem{name: name})
					}
				}
				tk.noteItems(e.ID, read)
			}
		case "text":
			g.cardText(tk, e.Delta)
		case "reasoning":
			labReasoning(g, tk, e.Delta)
		}
	}
	time.Sleep(time.Until(textEnd))
	g.cardTextDone(tk)
	sess.End()
	sess.Close()
	mu.Lock()
	tkt := ticket
	phase = "fill"
	mu.Unlock()
	if tkt != "" {
		time.Sleep(relay)
		start, opts, args, err := PicturesStart(&proto.PicturesRequest{Ticket: tkt, Space: "s_chat"}, time.Now())
		if err != nil {
			t.Error(err)
		} else {
			opts.User, opts.Space = "u1", start.Space
			pid := "lab-fill-" + tr.ID
			ps := g.Open(pid, opts, emit)
			if _, err := g.Action(context.Background(), &harness.TaskInfo{ID: pid, Start: &start}, PicturesActionID, &harness.Action{Name: "web.images", Call: PicturesActionID, Args: args}); err != nil {
				t.Error(err)
			}
			ps.End()
			ps.Close()
		}
	}
	// The answer's cards and their photos.
	var cards []labCard
	mu.Lock()
	defer mu.Unlock()
	for _, b := range itemsBlocks(tr.Answer, true) {
		for _, c := range parseCards(b) {
			lc := labCard{Case: tr.ID, Title: c.title}
			it, ok := tk.cards.matchItem(c.title)
			if ok {
				lc.Item = it.name
				for i, gi := range imgs {
					if gi.im.For != it.name {
						continue
					}
					ms := gi.at.Sub(textEnd).Milliseconds()
					lc.AfterMs, lc.Phase, lc.URL, lc.Caption = &ms, gi.phase, gi.im.URL, gi.im.Title
					if out != "" {
						lc.File = fmt.Sprintf("%s-%d.jpg", tr.ID, i+1)
						os.WriteFile(filepath.Join(out, lc.File), gi.im.Data, 0o644)
					}
					break
				}
			}
			cards = append(cards, lc)
		}
	}
	return cards
}

// labSearch counts and times the image searches (never the key).
type labSearch struct {
	*exa
	t  *testing.T
	id string
}

var labCredits struct {
	sync.Mutex
	fast, slow int
}

func (s *labSearch) Images(ctx context.Context, q string, n int) ([]ImageCandidate, error) {
	t0 := time.Now()
	cs, err := s.exa.Images(ctx, q, n)
	labCredits.Lock()
	labCredits.slow++
	labCredits.Unlock()
	s.t.Logf("%s   image search (descriptions) %q: %.1f s, %d candidates, err %v", s.id, q, time.Since(t0).Seconds(), len(cs), err)
	return cs, err
}

func (s *labSearch) ImagesFast(ctx context.Context, q string, n int) ([]ImageCandidate, error) {
	t0 := time.Now()
	cs, err := labFast(s.exa, ctx, q, n)
	labCredits.Lock()
	labCredits.fast++
	labCredits.Unlock()
	s.t.Logf("%s   image search (fast) %q: %.1f s, %d candidates, err %v", s.id, q, time.Since(t0).Seconds(), len(cs), err)
	return cs, err
}
