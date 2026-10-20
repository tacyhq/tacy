package guard

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tacyhq/tacy/proto"
)

// TestLiveCardLookups is the card lookups' lab (not run by default): real answers and their reader's checked items
// (saved from live runs, CARD_LOOKUP_CASES), the guard's production lookup path (matchItem, the image provider,
// pictureRefused, the guarded download, re-encode, cardShape) against the real image search, with keys from the
// environment (TAVILY_API_KEY). The pictures land in CARD_LOOKUP_OUT for a look.
//
//	set -a; . ../../.env; set +a
//	CARD_LOOKUP_CASES=…/live-cases.json CARD_LOOKUP_OUT=…/thumbs go test ./guard -run TestLiveCardLookups -v
func TestLiveCardLookups(t *testing.T) {
	path, out := os.Getenv("CARD_LOOKUP_CASES"), os.Getenv("CARD_LOOKUP_OUT")
	if path == "" || os.Getenv("TAVILY_API_KEY") == "" {
		t.Skip("lab only: CARD_LOOKUP_CASES and TAVILY_API_KEY")
	}
	var f struct {
		Cases []struct {
			ID     string   `json:"id"`
			Items  []string `json:"items"`
			Answer string   `json:"answer"`
		} `json:"cases"`
	}
	b, err := os.ReadFile(path)
	if err != nil || json.Unmarshal(b, &f) != nil {
		t.Fatalf("cases: %v", err)
	}
	keys := StaticKeys(os.Getenv)
	search := NewSearch("exa", func(n string) bool { return os.Getenv(n) != "" }, keys)
	fetcher := NewFetcher(false)
	lim := DefaultLimits
	for _, c := range f.Cases {
		g := New(Config{Search: search, Fetcher: fetcher, Icons: fetcher, Limits: &lim, Now: time.Now})
		var mu sync.Mutex
		var imgs []*proto.Image
		emit := func(e proto.Event) error {
			if e.Type == "image" {
				mu.Lock()
				imgs = append(imgs, e.Image)
				mu.Unlock()
			}
			return nil
		}
		t0 := time.Now()
		tk := g.open("lab-"+c.ID, TaskOptions{Permissions: map[string]string{"web.images": "always"}}, emit)
		read := &readerResult{}
		for _, n := range c.Items {
			read.items = append(read.items, keptItem{name: n})
		}
		tk.noteItems("c1", read)
		g.cardText(tk, c.Answer)
		g.cardTextDone(tk)
		tk.cards.wait(cardLookupWait + 10*time.Second)
		m := tk.cards.end(0, tk.background)
		cards := parseCardsOf(c.Answer)
		t.Logf("== %s: %d cards, %d pictures in %.1f s; metric %+v", c.ID, len(cards), len(imgs), time.Since(t0).Seconds(), m)
		for _, title := range cards {
			it, ok := tk.cards.matchItem(title)
			line := fmt.Sprintf("card %q -> item %q (%v)", title, it.name, ok)
			for i, im := range imgs {
				if im.For == it.name && ok {
					line += fmt.Sprintf(" -> %dx%d %q %s (page %s)", im.Width, im.Height, im.Title, im.URL, im.Source)
					if out != "" {
						os.MkdirAll(out, 0o755)
						os.WriteFile(filepath.Join(out, fmt.Sprintf("%s-%d-%s.jpg", c.ID, i+1, strings.ReplaceAll(itemKey(it.name), " ", "-"))), im.Data, 0o644)
					}
				}
			}
			t.Log(line)
		}
		g.close(tk)
	}
}

// parseCardsOf is the titles of an answer's items blocks.
func parseCardsOf(answer string) []string {
	var out []string
	for _, b := range itemsBlocks(answer, true) {
		for _, c := range parseCards(b) {
			out = append(out, c.title)
		}
	}
	return out
}
