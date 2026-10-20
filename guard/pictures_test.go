package guard

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

// lookupSearch is an image provider that records every query and answers from a table (by query).
type lookupSearch struct {
	fakeSearch
	mu      sync.Mutex
	asked   []string
	answers map[string][]ImageCandidate
	badCtx  bool
}

func (s *lookupSearch) Images(ctx context.Context, q string, _ int) ([]ImageCandidate, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	// The vault leases the provider's key for the task's space only (VaultLease): a lookup carries both.
	if SpaceFrom(ctx) != "s_chat" || taskFrom(ctx) != "t1" {
		s.badCtx = true
	}
	s.asked = append(s.asked, q)
	return s.answers[q], nil
}

func (s *lookupSearch) queries() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.asked)
}

// lookupRun opens a task with the given pictures setting, gives it reader items under call c1, feeds it the
// answer text and waits for its card pictures. Returns the images shown.
func lookupRun(t *testing.T, s *lookupSearch, web stubWeb, setting string, items []string, answer string) []*proto.Image {
	t.Helper()
	g := New(Config{Search: s, Fetcher: &http.Client{Transport: web}, Icons: &http.Client{Transport: stubWeb{}}, Now: time.Now})
	var mu sync.Mutex
	var imgs []*proto.Image
	out := func(e proto.Event) error {
		mu.Lock()
		defer mu.Unlock()
		if e.Type == "image" {
			if e.ID != "c1" {
				t.Errorf("picture under %q, want the item's call c1", e.ID)
			}
			imgs = append(imgs, e.Image)
		}
		return nil
	}
	tk := g.open("t1", TaskOptions{Space: "s_chat", Permissions: map[string]string{"web.search": "always", "web.images": setting}}, out)
	read := &readerResult{}
	for _, n := range items {
		read.items = append(read.items, keptItem{name: n})
	}
	tk.noteItems("c1", read)
	g.cardText(tk, answer)
	g.cardTextDone(tk)
	tk.cards.wait(5 * time.Second)
	mu.Lock()
	defer mu.Unlock()
	return slices.Clone(imgs)
}

const espressoCards = "Two picks [1][2]:\n```items\n" +
	`{"items":[{"title":"Profitec GO Espresso Machine","source":"[1]"},{"title":"Breville Barista Express","source":"[2]"},` +
	`{"title":"Gaggia Classic Pro for Jane Doe at 12 Elm Street, card 4111 1111 1111 1111","source":"[2]"},` +
	`{"title":"my password is hunter2","source":"[1]"}]}` + "\n```\nDone."

func espressoWeb() (*lookupSearch, stubWeb) {
	s := &lookupSearch{answers: map[string][]ImageCandidate{
		"Profitec GO": {
			{URL: "https://cdn.example/best-espresso-2026.jpg", Title: "The 4 Best Home Espresso Machines of 2026", Source: "https://reviews.example/best"},
			{URL: "https://shop.example/profitec-go-black.jpg", Title: "Profitec GO Espresso Machine Black", Source: "https://shop.example/profitec-go"},
		},
		"Breville Barista Express BES870XL": {
			{URL: "https://cdn.example/barista-person.jpg", Title: "A woman using the Breville Barista Express", Source: "https://blog.example/a"},
			{URL: "https://cdn.example/breville-logo.png", Title: "Breville", Source: "https://breville.example/"},
			{URL: "https://img.breville.example/bes870xl.jpg", Title: "Breville Barista Express espresso machine, brushed steel", Source: "https://breville.example/bes870xl"},
		},
		"Gaggia Classic Pro": {{URL: "https://img.example/gaggia.jpg", Title: "Gaggia Classic Pro", Source: "https://gaggia.example/"}},
	}}
	web := stubWeb{
		"https://cdn.example/best-espresso-2026.jpg": pngWH(600, 400),
		"https://shop.example/profitec-go-black.jpg": pngWH(600, 600),
		"https://cdn.example/barista-person.jpg":     pngWH(600, 600),
		"https://img.breville.example/bes870xl.jpg":  pngWH(500, 500),
		"https://img.example/gaggia.jpg":             pngWH(500, 500),
		"https://cdn.example/breville-logo.png":      pngWH(500, 500),
	}
	return s, web
}

// The exfiltration guard: a card is looked up only as one of the run's checked reader items, and what goes out is
// the reader's name, never the card's title. A title carrying chat text (a name, an address, a card number) goes
// out only as the item it names; one that names no item never goes out at all.
func TestCardLookupsSendOnlyReaderNames(t *testing.T) {
	s, web := espressoWeb()
	items := []string{"Profitec GO", "Breville Barista Express BES870XL", "Gaggia Classic Pro"}
	imgs := lookupRun(t, s, web, "always", items, espressoCards)
	if s.badCtx {
		t.Fatal("a lookup's image search ran without the task's id and space (the vault refuses its key lease)")
	}
	asked := s.queries()
	slices.Sort(asked)
	want := []string{"Breville Barista Express BES870XL", "Gaggia Classic Pro", "Profitec GO"}
	if !slices.Equal(asked, want) {
		t.Fatalf("image queries %q, want exactly the reader's names %q", asked, want)
	}
	for _, q := range asked {
		for _, leak := range []string{"Jane", "Elm", "4111", "hunter2", "password", "Machine"} {
			if strings.Contains(q, leak) {
				t.Fatalf("query %q carries the card's text %q", q, leak)
			}
		}
	}
	// Right pictures: the product shots, not the roundup's banner, the photo of a person or the logo.
	got := map[string]string{}
	for _, im := range imgs {
		got[im.For] = im.URL
		if len(im.Data) == 0 || im.Type != "image/jpeg" {
			t.Fatalf("image %+v", im)
		}
	}
	if got["Profitec GO"] != "https://shop.example/profitec-go-black.jpg" || got["Breville Barista Express BES870XL"] != "https://img.breville.example/bes870xl.jpg" ||
		got["Gaggia Classic Pro"] != "https://img.example/gaggia.jpg" || len(imgs) != 3 {
		t.Fatalf("pictures %v", got)
	}
}

// Pictures are one setting (web.images): on Ask or Never there's no lookup at all, and no prompt.
func TestCardLookupsNeedThePicturesSetting(t *testing.T) {
	for _, setting := range []string{"ask", "never", ""} {
		s, web := espressoWeb()
		imgs := lookupRun(t, s, web, setting, []string{"Profitec GO"}, espressoCards)
		if q := s.queries(); len(q) != 0 || len(imgs) != 0 {
			t.Fatalf("setting %q: queries %q, %d pictures", setting, q, len(imgs))
		}
	}
}

// No reader items (the run read nothing, or nothing it read named products): no lookup, whatever the titles say.
func TestCardLookupsWithoutItems(t *testing.T) {
	s, web := espressoWeb()
	lookupRun(t, s, web, "always", nil, espressoCards)
	if q := s.queries(); len(q) != 0 {
		t.Fatalf("queries %q", q)
	}
}

// At most maxCardLookups image searches an answer.
func TestCardLookupsCapped(t *testing.T) {
	var items []string
	var cards []string
	for i := range 9 {
		n := "Shoe Model " + string(rune('A'+i)) + "9"
		items = append(items, n)
		cards = append(cards, `{"title":"`+n+`","source":"[1]"}`)
	}
	s := &lookupSearch{answers: map[string][]ImageCandidate{}}
	lookupRun(t, s, stubWeb{}, "always", items, "```items\n{\"items\":["+strings.Join(cards, ",")+"]}\n```")
	if q := s.queries(); len(q) != maxCardLookups {
		t.Fatalf("%d lookups, want %d", len(q), maxCardLookups)
	}
}

func TestMatchItem(t *testing.T) {
	c := newCardPics()
	for _, n := range []string{"Profitec GO", "Breville Barista Express BES870XL", "ASICS Superblast 3", "Pro", "Brooks Ghost 18"} {
		c.items[itemKey(n)] = taskItem{name: n, call: "c1"}
	}
	for title, want := range map[string]string{
		"Asics Superblast 3":                         "ASICS Superblast 3",
		"Profitec GO Espresso Machine":               "Profitec GO",
		"Breville Barista Express":                   "Breville Barista Express BES870XL",
		"Brooks Ghost 18 / 17":                       "Brooks Ghost 18",
		"Profitec GO, which Jane at 12 Elm St loves": "Profitec GO",
		"Superblast":                                 "", // one word, no digit: too little to name an item
		"Gaggia Pro":                                 "", // contains the item "Pro": one word, no digit
		"my password is hunter2":                     "",
		"ASICS Superblast 2":                         "",
	} {
		it, ok := c.matchItem(title)
		if ok != (want != "") || it.name != want {
			t.Errorf("%q matched %q (%v), want %q", title, it.name, ok, want)
		}
	}
}

func TestPictureRefused(t *testing.T) {
	for _, c := range []struct {
		name, title, url, want string
	}{
		{"ASICS Superblast 3", "SUPERBLAST 3 | Unisex | White/Orange Glow | Running Shoes", "https://images.asics.example/1013A177_101.jpg", ""},
		{"ASICS Superblast 3", "ASICS Superblast 2 review", "https://cdn.example/sb2.jpg", imageNumber},
		{"ASICS Superblast 3", "The ASICS Superblast running shoe in blue", "https://cdn.example/sb.jpg", ""},
		{"Breville Barista Express BES870XL", "Breville Barista Express espresso machine", "https://cdn.example/b.jpg", ""},
		{"Profitec GO", "The 4 Best Home Espresso Machines of 2026", "https://cdn.example/hero.jpg", imageHero},
		{"Profitec GO", "A collage of espresso machines including the Profitec GO", "https://cdn.example/c.jpg", imageHero},
		{"Mizuno Wave Rider 30", "A man wearing Mizuno Wave Rider 30 on a trail", "https://cdn.example/m.jpg", imageHero},
		{"Breville Barista Express", "Breville Barista Express", "https://cdn.example/breville-logo.png", imageLogo},
		{"Gaggia Classic Evo Pro", "Rancilio Silvia espresso machine", "https://cdn.example/r.jpg", imageMismatch},
		// Lab, 2026-10-20: a review page's author headshot, its page named for the item.
		{"Puma Deviate Pure Nitro", "Carlos Sánchez", "https://cdn.runrepeat.com/storage/images/experts/carlos-sanchez-sm.jpg", imageHero},
		{"Puma Deviate Pure Nitro", "Carlos Sánchez", "https://cdn.example/carlos-sanchez-sm.jpg", imageMismatch},
	} {
		if got := pictureRefused(c.name, ImageCandidate{URL: c.url, Title: c.title}); got != c.want {
			t.Errorf("%q / %q: %q, want %q", c.name, c.title, got, c.want)
		}
	}
}

// Live on v0.8.17 (2026-10-20): Wirecutter's banner went on the Profitec GO's card, its title's "Espresso Machines"
// half the card's words. A roundup's own picture now needs its alt text or address to name the item closely.
func TestRoundupBannerNotACardPicture(t *testing.T) {
	src := citedSource{url: "https://www.nytimes.com/wirecutter/reviews/best-espresso-machine-grinder-and-accessories-for-beginners/",
		title: "The 4 Best Home Espresso Machines of 2026 | Reviews by Wirecutter"}
	banner := picCand{url: "https://cdn.thewirecutter.com/wp-content/media/2024/11/espressomachines-2048px-9378-2x1-1.jpg", kind: picThumb}
	if why := cardPicRefused("Profitec GO Espresso Machine", src, banner, cardCaptionMin); why != imageMismatch {
		t.Fatalf("banner: %q", why)
	}
	named := picCand{url: "https://cdn.thewirecutter.com/wp-content/media/2025/profitec-go-espresso.jpg", kind: picPage}
	if why := cardPicRefused("Profitec GO Espresso Machine", src, named, cardCaptionMin); why != "" {
		t.Fatalf("a roundup's picture named for the item: %q", why)
	}
}
