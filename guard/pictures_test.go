package guard

import (
	"context"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tacyhq/tacy/harness"
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
	if SpaceFrom(ctx) != "s_chat" || taskFrom(ctx) == "" {
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

// v0.8.20: a run whose pictures setting was Ask holds its cards' lookups back and ends with a ticket; the person's
// Allow then looks those (and only those) up under a pictures task, with the VM's own names, once, for the same user.
func TestHeldBackLookupsAfterAllow(t *testing.T) {
	s, web := espressoWeb()
	g := New(Config{Search: s, Fetcher: &http.Client{Transport: web}, Icons: &http.Client{Transport: stubWeb{}}, Now: time.Now})
	var mu sync.Mutex
	var evs []proto.Event
	out := func(e proto.Event) error { mu.Lock(); evs = append(evs, e); mu.Unlock(); return nil }
	sess := g.Open("t1", TaskOptions{User: "u1", Space: "s_chat", Permissions: map[string]string{"web.images": "ask"}}, out)
	tk := g.task(&harness.TaskInfo{ID: "t1"})
	read := &readerResult{}
	for _, n := range []string{"Profitec GO", "Breville Barista Express BES870XL", "Gaggia Classic Pro"} {
		read.items = append(read.items, keptItem{name: n})
	}
	tk.noteItems("c1", read)
	g.cardText(tk, espressoCards)
	g.cardTextDone(tk)
	sess.End()
	sess.Close()
	if q := s.queries(); len(q) != 0 {
		t.Fatalf("looked up before the person allowed it: %q", q)
	}
	ticket := ""
	for _, e := range evs {
		if e.Type == "pictures" {
			ticket = e.Pictures
		}
	}
	if len(ticket) != 32 {
		t.Fatalf("no ticket at the run's end: %+v", evs)
	}
	run := func(user, ticket string) (*harness.ActionResult, []*proto.Image) {
		start, opts, args, err := PicturesStart(&proto.PicturesRequest{Ticket: ticket}, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		opts.User, opts.Space = user, start.Space
		var imgs []*proto.Image
		id := "p-" + user + ticket[:4]
		ps := g.Open(id, opts, func(e proto.Event) error {
			if e.Type == "image" {
				if e.ID != "c1" {
					t.Errorf("picture under %q", e.ID)
				}
				imgs = append(imgs, e.Image)
			}
			return nil
		})
		ti := &harness.TaskInfo{ID: id, Start: &start}
		res, err := g.Action(context.Background(), ti, PicturesActionID, &harness.Action{Name: "web.images", Call: PicturesActionID, Args: args})
		if err != nil {
			t.Fatal(err)
		}
		ps.End()
		ps.Close()
		return res, imgs
	}
	// Another user tag can't use it (and doesn't use it up).
	if res, imgs := run("u2", ticket); res.Status != harness.ActionFailed || len(imgs) != 0 {
		t.Fatalf("another user: %+v %d", res, len(imgs))
	}
	res, imgs := run("u1", ticket)
	if res.Status != harness.ActionDone || len(imgs) != 3 {
		t.Fatalf("allowed: %+v, %d pictures", res, len(imgs))
	}
	asked := s.queries()
	slices.Sort(asked)
	if !slices.Equal(asked, []string{"Breville Barista Express BES870XL", "Gaggia Classic Pro", "Profitec GO"}) || s.badCtx {
		t.Fatalf("queries %q (ctx ok: %v)", asked, !s.badCtx)
	}
	// Once only.
	if res, _ := run("u1", ticket); res.Status != harness.ActionFailed {
		t.Fatalf("a second use: %+v", res)
	}
	// Photos off (Never) hold the lookups back too, and nothing goes out.
	s2, web2 := espressoWeb()
	g2 := New(Config{Search: s2, Fetcher: &http.Client{Transport: web2}, Icons: &http.Client{Transport: stubWeb{}}, Now: time.Now})
	var got []proto.Event
	sess2 := g2.Open("t2", TaskOptions{User: "u1", Space: "s_chat", Permissions: map[string]string{"web.images": "never"}}, func(e proto.Event) error { got = append(got, e); return nil })
	tk2 := g2.task(&harness.TaskInfo{ID: "t2"})
	tk2.noteItems("c1", read)
	g2.cardText(tk2, espressoCards)
	g2.cardTextDone(tk2)
	sess2.End()
	sess2.Close()
	if q := s2.queries(); len(q) != 0 || !slices.ContainsFunc(got, func(e proto.Event) bool { return e.Type == "pictures" }) {
		t.Fatalf("photos off: queries %q, ticket %v", q, slices.ContainsFunc(got, func(e proto.Event) bool { return e.Type == "pictures" }))
	}
}

// slowLookups holds the image searches for some names until released (or the lookup's context ends): lookups still
// loading when a run ends.
type slowLookups struct {
	*lookupSearch
	slow    map[string]bool
	release chan struct{}
}

func (s *slowLookups) Images(ctx context.Context, q string, n int) ([]ImageCandidate, error) {
	if s.slow[q] {
		select {
		case <-s.release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return s.lookupSearch.Images(ctx, q, n)
}

// v0.8.22: with pictures allowed, the lookups still loading when the run ends (running shoes: 2 of 4 shown) go into
// the run's ticket, and the pictures task right after the answer fills those cards: only those items, with the VM's
// own names, once, for the same user.
func TestLateLookupsFilledAfterTheAnswer(t *testing.T) {
	defer func(d time.Duration) { cardLookupWait = d }(cardLookupWait)
	cardLookupWait = 300 * time.Millisecond
	base, web := espressoWeb()
	s := &slowLookups{lookupSearch: base, slow: map[string]bool{"Breville Barista Express BES870XL": true, "Gaggia Classic Pro": true}, release: make(chan struct{})}
	g := New(Config{Search: s, Fetcher: &http.Client{Transport: web}, Icons: &http.Client{Transport: stubWeb{}}, Now: time.Now})
	var mu sync.Mutex
	var evs []proto.Event
	sess := g.Open("t1", TaskOptions{User: "u1", Space: "s_chat", Permissions: map[string]string{"web.images": "always"}}, func(e proto.Event) error {
		mu.Lock()
		evs = append(evs, e)
		mu.Unlock()
		return nil
	})
	tk := g.task(&harness.TaskInfo{ID: "t1"})
	read := &readerResult{}
	for _, n := range []string{"Profitec GO", "Breville Barista Express BES870XL", "Gaggia Classic Pro"} {
		read.items = append(read.items, keptItem{name: n})
	}
	tk.noteItems("c1", read)
	g.cardText(tk, espressoCards)
	g.cardTextDone(tk)
	sess.End()
	sess.Close()
	mu.Lock()
	ticket, shown := "", []string{}
	for _, e := range evs {
		switch e.Type {
		case "pictures":
			ticket = e.Pictures
		case "image":
			shown = append(shown, e.Image.For)
		}
	}
	mu.Unlock()
	if !slices.Equal(shown, []string{"Profitec GO"}) || len(ticket) != 32 {
		t.Fatalf("in the run: shown %q, ticket %q", shown, ticket)
	}
	close(s.release) // the provider answers now
	run := func(user, prev string) (*harness.ActionResult, []string) {
		start, opts, args, err := PicturesStart(&proto.PicturesRequest{Ticket: ticket}, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		opts.User, opts.PrevUser, opts.Space = user, prev, start.Space
		var got []string
		id := "p-" + user
		ps := g.Open(id, opts, func(e proto.Event) error {
			if e.Type == "image" {
				if e.ID != "c1" {
					t.Errorf("picture under %q", e.ID)
				}
				got = append(got, e.Image.For)
			}
			return nil
		})
		res, err := g.Action(context.Background(), &harness.TaskInfo{ID: id, Start: &start}, PicturesActionID, &harness.Action{Name: "web.images", Call: PicturesActionID, Args: args})
		if err != nil {
			t.Fatal(err)
		}
		ps.End()
		ps.Close()
		slices.Sort(got)
		return res, got
	}
	if res, got := run("u2", "u3"); res.Status != harness.ActionFailed || len(got) != 0 {
		t.Fatalf("another user: %+v %q", res, got)
	}
	before := len(s.queries())
	res, got := run("u1", "")
	if res.Status != harness.ActionDone || !slices.Equal(got, []string{"Breville Barista Express BES870XL", "Gaggia Classic Pro"}) {
		t.Fatalf("after the answer: %+v, %q", res, got)
	}
	asked := s.queries()[before:]
	slices.Sort(asked)
	if !slices.Equal(asked, []string{"Breville Barista Express BES870XL", "Gaggia Classic Pro"}) || s.badCtx {
		t.Fatalf("after the answer, queries %q (ctx ok: %v)", asked, !s.badCtx)
	}
	if res, got := run("u1", ""); res.Status != harness.ActionFailed || len(got) != 0 {
		t.Fatalf("a second use: %+v %q", res, got)
	}
}

// v0.8.22: a ticket from a run before midnight UTC is good with the same person's previous-day tag (the relay's
// X-Agent-User-Prev) within its 30 minutes; never with another person's tags, and never once it's stale.
func TestTicketAcrossMidnight(t *testing.T) {
	now := time.Date(2026, 10, 20, 23, 50, 0, 0, time.UTC)
	g := New(Config{Search: &lookupSearch{}, Now: func() time.Time { return now }})
	hold := func() string {
		tk := g.open("t-"+now.Format("150405.000000000"), TaskOptions{User: "day1-u1", Space: "s_chat", Permissions: map[string]string{"web.images": "ask"}}, func(proto.Event) error { return nil })
		tk.cards.deferItem(taskItem{name: "Profitec GO", call: "c1"})
		return g.holdPictures(tk)
	}
	tk := hold()
	now = now.Add(20 * time.Minute) // 00:10 the next day: the relay's tag is day2's now
	if _, err := g.takePictures(tk, "day2-u2", "day1-u2", "s_chat"); err == nil {
		t.Fatal("another person's tags took the ticket")
	}
	if _, err := g.takePictures(tk, "day2-u1", "", "s_chat"); err == nil {
		t.Fatal("the new day's tag alone took a ticket from the day before")
	}
	if _, err := g.takePictures(tk, "day2-u1", "day1-u1", "s_other"); err == nil {
		t.Fatal("another space took the ticket")
	}
	items, err := g.takePictures(tk, "day2-u1", "day1-u1", "s_chat")
	if err != nil || len(items) != 1 || items[0].name != "Profitec GO" {
		t.Fatalf("across midnight: %v %+v", err, items)
	}
	if _, err := g.takePictures(tk, "day2-u1", "day1-u1", "s_chat"); err == nil {
		t.Fatal("a ticket used twice")
	}
	// Stale: 31 minutes after the run, with the right tags, it's refused.
	now = time.Date(2026, 10, 20, 23, 50, 0, 0, time.UTC)
	stale := hold()
	now = now.Add(31 * time.Minute)
	if _, err := g.takePictures(stale, "day2-u1", "day1-u1", "s_chat"); err == nil {
		t.Fatal("a stale ticket was taken")
	}
	if _, err := g.takePictures(stale, "day1-u1", "", "s_chat"); err == nil {
		t.Fatal("a stale ticket was taken with the run's own tag")
	}
}
