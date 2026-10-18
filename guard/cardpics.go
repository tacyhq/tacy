package guard

// Card pictures (v0.8.7): an answer's item cards get their pictures from the sources they're about, before any
// image search. A page the agent read names its own picture in its metadata (pagePictures: its one product's
// JSON-LD image, og:image, twitter:image); a search result may carry the provider's picture of that page
// (SearchResult.Thumbs: Brave's thumbnail original, never its proxy; Tavily's result images). These are candidates
// tied to that source's [n], kept here and never shown to the model; the model is told only that the source has
// one ("picture": true in its result), so it calls image_search just for the cards whose source has none.
//
// Nothing is downloaded until the answer shows which sources are cards: the guard watches the answer text as it
// streams (the model's own words choose only which of the source's candidates to try: the address always comes
// from the page's markup or the provider's result), and when an `items` block closes, each card whose source has a
// candidate gets one try, best first (the page's metadata before the search's thumbnail), at most cardPicTries
// candidates. Each download is exactly an image_search download: the same guarded client (public addresses only,
// ports 80/443, the policy's host filter), downloadImage's caps and processImage's re-encode, the same failure
// words, the run's image slots (maxImagesPerRun). On top, for a card:
//   - the source page's title (or its alt text, or the picture's own address) must name the card's item
//     (captionScore >= cardCaptionMin: a roundup's banner doesn't go on one product's card): "mismatch";
//   - no logo, icon, sprite or banner: by the address (picURLRefused), by shape (under cardMinEdge on a side, or
//     wider or taller than cardMaxAspect to 1): "logo".
//
// The picture goes to people as an "image" event under the call that brought the source (its search or its page
// read), with that source's address as its page, so the chat puts it on the card that links there (item-cards.ts
// matches a picture whose page is the card's link). Its egress is on the task's background record (like the site
// icons): no new prompt, since nothing of the person's goes out: a GET of a picture the approved search or
// page named, from the VM, never the browser. Counts only on the record and the metric (card_pictures): pictures
// shown, tried, failed by reason; never an address.

import (
	"encoding/json"
	"maps"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/tacyhq/tacy/activity"
	"github.com/tacyhq/tacy/proto"
)

const (
	picPage  = "page"  // the page's own metadata (pagePictures)
	picThumb = "thumb" // the search provider's picture of the result

	cardPicTries   = 3               // candidates tried per card
	cardPicFetches = 3               // card picture downloads at once per task
	cardMinEdge    = 100             // px, the re-encoded picture's short side
	cardMaxAspect  = 3               // long side over short side
	cardCaptionMin = 0.5             // captionScore the source must reach for the card's title
	maxCardItems   = 8               // cards per items block (the chat's MAX_CARD_ITEMS)
	cardEndWait    = 3 * time.Second // the end of a run waits at most this for card pictures still loading

	imageLogo     = "logo"     // looks like a logo, icon, sprite or banner (its address or its shape)
	imageMismatch = "mismatch" // its page doesn't name the card's item (a roundup's banner on one product's card)
)

// picCand is a picture a source names as its own: from its markup or its search result, never from model text.
type picCand struct {
	url  string
	kind string // picPage or picThumb
	alt  string // the page's alt text for it, if any: for the caption check only
}

// citedSource is a citation number's source as people saw it, and the call it was shown under.
type citedSource struct{ url, title, call string }

func thumbCands(urls []string) []picCand {
	var out []picCand
	for _, u := range urls {
		out = append(out, picCand{url: u, kind: picThumb})
	}
	return out
}

// picKey is a page's address for matching: host without www., path without a trailing slash, the query; no scheme
// or fragment.
func picKey(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return raw
	}
	k := strings.TrimPrefix(strings.ToLower(u.Host), "www.") + strings.TrimSuffix(u.EscapedPath(), "/")
	if u.RawQuery != "" {
		k += "?" + u.RawQuery
	}
	return k
}

// logoWords in a picture's address mark a site's chrome, not the item: as a whole word (icon, badge) or anywhere
// in one (sitelogo.png, favicon-32.png, sprite_sheet.webp).
var (
	logoWords = map[string]bool{"icon": true, "icons": true, "badge": true, "badges": true, "avatar": true, "placeholder": true,
		"spacer": true, "pixel": true, "blank": true, "banner": true, "banners": true}
	logoParts = []string{"logo", "favicon", "sprite", "apple-touch"}
)

// picURLRefused is why a source's picture isn't worth a try, by its address ("" = fine): not http(s), SVG, or a
// logo, icon, sprite or banner by its file's path.
func picURLRefused(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil {
		return "not an absolute http(s) URL"
	}
	path := strings.ToLower(u.Path)
	if strings.HasSuffix(path, ".svg") || strings.HasSuffix(path, ".svgz") || strings.HasSuffix(path, ".ico") {
		return imageLogo
	}
	for _, p := range logoParts {
		if strings.Contains(path, p) {
			return imageLogo
		}
	}
	for _, w := range imageWords(path) {
		if logoWords[w] {
			return imageLogo
		}
	}
	return ""
}

// addPics adds a page's picture candidates (page metadata before thumbnails, each address once) and reports
// whether the page has any now.
func (t *Tools) addPics(page string, cs ...picCand) bool {
	if page == "" {
		return false
	}
	k := picKey(page)
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.pics == nil {
		t.pics = map[string][]picCand{}
	}
	list := t.pics[k]
	for _, c := range cs {
		if !slices.ContainsFunc(list, func(o picCand) bool { return o.url == c.url }) {
			list = append(list, c)
		}
	}
	slices.SortStableFunc(list, func(a, b picCand) int { return picRank(a) - picRank(b) })
	if len(list) > 0 {
		t.pics[k] = list
	}
	return len(list) > 0
}

func picRank(c picCand) int {
	if c.kind == picPage {
		return 0
	}
	return 1
}

// citedUnder remembers each citation's source as people saw it and the call it was shown under (Action, after
// the citations were redacted).
func (t *Tools) citedUnder(cs []proto.Citation, call string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.cited == nil {
		t.cited = map[int]citedSource{}
	}
	for _, c := range cs {
		if c.URL != "" {
			t.cited[c.Index] = citedSource{url: c.URL, title: c.Title, call: call}
		}
	}
}

// cardSource is a card's source by its reference (a citation number, or the address of one of the task's
// sources) and that page's picture candidates.
func (t *Tools) cardSource(ref cardRef) (citedSource, []picCand, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	src, ok := t.cited[ref.n]
	if !ok && ref.url != "" {
		k := picKey(ref.url)
		for _, n := range slices.Sorted(maps.Keys(t.cited)) {
			if c := t.cited[n]; picKey(c.url) == k {
				src, ok = c, true
				break
			}
		}
	}
	if !ok || src.call == "" {
		return citedSource{}, nil, false
	}
	return src, slices.Clone(t.pics[picKey(src.url)]), true
}

// ---- the answer's cards ------------------------------------------------------------------------------------

// cardRef is one card of an items block: its title and its source (a citation number, or an address).
type cardRef struct {
	title string
	n     int
	url   string
}

var (
	itemsOpen   = regexp.MustCompile("(?i)^ {0,3}(`{3,}|~{3,})\\s*items\\s*$")
	fenceLine   = regexp.MustCompile("^ {0,3}(`{3,}|~{3,})")
	fenceClose  = regexp.MustCompile("^ {0,3}(`{3,}|~{3,})\\s*$")
	cardRefText = regexp.MustCompile(`^\s*[\[【［]?\s*(\d{1,3})\s*[\]】］]?\s*$`)
)

// itemsBlocks are the closed fenced blocks with the language "items" in a Markdown text, in order (the chat's
// fencedBlocks: an unclosed one isn't a block yet; another fenced block's content is skipped).
func itemsBlocks(text string) []string {
	lines := strings.Split(text, "\n")
	var out []string
	other := ""
	for i := 0; i < len(lines); i++ {
		line := lines[i]
		fence := ""
		if m := fenceLine.FindStringSubmatch(line); m != nil {
			fence = m[1]
		}
		if other != "" {
			if fence != "" && fence[0] == other[0] && len(fence) >= len(other) && strings.TrimSpace(line) == fence {
				other = ""
			}
			continue
		}
		m := itemsOpen.FindStringSubmatch(line)
		if m == nil {
			if fence != "" {
				other = fence
			}
			continue
		}
		open := m[1]
		j := i + 1
		for ; j < len(lines); j++ {
			if c := fenceClose.FindStringSubmatch(lines[j]); c != nil && c[1][0] == open[0] && len(c[1]) >= len(open) {
				break
			}
		}
		if j == len(lines) {
			return out // still open
		}
		out = append(out, strings.Join(lines[i+1:j], "\n"))
		i = j
	}
	return out
}

// parseCards reads an items block's cards: {"items": [...]} or a bare array; each card's title and source
// ("source", else "url": "[3]", "3", 3, or an address). Cards without a title or a source are left out.
func parseCards(code string) []cardRef {
	var raw any
	if json.Unmarshal([]byte(code), &raw) != nil {
		return nil
	}
	list, _ := raw.([]any)
	if m, ok := raw.(map[string]any); ok {
		list, _ = m["items"].([]any)
	}
	var out []cardRef
	for _, e := range list {
		if len(out) == maxCardItems {
			break
		}
		m, ok := e.(map[string]any)
		if !ok {
			continue
		}
		title, _ := m["title"].(string)
		if title = strings.TrimSpace(title); title == "" || len(title) > 160 {
			continue
		}
		c := cardRef{title: title}
		for _, k := range []string{"source", "url"} {
			switch v := m[k].(type) {
			case float64:
				if v >= 1 && v <= 999 && v == float64(int(v)) {
					c.n = int(v)
				}
			case string:
				if s := cardRefText.FindStringSubmatch(v); s != nil {
					c.n, _ = strconv.Atoi(s[1])
				} else if c.url == "" && httpURL(v) && len(v) <= 2000 {
					c.url = v
				}
			}
			if c.n > 0 {
				break
			}
		}
		if c.n > 0 || c.url != "" {
			out = append(out, c)
		}
	}
	return out
}

// cardPics is a task's card pictures: the answer text it watches and what came of its tries.
type cardPics struct {
	mu     sync.Mutex
	text   strings.Builder // the current model call's answer text
	blocks int             // its closed items blocks already handled
	tried  map[string]bool // sources (picKey) a card picture was tried for, once each per task
	sent   map[string]int  // pictures sent per call (their index)
	cards  int             // cards whose source had a candidate
	shown  int
	st     imageStats
	open   int // card pictures still loading
	first  time.Time
	last   time.Time
	final  bool // the run ended: the metric is made, later outcomes aren't counted
	wg     sync.WaitGroup
	slots  chan struct{}
}

func newCardPics() *cardPics {
	return &cardPics{tried: map[string]bool{}, sent: map[string]int{}, slots: make(chan struct{}, cardPicFetches)}
}

// reset starts a model call's text.
func (c *cardPics) reset() {
	c.mu.Lock()
	c.text.Reset()
	c.blocks = 0
	c.mu.Unlock()
}

// feed adds answer text and returns the cards of the items blocks that closed with it.
func (c *cardPics) feed(delta string) []cardRef {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.text.Len()+len(delta) > 256<<10 {
		return nil // an answer this long isn't cards
	}
	c.text.WriteString(delta)
	if !strings.ContainsAny(delta, "`~\n") {
		return nil
	}
	blocks := itemsBlocks(c.text.String())
	if len(blocks) <= c.blocks {
		return nil
	}
	var out []cardRef
	for _, b := range blocks[c.blocks:] {
		out = append(out, parseCards(b)...)
	}
	c.blocks = len(blocks)
	return out
}

// cardText watches a model call's answer text: the cards of each items block that closes get their sources'
// pictures.
func (g *Guard) cardText(t *task, delta string) {
	for _, c := range t.cards.feed(delta) {
		g.cardPicture(t, c)
	}
}

// cardPicture starts one card's picture: its source's candidates, best first, in the background under the task.
func (g *Guard) cardPicture(t *task, card cardRef) {
	src, cands, ok := t.tools.cardSource(card)
	if !ok || len(cands) == 0 {
		return
	}
	cp := t.cards
	key := picKey(src.url)
	cp.mu.Lock()
	if cp.final || cp.tried[key] {
		cp.mu.Unlock()
		return
	}
	cp.tried[key] = true
	cp.cards++
	cp.mu.Unlock()
	if t.tools.reserveImages(1) == 0 {
		return // the run shows the most pictures it can
	}
	t.lateMu.Lock()
	if t.ctx.Err() != nil {
		t.lateMu.Unlock()
		t.tools.returnImages(1)
		return
	}
	cp.mu.Lock()
	cp.open++
	if cp.first.IsZero() {
		cp.first = time.Now()
	}
	cp.mu.Unlock()
	cp.wg.Add(1)
	t.lateMu.Unlock()
	go func() {
		defer cp.wg.Done()
		shown := g.fetchCardPicture(t, card.title, src, cands)
		if !shown {
			t.tools.returnImages(1)
		}
		cp.mu.Lock()
		cp.open--
		cp.last = time.Now()
		cp.mu.Unlock()
	}()
}

// cardPicRefused is why a candidate isn't tried for a card, before any request ("" = try it): its address
// (imageURLRefused, picURLRefused) or a source that doesn't name the card's item.
func cardPicRefused(title string, src citedSource, c picCand) string {
	if imageURLRefused(c.url) != "" {
		return imageBlocked
	}
	if why := picURLRefused(c.url); why != "" {
		return imageLogo
	}
	if !namesItem(title, ImageCandidate{URL: c.url, Title: src.title + " " + c.alt, Source: src.url}) {
		return imageMismatch
	}
	return ""
}

// namesItem: the picture's page title, alt text or addresses name the card's item: captionScore at least
// cardCaptionMin, and every model number of the title there (as the chat's matchScore: "Q5" never takes a "Q6"
// picture).
func namesItem(title string, c ImageCandidate) bool {
	q := imageWords(title)
	if captionScore(q, c) < cardCaptionMin {
		return false
	}
	text := imageWords(c.Title + " " + c.URL + " " + c.Source)
	joined := strings.Join(text, "")
	for _, w := range q {
		if strings.ContainsAny(w, "0123456789") && !slices.Contains(text, w) && !strings.Contains(joined, w) {
			return false
		}
	}
	return true
}

// errCardShape: a picture shaped like a logo or a banner.
var errCardShape = &imageError{reason: imageLogo, msg: "shaped like a logo or banner"}

// cardShape checks a re-encoded picture's shape for a card.
func cardShape(w, h int) error {
	short, long := min(w, h), max(w, h)
	if short < cardMinEdge || long > short*cardMaxAspect {
		return errCardShape
	}
	return nil
}

// fetchCardPicture tries a card's candidates in order until one works, and sends it. Reports whether one was
// shown.
func (g *Guard) fetchCardPicture(t *task, title string, src citedSource, cands []picCand) bool {
	ctx := t.ctx
	cp := t.cards
	count := func(ms int64, reason string) bool { // false: the run ended, nothing more is counted
		cp.mu.Lock()
		defer cp.mu.Unlock()
		if cp.final {
			return false
		}
		if ms >= 0 {
			cp.st.tried++
			cp.st.fetchMs += ms
		}
		if reason != "" {
			cp.st.fail(reason)
		}
		return true
	}
	for i, c := range cands {
		if i == cardPicTries {
			break
		}
		if why := cardPicRefused(title, src, c); why != "" {
			if !count(-1, why) {
				return false
			}
			continue
		}
		select {
		case cp.slots <- struct{}{}:
		case <-ctx.Done():
			return false
		}
		var gate toolOutcome
		rel, err := t.tools.enter(ctx, "fetch", &gate)
		t0 := time.Now()
		var data, jp []byte
		var w, h int
		if err == nil {
			data, err = downloadImage(ctx, t.tools.fetcher, c.url)
			rel()
		}
		if err == nil {
			jp, w, h, err = processImage(ctx, data, t.tools.decodes)
		}
		if err == nil {
			err = cardShape(w, h)
		}
		<-cp.slots
		if ctx.Err() != nil {
			return false // the task ended while it loaded: counted as never_arrived by the metric
		}
		if err != nil {
			if !count(time.Since(t0).Milliseconds(), imageFailReason(err)) {
				return false
			}
			continue
		}
		cp.mu.Lock()
		if cp.final {
			cp.mu.Unlock()
			return false
		}
		cp.st.tried++
		cp.st.fetchMs += time.Since(t0).Milliseconds()
		cp.st.bytes += len(jp)
		cp.shown++
		cp.sent[src.call]++
		index := cp.sent[src.call]
		cp.mu.Unlock()
		// The source's title was redacted with its citation (Action); the picture's page is that source's address,
		// which is what the chat matches a card's link against.
		t.emit(proto.Event{Type: "image", ID: src.call, Image: &proto.Image{Index: index, Title: src.title, Source: src.url,
			URL: c.url, Type: "image/jpeg", Width: w, Height: h, Data: jp}})
		return true
	}
	return false
}

// wait waits at most d for the card pictures still loading.
func (c *cardPics) wait(d time.Duration) {
	done := make(chan struct{})
	go func() { c.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(d):
	}
}

// end closes the count at the run's end: the metric (nil when no card had a source picture to try) and the
// record's counts (background facts). Pictures still loading count as never_arrived.
func (c *cardPics) end(step int, f *Facts) *proto.Metric {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.final {
		return nil
	}
	c.final = true
	if c.cards == 0 {
		return nil
	}
	st := c.st
	st.reasons = maps.Clone(st.reasons)
	for range c.open {
		st.fail(imageNever)
	}
	last := c.last
	if c.open > 0 || last.IsZero() {
		last = time.Now()
	}
	f.cardPictures(&activity.Images{Shown: c.shown, Failed: st.failed, Reasons: maps.Clone(st.reasons)})
	m := &proto.Metric{Kind: "card_pictures", Step: step, Ms: max(0, last.Sub(c.first).Milliseconds()), Outcome: "ok",
		Results: c.cards, Images: c.shown, Tried: st.tried, Failed: st.failed, Bytes: st.bytes, FetchMs: st.fetchMs}
	for r, n := range st.reasons {
		m.Reasons = addReason(m.Reasons, r, n)
	}
	return m
}

// cardPictures puts the run's card pictures on the record: shown, failed by reason (FactsData.CardPictures).
func (f *Facts) cardPictures(m *activity.Images) {
	if f == nil || m.Shown == 0 && m.Failed == 0 {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.d.CardPictures = f.d.CardPictures.Add(m)
}
