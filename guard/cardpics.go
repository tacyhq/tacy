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
//     (namesItem: half its words, all its model numbers; a roundup's banner doesn't go on one product's card): "mismatch";
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
	"errors"
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
	cardCaptionMin = 0.5             // share of the card title's words its source must name (namesItem)
	cardOtherMin   = 0.75            // the same for another source of the task (the chat's MATCH_THRESHOLD)
	cardOthers     = 3               // other sources tried for a card whose own gave none
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
		"spacer": true, "banner": true, "banners": true} // not "pixel": a Google Pixel's photo is named so
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

// listTitleRe marks a page about many items (a roundup, a comparison, a review list, deals): its picture is a
// banner, not one item's.
var listTitleRe = regexp.MustCompile(`(?i)\b(best|top \d+|\d+ (best|top|great|good)|vs\.?|versus|reviews|compared|comparison|guide|deals|alternatives|picks|ranked|ranking)\b`)

// pictureFlag is what the model is told about a source: "picture": true when it has a picture candidate and looks
// like one item's own page (not a list), so a card citing it needs no image search. The candidates are kept either
// way: a card may still get them (namesItem decides), and another card may get them as another source.
func (t *Tools) pictureFlag(page, title string, cs ...picCand) bool {
	return t.addPics(page, cs...) && !listTitleRe.MatchString(title)
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

// otherSources are the task's other sources whose own title names the card's item closely (namesItem at
// cardOtherMin: a product's own page or result next to the roundup the card cites), with picture candidates, in
// citation order, at most cardOthers; never the page skip (the card's own).
func (t *Tools) otherSources(title, skip string) []cardTry {
	t.mu.Lock()
	defer t.mu.Unlock()
	var out []cardTry
	seen := map[string]bool{skip: true}
	for _, n := range slices.Sorted(maps.Keys(t.cited)) {
		src := t.cited[n]
		k := picKey(src.url)
		if seen[k] || src.call == "" || len(t.pics[k]) == 0 || !namesItem(title, ImageCandidate{Title: src.title, Source: src.url}, cardOtherMin) {
			continue
		}
		seen[k] = true
		for _, c := range t.pics[k] {
			out = append(out, cardTry{src: src, c: c, other: true})
		}
		if len(seen) > cardOthers {
			break
		}
	}
	return out
}

// cardTry is one candidate for a card: from the card's own source, or (other) from another source naming its item.
type cardTry struct {
	src   citedSource
	c     picCand
	other bool
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
// fencedBlocks; another fenced block's content is skipped). An unclosed one isn't a block yet, unless final: the text
// is all there is, and the chat's Markdown renders a block the answer never closed as running to its end.
func itemsBlocks(text string, final bool) []string {
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
			if final {
				out = append(out, strings.Join(lines[i+1:], "\n"))
			}
			return out
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
	tried  map[string]bool // cards (their source's picKey, else their title) tried, once each per task
	taken  map[string]bool // picture addresses already sent for a card
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
	// pre: downloads a plain chat's search started while its reader read (prefetchResult), by address.
	pre map[string]*picFetch
	// items: the run's checked reader items, by itemKey, for lookups (pictures.go); lookups: cards looked up (at
	// most maxCardLookups), lookedUp: image searches made for them.
	items    map[string]taskItem
	lookups  int
	lookedUp int
	// deferred: cards that named a reader item but weren't looked up because the run's pictures setting was Ask
	// (pictures.go holdPictures), at most maxCardLookups
	deferred []taskItem
}

func newCardPics() *cardPics {
	return &cardPics{tried: map[string]bool{}, taken: map[string]bool{}, sent: map[string]int{}, slots: make(chan struct{}, cardPicFetches),
		pre: map[string]*picFetch{}, items: map[string]taskItem{}}
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
	return c.newCards(false)
}

// done is the end of a model call's text: an items block it left open counts too.
func (c *cardPics) done() []cardRef {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.newCards(true)
}

// newCards are the cards of the blocks not handled yet (c.mu held).
func (c *cardPics) newCards(final bool) []cardRef {
	blocks := itemsBlocks(c.text.String(), final)
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
		g.cardPicture(t, c, false)
	}
}

// cardTextDone: the model call's answer ended; a block it left open counts now.
func (g *Guard) cardTextDone(t *task) {
	for _, c := range t.cards.done() {
		g.cardPicture(t, c, false)
	}
}

// cardPicture starts one card's picture in the background under the task: its own source's candidates, best
// first, then (unless ownOnly) those of other sources that name its item closely (otherSources).
func (g *Guard) cardPicture(t *task, card cardRef, ownOnly bool) {
	var tries []cardTry
	own := ""
	if src, cands, ok := t.tools.cardSource(card); ok {
		own = picKey(src.url)
		for _, c := range cands {
			tries = append(tries, cardTry{src: src, c: c})
		}
	}
	if !ownOnly {
		tries = append(tries, t.tools.otherSources(card.title, own)...)
	}
	key := own + "|" + strings.ToLower(card.title) // a card once (two cards may cite one roundup)
	// No picture from the sources: looked up (pictures.go), when pictures are allowed and the title names one of
	// the run's reader items. Never for a plain chat's search (resultPictures: ownOnly).
	var lookup, later *taskItem
	if !ownOnly && t.opts.Via != ViaSearch {
		if it, ok := t.cards.matchItem(card.title); ok {
			switch {
			case g.lookupAllowed(t):
				lookup = &it
			case g.lookupAskable(t):
				later = &it // held back until the person allows pictures (pictures.go holdPictures)
			}
		}
	}
	if len(tries) == 0 && lookup == nil {
		if later != nil {
			t.cards.deferItem(*later)
		}
		return
	}
	cp := t.cards
	cp.mu.Lock()
	if cp.final || cp.tried[key] {
		cp.mu.Unlock()
		return
	}
	cp.tried[key] = true
	cp.cards++
	if lookup != nil {
		if cp.lookups >= maxCardLookups {
			lookup = nil
		} else {
			cp.lookups++
		}
	}
	cp.mu.Unlock()
	if len(tries) == 0 && lookup == nil {
		return
	}
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
		shown := len(tries) > 0 && g.fetchCardPicture(t, card.title, tries)
		if !shown && lookup != nil && t.ctx.Err() == nil {
			shown = g.lookupCardPicture(t, *lookup)
		}
		if !shown && later != nil {
			cp.deferItem(*later)
		}
		if !shown {
			t.tools.returnImages(1)
		}
		cp.mu.Lock()
		cp.open--
		cp.last = time.Now()
		cp.mu.Unlock()
	}()
}

// ---- a plain chat's search ------------------------------------------------------------------------------------

// resultPictures gives a plain chat's search (searchtask.go, v0.8.13) its results' own pictures for the chat's
// product cards. The VM doesn't see that chat's answer (its model runs outside the VM), so the cards aren't known
// here: each result whose own picture names one of the items the reader found in it (checked against the result:
// reader.go checkItems) gets that picture, tried as a card with that item's name. Everything else is agent mode's
// card picture, unchanged: the candidates are the provider's picture of the result (SearchResult.Thumbs, never
// shown to the model), the same checks before any request (cardPicRefused: the address, a logo or icon by its path,
// and the result's title or the picture's address naming the item, so a roundup's banner never goes on one
// product's card), the same guarded download in the VM (never the person's browser), re-encode and shape check
// (logos and banners), the same image slots and per-task caps, sent as an "image" event under the search with the
// result's address as its page (the chat puts it on the card that links there), its egress on the task's
// background record and its counts in the card_pictures metric. At most one picture a result; the end of the
// search waits for them as for agent mode's (cardEndWait). cites are the results' citations, in order.
//
// Stricter than a card's own check, since the card isn't known and the chat puts the picture on whichever card
// links to the result (v0.8.15, from the audit on v0.8.14's throwaway: a "6 Best Quiet Keyboards" banner passed for
// the item "Lofree Flow 2" on the "2" in its file name): only a result that is one item's own page (not a list or a
// roundup by its title, as the model's "picture": true says, pictureFlag) and whose title or addresses name the item
// as closely as another source must for a card (cardOtherMin, 0.75).
func (g *Guard) resultPictures(t *task, read *readerResult, cites []proto.Citation) {
	for i, c := range cites {
		var names []string
		for _, it := range read.resultItems(i) {
			names = append(names, it.name)
		}
		src, cands, ok := t.tools.cardSource(cardRef{n: c.Index})
		if !ok || len(cands) == 0 || listTitleRe.MatchString(src.title) {
			continue
		}
		for _, name := range names {
			if slices.ContainsFunc(cands, func(cd picCand) bool { return cardPicRefused(name, src, cd, cardOtherMin) == "" }) {
				g.cardPicture(t, cardRef{title: name, n: c.Index}, true)
				break
			}
		}
	}
}

// cardPicRefused is why a candidate isn't tried for a card, before any request ("" = try it): its address
// (imageURLRefused, picURLRefused) or a source that doesn't name the card's item (at min, namesItem).
func cardPicRefused(title string, src citedSource, c picCand, min float64) string {
	if imageURLRefused(c.url) != "" {
		return imageBlocked
	}
	if why := picURLRefused(c.url); why != "" {
		return imageLogo
	}
	// A roundup's or a review list's own picture is its banner (v0.8.18: "The 4 Best Home Espresso Machines" went
	// on the Profitec GO's card, its title's "espresso machine" half the card's words): only its alt text or the
	// picture's own address may name the item, closely.
	if listTitleRe.MatchString(src.title) {
		if !namesItem(title, ImageCandidate{URL: c.url, Title: c.alt}, cardOtherMin) {
			return imageMismatch
		}
		return ""
	}
	if !namesItem(title, ImageCandidate{URL: c.url, Title: src.title + " " + c.alt, Source: src.url}, min) {
		return imageMismatch
	}
	return ""
}

// namesItem: the picture's page title, alt text or addresses name the card's item: at least cardCaptionMin of the
// title's words there (numbers, as in model names, count double; "q6max" in an address counts for "Q6 Max"), and
// every model number of the title there (as the chat's matchScore: "Q5" never takes a "Q6" picture). Unlike
// captionScore (image_search's ranking) no penalty for logo-like words inside other words: "Q6-Max-Iconic.jpg" is
// a product shot; logos are refused by whole words in the address (picURLRefused) and by shape.
func namesItem(title string, c ImageCandidate, min float64) bool {
	q := imageWords(title)
	if len(q) == 0 {
		return false
	}
	text := imageWords(c.Title + " " + c.URL + " " + c.Source)
	joined := strings.Join(text, "")
	if whole := strings.Join(q, ""); len(whole) >= 4 && strings.Contains(joined, whole) {
		return true
	}
	var got, total float64
	for _, w := range q {
		weight := 1.0
		if strings.ContainsAny(w, "0123456789") {
			weight = 2
		}
		total += weight
		found := slices.Contains(text, w) || len(w) >= 3 && strings.Contains(joined, w)
		if found {
			got += weight
		} else if weight == 2 {
			return false
		}
	}
	return got/total >= min
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

// fetchCardPicture tries a card's candidates in order until one works (at most cardPicTries downloads), and sends
// it under its source's call. Reports whether one was shown. Another source's candidate that doesn't fit isn't
// counted as a failure: it was only a maybe.
func (g *Guard) fetchCardPicture(t *task, title string, tries []cardTry) bool {
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
	downloads := 0
	for _, try := range tries {
		if downloads == cardPicTries {
			break
		}
		src, c := try.src, try.c
		min := cardCaptionMin
		if try.other {
			min = cardOtherMin
		}
		cp.mu.Lock()
		taken := cp.taken[c.url]
		cp.mu.Unlock()
		if taken {
			continue // on another card already
		}
		if why := cardPicRefused(title, src, c, min); why != "" {
			if !try.other && !count(-1, why) {
				return false
			}
			continue
		}
		downloads++
		var jp []byte
		var w, h int
		var err error
		t0 := time.Now()
		ms := int64(-1)
		// Fetched already while the reader read (prefetchResult): its outcome, once it's there.
		if pf := cp.prefetched(c.url); pf != nil {
			select {
			case <-pf.done:
			case <-ctx.Done():
				return false
			}
			if pf.err != errNotFetched {
				cp.mu.Lock()
				pf.used = true
				cp.mu.Unlock()
				jp, w, h, err, ms = pf.jp, pf.w, pf.h, pf.err, pf.ms
			}
		}
		if ms < 0 {
			if jp, w, h, err = g.downloadCardPicture(t, c.url); ctx.Err() != nil {
				return false // the task ended while it loaded: counted as never_arrived by the metric
			}
			ms = time.Since(t0).Milliseconds()
		}
		if err != nil {
			if !count(ms, imageFailReason(err)) {
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
		cp.st.fetchMs += ms
		cp.st.bytes += len(jp)
		if cp.taken[c.url] {
			cp.mu.Unlock()
			continue // another card took it while this one loaded
		}
		cp.taken[c.url] = true
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

// downloadCardPicture is one card picture's download, under the task's card picture slots and the tool caps: the
// guarded client, downloadImage's caps, processImage's re-encode, and the card's shape check.
func (g *Guard) downloadCardPicture(t *task, u string) ([]byte, int, int, error) {
	ctx, cp := t.ctx, t.cards
	select {
	case cp.slots <- struct{}{}:
	case <-ctx.Done():
		return nil, 0, 0, ctx.Err()
	}
	defer func() { <-cp.slots }()
	var gate toolOutcome
	rel, err := t.tools.enter(ctx, "fetch", &gate)
	if err != nil {
		return nil, 0, 0, err
	}
	data, err := downloadImage(ctx, t.tools.fetcher, u)
	rel()
	if err != nil {
		return nil, 0, 0, err
	}
	jp, w, h, err := processImage(ctx, data, t.tools.decodes)
	if err == nil {
		err = cardShape(w, h)
	}
	return jp, w, h, err
}

// ---- a plain chat's search: pictures fetched while the reader reads (v0.8.16) --------------------------------

// picFetch is a card picture download started early (prefetchResult): once done is closed, the re-encoded picture
// and its size, or why it failed (errNotFetched: it wasn't needed), and how long it took. used: a card took it.
type picFetch struct {
	done chan struct{}
	jp   []byte
	w, h int
	err  error
	ms   int64
	used bool
}

// errNotFetched: a prefetch's candidate that wasn't downloaded (an earlier one worked, or the task ended).
var errNotFetched = errors.New("not fetched")

// prefetched is the early download of address u, or nil.
func (c *cardPics) prefetched(u string) *picFetch {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.pre[u]
}

// prefetchResult starts, as soon as the reader has read search result r (items: its checked items), the download
// resultPictures makes for it once the result is shown, so the picture is ready with the result instead of after it:
// the same item (the first that one of r's own pictures names closely, cardOtherMin), the same candidates in order,
// the same checks before any request (not a list's title; cardPicRefused at cardCaptionMin), the same download,
// re-encode and shape check under the same slots, at most cardPicTries downloads, stopping at the first that
// works. Nothing is shown from here: fetchCardPicture takes the outcome when the picture is shown (after the
// result) and counts it then; a download nothing took is counted at the run's end. Its egress is the task's
// background record, as every card picture's.
func (g *Guard) prefetchResult(t *task, r SearchResult, items []keptItem) {
	if len(items) == 0 || len(r.Thumbs) == 0 || listTitleRe.MatchString(r.Title) {
		return
	}
	src := citedSource{url: r.URL, title: r.Title}
	cands := thumbCands(r.Thumbs)
	name := ""
	for _, it := range items {
		if slices.ContainsFunc(cands, func(cd picCand) bool { return cardPicRefused(it.name, src, cd, cardOtherMin) == "" }) {
			name = it.name
			break
		}
	}
	if name == "" {
		return
	}
	cp := t.cards
	var todo []string
	var fetches []*picFetch
	cp.mu.Lock()
	for _, c := range cands {
		if len(todo) == cardPicTries {
			break
		}
		if cardPicRefused(name, src, c, cardCaptionMin) != "" || cp.pre[c.url] != nil {
			continue
		}
		pf := &picFetch{done: make(chan struct{})}
		cp.pre[c.url] = pf
		todo, fetches = append(todo, c.url), append(fetches, pf)
	}
	cp.mu.Unlock()
	if len(todo) == 0 {
		return
	}
	go func() {
		ok := false
		for i, u := range todo {
			pf := fetches[i]
			if ok || t.ctx.Err() != nil {
				pf.err = errNotFetched
				close(pf.done)
				continue
			}
			t0 := time.Now()
			pf.jp, pf.w, pf.h, pf.err = g.downloadCardPicture(t, u)
			pf.ms = time.Since(t0).Milliseconds()
			if t.ctx.Err() != nil && pf.err != nil {
				pf.err = errNotFetched
			}
			ok = pf.err == nil
			close(pf.done)
		}
	}()
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
	// Early downloads no card took (prefetchResult) were made all the same.
	for _, pf := range c.pre {
		select {
		case <-pf.done:
			if !pf.used && pf.err != errNotFetched {
				st.tried++
				st.fetchMs += pf.ms
				if pf.err != nil {
					st.fail(imageFailReason(pf.err))
				}
			}
		default:
		}
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
