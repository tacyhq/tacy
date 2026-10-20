package guard

// Card picture lookups (v0.8.18). An answer's item card gets its picture from its own source first (cardpics.go);
// a card citing a roundup or a review list has none there, and until v0.8.17 it got one only when the model called
// image_search for it, which it often didn't ("best 2 espresso machines", 2026-10-20: two cards, two
// searches, no image_search, no photos). Now the VM looks it up itself: one lookup per card still without a picture,
// at most maxCardLookups cards an answer, in the background like any card picture (the answer never waits; the end
// of the run waits at most cardLookupWait). Since v0.10.1 a lookup starts as soon as the answer or its reasoning
// names the item (watchMentions, below), and tries the provider's fast image search first.
//
// The exfiltration guard: nothing of the conversation may ride out in an image query, and a card's title is the
// model's text. So a card is looked up only when its title names one of the run's checked reader items (the
// quarantined reader's items, reader.go checkItems: each found in its source's own text, none reading like an
// instruction), and what goes out is the VM's own copy of that item's name (noteItems), PII-masked again, never the
// card's title. A title that names no item is never searched. The same for a lookup the answer's words start
// (v0.10.1): the words only choose which checked item; its name, the VM's copy, is what goes out.
//
// Permission: pictures are one feature with one setting, web.images ("Show product photos", asked once in the
// chat and remembered). A lookup runs only when the run's setting for web.images is Always allow and the policy's
// cap allows it; on Ask or Never there is no lookup and no prompt (the card keeps its placeholder). Its egress (the
// image search and the downloads) goes on the task's background record, as the card pictures' does.
//
// Which picture: the image search's candidates (the fast search's captioned by their page's title), refused before
// any request when their caption or addresses don't
// name the item, name another model number, or show a logo, a roundup's banner, a collage or people
// (pictureRefused); then ranked by caption (rankCandidates), downloaded, re-encoded and shape-checked (cardShape) as
// every card picture, at most cardPicTries of them.

import (
	"cmp"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/tacyhq/tacy/harness"
	"github.com/tacyhq/tacy/proto"
	"github.com/tacyhq/tacy/safety"
)

const (
	maxCardLookups   = 6   // image searches for card pictures per run
	lookupCandidates = 8   // candidates asked for per lookup
	maxTaskItems     = 200 // reader item names a run keeps for lookups
)

// lookupSearchTime is a lookup's image search, lookupFetchTime its downloads after it (each download also has
// imageFetchTime). Until v0.8.22 one 12 s budget covered both, and Tavily's image search with image descriptions takes
// 7-16 s on a query it hasn't seen (measured 2026-10-20 from a dev machine: response_time 6.9-15.6 s, 0.0 s once
// cached; without descriptions about 2 s): running shoes' two late lookups timed out in the run and again in the
// ticket's fill. Vars for the tests.
var (
	lookupSearchTime = 25 * time.Second
	lookupFetchTime  = 12 * time.Second
)

// cardLookupWait: the end of a run waits at most this for lookups still loading (those still open then go into the
// run's ticket, cardPics.end). A var for the tests.
var cardLookupWait = 6 * time.Second

// taskItem is a reader item a run can look up: its name as the reader gave it, and the call that brought its
// source (its picture is shown under that call).
type taskItem struct{ name, call string }

// itemKey is a name for matching: its letters and digits, lowercase, one space between words.
func itemKey(s string) string {
	return strings.Join(strings.FieldsFunc(strings.ToLower(s), func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsDigit(r) }), " ")
}

// allItems are a reader's checked items over all its parts.
func (r *readerResult) allItems() []keptItem {
	if r == nil || r.err != "" {
		return nil
	}
	if r.parts == nil {
		return r.items
	}
	var out []keptItem
	for _, p := range r.parts {
		if p != nil && p.err == "" {
			out = append(out, p.items...)
		}
	}
	return out
}

// noteItems keeps a call's checked reader items for the run's card lookups (first call wins for a name).
func (t *task) noteItems(call string, read *readerResult) {
	items := read.allItems()
	if len(items) == 0 {
		return
	}
	cp := t.cards
	cp.mu.Lock()
	defer cp.mu.Unlock()
	for _, it := range items {
		k := itemKey(it.name)
		if k == "" || len(cp.items) >= maxTaskItems {
			continue
		}
		if _, ok := cp.items[k]; !ok {
			cp.items[k] = taskItem{name: it.name, call: call}
		}
	}
}

// matchItem is the run's reader item a card's title names: the item whose words (itemKey) are the title's, or
// appear in the title in order as whole words ("Profitec GO" in "Profitec GO Espresso Machine"), or contain the
// title that way (the model shortened "Breville Barista Express BES870XL" to "Breville Barista Express"). The
// longest such item wins. ok false: none, and the card isn't looked up. Whatever matched, what goes out is the
// item's name, never the title.
func (c *cardPics) matchItem(title string) (taskItem, bool) {
	tk := itemKey(title)
	if tk == "" {
		return taskItem{}, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if it, ok := c.items[tk]; ok {
		return it, true
	}
	var best taskItem
	bestLen := 0
	for k, it := range c.items {
		// The item inside the title (the model added a category word), or the title inside the item (the model
		// shortened it), on word boundaries; at least two words or one with a digit, so "Pro" never matches.
		inTitle := strings.Contains(" "+tk+" ", " "+k+" ")
		inItem := strings.Contains(" "+k+" ", " "+tk+" ")
		if !inTitle && !inItem {
			continue
		}
		short := k
		if inItem {
			short = tk
		}
		if !strings.Contains(short, " ") && !strings.ContainsAny(short, "0123456789") {
			continue
		}
		if len(k) > bestLen {
			best, bestLen = it, len(k)
		}
	}
	return best, bestLen > 0
}

// lookupAllowed: the run's setting for pictures (web.images) is Always allow, under the policy's cap.
func (g *Guard) lookupAllowed(t *task) bool {
	if t.opts.Via == ViaSearch {
		return false // a plain chat's search: its answer isn't written here
	}
	return PermissionSetting(t.opts, "web.images", g.permissionCap(t.opts.Space, "web.images")) == safety.PermAlways
}

// ---- the lookup (v0.10.1) ---------------------------------------------------------------------------------------
//
// Until v0.10.0 a card's lookup started when its items block closed, about a second before the answer ended, with
// Tavily's image search with image descriptions (7-16 s on a query it hasn't seen): a live answer's pressure washers
// (2026-10-20) showed their photos about 30 s after the answer, through the ticket's fill, which searched again from
// the start. Now:
//   - a lookup starts as soon as the answer (or its reasoning) names one of the run's checked reader items
//     (watchMentions; at most maxEarlyLookups a run), so the search runs while the answer is still being written; a
//     card that names the item takes its outcome (one lookup per item, startLookup). What goes out is unchanged: the
//     VM's own copy of a checked item's name, never the answer's words, and only with pictures on (lookupAllowed);
//   - the search is the provider's fast one first (ImagesFast: no generated descriptions, about 2 s), its pictures
//     captioned by their page's title; the slow one with descriptions only when the fast one gave none that passed
//     the checks and downloaded;
//   - the best candidates download at once (lookupHedge), the best-ranked that works is shown.
// The photo checks are the same for both searches (pictureRefused before any download, cardShape after).

const (
	maxEarlyLookups = 4  // lookups started by a mention, before a card names the item, per run
	maxRunLookups   = 8  // items looked up per run, early ones included (each: the fast search, the slow one if needed)
	fastCandidates  = 12 // candidates asked for from the fast search
	lookupHedge     = 2  // candidates downloaded at once per lookup
)

// lookupFastTime: the fast image search's limit (it answers in about 2 s). A var for the tests.
var lookupFastTime = 8 * time.Second

// errNoFastImages: the image provider has no fast search (Brave): the lookup goes straight to Images.
var errNoFastImages = errors.New("no fast image search")

// fastImageSearcher is an image provider with a fast search (ImagesFast).
type fastImageSearcher interface {
	ImagesFast(ctx context.Context, query string, count int) ([]ImageCandidate, error)
}

// lookPic is a lookup's downloaded picture, re-encoded and shape-checked.
type lookPic struct {
	c    ImageCandidate
	jp   []byte
	w, h int
}

// lookup is one item's lookup: done closes when it ended; pics are its pictures that worked, best first.
type lookup struct {
	done chan struct{}
	pics []lookPic
}

// startLookup returns the run's lookup for item it, starting it if it hasn't started (nil: none may start: the run
// ended, or early and the run's early lookups are used up). It runs under the task's context.
func (g *Guard) startLookup(t *task, it taskItem, early bool) *lookup {
	cp := t.cards
	k := itemKey(it.name)
	cp.mu.Lock()
	if l := cp.looks[k]; l != nil {
		cp.mu.Unlock()
		return l
	}
	if cp.final || len(cp.looks) >= maxRunLookups || early && cp.early >= maxEarlyLookups {
		cp.mu.Unlock()
		return nil
	}
	if early {
		cp.early++
	}
	l := &lookup{done: make(chan struct{})}
	cp.looks[k] = l
	cp.mu.Unlock()
	go func() {
		defer close(l.done)
		l.pics = g.runLookup(t, it)
	}()
	return l
}

// runLookup is a lookup's searches and downloads: the fast search, then (no picture from it) the slow one; the
// pictures that worked, best first (at most lookupHedge).
func (g *Guard) runLookup(t *task, it taskItem) []lookPic {
	is, ok := t.tools.search.(ImageSearcher)
	if !ok {
		return nil
	}
	// The task and its space, as an action's context has them: the vault leases the image provider's key only for a
	// space whose policy allows it.
	base := withSpace(withTask(t.ctx, t.id), t.opts.Space)
	q, _ := maskPII(capRunes(strings.TrimSpace(it.name), maxQueryRunes))
	if q == "" || HiddenChars(q) || outboundLeak([]byte(q)) != nil {
		return nil
	}
	tried := map[string]bool{}
	search := func(fast bool) ([]ImageCandidate, bool) {
		limit := lookupSearchTime
		if fast {
			limit = lookupFastTime
		}
		sctx, cancel := context.WithTimeout(base, limit)
		defer cancel()
		var gate toolOutcome
		rel, err := t.tools.enter(sctx, "search", &gate)
		var cands []ImageCandidate
		if err == nil {
			if fast {
				f, ok := is.(fastImageSearcher)
				if !ok {
					rel()
					return nil, false
				}
				cands, err = f.ImagesFast(sctx, q, fastCandidates)
			} else {
				cands, err = is.Images(sctx, q, lookupCandidates)
			}
		}
		rel()
		if errors.Is(err, errNoFastImages) {
			return nil, false
		}
		t.cards.count(func(st *imageStats) { t.cards.lookedUp++ })
		if err != nil {
			why := imageFailReason(err)
			if errors.Is(sctx.Err(), context.DeadlineExceeded) {
				why = imageTimeout // the providers say "unreachable" for a request their context ended
			}
			t.cards.count(func(st *imageStats) { st.fail(why) })
			return nil, true
		}
		return cands, true
	}
	pick := func(cands []ImageCandidate) []lookPic {
		var list []ImageCandidate
		seen := map[string]bool{}
		for _, c := range cands {
			// A picture the fast search's caption didn't pass may pass with the slow one's (its own page's title, or
			// a description): only downloads aren't repeated.
			if tried[c.URL] || seen[c.URL] || imageURLRefused(c.URL) != "" {
				continue
			}
			seen[c.URL] = true
			if why := pictureRefused(it.name, c); why != "" {
				t.cards.count(func(st *imageStats) { st.fail(why) })
				continue
			}
			list = append(list, c)
		}
		// Best caption first; a plain product shot before a review's action photo or a special edition (lab,
		// 2026-10-20: RunRepeat's "Cut in half" and a gold "85th Anniversary" Gaggia came first).
		list = rankCandidates(it.name, list)
		slices.SortStableFunc(list, func(a, b ImageCandidate) int { return cmp.Compare(lessIdeal(it.name, a), lessIdeal(it.name, b)) })
		list = list[:min(len(list), cardPicTries)]
		for _, c := range list {
			tried[c.URL] = true
		}
		return g.downloadHedged(t, base, list)
	}
	if cands, ran := search(true); ran {
		if pics := pick(cands); len(pics) > 0 {
			return pics
		}
	}
	if t.ctx.Err() != nil {
		return nil
	}
	cands, _ := search(false)
	return pick(cands)
}

// downloadHedged downloads list's candidates, lookupHedge at once, and returns the ones that worked in list's order;
// it stops once the best-ranked of those still possible has worked. Under lookupFetchTime.
func (g *Guard) downloadHedged(t *task, base context.Context, list []ImageCandidate) []lookPic {
	if len(list) == 0 {
		return nil
	}
	ctx, cancel := context.WithTimeout(base, lookupFetchTime)
	defer cancel()
	type res struct {
		p   lookPic
		err error
		ms  int64
	}
	out := make([]*res, len(list))
	done := make([]chan struct{}, len(list))
	for i := range list {
		done[i] = make(chan struct{})
	}
	start := func(i int) {
		go func() {
			defer close(done[i])
			t0 := time.Now()
			jp, w, h, err := g.downloadCardPictureCtx(t, ctx, list[i].URL)
			out[i] = &res{p: lookPic{c: list[i], jp: jp, w: w, h: h}, err: err, ms: time.Since(t0).Milliseconds()}
		}()
	}
	next := 0
	for ; next < min(lookupHedge, len(list)); next++ {
		start(next)
	}
	var pics []lookPic
	for i := range list {
		select {
		case <-done[i]:
		case <-ctx.Done():
			return pics
		}
		r := out[i]
		t.cards.count(func(st *imageStats) {
			st.tried++
			st.fetchMs += r.ms
			if r.err != nil {
				st.fail(imageFailReason(r.err))
			} else {
				st.bytes += len(r.p.jp)
			}
		})
		if r.err == nil {
			pics = append(pics, r.p)
		}
		if len(pics) > 0 {
			// The best that worked so far: the ones already loading still may give a second picture (another card
			// of the same item), but nothing new starts.
			for j := i + 1; j < next; j++ {
				select {
				case <-done[j]:
					if out[j].err == nil {
						pics = append(pics, out[j].p)
					}
				default:
				}
			}
			return pics
		}
		if next < len(list) {
			start(next)
			next++
		}
	}
	return pics
}

// showLookup shows a card's picture from its item's lookup (startLookup: the one already running if the answer named
// the item before, else a new one), under the call that brought the item's source. Reports whether one was shown.
// Counted in card_pictures.
func (g *Guard) showLookup(t *task, it taskItem) bool {
	l := g.startLookup(t, it, false)
	if l == nil {
		return false
	}
	select {
	case <-l.done:
	case <-t.ctx.Done():
		return false
	}
	cp := t.cards
	for _, p := range l.pics {
		cp.mu.Lock()
		if cp.final {
			cp.mu.Unlock()
			return false
		}
		if cp.taken[p.c.URL] {
			cp.mu.Unlock()
			continue
		}
		cp.taken[p.c.URL] = true
		cp.shown++
		cp.sent[it.call]++
		index := cp.sent[it.call]
		cp.mu.Unlock()
		// The caption is the web's (redacted as an image search's is); For names the item, so the chat puts it on
		// that item's card.
		out := toolOutcome{images: []shownImage{{Title: p.c.Title}}}
		if ids := redactOutcome(&out); len(ids) > 0 {
			g.record(Egress{Task: t.id, Action: it.call, Op: "web.images", Decision: "redacted", Rule: "leak_scan", Patterns: ids})
		}
		t.emit(proto.Event{Type: "image", ID: it.call, Image: &proto.Image{Index: index, Title: out.images[0].Title, Source: p.c.Source,
			URL: p.c.URL, Type: "image/jpeg", Width: p.w, Height: p.h, Data: p.jp, For: it.name}})
		return true
	}
	return false
}

// count changes the card pictures' counts, unless the run ended (they were made then).
func (c *cardPics) count(f func(st *imageStats)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.final {
		f(&c.st)
	}
}

// watchMentions watches a model call's answer text and reasoning as they stream: each of the run's checked reader
// items it names (the item's words, whole, in order; at least two words or one with a digit, as matchItem) starts
// that item's lookup, when pictures are allowed (lookupAllowed), at most maxEarlyLookups a run. The words only choose
// which item: what goes out is the VM's copy of its name.
func (g *Guard) watchMentions(t *task, delta string) {
	if t.opts.Via == ViaSearch || t.opts.Via == ViaPictures || delta == "" {
		return
	}
	cp := t.cards
	cp.mu.Lock()
	if cp.final || len(cp.items) == 0 || cp.early >= maxEarlyLookups {
		cp.mu.Unlock()
		return
	}
	cp.tail += delta
	if n := len(cp.tail); n > mentionTail {
		cut := n - mentionTail
		for cut < n && !utf8.RuneStart(cp.tail[cut]) {
			cut++
		}
		cp.tail = cp.tail[cut:]
	}
	// Up to the last word's end: a word still streaming ("WF-1000XM" of "WF-1000XM6") isn't matched yet.
	end := strings.LastIndexFunc(cp.tail, func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsDigit(r) })
	if end < 0 {
		cp.mu.Unlock()
		return
	}
	text := " " + itemKey(cp.tail[:end]) + " "
	type at struct {
		it  taskItem
		pos int
	}
	var found []at
	for k, it := range cp.items {
		if cp.mentioned[k] || cp.looks[k] != nil || !mentionable(k) {
			continue
		}
		i := strings.Index(text, " "+k+" ")
		if i < 0 {
			continue
		}
		// A longer item that starts with this one ("Fellow Stagg EKG Pro" for "Fellow Stagg EKG"): named, it's that
		// one; maybe still streaming, wait for the next words.
		rest, longer, wait := text[i+len(k)+2:], false, false
		for k2 := range cp.items {
			tail, ok := strings.CutPrefix(k2, k+" ")
			if !ok {
				continue
			}
			if strings.HasPrefix(rest, tail+" ") {
				longer = true
			} else if strings.HasPrefix(tail, strings.TrimSpace(rest)) {
				wait = true
			}
		}
		if wait && !longer {
			continue
		}
		cp.mentioned[k] = true
		if !longer {
			found = append(found, at{it, i})
		}
	}
	// An item inside another one named at the same time ("Encore ESP" in "Baratza Encore ESP"): that one.
	found = slices.DeleteFunc(found, func(a at) bool {
		k := " " + itemKey(a.it.name) + " "
		return slices.ContainsFunc(found, func(b at) bool {
			k2 := " " + itemKey(b.it.name) + " "
			return k2 != k && strings.Contains(k2, k)
		})
	})
	cp.mu.Unlock()
	slices.SortFunc(found, func(a, b at) int { return cmp.Compare(a.pos, b.pos) }) // in the answer's order
	if len(found) == 0 || !g.lookupAllowed(t) {
		return
	}
	for _, f := range found {
		g.startLookup(t, f.it, true)
	}
}

// mentionable: an item name a mention may start a lookup for: two words or more, or one of at least 4 letters and
// digits with a digit in it ("DF54", not "2P" or "Pro").
func mentionable(k string) bool {
	if strings.Contains(k, " ") {
		return true
	}
	return len(k) >= 4 && strings.ContainsAny(k, "0123456789") && strings.IndexFunc(k, unicode.IsLetter) >= 0
}

// mentionTail: the answer's last bytes watchMentions looks at (an item's name is at most 160).
const mentionTail = 600

// ---- which picture --------------------------------------------------------------------------------------------

var (
	// heroRe: a caption about many things or a scene, not one item (a roundup's banner, a lineup, a collage).
	heroRe = regexp.MustCompile(`(?i)\b(collage|lineup|line-up|side[- ]by[- ]side|assorted|various|several|multiple|group of|selection of|range of|collection of|flat ?lay)\b`)
	// peopleWords in a caption: a photo of people (a reviewer, a model wearing it), not the item. Ignored when the
	// item's own name has the word ("Breville Barista Express").
	peopleWords = map[string]bool{"person": true, "people": true, "man": true, "woman": true, "men": true, "women": true, "girl": true,
		"boy": true, "guy": true, "lady": true, "portrait": true, "selfie": true, "smiling": true, "holding": true, "wearing": true,
		"face": true, "ceo": true, "reviewer": true, "host": true, "barista": true, "chef": true, "runner": true,
		"athlete": true, "hands": true, "hand": true}
)

// lessIdealRe: a caption of a review's photo (on feet, cut in half, first run) or a special or used one: tried after
// plain product shots.
var lessIdealRe = regexp.MustCompile(`(?i)\b(review|reviewed|tested|testing|first run|first look|on feet|cut in half|hands[- ]on|unboxing|refurbished|used|renewed|limited edition|anniversary|special edition)\b`)

// lessIdeal is 1 for a candidate lessIdealRe marks (unless the item's own name says it), else 0.
func lessIdeal(name string, c ImageCandidate) int {
	if m := lessIdealRe.FindString(c.Title); m != "" && !strings.Contains(strings.ToLower(name), strings.ToLower(m)) {
		return 1
	}
	return 0
}

// personPathWords in a picture's address: a person's photo (a site's authors and experts).
var personPathWords = map[string]bool{"experts": true, "expert": true, "authors": true, "author": true, "staff": true, "team": true,
	"headshot": true, "headshots": true, "profile": true, "profiles": true, "people": true, "contributors": true, "bio": true}

// Why a lookup's candidate isn't tried (pictureRefused), besides imageLogo and imageMismatch.
const (
	imageHero   = "hero"   // a roundup's or a scene's picture: many things, or people
	imageNumber = "number" // the caption names another model number
)

// pictureRefused is why an image search's candidate isn't tried for an item's card ("" = try it), before any
// request: a logo by its address (picURLRefused), a roundup's or a collage's caption, a caption about people, a
// caption naming another model, or a caption and addresses that don't name the item (pictureNames).
func pictureRefused(name string, c ImageCandidate) string {
	if picURLRefused(c.URL) != "" {
		return imageLogo
	}
	if listTitleRe.MatchString(c.Title) || heroRe.MatchString(c.Title) {
		return imageHero
	}
	own := map[string]bool{}
	for _, w := range imageWords(name) {
		own[w] = true
	}
	for _, w := range imageWords(c.URL) {
		if personPathWords[w] && !own[w] {
			return imageHero
		}
	}
	for _, w := range imageWords(c.Title) {
		if peopleWords[w] && !own[w] {
			return imageHero
		}
	}
	return pictureNames(name, c)
}

// pictureNames: the candidate names the item ("" = yes). As namesItem at cardOtherMin (0.75 of the name's words in
// its caption or its own address; "q6max" in an address counts for "Q6 Max"), except for model numbers: a missing one is
// forgiven only when the caption names no number at all (a description, "the Breville Barista Express espresso
// machine", for "Breville Barista Express BES870XL"); a caption with other numbers ("Superblast 2" for "Superblast
// 3") is refused. The ranking (captionScore) still puts a candidate with the numbers first.
func pictureNames(name string, c ImageCandidate) string {
	q := imageWords(name)
	if len(q) == 0 {
		return imageMismatch
	}
	// The caption and the picture's own address, not its page's: a review page about the item also shows its
	// author's headshot (lab, 2026-10-20: "Carlos Sánchez" on runrepeat.com/puma-deviate-pure-nitro).
	text := imageWords(c.Title + " " + c.URL)
	joined := strings.Join(text, "")
	if whole := strings.Join(q, ""); len(whole) >= 4 && strings.Contains(joined, whole) {
		return ""
	}
	captionNumbers := slices.ContainsFunc(imageWords(c.Title), func(w string) bool { return strings.ContainsAny(w, "0123456789") })
	var got, total float64
	for _, w := range q {
		found := slices.Contains(text, w) || len(w) >= 3 && strings.Contains(joined, w) || unitNumber(w, text)
		if strings.ContainsAny(w, "0123456789") {
			if !found && captionNumbers {
				return imageNumber
			}
			continue
		}
		total++
		if found {
			got++
		}
	}
	if total == 0 || got/total < cardOtherMin {
		return imageMismatch
	}
	return ""
}

// unitWords follow a small number as its unit in a caption ("20V" for "20-Volt", "6QT" for "6-Quart").
var unitWords = map[string]bool{"v": true, "volt": true, "qt": true, "quart": true, "in": true, "inch": true, "mm": true, "cm": true,
	"l": true, "ml": true, "oz": true, "gal": true, "w": true, "ah": true, "mah": true, "hp": true, "cfm": true, "psi": true,
	"gb": true, "tb": true, "hz": true, "ft": true, "lb": true, "lbs": true, "kg": true, "mph": true, "db": true}

// unitNumber: a small number of the item's name (w, up to 3 digits) is in the caption with its unit joined to it
// (v0.10.1: "20V" for the "20" of "20-Volt", "6QT" for the "6" of "6-Quart"; Tavily's page titles write them so). Only
// a unit: "9a" is another model than "9", "15pro" than "15".
func unitNumber(w string, text []string) bool {
	if len(w) > 3 || strings.Trim(w, "0123456789") != "" {
		return false
	}
	for _, x := range text {
		if rest, ok := strings.CutPrefix(x, w); ok && unitWords[rest] {
			return true
		}
	}
	return false
}

// endWait is how long the end of a run waits for card pictures still loading: longer when a lookup is among them
// (an image search, then the download).
func (c *cardPics) endWait() time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.lookups > 0 {
		return cardLookupWait
	}
	return cardEndWait
}

// ---- after the answer: the person allows pictures (v0.8.21) -----------------------------------------------------
//
// A run whose pictures setting was still Ask doesn't look its cards up (nothing goes out without the person's
// answer); its answer offers "Show product photos?". Until v0.8.19 an Allow there only changed the setting for later
// runs, so the answer on screen kept its placeholders (2026-10-20). Now the run holds back, in this
// gatewayd's memory only, the reader items its photo-less cards named (deferItem), and its end sends the tab a
// ticket for them (a "pictures" event, holdPictures). When the person allows pictures, the tab sends that ticket to
// POST /pictures: a task of its own kind (ViaPictures) with one action, web.images, which looks those items up
// (pictureLookups) exactly as the run would have (lookupCardPicture: the VM's own copy of each name, the same
// checks), and shows each picture under the call that brought its item, for that answer's cards. The tab sends no
// names: the exfil guard is unchanged. A ticket is good once, for 30 minutes, under the run's user tag and space.
//
// v0.8.22: a run with pictures allowed whose lookups were still loading when it ended (the end waits at most
// cardLookupWait) puts those cards' items in the ticket too (cardPics.end), and the tab, photos being on already,
// sends it at once: the answer's remaining cards fill right after it. The previous UTC day's user tag of the same
// person is accepted for a ticket (takePictures), so one from before midnight UTC still works after it.

// ViaPictures is a task started by POST /pictures (TaskOptions.Via).
const ViaPictures = "pictures"

const (
	laterTTL  = 30 * time.Minute
	maxLater  = 2048             // tickets held at once (the oldest go first)
	laterWait = 40 * time.Second // a lookup's search and downloads (lookupSearchTime + lookupFetchTime), with room
)

// picturesAgent names what runs a pictures task in its activity record: no agent definition, no brain.
var picturesAgent = harness.AgentRef{ID: "a_search", Version: "1", Digest: "unsigned"}

type laterEntry struct {
	user, space string
	items       []taskItem
	expires     time.Time
}

// laterPictures are the held-back lookups by ticket.
type laterPictures struct {
	mu    sync.Mutex
	m     map[string]*laterEntry
	order []string
}

// lookupAskable: the run's pictures setting isn't Always allow (Ask, or photos off for the chat or in Settings): its
// cards' lookups are held back, in memory only, for the person turning photos on for that answer (POST /pictures).
// Nothing leaves until then.
func (g *Guard) lookupAskable(t *task) bool {
	return t.opts.Via != ViaSearch && t.opts.Via != ViaPictures &&
		PermissionSetting(t.opts, "web.images", g.permissionCap(t.opts.Space, "web.images")) != safety.PermAlways
}

// deferItem holds back a card's lookup (once per item, at most maxCardLookups).
func (c *cardPics) deferItem(it taskItem) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.final || len(c.deferred) >= maxCardLookups || slices.ContainsFunc(c.deferred, func(x taskItem) bool { return x.name == it.name }) {
		return
	}
	c.deferred = append(c.deferred, it)
}

// holdPictures keeps a run's held-back lookups under a new ticket and returns it ("": none).
func (g *Guard) holdPictures(t *task) string {
	t.cards.mu.Lock()
	items := slices.Clone(t.cards.deferred)
	t.cards.mu.Unlock()
	if len(items) == 0 {
		return ""
	}
	b := make([]byte, 16)
	rand.Read(b)
	id := hex.EncodeToString(b)
	now := g.cfg.Now()
	l := &g.later
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.m == nil {
		l.m = map[string]*laterEntry{}
	}
	l.order = slices.DeleteFunc(l.order, func(k string) bool {
		if e := l.m[k]; e == nil || now.After(e.expires) {
			delete(l.m, k)
			return true
		}
		return false
	})
	for len(l.order) >= maxLater {
		delete(l.m, l.order[0])
		l.order = l.order[1:]
	}
	l.m[id] = &laterEntry{user: t.opts.User, space: t.opts.Space, items: items, expires: now.Add(laterTTL)}
	l.order = append(l.order, id)
	return id
}

// errNoTicket: the same words for every refusal, so a tab learns nothing about other tickets.
var errNoTicket = errors.New("these pictures can't be looked up now (the answer is too old, or they were looked up already)")

// takePictures is a ticket's held-back lookups, once, for the same user tag and space.
//
// prev (v0.8.22) is the same person's tag for the previous UTC day: the relay's tag is an HMAC of the UTC day and the
// account (the chat Worker's userTag), so a ticket from a run just before midnight UTC was refused just
// after it. Accepting prev is safe: the relay computes both tags from the one signed-in account, with its secret,
// so prev is never another person's tag (the VM never sees account ids and can't make or guess one); the ticket is
// still 128 random bits, good once, for this space, and still only for laterTTL from the run's end (expires), so
// yesterday's tag opens nothing older than 30 minutes; and what it unlocks is unchanged (lookups of the VM's own
// copies of the run's checked item names, pictures shown to the same account's tab).
func (g *Guard) takePictures(ticket, user, prev, space string) ([]taskItem, error) {
	l := &g.later
	l.mu.Lock()
	defer l.mu.Unlock()
	e := l.m[ticket]
	ok := e != nil && (e.user == user || prev != "" && e.user == prev)
	if !ok || e.space != space || g.cfg.Now().After(e.expires) {
		return nil, errNoTicket
	}
	delete(l.m, ticket)
	return e.items, nil
}

// PicturesStart checks a pictures request and makes its task: web.images only, no models, no input; its setting
// for web.images is Always allow (the person just allowed pictures), still under the policy's cap.
func PicturesStart(r *proto.PicturesRequest, now time.Time) (harness.Start, TaskOptions, []byte, error) {
	var s harness.Start
	if len(r.Ticket) != 32 || strings.Trim(r.Ticket, "0123456789abcdef") != "" {
		return s, TaskOptions{}, nil, errors.New("ticket must be the run's (32 hex)")
	}
	secret := make([]byte, 32)
	rand.Read(secret)
	args, _ := json.Marshal(map[string]any{"query": "pictures"})
	// Its space (keys v2 slice 6, v0.10.0): the one agentd verified (runauth), or as the request names it for a guard
	// that runs alone (tests: nothing is recorded there). No default: every request names one.
	switch {
	case r.Verified != nil:
		s.Space = r.Verified.Space
	case r.Space != "":
		s.Space = r.Space
	default:
		return s, TaskOptions{}, nil, errors.New("the request names no space")
	}
	s.Attempt, s.Agent = 1, picturesAgent
	s.Tools = ToolDefs("web.images")
	s.Limits = harness.TaskLimits{Deadline: now.Add(time.Minute).UTC().Format(time.RFC3339)}
	return s, TaskOptions{Via: ViaPictures, Pictures: r.Ticket, RunSecret: hex.EncodeToString(secret),
		Permissions: map[string]string{"web.search": "never", "web.fetch": "never", "web.images": "always"}}, args, nil
}

// PicturesActionID is the request id of a pictures task's one action.
const PicturesActionID = "pictures"

var errPicturesOnly = harness.Errf(harness.CodeNotAllowed, "a pictures task looks up its ticket's pictures and nothing else")

// picturesOnly: a pictures task makes one web.images action and nothing else (t.mu not held).
func (t *task) picturesOnly(req any) error {
	a, ok := req.(*harness.Action)
	if !ok || a.Name != "web.images" {
		return errPicturesOnly
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.searched {
		return errPicturesOnly
	}
	t.searched = true
	return nil
}

// pictureLookups is a pictures task's one action: its ticket's held-back lookups, at once, each shown under the call
// that brought its item; done when all ended (at most laterWait), with how many were shown.
func (g *Guard) pictureLookups(t *task) (*harness.ActionResult, error) {
	if PermissionSetting(t.opts, "web.images", g.permissionCap(t.opts.Space, "web.images")) != safety.PermAlways {
		return PermissionDenial("web.images", PermNeverSetting), nil
	}
	items, err := g.takePictures(t.opts.Pictures, t.opts.User, t.opts.PrevUser, t.opts.Space)
	if err != nil {
		return &harness.ActionResult{Status: harness.ActionFailed, Error: err.Error()}, nil
	}
	cp := t.cards
	cp.mu.Lock()
	cp.cards += len(items)
	cp.lookups = len(items)
	if cp.first.IsZero() {
		cp.first = time.Now()
	}
	cp.mu.Unlock()
	var wg sync.WaitGroup
	var mu sync.Mutex
	shown := 0
	for _, it := range items {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if g.showLookup(t, it) {
				mu.Lock()
				shown++
				mu.Unlock()
			}
		}()
	}
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(laterWait):
	}
	cp.mu.Lock()
	cp.last = time.Now()
	cp.mu.Unlock()
	mu.Lock()
	n := shown
	mu.Unlock()
	out, _ := json.Marshal(map[string]int{"looked_up": len(items), "shown": n})
	return &harness.ActionResult{Status: harness.ActionDone, Output: out}, nil
}
