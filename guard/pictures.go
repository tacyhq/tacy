package guard

// Card picture lookups (v0.8.18). An answer's item card gets its picture from its own source first (cardpics.go);
// a card citing a roundup or a review list has none there, and until v0.8.17 it got one only when the model called
// image_search for it, which it often didn't ("best 2 espresso machines", 2026-10-20: two cards, two
// searches, no image_search, no photos). Now the VM looks it up itself, once the card's items block closes: one
// image search per card still without a picture, at most maxCardLookups an answer, in the background like any card
// picture (the answer never waits; the end of the run waits at most cardLookupWait).
//
// The exfiltration guard: nothing of the conversation may ride out in an image query, and a card's title is the
// model's text. So a card is looked up only when its title names one of the run's checked reader items (the
// quarantined reader's items, reader.go checkItems: each found in its source's own text, none reading like an
// instruction), and what goes out is the VM's own copy of that item's name (noteItems), PII-masked again, never the
// card's title. A title that names no item is never searched.
//
// Permission: pictures are one feature with one setting, web.images ("Show product photos", asked once in the
// chat and remembered). A lookup runs only when the run's setting for web.images is Always allow and the policy's
// cap allows it; on Ask or Never there is no lookup and no prompt (the card keeps its placeholder). Its egress (the
// image search and the downloads) goes on the task's background record, as the card pictures' does.
//
// Which picture: the image search's candidates, refused before any request when their caption or addresses don't
// name the item, name another model number, or show a logo, a roundup's banner, a collage or people
// (pictureRefused); then ranked by caption (rankCandidates), downloaded, re-encoded and shape-checked (cardShape) as
// every card picture, at most cardPicTries of them.

import (
	"cmp"
	"context"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode"

	"github.com/tacyhq/tacy/proto"
	"github.com/tacyhq/tacy/safety"
)

const (
	maxCardLookups   = 6               // image searches for card pictures per run
	lookupCandidates = 8               // candidates asked for per lookup
	cardLookupWait   = 6 * time.Second // the end of a run waits at most this for lookups still loading
	lookupTime       = 12 * time.Second
	maxTaskItems     = 200 // reader item names a run keeps for lookups
)

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

// lookupCardPicture looks a card's picture up with the image search, for the run's reader item its title names
// (the VM's copy of the name goes out, never the title), and shows the first candidate that passes the checks
// under the call that brought the item's source. Reports whether one was shown. Counted in card_pictures.
func (g *Guard) lookupCardPicture(t *task, it taskItem) bool {
	cp := t.cards
	is, ok := t.tools.search.(ImageSearcher)
	if !ok {
		return false
	}
	ctx, cancel := context.WithTimeout(t.ctx, lookupTime)
	defer cancel()
	q, _ := maskPII(capRunes(strings.TrimSpace(it.name), maxQueryRunes))
	if q == "" || HiddenChars(q) || outboundLeak([]byte(q)) != nil {
		return false
	}
	var gate toolOutcome
	rel, err := t.tools.enter(ctx, "search", &gate)
	var cands []ImageCandidate
	if err == nil {
		cands, err = is.Images(ctx, q, lookupCandidates)
	}
	rel()
	cp.mu.Lock()
	cp.lookedUp++
	cp.mu.Unlock()
	if err != nil {
		return false
	}
	var list []ImageCandidate
	seen := map[string]bool{}
	for _, c := range cands {
		if seen[c.URL] || imageURLRefused(c.URL) != "" {
			continue
		}
		seen[c.URL] = true
		if why := pictureRefused(it.name, c); why != "" {
			cp.mu.Lock()
			cp.st.fail(why)
			cp.mu.Unlock()
			continue
		}
		list = append(list, c)
	}
	// Best caption first; a plain product shot before a review's action photo or a special edition (lab, 2026-10-20:
	// RunRepeat's "Cut in half" and a gold "85th Anniversary" Gaggia came first).
	list = rankCandidates(it.name, list)
	slices.SortStableFunc(list, func(a, b ImageCandidate) int { return cmp.Compare(lessIdeal(it.name, a), lessIdeal(it.name, b)) })
	for i, c := range list {
		if i == cardPicTries || ctx.Err() != nil {
			break
		}
		cp.mu.Lock()
		taken := cp.taken[c.URL] || cp.final
		cp.mu.Unlock()
		if taken {
			continue
		}
		t0 := time.Now()
		jp, w, h, err := g.downloadCardPicture(t, c.URL)
		ms := time.Since(t0).Milliseconds()
		cp.mu.Lock()
		if cp.final {
			cp.mu.Unlock()
			return false
		}
		cp.st.tried++
		cp.st.fetchMs += ms
		if err != nil {
			cp.st.fail(imageFailReason(err))
			cp.mu.Unlock()
			continue
		}
		if cp.taken[c.URL] {
			cp.mu.Unlock()
			continue
		}
		cp.st.bytes += len(jp)
		cp.taken[c.URL] = true
		cp.shown++
		cp.sent[it.call]++
		index := cp.sent[it.call]
		cp.mu.Unlock()
		// The caption is the web's (redacted as an image search's is); For names the item, so the chat puts it on
		// that item's card.
		out := toolOutcome{images: []shownImage{{Title: c.Title}}}
		if ids := redactOutcome(&out); len(ids) > 0 {
			g.record(Egress{Task: t.id, Action: it.call, Op: "web.images", Decision: "redacted", Rule: "leak_scan", Patterns: ids})
		}
		title := out.images[0].Title
		t.emit(proto.Event{Type: "image", ID: it.call, Image: &proto.Image{Index: index, Title: title, Source: c.Source,
			URL: c.URL, Type: "image/jpeg", Width: w, Height: h, Data: jp, For: it.name}})
		return true
	}
	return false
}

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
		found := slices.Contains(text, w) || len(w) >= 3 && strings.Contains(joined, w)
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
