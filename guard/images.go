package guard

// image_search: find pictures with the search provider, then download, check and re-encode them here, in the VM.
// The browser never loads an image URL (its CSP allows images from its own origin only, and a request from the
// browser would tell the image host the user's IP next to what they looked at); it gets the re-encoded bytes inside
// the encrypted stream and draws them on a canvas.
//
// Every downloaded image goes through the same guards as fetch_page (public http(s) only, the dialer refuses private,
// loopback, link-local and CGNAT addresses and ports other than 80/443; URLs with personal data refused), then:
//   - at most maxImageDownload bytes read, the format taken from the bytes (JPEG, PNG, GIF, WebP), never the
//     Content-Type header; SVG and everything else refused;
//   - dimensions checked before decoding (maxDecodePixels), decoded by Go's decoders (GIF: first frame; WebP:
//     golang.org/x/image/webp), at most limits.ImageDecodes at once across the VM (memory);
//   - scaled down to maxImageEdge on the long side, drawn onto white (transparency flattened) and encoded as a new
//     JPEG: nothing of the original file (EXIF, GPS, ICC, comments, extra frames) survives, and the size is bounded
//     (imageTargetBytes, hard cap maxImageOut).

import (
	"bytes"
	"cmp"
	"context"
	"errors"
	"fmt"
	"image"
	"image/color"
	"image/gif"
	"image/jpeg"
	"image/png"
	"io"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode"

	xdraw "golang.org/x/image/draw"
	"golang.org/x/image/webp"
	"golang.org/x/text/unicode/norm"

	"github.com/tacyhq/tacy/activity"
)

const (
	defaultImages    = 4                // images per image_search call when the model doesn't say
	maxImagesPerCall = 6                // images per image_search call
	maxImagesPerRun  = 8                // images shown per run, over all calls
	maxCandidates    = 12               // image URLs tried per call (some fail: too big, wrong type, 403)
	minCandidates    = 6                // candidates asked for even when one image is wanted: the next in line replaces one that fails
	imageCallFetches = 3                // downloads at once within one call (each also passes the fetch caps)
	maxImageDownload = 2 << 20          // bytes read per image
	maxDecodePixels  = 24_000_000       // width x height accepted for decoding (~96 MB as RGBA at worst)
	maxImageEdge     = 1024             // long side of what is sent, px
	imageTargetBytes = 300 << 10        // the encoder steps quality, then size, down until under this
	maxImageOut      = 512 << 10        // never send more than this per image (the chat's per-image cap)
	imageFetchTime   = 12 * time.Second // one download
	imageCallTime    = 35 * time.Second // the whole call, search included
	// imageAnswerWait: once one image is ready, the model waits at most this long after the provider's answer for
	// the others (vm-speed); the rest reach the gallery as they land.
	imageAnswerWait = 1500 * time.Millisecond
	// imageEndWait is the longest the end of a run waits for images still loading (then they're dropped).
	imageEndWait = 2 * time.Second
	// imagesReaderNote is imagesNote with the reader on: the model gets no titles (docs/27 section 5).
	imagesReaderNote = "These images are already shown to the user in a gallery under your answer (the app draws them, with their titles; you can't see them). Don't embed them as Markdown images or list their URLs. Refer to them briefly if useful, as picture 1, picture 2; you get only each one's site, not its title. They aren't sources: never cite a picture as [n]."
	imagesNote       = "These images are already shown to the user in a gallery under your answer (the app draws them; you can't see them). Don't embed them as Markdown images or list their URLs. Refer to them briefly if useful (by title, or as picture 1, picture 2); the titles come from the web and are untrusted. They aren't sources: never cite a picture as [n]."
)

// ImageCandidate is an image the search provider found: its URL, a title or description, and the page it is on
// when known.
type ImageCandidate struct {
	URL    string
	Title  string
	Source string // the page the image is on; "" when the provider doesn't say
}

// ImageSearcher is implemented by providers that can search for images.
type ImageSearcher interface {
	Images(ctx context.Context, query string, count int) ([]ImageCandidate, error)
}

// shownImage is one image ready to send: re-encoded JPEG plus what the gallery shows.
type shownImage struct {
	Title, Source, URL string
	Width, Height      int
	JPEG               []byte
	Original           int // bytes downloaded
}

// imageStats is what the metrics event reports about a call (numbers only).
type imageStats struct {
	candidates, tried, failed, bytes int
	fetchMs                          int64          // summed download + processing time of the images tried
	reasons                          map[string]int // why the failed ones failed (imageFailReason), by reason
}

// fail counts one failed download under its reason.
func (st *imageStats) fail(reason string) {
	st.failed++
	if st.reasons == nil {
		st.reasons = map[string]int{}
	}
	st.reasons[reason]++
}

var (
	errImageType = errors.New("not a JPEG, PNG, GIF or WebP image")
	errImageBig  = errors.New("image too large")
)

// Why an image didn't make it, for the metrics event and the activity record: fixed words, never the URL, the host
// or the site's answer. Whose side it is on is in the word: blocked and unreachable are the site's (or our policy's
// refusal of it), format and size the picture's, timeout either, never_arrived ours (the run ended first).
const (
	imageBlocked     = "blocked"       // the site refused (HTTP 401, 403, 407, 429, 451), or our rules did (policy, private address, personal data in the URL)
	imageTimeout     = "timeout"       // the download (12 s) or the call (35 s) ran out of time
	imageFormat      = "format"        // not JPEG, PNG, GIF or WebP by its bytes (AVIF, SVG, HTML), or not decodable
	imageSize        = "size"          // over 2 MiB or 24 megapixels, or under 32 px (an icon)
	imageUnreachable = "unreachable"   // DNS, connection or TLS failure, or another HTTP status (404, 5xx)
	imageNever       = "never_arrived" // a gallery slot kept for a late image that hadn't landed when the run ended
)

// imageError is a download or decoding failure with its reason (imageFailReason).
type imageError struct{ reason, msg string }

func (e *imageError) Error() string { return e.msg }

func imageErrorf(reason, format string, a ...any) error {
	return &imageError{reason: reason, msg: fmt.Sprintf(format, a...)}
}

// imageFailReason is why a candidate failed, as one of the fixed words above.
func imageFailReason(err error) string {
	var ie *imageError
	switch {
	case errors.As(err, &ie):
		return ie.reason
	case errors.Is(err, errImageType):
		return imageFormat
	case errors.Is(err, errImageBig):
		return imageSize
	case errors.Is(err, context.DeadlineExceeded):
		return imageTimeout
	case errors.Is(err, context.Canceled):
		return imageNever // the run ended while it loaded
	}
	return imageUnreachable
}

// httpFailReason: a site refusing (auth, forbidden, rate limit, legal) is "blocked"; anything else "unreachable".
func httpFailReason(status int) string {
	switch status {
	case 401, 403, 407, 429, 451:
		return imageBlocked
	}
	return imageUnreachable
}

// netFailReason sorts a failed request: our policy or the dialer's address rules (blocked), time (timeout), the
// rest (unreachable). errText's words, so the two agree.
func netFailReason(err error) string {
	if errors.Is(err, context.Canceled) {
		return imageNever
	}
	switch errText(err) {
	case "host not allowed by the policy", "address not allowed":
		return imageBlocked
	case "timeout":
		return imageTimeout
	}
	return imageUnreachable
}

// sniffImage tells the format from the first bytes, or "" for anything else.
func sniffImage(b []byte) string {
	switch {
	case bytes.HasPrefix(b, []byte{0xff, 0xd8, 0xff}):
		return "jpeg"
	case bytes.HasPrefix(b, []byte("\x89PNG\r\n\x1a\n")):
		return "png"
	case bytes.HasPrefix(b, []byte("GIF87a")), bytes.HasPrefix(b, []byte("GIF89a")):
		return "gif"
	case len(b) >= 12 && bytes.Equal(b[:4], []byte("RIFF")) && bytes.Equal(b[8:12], []byte("WEBP")):
		return "webp"
	}
	return ""
}

type imageCodec struct {
	config func(io.Reader) (image.Config, error)
	decode func(io.Reader) (image.Image, error)
}

var imageCodecs = map[string]imageCodec{
	"jpeg": {jpeg.DecodeConfig, jpeg.Decode},
	"png":  {png.DecodeConfig, png.Decode},
	"gif":  {gif.DecodeConfig, gif.Decode}, // first frame
	"webp": {webp.DecodeConfig, webp.Decode},
}

// processImage checks and re-encodes downloaded bytes: format from the bytes, size checked before decoding,
// decoded, scaled to at most maxImageEdge, flattened onto white and encoded as JPEG under imageTargetBytes when it
// can (hard cap maxImageOut). decodes, when set, bounds how many decode at once.
func processImage(ctx context.Context, data []byte, decodes chan struct{}) ([]byte, int, int, error) {
	format := sniffImage(data)
	codec, ok := imageCodecs[format]
	if !ok {
		return nil, 0, 0, errImageType
	}
	cfg, err := codec.config(bytes.NewReader(data))
	if err != nil {
		return nil, 0, 0, imageErrorf(imageFormat, "unreadable %s", format)
	}
	if cfg.Width <= 0 || cfg.Height <= 0 || cfg.Width > 20000 || cfg.Height > 20000 || cfg.Width*cfg.Height > maxDecodePixels {
		return nil, 0, 0, errImageBig
	}
	if min(cfg.Width, cfg.Height) < 32 {
		return nil, 0, 0, imageErrorf(imageSize, "image too small") // icons, tracking pixels
	}
	if decodes != nil {
		select {
		case decodes <- struct{}{}:
			defer func() { <-decodes }()
		case <-ctx.Done():
			return nil, 0, 0, ctx.Err()
		}
	}
	src, err := codec.decode(bytes.NewReader(data))
	if err != nil {
		return nil, 0, 0, imageErrorf(imageFormat, "unreadable %s", format)
	}
	b := src.Bounds()
	if b.Dx() <= 0 || b.Dy() <= 0 || b.Dx()*b.Dy() > maxDecodePixels {
		return nil, 0, 0, errImageBig
	}
	edge := maxImageEdge
	for _, q := range []int{85, 75, 65, 65, 65, 65} {
		w, h := fitEdge(b.Dx(), b.Dy(), edge)
		dst := image.NewRGBA(image.Rect(0, 0, w, h))
		xdraw.Draw(dst, dst.Bounds(), image.NewUniform(color.White), image.Point{}, xdraw.Src)
		xdraw.CatmullRom.Scale(dst, dst.Bounds(), src, b, xdraw.Over, nil)
		var out bytes.Buffer
		if err := jpeg.Encode(&out, dst, &jpeg.Options{Quality: q}); err != nil {
			return nil, 0, 0, imageErrorf(imageFormat, "encoding failed")
		}
		if out.Len() <= imageTargetBytes {
			return out.Bytes(), w, h, nil
		}
		if q == 65 {
			edge = edge * 4 / 5 // quality is as low as it goes: shrink
		}
		if ctx.Err() != nil {
			return nil, 0, 0, ctx.Err()
		}
	}
	return nil, 0, 0, errImageBig // still over the target at ~430 px: noise, not a picture
}

// fitEdge scales w x h so the long side is at most edge (never enlarged).
func fitEdge(w, h, edge int) (int, int) {
	if w <= edge && h <= edge {
		return w, h
	}
	if w >= h {
		return edge, max(1, h*edge/w)
	}
	return max(1, w*edge/h), edge
}

// imageURLRefused is why a URL can't be fetched before any network call ("" = fine): only absolute http(s) URLs
// without credentials, none carrying personal data (same kinds as fetch_page).
func imageURLRefused(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil {
		return "not an absolute http(s) URL"
	}
	_, found := maskPII(raw)
	for _, k := range found {
		if k == "email" || k == "ssn" || k == "card" || k == "iban" || k == "url-credentials" {
			return "personal data in the URL"
		}
	}
	return ""
}

// downloadImage fetches one image through the guarded client: status 200, at most maxImageDownload bytes.
func downloadImage(ctx context.Context, client *http.Client, raw string) ([]byte, error) {
	if why := imageURLRefused(raw); why != "" {
		return nil, imageErrorf(imageBlocked, "%s", why)
	}
	ctx, cancel := context.WithTimeout(ctx, imageFetchTime)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", raw, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; sealed-agent/0.1)")
	req.Header.Set("Accept", "image/jpeg,image/png,image/webp,image/gif;q=0.9,*/*;q=0.1")
	res, err := client.Do(req)
	if err != nil {
		return nil, imageErrorf(netFailReason(err), "fetch failed: %s", errText(err))
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return nil, imageErrorf(httpFailReason(res.StatusCode), "fetch failed: HTTP %d", res.StatusCode)
	}
	if res.ContentLength > maxImageDownload {
		return nil, errImageBig
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, maxImageDownload+1))
	if err != nil {
		if ctx.Err() != nil {
			return nil, imageErrorf(imageTimeout, "fetch failed while reading: timeout")
		}
		return nil, imageErrorf(imageUnreachable, "fetch failed while reading")
	}
	if len(body) > maxImageDownload {
		return nil, errImageBig
	}
	return body, nil
}

// reserveImages takes up to n of the run's remaining image slots; give back what isn't used.
func (t *Tools) reserveImages(n int) int {
	t.mu.Lock()
	defer t.mu.Unlock()
	n = max(0, min(n, maxImagesPerRun-t.imagesUsed))
	t.imagesUsed += n
	return n
}

func (t *Tools) returnImages(n int) {
	t.mu.Lock()
	t.imagesUsed -= n
	t.mu.Unlock()
}

// findImages runs one image_search: the provider's image search (behind the search caps), then up to want images
// downloaded (each behind the fetch caps) and re-encoded, in the provider's order.
//
// The model waits for the images it is told about, but not for all of them (vm-speed): once at least one image is
// ready and imageAnswerWait has passed since the provider answered, the call returns with the images ready so far
// (in the provider's order) and the rest of the downloads go on in the background, under the task (t.bg): what
// comes in later, up to the slots left, arrives on the returned tail and is shown in the gallery as it lands
// (Guard.lateImages). With no task (t.bg nil) the call waits for every image, as before. Every download's egress
// goes on the activity record: the action's when it finished before the call returned, the task's background
// record (with the site icons) when after.
func (t *Tools) findImages(ctx context.Context, query string, want int, out *toolOutcome) ([]shownImage, imageStats, *imageTail, error) {
	var st imageStats
	is, ok := t.search.(ImageSearcher)
	if !ok {
		return nil, st, nil, errors.New("image search isn't available with this search provider")
	}
	callStart := time.Now()
	ctx, cancel := context.WithTimeout(ctx, imageCallTime)
	defer cancel()
	var gate toolOutcome
	release, err := t.enter(ctx, "search", &gate)
	out.wait += gate.wait
	var cands []ImageCandidate
	if err == nil {
		cands, err = is.Images(ctx, query, min(maxCandidates, max(want*3, minCandidates)))
	}
	release()
	if err != nil {
		return nil, st, nil, err
	}
	// Dedupe, drop what can be refused without a request, cap.
	seen := map[string]bool{}
	var list []ImageCandidate
	for _, c := range cands {
		if seen[c.URL] || imageURLRefused(c.URL) != "" || strings.HasSuffix(strings.ToLower(strings.SplitN(c.URL, "?", 2)[0]), ".svg") {
			continue
		}
		seen[c.URL] = true
		list = append(list, c)
		if len(list) == maxCandidates {
			break
		}
	}
	// Best caption match first (the provider's order on a tie): when a picture fails, the next one tried is the
	// one that most looks like what was asked for, not just the provider's next.
	list = rankCandidates(query, list)
	st.candidates = len(list)

	// The downloads' context: the call's values (task, space, host filter) and its overall deadline, but not its
	// cancellation, so they can outlive the call; they end with the task instead. Without a task: the call's.
	background := t.bg != nil
	var dctx context.Context
	var stop context.CancelFunc
	unhook := func() bool { return true }
	if background {
		dctx, stop = context.WithDeadline(context.WithoutCancel(ctx), callStart.Add(imageCallTime))
		unhook = context.AfterFunc(t.bg, stop)
	} else {
		dctx, stop = context.WithCancel(ctx)
	}
	reqFacts, bgFacts := FactsFrom(ctx), FactsFrom(t.bg)

	// Downloads run imageCallFetches at a time. Before the call returns, the images shown are the first `want`
	// that work in the provider's order: once every candidate before the want-th success has finished, the rest
	// are cancelled.
	type got struct {
		done   bool
		img    *shownImage
		ms     int64
		reason string // failed: why (imageFailReason)
		taken  bool   // shown already (returned to the model, or sent on the tail)
	}
	res := make([]got, len(list))
	slots := make(chan struct{}, imageCallFetches)
	var wg sync.WaitGroup
	var mu sync.Mutex
	changed := make(chan struct{}, 1)
	var (
		returned bool          // the call returned (mu)
		waited   time.Duration // time the downloads waited for the caps before the call returned (mu)
		tail     *imageTail    // set when the call returns with slots left (mu)
	)
	// settled: the first want successes in order are known (mu held).
	settled := func() bool {
		ok := 0
		for _, r := range res {
			if !r.done {
				return false
			}
			if r.img != nil {
				if ok++; ok == want {
					return true
				}
			}
		}
		return false
	}
	ready := func() (n int) { // successes so far (mu held)
		for _, r := range res {
			if r.img != nil {
				n++
			}
		}
		return n
	}
	for i, c := range list {
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case slots <- struct{}{}:
				defer func() { <-slots }()
			case <-dctx.Done():
				return
			}
			if dctx.Err() != nil {
				return
			}
			// Each download keeps its own egress, then hands it to the action's record or the task's.
			facts := &Facts{}
			fctx := WithFacts(dctx, facts)
			var g toolOutcome
			rel, err := t.enter(fctx, "fetch", &g)
			defer func() {
				mu.Lock()
				if returned {
					bgFacts.Merge(facts.Data())
				} else {
					reqFacts.Merge(facts.Data())
				}
				mu.Unlock()
			}()
			mu.Lock()
			if !returned {
				waited += g.wait
			}
			mu.Unlock()
			if err != nil {
				return
			}
			t0 := time.Now()
			data, err := downloadImage(fctx, t.fetcher, c.URL)
			rel()
			var jp []byte
			var w, h int
			if err == nil {
				jp, w, h, err = processImage(fctx, data, t.decodes)
			}
			if err != nil && dctx.Err() != nil && ctx.Err() == nil {
				return // cancelled because enough images arrived: neither shown nor failed
			}
			mu.Lock()
			defer mu.Unlock()
			if returned && err != nil && errors.Is(dctx.Err(), context.Canceled) {
				return // after the result: stopped because the slots filled, or the task ended (counted by slot)
			}
			res[i] = got{done: true, ms: time.Since(t0).Milliseconds()}
			if err == nil {
				res[i].img = &shownImage{Title: c.Title, Source: c.Source, URL: c.URL, Width: w, Height: h, JPEG: jp, Original: len(data)}
			} else {
				res[i].reason = imageFailReason(err)
				if errors.Is(dctx.Err(), context.DeadlineExceeded) {
					res[i].reason = imageTimeout // the call's time ran out while it loaded
				}
			}
			if returned && tail != nil { // after the call's result: the tail's numbers (its metric is sent when it ends)
				tail.st.tried++
				tail.st.fetchMs += res[i].ms
				if err != nil {
					tail.st.fail(res[i].reason)
				}
			}
			switch {
			case !returned:
				if settled() {
					stop()
				}
				select {
				case changed <- struct{}{}:
				default:
				}
			case tail != nil && res[i].img != nil && tail.left > 0:
				res[i].taken = true
				tail.left--
				tail.ch <- *res[i].img // buffered for every slot: never blocks
				if tail.left == 0 {
					stop()
				}
			}
		}()
	}
	all := make(chan struct{})
	go func() { wg.Wait(); close(all) }()

	var early <-chan time.Time
	if background {
		tm := time.NewTimer(imageAnswerWait)
		defer tm.Stop()
		early = tm.C
	}
	passed, finished := false, false
wait:
	for {
		mu.Lock()
		s, n := settled(), ready()
		mu.Unlock()
		if s || (passed && n > 0) {
			break
		}
		select {
		case <-changed:
		case <-early:
			passed = true
		case <-all:
			finished = true
			break wait
		case <-ctx.Done(): // the call's time is up, or the task was cancelled: what's done is shown
			stop()
			<-all
			finished = true
			break wait
		}
	}

	mu.Lock()
	returned = true
	out.wait += waited
	var imgs []shownImage
	for i := range res {
		r := &res[i]
		if !r.done {
			continue
		}
		st.tried++
		st.fetchMs += r.ms
		if r.img == nil {
			st.fail(r.reason)
			continue
		}
		if len(imgs) < want {
			r.taken = true
			imgs = append(imgs, *r.img)
			st.bytes += len(r.img.JPEG)
		}
	}
	reqFacts.imageCounts(len(imgs), st.reasons) // the action's record: what it showed and what failed before its result
	if left := want - len(imgs); left > 0 && background && !finished && ctx.Err() == nil {
		tail = &imageTail{ch: make(chan shownImage, left), slots: left, left: left}
	}
	mu.Unlock()
	if tail == nil {
		stop()
		unhook()
		return imgs, st, nil, nil
	}
	go func() { // the tail ends when the last download does
		<-all
		stop()
		unhook()
		close(tail.ch)
	}()
	return imgs, st, tail, nil
}

// imageTail is an image search that returned to the model before all its images were in: the images that land
// later arrive on ch, at most slots of them; ch is closed when the downloads are over (all done, the slots filled,
// imageCallTime from the call's start, or the task ended).
type imageTail struct {
	ch    chan shownImage
	slots int // image slots the call kept for these (Tools.reserveImages); what isn't used goes back
	left  int // slots still open (findImages' mu)
	// st: the downloads that finished after the call returned (tried, failed and why, time). Written under
	// findImages' mu; read once ch is closed (every download has finished by then).
	st imageStats
}

// ---- which candidate first ----------------------------------------------------------------------------------

// imageStop are words that say nothing about what a picture shows.
var imageStop = map[string]bool{"a": true, "an": true, "the": true, "and": true, "or": true, "of": true, "for": true, "with": true,
	"by": true, "in": true, "on": true, "to": true, "image": true, "images": true, "photo": true, "photos": true, "picture": true,
	"pictures": true, "jpg": true, "jpeg": true, "png": true, "webp": true, "gif": true, "www": true, "com": true, "https": true, "http": true}

// notAPhoto are words in an image's address or caption that mark a site's chrome, not the thing asked for.
var notAPhoto = []string{"logo", "icon", "favicon", "sprite", "avatar", "placeholder", "banner", "badge", "pixel", "spacer"}

// foldAccents takes the accents off letters (NFKD, combining marks dropped): "Kärcher" is "Karcher", as most shops
// and addresses write it (v0.10.1: a "Kärcher K4" card refused its "Karcher K4" pictures).
func foldAccents(s string) string {
	ascii := true
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			ascii = false
			break
		}
	}
	if ascii {
		return s
	}
	return strings.Map(func(r rune) rune {
		if unicode.Is(unicode.Mn, r) {
			return -1
		}
		return r
	}, norm.NFKD.String(s))
}

// imageWords are the lowercase words and numbers of s, accents folded, without filler words.
func imageWords(s string) []string {
	var out []string
	for _, w := range strings.FieldsFunc(strings.ToLower(foldAccents(s)), func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r > 0x7f && unicode.IsLetter(r))
	}) {
		if !imageStop[w] {
			out = append(out, w)
		}
	}
	return out
}

// shortLetters: one or two letters, the series letter of a model number ("K" of "K 4", "Q" of "Q 6").
func shortLetters(w string) bool {
	return len(w) <= 2 && w != "" && strings.Trim(w, "abcdefghijklmnopqrstuvwxyz") == ""
}

func allDigits(w string) bool { return w != "" && strings.Trim(w, "0123456789") == "" }

// spacedModel: q[i] is in text once a model number's spacing is ignored: "K 4" and "K4" are one model. A joined
// "k4" is found where text writes "K 4", and the "k" or the "4" of "K 4" where text writes "K4". Only one or two
// letters and the number right after them: "K 5" never matches "K4", and "4" alone never matches "K4".
func spacedModel(q []string, i int, text []string) bool {
	has := func(w string) bool {
		if slices.Contains(text, w) {
			return true
		}
		for j := 0; j+1 < len(text); j++ {
			if shortLetters(text[j]) && allDigits(text[j+1]) && text[j]+text[j+1] == w {
				return true
			}
		}
		return false
	}
	w := q[i]
	if letters := strings.TrimRight(w, "0123456789"); shortLetters(letters) && allDigits(w[len(letters):]) && has(w) {
		return true
	}
	if i > 0 && shortLetters(q[i-1]) && allDigits(w) && has(q[i-1]+w) {
		return true
	}
	return i+1 < len(q) && shortLetters(w) && allDigits(q[i+1]) && has(w+q[i+1])
}

// captionScore is how well a candidate's caption, file address and page address name the query: the share of the
// query's words found there (numbers, as in model names, count double; "q6max" in an address counts for "Q6 Max"),
// less a penalty when it looks like a logo or an icon. 0 for a query without words.
func captionScore(query []string, c ImageCandidate) float64 {
	if len(query) == 0 {
		return 0
	}
	text := c.Title + " " + c.URL + " " + c.Source
	words := map[string]bool{}
	for _, w := range imageWords(text) {
		words[w] = true
	}
	joined := strings.Join(imageWords(text), "")
	var got, total float64
	for _, w := range query {
		weight := 1.0
		if strings.ContainsAny(w, "0123456789") {
			weight = 2
		}
		total += weight
		if words[w] || (len(w) >= 3 && strings.Contains(joined, w)) {
			got += weight
		}
	}
	if whole := strings.Join(query, ""); len(whole) >= 4 && strings.Contains(joined, whole) {
		got = total
	}
	score := got / total
	low := strings.ToLower(text)
	for _, w := range notAPhoto {
		if strings.Contains(low, w) {
			score -= 1 // after every real match; among themselves, still by caption
			break
		}
	}
	return score
}

// rankCandidates orders candidates by captionScore, best first, keeping the provider's order among equals.
func rankCandidates(query string, list []ImageCandidate) []ImageCandidate {
	q := imageWords(query)
	type scored struct {
		c ImageCandidate
		s float64
	}
	xs := make([]scored, len(list))
	for i, c := range list {
		xs[i] = scored{c, captionScore(q, c)}
	}
	slices.SortStableFunc(xs, func(a, b scored) int { return cmp.Compare(b.s, a.s) })
	out := make([]ImageCandidate, len(xs))
	for i, x := range xs {
		out[i] = x.c
	}
	return out
}

// imageCounts puts the pictures shown and the failed downloads, by reason, on the record (FactsData.Images).
func (f *Facts) imageCounts(shown int, reasons map[string]int) {
	n := 0
	for _, c := range reasons {
		n += c
	}
	f.addImages(&activity.Images{Shown: shown, Failed: n, Reasons: maps.Clone(reasons)})
}

// imageNever puts gallery slots that stayed empty on the record (never_arrived).
func (f *Facts) imageNever(n int) {
	if n > 0 {
		f.addImages(&activity.Images{Failed: n, Reasons: map[string]int{imageNever: n}})
	}
}

func (f *Facts) addImages(m *activity.Images) {
	if f == nil || m.Failed == 0 && m.Shown == 0 {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.d.Images = f.d.Images.Add(m)
}
