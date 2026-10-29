package guard

// Site icons (favicons) for the sources the chat lists. The browser must never load them itself: a request from
// the browser to the site, or to a favicon service, would tell that party the user's IP next to what the answer
// used, and the chat's CSP allows images from its own origin only. So the VM fetches them, like image_search's
// images, and sends them inside the encrypted stream as "favicon" events, one per site, whenever one is ready
// (mostly while the model is still working on its next step).
//
// For each distinct site of a run's sources (web_search results, fetch_page pages, image_search source pages), in
// the order they appear, at most maxIconHosts per run:
//  1. https://<host>/favicon.ico;
//  2. if that fails, the home page (first maxIconPage bytes only) and its <link rel="icon"> /
//     <link rel="apple-touch-icon"> (SVG skipped), best size first, at most maxIconLinks of them.
//
// Every request goes through the same client as fetch_page and the image downloads (public addresses on ports
// 80/443 only, at most 5 redirects, http(s) only), iconFetchTime each, iconHostTime per site, at most
// maxIconDownload bytes read. The format comes from the bytes (ICO, PNG, GIF, JPEG, WebP; never SVG or the
// Content-Type), dimensions are checked before decoding, ICO is read by decodeICO below (PNG or BMP entries; no
// dependency), and the icon is redrawn into a 32x32 PNG: nothing else of the file survives.
//
// Icons never hold up or fail a run: errors only mean the chat shows the site's letter instead. They don't use the
// per-user tool caps (a run's own searches shouldn't wait for icons): iconRunFetches sites at once per run, and
// Limits.Favicons at once across the VM. At the end of a run the VM waits at most iconEndWait for icons still
// being fetched, then drops them; one "favicons" metrics event reports the numbers.

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	xdraw "golang.org/x/image/draw"
	"golang.org/x/net/html"

	"github.com/tacyhq/tacy/proto"
)

const (
	maxIconHosts    = 16                     // sites per run
	iconRunFetches  = 3                      // sites fetched at once per run
	iconFetchTime   = 3 * time.Second        // one request
	iconHostTime    = 6 * time.Second        // one site, every attempt
	iconEndWait     = 500 * time.Millisecond // longest wait at the end of a run for icons still being fetched (2 s before vm-speed)
	maxIconDownload = 100 << 10              // bytes read per icon
	maxIconPage     = 100 << 10              // bytes of the home page read for its <link rel="icon">
	maxIconLinks    = 2                      // <link> icons tried per site
	maxIconEdge     = 1024                   // width and height accepted for decoding
	iconSize        = 32                     // what is sent: iconSize x iconSize PNG
	maxIconOut      = 8 << 10                // never send more than this per icon (a 32x32 RGBA PNG is ~4 KiB at worst)
)

var (
	errIconType  = errors.New("not an ICO, PNG, GIF, JPEG or WebP icon")
	errIconBig   = errors.New("icon too large")
	errIconBad   = errors.New("unreadable icon")
	errIconBlank = errors.New("icon is blank")
	errNoIcon    = errors.New("no icon found")
)

// iconKey is the site a URL is on as the chat names it (hostname, lowercase, without "www.") and the host to fetch
// from, or ok=false for anything that isn't a public http(s) DNS name.
func iconKey(raw string) (key, host string, ok bool) {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil {
		return "", "", false
	}
	host = strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	if len(host) > 253 || !strings.Contains(host, ".") || strings.Trim(host, "0123456789.") == "" {
		return "", "", false // a single label, or an IPv4 address: no site to name
	}
	for _, c := range host {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '.') {
			return "", "", false // IPv6 literals, odd characters
		}
	}
	return strings.TrimPrefix(host, "www."), host, true
}

// sniffIcon tells the format from the first bytes: an ICO, or one of the image formats images.go reads.
func sniffIcon(b []byte) string {
	if len(b) >= 6 && b[0] == 0 && b[1] == 0 && b[2] == 1 && b[3] == 0 {
		return "ico"
	}
	return sniffImage(b)
}

// processIcon checks downloaded bytes and redraws them as an iconSize x iconSize PNG (transparent where the icon
// is; smaller icons scaled up by whole pixels when they fit evenly, so 16 px icons stay crisp). decodes, when set,
// bounds how many decode at once (shared with image_search).
func processIcon(ctx context.Context, data []byte, decodes chan struct{}) ([]byte, error) {
	if len(data) > maxIconDownload {
		return nil, errIconBig
	}
	format := sniffIcon(data)
	if format == "" {
		return nil, errIconType
	}
	if decodes != nil {
		select {
		case decodes <- struct{}{}:
			defer func() { <-decodes }()
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	var src image.Image
	var err error
	if format == "ico" {
		src, err = decodeICO(data)
	} else {
		src, err = decodeChecked(imageCodecs[format], data)
	}
	if err != nil {
		return nil, err
	}
	b := src.Bounds()
	w, h := b.Dx(), b.Dy()
	if w <= 0 || h <= 0 || w > maxIconEdge || h > maxIconEdge {
		return nil, errIconBig
	}
	if min(w, h) < 8 {
		return nil, errIconBlank // a tracking pixel or a placeholder, not an icon
	}
	// Fit the long side to iconSize, centered on transparent.
	dw, dh := iconSize, iconSize
	if w > h {
		dh = max(1, h*iconSize/w)
	} else if h > w {
		dw = max(1, w*iconSize/h)
	}
	dst := image.NewNRGBA(image.Rect(0, 0, iconSize, iconSize))
	r := image.Rect((iconSize-dw)/2, (iconSize-dh)/2, (iconSize-dw)/2+dw, (iconSize-dh)/2+dh)
	var scaler xdraw.Scaler = xdraw.CatmullRom
	if w <= iconSize && h <= iconSize && iconSize%w == 0 && iconSize%h == 0 && w == h {
		scaler = xdraw.NearestNeighbor
	}
	scaler.Scale(dst, r, src, b, xdraw.Src, nil)
	visible := 0
	for i := 3; i < len(dst.Pix); i += 4 {
		if dst.Pix[i] >= 32 {
			visible++
		}
	}
	if visible < 16 {
		return nil, errIconBlank // fully (or almost) transparent: the letter reads better
	}
	var out bytes.Buffer
	enc := png.Encoder{CompressionLevel: png.BestCompression}
	if err := enc.Encode(&out, dst); err != nil {
		return nil, errIconBad
	}
	if out.Len() > maxIconOut {
		return nil, errIconBig
	}
	return out.Bytes(), nil
}

// decodeChecked decodes PNG, GIF (first frame), JPEG or WebP after checking the dimensions in its header.
func decodeChecked(codec imageCodec, data []byte) (image.Image, error) {
	if codec.config == nil {
		return nil, errIconType
	}
	cfg, err := codec.config(bytes.NewReader(data))
	if err != nil {
		return nil, errIconBad
	}
	if cfg.Width <= 0 || cfg.Height <= 0 || cfg.Width > maxIconEdge || cfg.Height > maxIconEdge {
		return nil, errIconBig
	}
	img, err := codec.decode(bytes.NewReader(data))
	if err != nil {
		return nil, errIconBad
	}
	return img, nil
}

// ---- ICO ------------------------------------------------------------------------------------------------------

// decodeICO reads a Windows icon file: a directory of images, each a PNG or a BMP without its file header (a DIB:
// BITMAPINFOHEADER, the colors at twice the height, then a 1-bit transparency mask). It picks the smallest image at
// least iconSize wide (else the largest) and decodes that one. Supported DIBs: 1, 4, 8, 24 and 32 bits per pixel,
// uncompressed. Every offset and length is checked against the data.
func decodeICO(b []byte) (image.Image, error) {
	le16 := func(p []byte) int { return int(binary.LittleEndian.Uint16(p)) }
	le32 := func(p []byte) int { return int(binary.LittleEndian.Uint32(p)) }
	if len(b) < 6 || le16(b[0:]) != 0 || le16(b[2:]) != 1 {
		return nil, errIconType
	}
	n := le16(b[4:])
	if n == 0 || n > 64 || len(b) < 6+16*n {
		return nil, errIconBad
	}
	type entry struct{ w, bpp, off, size int }
	var best *entry
	better := func(a, cur *entry) bool {
		switch {
		case cur == nil:
			return true
		case (a.w >= iconSize) != (cur.w >= iconSize):
			return a.w >= iconSize
		case a.w != cur.w:
			if a.w >= iconSize {
				return a.w < cur.w // the smallest that is big enough
			}
			return a.w > cur.w // else the largest
		}
		return a.bpp > cur.bpp
	}
	for i := range n {
		d := b[6+16*i:]
		e := entry{w: int(d[0]), bpp: le16(d[6:]), size: le32(d[8:]), off: le32(d[12:])}
		if e.w == 0 {
			e.w = 256
		}
		if e.off < 6+16*n || e.size <= 0 || e.off > len(b) || e.size > len(b)-e.off {
			continue
		}
		if better(&e, best) {
			best = &e
		}
	}
	if best == nil {
		return nil, errIconBad
	}
	data := b[best.off : best.off+best.size]
	if bytes.HasPrefix(data, []byte("\x89PNG\r\n\x1a\n")) {
		return decodeChecked(imageCodecs["png"], data)
	}
	return decodeDIB(data)
}

// decodeDIB decodes one BMP entry of an ICO (see decodeICO).
func decodeDIB(d []byte) (image.Image, error) {
	le16 := func(p []byte) int { return int(binary.LittleEndian.Uint16(p)) }
	le32 := func(p []byte) int { return int(binary.LittleEndian.Uint32(p)) }
	if len(d) < 40 {
		return nil, errIconBad
	}
	hs := le32(d[0:])
	if hs < 40 || hs > len(d) {
		return nil, errIconBad
	}
	w := int(int32(binary.LittleEndian.Uint32(d[4:])))
	hh := int(int32(binary.LittleEndian.Uint32(d[8:])))
	bpp, comp, used := le16(d[14:]), le32(d[16:]), le32(d[32:])
	topDown := hh < 0
	if topDown {
		hh = -hh
	}
	h := hh / 2 // colors and mask
	if w <= 0 || w > 256 || h <= 0 || h > 256 {
		return nil, errIconBad
	}
	if comp != 0 {
		return nil, errIconType // compressed or bit-field DIBs: rare in icons
	}
	off := hs
	var pal []color.NRGBA
	switch bpp {
	case 1, 4, 8:
		k := used
		if k <= 0 || k > 1<<bpp {
			k = 1 << bpp
		}
		if off+4*k > len(d) {
			return nil, errIconBad
		}
		for i := range k {
			p := d[off+4*i:]
			pal = append(pal, color.NRGBA{p[2], p[1], p[0], 255})
		}
		off += 4 * k
	case 24, 32:
	default:
		return nil, errIconType
	}
	stride := (w*bpp + 31) / 32 * 4
	maskStride := (w + 31) / 32 * 4
	if off+stride*h > len(d) {
		return nil, errIconBad
	}
	hasMask := off+stride*h+maskStride*h <= len(d)
	img := image.NewNRGBA(image.Rect(0, 0, w, h))
	alpha := false
	for r := range h {
		y := h - 1 - r // rows are stored bottom up
		if topDown {
			y = r
		}
		line := d[off+r*stride : off+(r+1)*stride]
		for x := range w {
			var c color.NRGBA
			switch bpp {
			case 32:
				p := line[x*4:]
				c = color.NRGBA{p[2], p[1], p[0], p[3]}
				alpha = alpha || p[3] != 0
			case 24:
				p := line[x*3:]
				c = color.NRGBA{p[2], p[1], p[0], 255}
			default:
				var idx int
				switch bpp {
				case 8:
					idx = int(line[x])
				case 4:
					idx = int(line[x/2]>>(4*(1-x%2))) & 0xf
				case 1:
					idx = int(line[x/8]>>(7-x%8)) & 1
				}
				if idx < len(pal) {
					c = pal[idx]
				}
			}
			img.SetNRGBA(x, y, c)
		}
	}
	// The mask says which pixels are transparent, unless 32-bit pixels carry their own alpha.
	if hasMask && !alpha {
		m := off + stride*h
		for r := range h {
			y := h - 1 - r
			if topDown {
				y = r
			}
			line := d[m+r*maskStride : m+(r+1)*maskStride]
			for x := range w {
				if line[x/8]>>(7-x%8)&1 == 1 {
					img.SetNRGBA(x, y, color.NRGBA{})
				}
			}
		}
	}
	return img, nil
}

// ---- finding and fetching -------------------------------------------------------------------------------------

// iconGet fetches one icon URL (or decodes a data: URL) through the guarded client: status 200, at most
// maxIconDownload bytes.
func iconGet(ctx context.Context, client *http.Client, raw string) ([]byte, error) {
	if strings.HasPrefix(raw, "data:") {
		return iconDataURL(raw)
	}
	if why := imageURLRefused(raw); why != "" {
		return nil, errors.New(why)
	}
	ctx, cancel := context.WithTimeout(ctx, iconFetchTime)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", raw, nil)
	req.Header.Set("User-Agent", FetchUserAgent)
	req.Header.Set("Accept", "image/x-icon,image/png,image/webp,image/gif,image/jpeg;q=0.9,*/*;q=0.1")
	res, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch failed: %s", errText(err))
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return nil, fmt.Errorf("fetch failed: HTTP %d", res.StatusCode)
	}
	if res.ContentLength > maxIconDownload {
		return nil, errIconBig
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, maxIconDownload+1))
	if err != nil {
		return nil, errors.New("fetch failed while reading")
	}
	if len(body) > maxIconDownload {
		return nil, errIconBig
	}
	return body, nil
}

// iconDataURL decodes an icon given inline in the page (`data:image/png;base64,...`). No network.
func iconDataURL(raw string) ([]byte, error) {
	meta, payload, ok := strings.Cut(strings.TrimPrefix(raw, "data:"), ",")
	if !ok || !strings.HasPrefix(meta, "image/") || !strings.HasSuffix(meta, ";base64") || strings.Contains(meta, "svg") {
		return nil, errIconType
	}
	if base64.StdEncoding.DecodedLen(len(payload)) > maxIconDownload+3 {
		return nil, errIconBig
	}
	b, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		return nil, errIconBad
	}
	return b, nil
}

// iconPage reads the start of a site's home page (at most maxIconPage bytes; the <head> is near the top) and
// returns it with the URL it ended up at, for resolving relative links.
func iconPage(ctx context.Context, client *http.Client, raw string) ([]byte, *url.URL, error) {
	ctx, cancel := context.WithTimeout(ctx, iconFetchTime)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", raw, nil)
	req.Header.Set("User-Agent", FetchUserAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml;q=0.9,*/*;q=0.1")
	res, err := client.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("fetch failed: %s", errText(err))
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return nil, nil, fmt.Errorf("fetch failed: HTTP %d", res.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, maxIconPage))
	if err != nil && len(body) == 0 {
		return nil, nil, errors.New("fetch failed while reading")
	}
	return body, res.Request.URL, nil
}

// iconLinks lists the icons a page's <head> declares, best first: <link rel="icon"> (and "shortcut icon"),
// then <link rel="apple-touch-icon">; sizes nearest iconSize from above first; SVG and mask icons skipped. URLs are
// resolved against base; only http(s) and data: ones are kept.
func iconLinks(page []byte, base *url.URL) []string {
	type cand struct {
		url   string
		score int
	}
	var cs []cand
	z := html.NewTokenizer(bytes.NewReader(page))
	for {
		tt := z.Next()
		if tt == html.ErrorToken {
			break
		}
		if tt != html.StartTagToken && tt != html.SelfClosingTagToken {
			continue
		}
		name, hasAttr := z.TagName()
		if string(name) == "body" {
			break
		}
		if string(name) != "link" || !hasAttr {
			continue
		}
		var rel, href, typ, sizes string
		for {
			k, v, more := z.TagAttr()
			switch string(k) {
			case "rel":
				rel = strings.ToLower(string(v))
			case "href":
				href = strings.TrimSpace(string(v))
			case "type":
				typ = strings.ToLower(string(v))
			case "sizes":
				sizes = strings.ToLower(string(v))
			}
			if !more {
				break
			}
		}
		fields := strings.Fields(rel)
		icon, touch := false, false
		for _, f := range fields {
			switch f {
			case "icon":
				icon = true
			case "apple-touch-icon", "apple-touch-icon-precomposed":
				touch = true
			case "mask-icon":
				icon, touch = false, false
			}
		}
		if (!icon && !touch) || href == "" || strings.Contains(typ, "svg") {
			continue
		}
		u, err := base.Parse(href)
		if err != nil {
			continue
		}
		if u.Scheme == "data" {
			if strings.Contains(strings.ToLower(href[:min(len(href), 40)]), "svg") {
				continue
			}
		} else if u.Scheme != "http" && u.Scheme != "https" {
			continue
		} else if strings.HasSuffix(strings.ToLower(u.Path), ".svg") {
			continue
		}
		// Score: a known size of at least iconSize, the closer the better; then unknown sizes; then small ones.
		score := 700
		if touch {
			score = 600 // usually 180 px: fine, but a real favicon is drawn for small sizes
		}
		known := -1
		for _, s := range strings.Fields(sizes) {
			wh := strings.SplitN(s, "x", 2)
			if len(wh) != 2 {
				continue
			}
			px, err := strconv.Atoi(wh[0])
			if err != nil || px <= 0 {
				continue
			}
			v := 300 + px
			if px >= iconSize && px <= maxIconEdge {
				v = 1000 - (px - iconSize)
			}
			known = max(known, v)
		}
		if known >= 0 {
			score = known
		}
		cs = append(cs, cand{u.String(), score})
	}
	sort.SliceStable(cs, func(i, j int) bool { return cs[i].score > cs[j].score })
	seen := map[string]bool{}
	var out []string
	for _, c := range cs {
		if !seen[c.url] {
			seen[c.url] = true
			out = append(out, c.url)
		}
	}
	return out
}

// fetchSiteIcon finds and processes one site's icon: /favicon.ico, then the home page's declared icons.
func fetchSiteIcon(ctx context.Context, client *http.Client, host string, decodes chan struct{}) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, iconHostTime)
	defer cancel()
	base := "https://" + host + "/"
	if b, err := iconGet(ctx, client, base+"favicon.ico"); err == nil {
		if out, err := processIcon(ctx, b, decodes); err == nil {
			return out, nil
		}
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	page, final, err := iconPage(ctx, client, base)
	if err != nil {
		return nil, err
	}
	tried := 0
	for _, link := range iconLinks(page, final) {
		if link == base+"favicon.ico" {
			continue // tried already
		}
		if tried == maxIconLinks || ctx.Err() != nil {
			break
		}
		tried++
		if b, err := iconGet(ctx, client, link); err == nil {
			if out, err := processIcon(ctx, b, decodes); err == nil {
				return out, nil
			}
		}
	}
	return nil, errNoIcon
}

// ---- per run --------------------------------------------------------------------------------------------------

// siteIcons fetches one run's site icons in the background and emits them as they arrive.
type siteIcons struct {
	client  *http.Client
	gate    func(context.Context) (func(), error) // the VM-wide cap (Limits.Favicons); nil = none
	decodes chan struct{}
	emit    func(proto.Event) error // safe to call from any goroutine
	ctx     context.Context
	cancel  context.CancelFunc
	slots   chan struct{}
	wg      sync.WaitGroup

	mu      sync.Mutex
	seen    map[string]bool
	started time.Time
	sites   int
	sent    int
	failed  int
	bytes   int
	fetchMs int64
	wait    time.Duration
}

// newSiteIcons starts a run's icon fetcher; nil client means none (every method is a no-op on nil).
func newSiteIcons(ctx context.Context, client *http.Client, gate func(context.Context) (func(), error), decodes chan struct{},
	emit func(proto.Event) error) *siteIcons {
	if client == nil {
		return nil
	}
	ctx, cancel := context.WithCancel(ctx)
	return &siteIcons{client: client, gate: gate, decodes: decodes, emit: emit, ctx: ctx, cancel: cancel,
		slots: make(chan struct{}, iconRunFetches), seen: map[string]bool{}}
}

// add starts fetching the icons of the sites these URLs are on that the run hasn't seen yet (at most
// maxIconHosts sites per run, first come first served).
func (s *siteIcons) add(urls ...string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, raw := range urls {
		key, host, ok := iconKey(raw)
		if !ok || s.seen[key] || len(s.seen) >= maxIconHosts || s.ctx.Err() != nil {
			continue
		}
		s.seen[key] = true
		if s.started.IsZero() {
			s.started = time.Now()
		}
		s.wg.Add(1)
		go s.fetch(key, host)
	}
}

func (s *siteIcons) fetch(key, host string) {
	defer s.wg.Done()
	select {
	case s.slots <- struct{}{}:
		defer func() { <-s.slots }()
	case <-s.ctx.Done():
		return
	}
	t0 := time.Now()
	release := func() {}
	if s.gate != nil {
		rel, err := s.gate(s.ctx)
		if err != nil {
			return
		}
		release = rel
	}
	waited := time.Since(t0)
	t1 := time.Now()
	out, err := fetchSiteIcon(s.ctx, s.client, host, s.decodes)
	release()
	if err != nil && s.ctx.Err() != nil {
		return // the run ended first: neither sent nor failed
	}
	s.mu.Lock()
	s.sites++
	s.wait += waited
	s.fetchMs += time.Since(t1).Milliseconds()
	if err != nil {
		s.failed++
		s.mu.Unlock()
		return
	}
	s.mu.Unlock()
	if s.emit(proto.Event{Type: "favicon", Favicon: &proto.Favicon{Host: key, Type: "image/png", Data: out}}) == nil {
		s.mu.Lock()
		s.sent++
		s.bytes += len(out)
		s.mu.Unlock()
	}
}

// finish waits up to wait for icons still being fetched, stops the rest, and returns the run's numbers (nil when
// no site was tried).
func (s *siteIcons) finish(wait time.Duration, step int) *proto.Metric {
	if s == nil {
		return nil
	}
	done := make(chan struct{})
	go func() { s.wg.Wait(); close(done) }()
	t := time.NewTimer(wait)
	defer t.Stop()
	select {
	case <-done:
	case <-t.C:
	case <-s.ctx.Done():
	}
	s.stop()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sites == 0 {
		return nil
	}
	return &proto.Metric{Kind: "favicons", Step: step, Ms: time.Since(s.started).Milliseconds(), Results: s.sites,
		Images: s.sent, Failed: s.failed, Bytes: s.bytes, FetchMs: s.fetchMs, WaitMs: s.wait.Milliseconds(), Outcome: "ok"}
}

// stop cancels whatever is still being fetched and waits for it to end (nothing is emitted after it returns).
func (s *siteIcons) stop() {
	if s == nil {
		return
	}
	s.cancel()
	s.wg.Wait()
}

// sourceURLs are the pages a tool call's result names, for their sites' icons: its citations, and an image
// search's source pages (or the images' own URLs).
func sourceURLs(out toolOutcome) []string {
	var us []string
	for _, c := range out.citations {
		us = append(us, c.URL)
	}
	for _, im := range out.images {
		if im.Source != "" {
			us = append(us, im.Source)
		} else {
			us = append(us, im.URL)
		}
	}
	return us
}
