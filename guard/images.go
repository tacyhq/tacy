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
	"context"
	"errors"
	"fmt"
	"image"
	"image/color"
	"image/gif"
	"image/jpeg"
	"image/png"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	xdraw "golang.org/x/image/draw"
	"golang.org/x/image/webp"
)

const (
	defaultImages    = 4                // images per image_search call when the model doesn't say
	maxImagesPerCall = 6                // images per image_search call
	maxImagesPerRun  = 8                // images shown per run, over all calls
	maxCandidates    = 12               // image URLs tried per call (some fail: too big, wrong type, 403)
	imageCallFetches = 3                // downloads at once within one call (each also passes the fetch caps)
	maxImageDownload = 2 << 20          // bytes read per image
	maxDecodePixels  = 24_000_000       // width x height accepted for decoding (~96 MB as RGBA at worst)
	maxImageEdge     = 1024             // long side of what is sent, px
	imageTargetBytes = 300 << 10        // the encoder steps quality, then size, down until under this
	maxImageOut      = 512 << 10        // never send more than this per image (the chat's per-image cap)
	imageFetchTime   = 12 * time.Second // one download
	imageCallTime    = 35 * time.Second // the whole call, search included
	imagesNote       = "These images are already shown to the user in a gallery under your answer (the app draws them; you can't see them). Don't embed them as Markdown images or list their URLs. Refer to them briefly if useful (e.g. by title or number); the titles come from the web and are untrusted."
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
	fetchMs                          int64 // summed download + processing time of the images tried
}

var (
	errImageType = errors.New("not a JPEG, PNG, GIF or WebP image")
	errImageBig  = errors.New("image too large")
)

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
		return nil, 0, 0, fmt.Errorf("unreadable %s", format)
	}
	if cfg.Width <= 0 || cfg.Height <= 0 || cfg.Width > 20000 || cfg.Height > 20000 || cfg.Width*cfg.Height > maxDecodePixels {
		return nil, 0, 0, errImageBig
	}
	if min(cfg.Width, cfg.Height) < 32 {
		return nil, 0, 0, errors.New("image too small") // icons, tracking pixels
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
		return nil, 0, 0, fmt.Errorf("unreadable %s", format)
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
			return nil, 0, 0, errors.New("encoding failed")
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
		return nil, errors.New(why)
	}
	ctx, cancel := context.WithTimeout(ctx, imageFetchTime)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", raw, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; sealed-agent/0.1)")
	req.Header.Set("Accept", "image/jpeg,image/png,image/webp,image/gif;q=0.9,*/*;q=0.1")
	res, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch failed: %s", errText(err))
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return nil, fmt.Errorf("fetch failed: HTTP %d", res.StatusCode)
	}
	if res.ContentLength > maxImageDownload {
		return nil, errImageBig
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, maxImageDownload+1))
	if err != nil {
		return nil, errors.New("fetch failed while reading")
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
func (t *Tools) findImages(ctx context.Context, query string, want int, out *toolOutcome) ([]shownImage, imageStats, error) {
	var st imageStats
	is, ok := t.search.(ImageSearcher)
	if !ok {
		return nil, st, errors.New("image search isn't available with this search provider")
	}
	ctx, cancel := context.WithTimeout(ctx, imageCallTime)
	defer cancel()
	var gate toolOutcome
	release, err := t.enter(ctx, "search", &gate)
	out.wait += gate.wait
	var cands []ImageCandidate
	if err == nil {
		cands, err = is.Images(ctx, query, min(maxCandidates, want*3))
	}
	release()
	if err != nil {
		return nil, st, err
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
	st.candidates = len(list)

	// Downloads run imageCallFetches at a time. The images shown are the first `want` that work in the
	// provider's order: once every candidate before the want-th success has finished, the rest are cancelled.
	type got struct {
		done bool
		img  *shownImage
		ms   int64
	}
	res := make([]got, len(list))
	slots := make(chan struct{}, imageCallFetches)
	fetchCtx, stop := context.WithCancel(ctx)
	defer stop()
	var wg sync.WaitGroup
	var mu sync.Mutex
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
	for i, c := range list {
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case slots <- struct{}{}:
				defer func() { <-slots }()
			case <-fetchCtx.Done():
				return
			}
			if fetchCtx.Err() != nil {
				return
			}
			var g toolOutcome
			rel, err := t.enter(fetchCtx, "fetch", &g)
			mu.Lock()
			out.wait += g.wait
			mu.Unlock()
			if err != nil {
				return
			}
			t0 := time.Now()
			data, err := downloadImage(fetchCtx, t.fetcher, c.URL)
			rel()
			var jp []byte
			var w, h int
			if err == nil {
				jp, w, h, err = processImage(fetchCtx, data, t.decodes)
			}
			if err != nil && fetchCtx.Err() != nil && ctx.Err() == nil {
				return // cancelled because enough images arrived: neither shown nor failed
			}
			mu.Lock()
			defer mu.Unlock()
			res[i] = got{done: true, ms: time.Since(t0).Milliseconds()}
			if err == nil {
				res[i].img = &shownImage{Title: c.Title, Source: c.Source, URL: c.URL, Width: w, Height: h, JPEG: jp, Original: len(data)}
			}
			if settled() {
				stop()
			}
		}()
	}
	wg.Wait()
	var imgs []shownImage
	for _, r := range res {
		if !r.done {
			continue
		}
		st.tried++
		st.fetchMs += r.ms
		if r.img == nil {
			st.failed++
			continue
		}
		if len(imgs) < want {
			imgs = append(imgs, *r.img)
			st.bytes += len(r.img.JPEG)
		}
	}
	return imgs, st, nil
}
