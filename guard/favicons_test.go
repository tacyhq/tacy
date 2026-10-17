package guard

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"hash/crc32"
	"image"
	"image/color"
	"image/gif"
	"image/png"
	"math/rand/v2"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/tacyhq/tacy/proto"
)

// Site icon tests are offline: icons are generated here and served by a local TLS server that answers for every
// host name (the test client dials it whatever the URL says).

// icoFile builds an ICO with the given entries (each a PNG or a DIB) and their directory sizes.
func icoFile(entries ...icoEntry) []byte {
	var b bytes.Buffer
	binary.Write(&b, binary.LittleEndian, [3]uint16{0, 1, uint16(len(entries))})
	off := 6 + 16*len(entries)
	for _, e := range entries {
		w := byte(e.w)
		if e.w >= 256 {
			w = 0
		}
		b.Write([]byte{w, w, 0, 0})
		binary.Write(&b, binary.LittleEndian, [2]uint16{1, uint16(e.bpp)})
		binary.Write(&b, binary.LittleEndian, [2]uint32{uint32(len(e.data)), uint32(off)})
		off += len(e.data)
	}
	for _, e := range entries {
		b.Write(e.data)
	}
	return b.Bytes()
}

type icoEntry struct {
	w, bpp int
	data   []byte
}

// dib builds an ICO's BMP entry: w x w, bpp bits per pixel, pixel(x, y) gives the color (palette index for <= 8
// bpp), and masked(x, y) the AND-mask bit (1 = transparent).
func dib(w, bpp int, pal []color.NRGBA, pixel func(x, y int) color.NRGBA, index func(x, y int) int, masked func(x, y int) bool) []byte {
	var b bytes.Buffer
	binary.Write(&b, binary.LittleEndian, uint32(40))
	binary.Write(&b, binary.LittleEndian, int32(w))
	binary.Write(&b, binary.LittleEndian, int32(2*w))
	binary.Write(&b, binary.LittleEndian, uint16(1))
	binary.Write(&b, binary.LittleEndian, uint16(bpp))
	binary.Write(&b, binary.LittleEndian, [6]uint32{0, 0, 0, 0, uint32(len(pal)), 0})
	for _, c := range pal {
		b.Write([]byte{c.B, c.G, c.R, 0})
	}
	stride := (w*bpp + 31) / 32 * 4
	for r := range w {
		y := w - 1 - r
		line := make([]byte, stride)
		for x := range w {
			switch bpp {
			case 32:
				c := pixel(x, y)
				copy(line[x*4:], []byte{c.B, c.G, c.R, c.A})
			case 24:
				c := pixel(x, y)
				copy(line[x*3:], []byte{c.B, c.G, c.R})
			case 8:
				line[x] = byte(index(x, y))
			case 4:
				line[x/2] |= byte(index(x, y)) << (4 * (1 - x%2))
			case 1:
				line[x/8] |= byte(index(x, y)) << (7 - x%8)
			}
		}
		b.Write(line)
	}
	ms := (w + 31) / 32 * 4
	for r := range w {
		y := w - 1 - r
		line := make([]byte, ms)
		for x := range w {
			if masked != nil && masked(x, y) {
				line[x/8] |= 1 << (7 - x%8)
			}
		}
		b.Write(line)
	}
	return b.Bytes()
}

func decodePNG(t *testing.T, b []byte) image.Image {
	t.Helper()
	img, err := png.Decode(bytes.NewReader(b))
	if err != nil {
		t.Fatalf("output isn't a PNG: %v", err)
	}
	return img
}

func nrgbaAt(img image.Image, x, y int) color.NRGBA {
	return color.NRGBAModel.Convert(img.At(x, y)).(color.NRGBA)
}

func TestIconKey(t *testing.T) {
	for raw, want := range map[string]string{
		"https://www.IMPAwards.com/2016/arrival.html": "impawards.com",
		"http://en.wikipedia.org/wiki/Arrival":        "en.wikipedia.org",
		"https://example.com.:443/x":                  "example.com",
	} {
		if k, _, ok := iconKey(raw); !ok || k != want {
			t.Errorf("%s: %q %v", raw, k, ok)
		}
	}
	if _, host, _ := iconKey("https://www.example.com/a"); host != "www.example.com" {
		t.Fatalf("fetch host %q (should keep www.)", host)
	}
	for _, raw := range []string{"javascript:alert(1)", "https://10.0.0.1/x", "http://[::1]/", "https://localhost/", "ftp://example.com/", "https://u:p@example.com/", "not a url"} {
		if k, _, ok := iconKey(raw); ok {
			t.Errorf("%s accepted as %q", raw, k)
		}
	}
}

func TestDecodeICO(t *testing.T) {
	red, blue := color.NRGBA{255, 0, 0, 255}, color.NRGBA{0, 0, 255, 255}
	// A PNG inside: the most common modern ICO.
	ico := icoFile(icoEntry{32, 32, pngBytes(t, 32, 32, false)})
	img, err := decodeICO(ico)
	if err != nil || img.Bounds().Dx() != 32 {
		t.Fatalf("png entry: %v", err)
	}
	// 32 bpp BMP with alpha: alpha is taken from the pixels, the mask ignored.
	half := func(x, y int) color.NRGBA {
		if x < 8 {
			return color.NRGBA{}
		}
		return red
	}
	img, err = decodeICO(icoFile(icoEntry{16, 32, dib(16, 32, nil, half, nil, func(x, y int) bool { return true })}))
	if err != nil || nrgbaAt(img, 12, 3) != red || nrgbaAt(img, 2, 3).A != 0 {
		t.Fatalf("32 bpp: %v %v %v", err, nrgbaAt(img, 12, 3), nrgbaAt(img, 2, 3))
	}
	// 24 bpp, 8, 4 and 1 bpp with a palette: the AND mask makes pixels transparent. Rows are bottom up.
	top := func(x, y int) bool { return y < 4 }
	solid := func(x, y int) color.NRGBA { return blue }
	img, err = decodeICO(icoFile(icoEntry{16, 24, dib(16, 24, nil, solid, nil, top)}))
	if err != nil || nrgbaAt(img, 5, 10) != blue || nrgbaAt(img, 5, 1).A != 0 {
		t.Fatalf("24 bpp: %v", err)
	}
	pal := []color.NRGBA{red, blue}
	stripes := func(x, y int) int { return x % 2 }
	for _, bpp := range []int{8, 4, 1} {
		img, err = decodeICO(icoFile(icoEntry{16, bpp, dib(16, bpp, pal, nil, stripes, top)}))
		if err != nil {
			t.Fatalf("%d bpp: %v", bpp, err)
		}
		if nrgbaAt(img, 0, 8) != red || nrgbaAt(img, 1, 8) != blue || nrgbaAt(img, 1, 2).A != 0 {
			t.Fatalf("%d bpp pixels: %v %v %v", bpp, nrgbaAt(img, 0, 8), nrgbaAt(img, 1, 8), nrgbaAt(img, 1, 2))
		}
	}
	// The smallest entry at least 32 wide is chosen (else the largest).
	ico = icoFile(icoEntry{16, 32, pngBytes(t, 16, 16, false)}, icoEntry{64, 32, pngBytes(t, 64, 64, false)},
		icoEntry{32, 32, pngBytes(t, 32, 32, false)}, icoEntry{48, 32, pngBytes(t, 48, 48, false)})
	if img, err := decodeICO(ico); err != nil || img.Bounds().Dx() != 32 {
		t.Fatalf("picked %v (%v)", img.Bounds(), err)
	}
	ico = icoFile(icoEntry{16, 32, pngBytes(t, 16, 16, false)}, icoEntry{24, 32, pngBytes(t, 24, 24, false)})
	if img, err := decodeICO(ico); err != nil || img.Bounds().Dx() != 24 {
		t.Fatalf("picked %v (%v)", img.Bounds(), err)
	}
}

func TestDecodeICOMalformed(t *testing.T) {
	good := icoFile(icoEntry{16, 8, dib(16, 8, []color.NRGBA{{1, 2, 3, 255}}, nil, func(x, y int) int { return 0 }, nil)})
	bad := map[string][]byte{
		"empty":         {},
		"no entries":    {0, 0, 1, 0, 0, 0},
		"cursor":        {0, 0, 2, 0, 1, 0},
		"truncated dir": {0, 0, 1, 0, 5, 0, 16, 16},
		"truncated dib": good[:len(good)-200],
	}
	// Offset past the end.
	off := append([]byte(nil), good...)
	binary.LittleEndian.PutUint32(off[6+12:], 1<<30)
	bad["offset"] = off
	// Size past the end.
	size := append([]byte(nil), good...)
	binary.LittleEndian.PutUint32(size[6+8:], uint32(len(good)))
	bad["size"] = size
	// A DIB claiming 4000 px.
	huge := append([]byte(nil), good...)
	binary.LittleEndian.PutUint32(huge[22+4:], 4000)
	bad["huge dib"] = huge
	// RLE-compressed DIB.
	rle := append([]byte(nil), good...)
	binary.LittleEndian.PutUint32(rle[22+16:], 1)
	bad["compressed"] = rle
	// A PNG entry that claims 5000 x 5000.
	bad["huge png"] = icoFile(icoEntry{0, 32, pngHeader(5000, 5000)})
	for name, b := range bad {
		if _, err := decodeICO(b); err == nil {
			t.Errorf("%s: decoded", name)
		}
	}
	// Random corruption never panics.
	r := rand.New(rand.NewPCG(3, 4))
	for range 2000 {
		b := append([]byte(nil), good...)
		for range 1 + r.IntN(8) {
			b[r.IntN(len(b))] = byte(r.IntN(256))
		}
		decodeICO(b[:r.IntN(len(b)+1)])
	}
}

func TestProcessIcon(t *testing.T) {
	ctx := context.Background()
	// Large PNG: fitted into 32x32, aspect kept, centered on transparent.
	out, err := processIcon(ctx, pngBytes(t, 128, 64, false), make(chan struct{}, 1))
	if err != nil || sniffImage(out) != "png" || len(out) > maxIconOut {
		t.Fatalf("png: %v", err)
	}
	img := decodePNG(t, out)
	if img.Bounds() != image.Rect(0, 0, 32, 32) || nrgbaAt(img, 16, 2).A != 0 || nrgbaAt(img, 16, 16).A != 255 {
		t.Fatalf("fit: %v, top %v, middle %v", img.Bounds(), nrgbaAt(img, 16, 2), nrgbaAt(img, 16, 16))
	}
	// A 16 px ICO is scaled up by whole pixels (crisp), the mask kept as transparency.
	pal := []color.NRGBA{{255, 0, 0, 255}, {0, 0, 255, 255}}
	ico := icoFile(icoEntry{16, 4, dib(16, 4, pal, nil, func(x, y int) int { return x % 2 }, func(x, y int) bool { return y == 0 })})
	out, err = processIcon(ctx, ico, nil)
	if err != nil {
		t.Fatal(err)
	}
	img = decodePNG(t, out)
	if nrgbaAt(img, 0, 5) != pal[0] || nrgbaAt(img, 2, 5) != pal[1] || nrgbaAt(img, 1, 5) != pal[0] || nrgbaAt(img, 5, 0).A != 0 || nrgbaAt(img, 5, 1).A != 0 {
		t.Fatalf("ico 16 -> 32: %v %v %v", nrgbaAt(img, 0, 5), nrgbaAt(img, 2, 5), nrgbaAt(img, 5, 0))
	}
	// GIF, WebP.
	var g bytes.Buffer
	gif.Encode(&g, image.NewPaletted(image.Rect(0, 0, 48, 48), []color.Color{color.Black}), nil)
	webpData, _ := os.ReadFile("testdata/gopher-doc.with-alpha.lossless.webp")
	for name, b := range map[string][]byte{"gif": g.Bytes(), "jpeg": noisyJPEG(t, 64, 64), "webp": webpData} {
		if out, err := processIcon(ctx, b, nil); err != nil || decodePNG(t, out).Bounds().Dx() != 32 {
			t.Fatalf("%s: %v", name, err)
		}
	}
	// Only the pixels survive: text chunks of the original are gone.
	src := pngBytes(t, 32, 32, false)
	chunk := append([]byte("tEXt"), []byte("Comment\x00tracking-id-1234")...)
	var withText bytes.Buffer
	withText.Write(src[:33]) // signature + IHDR
	binary.Write(&withText, binary.BigEndian, uint32(len(chunk)-4))
	withText.Write(chunk)
	binary.Write(&withText, binary.BigEndian, crc32.ChecksumIEEE(chunk))
	withText.Write(src[33:])
	if out, err := processIcon(ctx, withText.Bytes(), nil); err != nil || bytes.Contains(out, []byte("tracking")) {
		t.Fatalf("metadata kept or refused: %v", err)
	}
	// Refused: SVG, HTML, too many bytes, too many pixels (before decoding), blank.
	refused := map[string][]byte{
		"svg":   []byte(`<svg xmlns="http://www.w3.org/2000/svg"><rect width="32" height="32"/></svg>`),
		"html":  []byte("<html>no icon here</html>"),
		"big":   append(pngBytes(t, 32, 32, false), make([]byte, maxIconDownload)...),
		"huge":  pngHeader(4096, 4096),
		"blank": pngBytes(t, 32, 32, true)[:0],
	}
	blank := image.NewNRGBA(image.Rect(0, 0, 32, 32))
	var bb bytes.Buffer
	png.Encode(&bb, blank)
	refused["blank"] = bb.Bytes()
	for name, b := range refused {
		if _, err := processIcon(ctx, b, nil); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := processIcon(ctx, pngHeader(4096, 4096), nil); err != errIconBig {
		t.Fatalf("huge: %v", err)
	}
}

func TestIconLinks(t *testing.T) {
	base, _ := url.Parse("https://www.example.com/start/")
	page := `<!doctype html><html><head>
<link rel="stylesheet" href="/a.css">
<link rel="mask-icon" href="/mask.png">
<link rel="icon" type="image/svg+xml" href="/icon.svg">
<link rel="icon" href="/vector.SVG">
<link rel="apple-touch-icon" href="/touch.png">
<link rel="icon" href="/big.png" sizes="192x192">
<link rel="shortcut icon" href="fav.ico">
<link rel="icon" href="/i32.png" sizes="32x32">
<link rel="icon" href="/i16.png" sizes="16x16">
<link rel="icon" href="javascript:alert(1)">
<link rel="icon" href="data:image/png;base64,iVBORw0KGgo=">
</head><body><link rel="icon" href="/late.png" sizes="32x32"></body></html>`
	got := iconLinks([]byte(page), base)
	want := []string{
		"https://www.example.com/i32.png",
		"https://www.example.com/big.png",
		"https://www.example.com/start/fav.ico",
		"data:image/png;base64,iVBORw0KGgo=",
		"https://www.example.com/touch.png",
		"https://www.example.com/i16.png",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("links:\n%s", strings.Join(got, "\n"))
	}
	// data: URLs decode without a request; SVG ones are refused.
	if b, err := iconDataURL("data:image/png;base64," + base64.StdEncoding.EncodeToString(pngBytes(t, 32, 32, false))); err != nil || sniffImage(b) != "png" {
		t.Fatalf("data url: %v", err)
	}
	if _, err := iconDataURL("data:image/svg+xml;base64,PHN2Zz4="); err == nil {
		t.Fatal("svg data url accepted")
	}
	if _, err := iconDataURL("data:image/png;base64," + strings.Repeat("A", maxIconDownload*2)); err != errIconBig {
		t.Fatalf("big data url: %v", err)
	}
}

// iconWeb is a TLS server answering for every host: what each path does depends on the host's first label.
type iconWeb struct {
	srv      *httptest.Server
	mu       sync.Mutex
	hits     map[string]int // host -> requests
	inFlight atomic.Int32
	maxSeen  atomic.Int32
	delay    time.Duration
}

func newIconWeb(t *testing.T) *iconWeb {
	w := &iconWeb{hits: map[string]int{}}
	ico := icoFile(icoEntry{16, 32, pngBytes(t, 16, 16, false)})
	big := append(pngBytes(t, 32, 32, false), make([]byte, maxIconDownload+10)...)
	w.srv = httptest.NewTLSServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		n := w.inFlight.Add(1)
		defer w.inFlight.Add(-1)
		for {
			m := w.maxSeen.Load()
			if n <= m || w.maxSeen.CompareAndSwap(m, n) {
				break
			}
		}
		host := strings.TrimPrefix(strings.Split(r.Host, ":")[0], "www.")
		w.mu.Lock()
		w.hits[host]++
		w.mu.Unlock()
		if w.delay > 0 {
			time.Sleep(w.delay)
		}
		kind := strings.Split(host, ".")[0]
		switch {
		case kind == "slow":
			select {
			case <-time.After(10 * time.Second):
			case <-r.Context().Done():
			}
		case kind == "ico" && r.URL.Path == "/favicon.ico":
			rw.Header().Set("Content-Type", "image/x-icon")
			rw.Write(ico)
		case kind == "linked" && r.URL.Path == "/":
			fmt.Fprint(rw, `<html><head><link rel="icon" href="/static/icon.svg" type="image/svg+xml"><link rel="icon" href="/static/icon-32.png" sizes="32x32"></head><body>hi</body></html>`)
		case kind == "linked" && r.URL.Path == "/static/icon-32.png":
			rw.Write(pngBytes(t, 32, 32, false))
		case kind == "big" && r.URL.Path == "/favicon.ico":
			rw.(http.Flusher).Flush() // no Content-Length: the read limit catches it
			rw.Write(big)
		case kind == "loop":
			http.Redirect(rw, r, fmt.Sprintf("/hop%d", rand.IntN(1000)), http.StatusFound)
		case kind == "svg" && r.URL.Path == "/favicon.ico":
			rw.Write([]byte(`<svg xmlns="http://www.w3.org/2000/svg"/>`))
		case kind == "private" && r.URL.Path == "/favicon.ico":
			http.Redirect(rw, r, "https://10.1.2.3/favicon.ico", http.StatusFound)
		default:
			http.NotFound(rw, r)
		}
	}))
	t.Cleanup(w.srv.Close)
	return w
}

// client dials the test server for every host (and trusts its certificate for any name), behind the given
// connection check (nil: none).
func (w *iconWeb) client(control func(string, string, syscall.RawConn) error) *http.Client {
	c := newFetcher(control)
	tr := c.Transport.(*http.Transport)
	addr := w.srv.Listener.Addr().String()
	d := &net.Dialer{Timeout: 5 * time.Second}
	tr.DialContext = func(ctx context.Context, network, a string) (net.Conn, error) {
		if control != nil {
			if err := control(network, a, nil); err != nil {
				return nil, err
			}
		}
		return d.DialContext(ctx, network, addr)
	}
	tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	return c
}

func (w *iconWeb) count(host string) int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.hits[host]
}

func TestFetchSiteIcon(t *testing.T) {
	web := newIconWeb(t)
	c := web.client(nil)
	ctx := context.Background()
	out, err := fetchSiteIcon(ctx, c, "ico.example", nil)
	if err != nil || decodePNG(t, out).Bounds().Dx() != 32 || web.count("ico.example") != 1 {
		t.Fatalf("favicon.ico: %v, %d requests", err, web.count("ico.example"))
	}
	// No /favicon.ico: the home page's <link rel="icon"> (SVG skipped).
	if out, err := fetchSiteIcon(ctx, c, "linked.example", nil); err != nil || len(out) == 0 || web.count("linked.example") != 3 {
		t.Fatalf("linked: %v, %d requests", err, web.count("linked.example"))
	}
	// Refused: more than maxIconDownload bytes, SVG, no icon, a redirect loop (stops at 5), a redirect to a private
	// address.
	for _, host := range []string{"big.example", "svg.example", "none.example", "loop.example"} {
		if _, err := fetchSiteIcon(ctx, c, host, nil); err == nil {
			t.Errorf("%s: got an icon", host)
		}
	}
	if n := web.count("loop.example"); n > 2*6 {
		t.Fatalf("redirect loop followed %d times", n)
	}
	guarded := web.client(func(network, address string, _ syscall.RawConn) error {
		if strings.HasPrefix(address, "10.") {
			return fmt.Errorf("address not public")
		}
		return nil
	})
	if _, err := fetchSiteIcon(ctx, guarded, "private.example", nil); err == nil {
		t.Fatal("followed a redirect to a private address")
	}
	// The real dialer refuses the local server (SSRF guard shared with fetch_page).
	if _, err := iconGet(ctx, newFetcher(publicOnly), web.srv.URL+"/favicon.ico"); err == nil || !strings.Contains(err.Error(), "not allowed") {
		t.Fatalf("local address fetched: %v", err)
	}
	// A server that never answers: given up after iconFetchTime per request, iconHostTime per site.
	t0 := time.Now()
	if _, err := fetchSiteIcon(ctx, c, "slow.example", nil); err == nil {
		t.Fatal("slow: got an icon")
	}
	if d := time.Since(t0); d > iconHostTime+time.Second {
		t.Fatalf("slow site took %v", d)
	}
}

// manySites is a search provider whose results are on n distinct sites (kind.site<i>.example).
type manySites struct {
	n    int
	kind string
}

func (m *manySites) Name() string { return "fake" }

func (m *manySites) Search(_ context.Context, q string, n int) ([]SearchResult, error) {
	var rs []SearchResult
	for i := range m.n {
		rs = append(rs, SearchResult{Title: fmt.Sprint("Result ", i), URL: fmt.Sprintf("https://www.%s.site%d.example/page", m.kind, i)})
	}
	return rs, nil
}

func TestAgentSiteIcons(t *testing.T) {
	web := newIconWeb(t)
	web.delay = 20 * time.Millisecond
	a, _, _ := newTestAgent(t,
		toolCallSSE("c1", "web_search", `{"query":"posters","count":8}`),
		toolCallSSE("c2", "web_search", `{"query":"more posters","count":8}`),
		textSSE("Here [1]."))
	sites := &manySites{n: 12, kind: "ico"}
	a.newTools = func() *Tools { return &Tools{search: sites, fetcher: newFetcher(nil)} }
	a.icons = web.client(nil)
	a.gates = newToolGates(DefaultLimits)
	evs := collect(t, a, proto.RunRequest{Messages: []proto.Message{{Role: "user", Content: "posters"}}})
	// Two searches of 12 sites each, the same sites: 12 distinct sites, one icon each.
	var icons []proto.Event
	firstResult, done, metric := -1, -1, -1
	for i, e := range evs {
		switch e.Type {
		case "favicon":
			icons = append(icons, e)
		case "tool_result":
			if firstResult < 0 {
				firstResult = i
			}
		case "done":
			done = i
		case "metrics":
			if e.Metrics.Kind == "favicons" {
				metric = i
			}
		}
	}
	if len(icons) != 12 {
		t.Fatalf("%d icons: %s", len(icons), types(evs))
	}
	seen := map[string]bool{}
	for _, e := range icons {
		f := e.Favicon
		if f == nil || f.Type != "image/png" || !strings.HasPrefix(f.Host, "ico.site") || strings.HasPrefix(f.Host, "www.") || seen[f.Host] {
			t.Fatalf("icon %+v", f)
		}
		seen[f.Host] = true
		if decodePNG(t, f.Data).Bounds().Dx() != 32 {
			t.Fatal("not 32x32")
		}
	}
	for i, e := range evs {
		if e.Type == "favicon" && i < firstResult {
			t.Fatal("icon before the tool result that named its site")
		}
	}
	if metric < 0 || metric > done {
		t.Fatalf("favicons metric missing or after done: %s", types(evs))
	}
	m := evs[metric].Metrics
	if m.Results != 12 || m.Images != 12 || m.Failed != 0 || m.Bytes <= 0 || m.Outcome != "ok" {
		t.Fatalf("metric %+v", m)
	}
	b, _ := json.Marshal(evs[metric])
	if strings.Contains(string(b), "example") || strings.Contains(string(b), "http") {
		t.Fatalf("metrics event carries hosts: %s", b)
	}
	// At most iconRunFetches sites at once (each site is one request here).
	if web.maxSeen.Load() > iconRunFetches {
		t.Fatalf("%d requests at once", web.maxSeen.Load())
	}
}

func TestAgentSiteIconCaps(t *testing.T) {
	web := newIconWeb(t)
	a, _, _ := newTestAgent(t, toolCallSSE("c1", "web_search", `{"query":"x"}`), textSSE("ok"))
	a.newTools = func() *Tools { return &Tools{search: &manySites{n: 40, kind: "none"}, fetcher: newFetcher(nil)} }
	a.icons = web.client(nil)
	evs := collect(t, a, proto.RunRequest{Messages: []proto.Message{{Role: "user", Content: "q"}}})
	// No site has an icon: the run still ends normally, and at most maxIconHosts sites were tried.
	if evs[len(evs)-1].Type != "done" {
		t.Fatalf("events %s", types(evs))
	}
	web.mu.Lock()
	sitesTried := len(web.hits)
	web.mu.Unlock()
	if sitesTried > maxIconHosts {
		t.Fatalf("%d sites contacted", sitesTried)
	}
	for _, e := range evs {
		if e.Type == "favicon" {
			t.Fatal("an icon for a site without one")
		}
		if e.Type == "metrics" && e.Metrics.Kind == "favicons" && (e.Metrics.Failed != e.Metrics.Results || e.Metrics.Images != 0) {
			t.Fatalf("metric %+v", e.Metrics)
		}
	}
}

func TestAgentSiteIconsDontHoldTheAnswer(t *testing.T) {
	web := newIconWeb(t)
	a, _, _ := newTestAgent(t, toolCallSSE("c1", "web_search", `{"query":"x"}`), textSSE("ok"))
	a.newTools = func() *Tools { return &Tools{search: &manySites{n: 3, kind: "slow"}, fetcher: newFetcher(nil)} }
	a.icons = web.client(nil)
	t0 := time.Now()
	var mu sync.Mutex
	var evs []proto.Event
	r := proto.RunRequest{Messages: []proto.Message{{Role: "user", Content: "q"}}}
	validate(&r)
	a.Run(context.Background(), &r, func(e proto.Event) error {
		mu.Lock()
		evs = append(evs, e)
		mu.Unlock()
		return nil
	})
	// Sites that never answer: the run ends iconEndWait after the answer, and nothing is emitted after Run returns.
	if d := time.Since(t0); d > iconEndWait+2*time.Second {
		t.Fatalf("run took %v", d)
	}
	mu.Lock()
	n := len(evs)
	last := evs[n-1].Type
	mu.Unlock()
	if last != "done" {
		t.Fatalf("last event %s", last)
	}
	time.Sleep(200 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	if len(evs) != n {
		t.Fatal("events after Run returned")
	}
}

func TestSourceURLs(t *testing.T) {
	out := toolOutcome{citations: []proto.Citation{{URL: "https://a.example/1"}}, images: []shownImage{{Source: "https://b.example/p", URL: "https://cdn.example/i.jpg"}, {URL: "https://c.example/i.png"}}}
	if got := strings.Join(sourceURLs(out), " "); got != "https://a.example/1 https://b.example/p https://c.example/i.png" {
		t.Fatal(got)
	}
}
