package guard

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"hash/crc32"
	"image"
	"image/color"
	"image/gif"
	"image/jpeg"
	"image/png"
	"math/rand/v2"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"syscall"
	"testing"

	"github.com/tacyhq/tacy/proto"
)

// Image tests are offline: images are generated here (WebP comes from x/image's test files, BSD-3-Clause) and
// served by a local server.

func pngBytes(t *testing.T, w, h int, transparent bool) []byte {
	t.Helper()
	img := image.NewNRGBA(image.Rect(0, 0, w, h))
	for y := range h {
		for x := range w {
			a := uint8(255)
			if transparent && x < w/2 {
				a = 0
			}
			img.Set(x, y, color.NRGBA{uint8(x), uint8(y), 200, a})
		}
	}
	var b bytes.Buffer
	png.Encode(&b, img)
	return b.Bytes()
}

// noisyJPEG is a photo-like image that compresses badly: random pixels.
func noisyJPEG(t *testing.T, w, h int) []byte {
	t.Helper()
	r := rand.New(rand.NewPCG(1, 2))
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	for i := range img.Pix {
		img.Pix[i] = uint8(r.IntN(256))
	}
	var b bytes.Buffer
	jpeg.Encode(&b, img, &jpeg.Options{Quality: 95})
	return b.Bytes()
}

// pngHeader is a PNG signature and IHDR claiming w x h, with no pixel data: DecodeConfig reads it, Decode can't.
func pngHeader(w, h uint32) []byte {
	var b bytes.Buffer
	b.WriteString("\x89PNG\r\n\x1a\n")
	ihdr := make([]byte, 13)
	binary.BigEndian.PutUint32(ihdr[0:], w)
	binary.BigEndian.PutUint32(ihdr[4:], h)
	ihdr[8], ihdr[9] = 8, 6 // 8-bit RGBA
	binary.Write(&b, binary.BigEndian, uint32(13))
	chunk := append([]byte("IHDR"), ihdr...)
	b.Write(chunk)
	binary.Write(&b, binary.BigEndian, crc32.ChecksumIEEE(chunk))
	return b.Bytes()
}

func TestSniffImage(t *testing.T) {
	webpData, _ := os.ReadFile("testdata/blue-purple-pink.lossy.webp")
	cases := map[string][]byte{
		"png":  pngBytes(t, 40, 40, false),
		"jpeg": noisyJPEG(t, 40, 40),
		"gif":  []byte("GIF89a......"),
		"webp": webpData,
		"":     []byte(`<svg xmlns="http://www.w3.org/2000/svg"></svg>`),
	}
	for want, b := range cases {
		if got := sniffImage(b); got != want {
			t.Errorf("sniff %q: got %q", want, got)
		}
	}
	for _, b := range [][]byte{[]byte("<html><body>not an image"), []byte("BM\x00\x00"), nil, []byte("RIFF....WAVE")} {
		if sniffImage(b) != "" {
			t.Errorf("%q sniffed as an image", b)
		}
	}
}

func TestProcessImage(t *testing.T) {
	ctx := context.Background()
	// A large PNG with transparency: scaled to 1024 on the long side, flattened onto white, JPEG out.
	out, w, h, err := processImage(ctx, pngBytes(t, 2048, 1024, true), make(chan struct{}, 1))
	if err != nil || w != 1024 || h != 512 || sniffImage(out) != "jpeg" {
		t.Fatalf("png: %v %dx%d %q", err, w, h, sniffImage(out))
	}
	dec, err := jpeg.Decode(bytes.NewReader(out))
	if err != nil || dec.Bounds().Dx() != 1024 {
		t.Fatalf("output doesn't decode: %v", err)
	}
	if r, g, b, _ := dec.At(10, 10).RGBA(); r>>8 < 245 || g>>8 < 245 || b>>8 < 245 {
		t.Fatalf("transparent area isn't white: %d %d %d", r>>8, g>>8, b>>8)
	}
	// Nothing of the original survives: a JPEG with an EXIF segment comes back without it.
	src := noisyJPEG(t, 300, 200)
	exif := append([]byte{0xff, 0xe1, 0x00, 0x16}, []byte("Exif\x00\x00GPS 38.7N 9.1W!!")...)
	withExif := append(append([]byte{0xff, 0xd8}, exif...), src[2:]...)
	if !bytes.Contains(withExif, []byte("Exif")) {
		t.Fatal("test image has no EXIF")
	}
	out, w, h, err = processImage(ctx, withExif, nil)
	if err != nil || w != 300 || h != 200 || bytes.Contains(out, []byte("Exif")) || bytes.Contains(out, []byte("GPS")) {
		t.Fatalf("exif: %v %dx%d, exif kept: %v", err, w, h, bytes.Contains(out, []byte("Exif")))
	}
	// Noise that compresses badly still ends under the target (quality, then size steps).
	out, w, _, err = processImage(ctx, noisyJPEG(t, 1600, 1200), nil)
	if err != nil || len(out) > imageTargetBytes || w > maxImageEdge {
		t.Fatalf("noisy: %v, %d bytes, width %d", err, len(out), w)
	}
	// GIF: first frame.
	var g bytes.Buffer
	pal := image.NewPaletted(image.Rect(0, 0, 64, 48), []color.Color{color.Black, color.White})
	gif.EncodeAll(&g, &gif.GIF{Image: []*image.Paletted{pal, pal}, Delay: []int{1, 1}})
	if _, w, h, err := processImage(ctx, g.Bytes(), nil); err != nil || w != 64 || h != 48 {
		t.Fatalf("gif: %v %dx%d", err, w, h)
	}
	// WebP, lossy and lossless with alpha.
	for _, f := range []string{"testdata/blue-purple-pink.lossy.webp", "testdata/gopher-doc.with-alpha.lossless.webp"} {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if out, _, _, err := processImage(ctx, b, nil); err != nil || sniffImage(out) != "jpeg" {
			t.Fatalf("%s: %v", f, err)
		}
	}
	// Refused: not an image, a bomb (huge dimensions, checked before decoding), tiny, truncated.
	refused := map[string][]byte{
		"svg":       []byte(`<svg xmlns="http://www.w3.org/2000/svg" width="10000" height="10000"/>`),
		"html":      []byte("<!doctype html><title>x</title>"),
		"bomb":      pngHeader(30000, 30000),
		"wide bomb": pngHeader(20000, 1300),
		"tiny":      pngBytes(t, 16, 16, false),
		"truncated": pngBytes(t, 100, 100, false)[:60],
	}
	for name, b := range refused {
		if _, _, _, err := processImage(ctx, b, nil); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestImageURLRefused(t *testing.T) {
	for _, u := range []string{"ftp://example.com/a.jpg", "file:///etc/passwd", "/relative.png", "https://bob:pw@example.com/a.png",
		"https://example.com/a.png?email=jane@example.com", "javascript:alert(1)", "data:image/png;base64,AAAA"} {
		if imageURLRefused(u) == "" {
			t.Errorf("%s allowed", u)
		}
	}
	if why := imageURLRefused("https://cdn.example.com/posters/arrival-2016.jpg?w=800"); why != "" {
		t.Errorf("good URL refused: %s", why)
	}
}

func TestDownloadImage(t *testing.T) {
	big := bytes.Repeat([]byte{0xff}, maxImageDownload+10)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ok.png":
			w.Header().Set("Content-Type", "image/png")
			w.Write(pngBytes(t, 64, 64, false))
		case "/big.jpg": // no Content-Length (chunked): the read limit catches it
			w.Header().Set("Content-Type", "image/jpeg")
			w.(http.Flusher).Flush()
			w.Write(big)
		case "/lying.png": // says PNG, is HTML
			w.Header().Set("Content-Type", "image/png")
			w.Write([]byte("<html>gotcha</html>"))
		case "/redirect":
			http.Redirect(w, r, "/ok.png", http.StatusFound)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	ctx := context.Background()
	open := newFetcher(func(string, string, syscall.RawConn) error { return nil })
	if b, err := downloadImage(ctx, open, srv.URL+"/ok.png"); err != nil || sniffImage(b) != "png" {
		t.Fatalf("ok: %v", err)
	}
	if b, err := downloadImage(ctx, open, srv.URL+"/redirect"); err != nil || sniffImage(b) != "png" {
		t.Fatalf("redirect: %v", err)
	}
	if _, err := downloadImage(ctx, open, srv.URL+"/big.jpg"); err != errImageBig {
		t.Fatalf("big: %v", err)
	}
	if _, err := downloadImage(ctx, open, srv.URL+"/missing.png"); err == nil || !strings.Contains(err.Error(), "404") {
		t.Fatalf("404: %v", err)
	}
	b, err := downloadImage(ctx, open, srv.URL+"/lying.png")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := processImage(ctx, b, nil); err != errImageType {
		t.Fatalf("a Content-Type that lies was trusted: %v", err)
	}
	// The real dialer refuses the local server (SSRF guard shared with fetch_page).
	if _, err := downloadImage(ctx, newFetcher(publicOnly), srv.URL+"/ok.png"); err == nil || !strings.Contains(err.Error(), "not allowed") {
		t.Fatalf("local address fetched: %v", err)
	}
}

func TestParseTavilyImages(t *testing.T) {
	raw := []byte(`{"images":[
	  {"url":"https://img.example/a.jpg","title":"Arrival Movie Poster - IMP Awards","description":"An alien ship"},
	  {"url":"https://img.example/b.jpg","title":"Some page","description":"desc b"},
	  {"url":"ftp://img.example/c.jpg","title":"bad scheme"},
	  "https://img.example/plain.jpg"],
	 "results":[
	  {"title":"Arrival Movie Poster - IMP Awards","url":"https://www.impawards.com/2016/arrival.html","images":[
	    {"url":"https://www.impawards.com/logo.png","description":null},
	    {"url":"https://www.impawards.com/logo2.png","description":"Site logo"},
	    {"url":"https://www.impawards.com/2016/posters/arrival.jpg","description":"Arrival Movie Poster"}]},
	  {"title":"Other","url":"https://other.example/page","images":[{"url":"https://img.example/b.jpg","description":"dup"}]}]}`)
	cs, err := parseTavilyImages(raw, 10)
	if err != nil {
		t.Fatal(err)
	}
	want := []ImageCandidate{
		{"https://img.example/a.jpg", "Arrival Movie Poster - IMP Awards", "https://www.impawards.com/2016/arrival.html"}, // by page title
		{"https://img.example/b.jpg", "Some page", "https://other.example/page"},                                          // by URL
		{"https://img.example/plain.jpg", "", ""},
		{"https://www.impawards.com/2016/posters/arrival.jpg", "Arrival Movie Poster", "https://www.impawards.com/2016/arrival.html"},
		{"https://img.example/b.jpg", "dup", "https://other.example/page"}, // deduped later, by findImages
	}
	if fmt.Sprint(cs) != fmt.Sprint(want) {
		t.Fatalf("got  %v\nwant %v", cs, want)
	}
	if cs, _ := parseTavilyImages(raw, 2); len(cs) != 2 {
		t.Fatalf("count not applied: %d", len(cs))
	}
}

// imageWeb serves images for the agent tests: /img/N.png is a valid image, /bad/N an HTML page.
type imageWeb struct {
	mu   sync.Mutex
	hits int
}

func (s *imageWeb) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.hits++
	s.mu.Unlock()
	if strings.HasPrefix(r.URL.Path, "/img/") {
		w.Header().Set("Content-Type", "image/png")
		w.Write(pngCache)
		return
	}
	w.Write([]byte("<html>no</html>"))
}

var pngCache []byte

// imageSearch is a fake provider for the agent loop: web results, and image candidates on base.
type imageSearch struct {
	fakeSearch
	base    string
	queries []string
}

func (f *imageSearch) Images(_ context.Context, q string, n int) ([]ImageCandidate, error) {
	f.mu.Lock()
	f.queries = append(f.queries, q)
	f.mu.Unlock()
	var cs []ImageCandidate
	for i := range n {
		u := fmt.Sprintf("%s/img/%d.png", f.base, i)
		if i == 1 {
			u = f.base + "/bad/1" // fails: not an image
		}
		cs = append(cs, ImageCandidate{URL: u, Title: fmt.Sprintf("Poster %d", i), Source: fmt.Sprintf("https://posters.example/%d", i)})
	}
	return cs, nil
}

func newImageAgent(t *testing.T, responses ...string) (*Agent, *fakeModel, *imageSearch, *imageWeb) {
	if pngCache == nil {
		pngCache = pngBytes(t, 300, 450, false)
	}
	a, fm, _ := newTestAgent(t, responses...)
	web := &imageWeb{}
	srv := httptest.NewServer(web)
	t.Cleanup(srv.Close)
	is := &imageSearch{base: srv.URL}
	a.gates = newToolGates(DefaultLimits)
	a.newTools = func() *Tools { return &Tools{search: is, fetcher: newFetcher(nil)} }
	return a, fm, is, web
}

// switchover: the model calls the tool by the name it now sees (web_fetch, web_images: docs/20); people's
// events keep fetch_page and image_search.
func TestAgentImageSearch(t *testing.T) {
	a, fm, is, _ := newImageAgent(t,
		toolCallSSE("c1", "web_images", `{"query":"Arrival poster for jane@example.com","count":3}`),
		textSSE("Here are three posters."))
	evs := collect(t, a, proto.RunRequest{Space: testSpace, Permissions: AllowAll(), Messages: []proto.Message{{Role: "user", Content: "show me posters of Arrival"}}})
	if got := types(evs); got != "meta,step,usage,metrics,tool_call,image,image,image,tool_result,metrics,step,text,usage,metrics,done" {
		t.Fatalf("events %s", got)
	}
	if len(is.queries) != 1 || is.queries[0] != "Arrival poster for [email]" {
		t.Fatalf("image query %q", is.queries)
	}
	// Images in candidate order (the failing one skipped), re-encoded JPEGs with their sources.
	var titles []string
	for _, e := range evs[5:8] {
		im := e.Image
		if e.ID != "c1" || im == nil || im.Type != "image/jpeg" || sniffImage(im.Data) != "jpeg" || im.Width != 300 || im.Height != 450 ||
			!strings.HasPrefix(im.Source, "https://posters.example/") || !strings.HasSuffix(im.URL, ".png") {
			t.Fatalf("image event %+v", e)
		}
		titles = append(titles, fmt.Sprint(im.Index, ":", im.Title))
	}
	if strings.Join(titles, ",") != "1:Poster 0,2:Poster 2,3:Poster 3" {
		t.Fatalf("order %v", titles)
	}
	// The model gets titles and sources only (no bytes), and is told the user sees them.
	var res struct {
		Note   string
		Shown  int
		Images []struct {
			N             int
			Title, Source string
		}
	}
	json.Unmarshal(evs[8].Result, &res)
	if res.Shown != 3 || len(res.Images) != 3 || !strings.Contains(res.Note, "already shown to the user") || len(evs[8].Result) > 2000 {
		t.Fatalf("tool result %s", evs[8].Result)
	}
	if !strings.Contains(fm.requests[0]["messages"].([]any)[0].(map[string]any)["content"].(string), "Never say you can't display") {
		t.Fatal("system prompt doesn't mention images")
	}
	// Metrics: numbers only.
	m := evs[9].Metrics
	if m.Kind != "images" || m.Images != 3 || m.Results < 4 || m.Failed < 1 || m.Bytes <= 0 || m.Outcome != "ok" || m.Provider != "fake" {
		t.Fatalf("metric %+v", m)
	}
	b, _ := json.Marshal(evs[9])
	if strings.Contains(string(b), "http") || strings.Contains(string(b), "Poster") || strings.Contains(string(b), "Arrival") {
		t.Fatalf("metrics event carries content: %s", b)
	}
}

// switchover: the model calls the tool by the name it now sees (web_fetch, web_images: docs/20); people's
// events keep fetch_page and image_search.
func TestAgentImageRunCap(t *testing.T) {
	a, _, _, _ := newImageAgent(t,
		toolCallSSE("c1", "web_images", `{"query":"a","count":6}`),
		toolCallSSE("c2", "web_images", `{"query":"b","count":6}`),
		toolCallSSE("c3", "web_images", `{"query":"c","count":6}`),
		textSSE("done"))
	evs := collect(t, a, proto.RunRequest{Space: testSpace, Permissions: AllowAll(), Messages: []proto.Message{{Role: "user", Content: "lots of pictures"}}})
	per := map[string]int{}
	for _, e := range evs {
		if e.Type == "image" {
			per[e.ID]++
		}
	}
	if per["c1"] != 6 || per["c2"] != 2 || per["c3"] != 0 {
		t.Fatalf("images per call %v (cap %d per run)", per, maxImagesPerRun)
	}
	var last proto.Event
	for _, e := range evs {
		if e.Type == "tool_result" && e.ID == "c3" {
			last = e
		}
	}
	if !strings.Contains(string(last.Result), "most images") {
		t.Fatalf("third call: %s", last.Result)
	}
}

// switchover: the model calls the tool by the name it now sees (web_fetch, web_images: docs/20); people's
// events keep fetch_page and image_search.
func TestAgentImageSearchUnsupportedProvider(t *testing.T) {
	a, _, _ := newTestAgent(t, toolCallSSE("c1", "web_images", `{"query":"x"}`), textSSE("ok"))
	// A provider without image search (app/'s test fake had none; the guard's fakeSearch has one).
	a.newTools = func() *Tools {
		return &Tools{search: struct{ SearchProvider }{&fakeSearch{}}, fetcher: newFetcher(nil)}
	}
	evs := collect(t, a, proto.RunRequest{Space: testSpace, Permissions: AllowAll(), Messages: []proto.Message{{Role: "user", Content: "q"}}})
	for _, e := range evs {
		if e.Type == "tool_result" && !strings.Contains(string(e.Result), "isn't available") {
			t.Fatalf("result %s", e.Result)
		}
	}
}

// With the quarantined reader on, an image search gives the model no titles (the provider's and pages' text) and
// only each image's page host; people still see the titles in the gallery (docs/27 section 5).
func TestAgentImageSearchReaderTitles(t *testing.T) {
	a, fm, is, _ := newImageAgent(t,
		toolCallSSE("c1", "web_images", `{"query":"Arrival poster","count":3}`),
		textSSE("Here are three posters."))
	a.newTools = func() *Tools { return &Tools{search: is, fetcher: newFetcher(nil), reader: true} }
	evs := collect(t, a, proto.RunRequest{Space: testSpace, Permissions: AllowAll(), Messages: []proto.Message{{Role: "user", Content: "show me posters of Arrival"}}})
	var res *proto.Event
	for i := range evs {
		if evs[i].Type == "tool_result" {
			res = &evs[i]
		}
		if evs[i].Type == "image" && !strings.HasPrefix(evs[i].Image.Title, "Poster") {
			t.Fatalf("gallery title %+v", evs[i].Image)
		}
	}
	if res == nil || strings.Contains(string(res.Result), "Poster") || strings.Contains(string(res.Result), "posters.example/") ||
		!strings.Contains(string(res.Result), `"source":"posters.example"`) {
		t.Fatalf("tool result %v", res)
	}
	b, _ := json.Marshal(fm.requests)
	if strings.Contains(string(b), "Poster 0") {
		t.Fatal("an image title reached the model")
	}
}

// Every fetch from the VM's web side says it is a Tacy agent: pages (agent_test.go), images, site icons and
// the home page an icon is looked up on. No browser disguise, no URL.
func TestFetchUserAgent(t *testing.T) {
	if FetchUserAgent != "Mozilla/5.0 (compatible; Tacy/1.0)" {
		t.Fatalf("FetchUserAgent = %q", FetchUserAgent)
	}
	var mu sync.Mutex
	got := map[string]string{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		got[r.URL.Path] = r.Header.Get("User-Agent")
		mu.Unlock()
		if r.URL.Path == "/" {
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte(`<html><head><link rel="icon" href="/favicon.png"></head></html>`))
			return
		}
		w.Header().Set("Content-Type", "image/png")
		w.Write(pngBytes(t, 32, 32, false))
	}))
	defer srv.Close()
	ctx := context.Background()
	open := newFetcher(func(string, string, syscall.RawConn) error { return nil })
	if _, err := downloadImage(ctx, open, srv.URL+"/pic.png"); err != nil {
		t.Fatal(err)
	}
	if _, err := iconGet(ctx, open, srv.URL+"/favicon.png"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := iconPage(ctx, open, srv.URL+"/"); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	for _, p := range []string{"/pic.png", "/favicon.png", "/"} {
		if got[p] != FetchUserAgent {
			t.Errorf("%s sent User-Agent %q", p, got[p])
		}
	}
}
