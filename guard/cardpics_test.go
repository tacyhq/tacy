package guard

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/tacyhq/tacy/proto"
	"github.com/tacyhq/tacy/vault"
	"golang.org/x/net/html"
)

func picURLs(cs []picCand) []string {
	var out []string
	for _, c := range cs {
		out = append(out, c.url)
	}
	return out
}

func pagePics(t *testing.T, base, src string) []picCand {
	t.Helper()
	doc, err := html.Parse(strings.NewReader(src))
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(base)
	return pagePictures(doc, u)
}

func TestPagePicturesMetadata(t *testing.T) {
	page := `<html><head>
<meta property="og:image" content="/media/q6max-front.jpg">
<meta property="og:image:secure_url" content="https://cdn.keychron.example/media/q6max-front.jpg">
<meta property="og:image:alt" content="Keychron Q6 Max, front">
<meta name="twitter:image" content="//cdn.keychron.example/tw/q6max.png">
<meta property="og:image" content="javascript:alert(1)">
<meta name="twitter:image" content="data:image/png;base64,AAAA">
<link rel="image_src" href="images/q6max-side.webp">
</head><body><p>Q6 Max</p></body></html>`
	got := pagePics(t, "https://www.keychron.example/products/q6-max?variant=1", page)
	want := []string{
		"https://cdn.keychron.example/media/q6max-front.jpg", // og:image:secure_url first
		"https://www.keychron.example/media/q6max-front.jpg", // og:image, resolved against the page
		"https://cdn.keychron.example/tw/q6max.png",          // twitter:image, protocol-relative takes the page's scheme
	}
	if !slices.Equal(picURLs(got), want) {
		t.Fatalf("pictures %q, want %q", picURLs(got), want)
	}
	if got[0].kind != picPage || got[0].alt != "Keychron Q6 Max, front" {
		t.Fatalf("first %+v", got[0])
	}
	// An http page keeps http (as image_search does: no scheme upgrades).
	got = pagePics(t, "http://shop.example/p/1", `<meta property="og:image" content="/a.jpg">`)
	if !slices.Equal(picURLs(got), []string{"http://shop.example/a.jpg"}) {
		t.Fatalf("http page: %q", picURLs(got))
	}
}

func TestPagePicturesJSONLD(t *testing.T) {
	ld := func(s string) string { return `<script type="application/ld+json">` + s + `</script>` }
	cases := []struct {
		name, page string
		want       []string
	}{
		{"string", ld(`{"@type":"Product","name":"Flow","image":"/img/flow.jpg"}`) + `<meta property="og:image" content="/og.jpg">`,
			[]string{"https://lofree.example/img/flow.jpg", "https://lofree.example/og.jpg"}},
		{"array", ld(`{"@context":"https://schema.org","@type":"Product","image":["https://cdn.example/1.jpg","https://cdn.example/2.jpg"]}`),
			[]string{"https://cdn.example/1.jpg", "https://cdn.example/2.jpg"}},
		{"ImageObject in @graph", ld(`{"@graph":[{"@type":"WebPage"},{"@type":["Product"],"image":{"@type":"ImageObject","url":"a/b.png"}}]}`),
			[]string{"https://lofree.example/p/a/b.png"}},
		{"contentUrl list", ld(`[{"@type":"Product","image":[{"contentUrl":"https://cdn.example/c.webp"}]}]`),
			[]string{"https://cdn.example/c.webp"}},
		{"offer's image", ld(`{"@type":"Product","offers":[{"@type":"Offer","price":"99"},{"@type":"Offer","image":"/offer.jpg"}]}`),
			[]string{"https://lofree.example/offer.jpg"}},
		// A roundup lists several products: none of their pictures is the page's own.
		{"roundup", ld(`[{"@type":"Product","image":"/a.jpg"},{"@type":"Product","image":"/b.jpg"}]`) + `<meta property="og:image" content="/hero.jpg">`,
			[]string{"https://lofree.example/hero.jpg"}},
		{"bad schemes and logos", ld(`{"@type":"Product","image":["javascript:void(0)","data:image/jpeg;base64,AA","/brand-logo.png","/img/x.svg","https://u:p@cdn.example/x.jpg","/ok.jpg"]}`),
			[]string{"https://lofree.example/ok.jpg"}},
		{"not JSON", ld(`{"@type":"Product","image":`), nil},
	}
	for _, c := range cases {
		got := picURLs(pagePics(t, "https://lofree.example/p/flow", c.page))
		if !slices.Equal(got, c.want) {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
}

func TestPicURLRefused(t *testing.T) {
	for _, u := range []string{"https://a.example/static/logo.png", "https://a.example/img/SiteLogo_white.jpg",
		"https://a.example/favicon-32x32.png", "https://a.example/assets/sprite.webp", "https://a.example/icons/cart.png",
		"https://a.example/x/icon.png", "https://a.example/a.svg", "https://a.example/a.SVG?v=2", "https://a.example/favicon.ico",
		"https://a.example/banner/top.jpg", "ftp://a.example/a.jpg", "javascript:alert(1)", "data:image/png;base64,AA"} {
		if picURLRefused(u) == "" {
			t.Errorf("%s accepted", u)
		}
	}
	for _, u := range []string{"https://a.example/products/q6-max-front.jpg", "http://cdn.example/silicone-case.webp?w=800", "https://store.example/google-pixel-10-pro.jpg",
		"https://hips.hearstapps.example/vader-prod/1737738862-hoka-bondi-9.jpg?crop=0.6xw&resize=980:*"} {
		if why := picURLRefused(u); why != "" {
			t.Errorf("%s refused: %s", u, why)
		}
	}
}

func TestCardShapeAndCaption(t *testing.T) {
	for _, c := range []struct {
		w, h int
		ok   bool
	}{{1024, 537, true}, {300, 300, true}, {99, 300, false}, {1024, 200, false}, {200, 700, false}, {300, 900, true}} {
		if (cardShape(c.w, c.h) == nil) != c.ok {
			t.Errorf("%dx%d: ok should be %v", c.w, c.h, c.ok)
		}
	}
	product := citedSource{url: "https://www.keychron.example/products/keychron-q6-max", title: "Keychron Q6 Max QMK Wireless Keyboard"}
	roundup := citedSource{url: "https://www.rtings.example/keyboard/reviews/best", title: "The 7 Best Mechanical Keyboards of 2026"}
	pic := picCand{url: "https://cdn.example/files/hero.jpg", kind: picPage}
	if why := cardPicRefused("Keychron Q6 Max", product, pic, cardCaptionMin); why != "" {
		t.Fatalf("the product's own page refused: %s", why)
	}
	if why := cardPicRefused("Keychron Q6 Max", roundup, pic, cardCaptionMin); why != imageMismatch {
		t.Fatalf("a roundup's banner on a product card: %q", why)
	}
	if why := cardPicRefused("Keychron Q5 Max", product, pic, cardCaptionMin); why != imageMismatch {
		t.Fatalf("another model number: %q", why) // numbers count double: Q5 isn't Q6
	}
	// The alt text or the picture's own address can name the item when the page title doesn't.
	if why := cardPicRefused("Lofree Flow", roundup, picCand{url: "https://cdn.example/lofree-flow-84.jpg"}, cardCaptionMin); why != "" {
		t.Fatalf("named by its address: %s", why)
	}
	// Found live (Tavily's first picture of Keychron's page): "Iconic" isn't an icon.
	if why := cardPicRefused("Keychron Q6 Max", citedSource{url: "https://www.keychron.com/products/keychron-q6-max-qmk-via-wireless-custom-mechanical-keyboard",
		title: "Keychron Q6 Max QMK/VIA Wireless Custom Mechanical Keyboard"},
		picCand{url: "http://www.keychron.com/cdn/shop/files/Q6-Max-Iconic-Features.jpg?crop=center&height=1200&v=1753926018&width=1200"}, cardCaptionMin); why != "" {
		t.Fatalf("Q6-Max-Iconic-Features.jpg refused: %s", why)
	}
	if why := cardPicRefused("Keychron Q6 Max", product, picCand{url: "https://cdn.example/keychron-logo.png"}, cardCaptionMin); why != imageLogo {
		t.Fatalf("logo: %q", why)
	}
	if why := cardPicRefused("Keychron Q6 Max", product, picCand{url: "http://127.0.0.1:8080/a.jpg?x=jane@example.com"}, cardCaptionMin); why != imageBlocked {
		t.Fatalf("personal data: %q", why)
	}
}

func TestItemsBlocksAndCards(t *testing.T) {
	text := "Here are two.\n\n```json\n{\"items\":[{\"title\":\"not cards\",\"source\":\"[9]\"}]}\n```\n\n```items\n" +
		`{"items":[{"title":"Keychron Q6 Max","source":"[3]"},{"title":"Lofree Flow","source":"【4】"},{"title":"No source"},` +
		`{"title":"By number","url":5},{"title":"By address","url":"https://shop.example/p"},{"title":"","source":"[6]"}]}` +
		"\n```\nMore text.\n```items\n[{\"title\":\"Still open\",\"source\":\"[7]\"}]\n"
	blocks := itemsBlocks(text, false)
	if len(blocks) != 1 {
		t.Fatalf("%d blocks", len(blocks))
	}
	if final := itemsBlocks(text, true); len(final) != 2 || !slices.Equal(parseCards(final[1]), []cardRef{{title: "Still open", n: 7}}) {
		t.Fatalf("the open block at the end: %q", final)
	}
	cards := parseCards(blocks[0])
	want := []cardRef{{title: "Keychron Q6 Max", n: 3}, {title: "Lofree Flow", n: 4}, {title: "By number", n: 5},
		{title: "By address", url: "https://shop.example/p"}}
	if !slices.Equal(cards, want) {
		t.Fatalf("cards %+v", cards)
	}
	// Streamed: the block's cards come once, when it closes (also at the very end of the text, with no newline).
	cp := newCardPics()
	var got []cardRef
	for _, d := range []string{"Intro\n``", "`items\n[{\"title\":\"A\",", "\"source\":\"[1]\"}]\n`", "``"} {
		got = append(got, cp.feed(d)...)
	}
	got = append(got, cp.feed(" thanks")...)
	if !slices.Equal(got, []cardRef{{title: "A", n: 1}}) {
		t.Fatalf("streamed %+v", got)
	}
	cp.reset()
	if got := cp.feed("```items\n[{\"title\":\"B\",\"source\":2}]\n```"); !slices.Equal(got, []cardRef{{title: "B", n: 2}}) {
		t.Fatalf("after reset %+v", got)
	}
	if got := cp.done(); got != nil {
		t.Fatalf("done again %+v", got)
	}
	// Seen live: the answer ends without closing its block; the call's end counts it (once).
	cp.reset()
	if got := cp.feed("```items\n{\"items\":[{\"title\":\"C\",\"source\":\"[3]\"}]}\n"); got != nil {
		t.Fatalf("open block taken early %+v", got)
	}
	if got := cp.done(); !slices.Equal(got, []cardRef{{title: "C", n: 3}}) {
		t.Fatalf("open block at the end %+v", got)
	}
	if got := cp.done(); got != nil {
		t.Fatalf("twice %+v", got)
	}
}

func TestSearchThumbnails(t *testing.T) {
	var body string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(body)) }))
	defer srv.Close()
	body = `{"web":{"results":[
{"title":"Q6 Max","url":"https://keychron.example/q6","thumbnail":{"src":"https://imgs.search.brave.com/proxy","original":"https://keychron.example/q6.jpg","logo":false}},
{"title":"Brand","url":"https://brand.example/","thumbnail":{"src":"https://imgs.search.brave.com/p2","original":"https://brand.example/b.png","logo":true}},
{"title":"Proxy only","url":"https://p.example/","thumbnail":{"src":"https://imgs.search.brave.com/p3"}},
{"title":"SVG","url":"https://s.example/","thumbnail":{"original":"https://s.example/a.svg"}}]}}`
	b := &brave{lease: testLease(), base: srv.URL + "/res/v1/web/search", http: srv.Client()}
	rs, err := b.Search(context.Background(), "q6", 8)
	if err != nil {
		t.Fatal(err)
	}
	var thumbs [][]string
	for _, r := range rs {
		thumbs = append(thumbs, r.Thumbs)
	}
	if len(rs) != 4 || !slices.Equal(rs[0].Thumbs, []string{"https://keychron.example/q6.jpg"}) || rs[1].Thumbs != nil || rs[2].Thumbs != nil || rs[3].Thumbs != nil {
		t.Fatalf("brave thumbs %q", thumbs)
	}
	body = `{"results":[{"title":"Runners","url":"https://run.example/best","content":"x","images":[
"https://run.example/wp-content/uploads/main.jpeg","https://run.example/static/icons/check.svg","https://i0.example/cropped-run-logo.png","https://run.example/two.jpg","https://run.example/three.jpg"]},
{"title":"None","url":"https://none.example/","content":"y"}]}`
	tv := &tavily{lease: testLease(), base: srv.URL, http: srv.Client()}
	rs, err = tv.Search(context.Background(), "shoes", 5)
	if err != nil {
		t.Fatal(err)
	}
	if len(rs) != 2 || !slices.Equal(rs[0].Thumbs, []string{"https://run.example/wp-content/uploads/main.jpeg", "https://run.example/two.jpg"}) || rs[1].Thumbs != nil {
		t.Fatalf("tavily thumbs %+v", rs)
	}
}

// thumbSearch is a provider whose results carry pictures.
type thumbSearch struct{ fakeSearch }

func (*thumbSearch) Search(context.Context, string, int) ([]SearchResult, error) {
	return []SearchResult{
		{Title: "Keychron Q6 Max QMK Wireless Keyboard", URL: "https://keychron.example/products/q6-max", Snippet: "s",
			Thumbs: []string{"https://img.keychron.example/missing.jpg", "https://img.keychron.example/q6.png"}},
		{Title: "The best keyboards of 2026", URL: "https://reviews.example/best", Snippet: "s", Thumbs: []string{"https://reviews.example/hero.png"}},
		{Title: "Lofree Flow", URL: "https://lofree.example/flow", Snippet: "s"},
	}, nil
}

// A product answer's cards get pictures from their own sources, without an image search: the picture lands
// under the search's call with the source's address as its page, the result told the model which sources have
// one, a roundup's banner isn't put on a product card, and the metric and the record count it.
func TestCardPicturesFromSearchResults(t *testing.T) {
	cards := "Two picks:\n```items\n" + `{"items":[{"title":"Keychron Q6 Max","source":"[1]"},{"title":"Lofree Flow","source":"[2]"},{"title":"Lofree Flow 2","source":"[3]"}]}` + "\n```"
	a, _, _ := newTestAgent(t, toolCallSSE("c1", "web_search", `{"query":"keyboards"}`), textSSE(cards))
	web := stubWeb{"https://img.keychron.example/q6.png": pngWH(400, 300), "https://reviews.example/hero.png": pngWH(400, 300)}
	a.newTools = func() *Tools { return &Tools{search: &thumbSearch{}, fetcher: &http.Client{Transport: web}} }
	evs := collect(t, a, proto.RunRequest{Permissions: AllowAll(), Messages: []proto.Message{{Role: "user", Content: "recommend keyboards"}}})
	var imgs []*proto.Image
	var ids []string
	var m *proto.Metric
	for _, e := range evs {
		switch {
		case e.Type == "image":
			imgs, ids = append(imgs, e.Image), append(ids, e.ID)
		case e.Type == "metrics" && e.Metrics.Kind == "card_pictures":
			m = e.Metrics
		case e.Type == "tool_call" && e.Name == "image_search":
			t.Fatal("an image search ran")
		case e.Type == "tool_result":
			var r struct {
				Results []struct {
					N       int  `json:"n"`
					Picture bool `json:"picture"`
				} `json:"results"`
			}
			json.Unmarshal(e.Result, &r)
			// [2] has a picture but is a list ("The best keyboards of 2026"): not flagged; its picture is still a candidate.
			if len(r.Results) != 3 || !r.Results[0].Picture || r.Results[1].Picture || r.Results[2].Picture {
				t.Fatalf("picture flags %s", e.Result)
			}
			if strings.Contains(string(e.Result), "img.keychron") || strings.Contains(string(e.Result), "hero.png") {
				t.Fatalf("a picture's address reached the model: %s", e.Result)
			}
		}
	}
	if len(imgs) != 1 || ids[0] != "c1" || imgs[0].Source != "https://keychron.example/products/q6-max" ||
		imgs[0].URL != "https://img.keychron.example/q6.png" || imgs[0].Index != 1 || len(imgs[0].Data) == 0 || imgs[0].Type != "image/jpeg" {
		t.Fatalf("images %+v under %q", imgs, ids)
	}
	if evs[len(evs)-1].Type != "done" {
		t.Fatalf("last %s", evs[len(evs)-1].Type)
	}
	// [1]: the first thumbnail 404s, the second works; [2]: the roundup's banner isn't for "Lofree Flow"; [3]: no
	// picture known.
	if m == nil || m.Results != 2 || m.Images != 1 || m.Tried != 2 || m.Failed != 2 || m.Reasons["unreachable"] != 1 ||
		m.Reasons["mismatch"] != 1 || m.Bytes <= 0 || m.Outcome != "ok" {
		t.Fatalf("metric %+v", m)
	}
}

// A card citing a roundup (whose banner doesn't name its item) gets the picture of another result of the run that
// is the item's own page, under that result's call, with that page as its source (the chat then matches it by
// name); a picture goes on one card only.
func TestCardPicturesFromAnotherSource(t *testing.T) {
	cards := "```items\n" + `[{"title":"Keychron Q6 Max","source":"[2]"},{"title":"Keychron Q6 Max keyboard","source":"[2]"}]` + "\n```"
	a, _, _ := newTestAgent(t, toolCallSSE("c1", "web_search", `{"query":"keyboards"}`), textSSE(cards))
	web := stubWeb{"https://img.keychron.example/q6.png": pngWH(400, 300), "https://reviews.example/hero.png": pngWH(400, 300)}
	a.newTools = func() *Tools { return &Tools{search: &thumbSearch{}, fetcher: &http.Client{Transport: web}} }
	evs := collect(t, a, proto.RunRequest{Permissions: AllowAll(), Messages: []proto.Message{{Role: "user", Content: "recommend keyboards"}}})
	var imgs []*proto.Image
	var m *proto.Metric
	for _, e := range evs {
		if e.Type == "image" {
			imgs = append(imgs, e.Image)
		}
		if e.Type == "metrics" && e.Metrics.Kind == "card_pictures" {
			m = e.Metrics
		}
	}
	if len(imgs) != 1 || imgs[0].Source != "https://keychron.example/products/q6-max" || imgs[0].URL != "https://img.keychron.example/q6.png" {
		t.Fatalf("images %+v", imgs)
	}
	// Each card: the roundup's banner refused (mismatch); the other source's first thumbnail 404s for the first card.
	if m == nil || m.Results != 2 || m.Images != 1 || m.Reasons["mismatch"] != 2 {
		t.Fatalf("metric %+v", m)
	}
}

// A page the agent read gives its og:image to the card about it; a card citing a search result for the same page
// gets it too, ahead of the result's own thumbnail.
func TestCardPicturesFromPageMetadata(t *testing.T) {
	page := `<html><head><title>Lofree Flow 84 | Lofree</title><meta property="og:image" content="/cdn/flow-84.jpg"></head>` +
		`<body><main><h1>Lofree Flow 84</h1><p>` + strings.Repeat("A low-profile mechanical keyboard. ", 12) + `</p></main></body></html>`
	web := stubWeb{"https://lofree.example/products/flow": []byte(page), "https://lofree.example/cdn/flow-84.jpg": pngWH(500, 400)}
	cards := "```items\n" + `[{"title":"Lofree Flow 84","source":"[1]"}]` + "\n```\nThat's it."
	a, _, _ := newTestAgent(t, toolCallSSE("p1", "web_fetch", `{"url":"https://lofree.example/products/flow"}`), textSSE(cards))
	a.newTools = func() *Tools { return &Tools{search: &fakeSearch{}, fetcher: &http.Client{Transport: web}} }
	evs := collect(t, a, proto.RunRequest{Permissions: AllowAll(), Tools: []string{"web_search", "fetch_page"},
		Messages: []proto.Message{{Role: "user", Content: "is the lofree flow good?"}}})
	var img *proto.Image
	for _, e := range evs {
		if e.Type == "image" {
			if e.ID != "p1" {
				t.Fatalf("image under %q", e.ID)
			}
			img = e.Image
		}
		if e.Type == "tool_result" && !strings.Contains(string(e.Result), `"picture":true`) {
			t.Fatalf("page result without the picture flag: %.200s", e.Result)
		}
	}
	if img == nil || img.Source != "https://lofree.example/products/flow" || img.URL != "https://lofree.example/cdn/flow-84.jpg" || img.Title != "Lofree Flow 84 | Lofree" {
		t.Fatalf("image %+v", img)
	}

	// The store: page metadata before thumbnails, whichever came first.
	tl := &Tools{}
	tl.addPics("https://www.lofree.example/products/flow/", picCand{url: "https://t.example/1.jpg", kind: picThumb})
	tl.addPics("https://lofree.example/products/flow", picCand{url: "https://lofree.example/og.jpg", kind: picPage})
	tl.citedUnder([]proto.Citation{{Index: 4, URL: "https://lofree.example/products/flow", Title: "Flow"}}, "c9")
	src, cs, ok := tl.cardSource(cardRef{n: 4})
	if !ok || src.call != "c9" || !slices.Equal(picURLs(cs), []string{"https://lofree.example/og.jpg", "https://t.example/1.jpg"}) {
		t.Fatalf("source %+v %q", src, picURLs(cs))
	}
	if _, _, ok := tl.cardSource(cardRef{n: 5}); ok {
		t.Fatal("an unknown number resolved")
	}
	if src, _, ok := tl.cardSource(cardRef{url: "https://lofree.example/products/flow"}); !ok || src.call != "c9" {
		t.Fatal("a source's address didn't resolve")
	}
}

// Only a page that looks like one item's own is flagged (a list's picture is a banner).
func TestPictureFlagLists(t *testing.T) {
	tl := &Tools{}
	c := picCand{url: "https://a.example/p.jpg", kind: picPage}
	for title, want := range map[string]bool{"Keychron Q6 Max QMK/VIA Wireless Keyboard": true, "Sony WH-1000XM6 | Sony US": true,
		"The 7 Best Mechanical Keyboards of 2026": false, "Top 10 robot vacuums": false, "Pegasus 41 vs Ghost 17": false,
		"Running shoe reviews": false, "Best running shoes for beginners": false, "Keyboard buying guide": false} {
		if got := tl.pictureFlag("https://a.example/"+title, title, c); got != want {
			t.Errorf("%q: %v", title, got)
		}
	}
	if tl.pictureFlag("https://a.example/none", "Keychron Q6 Max") {
		t.Error("flagged without a picture")
	}
}

// The model sees the flag with the reader on too (no address, no title of the picture).
func TestPictureFlagWithReader(t *testing.T) {
	tl := &Tools{reader: true}
	out := tl.Finish(pending{out: toolOutcome{ran: true}, query: "q", read: &readerResult{err: "x"},
		results: []SearchResult{{Title: "A", URL: "https://a.example/", Thumbs: []string{"https://a.example/p.jpg"}}, {Title: "B", URL: "https://b.example/"}}})
	if !strings.Contains(out.content, `{"n":1,"site":"https://a.example","picture":true}`) || strings.Contains(out.content, "p.jpg") ||
		strings.Contains(out.content, `"n":2,"site":"https://b.example","picture"`) {
		t.Fatalf("reader view %s", out.content)
	}
}

// Card pictures go through the same dialer as every page: a private address is refused.
func TestCardPicturePrivateAddressRefused(t *testing.T) {
	f := newFetcher(publicOnly)
	_, err := downloadImage(context.Background(), f, "http://127.0.0.1/a.jpg")
	if err == nil || imageFailReason(err) != imageBlocked {
		t.Fatalf("loopback: %v (%s)", err, imageFailReason(err))
	}
}

func testLease() Lease {
	return func(context.Context, string, string, string) (*vault.Secret, error) {
		return vault.NewSecret([]byte("test-search-key-0123456789"), "l1"), nil
	}
}

// The run's end closes the count: a picture still loading is never_arrived; the record gets counts only.
func TestCardPicturesEnd(t *testing.T) {
	cp := newCardPics()
	if m := cp.end(2, &Facts{}); m != nil {
		t.Fatalf("a metric without cards: %+v", m)
	}
	cp = newCardPics()
	cp.cards, cp.shown, cp.open = 3, 1, 1
	cp.st.tried = 2
	cp.st.fail(imageLogo)
	f := &Facts{}
	m := cp.end(2, f)
	if m == nil || m.Kind != "card_pictures" || m.Step != 2 || m.Results != 3 || m.Images != 1 || m.Failed != 2 ||
		m.Reasons[imageNever] != 1 || m.Reasons[imageLogo] != 1 {
		t.Fatalf("metric %+v", m)
	}
	b, _ := json.Marshal(f.Data())
	if !strings.Contains(string(b), `"card_pictures":{"shown":1,"failed":2,"reasons":{"logo":1,"never_arrived":1}}`) || strings.Contains(string(b), "http") {
		t.Fatalf("facts %s", b)
	}
	if cp.end(2, f) != nil {
		t.Fatal("ended twice")
	}
}
