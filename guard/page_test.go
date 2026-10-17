package guard

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/net/html"
)

// Synthetic pages (testdata/pages, gzipped; written by testdata/pages/gen.go, every brand, name and sentence
// invented) with the structure real ones have: a store's product page whose content comes after 2.3 MB of scripts
// and a mega-menu, a second store with its content in role=main, a news article, a wiki article with a list of
// languages in its <main>.
func fixture(t *testing.T, name string) []byte {
	t.Helper()
	f, err := os.Open("testdata/pages/" + name + ".html.gz")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	z, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(z)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// pageText is fetch_page's text for a page body, as fetch builds it.
func pageText(t *testing.T, body []byte) (string, string) {
	t.Helper()
	kept, err := readHTML(bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	title, text := htmlText(string(kept))
	return title, capRunes(strings.TrimSpace(text), maxPageChars)
}

// oldText is what fetch_page returned before main-content extraction: the first 2 MiB, the whole page's text.
func oldText(body []byte) string {
	if len(body) > maxPageBytes {
		body = body[:maxPageBytes]
	}
	doc, _ := html.Parse(bytes.NewReader(body))
	return capRunes(strings.TrimSpace(nodeText(doc, false)), maxPageChars)
}

func TestPageFixtures(t *testing.T) {
	for _, c := range []struct {
		name      string
		streamed  bool     // the content starts after maxPageBytes of the page (scripts): only streaming reaches it
		want      []string // in the new text
		notWant   []string // menus, headers, banners: gone
		oldMissed []string // what the old text didn't have
	}{
		{name: "shop-product", streamed: true,
			want: []string{"Product: Larkspur K7 Pro", "Brand: Larkspur Keys", "189.00 USD, InStock", "Assembled / Slate Grey / Tidewater Red",
				"Regular price", "Specifications", "Layout: 75%, ANSI, with knob", "Battery: 4000 mAh"},
			notWant: []string{"Select region", "Skip to content", "Find Your Perfect Board", "Add to cart", "You may also like",
				"We use cookies"},
			oldMissed: []string{"189.00", "Specifications"}},
		{name: "gadget-store",
			want:      []string{"Quillon HE60", "59.99", "Hall Effect", "8000mAh"},
			notWant:   []string{"Search our store", "Country / currency", "Free shipping on orders over", "Join our newsletter"},
			oldMissed: nil},
		{name: "news-article",
			want: []string{"Headline: Lantern festival moves to the river quay", "Published: 2026-10-16", "By: Odile Marchetti",
				"Lantern festival moves to the river quay after storm damages the old market square\n2 hours ago Odile Marchetti Wrenmouth",
				"The Wrenmouth lantern festival will move to the river quay"},
			notWant:   []string{"Skip to content", "Site search", "We use cookies", "More stories"},
			oldMissed: []string{"Published: 2026-10-16"}},
		{name: "wiki-article",
			want:      []string{"Fernwick keyboards are mechanical input devices", "Updated: 2026-10-05"},
			notWant:   []string{"Jump to content", "العربية", "中文", "Edit links", "View history"},
			oldMissed: []string{"Updated: 2026-10-05"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			body := fixture(t, c.name)
			title, text := pageText(t, body)
			if title == "" {
				t.Error("no title")
			}
			for _, w := range c.want {
				if !strings.Contains(text, w) {
					t.Errorf("text lacks %q", w)
				}
			}
			for _, w := range c.notWant {
				if strings.Contains(text, w) {
					t.Errorf("text still has %q", w)
				}
			}
			old := oldText(body)
			for _, w := range c.oldMissed {
				if strings.Contains(old, w) {
					t.Errorf("the old text already had %q (the fixture no longer shows the problem)", w)
				}
			}
			for _, w := range c.notWant {
				if !strings.Contains(old, w) {
					t.Logf("note: the old text didn't have %q either", w)
				}
			}
			if i := bytes.Index(body, []byte("<main")); c.streamed && i < maxPageBytes {
				t.Errorf("<main> at byte %d, within the first %d: the fixture no longer needs streaming", i, maxPageBytes)
			}
		})
	}
}

// Scripts (other than JSON-LD), styles, SVG and comments are dropped while the page streams in, so a page whose
// first 2 MiB are scripts still gets to its content; the kept markup is capped.
func TestReadHTML(t *testing.T) {
	big := strings.Repeat("x", 600<<10)
	var src strings.Builder
	src.WriteString(`<!doctype html><html><head><title>T</title>`)
	for range 5 { // 3 MB of scripts and styles
		src.WriteString(`<script>var a="` + big + `";</script><style>.a{content:"` + big + `"}</style>`)
	}
	src.WriteString(`<script type="application/ld+json">{"@type":"Product","name":"Widget","offers":{"@type":"Offer","price":"12.50","priceCurrency":"EUR","availability":"https://schema.org/InStock"}}</script>`)
	src.WriteString(`</head><body><!-- a comment --><svg><title>icon</title><path d="M0"/><svg><g/></svg></svg><math><mi>x</mi></math>`)
	src.WriteString(`<main><h1>Widget</h1><p>` + strings.Repeat("A fine widget. ", 20) + `</p></main></body></html>`)
	kept, err := readHTML(strings.NewReader(src.String()))
	if err != nil {
		t.Fatal(err)
	}
	k := string(kept)
	for _, gone := range []string{"var a=", ".a{", "a comment", "<svg", "<path", "icon", "<math", "<mi>"} {
		if strings.Contains(k, gone) {
			t.Errorf("kept %q", gone)
		}
	}
	for _, kept := range []string{"<title>T</title>", `"name":"Widget"`, "<main><h1>Widget</h1>"} {
		if !strings.Contains(k, kept) {
			t.Errorf("dropped %q", kept)
		}
	}
	title, text := htmlText(k)
	if title != "T" || !strings.HasPrefix(text, "From the page's structured data:\nProduct: Widget\nOffers:\n- 12.50 EUR, InStock\n\nWidget\nA fine widget.") {
		t.Fatalf("got %q / %q", title, text)
	}

	// Kept markup is capped at maxPageBytes; the rest of the read is cut.
	huge := "<html><body><main>" + strings.Repeat("<p>word</p>", maxPageBytes/8) + "</main></body></html>"
	kept, err = readHTML(strings.NewReader(huge))
	if err != nil || len(kept) > maxPageBytes || len(kept) < maxPageBytes-64 {
		t.Fatalf("kept %d bytes, err %v", len(kept), err)
	}
	// One script bigger than the buffer limit ends the page there (what came before is kept).
	kept, err = readHTML(strings.NewReader("<p>before</p><script>" + strings.Repeat("y", maxPageBytes+10) + "</script><p>after</p>"))
	if err != nil || !strings.Contains(string(kept), "before") || strings.Contains(string(kept), "yyyy") {
		t.Fatalf("kept %q…, err %v", capRunes(string(kept), 80), err)
	}
}

// The content element: main or role=main first (the largest), then article, then a product section; inside it,
// chrome is dropped; too little text, or none of them, and it's the whole page as before.
func TestMainContent(t *testing.T) {
	long := strings.Repeat("Content sentence here. ", 12)
	for _, c := range []struct{ name, html, want string }{
		{"main without chrome",
			`<body><header>Site menu</header><main><nav>Breadcrumbs</nav><header><h1>Heading</h1></header><p>` + long + `</p>` +
				`<aside>Related</aside><div id="cookie-banner">We use cookies</div><div class="onetrust-pc">Consent</div>` +
				`<div role="dialog">Sign up</div><form><label>Size</label><select><option>XL</option></select><button>Add to cart</button></form>` +
				`<footer>Main footer</footer></main><footer>Site footer</footer></body>`,
			strings.TrimSpace(long) + "\nSize"},
		{"an article's own header stays",
			`<body><main><header>Page tools</header><article><header><h1>Headline</h1><time>Oct 16</time></header><p>` + long + `</p></article></main></body>`,
			"Headline\nOct 16\n" + strings.TrimSpace(long)},
		{"role=main",
			`<body><div class="menu">Menu A Menu B</div><div role="main"><p>` + long + `</p></div></body>`,
			strings.TrimSpace(long)},
		{"largest main wins over an empty decoy",
			`<body><main></main><main><p>` + long + `</p></main></body>`,
			strings.TrimSpace(long)},
		{"article when there's no main",
			`<body><div>Menu A Menu B</div><article><p>short</p></article><article><h1>Story</h1><p>` + long + `</p></article></body>`,
			"Story\n" + strings.TrimSpace(long)},
		{"product section",
			`<body><div>Menu A</div><div id="MainProduct-123"><h1>Thing</h1><p>` + long + `</p></div><div>Footer stuff</div></body>`,
			"Thing\n" + strings.TrimSpace(long)},
		{"schema.org microdata",
			`<body><div>Menu A</div><div itemscope itemtype="https://schema.org/Product"><p>` + long + `</p></div></body>`,
			strings.TrimSpace(long)},
		{"too little in main: whole page",
			`<body><div>Menu A</div><main><p>tiny</p></main><div>` + long + `</div><nav>gone as before</nav></body>`,
			"Menu A\ntiny\n" + strings.TrimSpace(long)},
		{"nothing found: whole page, as before",
			`<body><header>Top</header><div>Menu A</div><p>` + long + `</p><aside>Side</aside><footer>Foot</footer></body>`,
			"Top\nMenu A\n" + strings.TrimSpace(long) + "\nSide"},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, got := htmlText(c.html)
			if got != c.want {
				t.Fatalf("got\n%q\nwant\n%q", got, c.want)
			}
			if strings.HasPrefix(c.name, "nothing found") {
				doc, _ := html.Parse(strings.NewReader(c.html))
				if old := nodeText(doc, false); got != old {
					t.Fatalf("the fallback differs from the old text %q", old)
				}
			}
		})
	}
}

func TestStructuredFacts(t *testing.T) {
	page := func(ld string) string {
		return `<html><head><script type="application/ld+json; charset=utf-8">` + ld + `</script></head><body><p>x</p></body></html>`
	}
	for _, c := range []struct{ name, ld, want string }{
		{"graph with brand object, aggregate offer and rating",
			`{"@context":"https://schema.org","@graph":[{"@type":"Organization","name":"Org"},{"@type":["Product"],"name":"Board",` +
				`"brand":{"@type":"Brand","name":"Maker"},"sku":"B-1","aggregateRating":{"ratingValue":4.6,"reviewCount":"120"},` +
				`"offers":{"@type":"AggregateOffer","lowPrice":99,"highPrice":"129.00","priceCurrency":"USD","availability":"http://schema.org/InStock"}}]}`,
			"From the page's structured data:\nProduct: Board\nBrand: Maker\nSKU: B-1\nRating: 4.6 (120 reviews)\nOffers:\n- 99 to 129.00 USD, InStock"},
		{"product group variants",
			`[{"@type":"ProductGroup","name":"Kbd","hasVariant":[{"@type":"Product","name":"Kbd - Red","offers":{"price":"10","priceCurrency":"GBP","availability":"https://schema.org/OutOfStock"}},` +
				`{"@type":"Product","name":"Kbd - Blue","offers":[{"price":"11","priceCurrency":"GBP"}]}]}]`,
			"From the page's structured data:\nProduct: Kbd\nOffers:\n- Red, 10 GBP, OutOfStock\n- Blue, 11 GBP"},
		{"news article",
			`{"@type":"NewsArticle","headline":"Big news","datePublished":"2026-10-16","author":[{"@type":"Person","name":"A. Writer"},{"name":"B. Writer"}],"publisher":{"name":"Paper"}}`,
			"From the page's structured data:\nHeadline: Big news\nPublished: 2026-10-16\nBy: A. Writer, B. Writer\nPublisher: Paper"},
		{"nothing useful", `{"@type":"BreadcrumbList","itemListElement":[]}`, ""},
		{"not JSON", `{"@type":"Product",`, ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			doc, _ := html.Parse(strings.NewReader(page(c.ld)))
			if got := structuredFacts(doc); got != c.want {
				t.Fatalf("got\n%q\nwant\n%q", got, c.want)
			}
		})
	}
	// At most maxLDOffers offers and maxFactsChars in all, whatever the page carries.
	var offers []string
	for range 50 {
		offers = append(offers, `{"price":"1","priceCurrency":"USD","name":"`+strings.Repeat("v", 200)+`"}`)
	}
	doc, _ := html.Parse(strings.NewReader(page(`{"@type":"Product","name":"P","offers":[` + strings.Join(offers, ",") + `]}`)))
	got := structuredFacts(doc)
	if n := strings.Count(got, "\n- "); n > maxLDOffers || len([]rune(got)) > maxFactsChars+1 {
		t.Fatalf("%d offers, %d characters", n, len([]rune(got)))
	}
}

// fetch_page end to end on a page whose content comes after 2.5 MB of scripts: the product's facts and text
// are in the result.
func TestFetchPageMainContent(t *testing.T) {
	page := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		io.WriteString(w, `<html><head><title>Shop</title>`)
		for range 5 {
			io.WriteString(w, `<script>window.menu="`+strings.Repeat("m", 500<<10)+`"</script>`)
		}
		io.WriteString(w, `</head><body><header><nav>`+strings.Repeat("<a>Menu item</a>", 2000)+`</nav></header>`+
			`<main><h1>Gadget</h1><p>`+strings.Repeat("Specs and details. ", 20)+`</p><p>Price 42.00</p></main></body></html>`)
	}))
	defer page.Close()
	tools := &Tools{fetcher: newFetcher(func(string, string, syscall.RawConn) error { return nil })}
	out, _ := tools.Run(context.Background(), "fetch_page", json.RawMessage(`{"url":"`+page.URL+`"}`))
	var r struct{ Title, Text string }
	json.Unmarshal([]byte(out.content), &r)
	if r.Title != "Shop" || !strings.HasPrefix(r.Text, "Gadget\nSpecs and details.") || !strings.HasSuffix(r.Text, "Price 42.00") {
		t.Fatalf("got %q / %q", r.Title, capRunes(r.Text, 200))
	}
}
