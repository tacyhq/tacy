//go:build ignore

// gen writes the synthetic pages fetch_page's tests read (page_test.go). Every brand, name and sentence in them
// is invented; they copy the structure real pages have, not their content: megabytes of scripts and menus before
// the content, JSON-LD Product/Offer and NewsArticle data, <main>/<article>/role=main and product sections, cookie
// banners, nav/header/footer/aside, and a wiki's list of languages. Run from guard/:
//
//	go run testdata/pages/gen.go
package main

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"os"
	"strings"
)

func main() {
	for name, page := range map[string]string{
		"shop-product": shopProduct(),
		"gadget-store": gadgetStore(),
		"news-article": newsArticle(),
		"wiki-article": wikiArticle(),
	} {
		var b bytes.Buffer
		z, _ := gzip.NewWriterLevel(&b, gzip.BestCompression) // no name or time in the header: same bytes every run
		z.Write([]byte(page))
		z.Close()
		if err := os.WriteFile("testdata/pages/"+name+".html.gz", b.Bytes(), 0o644); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Printf("%s: %d bytes (%d gzipped)\n", name, len(page), b.Len())
	}
}

// rng is a fixed linear congruential generator, so the filler is varied but the same every run.
type rng uint64

func (r *rng) n(max int) int {
	*r = *r*6364136223846793005 + 1442695040888963407
	return int(uint64(*r)>>33) % max
}

var words = strings.Fields(`alpha brisk cobalt delta ember fable grove harbor iris juniper kestrel lumen marlow
nectar onyx pebble quartz russet sable tundra umber velvet willow xenon yarrow zephyr`)

// scripts is about n bytes of inline scripts in chunks of about 60 KB, like a theme's bundles and catalog data.
func scripts(seed rng, n int) string {
	r := seed
	var b strings.Builder
	for b.Len() < n {
		b.WriteString(`<script>window.__bundle_` + fmt.Sprint(r.n(1e6)) + `=[`)
		base := r.n(1e6)
		for i := 0; i < 900; i++ {
			w := words[r.n(len(words))]
			fmt.Fprintf(&b, `{"id":%d,"handle":"%s-%d","title":"%s %d","price":%d,"available":true},`, base+i, w, i, w, i, 100*(i%300))
		}
		b.WriteString("{}];if(window.__boot){window.__boot();}</script>\n")
	}
	return b.String()
}

// megaMenu is a store's navigation: categories of links, many thousands of characters of text, in a theme's own
// elements rather than <nav> (so the whole-page text, which drops <nav>, still fills up with it).
func megaMenu(seed rng, cats []string, perCat int) string {
	r := seed
	var b strings.Builder
	b.WriteString(`<div class="mega-menu"><ul class="mega-menu__list">`)
	for _, c := range cats {
		fmt.Fprintf(&b, `<li class="mega-menu__item"><details><summary>%s</summary><ul class="mega-menu__content">`, c)
		for i := 0; i < perCat; i++ {
			w1, w2 := words[r.n(len(words))], words[r.n(len(words))]
			fmt.Fprintf(&b, `<li><a class="mega-menu__link" href="/collections/%s-%s-%d">%s %s %s %d</a></li>`,
				w1, w2, i, c, strings.ToUpper(w1[:1])+w1[1:], strings.ToUpper(w2[:1])+w2[1:], 10+r.n(90))
		}
		b.WriteString(`</ul></details></li>`)
	}
	b.WriteString(`</ul></div>`)
	return b.String()
}

// shopProduct: a store's product page whose content starts after 2.3 MB of scripts (more than the 2 MiB fetch_page
// keeps), behind a region picker and a mega-menu; JSON-LD Product with named offers; the content is a <main> with a
// product section, a form of options, a related-products aside and a cookie banner after it.
func shopProduct() string {
	ld := `{"@context":"https://schema.org","@type":"Product","name":"Larkspur K7 Pro","brand":{"@type":"Brand","name":"Larkspur Keys"},` +
		`"sku":"K7P-A1","description":"The K7 Pro is a 75% aluminium wireless mechanical keyboard with a rotary knob, hot-swappable sockets and a 4000 mAh battery.",` +
		`"aggregateRating":{"@type":"AggregateRating","ratingValue":"4.7","reviewCount":"38"},"offers":[`
	var offers []string
	avail := []string{"InStock", "BackOrder", "OutOfStock"}
	i := 0
	for _, kind := range []string{"Assembled", "Barebone"} {
		for _, color := range []string{"Slate Grey", "Chalk White", "Heather Purple"} {
			for _, sw := range []string{"Tidewater Red", "Tidewater Brown"} {
				price := "189.00"
				if kind == "Barebone" {
					price = "159.00"
				}
				offers = append(offers, fmt.Sprintf(`{"@type":"Offer","name":"Larkspur K7 Pro - %s / %s / %s","price":"%s","priceCurrency":"USD","availability":"https://schema.org/%s","sku":"K7P-%d"}`,
					kind, color, sw, price, avail[i%3], 100+i))
				i++
			}
		}
	}
	ld += strings.Join(offers, ",") + `]}`

	regions := []string{"United States", "Canada", "United Kingdom", "Ireland", "Australia", "New Zealand", "Japan",
		"South Korea", "Singapore", "Malaysia", "Thailand", "Germany", "France", "Spain", "Italy", "Netherlands",
		"Poland", "Sweden", "Brazil", "Mexico"}
	var reg strings.Builder
	for _, x := range regions {
		reg.WriteString(`<li><a href="#" class="localization__link">` + x + `</a></li>`)
	}

	return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Larkspur K7 Pro Wireless Mechanical Keyboard – Larkspur Keys</title>
<link rel="canonical" href="https://larkspur-keys.example/products/k7-pro">
<style>.header{display:flex}.mega-menu__content{display:grid}` + strings.Repeat(".x{color:#333}", 2000) + `</style>
` + scripts(1, 1100<<10) + `<script type="application/ld+json">{"@context":"https://schema.org","@type":"Organization","name":"Larkspur Keys","url":"https://larkspur-keys.example"}</script>
<script type="application/ld+json">` + ld + `</script>
</head><body class="template-product">
<a class="skip-to-content-link" href="#main-content">Skip to content</a>
<div class="announcement-bar" role="region"><p>Orders placed before noon ship the same working day.</p></div>
<header class="header" role="banner">
<a class="header__logo" href="/"><svg viewBox="0 0 10 10"><title>Larkspur Keys</title><path d="M0 0h10v10H0z"/></svg></a>
<div class="header__search"><a href="/search">Search</a></div><a href="/account/login">Log in</a>
<div class="localization"><h2>Select region</h2><ul class="localization__list">` + reg.String() + `</ul></div>
<a href="/cart">Cart</a>
` + megaMenu(2, []string{"Keyboards", "Low Profile", "Keycaps", "Switches", "Mice", "Accessories", "Spare Parts", "Bundles"}, 70) + `
<div class="mega-menu__promo"><a href="/pages/quiz">Find Your Perfect Board</a><p>Answer five questions and we'll match a layout to your desk.</p></div>
</header>
` + scripts(3, 1250<<10) + `<main id="main-content" class="content-for-layout" role="main">
<section id="shopify-section-template--2207__main-product" class="shopify-section product-section">
<a class="skip-to-content-link" href="#ProductInfo">Skip to product information</a>
<div class="product__media-list"><span class="slider-counter">1 / of 14</span><img src="/cdn/k7-pro-1.jpg" alt="K7 Pro in Slate Grey"></div>
<div id="ProductInfo" class="product__info-container">
<p class="product__text">K Series</p>
<h1 class="product__title">Larkspur K7 Pro Wireless Mechanical Keyboard</h1>
<div class="rating" role="img" aria-label="4.7 out of 5 stars">★★★★★ (38)</div>
<p class="product__sku">SKU: K7P-A1</p>
<div class="price"><span class="visually-hidden">Regular price</span> <span class="price-item">$189.00 USD</span></div>
<form method="post" action="/cart/add" class="product-form">
<fieldset class="product-form__input"><legend>Type</legend><input type="radio" name="Type" value="Assembled" checked><label>Assembled</label><input type="radio" name="Type" value="Barebone"><label>Barebone</label></fieldset>
<fieldset class="product-form__input"><legend>Color</legend><input type="radio" name="Color" value="Slate Grey" checked><label>Slate Grey</label><input type="radio" name="Color" value="Chalk White"><label>Chalk White</label><input type="radio" name="Color" value="Heather Purple"><label>Heather Purple</label></fieldset>
<label for="Switch">Switch</label><select id="Switch" name="Switch"><option>Tidewater Red</option><option>Tidewater Brown</option></select>
<label for="Quantity">Quantity</label><input id="Quantity" type="number" value="1">
<button type="submit" name="add">Add to cart</button><button type="button" class="shopify-payment-button">Buy it now</button>
</form>
<div class="product__description rte">
<p>The K7 Pro packs a full function row, arrow keys and a rotary knob into a 75% aluminium case. It connects over 2.4 GHz, Bluetooth to up to three devices, or a USB-C cable, and the sockets take any three- or five-pin switch.</p>
<p>A gasket-mounted plate, two layers of foam and a silicone bottom pad keep the sound low and even across the board.</p>
<h2>Specifications</h2>
<ul>
<li><strong>Layout:</strong> 75%, ANSI, with knob</li>
<li><strong>Case:</strong> CNC-machined aluminium</li>
<li><strong>Connection:</strong> 2.4 GHz, Bluetooth 5.1, USB-C wired</li>
<li><strong>Polling rate:</strong> 1000 Hz (2.4 GHz and wired)</li>
<li><strong>Battery:</strong> 4000 mAh</li>
<li><strong>Weight:</strong> 1.8 kg</li>
</ul>
</div>
</div>
<aside class="product-recommendations"><h2>You may also like</h2><ul><li>Larkspur K3 Low Profile $99.00</li><li>Tideline keycap set $49.00</li></ul></aside>
</section>
</main>
<footer class="footer"><ul><li><a href="/pages/contact">Contact</a></li><li><a href="/policies/shipping">Shipping policy</a></li></ul><p>© 2026 Larkspur Keys</p></footer>
<div id="shopify-pc__banner" class="cookie-banner" role="dialog"><p>We use cookies to improve your experience on our site.</p><button>Accept</button><button>Decline</button></div>
</body></html>
`
}

// gadgetStore: a store's product page under 2 MiB, content in <main role="main">, no product JSON-LD (only an
// organization and breadcrumbs); a promo bar, a currency picker and a search form before it; a newsletter dialog in it.
func gadgetStore() string {
	var countries strings.Builder
	for _, c := range []string{"United States (USD $)", "Canada (CAD $)", "United Kingdom (GBP £)", "Euro area (EUR €)",
		"Australia (AUD $)", "Japan (JPY ¥)", "Singapore (SGD $)", "Switzerland (CHF)", "Norway (NOK kr)"} {
		countries.WriteString(`<li><a href="#">` + c + `</a></li>`)
	}
	return `<!doctype html><html lang="en"><head><meta charset="utf-8">
<title>Quillon HE60 Magnetic Keyboard | Quillon Gear</title>
` + scripts(5, 600<<10) + `<script type="application/ld+json">{"@context":"https://schema.org","@type":"Organization","name":"Quillon Gear","url":"https://quillon-gear.example"}</script>
<script type="application/ld+json">{"@context":"https://schema.org","@type":"BreadcrumbList","itemListElement":[{"@type":"ListItem","position":1,"name":"Home"},{"@type":"ListItem","position":2,"name":"HE Series"}]}</script>
</head><body>
<div class="announcement-bar"><p>Free shipping on orders over $69 for in-stock products. 1-year warranty · 30-day returns</p></div>
<header class="site-header">
<div class="header__icons"><a href="/search">Search products</a><a href="/cart">0</a><a href="/account">Account</a><a href="/wishlist">Wishlist</a></div>
<details class="currency-picker"><summary>Country / currency</summary><ul>` + countries.String() + `</ul></details>
<div class="search-modal"><p>Search our store</p></div>
` + megaMenu(6, []string{"Series", "By use", "Keycaps", "Switches", "Mice", "Deskmats", "Cables"}, 45) + `
</header>
<main role="main" id="MainContent" class="content-for-layout">
<div class="product-hero">
<p class="product-series">HE Series</p>
<p class="vendor">Quillon Gear</p>
<h1>Quillon HE60</h1>
<p class="tagline">60% Hall Effect · tri-mode wireless · 8K polling · five-layer dampening. A compact board for fast games and small desks.</p>
<div class="price"><span>$59.99</span></div>
<p>Color: Graphite</p>
<p>Switch: Quillon Frost Magnetic Switch</p>
<ul class="highlights"><li>60% Hall Effect Layout</li><li>Adjustable 0.1–3.4 mm Actuation</li><li>8000 Hz Polling</li><li>Tri-Mode Wireless</li><li>8000mAh Battery</li></ul>
<form action="/cart/add"><select name="id"><option>Graphite</option><option>Frost</option></select><button>Add to cart</button></form>
</div>
<section class="feature">
<h2>Rapid Trigger and Advanced Keys</h2><p>Each key reports its position continuously, so it can reset the moment it starts to rise and fire again before it is fully released.</p>
<h2>Contactless sensing</h2><p>Hall Effect switches read a magnet's position instead of closing a metal contact, so there is nothing to wear out and the actuation point can be set per key.</p>
<h2>Battery</h2><p>The 8000mAh cell lasts about three weeks of office use on Bluetooth with the backlight off.</p>
</section>
<section class="recommended"><h2>Recommended Products</h2><ul><li>Quillon Drift Mouse $35.99</li><li>Quillon Ember Keycap Set $24.99</li><li>Quillon Coiled Cable $19.99</li></ul></section>
<div class="newsletter-popup" role="dialog" aria-modal="true"><p>Join our newsletter and get 10% off your first order.</p><input type="email"><button>Subscribe</button></div>
</main>
<footer><nav><a href="/pages/about">About</a><a href="/pages/faq">FAQ</a></nav><p>© 2026 Quillon Gear</p></footer>
<div class="cookieconsent"><p>This store uses cookies.</p><button>OK</button></div>
</body></html>
`
}

// newsArticle: a news story with NewsArticle JSON-LD, a header and section nav before <main>, a cookie banner at the
// top of <main>, an <article> with its own header (headline, time, byline), and a related-stories aside.
func newsArticle() string {
	var sections strings.Builder
	for _, s := range []string{"Home", "News", "Business", "Weather", "Sport", "Culture", "Travel", "Science", "Local",
		"Opinion", "Podcasts", "Video", "Puzzles", "Newsletters"} {
		sections.WriteString(`<li><a href="/` + strings.ToLower(s) + `">` + s + `</a></li>`)
	}
	ld := `{"@context":"https://schema.org","@type":"NewsArticle","headline":"Lantern festival moves to the river quay after storm damages the old market square",` +
		`"datePublished":"2026-10-16T21:05:05.786Z","dateModified":"2026-10-17T05:20:40.681Z",` +
		`"author":[{"@type":"Person","name":"Odile Marchetti","url":"https://harbour-courier.example/authors/odile-marchetti"}],` +
		`"publisher":{"@type":"NewsMediaOrganization","name":"Harbour Courier","logo":{"@type":"ImageObject","url":"https://harbour-courier.example/logo.png"}},` +
		`"image":["https://harbour-courier.example/img/quay.jpg"],"mainEntityOfPage":"https://harbour-courier.example/news/lantern-festival-quay"}`
	return `<!doctype html><html lang="en-GB"><head><meta charset="utf-8">
<title>Lantern festival moves to the river quay after storm | Harbour Courier</title>
<script type="application/ld+json">` + ld + `</script>
` + scripts(7, 180<<10) + `</head><body>
<a class="skip-link" href="#main-content">Skip to content</a>
<header class="site-header" role="banner">
<a href="/" class="brand"><svg><title>Harbour Courier</title></svg></a>
<a href="/live" class="watch-live">Watch Live</a>
<div class="search"><a href="/search">Site search</a></div>
<a href="/account">Sign in</a>
</header>
<nav class="sections" aria-label="Sections"><ul>` + sections.String() + `</ul></nav>
<main id="main-content">
<div id="cookie-banner" class="cookie-banner"><p>We use cookies to give you the best online experience. Let us know if you agree to all of these cookies.</p><button>Yes, I agree</button><a href="/privacy">No, take me to settings</a></div>
<article>
<header class="story-header">
<h1>Lantern festival moves to the river quay after storm damages the old market square</h1>
<time datetime="2026-10-16T21:05:05.786Z">2 hours ago</time>
<div class="byline"><span>Odile Marchetti</span> <span>Wrenmouth</span></div>
</header>
<figure><img src="/img/quay.jpg" alt=""><figcaption>Volunteers stacked paper lanterns in the harbour master's shed on Friday</figcaption></figure>
<p>The Wrenmouth lantern festival will move to the river quay this year after last week's storm brought down part of the arcade roof over the old market square.</p>
<p>Organisers said the 400 paper lanterns made by local schools were stored safely and would be carried along the quay at dusk on Saturday as planned.</p>
<p>"We had a choice between cancelling and moving, and nobody wanted to cancel," said festival chair Tobias Fenwright. "The quay is longer, so the procession will be too."</p>
<p>The town council has closed the square while engineers inspect the arcade, which dates from 1887. A spokesperson said repairs were expected to take at least six weeks.</p>
<p>Traders who usually set up stalls in the square have been offered pitches along Ropewalk Lane at no charge for the evening.</p>
<p>The festival began in 1952 to mark the reopening of the harbour after a winter of flooding, and has been held every October since, apart from two years when it was moved indoors.</p>
<div class="share-tools"><button>Share</button><button>Save</button></div>
</article>
<aside class="related" aria-label="Related"><h2>More stories</h2><ul><li><a href="/news/1">Ferry timetable changes for the winter</a></li><li><a href="/news/2">School wins regional rowing title</a></li></ul></aside>
</main>
<footer class="site-footer"><nav><a href="/terms">Terms of Use</a><a href="/about">About the Courier</a><a href="/privacy">Privacy Policy</a></nav><p>© 2026 Harbour Courier</p></footer>
</body></html>
`
}

// wikiArticle: an encyclopedia article: Article JSON-LD (its dateModified only there), a jump link, header and
// sidebar before <main>, and inside <main> a header with the title, a list of 40 languages and the page tools.
func wikiArticle() string {
	langs := []struct{ code, name string }{{"af", "Afrikaans"}, {"ar", "العربية"}, {"az", "Azərbaycanca"}, {"bn", "বাংলা"},
		{"bg", "Български"}, {"ca", "Català"}, {"cs", "Čeština"}, {"da", "Dansk"}, {"de", "Deutsch"}, {"et", "Eesti"},
		{"el", "Ελληνικά"}, {"es", "Español"}, {"eo", "Esperanto"}, {"eu", "Euskara"}, {"fa", "فارسی"}, {"fr", "Français"},
		{"ga", "Gaeilge"}, {"gl", "Galego"}, {"ko", "한국어"}, {"ha", "Hausa"}, {"hy", "Հայերեն"}, {"hi", "हिन्दी"},
		{"hr", "Hrvatski"}, {"id", "Bahasa Indonesia"}, {"is", "Íslenska"}, {"it", "Italiano"}, {"he", "עברית"},
		{"ka", "ქართული"}, {"lt", "Lietuvių"}, {"hu", "Magyar"}, {"nl", "Nederlands"}, {"ja", "日本語"}, {"pl", "Polski"},
		{"pt", "Português"}, {"ru", "Русский"}, {"fi", "Suomi"}, {"sv", "Svenska"}, {"th", "ไทย"}, {"vi", "Tiếng Việt"},
		{"zh", "中文"}}
	var ll strings.Builder
	for _, l := range langs {
		fmt.Fprintf(&ll, `<li class="interlanguage-link interwiki-%s"><a href="https://%s.openpedia.example/wiki/Fernwick" lang="%s" hreflang="%s">%s</a></li>`,
			l.code, l.code, l.code, l.code, l.name)
	}
	var side strings.Builder
	for _, s := range []string{"Main page", "Contents", "Current events", "Random article", "About Openpedia", "Contact us",
		"Help", "Learn to edit", "Community portal", "Recent changes", "Upload file", "Special pages"} {
		side.WriteString(`<li><a href="#">` + s + `</a></li>`)
	}
	ld := `{"@context":"https://schema.org","@type":"Article","name":"Fernwick keyboard","url":"https://en.openpedia.example/wiki/Fernwick_keyboard",` +
		`"headline":"typesetting keyboard made by the Fernwick Press Works","author":{"@type":"Organization","name":"Contributors to Openpedia"},` +
		`"publisher":{"@type":"Organization","name":"Openpedia Collective"},"datePublished":"2004-03-02T10:15:00Z","dateModified":"2026-10-05T17:59:11Z"}`
	return `<!doctype html><html class="client-nojs" lang="en" dir="ltr"><head><meta charset="UTF-8">
<title>Fernwick keyboard - Openpedia</title>
<script>document.documentElement.className="client-js";var CONF={"wgPageName":"Fernwick_keyboard","wgRevisionId":981234567};</script>
` + scripts(9, 40<<10) + `<script type="application/ld+json">` + ld + `</script>
</head><body class="skin-vector">
<a class="jump-link" href="#bodyContent">Jump to content</a>
<header class="vector-header"><a href="/" class="logo">Openpedia</a><form role="search"><input name="search" placeholder="Search Openpedia"><button>Search</button></form><a href="/create-account">Create account</a><a href="/login">Log in</a></header>
<div class="vector-sidebar"><nav aria-label="Site"><h3>Main menu</h3><ul>` + side.String() + `</ul></nav></div>
<main id="content" class="mw-body">
<header class="mw-body-header">
<h1 id="firstHeading">Fernwick keyboard</h1>
<div id="p-lang-btn" class="vector-dropdown"><span class="vector-dropdown-label">40 languages</span>
<div class="vector-dropdown-content"><ul class="interlanguage-links">` + ll.String() + `</ul>
<div class="after-portlet"><span class="wb-langlinks-edit"><a href="#">Edit links</a></span></div></div></div>
<div class="vector-page-toolbar"><ul><li>Article</li><li>Talk</li><li>Read</li><li>Edit</li><li>View history</li><li>Tools</li></ul></div>
</header>
<div id="bodyContent" class="vector-body">
<div id="siteSub">From Openpedia, the free encyclopedia</div>
<div class="mw-parser-output">
<div role="note" class="hatnote">This article is about the typesetting keyboard. For the press works that made it, see Fernwick Press Works.</div>
<table class="box-More_citations ambox"><tr><td>This article needs additional citations for verification. Please help improve it by adding references to reliable sources. (March 2024)</td></tr></table>
<table class="infobox"><tr><th colspan="2">Fernwick keyboard</th></tr><tr><th>Manufacturer</th><td>Fernwick Press Works</td></tr><tr><th>Introduced</th><td>1921</td></tr><tr><th>Keys</th><td>84</td></tr></table>
<p>Fernwick keyboards are mechanical input devices built for hot-metal typesetting, where an operator's keystrokes released brass matrices from a magazine above the keys. They were made by the Fernwick Press Works in the river town of Ashcombe between 1921 and 1958.</p>
<p>Unlike a typewriter, a Fernwick keyboard had no shift key: capital letters, small capitals and figures each had their own bank of keys, coloured to tell them apart, which is why the boards are unusually wide.</p>
<h2>History</h2>
<p>The first board was designed by the engineer Maud Ellery, who had repaired composing machines for a newspaper before joining the works. Her layout grouped the most frequent letters under the strongest fingers, a choice later operators credited with fewer jammed matrices.</p>
<p>Production peaked in the 1930s, when the works employed some three hundred people. After a fire in 1949 the works made spare parts only, and the last complete board left the factory in 1958.</p>
<h2>Design</h2>
<p>Each key pulled a thin steel rod that tripped an escapement in the magazine. The key travel was long, about 12 millimetres, and the force needed rose towards the bottom of the stroke, so a light touch did nothing and a firm one released exactly one matrix.</p>
<h2>Legacy</h2>
<p>A few dozen boards survive in printing museums. Collectors of modern mechanical keyboards sometimes cite the colour-coded banks as an early example of grouping keys by function.</p>
<h2>References</h2>
<ol class="references"><li>Ellery, M. (1923). Notes on the composing keyboard. Ashcombe: Fernwick Press Works.</li><li>Pell, R. (1987). Hot Metal in the Valley. Ashcombe Local History Society.</li></ol>
</div></div>
</main>
<footer id="footer"><ul><li>This page was last edited on 5 October 2026, at 17:59 (UTC).</li><li>Text is available under an open licence.</li></ul><ul><li><a href="#">Privacy policy</a></li><li><a href="#">About Openpedia</a></li></ul></footer>
</body></html>
`
}
