package guard

import (
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/net/html"
	"golang.org/x/net/html/atom"
)

// fetch_page's text: the page's main content, not its menus. A store's product page and a news article put
// thousands of characters of navigation, mega-menus and cookie banners before the content, and the text cap
// (maxPageChars) used to fill with them (measured 2026-10-17 on a Keychron product page: all 12,000 characters
// were menu, no price). So:
//
//  1. readHTML streams the page and keeps only markup that can become text: scripts (except JSON-LD), styles,
//     SVG, MathML and comments are dropped as they arrive, so the 2 MiB kept reach the content (Keychron's menu
//     scripts alone are 1.9 MB).
//  2. structuredFacts reads the page's JSON-LD: a product's name, brand, price, availability and rating; an
//     article's headline, dates and authors. They go first.
//  3. mainContent picks the content element: the largest <main> or role=main, else the largest <article>, else
//     a product section (schema.org Product microdata, Shopify's main-product section). Inside it, navigation,
//     headers, footers, asides, dialogs, cookie and consent banners and form controls are dropped.
//  4. Nothing found (or too little text in it): the whole page as before.
//
// It only reads the parse tree; nothing runs.

// minMainChars is the least text a content element must have to be used instead of the whole page.
const minMainChars = 200

// Limits for the JSON-LD a page carries: blocks read, bytes per block, products and offers described.
const (
	maxLDBlocks   = 16
	maxLDBytes    = 512 << 10
	maxLDProducts = 3
	maxLDOffers   = 8
	maxFactsChars = 2000
)

// readHTML reads up to maxPageRead bytes of HTML and keeps at most maxPageBytes of the markup that can become
// text, in order. A read error after something was kept ends the page there (like a page cut at the cap).
func readHTML(r io.Reader) ([]byte, error) {
	z := html.NewTokenizer(io.LimitReader(r, maxPageRead))
	z.SetMaxBuf(maxPageBytes) // one token (a huge inline script) can't buffer more than this
	out := make([]byte, 0, 256<<10)
	foreign := 0  // depth inside <svg> or <math>, all dropped
	dropRaw := "" // inside a dropped raw-text element (script, style): its text and end tag are dropped too
	for {
		tt := z.Next()
		if tt == html.ErrorToken {
			if err := z.Err(); err != io.EOF && !errors.Is(err, html.ErrBufferExceeded) && len(out) == 0 {
				return nil, err
			}
			return out, nil
		}
		mark := len(out)
		out = append(out, z.Raw()...) // before TagName, which may change the raw bytes
		drop := false
		switch tt {
		case html.CommentToken:
			drop = true
		case html.TextToken:
			drop = dropRaw != "" || foreign > 0
		case html.StartTagToken, html.SelfClosingTagToken:
			name, hasAttr := z.TagName()
			switch n := string(name); {
			case foreign > 0:
				drop = true
				if tt == html.StartTagToken && (n == "svg" || n == "math") {
					foreign++
				}
			case n == "svg" || n == "math":
				drop = true
				if tt == html.StartTagToken {
					foreign = 1
				}
			case n == "style" || (n == "script" && !(hasAttr && ldJSONScript(z))):
				drop = true
				if tt == html.StartTagToken {
					dropRaw = n
				}
			}
		case html.EndTagToken:
			name, _ := z.TagName()
			switch n := string(name); {
			case foreign > 0:
				drop = true
				if n == "svg" || n == "math" {
					foreign--
				}
			case dropRaw != "" && n == dropRaw:
				drop, dropRaw = true, ""
			}
		}
		if drop {
			out = out[:mark]
			continue
		}
		if len(out) > maxPageBytes {
			return out[:mark], nil
		}
	}
}

// ldJSONScript reports whether the current <script> start tag is type="application/ld+json".
func ldJSONScript(z *html.Tokenizer) bool {
	for {
		k, v, more := z.TagAttr()
		if string(k) == "type" {
			return isLDJSON(string(v))
		}
		if !more {
			return false
		}
	}
}

func isLDJSON(t string) bool {
	t, _, _ = strings.Cut(t, ";")
	return strings.EqualFold(strings.TrimSpace(t), "application/ld+json")
}

// skipTags are never text, wherever they are (the whole-page fallback drops these).
var skipTags = map[string]bool{"script": true, "style": true, "noscript": true, "svg": true, "template": true,
	"iframe": true, "nav": true, "footer": true, "title": true, "form": true, "button": true}

// skipInMain are also dropped inside a content element: page chrome and form controls. (A form there stays: a
// product's options are often in one; its inputs, selects and buttons go.)
var skipInMain = map[string]bool{"script": true, "style": true, "noscript": true, "svg": true, "math": true,
	"template": true, "iframe": true, "nav": true, "footer": true, "aside": true, "title": true,
	"button": true, "dialog": true, "select": true, "input": true, "textarea": true, "object": true, "embed": true}

// skipRoles are ARIA roles of page chrome.
var skipRoles = map[string]bool{"navigation": true, "banner": true, "contentinfo": true, "complementary": true,
	"dialog": true, "alertdialog": true, "search": true, "menu": true, "menubar": true}

// bannerRe matches the id or class of cookie and consent banners (and the common consent managers').
var bannerRe = regexp.MustCompile(`(?i)cookie[-_ ]?(?:banner|consent|notice|bar|law|popup|modal|policy|settings|wall)|cookieconsent|cookiebot|onetrust|consent[-_ ]?(?:banner|manager|modal|popup|dialog)|gdpr|didomi|usercentrics|osano|truste|qc-cmp|cmp-container|sp_message`)

var blockTags = map[string]bool{"p": true, "div": true, "br": true, "li": true, "tr": true, "h1": true, "h2": true,
	"h3": true, "h4": true, "h5": true, "h6": true, "section": true, "article": true, "pre": true, "blockquote": true,
	"table": true, "ul": true, "ol": true, "header": true, "main": true, "dt": true, "dd": true, "figcaption": true,
	"details": true, "summary": true, "fieldset": true, "legend": true}

// htmlText extracts the title and readable text of an HTML page: its structured facts, then its main content,
// or the whole page when no content element is found.
func htmlText(src string) (title, text string) {
	doc, err := html.Parse(strings.NewReader(src))
	if err != nil {
		return "", ""
	}
	title = pageTitle(doc)
	facts := structuredFacts(doc)
	body := ""
	if root := mainContent(doc); root != nil {
		body = nodeText(root, true)
	}
	if len(body) < minMainChars {
		body = nodeText(doc, false)
	}
	if facts != "" {
		return title, facts + "\n\n" + body
	}
	return title, body
}

func pageTitle(doc *html.Node) string {
	var title string
	var walk func(n *html.Node) bool
	walk = func(n *html.Node) bool {
		if n.Type == html.ElementNode && n.DataAtom == atom.Svg {
			return false // an SVG's <title> isn't the page's
		}
		if n.Type == html.ElementNode && n.DataAtom == atom.Title && n.FirstChild != nil {
			title = n.FirstChild.Data
			return true
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			if walk(c) {
				return true
			}
		}
		return false
	}
	walk(doc)
	return title
}

func attr(n *html.Node, key string) string {
	for _, a := range n.Attr {
		if a.Namespace == "" && a.Key == key {
			return a.Val
		}
	}
	return ""
}

// chrome reports whether an element inside a content element is page chrome to drop. A <header> is chrome
// unless it's an article's own (its headline and byline); a main's header holds the site's or the page's tools
// (Wikipedia's language list).
func chrome(n *html.Node, inArticle bool) bool {
	if n.DataAtom == atom.Header && !inArticle {
		return true
	}
	if skipInMain[n.Data] || skipRoles[strings.ToLower(strings.TrimSpace(attr(n, "role")))] || attr(n, "aria-modal") == "true" {
		return true
	}
	if id, class := attr(n, "id"), attr(n, "class"); (id != "" || class != "") && bannerRe.MatchString(id+" "+class) {
		return true
	}
	return false
}

// nodeText is the readable text under n: block elements end lines, runs of space collapse, blank lines go.
// strict (a content element): chrome is dropped too; otherwise only skipTags (the whole-page fallback, as fetch_page
// always did).
func nodeText(n *html.Node, strict bool) string {
	var b strings.Builder
	var walk func(n *html.Node, inArticle bool)
	walk = func(n *html.Node, inArticle bool) {
		if b.Len() > maxPageChars*2 {
			return
		}
		if n.Type == html.ElementNode {
			if strict && chrome(n, inArticle) || !strict && skipTags[n.Data] {
				return
			}
			inArticle = inArticle || n.DataAtom == atom.Article
		}
		if n.Type == html.TextNode {
			if t := strings.Join(strings.Fields(n.Data), " "); t != "" {
				b.WriteString(t)
				b.WriteByte(' ')
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c, inArticle)
		}
		if n.Type == html.ElementNode && blockTags[n.Data] {
			b.WriteByte('\n')
		}
	}
	walk(n, false)
	var lines []string
	for _, l := range strings.Split(b.String(), "\n") {
		if l = strings.TrimSpace(l); l != "" {
			lines = append(lines, l)
		}
	}
	return strings.Join(lines, "\n")
}

// mainContent is the page's content element, or nil: the largest <main> or role=main, else the largest
// <article>, else a product section. "Largest" by text, so an empty or decoy element doesn't win.
func mainContent(doc *html.Node) *html.Node {
	var mains, articles, products []*html.Node
	var walk func(n *html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode {
			switch {
			case n.DataAtom == atom.Main || strings.EqualFold(strings.TrimSpace(attr(n, "role")), "main"):
				mains = append(mains, n)
			case n.DataAtom == atom.Article:
				articles = append(articles, n)
			case productSection(n):
				products = append(products, n)
			}
			if n.DataAtom == atom.Svg || n.DataAtom == atom.Template || n.DataAtom == atom.Script {
				return
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(doc)
	for _, set := range [][]*html.Node{mains, articles, products} {
		var best *html.Node
		bestLen := 0
		for _, n := range set {
			if l := len(nodeText(n, true)); l > bestLen {
				best, bestLen = n, l
			}
		}
		if bestLen >= minMainChars {
			return best
		}
	}
	return nil
}

// productSection: schema.org Product microdata, or a Shopify theme's main product section.
func productSection(n *html.Node) bool {
	if t := attr(n, "itemtype"); strings.Contains(t, "schema.org/Product") {
		return true
	}
	id := attr(n, "id")
	return strings.HasPrefix(id, "MainProduct-") || strings.Contains(id, "__main-product") || strings.Contains(id, "__main_product")
}

// ---- JSON-LD ------------------------------------------------------------------------------------------------

// structuredFacts describes the products and articles in a page's JSON-LD, or "".
func structuredFacts(doc *html.Node) string {
	var items []map[string]any
	blocks := 0
	var walk func(n *html.Node)
	walk = func(n *html.Node) {
		if blocks >= maxLDBlocks {
			return
		}
		if n.Type == html.ElementNode && n.DataAtom == atom.Script {
			if isLDJSON(attr(n, "type")) && n.FirstChild != nil && len(n.FirstChild.Data) <= maxLDBytes {
				blocks++
				var v any
				if json.Unmarshal([]byte(strings.TrimSpace(n.FirstChild.Data)), &v) == nil {
					collectLD(v, &items, 0)
				}
			}
			return
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(doc)
	var out []string
	products := 0
	for _, it := range items {
		switch {
		case hasType(it, "Product", "ProductGroup", "IndividualProduct", "ProductModel"):
			if products < maxLDProducts {
				products++
				out = append(out, productFacts(it))
			}
		case hasType(it, "Article", "NewsArticle", "ReportageNewsArticle", "AnalysisNewsArticle", "BlogPosting",
			"TechArticle", "ScholarlyArticle", "Report"):
			out = append(out, articleFacts(it))
		}
	}
	s := strings.Join(compact(out), "\n\n")
	if s == "" {
		return ""
	}
	return capRunes("From the page's structured data:\n"+s, maxFactsChars)
}

// collectLD gathers the objects of a JSON-LD document: top-level ones, arrays of them and @graph members.
func collectLD(v any, items *[]map[string]any, depth int) {
	if depth > 3 || len(*items) >= 64 {
		return
	}
	switch x := v.(type) {
	case []any:
		for _, e := range x {
			collectLD(e, items, depth+1)
		}
	case map[string]any:
		*items = append(*items, x)
		if g, ok := x["@graph"]; ok {
			collectLD(g, items, depth+1)
		}
	}
}

func hasType(m map[string]any, types ...string) bool {
	var ts []string
	switch t := m["@type"].(type) {
	case string:
		ts = []string{t}
	case []any:
		for _, e := range t {
			if s, ok := e.(string); ok {
				ts = append(ts, s)
			}
		}
	}
	for _, t := range ts {
		t = strings.TrimPrefix(strings.TrimPrefix(t, "http://schema.org/"), "https://schema.org/")
		for _, want := range types {
			if t == want {
				return true
			}
		}
	}
	return false
}

// str is a JSON-LD value as short plain text: a string or number, or an object's name; "" otherwise.
func str(v any) string {
	switch x := v.(type) {
	case string:
		return clean(x, 300)
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	case json.Number:
		return x.String()
	case map[string]any:
		return str(x["name"])
	case []any:
		if len(x) > 0 {
			return str(x[0])
		}
	}
	return ""
}

// names lists the names in a value that is one person/organization or several.
func names(v any) string {
	var out []string
	switch x := v.(type) {
	case []any:
		for _, e := range x {
			if s := str(e); s != "" && len(out) < 5 {
				out = append(out, s)
			}
		}
	default:
		if s := str(x); s != "" {
			out = append(out, s)
		}
	}
	return strings.Join(out, ", ")
}

// schemaValue drops schema.org's prefix from an enumeration ("https://schema.org/InStock" -> "InStock").
func schemaValue(v any) string {
	s := str(v)
	if i := strings.LastIndexByte(s, '/'); i >= 0 && strings.Contains(s, "schema.org") {
		s = s[i+1:]
	}
	return s
}

func line(label, v string) string {
	if v == "" {
		return ""
	}
	return label + ": " + v
}

func productFacts(p map[string]any) string {
	ls := []string{
		line("Product", str(p["name"])),
		line("Brand", str(p["brand"])),
		line("SKU", str(p["sku"])),
		line("MPN", str(p["mpn"])),
	}
	if d := str(p["description"]); d != "" {
		ls = append(ls, line("Description", capRunes(d, 300)))
	}
	if r, ok := p["aggregateRating"].(map[string]any); ok {
		if v := str(r["ratingValue"]); v != "" {
			n := cmpStr(str(r["reviewCount"]), str(r["ratingCount"]))
			if n != "" {
				v += " (" + n + " reviews)"
			}
			ls = append(ls, line("Rating", v))
		}
	}
	var offers []string
	name := str(p["name"])
	addOffers(p["offers"], "", name, &offers)
	if vs, ok := p["hasVariant"].([]any); ok { // a ProductGroup: each variant has its own offers
		for _, v := range vs {
			if m, ok := v.(map[string]any); ok {
				addOffers(m["offers"], str(m["name"]), name, &offers)
			}
		}
	}
	if len(offers) > 0 {
		ls = append(ls, "Offers:")
		ls = append(ls, offers...)
	}
	return strings.Join(compact(ls), "\n")
}

func cmpStr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// addOffers describes an Offer, an AggregateOffer or a list of them, one line each, at most maxLDOffers. An
// offer's name drops the product's name in front ("Q1 Max - Knob / Black" -> "Knob / Black").
func addOffers(v any, variant, product string, out *[]string) {
	switch x := v.(type) {
	case []any:
		for _, e := range x {
			addOffers(e, variant, product, out)
		}
	case map[string]any:
		if len(*out) >= maxLDOffers {
			return
		}
		cur := str(x["priceCurrency"])
		price := str(x["price"])
		if price == "" {
			if ps, ok := x["priceSpecification"].(map[string]any); ok {
				price, cur = str(ps["price"]), cmpStr(cur, str(ps["priceCurrency"]))
			}
		}
		if lo, hi := str(x["lowPrice"]), str(x["highPrice"]); price == "" && lo != "" {
			price = lo
			if hi != "" && hi != lo {
				price += " to " + hi
			}
		}
		label := cmpStr(str(x["name"]), variant)
		if product != "" && label != product && strings.HasPrefix(label, product) {
			label = strings.TrimLeft(strings.TrimPrefix(label, product), " -–/:|")
		}
		parts := compact([]string{
			label,
			strings.TrimSpace(price + " " + cur),
			schemaValue(x["availability"]),
			schemaValue(x["itemCondition"]),
			line("seller", str(x["seller"])),
		})
		if len(parts) > 0 {
			*out = append(*out, "- "+strings.Join(parts, ", "))
		}
	}
}

func articleFacts(a map[string]any) string {
	return strings.Join(compact([]string{
		line("Headline", cmpStr(str(a["headline"]), str(a["name"]))),
		line("Published", str(a["datePublished"])),
		line("Updated", str(a["dateModified"])),
		line("By", names(a["author"])),
		line("Publisher", str(a["publisher"])),
	}), "\n")
}

func compact(ss []string) []string {
	out := ss[:0:0]
	for _, s := range ss {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}
