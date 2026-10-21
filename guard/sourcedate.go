package guard

import (
	"encoding/json"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/html"
	"golang.org/x/net/html/atom"
)

// A source's date (research-dates, 2026-10-21): research cited web sources without saying when they were published,
// so an old page could read as current. The search provider gives a published date for some results only (Exa's
// publishedDate: about 45% of the results the research lab's agents cited; Tavily's only on news searches); a page
// read had none at all, though most pages state one in their metadata. So code finds it:
//
//   - a search result: the provider's date, else a date in its address (/2026/09/16/, /2026-09-16-…, /2026/09/);
//   - a page read: its metadata (JSON-LD datePublished and dateModified, then the article:, og:, Dublin Core,
//     citation_ and itemprop <meta> tags, then <time itemprop="datePublished">), else a date in its address.
//
// The date is code's, never the page's text: it goes to the model as the result's or page's "age" (a reader-on model
// gets nothing else of the address or the markup) and to the person in the Sources list (citation Age). Always
// in one of the forms ageText makes, digits only: "2026-09-16", "2026-09", "updated 2026-10-01" or
// "2026-09-16, updated 2026-10-01". A date before 1990 or after tomorrow is no date.

// ageText is a source's age from its published and updated dates (each "YYYY-MM-DD", "YYYY-MM" or ""): an update
// only when it is later than the publication.
func ageText(published, updated string) string {
	switch {
	case published == "" && updated == "":
		return ""
	case published == "":
		return "updated " + updated
	case updated <= published || strings.HasPrefix(updated, published) || strings.HasPrefix(published, updated):
		return published // no update, the same day or month, or an "update" before the publication
	}
	return published + ", updated " + updated
}

// isoDateRe is the start of an ISO 8601 date or timestamp: 2026-09-16, 2026-09-16T08:00:00Z, 2026-09.
var isoDateRe = regexp.MustCompile(`^((?:19|20)\d{2})-(\d{2})(?:-(\d{2}))?(?:[T ]\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?(?:Z|[+-]\d{2}:?\d{2})?)?$`)

// slashDateRe is 2026/09/16 (citation_publication_date's form) or 20260916.
var slashDateRe = regexp.MustCompile(`^((?:19|20)\d{2})[/.]?(\d{2})[/.]?(\d{2})$`)

// textDateLayouts are the other forms page metadata uses (RFC 1123 and the like, and written-out dates).
var textDateLayouts = []string{time.RFC1123, time.RFC1123Z, time.RFC850, time.ANSIC, "Mon, 2 Jan 2006 15:04:05 MST",
	"Mon, 2 Jan 2006 15:04:05 -0700", "January 2, 2006", "Jan 2, 2006", "2 January 2006", "2 Jan 2006", "January 2006"}

// normDate is a date as a page's metadata or a provider writes it, as "YYYY-MM-DD" (or "YYYY-MM" when only a month
// is given), or "" when it isn't a plausible date (before 1990, or after the day after now). The calendar date as
// written: a timestamp's date isn't moved to UTC.
func normDate(s string, now time.Time) string {
	s = strings.TrimSpace(s)
	if s == "" || len(s) > 64 {
		return ""
	}
	y, m, d := "", "", ""
	if g := isoDateRe.FindStringSubmatch(s); g != nil {
		y, m, d = g[1], g[2], g[3]
	} else if g := slashDateRe.FindStringSubmatch(s); g != nil {
		y, m, d = g[1], g[2], g[3]
	} else {
		for _, l := range textDateLayouts {
			if t, err := time.Parse(l, s); err == nil {
				y, m, d = t.Format("2006"), t.Format("01"), t.Format("02")
				if l == "January 2006" {
					d = ""
				}
				break
			}
		}
	}
	return checkedDate(y, m, d, now)
}

// checkedDate is y-m(-d) when it is a real calendar date from 1990 to the day after now, else "".
func checkedDate(y, m, d string, now time.Time) string {
	if y == "" || m == "" {
		return ""
	}
	yi, _ := strconv.Atoi(y)
	mi, _ := strconv.Atoi(m)
	if yi < 1990 || mi < 1 || mi > 12 {
		return ""
	}
	t := time.Date(yi, time.Month(mi), 1, 0, 0, 0, 0, time.UTC)
	out := y + "-" + m
	if d != "" {
		di, _ := strconv.Atoi(d)
		t = time.Date(yi, time.Month(mi), di, 0, 0, 0, 0, time.UTC)
		if di < 1 || t.Day() != di { // 2026-02-30 rolls over: no such day
			return ""
		}
		out += "-" + d
	}
	if !now.IsZero() && t.After(now.Add(24*time.Hour)) {
		return ""
	}
	return out
}

// providerAge is a search provider's date for a result, normalized ("" when it isn't a calendar date; Brave's
// relative "2 days ago" stays as it is: it was never shown as a date).
func providerAge(s string, now time.Time) string {
	if d := normDate(s, now); d != "" {
		return d
	}
	if strings.HasSuffix(strings.TrimSpace(s), " ago") {
		return clean(s, 40)
	}
	return ""
}

// URL dates: a day (/2026/09/16/, /2026-09-16-slug, 8 digits as in /bcreg20260319a.htm, the Federal Reserve's) or a
// month (/2026/09/, WordPress's uploads; /2026/9/slug; /files/2026-09/, Drupal's) in the path, as news sites, blogs,
// CMSs and agencies write their addresses. Never from the query or the host.
var (
	urlDayRe    = regexp.MustCompile(`(?:^|/)((?:19|20)\d{2})/(\d{2})/(\d{2})(?:/|$|-|\.html?$)`) // not "/2025/03/10_article": an issue number
	urlDashRe   = regexp.MustCompile(`(?:^|/)((?:19|20)\d{2})-(\d{2})-(\d{2})(?:/|$|[-_.])`)
	urlCompRe   = regexp.MustCompile(`(?:^|[^\d])((?:19|20)\d{2})(\d{2})(\d{2})(?:[^\d]|$)`)
	urlMonthRe  = regexp.MustCompile(`(?:^|/)((?:19|20)\d{2})/(\d{1,2})/(?:[^/\d]|\d{2}/)`)
	urlFolderRe = regexp.MustCompile(`(?:^|/)((?:19|20)\d{2})-(\d{2})/`)
)

// urlDate is the date in an address's path ("YYYY-MM-DD" or "YYYY-MM"), or "".
func urlDate(raw string, now time.Time) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	p := u.EscapedPath()
	for _, re := range []*regexp.Regexp{urlDayRe, urlDashRe, urlCompRe} {
		if g := re.FindStringSubmatch(p); g != nil {
			if d := checkedDate(g[1], g[2], g[3], now); d != "" {
				return d
			}
		}
	}
	for _, re := range []*regexp.Regexp{urlMonthRe, urlFolderRe} {
		if g := re.FindStringSubmatch(p); g != nil {
			if len(g[2]) == 1 {
				g[2] = "0" + g[2]
			}
			if d := checkedDate(g[1], g[2], "", now); d != "" {
				return d
			}
		}
	}
	return ""
}

// resultAge is a search result's age: the provider's date, else its address's.
func resultAge(provider, raw string, now time.Time) string {
	if a := providerAge(provider, now); a != "" {
		return a
	}
	return urlDate(raw, now)
}

// Page metadata names for a published and an updated date (<meta property|name|itemprop>, lowercased), best first.
var (
	metaPublished = []string{"article:published_time", "og:article:published_time", "datepublished", "published_time",
		"article.published", "pubdate", "publishdate", "publish-date", "publish_date", "publication_date",
		"parsely-pub-date", "sailthru.date", "dc.date.issued", "dcterms.issued", "dc.date", "dcterms.date",
		"citation_publication_date", "citation_online_date", "citation_date", "date", "datecreated", "dcterms.created"}
	metaUpdated = []string{"article:modified_time", "og:updated_time", "datemodified", "dcterms.modified",
		"dc.date.modified", "article.updated", "last-modified", "lastmod"}
)

// ldDateTypes are the JSON-LD types whose datePublished is the page's own (not a product's or an event's).
var ldDateTypes = []string{"Article", "NewsArticle", "ReportageNewsArticle", "AnalysisNewsArticle", "BlogPosting",
	"TechArticle", "ScholarlyArticle", "Report", "WebPage", "AboutPage", "FAQPage", "QAPage", "ItemPage",
	"CollectionPage", "MedicalWebPage", "LiveBlogPosting", "PressRelease", "Legislation", "GovernmentService",
	"DigitalDocument", "CreativeWork", "Dataset", "Guide", "HowTo", "Review", "OpinionNewsArticle", "SocialMediaPosting",
	"DiscussionForumPosting"}

// pageDates are a page's published and updated dates as its metadata gives them ("YYYY-MM-DD", "YYYY-MM" or "").
func pageDates(doc *html.Node, now time.Time) (published, updated string) {
	meta := map[string]string{}
	var items []map[string]any
	timePub := ""
	times := map[string]bool{} // the distinct dates of the page's <time datetime> elements
	blocks := 0
	var walk func(n *html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode {
			switch n.DataAtom {
			case atom.Script:
				if blocks < maxLDBlocks && isLDJSON(attr(n, "type")) && n.FirstChild != nil && len(n.FirstChild.Data) <= maxLDBytes {
					blocks++
					var v any
					if json.Unmarshal([]byte(strings.TrimSpace(n.FirstChild.Data)), &v) == nil {
						collectLD(v, &items, 0)
					}
				}
				return
			case atom.Meta:
				for _, k := range []string{attr(n, "property"), attr(n, "name"), attr(n, "itemprop"), attr(n, "http-equiv")} {
					k = strings.ToLower(strings.TrimSpace(k))
					if k != "" && meta[k] == "" {
						meta[k] = attr(n, "content")
					}
				}
			case atom.Time:
				if d := normDate(attr(n, "datetime"), now); d != "" && len(times) <= 2 {
					times[d] = true
				}
				if timePub == "" {
					ip := strings.ToLower(attr(n, "itemprop"))
					if ip == "datepublished" || hasAttr(n, "pubdate") {
						timePub = attr(n, "datetime")
					}
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(doc)
	for _, it := range items {
		if !hasType(it, ldDateTypes...) {
			continue
		}
		if published == "" {
			published = normDate(str(it["datePublished"]), now)
		}
		if updated == "" {
			updated = normDate(str(it["dateModified"]), now)
		}
		if published != "" && updated != "" {
			break
		}
	}
	for _, k := range metaPublished {
		if published != "" {
			break
		}
		published = normDate(meta[k], now)
	}
	if published == "" {
		published = normDate(timePub, now)
	}
	if published == "" && updated == "" && len(times) == 1 {
		// One date in the whole page's <time> elements (a law firm's alert, a blog post without metadata): its date.
		// A page with several (a listing, comments, an events page) gets none from them.
		for d := range times {
			published = d
		}
	}
	for _, k := range metaUpdated {
		if updated != "" {
			break
		}
		updated = normDate(meta[k], now)
	}
	return published, updated
}

// pageAge is a page read's age: its metadata's dates, else its address's (the address after redirects).
func pageAge(doc *html.Node, final string, now time.Time) string {
	if doc != nil {
		if a := ageText(pageDates(doc, now)); a != "" {
			return a
		}
	}
	return urlDate(final, now)
}

func hasAttr(n *html.Node, key string) bool {
	for _, a := range n.Attr {
		if strings.EqualFold(a.Key, key) {
			return true
		}
	}
	return false
}
