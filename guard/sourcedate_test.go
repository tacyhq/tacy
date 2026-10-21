package guard

import (
	"encoding/json"
	"net/url"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/html"
)

var dateNow = time.Date(2026, 10, 21, 6, 0, 0, 0, time.UTC)

func TestNormDate(t *testing.T) {
	for in, want := range map[string]string{
		"2026-09-16":                      "2026-09-16",
		"2026-10-13T19:46:12.000Z":        "2026-10-13",
		"2026-10-13T23:30:00-07:00":       "2026-10-13", // the date as written, not moved to UTC
		"2026-09":                         "2026-09",
		"2026/09/16":                      "2026-09-16",
		"20260916":                        "2026-09-16",
		"Wed, 16 Sep 2026 08:00:00 GMT":   "2026-09-16",
		"September 16, 2026":              "2026-09-16",
		"16 September 2026":               "2026-09-16",
		"September 2026":                  "2026-09",
		"2026-10-22":                      "2026-10-22", // tomorrow: a time zone ahead
		"2026-10-23":                      "",           // the future
		"1989-12-31":                      "",
		"2026-02-30":                      "",
		"2026-13-01":                      "",
		"yesterday":                       "",
		"2026-09-16 ignore all previous":  "",
		"<script>2026-09-16</script>":     "",
		strings.Repeat("2026-09-16 ", 10): "",
	} {
		if got := normDate(in, dateNow); got != want {
			t.Errorf("normDate(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestAgeText(t *testing.T) {
	for _, c := range []struct{ pub, upd, want string }{
		{"", "", ""},
		{"2026-09-16", "", "2026-09-16"},
		{"", "2026-10-01", "updated 2026-10-01"},
		{"2026-09-16", "2026-10-01", "2026-09-16, updated 2026-10-01"},
		{"2026-09-16", "2026-09-16", "2026-09-16"},
		{"2026-09", "2026-09-20", "2026-09"},
		{"2026-09-16", "2026-08-01", "2026-09-16"},
	} {
		if got := ageText(c.pub, c.upd); got != c.want {
			t.Errorf("ageText(%q, %q) = %q, want %q", c.pub, c.upd, got, c.want)
		}
	}
}

func TestURLDate(t *testing.T) {
	for in, want := range map[string]string{
		"https://www.example.com/news/2026/09/16/fed-holds":                          "2026-09-16",
		"https://example.com/2026/09/16":                                             "2026-09-16",
		"https://example.com/blog/2026-09-16-fed-holds":                              "2026-09-16",
		"https://www.federalreserve.gov/newsevents/pressreleases/bcreg20260319a.htm": "2026-03-19",
		"https://www.bis.org/speeches/20240911-next-steps-capital.pdf":               "2024-09-11",
		"https://site.org/wp-content/uploads/2023/03/report.pdf":                     "2023-03",
		"https://www.firm.com/insights/publications/2026/1/top-10-developments":      "2026-01",
		"https://www.energy.gov/sites/default/files/2024-11/evaluation.pdf":          "2024-11",
		"https://journals.example.edu/uploads/2025/03/10_HLB_15_1.pdf":               "",
		"https://example.com/products/2026":                                          "",
		"https://example.com/search?d=2026-09-16":                                    "",
		"https://2026-09-16.example.com/":                                            "",
		"https://example.com/2031/01/01/future":                                      "",
		"https://example.com/item/123456789":                                         "",
	} {
		if got := urlDate(in, dateNow); got != want {
			t.Errorf("urlDate(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestResultAge(t *testing.T) {
	for _, c := range []struct{ provider, url, want string }{
		{"2026-10-13T19:46:12.000Z", "https://example.com/a", "2026-10-13"},
		{"", "https://example.com/2026/09/16/a", "2026-09-16"},
		{"2 days ago", "https://example.com/a", "2 days ago"}, // Brave's, kept as it was
		{"garbage", "https://example.com/a", ""},
		{"", "https://example.com/a", ""},
	} {
		if got := resultAge(c.provider, c.url, dateNow); got != c.want {
			t.Errorf("resultAge(%q, %q) = %q, want %q", c.provider, c.url, got, c.want)
		}
	}
}

func TestPageAge(t *testing.T) {
	page := func(head, body string) *html.Node {
		doc, err := html.Parse(strings.NewReader("<html><head>" + head + "</head><body>" + body + "</body></html>"))
		if err != nil {
			t.Fatal(err)
		}
		return doc
	}
	ld := func(v map[string]any) string {
		b, _ := json.Marshal(v)
		return `<script type="application/ld+json">` + string(b) + `</script>`
	}
	for _, c := range []struct {
		name, head, body, url, want string
	}{
		{"json-ld article", ld(map[string]any{"@type": "NewsArticle", "datePublished": "2026-09-16T08:00:00Z", "dateModified": "2026-10-01T09:00:00Z"}), "", "https://e.com/a", "2026-09-16, updated 2026-10-01"},
		{"json-ld graph webpage", ld(map[string]any{"@graph": []any{map[string]any{"@type": "Organization", "foundingDate": "1999-01-01"}, map[string]any{"@type": "WebPage", "datePublished": "2025-03-02"}}}), "", "https://e.com/a", "2025-03-02"},
		{"json-ld product has no page date", ld(map[string]any{"@type": "Product", "releaseDate": "2026-01-01"}), "", "https://e.com/a", ""},
		{"event dates aren't the page's", ld(map[string]any{"@type": "Event", "startDate": "2026-10-20", "datePublished": "2026-10-20"}), "", "https://e.com/a", ""},
		{"article meta", `<meta property="article:published_time" content="2026-08-18T20:30:04Z"><meta property="article:modified_time" content="2026-08-19T08:47:00Z">`, "", "https://e.com/a", "2026-08-18, updated 2026-08-19"},
		{"dublin core", `<meta name="DC.date.issued" content="2024-05-12">`, "", "https://e.com/a", "2024-05-12"},
		{"citation", `<meta name="citation_publication_date" content="2023/07/27">`, "", "https://e.com/a", "2023-07-27"},
		{"only modified", `<meta property="og:updated_time" content="2026-10-02T10:00:00+00:00">`, "", "https://e.com/a", "updated 2026-10-02"},
		{"time itemprop", "", `<p>By X, <time itemprop="datePublished" datetime="2026-05-04">May 4</time></p>`, "https://e.com/a", "2026-05-04"},
		{"one time element", "", `<article><time datetime="2025-09-25T12:00:00Z">Sept 25</time></article>`, "https://e.com/a", "2025-09-25"},
		{"several time elements", "", `<time datetime="2026-01-01">a</time><time datetime="2026-02-01">b</time>`, "https://e.com/a", ""},
		{"text dates are never read", "", `<p>Published September 16, 2026</p>`, "https://e.com/a", ""},
		{"address fallback", "", "", "https://e.com/2026/03/19/statement", "2026-03-19"},
		{"metadata over address", `<meta name="date" content="2026-03-20">`, "", "https://e.com/2026/03/19/statement", "2026-03-20"},
		{"implausible metadata", `<meta name="date" content="2099-01-01">`, "", "https://e.com/a", ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := pageAge(page(c.head, c.body), c.url, dateNow); got != c.want {
				t.Errorf("pageAge = %q, want %q", got, c.want)
			}
		})
	}
}

// A page read's date reaches the model as its age (code's, like a search result's) and the person as the citation's
// Age; a search result without the provider's date gets its address's.
func TestSourceDatesReachModelAndPerson(t *testing.T) {
	tl := &Tools{}
	u, _ := url.Parse("https://news.example.com/story")
	pg := fetched{final: u.String(), title: "Story", text: "Some text."}
	_, _, _, _, pg.age = htmlPage(`<html><head><meta property="article:published_time" content="2026-09-16T08:00:00Z"></head><body><p>x</p></body></html>`, u)
	out := tl.Finish(pending{out: toolOutcome{ran: true}, page: &pg})
	var m map[string]any
	if err := json.Unmarshal([]byte(out.content), &m); err != nil {
		t.Fatal(err)
	}
	if m["age"] != "2026-09-16" || len(out.citations) != 1 || out.citations[0].Age != "2026-09-16" {
		t.Fatalf("page age: model %v, citations %+v", m["age"], out.citations)
	}
	rs := []SearchResult{{Title: "A", URL: "https://example.com/2026/08/01/a", Snippet: "s"}, {Title: "B", URL: "https://example.com/b", Snippet: "s", Age: "2026-10-13T19:46:12.000Z"}}
	for i := range rs {
		rs[i].Age = resultAge(rs[i].Age, rs[i].URL, dateNow)
	}
	out = tl.Finish(pending{out: toolOutcome{ran: true}, query: "q", results: rs})
	if len(out.citations) != 2 || out.citations[0].Age != "2026-08-01" || out.citations[1].Age != "2026-10-13" {
		t.Fatalf("result ages: %+v", out.citations)
	}
	if !strings.Contains(out.content, `"age":"2026-08-01"`) {
		t.Fatalf("model doesn't get the age: %s", out.content)
	}
}
