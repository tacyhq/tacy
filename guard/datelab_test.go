//go:build datelab

// The source-date lab (research-dates, 2026-10-21): how many of the web sources research reports cited had a date
// Tacy's code knew, then and with sourcedate.go, on the same inputs: the research lab's saved runs (LabOut JSON,
// the chat's research scorecard) and its page cache (the pages those runs read, as fetched). No network, no
// model, no cost.
//
//	DATELAB_RUNS=dir1,dir2 DATELAB_PAGES=cache/pages go test -tags datelab -run TestDateLab -v ./guard
package guard

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestDateLab(t *testing.T) {
	runs, pages := os.Getenv("DATELAB_RUNS"), os.Getenv("DATELAB_PAGES")
	if runs == "" {
		t.Skip("DATELAB_RUNS not set")
	}
	cite := regexp.MustCompile(`\[(\d{1,3})\]`)
	type tally struct{ n, before, after, provider, address, meta int }
	var search, page tally
	now := time.Now()
	for _, dir := range strings.Split(runs, ",") {
		files, _ := filepath.Glob(filepath.Join(dir, "*.json"))
		for _, f := range files {
			base := filepath.Base(f)
			if strings.HasPrefix(base, "_") || strings.Count(base, ".") > 1 {
				continue // judged, fresh, overloaded and the round's own files
			}
			raw, err := os.ReadFile(f)
			if err != nil {
				continue
			}
			var o struct {
				Text    string `json:"text"`
				Results []struct {
					Name      string `json:"name"`
					Citations []struct {
						Index int    `json:"index"`
						URL   string `json:"url"`
						Age   string `json:"age"`
					} `json:"citations"`
				} `json:"results"`
			}
			if json.Unmarshal(raw, &o) != nil || o.Text == "" {
				continue
			}
			body, _, _ := strings.Cut(o.Text, "\n## Sources")
			cited := map[int]bool{}
			for _, m := range cite.FindAllStringSubmatch(body, -1) {
				var n int
				json.Unmarshal([]byte(m[1]), &n)
				cited[n] = true
			}
			for _, r := range o.Results {
				for _, c := range r.Citations {
					if !cited[c.Index] {
						continue
					}
					delete(cited, c.Index)
					switch r.Name {
					case "web_search":
						search.n++
						if c.Age != "" {
							search.before++
						}
						a := resultAge(c.Age, c.URL, now)
						if a != "" {
							search.after++
							if providerAge(c.Age, now) != "" {
								search.provider++
							} else {
								search.address++
								if os.Getenv("DATELAB_SHOW") != "" {
									t.Logf("address date %s: %s", a, c.URL)
								}
							}
						}
					case "fetch_page":
						page.n++
						if c.Age != "" {
							page.before++
						}
						a := ""
						if html := cachedPage(pages, c.URL); html != "" {
							u, _ := url.Parse(c.URL)
							_, _, _, _, a = htmlPage(html, u)
							if a != "" && a != urlDate(c.URL, now) {
								page.meta++
							}
						} else {
							a = urlDate(c.URL, now)
						}
						if a != "" {
							page.after++
							if a == urlDate(c.URL, now) {
								page.address++
							}
						} else if os.Getenv("DATELAB_SHOW") != "" {
							t.Logf("undated page: %s (cached: %v)", c.URL, cachedPage(pages, c.URL) != "")
						}
					}
				}
			}
		}
	}
	all := search.n + page.n
	t.Logf("cited search results: %d; dated before %d (%.0f%%), after %d (%.0f%%): provider %d, address %d",
		search.n, search.before, pct(search.before, search.n), search.after, pct(search.after, search.n), search.provider, search.address)
	t.Logf("cited page reads: %d; dated before %d (%.0f%%), after %d (%.0f%%): metadata %d, address %d",
		page.n, page.before, pct(page.before, page.n), page.after, pct(page.after, page.n), page.meta, page.address)
	t.Logf("all cited web sources: %d; dated before %d (%.0f%%), after %d (%.0f%%)", all, search.before+page.before,
		pct(search.before+page.before, all), search.after+page.after, pct(search.after+page.after, all))
}

func pct(a, b int) float64 {
	if b == 0 {
		return 0
	}
	return 100 * float64(a) / float64(b)
}

// cachedPage is a page as the research lab's cache recorded its GET (app/researchlab_test.go labTransport), or "".
func cachedPage(dir, raw string) string {
	if dir == "" {
		return ""
	}
	h := sha256.Sum256([]byte("GET " + raw + "\n"))
	b, err := os.ReadFile(filepath.Join(dir, hex.EncodeToString(h[:12])+".json"))
	if err != nil {
		return ""
	}
	var e struct {
		Status int    `json:"status"`
		Body   string `json:"body"`
	}
	if json.Unmarshal(b, &e) != nil || e.Status != 200 {
		return ""
	}
	page, err := readHTML(strings.NewReader(e.Body))
	if err != nil {
		return ""
	}
	return string(page)
}
