package guard

import (
	"context"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/tacyhq/tacy/vault"
)

// SearchResult is one web result, already capped and stripped of markup.
type SearchResult struct {
	Title   string
	URL     string
	Snippet string
	Age     string
}

// SearchProvider runs a web search. The query it gets is already PII-masked.
type SearchProvider interface {
	Name() string
	Search(ctx context.Context, query string, count int) ([]SearchResult, error)
}

// brave is the Brave Search API (api.search.brave.com, web search endpoint). The VM's IP and the masked query are
// all Brave sees; no user identifiers, cookies or location headers are sent.
type brave struct {
	lease Lease // BRAVE_SEARCH_API_KEY, per request
	base  string
	http  *http.Client
}

func newBrave(lease Lease) *brave {
	return &brave{lease: lease, base: "https://api.search.brave.com/res/v1/web/search", http: &http.Client{Timeout: 20 * time.Second}}
}

const (
	braveKey  = "BRAVE_SEARCH_API_KEY"
	tavilyKey = "TAVILY_API_KEY"
)

func (b *brave) Name() string { return "brave" }

var tagRe = regexp.MustCompile(`<[^>]*>`)

// clean strips markup Brave puts in snippets (<strong>), unescapes entities and caps the length.
func clean(s string, max int) string {
	s = html.UnescapeString(tagRe.ReplaceAllString(s, ""))
	s = strings.Join(strings.Fields(s), " ")
	return capRunes(s, max)
}

func capRunes(s string, max int) string {
	r := []rune(s)
	if len(r) > max {
		return string(r[:max]) + "…"
	}
	return s
}

func (b *brave) Search(ctx context.Context, query string, count int) ([]SearchResult, error) {
	key, err := searchKey(ctx, b.lease, braveKey, b.base)
	if err != nil {
		return nil, err
	}
	defer key.Wipe()
	q := url.Values{"q": {query}, "count": {fmt.Sprint(count)}, "safesearch": {"moderate"},
		"text_decorations": {"false"}, "result_filter": {"web"}}
	req, _ := http.NewRequestWithContext(ctx, "GET", b.base+"?"+q.Encode(), nil)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-Subscription-Token", string(key.Bytes()))
	res, err := b.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("search provider unreachable")
	}
	defer res.Body.Close()
	body, err := io.ReadAll(io.LimitReader(res.Body, 2<<20))
	if err != nil {
		return nil, err
	}
	body = exactRedact(body, []*vault.Secret{key}) // an echoed key never reaches the brain
	if res.StatusCode != 200 {
		return nil, fmt.Errorf("search provider returned %d", res.StatusCode)
	}
	var out struct {
		Web struct {
			Results []struct {
				Title         string   `json:"title"`
				URL           string   `json:"url"`
				Description   string   `json:"description"`
				Age           string   `json:"age"`
				ExtraSnippets []string `json:"extra_snippets"`
			} `json:"results"`
		} `json:"web"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("search provider: bad response")
	}
	var rs []SearchResult
	for _, r := range out.Web.Results {
		u, err := url.Parse(r.URL)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") {
			continue
		}
		snippet := r.Description
		if len(r.ExtraSnippets) > 0 {
			snippet += " … " + r.ExtraSnippets[0]
		}
		rs = append(rs, SearchResult{Title: clean(r.Title, 200), URL: capRunes(r.URL, 500),
			Snippet: clean(snippet, 600), Age: clean(r.Age, 40)})
		if len(rs) == count {
			break
		}
	}
	return rs, nil
}

// tavily is the Tavily Search API (api.tavily.com/search), the fallback when no Brave key is configured. Same
// deal as Brave: it sees the VM's IP and the masked query only.
type tavily struct {
	lease Lease // TAVILY_API_KEY, per request
	base  string
	http  *http.Client
}

func newTavily(lease Lease) *tavily {
	return &tavily{lease: lease, base: "https://api.tavily.com/search", http: &http.Client{Timeout: 20 * time.Second}}
}

func (t *tavily) Name() string { return "tavily" }

func (t *tavily) Search(ctx context.Context, query string, count int) ([]SearchResult, error) {
	key, err := searchKey(ctx, t.lease, tavilyKey, t.base)
	if err != nil {
		return nil, err
	}
	defer key.Wipe()
	body, _ := json.Marshal(map[string]any{"query": query, "max_results": count, "search_depth": "basic",
		"include_answer": false, "include_raw_content": false, "include_images": false})
	req, _ := http.NewRequestWithContext(ctx, "POST", t.base, strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+string(key.Bytes()))
	res, err := t.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("search provider unreachable")
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, 2<<20))
	if err != nil {
		return nil, err
	}
	raw = exactRedact(raw, []*vault.Secret{key}) // an echoed key never reaches the brain
	if res.StatusCode != 200 {
		return nil, fmt.Errorf("search provider returned %d", res.StatusCode)
	}
	var out struct {
		Results []struct {
			Title         string `json:"title"`
			URL           string `json:"url"`
			Content       string `json:"content"`
			PublishedDate string `json:"published_date"`
		} `json:"results"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("search provider: bad response")
	}
	var rs []SearchResult
	for _, r := range out.Results {
		u, err := url.Parse(r.URL)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") {
			continue
		}
		rs = append(rs, SearchResult{Title: clean(r.Title, 200), URL: capRunes(r.URL, 500),
			Snippet: clean(r.Content, 600), Age: clean(r.PublishedDate, 40)})
		if len(rs) == count {
			break
		}
	}
	return rs, nil
}

// Images is Tavily's search with include_images: the top-level images (with a generated description and the
// title of the page they come from) first, then images extracted from the results (those have their page URL).
// A top-level image whose URL also appears in a result's images, or whose page title equals a result's title,
// gets that result's URL as its source. Logos and descriptionless page images are skipped. One search credit.
func (t *tavily) Images(ctx context.Context, query string, count int) ([]ImageCandidate, error) {
	key, err := searchKey(ctx, t.lease, tavilyKey, t.base)
	if err != nil {
		return nil, err
	}
	defer key.Wipe()
	body, _ := json.Marshal(map[string]any{"query": query, "max_results": 5, "search_depth": "basic",
		"include_answer": false, "include_raw_content": false, "include_images": true, "include_image_descriptions": true})
	req, _ := http.NewRequestWithContext(ctx, "POST", t.base, strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+string(key.Bytes()))
	res, err := t.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("search provider unreachable")
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, 2<<20))
	if err != nil {
		return nil, err
	}
	raw = exactRedact(raw, []*vault.Secret{key}) // an echoed key never reaches the brain
	if res.StatusCode != 200 {
		return nil, fmt.Errorf("search provider returned %d", res.StatusCode)
	}
	return parseTavilyImages(raw, count)
}

type tavilyImage struct {
	URL         string `json:"url"`
	Title       string `json:"title"`
	Description string `json:"description"`
}

// UnmarshalJSON accepts an image as a plain URL string too (Tavily's format without descriptions).
func (i *tavilyImage) UnmarshalJSON(b []byte) error {
	var s string
	if json.Unmarshal(b, &s) == nil {
		i.URL = s
		return nil
	}
	type plain tavilyImage
	return json.Unmarshal(b, (*plain)(i))
}

func parseTavilyImages(raw []byte, count int) ([]ImageCandidate, error) {
	var out struct {
		Images  []tavilyImage `json:"images"`
		Results []struct {
			Title  string        `json:"title"`
			URL    string        `json:"url"`
			Images []tavilyImage `json:"images"`
		} `json:"results"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("search provider: bad response")
	}
	pageOf := map[string]string{}      // image URL -> result URL
	pageByTitle := map[string]string{} // result title -> result URL
	for _, r := range out.Results {
		if !httpURL(r.URL) {
			continue
		}
		pageByTitle[strings.TrimSpace(r.Title)] = r.URL
		for _, im := range r.Images {
			pageOf[im.URL] = r.URL
		}
	}
	var cs []ImageCandidate
	add := func(u, title, source string) {
		if !httpURL(u) || len(cs) >= count {
			return
		}
		cs = append(cs, ImageCandidate{URL: capRunes(u, 1000), Title: clean(title, 200), Source: capRunes(source, 500)})
	}
	for _, im := range out.Images {
		src := pageOf[im.URL]
		if src == "" {
			src = pageByTitle[strings.TrimSpace(im.Title)]
		}
		title := im.Title
		if title == "" {
			title = im.Description
		}
		add(im.URL, title, src)
	}
	for _, r := range out.Results {
		for _, im := range r.Images {
			if im.Description == "" || strings.Contains(strings.ToLower(im.URL), "logo") {
				continue
			}
			add(im.URL, im.Description, r.URL)
		}
	}
	return cs, nil
}

func httpURL(s string) bool {
	u, err := url.Parse(s)
	return err == nil && (u.Scheme == "https" || u.Scheme == "http") && u.Host != ""
}

// Images is Brave's image search (api.search.brave.com/res/v1/images/search): each result has the page it is on
// and the original image URL (properties.url). Brave's own thumbnail proxy isn't used: the VM fetches the original.
func (b *brave) Images(ctx context.Context, query string, count int) ([]ImageCandidate, error) {
	key, err := searchKey(ctx, b.lease, braveKey, b.base)
	if err != nil {
		return nil, err
	}
	defer key.Wipe()
	q := url.Values{"q": {query}, "count": {fmt.Sprint(min(count*2, 50))}, "safesearch": {"strict"}}
	base := strings.Replace(b.base, "/web/search", "/images/search", 1)
	req, _ := http.NewRequestWithContext(ctx, "GET", base+"?"+q.Encode(), nil)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-Subscription-Token", string(key.Bytes()))
	res, err := b.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("search provider unreachable")
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, 2<<20))
	if err != nil {
		return nil, err
	}
	raw = exactRedact(raw, []*vault.Secret{key}) // an echoed key never reaches the brain
	if res.StatusCode != 200 {
		return nil, fmt.Errorf("search provider returned %d", res.StatusCode)
	}
	var out struct {
		Results []struct {
			Title      string `json:"title"`
			URL        string `json:"url"`
			Properties struct {
				URL string `json:"url"`
			} `json:"properties"`
		} `json:"results"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("search provider: bad response")
	}
	var cs []ImageCandidate
	for _, r := range out.Results {
		if !httpURL(r.Properties.URL) {
			continue
		}
		src := ""
		if httpURL(r.URL) {
			src = capRunes(r.URL, 500)
		}
		cs = append(cs, ImageCandidate{URL: capRunes(r.Properties.URL, 1000), Title: clean(r.Title, 200), Source: src})
		if len(cs) == count {
			break
		}
	}
	return cs, nil
}

// NewSearch picks the provider: provider (SEARCH_PROVIDER: brave | tavily) if set, else Brave when its key is set
// (has: the vault's names, never values), else Tavily. Keys are leased per request.
func NewSearch(provider string, has func(name string) bool, lease Lease) SearchProvider {
	switch provider {
	case "brave":
		return newBrave(lease)
	case "tavily":
		return newTavily(lease)
	}
	if has(braveKey) {
		return newBrave(lease)
	}
	return newTavily(lease)
}
