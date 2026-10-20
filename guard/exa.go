package guard

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/tacyhq/tacy/vault"
)

// exa is Exa's search API (POST api.exa.ai/search; docs/29, decided 2026-10-18): the web search provider since
// v0.8.10. Exa sees the VM's IP, our key and the masked query, nothing else: the body has only the query, the result
// count, the search type, moderation and the highlights asked for; never Exa's optional user id, location or
// integration fields (userLocation, userIdentifier, x-exa-integration). Exa has no image search, so image_search
// stays on the provider it used before (images: Brave when its key is set, else Tavily).
type exa struct {
	lease  Lease // EXA_API_KEY, per request
	base   string
	http   *http.Client
	images imageProvider // web.images; nil: none
}

// imageProvider is a provider that searches images (image_search), with its name for the metrics.
type imageProvider interface {
	ImageSearcher
	Name() string
}

const exaKey = "EXA_API_KEY"

// exaType is Exa's search type: "fast" ($7 per 1,000 searches, about 0.8 s in the smoke test of 2026-10-18), or
// "instant" ($4, about 0.4 s). Highlights add about $1 per 1,000 pages (https://exa.ai/pricing).
const exaType = "fast"

// exaHighlightChars is roughly how much highlight text Exa returns per result (it may return more; the snippet is
// capped at maxSnippetRunes anyway, as Brave's and Tavily's are). 4,000 since v0.8.13 (search.go's measurement),
// 2,000 in v0.8.12 (was 400): measured on 10 questions 2026-10-19, the 400-character highlights kept none of the 48
// sneakers the pages named, and the share of an answer's specifics the sources back went from 71% to 90% with 2,000
// (and the reader's prompt naming items). Full text at 3,000 doubled the reader's time without more found; type
// "auto" found nothing more in about 6 s.
const exaHighlightChars = maxSnippetRunes

func newExa(lease Lease, images imageProvider) *exa {
	return &exa{lease: lease, base: "https://api.exa.ai/search", http: recordingClient(&http.Client{Timeout: 20 * time.Second}),
		images: images}
}

func (e *exa) Name() string { return "exa" }

// exaRequest is everything that goes to Exa. A struct, not a map, so nothing else can be added by accident.
type exaRequest struct {
	Query      string      `json:"query"`
	NumResults int         `json:"numResults"`
	Type       string      `json:"type"`
	Moderation bool        `json:"moderation"`
	Contents   exaContents `json:"contents"`
}

type exaContents struct {
	Highlights exaHighlights `json:"highlights"`
}

type exaHighlights struct {
	MaxCharacters int `json:"maxCharacters"`
}

func (e *exa) Search(ctx context.Context, query string, count int) ([]SearchResult, error) {
	key, err := searchKey(ctx, e.lease, exaKey, e.base)
	if err != nil {
		return nil, err
	}
	defer key.Wipe()
	// moderation: Exa's "filter unsafe content" (default off). Checked 2026-10-18 with made-up queries: an outright
	// pornographic query is refused (403 CONTENT_FILTER_ERROR); a milder one ("explicit nude photos") still returns
	// some adult and erotic sites, fewer than without it. Not as strict as Brave's safesearch.
	body, _ := json.Marshal(exaRequest{Query: query, NumResults: count, Type: exaType, Moderation: true,
		Contents: exaContents{Highlights: exaHighlights{MaxCharacters: exaHighlightChars}}})
	req, _ := http.NewRequestWithContext(ctx, "POST", e.base, strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("x-api-key", string(key.Bytes()))
	res, err := e.http.Do(req)
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
		// Exa's error text quotes the query back: only our own words and the status go on.
		var er struct {
			Tag string `json:"tag"`
		}
		if json.Unmarshal(raw, &er) == nil && er.Tag == "CONTENT_FILTER_ERROR" {
			return nil, fmt.Errorf("the search provider's safety filter refused this query")
		}
		return nil, fmt.Errorf("search provider returned %d", res.StatusCode)
	}
	return parseExa(raw, count)
}

func parseExa(raw []byte, count int) ([]SearchResult, error) {
	var out struct {
		Results []struct {
			Title         string   `json:"title"`
			URL           string   `json:"url"`
			PublishedDate string   `json:"publishedDate"`
			Highlights    []string `json:"highlights"`
			// Image: the page's main picture as Exa names it, a card picture candidate (cardpics.go); never shown to
			// the model. Favicon isn't used: the VM fetches site icons itself (favicons.go).
			Image string `json:"image"`
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
		rs = append(rs, SearchResult{Title: clean(r.Title, maxTitleRunes), URL: capRunes(r.URL, 500),
			Snippet: clean(strings.Join(r.Highlights, " … "), maxSnippetRunes), Age: clean(r.PublishedDate, 40), Thumbs: thumbsOf(r.Image)})
		if len(rs) == count {
			break
		}
	}
	return rs, nil
}

// Images is the image provider's (Exa has no image search).
func (e *exa) Images(ctx context.Context, query string, count int) ([]ImageCandidate, error) {
	if e.images == nil {
		return nil, fmt.Errorf("image search isn't available with this search provider")
	}
	return e.images.Images(ctx, query, count)
}

// ImagesFast is the image provider's fast search (card lookups, v0.10.1), when it has one.
func (e *exa) ImagesFast(ctx context.Context, query string, count int) ([]ImageCandidate, error) {
	f, ok := e.images.(fastImageSearcher)
	if !ok {
		return nil, errNoFastImages
	}
	return f.ImagesFast(ctx, query, count)
}

// ImageProvider names the provider image_search goes to (the metrics' provider).
func (e *exa) ImageProvider() string {
	if e.images == nil {
		return ""
	}
	return e.images.Name()
}

// imageProviderName is the name of the provider image_search uses with search s: its own, unless it hands images
// to another (Exa).
func imageProviderName(s SearchProvider) string {
	if p, ok := s.(interface{ ImageProvider() string }); ok {
		return p.ImageProvider()
	}
	return s.Name()
}
