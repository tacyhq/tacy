package guard

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// A web search that Exa fails on its side goes to Tavily once (v0.13.0; on 2026-10-21 Exa's credit ran out, HTTP
// 402, and every web search failed until someone noticed). Only the provider changes: the query is the one the
// guard already masked, the call keeps the tool caps it took (one more token of the provider rate for each extra
// request), Tavily's key is leased from the vault like any (connector "web", host api.tavily.com, on the activity
// record), and the results have the same shape (Tavily's content is the snippet, as before Exa). Never sent on:
//   - a refusal by our own guards: they act before any provider is called (policy, permission, the leak scan,
//     personal data, the person's images, the agent's caps), and a key the vault refuses is a refusal too;
//   - Exa's own safety filter refusing the query (CONTENT_FILTER_ERROR): another provider must not get round it;
//   - a search the run cancelled.
// After breakerFailures failures in a row, Exa is skipped for breakerCooldown: searches go straight to Tavily
// ("breaker_open"), then Exa gets one search again.

// providerError is a search provider failing on its side: an HTTP status other than 200, no answer in time, no
// connection, an answer that doesn't parse. Its text is the same as before (the model and people read it); class
// is a fixed word for the metrics and the record (searchClass).
type providerError struct {
	class string
	msg   string
	// retryAfter: a 429's Retry-After, when it gave one in seconds.
	retryAfter time.Duration
}

func (e *providerError) Error() string { return e.msg }

// Failure classes (fixed words: the metrics event, the chat's request_metrics and the activity record carry them).
const (
	classTimeout     = "timeout"
	classUnreachable = "unreachable"
	classBadResponse = "bad_response"
	classBreakerOpen = "breaker_open" // not a failure: Exa was skipped, the breaker being open
	classRefused     = "refused"      // the fallback's key or host refused by the vault or the policy
	classFailed      = "failed"       // anything else
)

// httpFailure is a provider's non-200 answer: http_402, http_429, http_4xx (other 4xx), http_5xx.
func httpFailure(res *http.Response) error {
	e := &providerError{msg: fmt.Sprintf("search provider returned %d", res.StatusCode)}
	switch c := res.StatusCode; {
	case c == 401 || c == 402 || c == 403 || c == 429:
		e.class = "http_" + strconv.Itoa(c)
	case c >= 500:
		e.class = "http_5xx"
	default:
		e.class = "http_4xx"
	}
	if s, err := strconv.Atoi(res.Header.Get("Retry-After")); err == nil && s > 0 {
		e.retryAfter = time.Duration(s) * time.Second
	}
	return e
}

// transportFailure is a request that got no answer. A host our policy refused stays that refusal (never a provider
// failure); a cancelled search is the caller's (Search checks ctx itself).
func transportFailure(err error) error {
	if errors.Is(err, errHostPolicy) {
		return errors.New("host not allowed by the policy")
	}
	// A request refused before it left by a transport that says so (the labs' Exa cap, internal/labexa): no answer
	// from the provider, and not one to take elsewhere.
	var nf interface{ NoFallback() bool }
	if errors.As(err, &nf) && nf.NoFallback() {
		return errors.New("search provider unreachable")
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() || errors.Is(err, context.DeadlineExceeded) {
		return &providerError{class: classTimeout, msg: "search provider unreachable"}
	}
	return &providerError{class: classUnreachable, msg: "search provider unreachable"}
}

func badResponse() error {
	return &providerError{class: classBadResponse, msg: "search provider: bad response"}
}

// searchClass is err's failure class ("" for a refusal or no error: never a reason to fall back).
func searchClass(err error) string {
	var pe *providerError
	if errors.As(err, &pe) {
		return pe.class
	}
	return ""
}

// SearchInfo is how one web search went, for its metrics event and its activity record: the provider whose
// results these are (or that failed last), and when it went to the fallback, why (the primary's failure class, or
// breaker_open). Status is the search's own failure class when it failed ("" when it didn't, or was refused).
// Fixed words only, never the query.
type SearchInfo struct {
	Provider string
	Fallback string
	Status   string
}

// searchMore takes what one more provider request of a search needs (a token of the provider rate: limits.go);
// nil: nothing.
type searchMore func(ctx context.Context) error

// infoSearcher is a provider that says how a search went (fallbackSearch); tools.go uses it when there is one.
type infoSearcher interface {
	SearchInfo(ctx context.Context, query string, count int, more searchMore) ([]SearchResult, SearchInfo, error)
}

// fallbackSearch is the primary provider (Exa) with a fallback (Tavily) for its own failures.
type fallbackSearch struct {
	primary, fallback SearchProvider
	br                *breaker
	// retryWait is the longest a 429 is waited out before its one retry (its Retry-After, when shorter).
	retryWait time.Duration
}

const (
	breakerFailures = 3
	breakerCooldown = 3 * time.Minute
	retry429Wait    = time.Second
)

func newFallbackSearch(primary, fallback SearchProvider) *fallbackSearch {
	return &fallbackSearch{primary: primary, fallback: fallback, br: &breaker{max: breakerFailures, cool: breakerCooldown, now: time.Now},
		retryWait: retry429Wait}
}

func (f *fallbackSearch) Name() string { return f.primary.Name() }

func (f *fallbackSearch) Search(ctx context.Context, query string, count int) ([]SearchResult, error) {
	rs, _, err := f.SearchInfo(ctx, query, count, nil)
	return rs, err
}

func (f *fallbackSearch) SearchInfo(ctx context.Context, query string, count int, more searchMore) ([]SearchResult, SearchInfo, error) {
	if !f.br.allow() {
		return f.second(ctx, query, count, more, classBreakerOpen, true)
	}
	rs, err := f.primary.Search(ctx, query, count)
	class := searchClass(err)
	if class == "http_429" && ctx.Err() == nil {
		// One retry after a short wait (its Retry-After when shorter), then the fallback.
		wait := f.retryWait
		var pe *providerError
		if errors.As(err, &pe) && pe.retryAfter > 0 && pe.retryAfter < wait {
			wait = pe.retryAfter
		}
		t := time.NewTimer(wait)
		select {
		case <-t.C:
		case <-ctx.Done():
		}
		t.Stop()
		if ctx.Err() == nil && (more == nil || more(ctx) == nil) {
			rs, err = f.primary.Search(ctx, query, count)
			class = searchClass(err)
		}
	}
	switch {
	case err == nil:
		f.br.success()
		return rs, SearchInfo{Provider: f.primary.Name()}, nil
	case ctx.Err() != nil || class == "":
		// Cancelled, or refused (our guards, the vault, Exa's safety filter): no fallback, not a provider failure.
		return nil, SearchInfo{Provider: f.primary.Name(), Status: class}, err
	}
	f.br.failure()
	return f.second(ctx, query, count, more, class, false)
}

// second runs the search on the fallback. why: the primary's failure class, or breaker_open (skipped: then this
// is the search's only request, and its rate token is the one the call took already).
func (f *fallbackSearch) second(ctx context.Context, query string, count int, more searchMore, why string, skipped bool) ([]SearchResult, SearchInfo, error) {
	info := SearchInfo{Provider: f.fallback.Name(), Fallback: why}
	if !skipped && more != nil {
		if err := more(ctx); err != nil {
			return nil, info, err
		}
	}
	rs, err := f.fallback.Search(ctx, query, count)
	if err != nil && ctx.Err() == nil {
		if info.Status = searchClass(err); info.Status == "" {
			info.Status = classRefused // the vault refused Tavily's key, or the policy its host
		}
	}
	return rs, info, err
}

// Images, ImagesFast and ImageProvider are the primary's (image search has its own provider: exa.go).
func (f *fallbackSearch) Images(ctx context.Context, query string, count int) ([]ImageCandidate, error) {
	is, ok := f.primary.(ImageSearcher)
	if !ok {
		return nil, fmt.Errorf("image search isn't available with this search provider")
	}
	return is.Images(ctx, query, count)
}

func (f *fallbackSearch) ImagesFast(ctx context.Context, query string, count int) ([]ImageCandidate, error) {
	fs, ok := f.primary.(fastImageSearcher)
	if !ok {
		return nil, errNoFastImages
	}
	return fs.ImagesFast(ctx, query, count)
}

func (f *fallbackSearch) ImageProvider() string { return imageProviderName(f.primary) }

// breaker counts the primary's failures in a row; at max it opens for cool (searches skip the primary), then lets
// the next search try it again (one more failure opens it again at once).
type breaker struct {
	mu    sync.Mutex
	max   int
	cool  time.Duration
	now   func() time.Time
	fails int
	until time.Time
}

func (b *breaker) allow() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return !b.now().Before(b.until)
}

func (b *breaker) failure() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.fails++
	if b.fails >= b.max {
		b.until = b.now().Add(b.cool)
	}
}

func (b *breaker) success() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.fails, b.until = 0, time.Time{}
}
