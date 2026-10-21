package storedfiles

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/tacyhq/tacy/proto"
)

// The production bucket's S3 endpoint and name (the chat's Cloudflare account; DEPLOY.md "File storage"). The release
// pins them; the signed policy must list the host for the files connector too (files.fetch, policies/chat-v5.json).
const (
	R2Host = "df4bf4829cdbbca3dca42a266b41b170.r2.cloudflarestorage.com"
	Bucket = "tacy-files"
)

// userAgent is what every request to R2 says: generic, nothing about the person or the run.
const userAgent = "tacy-vm"

// Fetcher reads stored objects from R2 with the presigned URLs the chat's Worker minted (GET only, an hour, one object
// each). It reads only what a ref names: the URL's host must be Host, its path exactly /<Bucket>/f/<owner>/<object> of
// that ref, and it must carry a SigV4 query signature; anything else is refused before a request is made. No
// redirects, no cookies, exact byte counts, and every byte fetched is counted against the run's Budget.
type Fetcher struct {
	Client *http.Client // nil: DefaultClient()
	Host   string       // "": R2Host
	Bucket string       // "": Bucket
	// Scheme is "https" in every release; tests and labs serving a stand-in over plain HTTP set "http".
	Scheme string
}

// DefaultClient is the fetcher's client: no redirects, bounded time, the system's TLS roots.
func DefaultClient() *http.Client {
	return &http.Client{
		Timeout: 2 * time.Minute,
		Transport: &http.Transport{
			Proxy:                 nil,
			DialContext:           (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 30 * time.Second,
			MaxIdleConnsPerHost:   4,
			ForceAttemptHTTP2:     true,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// ErrScope: a URL that doesn't name exactly the ref's object in the files bucket (another object, another account's,
// another host): refused before anything is sent.
var ErrScope = errors.New("storedfiles: the read URL isn't this file's object")

// ErrBudget: the run has fetched as many bytes as it may (MaxRunBytes).
var ErrBudget = fmt.Errorf("storedfiles: this run has read its %d MB of stored files", MaxRunBytes>>20)

// Budget counts what one run fetched, against MaxRunBytes (stored bytes). Safe for concurrent use.
type Budget struct {
	mu    sync.Mutex
	bytes int64
	Limit int64 // 0: MaxRunBytes
}

// Take counts n bytes, or refuses when they'd pass the limit.
func (b *Budget) Take(n int64) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	limit := b.Limit
	if limit <= 0 {
		limit = MaxRunBytes
	}
	if n < 0 || b.bytes+n > limit {
		return ErrBudget
	}
	b.bytes += n
	return nil
}

// Used is the bytes fetched so far.
func (b *Budget) Used() int64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.bytes
}

func (fe *Fetcher) host() string   { return cmpOr(fe.Host, R2Host) }
func (fe *Fetcher) bucket() string { return cmpOr(fe.Bucket, Bucket) }
func (fe *Fetcher) scheme() string { return cmpOr(fe.Scheme, "https") }

func cmpOr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// CheckURL is the scope check: u reads exactly f's object in the files bucket on the files host, signed.
func (fe *Fetcher) CheckURL(f *proto.StoredFile, raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != fe.scheme() || u.User != nil || u.Host != fe.host() || u.Fragment != "" || u.Opaque != "" {
		return nil, ErrScope
	}
	if u.EscapedPath() != "/"+fe.bucket()+"/"+ObjectKey(f.Owner, f.Object) {
		return nil, ErrScope
	}
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil || q.Get("X-Amz-Algorithm") != "AWS4-HMAC-SHA256" || q.Get("X-Amz-Signature") == "" || q.Has("x-id") && q.Get("x-id") != "GetObject" {
		return nil, ErrScope
	}
	return u, nil
}

// Reader is a ReadFunc for f's object through rawURL (f.URL, or one a URLSource gave), counted against budget.
func (fe *Fetcher) Reader(f *proto.StoredFile, rawURL string, budget *Budget) (ReadFunc, error) {
	u, err := fe.CheckURL(f, rawURL)
	if err != nil {
		return nil, err
	}
	client := fe.Client
	if client == nil {
		client = DefaultClient()
	}
	total := ObjectBytes(f.Padded)
	return func(ctx context.Context, from, to int64) ([]byte, error) {
		if from < 0 || to <= from || to > total {
			return nil, ErrBadSize
		}
		if err := budget.Take(to - from); err != nil {
			return nil, err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", userAgent)
		req.Header.Set("Range", "bytes="+strconv.FormatInt(from, 10)+"-"+strconv.FormatInt(to-1, 10))
		req.Header.Set("Accept-Encoding", "identity")
		resp, err := client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("storedfiles: fetch: %w", scrubURL(err))
		}
		defer resp.Body.Close()
		switch resp.StatusCode {
		case http.StatusPartialContent:
			if resp.Header.Get("Content-Range") != fmt.Sprintf("bytes %d-%d/%d", from, to-1, total) {
				return nil, ErrShort
			}
		case http.StatusOK: // a store that ignored the range: only right for the whole object
			if from != 0 || to != total {
				return nil, ErrShort
			}
		case http.StatusNotFound, http.StatusForbidden:
			return nil, fmt.Errorf("storedfiles: the file is gone or its read URL expired (%d)", resp.StatusCode)
		default:
			return nil, fmt.Errorf("storedfiles: fetch: status %d", resp.StatusCode)
		}
		b, err := io.ReadAll(io.LimitReader(resp.Body, to-from+1))
		if err != nil {
			return nil, fmt.Errorf("storedfiles: fetch: %w", scrubURL(err))
		}
		if int64(len(b)) != to-from {
			return nil, ErrShort
		}
		return b, nil
	}, nil
}

// scrubURL keeps a presigned URL (its signature) out of an error that may reach a log or the model.
func scrubURL(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return fmt.Errorf("%s: %w", strings.ToLower(ue.Op), ue.Err)
	}
	return err
}
