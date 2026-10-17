package release

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Limits for what FetchBundles and ResolveAttestations read. A bundle is a few KB; these only stop a hostile or
// broken server from making the client read or allocate without bound.
const (
	MaxAttestationsResponse = 16 << 20 // the attestations API response
	MaxBundleBlob           = 1 << 20  // one bundle_url download, as served (compressed)
	MaxBundle               = 4 << 20  // one bundle, decoded
	MaxAttestations         = 10       // entries followed per response (a digest normally has one or two)
	FetchTimeout            = 30 * time.Second
)

// AttestationsURL is where GitHub serves the Sigstore bundles for a digest, without authentication for a public
// repository: GET https://api.github.com/repos/tacyhq/tacy/attestations/sha256:<hex>. Nothing fetched from it is
// trusted; every bundle is verified. A relay may serve the same response (the browser need not call GitHub).
func AttestationsURL(repo string, composeSHA256 []byte) string {
	if repo == "" {
		repo = Repo
	}
	return "https://api.github.com/repos/" + repo + "/attestations/sha256:" + hex.EncodeToString(composeSHA256)
}

// Attestation is one entry of an attestations API response. GitHub either inlines the bundle or, as it now
// mostly does, sets bundle to null and gives a short-lived bundle_url (Azure blob storage) where the bundle is
// stored Snappy-compressed.
type Attestation struct {
	Bundle    json.RawMessage `json:"bundle"`
	BundleURL string          `json:"bundle_url"`
}

func (a Attestation) inline() bool { return len(a.Bundle) > 0 && string(a.Bundle) != "null" }

func parseEntries(body []byte) ([]Attestation, error) {
	var r struct {
		Attestations []Attestation `json:"attestations"`
	}
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, fmt.Errorf("attestations response: %w", err)
	}
	if len(r.Attestations) == 0 {
		return nil, errors.New("no attestation in the response")
	}
	return r.Attestations, nil
}

// ParseAttestations returns the inline bundles in an attestations API response, without network. Entries that
// only carry a bundle_url are skipped; ResolveAttestations follows them.
func ParseAttestations(body []byte) ([][]byte, error) {
	entries, err := parseEntries(body)
	if err != nil {
		return nil, err
	}
	var out [][]byte
	for _, a := range entries {
		if a.inline() {
			out = append(out, a.Bundle)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("no inline bundle in the attestations response")
	}
	return out, nil
}

// FetchBundles gets the bundles GitHub has for composeSHA256 in repo ("" = Repo): the attestations API response,
// with every bundle_url followed (ResolveAttestations). c nil = a client with FetchTimeout. The bundles are not
// verified; pass them to Verify or VerifyAny.
func FetchBundles(ctx context.Context, c *http.Client, repo string, composeSHA256 []byte) ([][]byte, error) {
	u := AttestationsURL(repo, composeSHA256)
	req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	res, err := client(c).Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	body, err := readLimited(res.Body, MaxAttestationsResponse)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", u, err)
	}
	if res.StatusCode != 200 {
		return nil, fmt.Errorf("%s: HTTP %d (no release for compose %x?)", u, res.StatusCode, composeSHA256)
	}
	return ResolveAttestations(ctx, c, body)
}

// ResolveAttestations returns the bundles in an attestations API response (from GitHub or a relay): inline ones
// as they are, bundle_url ones downloaded and decoded (FetchBundleURL), at most MaxAttestations. It fails only if
// no bundle could be had; then the error is the first one.
func ResolveAttestations(ctx context.Context, c *http.Client, body []byte) ([][]byte, error) {
	entries, err := parseEntries(body)
	if err != nil {
		return nil, err
	}
	if len(entries) > MaxAttestations {
		entries = entries[:MaxAttestations]
	}
	var out [][]byte
	var first error
	for _, a := range entries {
		var b []byte
		switch {
		case a.inline():
			b = a.Bundle
		case a.BundleURL != "":
			b, err = FetchBundleURL(ctx, c, a.BundleURL)
		default:
			err = errors.New("attestation has neither bundle nor bundle_url")
		}
		if b != nil {
			out = append(out, b)
		} else if first == nil {
			first = err
		}
	}
	if len(out) == 0 {
		return nil, first
	}
	return out, nil
}

// bundleHostSuffix is where GitHub stores bundles (tmaproduction.blob.core.windows.net). The URL comes from an
// unverified response, so only https to this storage is followed: the bundle is verified anyway, this only keeps
// a hostile response from pointing the client at other hosts (its local network, say).
const bundleHostSuffix = ".blob.core.windows.net"

// FetchBundleURL downloads one attestation's bundle_url and decodes it (DecodeBundleBlob). No redirects, at most
// MaxBundleBlob bytes, FetchTimeout unless c sets its own timeout.
func FetchBundleURL(ctx context.Context, c *http.Client, bundleURL string) ([]byte, error) {
	u, err := url.Parse(bundleURL)
	if err != nil || u.Scheme != "https" || u.User != nil || !strings.HasSuffix(u.Hostname(), bundleHostSuffix) ||
		u.Port() != "" {
		return nil, fmt.Errorf("bundle_url %q isn't https on *%s", trimQuery(bundleURL), bundleHostSuffix)
	}
	req, err := http.NewRequestWithContext(ctx, "GET", u.String(), nil)
	if err != nil {
		return nil, err
	}
	cc := *client(c)
	cc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	res, err := cc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("bundle_url: %w", err)
	}
	defer res.Body.Close()
	blob, err := readLimited(res.Body, MaxBundleBlob)
	if err != nil {
		return nil, fmt.Errorf("bundle_url %s: %w", trimQuery(bundleURL), err)
	}
	if res.StatusCode != 200 {
		return nil, fmt.Errorf("bundle_url %s: HTTP %d", trimQuery(bundleURL), res.StatusCode)
	}
	return DecodeBundleBlob(blob)
}

// DecodeBundleBlob turns what a bundle_url serves into the bundle JSON Verify takes: Snappy (block format)
// decoded, at most MaxBundle bytes. Plain JSON is returned as is.
func DecodeBundleBlob(blob []byte) ([]byte, error) {
	if json.Valid(blob) {
		return blob, nil
	}
	b, err := decodeSnappy(blob, MaxBundle)
	if err != nil {
		return nil, fmt.Errorf("bundle blob: %w", err)
	}
	if !json.Valid(b) {
		return nil, errors.New("bundle blob: decoded bundle isn't JSON")
	}
	return b, nil
}

func client(c *http.Client) *http.Client {
	if c == nil {
		return &http.Client{Timeout: FetchTimeout}
	}
	if c.Timeout == 0 {
		cc := *c
		cc.Timeout = FetchTimeout
		return &cc
	}
	return c
}

func readLimited(r io.Reader, max int64) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, max+1))
	if err == nil && int64(len(b)) > max {
		err = fmt.Errorf("response is over the %d byte limit", max)
	}
	return b, err
}

// trimQuery drops a URL's query (a bundle_url carries a storage access signature) for error messages.
func trimQuery(s string) string {
	s, _, _ = strings.Cut(s, "?")
	return s
}
