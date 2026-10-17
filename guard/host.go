package guard

import (
	"net/http"

	"github.com/tacyhq/tacy/internal/tinfoil"
)

// What gatewayd (../cmd/gatewayd) builds the guard from. The guard is every way out: the verified model upstream,
// the search provider and the public-only fetcher; it leases each key from the vault per call (keys.go).

// KnownModel reports whether the VM runs model m (the X-Agent-Model check before a run is queued).
func KnownModel(m string) bool {
	_, ok := models[m]
	return ok
}

// NewTinfoilUpstream is the model gateway's upstream: Tinfoil's router, verified (internal/tinfoil), with its key
// leased per call (TINFOIL_API_KEY, connector "model", the verified host).
func NewTinfoilUpstream(c *tinfoil.Client, lease Lease) Upstream {
	return &tinfoilUpstream{c: c, lease: lease}
}

// NewPlainUpstream is a plain OpenAI-compatible chat completions URL: local development and tests only.
func NewPlainUpstream(url string, client *http.Client) Upstream {
	return &plainUpstream{url: url, http: client}
}

// NewDevSearch is a Tavily-compatible search at url: local development and tests only.
func NewDevSearch(url string) SearchProvider {
	t := newTavily(StaticKeys(func(string) string { return "dev" }))
	t.base = url
	return t
}

// NewFetcher is the client for pages, images and site icons: public addresses only (the CVM), or any address when
// anyAddress (local development and tests only).
func NewFetcher(anyAddress bool) *http.Client {
	if anyAddress {
		return newFetcher(nil)
	}
	return newFetcher(publicOnly)
}
