package guard

import (
	"context"
	"errors"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync"

	"github.com/tacyhq/tacy/activity"
	"github.com/tacyhq/tacy/vault"
)

// Facts are what the guard saw and did for one request, for its activity record (docs/24): every host it reached
// (requests, policy refusals, bytes each way), every key lease the vault decided (names, never values) and every
// leak-scan decision (pattern ids). Metadata only: no query, URL path, page or argument. gatewayd sends them back
// with each result (gateway/v0); agentd's recorder puts them in the run's record.
type Facts struct {
	mu sync.Mutex
	d  FactsData
}

// FactsData is Facts on the wire.
type FactsData struct {
	Hosts    []activity.Host  `json:"hosts,omitzero"`
	Leases   []activity.Lease `json:"leases,omitzero"`
	Blocked  []string         `json:"blocked,omitzero"`  // leak-scan pattern ids that blocked the request
	Redacted []string         `json:"redacted,omitzero"` // leak-scan pattern ids redacted from the response
}

type factsKey struct{}

// WithFacts makes the guard's work under ctx add to f.
func WithFacts(ctx context.Context, f *Facts) context.Context {
	return context.WithValue(ctx, factsKey{}, f)
}

// FactsFrom is ctx's collector (nil: none; every method is a no-op on nil).
func FactsFrom(ctx context.Context) *Facts {
	f, _ := ctx.Value(factsKey{}).(*Facts)
	return f
}

// Data is a copy of what was collected.
func (f *Facts) Data() FactsData {
	if f == nil {
		return FactsData{}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return FactsData{Hosts: slices.Clone(f.d.Hosts), Leases: slices.Clone(f.d.Leases), Blocked: slices.Clone(f.d.Blocked),
		Redacted: slices.Clone(f.d.Redacted)}
}

// Ptr is Data as a pointer, nil when nothing was collected (nil f too): what gateway/v0 sends.
func (f *Facts) Ptr() *FactsData {
	d := f.Data()
	if len(d.Hosts) == 0 && len(d.Leases) == 0 && len(d.Blocked) == 0 && len(d.Redacted) == 0 {
		return nil
	}
	return &d
}

// BackgroundSession is a Session that also reports the task's egress outside any request (the sources' site
// icons), for the activity record. Ask after End.
type BackgroundSession interface {
	Background() FactsData
}

// Merge adds what another process collected (gatewayd's, on agentd's side).
func (f *Facts) Merge(d FactsData) {
	if f == nil {
		return
	}
	for _, h := range d.Hosts {
		f.host(h.Host, h.Requests, h.Refused, h.BytesOut, h.BytesIn)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.d.Leases = append(f.d.Leases, d.Leases...)
	f.d.Blocked = addIDs(f.d.Blocked, d.Blocked)
	f.d.Redacted = addIDs(f.d.Redacted, d.Redacted)
}

func (f *Facts) host(host string, requests, refused int, out, in int64) {
	if f == nil || host == "" {
		return
	}
	host = strings.ToLower(host)
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := range f.d.Hosts {
		if h := &f.d.Hosts[i]; h.Host == host {
			h.Requests += requests
			h.Refused += refused
			h.BytesOut += out
			h.BytesIn += in
			return
		}
	}
	if len(f.d.Hosts) >= maxFactHosts {
		host = "(other hosts)"
		for i := range f.d.Hosts {
			if h := &f.d.Hosts[i]; h.Host == host {
				h.Requests += requests
				h.Refused += refused
				h.BytesOut += out
				h.BytesIn += in
				return
			}
		}
	}
	f.d.Hosts = append(f.d.Hosts, activity.Host{Host: host, Requests: requests, Refused: refused, BytesOut: out, BytesIn: in})
}

// maxFactHosts caps the hosts one request lists (an image search reaches up to a few dozen).
const maxFactHosts = 64

// model counts one model call against the host the model key was leased for ("model" when none was: a dev
// upstream without keys).
func (f *Facts) model(out, in int64) {
	if f == nil {
		return
	}
	f.mu.Lock()
	host := "model"
	for _, l := range slices.Backward(f.d.Leases) {
		if l.Connector == "model" && l.Decision == "released" {
			host = l.Host
			break
		}
	}
	f.mu.Unlock()
	f.host(host, 1, 0, out, in)
}

func (f *Facts) lease(l activity.Lease) {
	if f == nil {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.d.Leases = append(f.d.Leases, l)
}

func (f *Facts) leak(blocked bool, ids []string) {
	if f == nil {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if blocked {
		f.d.Blocked = addIDs(f.d.Blocked, ids)
	} else {
		f.d.Redacted = addIDs(f.d.Redacted, ids)
	}
}

func addIDs(to, ids []string) []string {
	for _, id := range ids {
		if !slices.Contains(to, id) {
			to = append(to, id)
		}
	}
	slices.Sort(to)
	return to
}

// RecordLeases wraps a Lease so every lease decision lands in the request's facts: the secret's name, connector,
// host, the vault's lease id or why it refused. Never the value.
func RecordLeases(l Lease) Lease {
	return func(ctx context.Context, secret, connector, host string) (*vault.Secret, error) {
		s, err := l(ctx, secret, connector, host)
		rec := activity.Lease{Secret: secret, Connector: connector, Host: host, Decision: "released"}
		if err != nil {
			rec.Decision, rec.Reason = "denied", leaseReason(err)
		} else if s != nil {
			rec.Lease = s.Lease
		}
		FactsFrom(ctx).lease(rec)
		return s, err
	}
}

// leaseReason names the vault's rule (never its text, which could carry anything).
func leaseReason(err error) string {
	for _, k := range []struct {
		err  error
		name string
	}{{vault.ErrNoGrant, "no_grant"}, {vault.ErrHost, "host"}, {vault.ErrNotSet, "not_set"}, {vault.ErrBadRequest, "bad_request"},
		{vault.ErrStopped, "stopped"}, {vault.ErrStale, "stop_list_stale"}, {vault.ErrPolicyMissing, "policy_missing"},
		{vault.ErrPolicy, "policy_denied"}, {vault.ErrRateLimited, "rate_limited"}} {
		if errors.Is(err, k.err) {
			return k.name
		}
	}
	return "refused"
}

// recordTransport counts each request in the request's facts: its host, the bytes sent (the body's length) and
// received (the body as it is read). A request refused before any connection counts as refused.
type recordTransport struct{ base http.RoundTripper }

func (t recordTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	f := FactsFrom(r.Context())
	res, err := t.base.RoundTrip(r)
	if f == nil {
		return res, err
	}
	out := max(r.ContentLength, 0)
	if errors.Is(err, errHostPolicy) {
		f.host(r.URL.Hostname(), 0, 1, 0, 0)
		return res, err
	}
	f.host(r.URL.Hostname(), 1, 0, out, 0)
	if res != nil && res.Body != nil {
		res.Body = &countingBody{ReadCloser: res.Body, f: f, host: r.URL.Hostname()}
	}
	return res, err
}

// recordingClient is c with its requests counted (recordTransport); nil stays nil.
func recordingClient(c *http.Client) *http.Client {
	if c == nil {
		return nil
	}
	if _, ok := c.Transport.(recordTransport); ok {
		return c
	}
	cc := *c
	base := cc.Transport
	if base == nil {
		base = http.DefaultTransport
	}
	cc.Transport = recordTransport{base}
	return &cc
}

type countingBody struct {
	io.ReadCloser
	f    *Facts
	host string
}

func (b *countingBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if n > 0 {
		b.f.host(b.host, 0, 0, 0, int64(n))
	}
	return n, err
}
