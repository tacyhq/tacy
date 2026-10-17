package guard

import (
	"context"
	"sync"
	"time"
)

// Limits is how much the VM takes on at once. Set by flags (app/main.go); the compose passes none, so the attested
// defaults below are what runs. The run slots and queue are app/'s (its scheduler); the tool caps are here. Sized by the load test in findings/2026-10-14/load-test.md (tdx.small: 1 vCPU,
// 2 GB).
//
// Users: the relay (the chat's Worker) sends an opaque per-user tag in X-Agent-User (an HMAC of the user id under
// a Worker secret, rotated daily). The VM uses it only to count runs and tool calls per user here, in memory, and
// never logs or stores it. Requests without a tag share one bucket ("").
type Limits struct {
	MaxRuns      int           // runs at once (all users)
	MaxQueue     int           // runs waiting for a slot (all users); beyond that: 429 queue_full
	QueueTimeout time.Duration // longest wait for a slot; then the run ends with an error event
	UserRuns     int           // runs at once per user
	UserQueue    int           // runs waiting per user; beyond that: 429 user_queue_full

	RunTools       int // tool calls at once within one run (a step's calls run in parallel)
	UserTools      int // searches and page fetches at once per user, across all their runs
	Searches       int // web searches at once, all users
	SearchesPerMin int // web searches per minute, all users (the provider's rate limit, with headroom)
	SearchBurst    int // searches that may start at once before the per-minute rate applies
	Fetches        int // page fetches at once, all users (each reads up to 2 MiB); image downloads count here too
	ImageDecodes   int // images decoded and re-encoded at once, all users (each up to ~100 MB while decoding); site icons too
	Favicons       int // site icons fetched at once, all users (favicons.go; outside the per-user tool caps)
}

// DefaultLimits are the attested defaults (app/main.go's flags start from them). See load-test.md. Tavily's development keys allow 100 requests per minute
// (docs.tavily.com/documentation/rate-limits); burst + rate stays under that in any 60 s window.
var DefaultLimits = Limits{
	MaxRuns: 24, MaxQueue: 48, QueueTimeout: 60 * time.Second, UserRuns: 3, UserQueue: 3,
	RunTools: 4, UserTools: 6, Searches: 12, SearchesPerMin: 75, SearchBurst: 20, Fetches: 16,
	ImageDecodes: 3, Favicons: 8,
}

// ---- tool calls: per-user and global caps, and the search provider's rate --------------------------------

// keyedSem is a counting semaphore per key (user), created on first use and dropped when unused.
type keyedSem struct {
	mu  sync.Mutex
	cap int
	m   map[string]*keyedEntry
}

type keyedEntry struct {
	ch   chan struct{}
	refs int
}

func newKeyedSem(n int) *keyedSem { return &keyedSem{cap: n, m: map[string]*keyedEntry{}} }

func (k *keyedSem) acquire(ctx context.Context, key string) (func(), error) {
	k.mu.Lock()
	e := k.m[key]
	if e == nil {
		e = &keyedEntry{ch: make(chan struct{}, k.cap)}
		k.m[key] = e
	}
	e.refs++
	k.mu.Unlock()
	unref := func() {
		k.mu.Lock()
		if e.refs--; e.refs == 0 {
			delete(k.m, key)
		}
		k.mu.Unlock()
	}
	select {
	case e.ch <- struct{}{}:
		return func() { <-e.ch; unref() }, nil
	case <-ctx.Done():
		unref()
		return nil, ctx.Err()
	}
}

func acquireSem(ctx context.Context, sem chan struct{}) (func(), error) {
	select {
	case sem <- struct{}{}:
		return func() { <-sem }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// rateLimiter is a token bucket: burst tokens, refilled at perMin per minute. A waiter reserves its token (the
// count may go negative) and sleeps until it is due, so waiters are served in order.
type rateLimiter struct {
	mu     sync.Mutex
	tokens float64
	burst  float64
	perSec float64
	last   time.Time
}

func newRateLimiter(perMin, burst int) *rateLimiter {
	return &rateLimiter{tokens: float64(burst), burst: float64(burst), perSec: float64(perMin) / 60, last: time.Now()}
}

func (r *rateLimiter) wait(ctx context.Context) error {
	r.mu.Lock()
	now := time.Now()
	r.tokens = min(r.burst, r.tokens+now.Sub(r.last).Seconds()*r.perSec)
	r.last = now
	r.tokens--
	var d time.Duration
	if r.tokens < 0 {
		d = time.Duration(-r.tokens / r.perSec * float64(time.Second))
	}
	r.mu.Unlock()
	if d <= 0 {
		return nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		r.mu.Lock()
		r.tokens++ // give the reservation back
		r.mu.Unlock()
		return ctx.Err()
	}
}

// toolGates holds the caps every run's tool calls go through: per user first (so one user waiting doesn't hold
// a global slot), then the global cap for that tool, then (searches) the provider's rate.
type toolGates struct {
	user     *keyedSem
	searches chan struct{}
	fetches  chan struct{}
	rate     *rateLimiter
	decodes  chan struct{} // image decodes (images.go), held only while decoding and re-encoding
	favicons chan struct{} // site icons being fetched (favicons.go)
}

func newToolGates(lim Limits) *toolGates {
	return &toolGates{user: newKeyedSem(lim.UserTools), searches: make(chan struct{}, lim.Searches),
		fetches: make(chan struct{}, lim.Fetches), rate: newRateLimiter(lim.SearchesPerMin, lim.SearchBurst),
		decodes: make(chan struct{}, max(1, lim.ImageDecodes)), favicons: make(chan struct{}, max(1, lim.Favicons))}
}

// iconGate is the VM-wide cap site icons wait for (not the per-user tool caps: a run's own searches and page
// fetches shouldn't wait behind its icons; favicons.go fetches at most iconRunFetches sites at once per run).
func (g *toolGates) iconGate() func(context.Context) (func(), error) {
	if g == nil {
		return nil
	}
	return func(ctx context.Context) (func(), error) { return acquireSem(ctx, g.favicons) }
}

// acquire waits for every cap a tool call needs and returns their release. kind: "search" | "fetch".
func (g *toolGates) acquire(ctx context.Context, user, kind string) (func(), error) {
	relUser, err := g.user.acquire(ctx, user)
	if err != nil {
		return nil, err
	}
	global := g.fetches
	if kind == "search" {
		global = g.searches
	}
	relGlobal, err := acquireSem(ctx, global)
	if err != nil {
		relUser()
		return nil, err
	}
	if kind == "search" {
		if err := g.rate.wait(ctx); err != nil {
			relGlobal()
			relUser()
			return nil, err
		}
	}
	return func() { relGlobal(); relUser() }, nil
}

// forUser is the gate one run's Tools use.
func (g *toolGates) forUser(user string) func(context.Context, string) (func(), error) {
	if g == nil {
		return nil
	}
	return func(ctx context.Context, kind string) (func(), error) { return g.acquire(ctx, user, kind) }
}
