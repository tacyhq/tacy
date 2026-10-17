package safety

import (
	"sync"
	"time"
)

// Limiter is a set of token buckets by key (the vault: one per secret, connector and space). Keys are names and
// ids only, never values. Safe for concurrent use.
type Limiter struct {
	Now func() time.Time

	mu      sync.Mutex
	buckets map[string]*bucket
}

type bucket struct {
	tokens float64
	last   time.Time
	rate   Rate
}

// Allow takes one token from each key's bucket at its rate, all or none. A zero rate never limits. It returns the
// first key that is out of tokens ("" when allowed).
func (l *Limiter) Allow(keys []string, rates []Rate) string {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.buckets == nil {
		l.buckets = map[string]*bucket{}
	}
	now := time.Now()
	if l.Now != nil {
		now = l.Now()
	}
	bs := make([]*bucket, len(keys))
	for i, k := range keys {
		r := rates[i]
		if r.PerMinute <= 0 {
			continue
		}
		b := l.buckets[k]
		if b == nil || b.rate != r {
			b = &bucket{tokens: float64(r.Burst), last: now, rate: r}
			if old := l.buckets[k]; old != nil {
				b.tokens = min(old.tokens, float64(r.Burst)) // a narrower rate takes effect at once
			}
			l.buckets[k] = b
		}
		b.tokens = min(float64(r.Burst), b.tokens+now.Sub(b.last).Minutes()*float64(r.PerMinute))
		b.last = now
		if b.tokens < 1 {
			return k
		}
		bs[i] = b
	}
	for _, b := range bs {
		if b != nil {
			b.tokens--
		}
	}
	if len(l.buckets) > 4096 { // forget full buckets (they'd start full anyway)
		for k, b := range l.buckets {
			if b.tokens >= float64(b.rate.Burst) {
				delete(l.buckets, k)
			}
		}
	}
	return ""
}
