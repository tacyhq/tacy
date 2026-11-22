package holder

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/tacyhq/tacy/kms/split"
)

// MemoryNonces is a NonceStore in this process's memory, bounded (when full, expired entries go, then the request
// is refused rather than forgetting a live nonce). For tests and kmsctl break-glass; a deployed holder's is durable.
type MemoryNonces struct {
	mu     sync.Mutex
	max    int
	used   map[string]time.Time
	claims map[string]claim
	now    func() time.Time // the holder's clock (bind); nil: the wall clock
}

// NewMemoryNonces holds at most max live nonces. It keeps time on the clock of the holder it is given to (New binds
// it to Config.Now): an in-process store has no clock of its own, and one on the wall clock beside a holder on another
// clock would drop a ticket claim the holder still counts on (the start ticket tests broke the day after their
// fixed date). A durable store (D1, Upstash, Firestore) keeps time on its server's clock, as the holder's own is.
func NewMemoryNonces(max int) *MemoryNonces {
	return &MemoryNonces{max: max, used: map[string]time.Time{}}
}

// bind sets the store's clock to the holder's, once: the first holder given the store sets it.
func (m *MemoryNonces) bind(now func() time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.now == nil {
		m.now = now
	}
}

func (m *MemoryNonces) clock() time.Time {
	if m.now == nil {
		return time.Now()
	}
	return m.now()
}

// Use implements NonceStore.
func (m *MemoryNonces) Use(_ context.Context, nonce string, expires time.Time) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.used[nonce]; ok {
		return false, nil
	}
	if len(m.used) >= m.max {
		now := m.clock()
		for n, e := range m.used {
			if !now.Before(e) {
				delete(m.used, n)
			}
		}
		if len(m.used) >= m.max {
			return false, errors.New("too many live nonces")
		}
	}
	m.used[nonce] = expires
	return true, nil
}

// Claim implements NonceStore (start-ticket claims, kept with the nonces).
func (m *MemoryNonces) Claim(_ context.Context, key, value string, create bool, expires time.Time) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.claims == nil {
		m.claims = map[string]claim{}
	}
	now := m.clock()
	if c, ok := m.claims[key]; ok && now.Before(c.expires) {
		return c.value, nil
	}
	if !create {
		return "", nil
	}
	m.claims[key] = claim{value: value, expires: expires}
	return value, nil
}

type claim struct {
	value   string
	expires time.Time
}

// MemoryStore is a PolicyStore in memory: the reference for the durable ones (D1: Apply in one batch on the primary,
// guarded on the current seq and hash; Upstash: one Lua script on a single-region database; no read replicas). For
// tests and kmsctl break-glass.
type MemoryStore struct {
	mu    sync.Mutex
	gens  map[string]*genState
	prune time.Duration // withdrawn items older than this are forgotten (0: 30 days)
}

type genState struct {
	seq   uint64
	hash  string
	items map[string]ItemState
}

// Init sets generation gen's seq to floor (a holder's deploy does this once per admin-key generation).
func (m *MemoryStore) Init(gen string, floor uint64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.gens == nil {
		m.gens = map[string]*genState{}
	}
	if _, ok := m.gens[gen]; !ok {
		m.gens[gen] = &genState{seq: floor, items: map[string]ItemState{}}
	}
}

// Apply implements PolicyStore.
func (m *MemoryStore) Apply(_ context.Context, gen string, seq uint64, hash string, items []string, now time.Time) (map[string]ItemState, []string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	g := m.gens[gen]
	if g == nil {
		return nil, nil, ErrUninitialized
	}
	switch {
	case seq < g.seq:
		return nil, nil, &SeqRefusal{Err: ErrStale, Top: g.seq}
	case seq > g.seq+split.MaxSeqJump:
		return nil, nil, &SeqRefusal{Err: ErrJump, Top: g.seq}
	case seq == g.seq && g.hash != "" && g.hash != hash:
		return nil, nil, &SeqRefusal{Err: ErrEquivocation, Top: g.seq}
	}
	g.seq, g.hash = seq, hash
	var added []string
	in := map[string]bool{}
	for _, it := range items {
		in[it] = true
		st, ok := g.items[it]
		if !ok || !st.Withdrawn.IsZero() {
			g.items[it] = ItemState{First: now}
			added = append(added, it)
		}
	}
	prune := m.prune
	if prune == 0 {
		prune = 30 * 24 * time.Hour
	}
	for it, st := range g.items {
		switch {
		case !in[it] && st.Withdrawn.IsZero() && !Permanent(it):
			g.items[it] = ItemState{First: st.First, Withdrawn: now}
		case !st.Withdrawn.IsZero() && now.Sub(st.Withdrawn) > prune:
			delete(g.items, it)
		}
	}
	out := make(map[string]ItemState, len(g.items))
	for it, st := range g.items {
		out[it] = st
	}
	return out, added, nil
}

// Top implements PolicyStore.
func (m *MemoryStore) Top(_ context.Context, gen string) (uint64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	g := m.gens[gen]
	if g == nil {
		return 0, ErrUninitialized
	}
	return g.seq, nil
}

// Expedite implements PolicyStore.
func (m *MemoryStore) Expedite(_ context.Context, gen, item string, t time.Time) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	g := m.gens[gen]
	if g == nil {
		return false, ErrUninitialized
	}
	st, ok := g.items[item]
	if !ok || !st.Withdrawn.IsZero() || !t.Before(st.First) {
		return false, nil
	}
	g.items[item] = ItemState{First: t}
	return true, nil
}

// Permanent says whether a policy item is never withdrawn (a revoked machine certificate, split.ItemMachineRevoked):
// every PolicyStore's Apply leaves it as it is when a newer policy doesn't list it, so it is never pruned either.
func Permanent(item string) bool { return strings.HasPrefix(item, split.ItemMachineRevoked) }
