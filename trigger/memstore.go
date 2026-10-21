package trigger

import (
	"slices"
	"sync"
	"testing"
	"time"
)

// MemStore is an in-memory Store.
type MemStore struct {
	mu    sync.Mutex
	defs  map[string][]byte
	vers  map[string]uint64
	state map[string]string
	fired map[string]int64
	seen  map[string]time.Time
	hw    time.Time
}

func NewMemStore() *MemStore {
	return &MemStore{defs: map[string][]byte{}, vers: map[string]uint64{}, state: map[string]string{}, fired: map[string]int64{}, seen: map[string]time.Time{}}
}

func (m *MemStore) SaveDefinition(agent string, version uint64, env []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if v, ok := m.vers[agent]; ok && (v > version || v == version && (string(m.defs[agent]) != string(env) || m.state[agent] != StateActive)) {
		return ErrStale
	}
	m.defs[agent], m.vers[agent], m.state[agent] = slices.Clone(env), version, StateActive
	return nil
}

func (m *MemStore) Definitions() ([]Stored, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Stored
	for a, b := range m.defs {
		if m.state[a] != StateRemoved {
			out = append(out, Stored{Env: slices.Clone(b), State: m.state[a]})
		}
	}
	return out, nil
}

func (m *MemStore) SetState(agent string, version uint64, state string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if v, ok := m.vers[agent]; !ok || v != version {
		return ErrStale
	}
	m.state[agent] = state
	if state == StateRemoved { // only the agent id and version stay (the floor)
		m.defs[agent] = nil
	}
	return nil
}

func (m *MemStore) ExpireDefinition(agent string, version uint64, env []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if v, ok := m.vers[agent]; !ok || v != version || m.state[agent] == StateRemoved {
		return ErrStale
	}
	m.defs[agent], m.state[agent] = slices.Clone(env), StateExpired
	return nil
}

func (m *MemStore) LastFired(trigger string) (int64, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.fired[trigger]
	return s, ok, nil
}

func (m *MemStore) SetFired(trigger string, slot int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if s, ok := m.fired[trigger]; !ok || slot > s {
		m.fired[trigger] = slot
	}
	return nil
}

func (m *MemStore) See(trigger, delivery string, until time.Time) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := trigger + "\x00" + delivery
	if _, ok := m.seen[k]; ok {
		return false, nil
	}
	m.seen[k] = until
	return true, nil
}

func (m *MemStore) Seen(trigger, delivery string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.seen[trigger+"\x00"+delivery]
	return ok, nil
}

func (m *MemStore) PruneSeen(t time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for k, u := range m.seen {
		if u.Before(t) {
			delete(m.seen, k)
		}
	}
	return nil
}

func (m *MemStore) HighWater() (time.Time, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.hw, nil
}

func (m *MemStore) SetHighWater(t time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if t.After(m.hw) {
		m.hw = t
	}
	return nil
}

// RunStoreTests checks a Store (MemStore here, the queue's SQLite in package queue).
func RunStoreTests(t *testing.T, s Store) {
	t.Helper()
	if err := s.SaveDefinition("a_1", 2, []byte(`{"v":2}`)); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveDefinition("a_1", 1, []byte(`{"v":1}`)); err != ErrStale {
		t.Fatalf("older version: %v", err)
	}
	if err := s.SaveDefinition("a_1", 2, []byte(`{"v":"other"}`)); err != ErrStale {
		t.Fatalf("same version, other bytes: %v", err)
	}
	if err := s.SaveDefinition("a_1", 2, []byte(`{"v":2}`)); err != nil {
		t.Fatalf("same bytes again: %v", err)
	}
	s.SaveDefinition("a_2", 1, []byte(`{"v":"b"}`))
	defs, err := s.Definitions()
	if err != nil || len(defs) != 2 || !slices.ContainsFunc(defs, func(d Stored) bool { return string(d.Env) == `{"v":2}` && d.State == StateActive }) {
		t.Fatalf("definitions %v %v", defs, err)
	}
	// Stopped: listed as stopped; the same bytes can't come back at that version; a newer one is active again.
	if err := s.SetState("a_2", 2, StateStopped); err != ErrStale {
		t.Fatalf("stop another version: %v", err)
	}
	if err := s.SetState("a_2", 1, StateStopped); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveDefinition("a_2", 1, []byte(`{"v":"b"}`)); err != ErrStale {
		t.Fatalf("stopped version again: %v", err)
	}
	defs, _ = s.Definitions()
	if !slices.ContainsFunc(defs, func(d Stored) bool { return string(d.Env) == `{"v":"b"}` && d.State == StateStopped }) {
		t.Fatalf("stopped not listed: %v", defs)
	}
	if err := s.SetState("a_2", 1, StateRemoved); err != nil {
		t.Fatal(err)
	}
	if defs, _ = s.Definitions(); len(defs) != 1 {
		t.Fatalf("removed still listed: %v", defs)
	}
	if err := s.SaveDefinition("a_2", 1, []byte(`{"v":"b"}`)); err != ErrStale {
		t.Fatalf("removed version again: %v", err)
	}
	if err := s.SaveDefinition("a_2", 2, []byte(`{"v":"c"}`)); err != nil {
		t.Fatalf("newer after removal: %v", err)
	}
	if defs, _ = s.Definitions(); len(defs) != 2 {
		t.Fatalf("renewed not listed: %v", defs)
	}
	if _, ok, _ := s.LastFired("tr_1"); ok {
		t.Fatal("fired before")
	}
	s.SetFired("tr_1", 5)
	s.SetFired("tr_1", 3) // never lowered
	if slot, ok, err := s.LastFired("tr_1"); err != nil || !ok || slot != 5 {
		t.Fatalf("last fired %d %v %v", slot, ok, err)
	}
	t0 := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	if seen, _ := s.Seen("tr_1", "d1"); seen {
		t.Fatal("seen before recorded")
	}
	if fresh, err := s.See("tr_1", "d1", t0); err != nil || !fresh {
		t.Fatal("first delivery")
	}
	if seen, _ := s.Seen("tr_1", "d1"); !seen {
		t.Fatal("not seen after recorded")
	}
	if fresh, _ := s.See("tr_1", "d1", t0.Add(time.Hour)); fresh {
		t.Fatal("replayed delivery fresh")
	}
	if fresh, _ := s.See("tr_2", "d1", t0); !fresh {
		t.Fatal("same delivery id on another trigger")
	}
	s.PruneSeen(t0.Add(time.Second))
	if fresh, _ := s.See("tr_1", "d1", t0); !fresh {
		t.Fatal("pruned delivery still seen")
	}
	if hw, _ := s.HighWater(); !hw.IsZero() {
		t.Fatal("high water")
	}
	s.SetHighWater(t0)
	s.SetHighWater(t0.Add(-time.Hour))
	if hw, _ := s.HighWater(); !hw.Equal(t0) {
		t.Fatalf("high water %v", hw)
	}
}
