package trigger

import (
	"crypto/ed25519"
	"sync"
	"time"

	"github.com/tacyhq/tacy/identity"
)

// Personal spaces on the shared chat VM (docs/30 "Scheduled tasks", slice 2). There is no space log there: a
// person's space is theirs because they hold its key. An install proves that the way a run does (the space proof
// against this boot's key, and the identity's signature, package runauth); the VM then records "identity X holds
// space S, with identity key K and seal key P" (a Holder). That record is the Directory the definition's signature
// and the sponsor's checks at each tick are verified against. Holders are only ever added by such a proof; they
// stay until the VM's disk goes (a person can't leave their own space).

// Holder is one identity's proved hold on a space.
type Holder struct {
	Space    string
	Identity string
	Key      string // "ed25519:<base64>"
	Seal     string // "x25519:<base64>"
	At       time.Time
}

// HolderStore keeps holders (the queue's side file in agentd).
type HolderStore interface {
	// PutHolder records h (replacing that identity's earlier record for the space).
	PutHolder(h Holder) error
	// Holder returns the identity's record for the space (nil: none).
	Holder(space, id string) (*Holder, error)
}

// HolderDirectory is an identity.Directory over a HolderStore, for one firm (the shared VM's).
type HolderDirectory struct {
	Firm  string
	Store HolderStore
}

var _ identity.Directory = (*HolderDirectory)(nil)

// Key is identity.Directory.Key: the key the identity proved with when it last showed it holds the space.
func (d *HolderDirectory) Key(firm, space, id string) (ed25519.PublicKey, error) {
	if firm != d.Firm {
		return nil, identity.ErrUnknown
	}
	h, err := d.Store.Holder(space, id)
	if err != nil {
		return nil, err
	}
	if h == nil {
		return nil, identity.ErrNotHolder
	}
	return identity.ParseKey(h.Key)
}

// MemHolders is an in-memory HolderStore.
type MemHolders struct {
	mu sync.Mutex
	m  map[string]Holder
}

func (m *MemHolders) PutHolder(h Holder) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.m == nil {
		m.m = map[string]Holder{}
	}
	m.m[h.Space+"\x00"+h.Identity] = h
	return nil
}

func (m *MemHolders) Holder(space, id string) (*Holder, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	h, ok := m.m[space+"\x00"+id]
	if !ok {
		return nil, nil
	}
	return &h, nil
}

// Result is a finished scheduled run's result, sealed to the space's seal key, kept until the browser deletes it or
// ResultKeep passes (docs/30 "Scheduled tasks", decision 4).
type Result struct {
	Seq         int64 // the store's order (results listed after a seq)
	Task        string
	Space       string
	Seal        string
	Agent       string
	Version     uint64
	Trigger     string
	Day         string // the slot's local date ("YYYY-MM-DD"; "" for a non-daily schedule)
	ScheduledAt time.Time
	StartedAt   time.Time
	EndedAt     time.Time
	State       string
	Code        string
	// Quiet: the run found nothing that changed and told nobody (Definition.Notify): the browser records that it ran
	// and adds no message.
	Quiet   bool
	Enc, CT []byte // HPKE encapsulated key and ciphertext
}

// ResultKeep is how long a result is kept after its run ended.
const ResultKeep = 7 * 24 * time.Hour

// ResultStore keeps sealed results.
type ResultStore interface {
	// PutResult stores r (a second result for the same task replaces nothing: the first stays); it returns r's seq.
	PutResult(r Result) (int64, error)
	// Results lists the space's results sealed to seal with seq after after, oldest first, at most limit, without
	// their ciphertext.
	Results(space, seal string, after int64, limit int) ([]Result, error)
	// GetResult returns one result with its ciphertext (nil: none in that space and seal).
	GetResult(space, seal, task string) (*Result, error)
	// DeleteResults deletes the space's results for tasks; it returns how many it deleted.
	DeleteResults(space, seal string, tasks []string) (int, error)
	// DeleteAgentResults deletes every result of an agent in the space (a removed schedule).
	DeleteAgentResults(space, agent string) (int, error)
	// PruneResults deletes results whose run ended before t.
	PruneResults(t time.Time) error
}

// MemResults is an in-memory ResultStore.
type MemResults struct {
	mu  sync.Mutex
	seq int64
	rs  []Result
	// the collect counters (collect.go): runs in a row whose result nobody collected, and the version stopped for it
	missed  map[string]int
	stopped map[string]uint64
}

var _ CollectStore = (*MemResults)(nil)

func (m *MemResults) PutResult(r Result) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, x := range m.rs {
		if x.Task == r.Task {
			return x.Seq, nil
		}
	}
	m.seq++
	r.Seq = m.seq
	m.rs = append(m.rs, r)
	if m.missed == nil {
		m.missed = map[string]int{}
	}
	m.missed[r.Agent]++
	return r.Seq, nil
}

func (m *MemResults) Results(space, seal string, after int64, limit int) ([]Result, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Result
	for _, r := range m.rs {
		if r.Space == space && r.Seal == seal && r.Seq > after && len(out) < limit {
			r.Enc, r.CT = nil, make([]byte, 0, len(r.CT))
			out = append(out, r)
		}
	}
	return out, nil
}

func (m *MemResults) GetResult(space, seal, task string) (*Result, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, r := range m.rs {
		if r.Space == space && r.Seal == seal && r.Task == task {
			return &r, nil
		}
	}
	return nil, nil
}

func (m *MemResults) del(keep func(Result) bool) int {
	n := 0
	out := m.rs[:0]
	for _, r := range m.rs {
		if keep(r) {
			out = append(out, r)
		} else {
			n++
		}
	}
	m.rs = out
	return n
}

func (m *MemResults) DeleteResults(space, seal string, tasks []string) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	set := map[string]bool{}
	for _, t := range tasks {
		set[t] = true
	}
	return m.del(func(r Result) bool {
		if r.Space == space && r.Seal == seal && set[r.Task] {
			delete(m.missed, r.Agent) // collected: the count starts again
			return false
		}
		return true
	}), nil
}

func (m *MemResults) DeleteAgentResults(space, agent string) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.missed, agent)
	delete(m.stopped, agent)
	return m.del(func(r Result) bool { return !(r.Space == space && r.Agent == agent) }), nil
}

func (m *MemResults) Uncollected(agent string) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.missed[agent], nil
}

func (m *MemResults) SetStoppedUncollected(agent string, version uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.stopped == nil {
		m.stopped = map[string]uint64{}
	}
	m.stopped[agent] = version
	return nil
}

func (m *MemResults) StoppedUncollected(agent string, version uint64) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.stopped[agent]
	return ok && v == version, nil
}

func (m *MemResults) ResetCollect(agent string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.missed, agent)
	delete(m.stopped, agent)
	return nil
}

func (m *MemResults) PruneResults(t time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.del(func(r Result) bool { return !r.EndedAt.Before(t) })
	return nil
}
