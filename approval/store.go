package approval

import (
	"errors"
	"slices"
	"sync"
	"time"
)

// States of a held effect (docs/27 section 2, the effect outbox): held until a person decides; approved, then
// sending (written before the connector is called), then sent or failed. A restart finds a sending effect unknown:
// it may or may not have happened, so it is never sent again by the VM (docs/27 section 4, "Once-only").
const (
	StateHeld     = "held"
	StateApproved = "approved"
	StateDenied   = "denied"
	StateExpired  = "expired"
	StateSending  = "sending"
	StateSent     = "sent"
	StateFailed   = "failed"
	StateUnknown  = "unknown"
)

// next lists the moves an effect may make.
var next = map[string][]string{
	StateHeld:     {StateApproved, StateDenied, StateExpired},
	StateApproved: {StateSending, StateExpired},
	StateSending:  {StateSent, StateFailed, StateUnknown},
}

// Record is one held effect and its approval.
type Record struct {
	ID         string // ap_
	Firm       string
	Space      string
	Task       string
	Request    string
	Action     string
	Effect     []byte // canonical JSON
	EffectHash string
	Approvers  []string
	ExpiresAt  time.Time
	CreatedAt  time.Time
	State      string
	// Decision is the payload the approver signed (approve or deny), kept as the record of who decided.
	Decision []byte
}

// Expect is what Check must find for this record.
func (r Record) Expect() Expect {
	return Expect{Approval: r.ID, Firm: r.Firm, Space: r.Space, Task: r.Task, Request: r.Request, Action: r.Action,
		EffectHash: r.EffectHash, Approvers: r.Approvers, ExpiresAt: r.ExpiresAt}
}

// ErrState: the record isn't in a state that allows the move (a second decision, a resend).
var ErrState = errors.New("approval: not in a state that allows this")

// Store keeps the records on the VM's encrypted disk (the queue's SQLite in agentd; MemStore in tests). Each
// method is one transaction.
type Store interface {
	// PutApproval records r as held unless its id exists; it returns the stored record either way (a restarted
	// agentd finds the first one, with its expiry) and whether it was new.
	PutApproval(r Record) (Record, bool, error)
	// Approval returns a record, or nil.
	Approval(id string) (*Record, error)
	// MoveApproval moves a record from one state to another, atomically (compare and swap): ErrState when it isn't
	// in from. decision, when set, is stored with the move.
	MoveApproval(id, from, to string, decision []byte) error
	// Approvals returns the records in any of states, oldest first.
	Approvals(states ...string) ([]Record, error)
	// DeleteApprovals removes a task's records (the task was forgotten).
	DeleteApprovals(task string) error
}

// Allowed reports whether an effect may move from one state to another.
func Allowed(from, to string) bool { return slices.Contains(next[from], to) }

// MemStore is an in-memory Store.
type MemStore struct {
	mu   sync.Mutex
	recs map[string]*Record
	seq  []string
}

func NewMemStore() *MemStore { return &MemStore{recs: map[string]*Record{}} }

func clone(r *Record) Record {
	c := *r
	c.Effect, c.Decision, c.Approvers = slices.Clone(r.Effect), slices.Clone(r.Decision), slices.Clone(r.Approvers)
	return c
}

func (m *MemStore) PutApproval(r Record) (Record, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if old := m.recs[r.ID]; old != nil {
		return clone(old), false, nil
	}
	r.State = StateHeld
	c := clone(&r)
	m.recs[r.ID] = &c
	m.seq = append(m.seq, r.ID)
	return clone(&c), true, nil
}

func (m *MemStore) Approval(id string) (*Record, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if r := m.recs[id]; r != nil {
		c := clone(r)
		return &c, nil
	}
	return nil, nil
}

func (m *MemStore) MoveApproval(id, from, to string, decision []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	r := m.recs[id]
	if r == nil || r.State != from || !Allowed(from, to) {
		return ErrState
	}
	r.State = to
	if decision != nil {
		r.Decision = slices.Clone(decision)
	}
	return nil
}

func (m *MemStore) Approvals(states ...string) ([]Record, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Record
	for _, id := range m.seq {
		if r := m.recs[id]; r != nil && slices.Contains(states, r.State) {
			out = append(out, clone(r))
		}
	}
	return out, nil
}

func (m *MemStore) DeleteApprovals(task string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, r := range m.recs {
		if r.Task == task {
			delete(m.recs, id)
		}
	}
	m.seq = slices.DeleteFunc(m.seq, func(id string) bool { return m.recs[id] == nil })
	return nil
}
