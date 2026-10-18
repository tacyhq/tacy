package activity

import (
	"encoding/json/v2"
	"errors"
	"slices"
	"sync"
	"time"
)

// Recorder writes runs' records: a start record when a run starts, the calls it made kept in memory, an end
// record when it ends. Appends are serialized, so each chain's records are written in order. Safe for concurrent
// use.
type Recorder struct {
	Signer *Signer
	Store  Store
	Now    func() time.Time // nil: time.Now

	mu   sync.Mutex // appends
	rmu  sync.Mutex // runs
	runs map[string]*run
}

type run struct {
	info     Start
	chain    string
	startSeq uint64
	start    Sealed
	calls    []Call
	leases   []Lease
}

// Start is what is known about a run when it starts.
type Start struct {
	Run      string
	Space    string
	To       string // recipient: "x25519:<base64>"
	Agent    Agent
	Trigger  Trigger
	Controls *Controls
	Models   []string
	Tools    []string
	Limits   Limits
	Input    Input
	Started  time.Time
}

// End is how a run ended.
type End struct {
	Status     Status
	Usage      *Usage
	Steps      int
	Background []Host
	Tainted    bool // the run had untrusted input from its start (an earlier assistant turn); its calls say the rest
}

func (r *Recorder) now() time.Time {
	if r.Now != nil {
		return r.Now().UTC()
	}
	return time.Now().UTC()
}

// append seals body as chain's next record. The body's chain and seq are filled in.
func (r *Recorder) append(chain, to string, body *Run, open *OpenRun, closed string) (Sealed, uint64, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	head, err := r.Store.Head(chain)
	if err != nil {
		return Sealed{}, 0, err
	}
	body.Type, body.Chain, body.Seq = BodyType, chain, head.Seq+1
	pt, err := json.Marshal(body)
	if err != nil {
		return Sealed{}, 0, err
	}
	pt = pad(pt)
	now := r.now()
	rec, hash, err := r.Signer.seal(chain, body.Seq, head.Hash, now.Unix(), to, pt)
	clear(pt)
	if err != nil {
		return Sealed{}, 0, err
	}
	if open != nil {
		open.StartSeq = body.Seq
	}
	if err := r.Store.Append(chain, head, Link{Seq: body.Seq, Hash: hash}, rec, now, open, closed); err != nil {
		return Sealed{}, 0, err
	}
	return rec, body.Seq, nil
}

// pad fills a body with trailing spaces (still the same JSON) to the next size bucket: powers of two from 1 KiB,
// then 64 KiB steps, so ct_len in the public header says little about how much a run did.
func pad(b []byte) []byte {
	size := 1024
	for size < len(b) && size < 64<<10 {
		size *= 2
	}
	if len(b) > size {
		size = (len(b) + 64<<10 - 1) / (64 << 10) * (64 << 10)
	}
	out := make([]byte, size)
	copy(out, b)
	for i := len(b); i < size; i++ {
		out[i] = ' '
	}
	clear(b)
	return out
}

// ErrNoRecipient: a run without a recipient key isn't recorded (nobody could read its record).
var ErrNoRecipient = errors.New("activity: no recipient")

// Begin writes a run's start record. The run's calls are then added with Call and its end with Finish.
func (r *Recorder) Begin(s Start) (Sealed, error) {
	if s.To == "" {
		return Sealed{}, ErrNoRecipient
	}
	if _, err := ParseRecipient(s.To); err != nil {
		return Sealed{}, err
	}
	if s.Started.IsZero() {
		s.Started = r.now()
	}
	chain := ChainID(s.Space, s.To)
	body := &Run{Event: EventStart, Run: s.Run, Space: s.Space, Agent: &s.Agent, Trigger: &s.Trigger, Controls: s.Controls,
		Models: s.Models, Tools: s.Tools, Limits: &s.Limits, Input: &s.Input, Started: s.Started}
	open := &OpenRun{Run: s.Run, Space: s.Space, To: s.To, Started: s.Started}
	rec, seq, err := r.append(chain, s.To, body, open, "")
	if err != nil {
		return Sealed{}, err
	}
	r.rmu.Lock()
	if r.runs == nil {
		r.runs = map[string]*run{}
	}
	r.runs[s.Run] = &run{info: s, chain: chain, startSeq: seq, start: rec}
	r.rmu.Unlock()
	return rec, nil
}

// Recording reports whether a run is being recorded (it had a start record).
func (r *Recorder) Recording(id string) bool {
	r.rmu.Lock()
	defer r.rmu.Unlock()
	return r.runs[id] != nil
}

// StartedAt is when a recorded run started (zero when it isn't recorded).
func (r *Recorder) StartedAt(id string) time.Time {
	r.rmu.Lock()
	defer r.rmu.Unlock()
	if x := r.runs[id]; x != nil {
		return x.info.Started
	}
	return time.Time{}
}

// Call adds one finished call (and the leases made for it) to a recorded run; nothing for a run that isn't
// recorded.
func (r *Recorder) Call(id string, c Call, leases []Lease) {
	r.CallEnd(id, r.CallStart(id, c), c, leases)
}

// CallStart adds a call that has started (outcome "running" until CallEnd) and returns its place, or -1 for a run
// that isn't recorded. A run that ends with calls still running records them as "unfinished".
func (r *Recorder) CallStart(id string, c Call) int {
	r.rmu.Lock()
	defer r.rmu.Unlock()
	x := r.runs[id]
	if x == nil {
		return -1
	}
	c.Outcome = "running"
	x.calls = append(x.calls, c)
	return len(x.calls) - 1
}

// CallEnd fills in the call CallStart added.
func (r *Recorder) CallEnd(id string, i int, c Call, leases []Lease) {
	r.rmu.Lock()
	defer r.rmu.Unlock()
	x := r.runs[id]
	if x == nil || i < 0 || i >= len(x.calls) {
		return
	}
	x.calls[i] = c
	for _, l := range leases {
		l.Call = c.ID
		x.leases = append(x.leases, l)
	}
}

// Finish writes a run's end record and forgets the run. It returns the run's start and end records (for the
// person who started it), or ErrNoRecipient for a run that isn't recorded.
func (r *Recorder) Finish(id string, e End) ([]Sealed, error) {
	r.rmu.Lock()
	x := r.runs[id]
	delete(r.runs, id)
	r.rmu.Unlock()
	if x == nil {
		return nil, ErrNoRecipient
	}
	for i := range x.calls {
		if x.calls[i].Outcome == "running" {
			x.calls[i].Outcome = "unfinished"
		}
	}
	body := &Run{Event: EventEnd, Run: id, Space: x.info.Space, Started: x.info.Started, Ended: r.now(), Status: &e.Status,
		Calls: x.calls, Leases: x.leases, Usage: e.Usage, Steps: e.Steps, Background: e.Background, StartSeq: x.startSeq,
		Tainted: e.Tainted || slices.ContainsFunc(x.calls, func(c Call) bool { return c.Untrusted || c.Tainted })}
	rec, _, err := r.append(x.chain, x.info.To, body, nil, id)
	if err != nil {
		return nil, err
	}
	return []Sealed{x.start, rec}, nil
}

// Refused writes the one record of a run refused before it started (a stop, no policy, a model the policy doesn't
// allow, the day's budget used up).
func (r *Recorder) Refused(s Start, st Status) (Sealed, error) {
	if s.To == "" {
		return Sealed{}, ErrNoRecipient
	}
	if _, err := ParseRecipient(s.To); err != nil {
		return Sealed{}, err
	}
	now := r.now()
	st.State = "refused"
	body := &Run{Event: EventRefused, Run: s.Run, Space: s.Space, Agent: &s.Agent, Trigger: &s.Trigger, Controls: s.Controls,
		Models: s.Models, Tools: s.Tools, Input: &s.Input, Started: now, Ended: now, Status: &st}
	rec, _, err := r.append(ChainID(s.Space, s.To), s.To, body, nil, "")
	return rec, err
}

// Recover writes an interrupted end record for every run a previous process started and never ended (it died:
// a restart, an update, a crash). Their calls are unknown (they were in that process's memory). Returns how many.
func (r *Recorder) Recover() (int, error) {
	open, err := r.Store.OpenRuns()
	if err != nil {
		return 0, err
	}
	n := 0
	for _, o := range open {
		body := &Run{Event: EventInterrupted, Run: o.Run, Space: o.Space, Started: o.Started, Ended: r.now(),
			Status: &Status{State: "interrupted", Reason: "restart"}, StartSeq: o.StartSeq}
		if _, _, err := r.append(ChainID(o.Space, o.To), o.To, body, nil, o.Run); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

// Head is the current end of the chain of `to` in space (Seq 0 for a chain with no records yet), and its id.
func (r *Recorder) Head(space, to string) (string, Link, error) {
	chain := ChainID(space, to)
	r.mu.Lock()
	defer r.mu.Unlock()
	l, err := r.Store.Head(chain)
	return chain, l, err
}
