package keylog

import (
	"errors"
	"fmt"
	"slices"
)

// View is what the log said at one entry: the key admins' Ed25519 keys and the signatures an admin-signed
// document needs then. Documents (policies, the firm's stop lists) are checked against the view at the log head
// when they arrive; one the VM already took stays in force after its signers leave.
type View struct {
	Seq       int64
	Head      string
	Admins    []string // current key admins' Ed25519 keys, sorted
	Threshold int64    // admin signatures needed (the effective threshold)
	Kit       string   // the recovery kit's Ed25519 key (it signs no documents)
}

// Fork is proof of equivocation: two entries at one position, each a valid continuation of the same log.
type Fork struct {
	Seq    int64  `json:"seq"`
	Ours   string `json:"ours"`   // the entry this VM holds there
	Theirs string `json:"theirs"` // the other one's hash
	Entry  Entry  `json:"entry"`  // the other one
}

// Log is a firm's key log as the VM holds it: verified from a pinned genesis, extend only. Not safe for
// concurrent use (the safety state locks around it).
type Log struct {
	firm, genesis string
	entries       []Entry
	hashes        []string
	states        []*State // state after each entry (small: a few identities and admins each)
}

// New makes an empty log for firm whose first entry must hash to genesis.
func New(firm, genesis string) (*Log, error) {
	if !firmOK(firm, firm) || !hashRe.MatchString(genesis) {
		return nil, errors.New("key log: a firm id and a genesis hash (64 hex) are required")
	}
	return &Log{firm: firm, genesis: genesis}, nil
}

// Firm and Genesis are what the log was pinned to.
func (l *Log) Firm() string    { return l.firm }
func (l *Log) Genesis() string { return l.genesis }

// Seq is the number of entries held (0 before the genesis arrives).
func (l *Log) Seq() int64 { return int64(len(l.entries)) }

// Head is the last entry's hash ("" when empty).
func (l *Log) Head() string {
	if len(l.hashes) == 0 {
		return ""
	}
	return l.hashes[len(l.hashes)-1]
}

// Entries are the held entries in order (shared: don't modify).
func (l *Log) Entries() []Entry { return l.entries }

// HashAt is entry seq's hash ("" outside the log).
func (l *Log) HashAt(seq int64) string {
	if seq < 1 || seq > l.Seq() {
		return ""
	}
	return l.hashes[seq-1]
}

// State is the state at the head (nil when empty).
func (l *Log) State() *State {
	if len(l.states) == 0 {
		return nil
	}
	return l.states[len(l.states)-1]
}

// ViewAt is the view after entry seq (seq 1 … Seq()); ok false outside the log.
func (l *Log) ViewAt(seq int64) (View, bool) {
	if seq < 1 || seq > l.Seq() {
		return View{}, false
	}
	s := l.states[seq-1]
	return View{Seq: seq, Head: l.hashes[seq-1], Admins: s.AdminKeys(), Threshold: s.Effective(), Kit: s.Kit}, true
}

// Result of adding an entry.
type Result int

const (
	Appended Result = iota // the next entry, verified and taken
	Held                   // this exact entry is already held
)

// ErrFork is returned (wrapped, with the Fork) when an entry proves equivocation.
var ErrFork = errors.New("key log fork")

// ForkError carries the proof.
type ForkError struct{ Fork Fork }

func (e *ForkError) Error() string {
	return fmt.Sprintf("key log fork at entry %d: two valid entries (%.12s… held, %.12s… offered)", e.Fork.Seq, e.Fork.Ours, e.Fork.Theirs)
}
func (e *ForkError) Unwrap() error { return ErrFork }

// Add takes one checked entry (Check with this log's firm). The next entry is verified against the state at
// the head and appended; one already held is a no-op; a different entry at a held position is a fork when it
// is itself a valid continuation of the entries before it (anything else there is refused quietly, so a sender
// without the signers' keys can't raise the alarm); an entry beyond the next is refused (send from the head).
func (l *Log) Add(c *Checked) (Result, error) {
	if c.P.Firm != l.firm {
		return 0, errors.New("key log: entry is for another firm")
	}
	seq := c.P.Seq
	switch n := l.Seq(); {
	case seq <= n:
		if l.hashes[seq-1] == c.Hash {
			return Held, nil
		}
		if seq == 1 {
			// Another genesis is never "valid" here: the pin names ours. Refused, no alarm.
			return 0, errors.New("key log: not the pinned genesis")
		}
		if _, err := apply(l.states[seq-2], c); err != nil {
			return 0, fmt.Errorf("key log: entry %d differs from the one held and isn't valid: %w", seq, err)
		}
		return 0, &ForkError{Fork{Seq: seq, Ours: l.hashes[seq-1], Theirs: c.Hash, Entry: c.Entry}}
	case seq > n+1:
		return 0, fmt.Errorf("key log: entry %d arrived before entry %d (send the log from there)", seq, n+1)
	case n >= MaxEntries:
		return 0, errors.New("key log: too many entries")
	}
	if seq == 1 && c.Hash != l.genesis {
		return 0, errors.New("key log: not the pinned genesis")
	}
	s, err := apply(l.State(), c)
	if err != nil {
		return 0, fmt.Errorf("key log: %w", err)
	}
	l.entries = append(l.entries, c.Entry)
	l.hashes = append(l.hashes, c.Hash)
	l.states = append(l.states, s)
	return Appended, nil
}

// Load replays held entries (from disk) into an empty log; it stops at the first one that doesn't verify (a
// genesis pin changed in a new release, or a damaged file) and says how many it took.
func (l *Log) Load(entries []Entry) (int, error) {
	for i, e := range entries {
		c, err := Check(e, l.firm)
		if err == nil {
			_, err = l.Add(c)
		}
		if err != nil {
			return i, err
		}
	}
	return len(entries), nil
}

// AdminAt says whether key was a current key admin's Ed25519 key after entry seq.
func (l *Log) AdminAt(seq int64, key string) bool {
	v, ok := l.ViewAt(seq)
	return ok && slices.Contains(v.Admins, key)
}
