package safety

import (
	"crypto/ed25519"
	"encoding/json/v2"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"
)

// Error codes people's events and records carry (proto.Event.Code).
const (
	CodeStopped        = "stopped"         // a stop list stops this space, its firm, or everything
	CodeStale          = "stop_list_stale" // no fresh operator stop list: nothing goes out (without an operator key: side effects, and reads per policy)
	CodePolicyMissing  = "policy_missing"  // admin keys are pinned but no signed policy covers the space
	CodePolicyDenied   = "policy_denied"   // the policy doesn't allow this model, tool, connector or host
	CodeBudgetExceeded = "budget_exceeded" // a run or daily budget is used up
	CodeRateLimited    = "rate_limited"    // the vault's lease rate for a key, connector or space
)

// Error is a refusal with its code. The message names the rule, never content.
type Error struct {
	Code string
	Msg  string
}

func (e *Error) Error() string { return e.Code + ": " + e.Msg }

func errorf(code, format string, args ...any) *Error {
	return &Error{Code: code, Msg: fmt.Sprintf(format, args...)}
}

// CodeOf is err's code, or "".
func CodeOf(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}

// MaxSkew is how far in the future a document's issued_at may be.
const MaxSkew = 5 * time.Minute

// DefaultMaxStopAge is how old the newest operator stop list may get before the VM counts it stale.
const DefaultMaxStopAge = 10 * time.Minute

// DefaultMaxSilence is how long the process that pulls the operator's list (agentd, through gatewayd's pull every
// 10 s) may go without the list being delivered again before it counts as silent: about 18 missed pulls. Someone
// who drops the pull (the host, or anything on the network path) keeps a stop from arriving; after this long the
// VM stops everything instead of waiting for the list to age out.
const DefaultMaxSilence = 3 * time.Minute

// Config is a process's trust roots (pinned in the attested compose) and the release's ceiling.
type Config struct {
	Firm       string              // the firm this VM serves (one CVM per firm)
	Operator   ed25519.PublicKey   // signs the operator stop list; nil: no heartbeat can be checked (always stale)
	Admins     []ed25519.PublicKey // sign policies and the firm's stop list; none: the release policy applies alone
	Threshold  int                 // distinct admin signatures needed; 0: 1
	Release    *Policy             // the release's ceiling and default (required)
	MaxStopAge time.Duration       // 0: DefaultMaxStopAge
	// MaxSilence: with an operator key pinned, how long the newest operator list may go without being delivered
	// again (pulled or pushed) before nothing may go out; 0: not checked (gatewayd and vaultd, which get the list
	// from agentd, not from the pull).
	MaxSilence time.Duration
	Dir        string // where accepted documents and version floors persist; "": memory only
	Now        func() time.Time
}

type policyDoc struct {
	env  Envelope
	p    Policy
	hash string
}

type stopDoc struct {
	env  Envelope
	l    StopList
	hash string
}

// floor is the highest version (policies) or seq (stop lists) seen for a slot, with that document's hash: lower
// is a rollback, equal must be the same document.
type floor struct {
	N    uint64 `json:"n"`
	Hash string `json:"hash"`
}

// State is a process's verified view: the newest valid policy per firm and space, the newest stop list per
// issuer, and the floors that refuse rollbacks. Safe for concurrent use.
type State struct {
	cfg Config

	saveMu   sync.Mutex // Apply's writes, in order
	mu       sync.Mutex
	policies map[string]*policyDoc // by space ("": the firm's)
	stops    map[string]*stopDoc   // by issuer
	floors   map[string]floor
	gotStop  time.Time // when the newest operator list was accepted
	heard    time.Time // when the newest operator list was last delivered (taken, or the held one again); not from disk
	changed  chan struct{}
}

// NewState makes a State and loads what cfg.Dir holds (each document checked again).
func NewState(cfg Config) (*State, error) {
	if cfg.Release == nil || !ValidID(cfg.Firm) {
		return nil, errors.New("safety: a release policy and a valid firm id are required")
	}
	if cfg.Threshold <= 0 {
		cfg.Threshold = 1
	}
	if cfg.MaxStopAge <= 0 {
		cfg.MaxStopAge = DefaultMaxStopAge
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	s := &State{cfg: cfg, policies: map[string]*policyDoc{}, stops: map[string]*stopDoc{}, floors: map[string]floor{},
		changed: make(chan struct{})}
	if cfg.Dir != "" {
		if err := s.load(); err != nil {
			return nil, err
		}
	}
	return s, nil
}

// Firm is the firm this state serves.
func (s *State) Firm() string { return s.cfg.Firm }

// Changed is closed at the next change (then ask again).
func (s *State) Changed() <-chan struct{} {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.changed
}

// Apply checks and takes envelopes. It returns one error per envelope (nil: taken or already held) and whether
// anything changed.
func (s *State) Apply(envs []Envelope) ([]error, bool) {
	// Decoding and signature checks need no lock (the input is unauthenticated and may be slow to check); only
	// the floors and the swap do.
	errs := make([]error, len(envs))
	ready := make([]*verified, len(envs))
	for i := range envs {
		ready[i], errs[i] = s.verify(envs[i], false)
	}
	s.saveMu.Lock()
	defer s.saveMu.Unlock()
	s.mu.Lock()
	changed := false
	for i, v := range ready {
		if v != nil {
			var c bool
			c, errs[i] = s.take(v)
			changed = changed || c
		}
	}
	var snap []byte
	if changed {
		close(s.changed)
		s.changed = make(chan struct{})
		snap, _ = s.snapshot()
	}
	s.mu.Unlock()
	if changed {
		// Written in the order taken (saveMu), outside the state lock. The new documents apply in memory either
		// way; only the restart floor is at risk, so a failure is loud, never open.
		if err := s.write(snap); err != nil {
			for i := range errs {
				if errs[i] == nil {
					errs[i] = fmt.Errorf("safety: applied but not persisted: %w", err)
				}
			}
		}
	}
	return errs, changed
}

// verified is a document whose payload and signatures checked out, ready for the floors.
type verified struct {
	env  Envelope
	hash string
	p    *Policy
	l    *StopList
	at   time.Time
	disk bool // loaded from this process's own disk, not delivered
}

// verify checks a document on its own: shape, firm, signatures, dates. No state is read.
func (s *State) verify(e Envelope, fromDisk bool) (*verified, error) {
	now := s.cfg.Now()
	v := &verified{env: e, hash: e.Hash(), at: now, disk: fromDisk}
	switch e.Kind {
	case KindPolicy:
		var p Policy
		if err := strict(e.Payload, &p); err != nil {
			return nil, fmt.Errorf("policy: %w", err)
		}
		if err := p.Validate(); err != nil {
			return nil, err
		}
		switch {
		case p.Firm != s.cfg.Firm:
			return nil, errors.New("policy: for another firm")
		case len(s.cfg.Admins) == 0:
			return nil, errors.New("policy: no admin keys are pinned in this release")
		case e.signers(s.cfg.Admins) < s.cfg.Threshold:
			return nil, errors.New("policy: not signed by enough pinned admin keys")
		case p.IssuedAt.After(now.Add(MaxSkew)):
			return nil, errors.New("policy: issued in the future")
		}
		v.p = &p
		return v, nil
	case KindStop:
		var l StopList
		if err := strict(e.Payload, &l); err != nil {
			return nil, fmt.Errorf("stop list: %w", err)
		}
		if err := l.Validate(); err != nil {
			return nil, err
		}
		switch l.Issuer {
		case IssuerOperator:
			if s.cfg.Operator == nil || e.signers([]ed25519.PublicKey{s.cfg.Operator}) < 1 {
				return nil, errors.New("stop list: not signed by the pinned operator key")
			}
			if !fromDisk && !now.Before(l.ExpiresAt) {
				return nil, errors.New("stop list: expired")
			}
		case IssuerFirm:
			switch {
			case l.Firm != s.cfg.Firm:
				return nil, errors.New("stop list: for another firm")
			case len(s.cfg.Admins) == 0 || e.signers(s.cfg.Admins) < s.cfg.Threshold:
				return nil, errors.New("stop list: not signed by enough pinned admin keys")
			}
		}
		if l.IssuedAt.After(now.Add(MaxSkew)) {
			return nil, errors.New("stop list: issued in the future")
		}
		v.l = &l
		return v, nil
	}
	return nil, errors.New("safety: unknown document kind")
}

// take applies a verified document against the floors (s.mu held).
func (s *State) take(v *verified) (bool, error) {
	if v.p != nil {
		slot := "policy:" + v.p.Space
		ok, err := s.check(slot, v.p.Version, v.hash, s.policies[v.p.Space] != nil)
		if !ok {
			return false, err
		}
		s.policies[v.p.Space] = &policyDoc{env: v.env, p: *v.p, hash: v.hash}
		s.floors[slot] = floor{v.p.Version, v.hash}
		return true, nil
	}
	slot := "stop:" + v.l.Issuer
	ok, err := s.check(slot, v.l.Seq, v.hash, s.stops[v.l.Issuer] != nil)
	if v.l.Issuer == IssuerOperator && err == nil && !v.disk {
		s.heard = v.at // taken, or the list held delivered again: the pull (or a push) still reaches the VM
	}
	if !ok {
		return false, err
	}
	s.stops[v.l.Issuer] = &stopDoc{env: v.env, l: *v.l, hash: v.hash}
	s.floors[slot] = floor{v.l.Seq, v.hash}
	if v.l.Issuer == IssuerOperator {
		s.gotStop = v.at
	}
	return true, nil
}

// check decides whether a document numbered n with hash may replace the slot's: newer yes; the same document
// already held is a no-op; the same number with other content or a lower one is refused.
func (s *State) check(slot string, n uint64, hash string, held bool) (bool, error) {
	f, ok := s.floors[slot]
	switch {
	case !ok || n > f.N:
		return true, nil
	case n < f.N:
		return false, fmt.Errorf("%s: %d is older than %d (rollback refused)", slotName(slot), n, f.N)
	case hash != f.Hash:
		return false, fmt.Errorf("%s: %d was already signed with other content", slotName(slot), n)
	case held:
		return false, nil
	}
	return true, nil // the floor's own document, held again (after a restart)
}

// slotName names a slot in errors: "the firm's policy version", "space s_x's policy version", "the operator's stop list seq".
func slotName(slot string) string {
	switch kind, k, _ := strings.Cut(slot, ":"); {
	case kind == "policy" && k == "":
		return "the firm's policy version"
	case kind == "policy":
		return "space " + k + "'s policy version"
	default:
		return "the " + k + "'s stop list seq"
	}
}

// Stopped says whether space is stopped, and by which list.
func (s *State) Stopped(space string) (bool, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stopped(space)
}

func (s *State) stopped(space string) (bool, string) {
	for _, iss := range []string{IssuerOperator, IssuerFirm} {
		if d := s.stops[iss]; d != nil && d.l.stops(s.cfg.Firm, space) {
			return true, iss
		}
	}
	return false, ""
}

// Stale: no operator stop list fresh enough (none pinned, none received, expired or too old).
func (s *State) Stale() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stale()
}

func (s *State) stale() bool {
	d := s.stops[IssuerOperator]
	if s.cfg.Operator == nil || d == nil {
		return true
	}
	now := s.cfg.Now()
	return !now.Before(d.l.ExpiresAt) || now.Sub(d.l.IssuedAt) > s.cfg.MaxStopAge || now.Sub(s.gotStop) > s.cfg.MaxStopAge
}

// silent: MaxSilence is checked, an operator key is pinned, and the operator's list hasn't been delivered for
// longer than that (or not since this process started).
func (s *State) silent() bool {
	if s.cfg.MaxSilence <= 0 || s.cfg.Operator == nil {
		return false
	}
	return s.heard.IsZero() || s.cfg.Now().Sub(s.heard) > s.cfg.MaxSilence
}

// blocked: with an operator key pinned, a stale or silent stop list stops everything (model calls, searches, page
// and image fetches, leases), whatever the policy's stale_reads says: a stop that can't arrive must not leave reads
// running (fail closed). The release's behaviour, not a policy field, so signed policies load unchanged. Without
// an operator key nothing could ever arrive, and the attested compose says so: side effects stop, reads follow the
// policy.
func (s *State) blocked() bool {
	return s.cfg.Operator != nil && (s.stale() || s.silent())
}

// Heard says whether the operator's list has been delivered since this process started (pulled or pushed).
func (s *State) Heard() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return !s.heard.IsZero()
}

// Blocked says whether the stop list being stale or silent stops everything now (blocked).
func (s *State) Blocked() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.blocked()
}

// Policy is the effective policy for space.
func (s *State) Policy(space string) (*Effective, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.policy(space)
}

func (s *State) policy(space string) (*Effective, error) {
	e := &Effective{Layers: []*Policy{s.cfg.Release}}
	keys := []string{""}
	if space != "" {
		keys = append(keys, space)
	}
	for _, k := range keys {
		d := s.policies[k]
		if d == nil {
			// Signed once, not verifiable now (keys rotated in a new release): fail closed until a newer one
			// arrives. Not when no admin keys are pinned: then nothing could ever arrive, and the release policy
			// applies alone, as the attested compose says (a release without keys after one with them).
			if _, had := s.floors["policy:"+k]; had && len(s.cfg.Admins) > 0 {
				return nil, errorf(CodePolicyMissing, "the signed policy for this space can't be verified")
			}
			continue
		}
		e.Layers, e.Hashes = append(e.Layers, &d.p), append(e.Hashes, d.hash)
	}
	if len(s.cfg.Admins) > 0 && len(e.Hashes) == 0 {
		return nil, errorf(CodePolicyMissing, "no signed policy for this space yet")
	}
	return e, nil
}

// Check is what every process asks before doing something in space: stopped, policy present, and, when the stop
// list is stale or silent, whether this may go on (with an operator key pinned: nothing; without one: side effects
// never, reads if the policy allows).
func (s *State) Check(space string, effect bool) (*Effective, error) {
	if !ValidID(space) { // a request must name its space: an empty one would skip space stops and policies
		return nil, errorf(CodePolicyMissing, "the request names no space")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if stop, by := s.stopped(space); stop {
		return nil, errorf(CodeStopped, "this space was stopped by the %s's stop list", by)
	}
	e, err := s.policy(space)
	if err != nil {
		return nil, err
	}
	if s.blocked() {
		return nil, errorf(CodeStale, "the VM hasn't had a fresh operator stop list recently, so nothing goes out until it does")
	}
	if s.stale() && (effect || !e.StaleReads()) {
		return nil, errorf(CodeStale, "the VM has no fresh stop list, so it can't go on (actions with side effects always stop)")
	}
	return e, nil
}

// Status is what people's meta event and the records say about the controls a run ran under.
type Status struct {
	Policy      []string `json:"policy,omitzero"`       // signed policy hashes (firm, then space); none: the release's default
	Release     string   `json:"release_policy"`        // hash of the release's ceiling policy
	OperatorSeq uint64   `json:"operator_seq,omitzero"` // newest operator stop list
	FirmSeq     uint64   `json:"firm_seq,omitzero"`     // newest firm stop list
	Fresh       bool     `json:"stop_list_fresh"`       // operator list fresh, and (where checked) delivered recently
	Stopped     string   `json:"stopped,omitzero"`      // issuer of the list that stops this space
	// Blocked: the stop list is stale or silent with an operator key pinned, so nothing goes out (no model calls,
	// searches, page or image fetches) until a fresh one arrives.
	Blocked bool `json:"egress_blocked,omitzero"`
	// HeardS: seconds since the operator's list was last delivered to this process (pulled or pushed); absent when
	// it hasn't been since the process started.
	HeardS *int64 `json:"stop_list_heard_s,omitzero"`
}

// ReleaseHash identifies the release's ceiling policy: sha256 of its JSON as the release encodes it.
func ReleaseHash(p *Policy) string {
	b, _ := json.Marshal(p, json.Deterministic(true))
	e := Envelope{Kind: KindPolicy, Payload: b}
	return e.Hash()
}

// StatusOf reports space's controls.
func (s *State) StatusOf(space string) Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := Status{Release: ReleaseHash(s.cfg.Release), Fresh: !s.stale() && !s.silent(), Blocked: s.blocked()}
	if !s.heard.IsZero() {
		n := max(0, int64(s.cfg.Now().Sub(s.heard)/time.Second))
		st.HeardS = &n
	}
	if e, err := s.policy(space); err == nil {
		st.Policy = e.Hashes
	}
	if d := s.stops[IssuerOperator]; d != nil {
		st.OperatorSeq = d.l.Seq
	}
	if d := s.stops[IssuerFirm]; d != nil {
		st.FirmSeq = d.l.Seq
	}
	if stop, by := s.stopped(space); stop {
		st.Stopped = by
	}
	return st
}

// Docs are the documents held, to pass on to the next process (stop lists first, then policies by space).
func (s *State) Docs() []Envelope {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.docs()
}

func (s *State) docs() []Envelope {
	var out []Envelope
	for _, iss := range []string{IssuerOperator, IssuerFirm} {
		if d := s.stops[iss]; d != nil {
			out = append(out, d.env)
		}
	}
	spaces := make([]string, 0, len(s.policies))
	for k := range s.policies {
		spaces = append(spaces, k)
	}
	slices.Sort(spaces)
	for _, k := range spaces {
		out = append(out, s.policies[k].env)
	}
	return out
}

// ---- persistence (the encrypted disk: the floors outlive a restart) ----------------------------------------

type saved struct {
	Docs   []Envelope       `json:"docs"`
	Floors map[string]floor `json:"floors"`
}

func (s *State) path() string { return filepath.Join(s.cfg.Dir, "safety.json") }

func (s *State) snapshot() ([]byte, error) {
	return json.Marshal(saved{Docs: s.docs(), Floors: s.floors})
}

func (s *State) write(b []byte) error {
	if s.cfg.Dir == "" {
		return nil
	}
	if b == nil {
		return errors.New("safety: nothing to write")
	}
	if err := os.MkdirAll(s.cfg.Dir, 0o700); err != nil {
		return err
	}
	tmp := s.path() + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	_, err = f.Write(b)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	return os.Rename(tmp, s.path())
}

func (s *State) load() error {
	b, err := os.ReadFile(s.path())
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var sv saved
	if err := json.Unmarshal(b, &sv); err != nil {
		return fmt.Errorf("safety: %s: %w", s.path(), err)
	}
	for k, f := range sv.Floors {
		s.floors[k] = f
	}
	for _, e := range sv.Docs {
		// A document that no longer verifies (keys rotated in a new release) is dropped; its floor stays, so
		// the slot fails closed until a newer signed one arrives.
		if v, err := s.verify(e, true); err == nil {
			s.take(v)
		}
	}
	return nil
}
