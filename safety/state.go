package safety

import (
	"crypto/ed25519"
	"encoding/json/v2"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/tacyhq/tacy/keylog"
)

// Error codes people's events and records carry (proto.Event.Code).
const (
	CodeStopped        = "stopped"         // a stop list stops this space, its firm, or everything
	CodeStale          = "stop_list_stale" // no fresh operator stop list: nothing goes out (without an operator key: side effects, and reads per policy)
	CodePolicyMissing  = "policy_missing"  // admin keys (or a key log) are pinned but no signed policy covers the space
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
//
// Admin signers come from one of two places. Before keys v2 slice 5 (and on a VM whose compose pins no key log):
// Admins, Ed25519 keys pinned in the compose. With slice 5: Genesis, the hash of the firm key log's first entry
// (docs/26 section 4); the VM verifies the log from it (entries arrive over POST /keylog) and policies and the
// firm's stop lists are signed by the log's current key admins (its threshold). Never both.
type Config struct {
	Firm      string              // the firm this VM serves (one CVM per firm)
	Operator  ed25519.PublicKey   // signs the operator stop list; nil: no heartbeat can be checked (always stale)
	Admins    []ed25519.PublicKey // compose-pinned admin keys; none (and no Genesis): the release policy applies alone
	Threshold int                 // distinct compose admin signatures needed; 0: 1
	Genesis   string              // the firm key log's genesis hash (hex); "": admin keys from Admins
	// Carry: hashes of documents signed before the move to the key log (by a compose admin key that is now the
	// log's recovery kit, docs/26 decision 6). Each listed document is taken as admin-signed when the log's kit signed
	// it; nothing else the kit signs is. Only with Genesis. The release pins them, so the list is attested.
	Carry []string
	// PersonalSpaces (the shared chat VM, keys v2 slice 6): a space without a signed policy of its own runs under the
	// firm's policy, with the seal key its request proves and its budget counted for the relay's per-user tag
	// (people's personal spaces, which nobody signs a policy for). Off (a firm's VM): a space runs only under a
	// signed policy of its own that names its seal key, and only for an identity current in the firm key log.
	PersonalSpaces bool
	Release        *Policy       // the release's ceiling and default (required)
	MaxStopAge     time.Duration // 0: DefaultMaxStopAge
	// MaxSilence: with an operator key pinned, how long the newest operator list may go without being delivered
	// again (pulled or pushed) before nothing may go out; 0: not checked (gatewayd and vaultd, which get the list
	// from agentd, not from the pull).
	MaxSilence time.Duration
	Dir        string // where accepted documents, the key log and the floors persist; "": memory only
	Now        func() time.Time
}

type policyDoc struct {
	env  Envelope
	p    Policy
	hash string
	at   int64 // the key log entry it was taken at (0: no key log)
}

type stopDoc struct {
	env  Envelope
	l    StopList
	hash string
	at   int64
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
	log      *keylog.Log  // the firm key log (nil: admin keys from the compose)
	fork     *keylog.Fork // proof the key log forked: no admin-signed change is taken any more
}

// NewState makes a State and loads what cfg.Dir holds (each document checked again).
func NewState(cfg Config) (*State, error) {
	if cfg.Release == nil || !ValidID(cfg.Firm) {
		return nil, errors.New("safety: a release policy and a valid firm id are required")
	}
	var kl *keylog.Log
	switch {
	case cfg.Genesis != "" && len(cfg.Admins) > 0:
		return nil, errors.New("safety: pin either admin keys or a key log genesis, not both")
	case cfg.Genesis != "":
		var err error
		if kl, err = keylog.New(cfg.Firm, cfg.Genesis); err != nil {
			return nil, fmt.Errorf("safety: %w", err)
		}
	case len(cfg.Carry) > 0:
		return nil, errors.New("safety: carried documents need a key log genesis")
	}
	for _, h := range cfg.Carry {
		if len(h) != 64 || strings.Trim(h, "0123456789abcdef") != "" {
			return nil, errors.New("safety: a carried document is named by its hash (64 hex)")
		}
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
		changed: make(chan struct{}), log: kl}
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

// Apply checks and takes envelopes from anyone (POST /safety, POST /keylog): signed documents and key log
// entries. It returns one error per envelope (nil: taken or already held) and whether anything changed. Every
// admin-signed document is checked against the key log as it stands now (its current key admins), whatever
// order the envelopes come in.
func (s *State) Apply(envs []Envelope) ([]error, bool) { return s.apply(envs, false, false) }

// ApplyOrdered is Apply for what another process of this VM passes on (agentd's documents to gatewayd, gatewayd's
// to the vault): its Docs, the key log entries in order with each document right after the entry it was taken
// at. A document is checked against the key log as it stood there, so one signed by a key admin who was revoked
// later stays in force (docs/26 decision 12) here too, as it does in agentd. That position is agentd's word, the
// same trust gatewayd and vaultd already give agentd for floors (they have none of their own after a restart):
// it can only name a point of the log they verify themselves, so a document still needs the signatures of keys
// that were key admins there.
func (s *State) ApplyOrdered(envs []Envelope) ([]error, bool) { return s.apply(envs, true, false) }

func (s *State) apply(envs []Envelope, ordered, fromDisk bool) ([]error, bool) {
	errs := make([]error, len(envs))
	s.saveMu.Lock()
	defer s.saveMu.Unlock()
	changed := false
	at := int64(-1) // ordered: the key log entry the next document was taken at (-1: the head)
	for i, e := range envs {
		if keylog.IsKind(e.Kind) {
			seq, c, err := s.addEntry(e)
			errs[i], changed = err, changed || c
			if ordered && err == nil {
				at = seq
			}
			continue
		}
		// Decoding and signature checks need no lock (the input is unauthenticated and may be slow to check);
		// only the view, the floors and the swap do.
		s.mu.Lock()
		held := s.holds(e)
		// The operator's list is checked and taken again (take): a delivery of the one held keeps it heard, an
		// expired one is refused. It needs only the pinned operator key, never the key log.
		if held {
			if d := s.stops[IssuerOperator]; d != nil && d.hash == e.Hash() && d.env.Kind == e.Kind {
				held = false
			}
		}
		auth := s.authority(at)
		s.mu.Unlock()
		if held {
			continue // the same document again: nothing to check or change (also when its signers left since)
		}
		v, err := s.verify(e, auth, fromDisk)
		if err != nil {
			errs[i] = err
			continue
		}
		s.mu.Lock()
		c, err := s.take(v)
		s.mu.Unlock()
		errs[i], changed = err, changed || c
	}
	var snap []byte
	s.mu.Lock()
	if changed {
		close(s.changed)
		s.changed = make(chan struct{})
		snap, _ = s.snapshot()
	}
	s.mu.Unlock()
	if changed && !fromDisk {
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

// addEntry takes one key log entry: checked on its own outside the lock, then against the log. A proven fork
// is kept (and persisted) and from then on nothing admin-signed is taken: no entry past the head, no policy, no
// firm stop list (docs/26 section 4 and decision 5).
func (s *State) addEntry(e Envelope) (int64, bool, error) {
	if s.log == nil {
		return 0, false, errors.New("key log: this VM pins no key log genesis")
	}
	c, err := keylog.Check(entryOf(e), s.cfg.Firm)
	if err != nil {
		return 0, false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fork != nil && c.P.Seq > s.log.Seq() {
		return 0, false, fmt.Errorf("key log: it forked at entry %d, so this VM takes no more entries", s.fork.Seq)
	}
	r, err := s.log.Add(c)
	var fe *keylog.ForkError
	if errors.As(err, &fe) {
		if s.fork == nil {
			s.fork = &fe.Fork
			log.Printf("safety: keylog_fork: %v; no admin-signed change is taken from now on", fe)
			return 0, true, err
		}
		return 0, false, err
	}
	if err != nil {
		return 0, false, err
	}
	return c.P.Seq, r == keylog.Appended, nil
}

func entryOf(e Envelope) keylog.Entry {
	k := keylog.Entry{Kind: e.Kind, Payload: e.Payload}
	for _, s := range e.Sigs {
		k.Sigs = append(k.Sigs, keylog.Sig{Key: s.Key, Sig: s.Sig})
	}
	return k
}

func envelopeOf(k keylog.Entry) Envelope {
	e := Envelope{Kind: k.Kind, Payload: k.Payload}
	for _, s := range k.Sigs {
		e.Sigs = append(e.Sigs, Sig{Key: s.Key, Sig: s.Sig})
	}
	return e
}

// holds: e is the document held in its slot (s.mu held).
func (s *State) holds(e Envelope) bool {
	h := e.Hash()
	for _, d := range s.policies {
		if d.hash == h && d.env.Kind == e.Kind {
			return true
		}
	}
	for _, d := range s.stops {
		if d.hash == h && d.env.Kind == e.Kind {
			return true
		}
	}
	return false
}

// authority is who may sign admin documents: the compose's keys, or the key log's key admins after entry at (-1:
// the head). s.mu held.
type authority struct {
	keyed     bool // admin keys or a key log are pinned: documents need them
	logged    bool // the signers come from the key log
	admins    []ed25519.PublicKey
	threshold int
	count     int               // how many key admins there are (two or more: widening needs two signatures)
	kit       ed25519.PublicKey // the key log's recovery kit (signs only carried documents here)
	at        int64
	forked    bool
}

func (s *State) authority(at int64) authority {
	if s.log == nil {
		return authority{keyed: len(s.cfg.Admins) > 0, admins: s.cfg.Admins, threshold: s.cfg.Threshold, count: len(s.cfg.Admins)}
	}
	a := authority{keyed: true, logged: true, forked: s.fork != nil}
	if at < 0 {
		at = s.log.Seq()
	}
	v, ok := s.log.ViewAt(at)
	if !ok {
		return a // no key log yet (or that entry isn't held): nothing admin-signed verifies
	}
	for _, k := range v.Admins {
		if pk, err := keylog.ParseEd(k); err == nil {
			a.admins = append(a.admins, pk)
		}
	}
	a.threshold, a.count, a.at = int(v.Threshold), len(v.Admins), at
	a.kit, _ = keylog.ParseEd(v.Kit)
	return a
}

// verified is a document whose payload and signatures checked out, ready for the floors.
type verified struct {
	env  Envelope
	hash string
	p    *Policy
	l    *StopList
	t    time.Time
	at   int64 // the key log entry its signers were checked at
	sigs int   // distinct admin signatures (policies and firm lists)
	auth authority
	disk bool // loaded from this process's own disk, not delivered
}

// adminSigned checks e's admin signatures against auth: the threshold, or (key log only) a carried document the
// recovery kit signed. It returns the number of admin signatures.
func (s *State) adminSigned(e Envelope, hash string, auth authority, what string) (int, error) {
	switch {
	case !auth.keyed:
		return 0, fmt.Errorf("%s: no admin keys are pinned in this release", what)
	case auth.logged && auth.at == 0:
		return 0, fmt.Errorf("%s: this VM hasn't received its firm key log yet", what)
	case auth.forked:
		return 0, fmt.Errorf("%s: the firm key log forked, so this VM takes no admin-signed document", what)
	}
	n := e.signers(auth.admins)
	if n >= auth.threshold {
		return n, nil
	}
	if auth.logged && auth.kit != nil && slices.Contains(s.cfg.Carry, hash) && e.signers([]ed25519.PublicKey{auth.kit}) == 1 {
		return n, nil // signed by the old compose admin key, now the kit, and pinned by the release
	}
	if auth.logged {
		return n, fmt.Errorf("%s: not signed by enough current key admins (the firm key log)", what)
	}
	return n, fmt.Errorf("%s: not signed by enough pinned admin keys", what)
}

// verify checks a document on its own: shape, firm, signatures (against auth), dates. No state is read.
func (s *State) verify(e Envelope, auth authority, fromDisk bool) (*verified, error) {
	now := s.cfg.Now()
	v := &verified{env: e, hash: e.Hash(), t: now, at: auth.at, auth: auth, disk: fromDisk}
	switch e.Kind {
	case KindPolicy:
		var p Policy
		if err := strict(e.Payload, &p); err != nil {
			return nil, fmt.Errorf("policy: %w", err)
		}
		if err := p.Validate(); err != nil {
			return nil, err
		}
		if p.Firm != s.cfg.Firm {
			return nil, errors.New("policy: for another firm")
		}
		n, err := s.adminSigned(e, v.hash, auth, "policy")
		if err != nil {
			return nil, err
		}
		if p.IssuedAt.After(now.Add(MaxSkew)) {
			return nil, errors.New("policy: issued in the future")
		}
		v.p, v.sigs = &p, n
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
			v.at = 0
			if s.cfg.Operator == nil || e.signers([]ed25519.PublicKey{s.cfg.Operator}) < 1 {
				return nil, errors.New("stop list: not signed by the pinned operator key")
			}
			if !fromDisk && !now.Before(l.ExpiresAt) {
				return nil, errors.New("stop list: expired")
			}
		case IssuerFirm:
			if l.Firm != s.cfg.Firm {
				return nil, errors.New("stop list: for another firm")
			}
			n, err := s.adminSigned(e, v.hash, auth, "stop list")
			if err != nil {
				return nil, err
			}
			v.sigs = n
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
	if s.fork != nil && (v.p != nil || v.l.Issuer == IssuerFirm) {
		return false, errors.New("safety: the firm key log forked, so this VM takes no admin-signed document")
	}
	if v.p != nil {
		slot := "policy:" + v.p.Space
		ok, err := s.check(slot, v.p.Version, v.hash, s.policies[v.p.Space] != nil)
		if !ok {
			return false, err
		}
		// Two key admins' signatures to widen the policy in force, once the firm has two (docs/23 decision 6).
		if old := s.policies[v.p.Space]; old != nil && v.auth.logged && v.auth.count >= 2 && v.sigs < 2 && Widens(&old.p, v.p) {
			return false, errors.New("policy: it allows more than the policy in force, so it needs two key admins' signatures")
		}
		s.policies[v.p.Space] = &policyDoc{env: v.env, p: *v.p, hash: v.hash, at: v.at}
		s.floors[slot] = floor{v.p.Version, v.hash}
		return true, nil
	}
	slot := "stop:" + v.l.Issuer
	ok, err := s.check(slot, v.l.Seq, v.hash, s.stops[v.l.Issuer] != nil)
	if v.l.Issuer == IssuerOperator && err == nil && !v.disk {
		s.heard = v.t // taken, or the list held delivered again: the pull (or a push) still reaches the VM
	}
	if !ok {
		return false, err
	}
	s.stops[v.l.Issuer] = &stopDoc{env: v.env, l: *v.l, hash: v.hash, at: v.at}
	s.floors[slot] = floor{v.l.Seq, v.hash}
	if v.l.Issuer == IssuerOperator {
		s.gotStop = v.t
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

// keyed: admin-signed documents are required (admin keys or a key log genesis pinned).
func (s *State) keyed() bool { return len(s.cfg.Admins) > 0 || s.log != nil }

// Keyed says whether this VM takes signed documents at all (compose keys or a key log pinned).
func (s *State) Keyed() bool { return s.cfg.Operator != nil || s.keyed() }

// KeyLogged says whether admin signers come from a firm key log (POST /keylog is served).
func (s *State) KeyLogged() bool { return s.log != nil }

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

// OperatorTime is the operator's latest signed time (its stop list's issued_at, the heartbeat) and whether that
// list is fresh and heard (not stale, not silent). Schedules fire only near it (docs/27 section 3, "Clock"): the
// host controls the VM's clock, the operator's signature it can't make.
func (s *State) OperatorTime() (time.Time, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	d := s.stops[IssuerOperator]
	if d == nil || s.stale() || s.silent() {
		return time.Time{}, false
	}
	return d.l.IssuedAt, true
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
			if _, had := s.floors["policy:"+k]; had && s.keyed() {
				return nil, errorf(CodePolicyMissing, "the signed policy for this space can't be verified")
			}
			continue
		}
		e.Layers, e.Hashes = append(e.Layers, &d.p), append(e.Hashes, d.hash)
	}
	if s.keyed() && len(e.Hashes) == 0 {
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
	Keys   *Keys  `json:"keys,omitzero"` // the firm key log as this VM holds it (key log VMs only)
}

// Keys is the VM's firm key log head, announced to browsers in every run's meta (EHBP-authenticated to the attested
// key) and in GET /safety, so a browser can compare it with the log it verified itself and catch a server showing
// people different logs (docs/26 section 4). Genesis is the compose's pin; Seq 0 and Head "" until it arrives.
type Keys struct {
	Firm    string `json:"firm"`
	Genesis string `json:"genesis"`
	Seq     int64  `json:"seq"`
	Head    string `json:"head"`
	Fork    bool   `json:"fork,omitzero"` // the VM saw two valid entries at one position and takes no signed change
}

// PersonalSpaces says whether spaces without a policy of their own may run (Config.PersonalSpaces).
func (s *State) PersonalSpaces() bool { return s.cfg.PersonalSpaces }

// CurrentIdentity says whether id is current in the firm key log at its head with Ed25519 key ed ("ed25519:…"). False
// without a key log, or after a fork (the log can't be trusted for anything new).
func (s *State) CurrentIdentity(id, ed string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.log == nil || s.fork != nil {
		return false
	}
	st := s.log.State()
	if st == nil {
		return false
	}
	i, ok := st.Identity(id)
	return ok && i.Revoked == 0 && i.Ed25519 == ed
}

// KeysStatus is the key log head (nil without a key log).
func (s *State) KeysStatus() *Keys {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.keysStatus()
}

func (s *State) keysStatus() *Keys {
	if s.log == nil {
		return nil
	}
	return &Keys{Firm: s.cfg.Firm, Genesis: s.log.Genesis(), Seq: s.log.Seq(), Head: s.log.Head(), Fork: s.fork != nil}
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
	st.Keys = s.keysStatus()
	return st
}

// Docs are what this process holds, to pass on to the next process (ApplyOrdered) and to keep on disk: the key
// log entries in order, each followed by the documents taken at it; documents taken without a key log first
// (stop lists, then policies by space).
func (s *State) Docs() []Envelope {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.docs()
}

func (s *State) docs() []Envelope {
	byAt := map[int64][]Envelope{}
	for _, iss := range []string{IssuerOperator, IssuerFirm} {
		if d := s.stops[iss]; d != nil {
			byAt[d.at] = append(byAt[d.at], d.env)
		}
	}
	spaces := make([]string, 0, len(s.policies))
	for k := range s.policies {
		spaces = append(spaces, k)
	}
	slices.Sort(spaces)
	for _, k := range spaces {
		d := s.policies[k]
		byAt[d.at] = append(byAt[d.at], d.env)
	}
	out := byAt[0]
	if s.log != nil {
		for i, e := range s.log.Entries() {
			out = append(out, envelopeOf(e))
			out = append(out, byAt[int64(i+1)]...)
		}
	}
	return out
}

// ---- persistence (the encrypted disk: the floors outlive a restart) ----------------------------------------

type saved struct {
	Docs   []Envelope       `json:"docs"` // Docs order: key log entries with the documents taken at each
	Floors map[string]floor `json:"floors"`
	Fork   *keylog.Fork     `json:"keylog_fork,omitzero"`
}

func (s *State) path() string { return filepath.Join(s.cfg.Dir, "safety.json") }

func (s *State) snapshot() ([]byte, error) {
	return json.Marshal(saved{Docs: s.docs(), Floors: s.floors, Fork: s.fork})
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
	// Replayed in order: each document is checked again against the key log as it stood when it was taken (its
	// signers may have been revoked since: it stays in force, docs/26 decision 12). A document or entry that no longer
	// verifies (keys changed in a new release, another genesis pinned) is dropped; its floor stays, so the slot
	// fails closed until a newer signed one arrives.
	errs, _ := s.apply(sv.Docs, true, true)
	for i, err := range errs {
		if err != nil {
			log.Printf("safety: dropped a held %s at load: %v", sv.Docs[i].Kind, err)
		}
	}
	// The fork proof stays while the log still holds the entry it was against (a new release pinning another
	// genesis starts over). Set after the replay: what was held before the fork stays held.
	if f := sv.Fork; f != nil && s.log != nil && f.Seq > 1 && s.log.HashAt(f.Seq) == f.Ours {
		s.fork = f
	}
	return nil
}
