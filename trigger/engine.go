package trigger

import (
	"cmp"
	"crypto/ed25519"
	"encoding/json/v2"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/tacyhq/tacy/harness"
	"github.com/tacyhq/tacy/identity"
	"github.com/tacyhq/tacy/safety"
)

// Inbound events.
const (
	EventType   = "tacy.event/v1"
	KindEvent   = "event"
	eventLabel  = "tacy-event/v1"
	EventWindow = 5 * time.Minute // an event is taken only within this of the time it says it was sent
	MaxEvent    = 2 << 10
)

// EventPayload is what an event's sender signs. Ids only: the event wakes a task, it carries no content. What the
// task then reads (a mail, a file) it fetches itself through a connector and the quarantined reader.
type EventPayload struct {
	Type     string    `json:"type"`
	Trigger  string    `json:"trigger"`  // tr_
	Delivery string    `json:"delivery"` // the sender's id for this delivery: used once
	SentAt   time.Time `json:"sent_at"`
	Ref      string    `json:"ref,omitzero"` // what it's about, an id (a message id), for the task's connectors
}

var refRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:@-]{0,127}$`)

// SignEvent makes an event's envelope signed by the sender (tests, and a sender's code).
func SignEvent(p EventPayload, key ed25519.PrivateKey) (safety.Envelope, error) {
	p.Type = EventType
	b, err := json.Marshal(p)
	if err != nil {
		return safety.Envelope{}, err
	}
	return signEnvelope(eventLabel, KindEvent, b, key), nil
}

// Store keeps what triggers need across restarts, on the VM's encrypted disk (the queue's SQLite in agentd).
type Store interface {
	// SaveDefinition stores an agent's definition envelope (JSON) at version, replacing an older one, as active. It
	// is the version floor, also for a stored version that no longer verifies: ErrStale for a lower version, the same
	// version with other bytes, or the same version once stopped or removed; the same bytes again are fine.
	SaveDefinition(agent string, version uint64, env []byte) error
	// Definitions returns every stored definition that isn't removed, with its state.
	Definitions() ([]Stored, error)
	// SetState stops or removes the agent's stored definition at version (StateStopped, StateRemoved); ErrStale when
	// the stored one isn't that version. Removing keeps the version floor (the agent id and version) and nothing else:
	// the definition's envelope (its instructions, in plaintext) goes.
	SetState(agent string, version uint64, state string) error
	// ExpireDefinition replaces the agent's stored envelope at version with env (a redacted one: its stored files'
	// keys and read grant gone) and marks it StateExpired; ErrStale when the stored one isn't that version, or is
	// removed. An expired row is the version floor like a stopped one.
	ExpireDefinition(agent string, version uint64, env []byte) error
	// LastFired is the highest slot recorded for a schedule trigger (ok false: none yet).
	LastFired(trigger string) (slot int64, ok bool, err error)
	// SetFired records that the trigger's slot fired; it never lowers what's recorded.
	SetFired(trigger string, slot int64) error
	// See records a delivery of an event trigger, kept until until; fresh is false when it was seen before.
	See(trigger, delivery string, until time.Time) (fresh bool, err error)
	// Seen reports whether a delivery was recorded (and not pruned), without recording it.
	Seen(trigger, delivery string) (bool, error)
	// PruneSeen drops deliveries kept until before t.
	PruneSeen(t time.Time) error
	// HighWater is the latest clock reading a tick accepted (zero: none).
	HighWater() (time.Time, error)
	// SetHighWater raises the high-water mark (never lowers it).
	SetHighWater(t time.Time) error
}

// Config is what an Engine runs with.
type Config struct {
	Firm  string
	Dir   identity.Directory // nil: no definition, event or fire verifies (fail closed)
	Store Store
	// IDKey derives once-only task ids (agentd's per-firm key from dstack's KMS, as guard.Host.IDKey).
	IDKey []byte
	Now   func() time.Time
	// Trusted is the operator's latest signed time (the stop list's issued_at) and whether that list is fresh.
	// nil, or not fresh: nothing fires (docs/27 section 3, "Clock").
	Trusted func() (time.Time, bool)
	// MaxAge is how old the operator's signed time may be (the stop list's freshness, 10 minutes); MaxSkew how far
	// the VM's clock may run from it beyond that (5 minutes).
	MaxAge, MaxSkew time.Duration
	// Collect counts each schedule's uncollected results (collect.go): a schedule stops itself instead of firing once
	// MaxUncollected of its runs in a row left one. nil: no such stop (labs, engine tests).
	Collect CollectStore
}

// Stored is a definition as the store keeps it.
type Stored struct {
	Env   []byte
	State string // StateActive, StateStopped or StateExpired (removed ones aren't returned)
}

// Definition states.
const (
	StateActive  = "active"
	StateStopped = "stopped"
	StateRemoved = "removed"
	// StateExpired is what Schedules says of an active definition past its not_after. It is stored only for a
	// definition with stored files once it reaches not_after (ExpireFiles): its envelope is then kept redacted, the
	// files' keys and read grant gone, so it no longer verifies and never runs again; only a new version does.
	StateExpired = "expired"
	// StateEnded is what StateOf says of an active definition whose triggers are all one-time ones that have run or
	// been skipped (not stored: read from the fired slots).
	StateEnded = "ended"
)

// Engine verifies and keeps definitions, fires schedules and takes events. Safe for concurrent use.
type Engine struct {
	cfg  Config
	mu   sync.Mutex
	defs map[string]*Installed // by agent
}

// Installed is a verified definition.
type Installed struct {
	Def    *Definition
	Env    safety.Envelope
	Digest string // the envelope's sha256 (start.agent.digest)
	State  string // StateActive, StateStopped, or StateExpired (stored redacted: ExpireFiles)
}

// Fire is one task to start: from a schedule slot or an event delivery. Task is its derived id.
type Fire struct {
	Task     string
	Def      *Definition
	Digest   string
	Trigger  Trigger
	Slot     int64     // schedule (a daily or one-time one's: the local date's day number, DayOf)
	Due      time.Time // a daily or one-time schedule's: the slot's own instant (At is when it fired)
	Delivery string    // event
	Ref      string    // event
	SentAt   time.Time // event: when the sender says it sent it
	At       time.Time
}

// Errors.
var (
	ErrClock   = errors.New("trigger: the VM's clock can't be trusted now")
	ErrReplay  = errors.New("trigger: delivery already used")
	ErrUnknown = errors.New("trigger: no such trigger")
	ErrSponsor = errors.New("trigger: the sponsor's authority has ended")
	ErrStale   = errors.New("trigger: not newer than the stored version")
	ErrNoAgent = errors.New("trigger: no such agent")
	ErrPast    = errors.New("trigger: definition: the time of a one-time schedule has already passed")
)

func New(cfg Config) *Engine {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.MaxAge == 0 {
		cfg.MaxAge = 10 * time.Minute
	}
	if cfg.MaxSkew == 0 {
		cfg.MaxSkew = 5 * time.Minute
	}
	return &Engine{cfg: cfg, defs: map[string]*Installed{}}
}

// Load verifies the stored definitions again (a restart; the sponsor may have gone meanwhile): those that verify
// are installed, the others are left in the store but don't run. It returns how many were installed.
func (e *Engine) Load() (int, error) {
	stored, err := e.cfg.Store.Definitions()
	if err != nil {
		return 0, err
	}
	n := 0
	for _, st := range stored {
		var env safety.Envelope
		if json.Unmarshal(st.Env, &env, json.RejectUnknownMembers(true)) != nil {
			continue
		}
		// Checked as of when it was issued: one past its not_after is still listed (expired), and doesn't fire
		// (sponsorOK); the sponsor must still be in the directory.
		var d Definition
		if json.Unmarshal(env.Payload, &d) != nil {
			continue
		}
		if st.State == StateExpired { // redacted at its not_after (ExpireFiles): listed, never run; not verified
			if e.loadExpired(env, &d) {
				n++
			}
			continue
		}
		if _, err := e.install(env, false, d.IssuedAt, cmp.Or(st.State, StateActive)); err == nil {
			n++
		}
	}
	// Definitions with stored files that reached their not_after while agentd was down lose their keys now.
	return n, e.ExpireFiles()
}

// loadExpired keeps a stored expired definition (its envelope redacted, so its signature no longer checks): it is only
// listed, so the chat can offer to start it again with fresh keys, and never fires or takes an event (not active).
func (e *Engine) loadExpired(env safety.Envelope, d *Definition) bool {
	if d.Agent == "" || d.Firm != e.cfg.Firm || d.Space == "" {
		return false
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.defs[d.Agent] != nil {
		return false
	}
	e.defs[d.Agent] = &Installed{Def: d, Env: env, Digest: env.Hash(), State: StateExpired}
	return true
}

// ExpireFiles deletes the stored files' keys of every definition that has them and reached its not_after (active or
// stopped): its stored envelope is replaced by one without the keys and the read grant, in state expired, and the
// installed copy drops them too. A key must not wait on the VM's disk for a schedule that can't run any more (the design:
// from install until the schedule is removed or expires). It runs on every tick and at Load; the VM's own clock
// decides (a host moving it forward can only delete keys early).
func (e *Engine) ExpireFiles() error {
	now := e.cfg.Now()
	var errs []error
	for _, in := range e.Installed() {
		if in.State == StateExpired || (len(in.Def.Files) == 0 && in.Def.FilesGrant == "") || now.Before(in.Def.NotAfter) {
			continue
		}
		d := *in.Def
		d.Files = slices.Clone(d.Files)
		for i := range d.Files {
			d.Files[i].Key, d.Files[i].URL = nil, ""
		}
		d.FilesGrant = ""
		payload, err := json.Marshal(d)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		env := safety.Envelope{Kind: in.Env.Kind, Payload: payload, Sigs: in.Env.Sigs}
		b, err := json.Marshal(env)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if err := e.cfg.Store.ExpireDefinition(d.Agent, d.Version, b); err != nil {
			errs = append(errs, fmt.Errorf("trigger: expiring a definition's stored files: %w", err))
			continue
		}
		e.mu.Lock()
		if e.defs[d.Agent] == in {
			for i := range in.Def.Files { // the installed copy's keys go too (a run started before holds its own)
				clear(in.Def.Files[i].Key)
			}
			e.defs[d.Agent] = &Installed{Def: &d, Env: env, Digest: env.Hash(), State: StateExpired}
		}
		e.mu.Unlock()
	}
	return errors.Join(errs...)
}

// Install verifies a definition and keeps it: a newer version replaces the installed one; the same version again
// (byte for byte) is a no-op; an older one, or another with the same version, is refused (version floor).
func (e *Engine) Install(env safety.Envelope) (*Installed, error) {
	return e.InstallChecked(env, nil)
}

// InstallChecked is Install with an extra check of the verified definition before anything is stored (agentd's
// personal-space rules, Personal).
func (e *Engine) InstallChecked(env safety.Envelope, check func(*Definition) error) (*Installed, error) {
	d, err := VerifyDefinition(&env, e.cfg.Dir, e.cfg.Firm, e.cfg.Now())
	if err != nil {
		return nil, err
	}
	if check != nil {
		if err := check(d); err != nil {
			return nil, fmt.Errorf("trigger: definition: %w", err)
		}
	}
	return e.install(env, true, time.Time{}, StateActive)
}

// install keeps a definition: verified at at (zero: now), in state.
func (e *Engine) install(env safety.Envelope, store bool, at time.Time, state string) (*Installed, error) {
	if at.IsZero() {
		at = e.cfg.Now()
	}
	d, err := VerifyDefinition(&env, e.cfg.Dir, e.cfg.Firm, at)
	if err != nil {
		return nil, err
	}
	in := &Installed{Def: d, Env: env, Digest: env.Hash(), State: state}
	e.mu.Lock()
	defer e.mu.Unlock()
	if old := e.defs[d.Agent]; old != nil {
		switch {
		case old.Def.Space != d.Space || old.Def.Firm != d.Firm:
			return nil, errors.New("trigger: the agent id belongs to another space")
		case old.Def.Version == d.Version && old.Digest == in.Digest && old.State == StateActive:
			return old, nil
		case old.Def.Version >= d.Version:
			return nil, fmt.Errorf("%w: version %d isn't newer than the installed %d (%s)", ErrStale, d.Version, old.Def.Version, old.State)
		}
	}
	// A new one-time run must still be ahead (a restart's Load keeps one that has passed: it has ended).
	if store && slices.ContainsFunc(d.Triggers, func(t Trigger) bool { _, inst := t.OnceSlot(); return t.IsOnce() && !inst.After(at) }) {
		return nil, ErrPast
	}
	// A trigger id belongs to one agent.
	for agent, o := range e.defs {
		if agent == d.Agent {
			continue
		}
		for _, t := range o.Def.Triggers {
			if slices.ContainsFunc(d.Triggers, func(x Trigger) bool { return x.ID == t.ID }) {
				return nil, errors.New("trigger: a trigger id belongs to another agent")
			}
		}
	}
	if store {
		b, err := json.Marshal(env)
		if err != nil {
			return nil, err
		}
		if err := e.cfg.Store.SaveDefinition(d.Agent, d.Version, b); err != nil {
			if errors.Is(err, ErrStale) { // a stopped or removed version (gone from memory) is the floor too
				return nil, fmt.Errorf("%w: version %d isn't newer than the stored one", ErrStale, d.Version)
			}
			return nil, err
		}
		// A new version (a Resume, a renewal, an edit): its uncollected count starts again (collect.go).
		if e.cfg.Collect != nil {
			if err := e.cfg.Collect.ResetCollect(d.Agent); err != nil {
				return nil, err
			}
		}
	}
	e.defs[d.Agent] = in
	return in, nil
}

// Installed returns the installed definitions.
func (e *Engine) Installed() []*Installed {
	e.mu.Lock()
	defer e.mu.Unlock()
	var out []*Installed
	for _, d := range e.defs {
		out = append(out, d)
	}
	slices.SortFunc(out, func(a, b *Installed) int {
		if a.Def.Agent < b.Def.Agent {
			return -1
		}
		return 1
	})
	return out
}

// Get returns the agent's definition (active or stopped), or nil.
func (e *Engine) Get(agent string) *Installed {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.defs[agent]
}

// Stop ends an agent's schedules: stopped (still listed) or removed (gone, the version floor kept). Its open tasks
// are the caller's to cancel. Stopping a stopped one again is fine.
func (e *Engine) Stop(agent string, remove bool) (*Installed, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	in := e.defs[agent]
	if in == nil {
		return nil, ErrNoAgent
	}
	state := StateStopped
	if remove {
		state = StateRemoved
	}
	if in.State == state || (in.State == StateExpired && !remove) { // an expired one doesn't run: nothing to stop
		return in, nil
	}
	if err := e.cfg.Store.SetState(agent, in.Def.Version, state); err != nil {
		return nil, err
	}
	out := *in
	out.State = state
	if remove {
		delete(e.defs, agent)
	} else {
		e.defs[agent] = &out
	}
	return &out, nil
}

// StateOf is what a definition is now: active, stopped, ended (active, its one-time runs done or skipped) or expired
// (active, but past not_after or its sponsor gone).
func (e *Engine) StateOf(in *Installed) string {
	if in.State != StateActive {
		return in.State
	}
	if e.ended(in.Def) {
		return StateEnded
	}
	if e.sponsorOK(in.Def) != nil {
		return StateExpired
	}
	return StateActive
}

// ended: every trigger is a one-time schedule whose slot has fired or been skipped.
func (e *Engine) ended(d *Definition) bool {
	for _, t := range d.Triggers {
		if !t.IsOnce() {
			return false
		}
		slot, _ := t.OnceSlot()
		if last, ok, err := e.cfg.Store.LastFired(slotKey(&t)); err != nil || !ok || last < slot {
			return false
		}
	}
	return true
}

// Active counts the definitions that can fire a schedule now: active, sponsor current, before not_after, with a
// schedule trigger. A count only (the Worker's keep-on signal, docs/30 "Scheduled tasks", decision 3).
func (e *Engine) Active() int {
	n := 0
	for _, in := range e.Installed() {
		if e.StateOf(in) == StateActive && slices.ContainsFunc(in.Def.Triggers, func(t Trigger) bool { return t.Kind == Schedule }) {
			n++
		}
	}
	return n
}

// NextRun is the earliest instant a schedule run is due that hasn't started yet, over every definition Active counts,
// floored to the minute; zero when none is ahead. It lets the Worker stop the VM between runs and start it a little
// before the next one (docs/30 "Scheduled tasks", decision 3 as revised 2026-10-23), so it errs early: a run due now
// that hasn't fired (the VM just booted, its clock not trusted yet) is reported at its own, past instant until it
// fires or Due skips it (MaxLate), and a slot whose record can't be read counts as not fired. One time for all
// definitions together: no ids, no counts per schedule.
func (e *Engine) NextRun() time.Time {
	now := e.cfg.Now()
	var next time.Time
	for _, in := range e.Installed() {
		if e.StateOf(in) != StateActive {
			continue
		}
		for _, tr := range in.Def.Triggers {
			if tr.Kind != Schedule {
				continue
			}
			at := e.nextOf(in.Def, &tr, now)
			if at.IsZero() || !at.Before(in.Def.NotAfter) { // past not_after it never fires (sponsorOK)
				continue
			}
			if next.IsZero() || at.Before(next) {
				next = at
			}
		}
	}
	if next.IsZero() {
		return next
	}
	return next.UTC().Truncate(time.Minute)
}

// nextOf is a schedule trigger's next run as Due will see it: its current slot's instant while that slot is still to
// fire, else the next slot's (zero: none).
func (e *Engine) nextOf(d *Definition, tr *Trigger, now time.Time) time.Time {
	unfired := func(slot int64) bool {
		last, ok, err := e.cfg.Store.LastFired(slotKey(tr))
		return err != nil || !ok || last < slot
	}
	switch {
	case tr.IsDaily():
		if slot, at := tr.DailySlot(now); slot >= 0 && !at.Before(d.IssuedAt) && tr.onDay(slot) && now.Sub(at) <= MaxLate && unfired(slot) {
			return at
		}
		return tr.NextRun(now)
	case tr.IsOnce():
		slot, at := tr.OnceSlot()
		if slot < 0 || at.Before(d.IssuedAt) || now.Sub(at) > MaxLate || !unfired(slot) {
			return time.Time{}
		}
		return at
	default:
		p := tr.Period()
		if p <= 0 {
			return time.Time{}
		}
		slot := Slot(tr, now)
		if slot < 0 {
			return tr.Anchor
		}
		if unfired(slot) {
			return tr.Anchor.Add(time.Duration(slot) * p)
		}
		return tr.Anchor.Add(time.Duration(slot+1) * p)
	}
}

// SpaceCount is how many definitions (active or stopped, not removed) are in space: live leaves out the ended ones,
// all counts them.
func (e *Engine) SpaceCount(space string) (live, all int) {
	for _, in := range e.Installed() {
		if in.Def.Space == space {
			all++
			if e.StateOf(in) != StateEnded {
				live++
			}
		}
	}
	return live, all
}

// LastRan is the last slot of a schedule trigger that started a task, and the last it skipped for being late (-1:
// none).
func (e *Engine) LastRan(t *Trigger) (ran, skipped int64) {
	ran, skipped = -1, -1
	if s, ok, _ := e.cfg.Store.LastFired(slotKey(t) + "|ran"); ok {
		ran = s
	}
	if s, ok, _ := e.cfg.Store.LastFired(slotKey(t) + "|skipped"); ok {
		skipped = s
	}
	return ran, skipped
}

// TaskFor is the derived task id of a schedule slot (what Due gives that slot's fire).
func (e *Engine) TaskFor(d *Definition, t *Trigger, slot int64) string {
	return harness.DeriveTaskID(e.cfg.IDKey, "schedule", d.Space, slotKey(t), strconv.FormatInt(slot, 10))
}

// Sponsored checks that a task started from a definition may go on: the sponsor it runs for is still current in
// the firm and holds the space, and the definition's not_after hasn't passed. A task that fails it must stop
// (docs/27 section 3: the sponsor's authority caps the task's).
func (e *Engine) Sponsored(space, sponsor string, notAfter time.Time) error {
	return e.sponsorOK(&Definition{Firm: e.cfg.Firm, Space: space, Sponsor: sponsor, NotAfter: notAfter})
}

func (e *Engine) sponsorOK(d *Definition) error {
	if e.cfg.Dir == nil {
		return ErrSponsor
	}
	if !e.cfg.Now().Before(d.NotAfter) {
		return fmt.Errorf("%w: not_after passed", ErrSponsor)
	}
	if _, err := e.cfg.Dir.Key(d.Firm, d.Space, d.Sponsor); err != nil {
		return fmt.Errorf("%w: %v", ErrSponsor, err)
	}
	return nil
}

// clock checks the VM's clock before anything fires: not behind its high-water mark, and close to the operator's
// latest signed time. A host can still make a slot fire somewhat early or late; it can't make one fire twice.
func (e *Engine) clock() (time.Time, error) {
	now := e.cfg.Now()
	hw, err := e.cfg.Store.HighWater()
	if err != nil {
		return now, err
	}
	if now.Before(hw) {
		return now, fmt.Errorf("%w: it runs behind its high-water mark", ErrClock)
	}
	if e.cfg.Trusted == nil {
		return now, fmt.Errorf("%w: no operator time", ErrClock)
	}
	t, fresh := e.cfg.Trusted()
	if !fresh || now.Before(t.Add(-e.cfg.MaxSkew)) || now.After(t.Add(e.cfg.MaxAge+e.cfg.MaxSkew)) {
		return now, fmt.Errorf("%w: too far from the operator's signed time", ErrClock)
	}
	return now, nil
}

// Slot is the schedule slot t falls in (-1 before the anchor).
func Slot(tr *Trigger, t time.Time) int64 {
	p := tr.Period()
	if p <= 0 || t.Before(tr.Anchor) {
		return -1
	}
	return int64(t.Sub(tr.Anchor) / p)
}

// Due returns the schedule fires due now: per schedule trigger of each installed definition whose sponsor still
// holds, the current slot if it hasn't fired yet. Slots missed while the VM was off aren't fired one by one: only
// the current one (no burst after a long sleep). The caller starts each task (its id is derived, so a repeat finds
// the first) and then records it with Fired. A clock the engine can't trust fires nothing.
func (e *Engine) Due() ([]Fire, error) {
	now, err := e.clock()
	if err != nil {
		return nil, err
	}
	if err := e.cfg.Store.SetHighWater(now); err != nil {
		return nil, err
	}
	var out []Fire
	var collectErr error
	for _, in := range e.Installed() {
		if in.State != StateActive || e.sponsorOK(in.Def) != nil {
			continue
		}
		for _, tr := range in.Def.Triggers {
			if tr.Kind != Schedule {
				continue
			}
			var slot int64
			var at time.Time
			switch {
			case tr.IsDaily():
				slot, at = tr.DailySlot(now)
				if at.Before(in.Def.IssuedAt) || !tr.onDay(slot) { // a day before the schedule existed, or not one of its days
					continue
				}
			case tr.IsOnce():
				slot, at = tr.OnceSlot()
				if now.Before(at) || at.Before(in.Def.IssuedAt) { // not yet (or, never, before the schedule existed)
					continue
				}
			default:
				slot = Slot(&tr, now)
			}
			if slot < 0 {
				continue
			}
			last, ok, err := e.cfg.Store.LastFired(slotKey(&tr))
			if err != nil {
				return out, err
			}
			if ok && last >= slot {
				continue
			}
			if (tr.IsDaily() || tr.IsOnce()) && now.Sub(at) > MaxLate { // too late: skipped, never fired later (decision 2)
				if err := e.cfg.Store.SetFired(slotKey(&tr), slot); err != nil {
					return out, err
				}
				if err := e.cfg.Store.SetFired(slotKey(&tr)+"|skipped", slot); err != nil {
					return out, err
				}
				continue
			}
			// Nobody collected its last MaxUncollected results: it stops itself instead of running (collect.go). A
			// count that can't be read fires nothing (tried again next tick).
			stop, err := e.uncollected(in)
			if err != nil {
				collectErr = err
				break
			}
			if stop {
				break
			}
			out = append(out, Fire{Task: e.TaskFor(in.Def, &tr, slot), Def: in.Def, Digest: in.Digest, Trigger: tr, Slot: slot,
				At: now, Due: at})
		}
	}
	return out, collectErr
}

// uncollected checks, before a run of in fires, whether MaxUncollected of its runs in a row left a result nobody
// collected; if so it stops in (recording why, for that version) and says so. An error: the run doesn't fire.
func (e *Engine) uncollected(in *Installed) (bool, error) {
	if e.cfg.Collect == nil {
		return false, nil
	}
	n, err := e.cfg.Collect.Uncollected(in.Def.Agent)
	if err != nil {
		return false, fmt.Errorf("trigger: uncollected results unreadable, nothing fired: %w", err)
	}
	if n < MaxUncollected {
		return false, nil
	}
	if err := e.cfg.Collect.SetStoppedUncollected(in.Def.Agent, in.Def.Version); err != nil {
		return false, err
	}
	if _, err := e.Stop(in.Def.Agent, false); err != nil {
		return false, err
	}
	return true, nil
}

// StopReason is why in is stopped when it stopped itself (StopUncollected); "" otherwise.
func (e *Engine) StopReason(in *Installed) string {
	if e.cfg.Collect == nil || in.State != StateStopped {
		return ""
	}
	if ok, err := e.cfg.Collect.StoppedUncollected(in.Def.Agent, in.Def.Version); err == nil && ok {
		return StopUncollected
	}
	return ""
}

// Fired records that a schedule fire's task was started (or found already started).
func (e *Engine) Fired(f Fire) error {
	if f.Trigger.Kind != Schedule {
		return nil
	}
	if err := e.cfg.Store.SetFired(slotKey(&f.Trigger), f.Slot); err != nil {
		return err
	}
	return e.cfg.Store.SetFired(slotKey(&f.Trigger)+"|ran", f.Slot)
}

// slotKey names a schedule's slots: the trigger with its period and anchor, so a new version that changes either
// starts counting afresh instead of reading the old numbers.
func slotKey(t *Trigger) string {
	if t.IsDaily() {
		// One count per trigger whatever its time, days or zone: a new version that moves the time can't make a day
		// fire twice.
		return t.ID + "|daily"
	}
	if t.IsOnce() {
		// Its own count per time: a new version that moves the run to another time is a new run (the person asked
		// for it again); the same time again finds its slot recorded.
		return t.ID + "|once|" + t.At + "|" + t.Zone
	}
	return t.ID + "|" + t.Every + "|" + strconv.FormatInt(t.Anchor.Unix(), 10)
}

// Delivered records an event's delivery as used (call it once its task was started or found started; a delivery
// that couldn't start a task can be sent again).
func (e *Engine) Delivered(f Fire) error {
	if f.Trigger.Kind != Event {
		return nil
	}
	_, err := e.cfg.Store.See(f.Trigger.ID, f.Delivery, f.SentAt.Add(2*EventWindow))
	return err
}

// Event checks an inbound event: the envelope's shape, the trigger installed as an event trigger, the sender's
// signature with the key the definition pins, sent within EventWindow of the VM's clock, the clock trusted, the
// sponsor still current, and the delivery not used before (Delivered records it once its task started). It returns the task to start; its id is
// derived from the trigger and the delivery, so a replay the seen set no longer remembers still finds the first.
func (e *Engine) Event(env safety.Envelope) (Fire, error) {
	if env.Kind != KindEvent || len(env.Payload) == 0 || len(env.Payload) > MaxEvent || len(env.Sigs) != 1 {
		return Fire{}, errors.New("trigger: not an event envelope")
	}
	var p EventPayload
	if err := json.Unmarshal(env.Payload, &p, json.RejectUnknownMembers(true)); err != nil {
		return Fire{}, errors.New("trigger: bad event")
	}
	if p.Type != EventType || !identity.ValidID("tr", p.Trigger) || !refRe.MatchString(p.Delivery) ||
		(p.Ref != "" && !refRe.MatchString(p.Ref)) || p.SentAt.IsZero() {
		return Fire{}, errors.New("trigger: bad event fields")
	}
	in, tr := e.find(p.Trigger)
	if in == nil || tr.Kind != Event || in.State != StateActive {
		return Fire{}, ErrUnknown
	}
	k, _ := identity.ParseKey(tr.Sender)
	if !signedBy(&env, eventLabel, k) {
		return Fire{}, errors.New("trigger: event not signed by the trigger's sender")
	}
	now, err := e.clock()
	if err != nil {
		return Fire{}, err
	}
	if d := now.Sub(p.SentAt); d > EventWindow || d < -EventWindow {
		return Fire{}, errors.New("trigger: event outside its 5-minute window")
	}
	if err := e.sponsorOK(in.Def); err != nil {
		return Fire{}, err
	}
	if err := e.cfg.Store.SetHighWater(now); err != nil {
		return Fire{}, err
	}
	// Recorded by Delivered once its task started (kept past the window on both sides of the sender's time, so it
	// can't come back while valid); two at once both pass here and the derived task id makes one task.
	seen, err := e.cfg.Store.Seen(tr.ID, p.Delivery)
	if err != nil {
		return Fire{}, err
	}
	if seen {
		return Fire{}, ErrReplay
	}
	return Fire{Task: harness.DeriveTaskID(e.cfg.IDKey, "event", in.Def.Space, tr.ID, p.Delivery), Def: in.Def, Digest: in.Digest,
		Trigger: tr, Delivery: p.Delivery, Ref: p.Ref, At: now, SentAt: p.SentAt}, nil
}

func (e *Engine) find(id string) (*Installed, Trigger) {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, in := range e.defs {
		for _, t := range in.Def.Triggers {
			if t.ID == id {
				return in, t
			}
		}
	}
	return nil, Trigger{}
}

// Prune drops seen deliveries past their keep, by the high-water mark (a clock set back can't make them expire).
func (e *Engine) Prune() error {
	hw, err := e.cfg.Store.HighWater()
	if err != nil || hw.IsZero() {
		return err
	}
	return e.cfg.Store.PruneSeen(hw)
}
