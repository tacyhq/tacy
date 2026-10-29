// Package trigger is authenticated triggers (docs/27 section 3): tasks that start
// without a person typing in the chat, on a schedule or on an inbound event, each bound to a signed agent
// definition, its space and its sponsor.
//
//   - A definition (tacy.agent/v1, a subset for now: instructions, models, tools, triggers, permission settings) is signed
//     by its author and its sponsor, each an identity that is current in the firm's key log and holds the space
//     (identity.Directory). The sponsor's signature means "it runs with my authority, inside policy" until
//     not_after. The VM keeps the newest version per agent (a version floor).
//   - A schedule fires from the signed definition and the VM's clock; nobody sends anything (the control plane
//     only wakes the VM). Each slot fires at most once: the (trigger, slot) pair is recorded and the task id is
//     derived from it, so a repeat finds the first task. The clock may not run backwards past its high-water mark,
//     and the VM doesn't fire when its clock is far from the operator's latest signed time.
//   - An inbound event is signed by its sender's key, which the sponsor-signed definition pins; it carries ids
//     only (a delivery id and a reference), never content. A delivery is used once (a seen set, and a task id
//     derived from it), and only within 5 minutes of the time it says it was sent.
//   - When the sponsor is revoked, leaves the space, or the definition's not_after passes, its triggers stop and
//     its open tasks stop (Engine.Sponsored).
//
// Standard library only, plus the safety envelope's shape.
package trigger

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/tacyhq/tacy/identity"
	"github.com/tacyhq/tacy/proto"
	"github.com/tacyhq/tacy/safety"
	"github.com/tacyhq/tacy/storedfiles"
)

// DefinitionType names an agent definition's payload; KindAgent is its envelope kind.
const (
	DefinitionType = "tacy.agent/v1"
	KindAgent      = "agent"
	defLabel       = "tacy-agent/v1"
)

// Trigger kinds.
const (
	Schedule = "schedule"
	Event    = "event"
)

// Limits on a definition.
const (
	MaxDefinition   = 32 << 10
	MaxInstructions = 16 << 10
	MinEvery        = 15 * time.Minute
	MaxEvery        = 31 * 24 * time.Hour
	MaxSponsorship  = 366 * 24 * time.Hour // not_after at most this long after issued_at
	// DefaultSponsorship is how long the chat makes a schedule last unless the person picks otherwise;
	// renewing is a new version signed again.
	DefaultSponsorship = 90 * 24 * time.Hour
	// MaxLate: a daily run that can't start within this of its time is skipped for that day.
	MaxLate         = 3 * time.Hour
	MaxIssuedAhead  = 5 * time.Minute
	maxTriggers     = 8
	maxDefModels    = 8
	maxDefTools     = 16
	maxDefSteps     = 20 // a scheduled run's 20 steps (the digest's)
	defaultDefSteps = 6
)

// Definition is an agent definition's payload (the parts triggers need; docs/27 section 3).
type Definition struct {
	Type         string   `json:"type"`
	Firm         string   `json:"firm"`
	Space        string   `json:"space"`
	Agent        string   `json:"agent"` // a_
	Version      uint64   `json:"version"`
	Instructions string   `json:"instructions"`
	Models       []string `json:"models"`
	// Seal is the space's seal public key ("x25519:<base64>"): each run's activity records and its result are sealed
	// to it (docs/27 section 12: no triggered run without records).
	Seal     string    `json:"seal"`
	Tools    []string  `json:"tools,omitzero"`
	MaxSteps int       `json:"max_steps,omitzero"`
	Triggers []Trigger `json:"triggers"`
	// Allow is the sponsor's permission settings for unattended runs, per kind: always or never. Anything else (ask, or
	// a kind not named) is denied: nobody is there to ask.
	Allow map[string]string `json:"allow,omitzero"`
	// Memory (schedule upgrades, the VM release after v0.14.0): the schedule remembers what its runs found, on the
	// VM only (memory.go: the last MemoryRuns runs, each at most MemoryKeep), and each run sees it, so a digest can
	// skip what it reported before. Absent: every run starts from nothing, as before. An older VM refuses a
	// definition with it (strict decoding: unknown member), never runs it without.
	Memory bool `json:"memory,omitzero"`
	// Notify is when a run tells the person: "" every run (as before), or NotifyChanges: only when it found something
	// that changed against what it remembers (it needs Memory); a run that found nothing new ends quiet (no message,
	// its result marked quiet) through the schedule.no_change tool, never by reading its text.
	Notify string `json:"notify,omitzero"`
	// Files (since v0.17.0): stored files the sponsor picked for every run, each with its
	// object's key (proto.StoredFile, no URL), unwrapped in their browser at install and sent only inside this
	// definition (EHBP to the attested VM key, signed with it); FilesGrant is the chat Worker's read grant for exactly
	// these objects, with which a run asks for an hour's read URLs (guard/stored.go). A run reads the versions picked:
	// a newer version is another object, with a key the definition doesn't have (the chat installs it again). An older
	// VM refuses a definition with them (strict decoding), never runs it without.
	Files      []proto.StoredFile `json:"files,omitzero"`
	FilesGrant string             `json:"files_grant,omitzero"`
	Author     string             `json:"author"`  // i_
	Sponsor    string             `json:"sponsor"` // i_
	IssuedAt   time.Time          `json:"issued_at"`
	NotAfter   time.Time          `json:"not_after"` // the sponsor's authority ends here
}

// Trigger is one way a definition's tasks start.
type Trigger struct {
	ID   string `json:"id"` // tr_
	Kind string `json:"kind"`
	// Schedule: a slot every Every (a Go duration, whole minutes, 15m to 744h), counted from Anchor; or one a day at
	// Daily ("HH:MM", 24 h) wall-clock time in Zone (an IANA zone name), following its DST changes,
	// only on Days when it names some ("mon" … "sun", 1 to 6 of them in week order;
	// absent: every day); or once, at At ("YYYY-MM-DDTHH:MM") wall-clock time in Zone (v0.13.0, daily.go).
	Every  string    `json:"every,omitzero"`
	Anchor time.Time `json:"anchor,omitzero"`
	Daily  string    `json:"daily,omitzero"`
	Days   []string  `json:"days,omitzero"`
	At     string    `json:"at,omitzero"`
	Zone   string    `json:"zone,omitzero"`
	// Event: the sender's Ed25519 key ("ed25519:<base64>"): only events it signs start a task.
	Sender string `json:"sender,omitzero"`
}

// Period is a schedule's period (Every parsed).
func (t *Trigger) Period() time.Duration {
	d, _ := time.ParseDuration(t.Every)
	return d
}

var nameRe = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$`)

// grantRe is a read grant as the chat's Worker writes it: "g1." base64url payload "." base64url HMAC (opaque here; the
// Worker checks it). At most 16 KiB: 200 object ids and the rest.
var grantRe = regexp.MustCompile(`^g1\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]{16,128}\z`)

const maxGrantBytes = 16 << 10

func (t *Trigger) check() error {
	if !identity.ValidID("tr", t.ID) {
		return errors.New("trigger id must be tr_ in the id format")
	}
	switch t.Kind {
	case Schedule:
		if t.Sender != "" {
			return fmt.Errorf("schedule %s: no sender", t.ID)
		}
		if t.Daily != "" || t.Zone != "" || t.Days != nil || t.At != "" {
			if t.Every != "" || !t.Anchor.IsZero() {
				return fmt.Errorf("schedule %s: daily, at or every, only one", t.ID)
			}
			if t.At != "" {
				if t.Daily != "" || t.Days != nil {
					return fmt.Errorf("schedule %s: at is one run: no daily or days with it", t.ID)
				}
				if _, _, err := t.once(); err != nil {
					return fmt.Errorf("schedule %s: %w", t.ID, err)
				}
				return nil
			}
			if _, _, _, err := t.daily(); err != nil {
				return fmt.Errorf("schedule %s: %w", t.ID, err)
			}
			if _, err := t.weekdays(); err != nil {
				return fmt.Errorf("schedule %s: %w", t.ID, err)
			}
			return nil
		}
		d, err := time.ParseDuration(t.Every)
		if err != nil || d < MinEvery || d > MaxEvery || d%time.Minute != 0 || t.Anchor.IsZero() {
			return fmt.Errorf("schedule %s: every must be whole minutes from %v to %v, with an anchor", t.ID, MinEvery, MaxEvery)
		}
	case Event:
		if _, err := identity.ParseKey(t.Sender); err != nil || t.Every != "" || !t.Anchor.IsZero() || t.Daily != "" || t.Zone != "" ||
			t.Days != nil || t.At != "" {
			return fmt.Errorf("event %s: needs the sender's ed25519 key and nothing else", t.ID)
		}
	default:
		return fmt.Errorf("trigger %s: kind must be schedule or event", t.ID)
	}
	return nil
}

func (d *Definition) check(firm string, now time.Time) error {
	switch {
	case d.Type != DefinitionType:
		return errors.New("type must be " + DefinitionType)
	case d.Firm != firm:
		return errors.New("definition is for another firm")
	case !identity.ValidID("s", d.Space) || !identity.ValidID("a", d.Agent):
		return errors.New("space and agent must be s_ and a_ ids")
	case !identity.ValidID("i", d.Author) || !identity.ValidID("i", d.Sponsor):
		return errors.New("author and sponsor must be i_ ids")
	case d.Version == 0:
		return errors.New("version must be at least 1")
	case d.Instructions == "" || len(d.Instructions) > MaxInstructions:
		return errors.New("instructions must be 1 byte to 16 KiB")
	case !validSeal(d.Seal):
		return errors.New("seal must be the space's x25519 seal key")
	case len(d.Models) == 0 || len(d.Models) > maxDefModels || len(d.Tools) > maxDefTools:
		return errors.New("1 to 8 models and at most 16 tools")
	case d.MaxSteps < 0 || d.MaxSteps > maxDefSteps:
		return errors.New("max_steps must be 0 to 20")
	case len(d.Triggers) == 0 || len(d.Triggers) > maxTriggers:
		return errors.New("1 to 8 triggers")
	case d.Notify != "" && d.Notify != NotifyChanges:
		return errors.New(`notify must be "changes" or absent`)
	case d.Notify == NotifyChanges && !d.Memory:
		return errors.New("notify changes needs memory: a run compares with what the schedule remembers")
	case d.IssuedAt.IsZero() || d.IssuedAt.After(now.Add(MaxIssuedAhead)):
		return errors.New("issued_at missing or in the future")
	case !d.NotAfter.After(now):
		return errors.New("the sponsorship has ended (not_after)")
	case d.NotAfter.Sub(d.IssuedAt) > MaxSponsorship:
		return errors.New("not_after may be at most a year after issued_at")
	}
	if len(d.Files) > 0 || d.FilesGrant != "" {
		if err := storedfiles.Check(d.Files, false); err != nil {
			return err
		}
		if len(d.Files) == 0 || len(d.FilesGrant) > maxGrantBytes || !grantRe.MatchString(d.FilesGrant) {
			return errors.New("stored files need their read grant, and a grant its files")
		}
	}
	for _, n := range d.Tools {
		if !nameRe.MatchString(n) || len(n) > 64 {
			return fmt.Errorf("tool %q isn't an action name", n)
		}
	}
	if len(slices.Compact(slices.Sorted(slices.Values(d.Tools)))) != len(d.Tools) {
		return errors.New("a tool is listed twice")
	}
	for _, m := range d.Models {
		if m == "" || len(m) > 128 {
			return errors.New("bad model name")
		}
	}
	for k, v := range d.Allow {
		if !nameRe.MatchString(k) || (v != safety.PermAlways && v != safety.PermNever) {
			return fmt.Errorf("allow %s must be always or never", k)
		}
	}
	seen := map[string]bool{}
	for i := range d.Triggers {
		if err := d.Triggers[i].check(); err != nil {
			return err
		}
		if a := d.Triggers[i].Anchor; !a.IsZero() && (a.Sub(d.IssuedAt) > MaxSponsorship || d.IssuedAt.Sub(a) > MaxSponsorship) {
			return errors.New("a schedule's anchor must be within a year of issued_at")
		}
		if d.Triggers[i].IsOnce() { // its one run is within the sponsorship: not before issued_at, before not_after
			switch _, at, _ := d.Triggers[i].once(); {
			case at.Before(d.IssuedAt):
				return errors.New("the time of a one-time schedule has already passed (it is before issued_at)")
			case !at.Before(d.NotAfter):
				return errors.New("a one-time schedule's at must be before not_after")
			}
		}
		if seen[d.Triggers[i].ID] {
			return errors.New("a trigger id is used twice")
		}
		seen[d.Triggers[i].ID] = true
	}
	return nil
}

// validSeal: "x25519:<base64 of 32 bytes>" in its one spelling, a usable X25519 key (not all zero).
func validSeal(s string) bool {
	b64, ok := strings.CutPrefix(s, "x25519:")
	if !ok {
		return false
	}
	b, err := base64.StdEncoding.Strict().DecodeString(b64)
	if err != nil || len(b) != 32 || base64.StdEncoding.EncodeToString(b) != b64 || bytes.Equal(b, make([]byte, 32)) {
		return false
	}
	_, err = ecdh.X25519().NewPublicKey(b)
	return err == nil
}

// Personal checks a definition installed in a person's own space on the shared chat VM:
// it is for the space and seal key the request proved, its author and sponsor are the identity that
// signed the request, its triggers are daily (or chosen days) or one-time schedules and its tools web reads only (nothing that sends or
// changes something: approvals don't exist for personal spaces yet).
func Personal(d *Definition, space, seal, who string) error {
	switch {
	case d.Space != space || d.Seal != seal:
		return errors.New("the definition is for another space or seal key than the request proved")
	case d.Author != who || d.Sponsor != who:
		return errors.New("author and sponsor must be the identity that signed the request")
	}
	for _, t := range d.Triggers {
		if t.Kind != Schedule || (t.Daily == "" && t.At == "") {
			return errors.New("personal spaces take daily, weekday or one-time schedules only")
		}
	}
	for _, t := range d.Tools {
		// document.create: its result as a document in the person's own conversation, nothing sent (guard/documents.go).
		// mail.*: the sponsor's own connected email account, read-only (guard/mail.go, v0.19.0).
		if !slices.Contains(PersonalTools, t) {
			return fmt.Errorf("tool %s isn't one a personal schedule may use (%s)", t, strings.Join(PersonalTools, ", "))
		}
	}
	return nil
}

// PersonalTools are the tools a personal schedule may use: web reads, a document for the person, and (v0.19.0) the
// person's own email, read-only.
var PersonalTools = []string{"web.fetch", "web.search", "web.images", "document.create", "mail.search", "mail.read", "mail.folders"}

// Steps is the definition's step limit (its max_steps, else 6).
func (d *Definition) Steps() int {
	if d.MaxSteps == 0 {
		return defaultDefSteps
	}
	return d.MaxSteps
}

// signedBytes is what a definition's signatures cover: the label, the kind and the payload, NUL-separated.
func signedBytes(label, kind string, payload []byte) []byte {
	b := make([]byte, 0, len(label)+len(kind)+2+len(payload))
	b = append(b, label...)
	b = append(b, 0)
	b = append(b, kind...)
	b = append(b, 0)
	return append(b, payload...)
}

// SignDefinition makes a definition's envelope signed by each key (tests, and what the browser does).
func SignDefinition(d Definition, keys ...ed25519.PrivateKey) (safety.Envelope, error) {
	d.Type = DefinitionType
	b, err := json.Marshal(d)
	if err != nil {
		return safety.Envelope{}, err
	}
	return signEnvelope(defLabel, KindAgent, b, keys...), nil
}

func signEnvelope(label, kind string, payload []byte, keys ...ed25519.PrivateKey) safety.Envelope {
	e := safety.Envelope{Kind: kind, Payload: payload}
	for _, k := range keys {
		e.Sigs = append(e.Sigs, safety.Sig{Key: identity.KeyString(k.Public().(ed25519.PublicKey)),
			Sig: ed25519.Sign(k, signedBytes(label, kind, payload))})
	}
	return e
}

// signedBy reports whether one of env's signatures is pub's and valid.
func signedBy(env *safety.Envelope, label string, pub ed25519.PublicKey) bool {
	msg := signedBytes(label, env.Kind, env.Payload)
	for _, s := range env.Sigs {
		if k, err := identity.ParseKey(s.Key); err == nil && k.Equal(pub) && ed25519.Verify(pub, msg, s.Sig) {
			return true
		}
	}
	return false
}

// VerifyDefinition checks a definition's envelope for firm at now: its shape (strict JSON), its fields, and a valid
// signature by its author and by its sponsor, each current in the firm and holding the space (dir). One signature
// serves both when the author is the sponsor.
func VerifyDefinition(env *safety.Envelope, dir identity.Directory, firm string, now time.Time) (*Definition, error) {
	if dir == nil {
		return nil, errors.New("trigger: no identity directory on this VM")
	}
	if env.Kind != KindAgent || len(env.Payload) == 0 || len(env.Payload) > MaxDefinition || len(env.Sigs) == 0 || len(env.Sigs) > 4 {
		return nil, errors.New("trigger: not an agent definition envelope")
	}
	var d Definition
	if err := json.Unmarshal(env.Payload, &d, json.RejectUnknownMembers(true)); err != nil {
		return nil, fmt.Errorf("trigger: definition: %v", err)
	}
	if err := d.check(firm, now); err != nil {
		return nil, fmt.Errorf("trigger: definition: %w", err)
	}
	for _, who := range []string{d.Author, d.Sponsor} {
		k, err := dir.Key(firm, d.Space, who)
		if err != nil {
			return nil, fmt.Errorf("trigger: %s: %w", who, err)
		}
		if !signedBy(env, defLabel, k) {
			return nil, fmt.Errorf("trigger: no valid signature by %s", who)
		}
	}
	return &d, nil
}
