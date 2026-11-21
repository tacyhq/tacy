package safety

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"time"
)

// KindTrustList is the signed trust list: what agent VM software and keys the verifiers accept besides what they
// were built with, so a new dstack OS image (or boot measurements, a pre-launch script, a Tacy KMS key, a signed VM
// release, a higher VM release floor) is approved by a signature instead of a rebuild of every app. Signed by the offline admin
// keys (verifier.TrustListKeys pins them, SAFETY_ADMIN_KEYS-style ed25519:<base64>), served by the chat's Worker,
// checked by the verifier wherever it runs (the browser's WASM, the apps, kmsd). It can only add to the values a
// verifier was built with (they stay the floor), never remove one.
const KindTrustList = "trust-list"

// TrustListType names this trust list format.
const TrustListType = "tacy.trust-list/v1"

// MaxTrustListLifetime bounds the validity of a list that names an expiry. Lists don't expire from 2026-11-20
// (decided: withdrawal is a newer seq; clients keep the highest seq seen and the apps bundle a floor seq,
// verifier.TrustListFloorSeq), so a new list has none; one signed earlier with an expiry keeps it.
const MaxTrustListLifetime = 400 * 24 * time.Hour

// MaxTrustListPayload bounds a trust list's payload. It is larger than other documents' (MaxEnvelope), since each
// VM release in it carries its Sigstore bundle (about 11 KiB).
const MaxTrustListPayload = 128 << 10

// MaxTrustListSeq is the highest trust list seq (2^53-1, review2 M1): every verifier, the JavaScript ones included
// (a device's localStorage, the Worker's D1), must keep a seq exactly, and a number above this one can't be kept as a
// JavaScript number. A list above it is refused, so no list can make a device drop its record.
const MaxTrustListSeq = 1<<53 - 1

// MaxTrustSeqJump is how far a trust list's seq may be above the highest one a verifier took (the holders'
// split.MaxSeqJump): a list far above leaves the KMS admin no seq to withdraw with, and nothing legitimate jumps that
// far (each approve is one seq).
const MaxTrustSeqJump = 1000

// MaxTrustReleases and MaxTrustBundle bound a list's VM releases and each one's Sigstore bundle (JSON bytes).
const (
	MaxTrustReleases = 8
	MaxTrustBundle   = 32 << 10
)

// TrustList is one signed trust list. A verifier keeps the highest Seq it has taken and refuses lower ones (a
// replayed older list): a newer seq is how anything is withdrawn. A list that names an expiry is refused after it.
type TrustList struct {
	Type     string    `json:"type"`
	Seq      uint64    `json:"seq"`
	IssuedAt time.Time `json:"issued_at"`
	Expires  time.Time `json:"expires,omitzero"` // zero: never (lists from 2026-11-20 on)
	// OSImages are dstack OS images (os-image-hash, 64 hex) and their names, like verifier.ProdImages: each one
	// rebuilt with make os-repro-check and its verity root recomputed before it is listed.
	OSImages map[string]string `json:"os_images,omitzero"`
	// BootMeasurements are MRTD/RTMR0-2 sets (verifier.BootMeasurements), each for a listed or built-in OS image.
	BootMeasurements []TrustBoot `json:"boot_measurements,omitzero"`
	// PreLaunch are reviewed pre-launch scripts by sha256 (verifier.PreLaunchScripts).
	PreLaunch map[string]string `json:"pre_launch,omitzero"`
	// KMSIDs are Tacy KMS identities (its Ed25519 key, ed25519:<base64>) a VM's compose may name (-kms-key).
	KMSIDs map[string]string `json:"kms_ids,omitzero"`
	// VMReleaseFloor (vX.Y.Z): the oldest signed VM release accepted (raises the built-in minimum, never lowers it).
	VMReleaseFloor string `json:"vm_release_floor,omitzero"`
	// Releases are signed VM releases a release-mode verifier accepts besides the ones it was built with, so a new VM
	// release needs no app rebuild. Each one is checked exactly as a built-in one is (its Sigstore bundle, offline: the
	// release workflow's identity on its vX.Y.Z tag, the transparency log entry, at least the release floor), and one
	// whose bundle doesn't verify is ignored. They only add: a built-in release stays accepted unless below the floor.
	Releases []TrustRelease `json:"releases,omitzero"`
	// Optional, added before anything uses them so later changes need no lockstep app update (2026-11-20):
	// TCBGrace (as the holders' unlock policy has it), Platforms (attestation platforms accepted; empty = dstack) and
	// NextAdminKeys (the keys that will sign after a rotation, the no-downtime plan row 15).
	TCBGrace      *TCBGrace `json:"tcb_grace,omitempty"`
	Platforms     []string  `json:"platforms,omitempty"`
	NextAdminKeys []string  `json:"next_admin_keys,omitempty"`
	// More fields a later VM release may need, defined before any VM depends on them 	// clients first:
	// RevokedReleases are VM releases (vX.Y.Z) withdrawn at once, built in or listed (a vulnerable
	// release is dropped while its fix is gated). A client refuses a VM running one, whatever else accepts it.
	RevokedReleases []string `json:"revoked_releases,omitzero"`
	// Services are docker compose service names a release may have besides the built-in ones
	// (verifier.ReleaseServices): a later release's new container needs no app rebuild. Every image is still the
	// signed release's, pinned by digest.
	Services []string `json:"services,omitzero"`
	// KMSRoots are dstack KMS roots (key-provider ids: the KMS root CA's public key, DER, hex) a VM's CVM may take its
	// disk keys from besides verifier.KMSRoots: another provider's dstack. A retired root is refused.
	KMSRoots map[string]string `json:"kms_roots,omitzero"`
	// StartTicketKeys are the chat Worker's start-ticket keys (as the unlock policy's): parsed only by clients.
	StartTicketKeys []string `json:"start_ticket_keys,omitzero"`
	// RollbackWitness is the newest sealed-state head a holder witnessed: parsed only, for now.
	RollbackWitness *TrustWitness `json:"rollback_witness,omitzero"`
	// Optional holds members a newer build may read and an older one ignores (bounded, never checked here). Only what
	// is safe to ignore goes here: anything that narrows trust is a named member, which an older build refuses whole.
	Optional map[string]jsontext.Value `json:"optional,omitzero"`
}

// TrustWitness is a rollback witness head: a sealed-state chain head (sha256, hex) and its generation.
type TrustWitness struct {
	Head string `json:"head"`
	Seq  uint64 `json:"seq"`
}

// PlatformDstack is the attestation platform of a dstack CVM (Phala, or upstream dstack on another cloud): the one
// every verifier built today checks. A release for another TEE type names its own platform (TrustRelease.Platform);
// a verifier without that platform's checks ignores the entry, and a client says to update the app.
const PlatformDstack = "dstack"

// MaxAdminKeys bounds a list's next_admin_keys and start_ticket_keys.
const MaxAdminKeys = 8

// MaxTrustChain bounds a chain of admin key rotations (DecodeTrustListChain): lists that name next_admin_keys.
const MaxTrustChain = 8

// TCBGrace lets a quote whose TCB or QE status is one of Statuses (never Revoked) pass until Until, when Intel has
// published a TCB update the hosts haven't caught up with (the no-downtime plan row 14). MinTCBDate (YYYY-MM-DD or RFC 3339) and
// MinTCBEval (0: unchecked) bound how old the platform's TCB may be. At most MaxTCBGrace after the document's issue.
type TCBGrace struct {
	Until      time.Time `json:"until"`
	Statuses   []string  `json:"statuses"`
	MinTCBDate string    `json:"min_tcb_date,omitempty"`
	MinTCBEval int       `json:"min_tcb_eval,omitempty"`
}

// TCBGraceStatuses are the statuses a grace may allow (Revoked never).
var TCBGraceStatuses = []string{"OutOfDate", "ConfigurationNeeded"}

// MaxTCBGrace bounds a grace.
const MaxTCBGrace = 30 * 24 * time.Hour

// Validate checks a grace's form against its document's issue time.
func (g *TCBGrace) Validate(issuedAt time.Time) error {
	if g.Until.IsZero() || !g.Until.After(issuedAt) || g.Until.Sub(issuedAt) > MaxTCBGrace {
		return fmt.Errorf("tcb grace: until must be after the issue and within %s", MaxTCBGrace)
	}
	if len(g.Statuses) == 0 {
		return errors.New("tcb grace: no statuses")
	}
	for _, st := range g.Statuses {
		if !slices.Contains(TCBGraceStatuses, st) {
			return fmt.Errorf("tcb grace: status %q isn't one a grace may allow (%v; never Revoked)", st, TCBGraceStatuses)
		}
	}
	if g.MinTCBDate != "" {
		if _, err := tcbDate(g.MinTCBDate); err != nil {
			return fmt.Errorf("tcb grace: min_tcb_date: %w", err)
		}
	}
	if g.MinTCBEval < 0 {
		return errors.New("tcb grace: min_tcb_eval is negative")
	}
	return nil
}

// Allows checks a quote's TCB status, QE status and TCB date (Intel PCS's) under the grace at now. An UpToDate
// status always passes; Revoked never does.
func (g *TCBGrace) Allows(tcbStatus, qeStatus, date string, eval int, now time.Time) error {
	if !now.Before(g.Until) {
		return fmt.Errorf("the TCB grace ended at %s", g.Until.UTC().Format(time.RFC3339))
	}
	for what, st := range map[string]string{"TCB": tcbStatus, "QE": qeStatus} {
		if st != "UpToDate" && !slices.Contains(g.Statuses, st) {
			return fmt.Errorf("%s status %q isn't allowed by the TCB grace", what, st)
		}
	}
	if g.MinTCBDate != "" {
		min, _ := tcbDate(g.MinTCBDate)
		d, err := tcbDate(date)
		if err != nil || d.Before(min) {
			return fmt.Errorf("TCB date %q is older than the grace's %s", date, g.MinTCBDate)
		}
	}
	if g.MinTCBEval > 0 && eval < g.MinTCBEval {
		return fmt.Errorf("TCB evaluation %d is below the grace's %d", eval, g.MinTCBEval)
	}
	return nil
}

func tcbDate(s string) (time.Time, error) {
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, nil
	}
	return time.Parse("2006-01-02", s)
}

// TrustRelease is one signed VM release in a trust list, in the shape of a client's built-in release list entries
// (version, commit, compose sha256, Sigstore bundle), so a built-in entry can be copied into a list as it is.
type TrustRelease struct {
	Version       string         `json:"version"`
	Commit        string         `json:"commit"`
	ComposeSHA256 string         `json:"compose_sha256"`
	Bundle        jsontext.Value `json:"bundle"`
	// Platform is the attestation platform the release runs on; "" = PlatformDstack.
	Platform string `json:"platform,omitzero"`
}

// TrustBoot is one boot measurement set in a trust list.
type TrustBoot struct {
	Name    string `json:"name"`
	OSImage string `json:"os_image"`
	MRTD    string `json:"mrtd"`
	RTMR0   string `json:"rtmr0"`
	RTMR1   string `json:"rtmr1"`
	RTMR2   string `json:"rtmr2"`
	Source  string `json:"source"`
}

var (
	hex64       = regexp.MustCompile(`^[0-9a-f]{64}$`)
	hex96       = regexp.MustCompile(`^[0-9a-f]{96}$`)
	hex40       = regexp.MustCompile(`^[0-9a-f]{40}$`)
	versionRe   = regexp.MustCompile(`^v[0-9]{1,6}\.[0-9]{1,6}\.[0-9]{1,6}$`)
	trustNameRe = regexp.MustCompile(`^[^\x00-\x1f\x7f]{1,200}$`)
	platformRe  = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`) // an attestation platform name ("dstack")
	serviceRe   = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,31}$`)
	kmsRootRe   = regexp.MustCompile(`^[0-9a-f]{64,512}$`)
)

// Validate checks a trust list's shape (not its signature or its time).
func (l *TrustList) Validate() error {
	switch {
	case l.Type != TrustListType:
		return errors.New("trust list: type must be " + TrustListType)
	case l.Seq == 0 || l.IssuedAt.IsZero():
		return errors.New("trust list: seq and issued_at are required")
	case l.Seq > MaxTrustListSeq:
		return fmt.Errorf("trust list: seq %d is above %d (2^53-1, what every verifier can keep)", l.Seq, uint64(MaxTrustListSeq))
	case !l.Expires.IsZero() && (!l.Expires.After(l.IssuedAt) || l.Expires.Sub(l.IssuedAt) > MaxTrustListLifetime):
		return errors.New("trust list: expires, when set, must be after issued_at, within 400 days")
	case len(l.OSImages) > 64 || len(l.BootMeasurements) > 64 || len(l.PreLaunch) > 64 || len(l.KMSIDs) > 64:
		return errors.New("trust list: at most 64 entries of each kind")
	case l.VMReleaseFloor != "" && !versionRe.MatchString(l.VMReleaseFloor):
		return errors.New("trust list: vm_release_floor must be vX.Y.Z")
	case len(l.Releases) > MaxTrustReleases:
		return fmt.Errorf("trust list: at most %d releases", MaxTrustReleases)
	case len(l.RevokedReleases) > 64 || len(l.Services) > 16 || len(l.KMSRoots) > 16 || len(l.Platforms) > 8:
		return errors.New("trust list: at most 64 revoked releases, 16 services, 16 KMS roots and 8 platforms")
	case len(l.NextAdminKeys) > MaxAdminKeys || len(l.StartTicketKeys) > MaxAdminKeys:
		return fmt.Errorf("trust list: at most %d next admin keys and %d start-ticket keys", MaxAdminKeys, MaxAdminKeys)
	case l.RollbackWitness != nil && (!hex64.MatchString(l.RollbackWitness.Head) || l.RollbackWitness.Seq == 0):
		return errors.New("trust list: rollback_witness needs a head (sha256, hex) and a seq")
	case len(l.Optional) > 16:
		return errors.New("trust list: at most 16 optional members")
	}
	for k, v := range l.Optional {
		if !serviceRe.MatchString(k) || len(v) > 8<<10 || !v.IsValid() {
			return fmt.Errorf("trust list: bad optional member %q (a lowercase name, valid JSON of at most 8 KiB)", k)
		}
	}
	for name, keys := range map[string][]string{"next admin": l.NextAdminKeys, "start-ticket": l.StartTicketKeys} {
		seenKey := map[string]bool{}
		for _, k := range keys {
			if _, err := ParseKey(k); err != nil || k != KeyString(mustKey(k)) || seenKey[k] {
				return fmt.Errorf("trust list: bad or repeated %s key %q", name, k)
			}
			seenKey[k] = true
		}
	}
	revoked := map[string]bool{}
	for _, v := range l.RevokedReleases {
		if !versionRe.MatchString(v) || revoked[v] {
			return fmt.Errorf("trust list: bad or repeated revoked release %q", v)
		}
		revoked[v] = true
	}
	seenSvc := map[string]bool{}
	for _, n := range l.Services {
		if !serviceRe.MatchString(n) || seenSvc[n] {
			return fmt.Errorf("trust list: bad or repeated service %q", n)
		}
		seenSvc[n] = true
	}
	for h, n := range l.KMSRoots {
		if !kmsRootRe.MatchString(h) || !trustNameRe.MatchString(n) {
			return fmt.Errorf("trust list: bad KMS root %q", h)
		}
	}
	versions := map[string]bool{}
	for _, r := range l.Releases {
		if !versionRe.MatchString(r.Version) || !hex40.MatchString(r.Commit) || !hex64.MatchString(r.ComposeSHA256) {
			return fmt.Errorf("trust list: bad release %q (version vX.Y.Z; commit and compose_sha256 lowercase hex)", r.Version)
		}
		if versions[r.Version] {
			return fmt.Errorf("trust list: release %s listed twice", r.Version)
		}
		versions[r.Version] = true
		if revoked[r.Version] {
			return fmt.Errorf("trust list: release %s is both listed and revoked", r.Version)
		}
		if r.Platform != "" && !platformRe.MatchString(r.Platform) {
			return fmt.Errorf("trust list: release %s: bad platform %q", r.Version, r.Platform)
		}
		if len(r.Bundle) == 0 || len(r.Bundle) > MaxTrustBundle || r.Bundle.Kind() != '{' || !r.Bundle.IsValid() {
			return fmt.Errorf("trust list: release %s: the bundle must be a JSON object of at most %d bytes", r.Version, MaxTrustBundle)
		}
	}
	if l.TCBGrace != nil {
		if err := l.TCBGrace.Validate(l.IssuedAt); err != nil {
			return fmt.Errorf("trust list: %w", err)
		}
	}
	for _, pl := range l.Platforms {
		if !platformRe.MatchString(pl) {
			return fmt.Errorf("trust list: bad platform %q", pl)
		}
	}
	for _, k := range l.NextAdminKeys {
		if _, err := ParseKey(k); err != nil {
			return fmt.Errorf("trust list: next admin key: %w", err)
		}
	}
	for h, n := range l.OSImages {
		if !hex64.MatchString(h) || !trustNameRe.MatchString(n) {
			return fmt.Errorf("trust list: bad OS image %q", h)
		}
	}
	for h, n := range l.PreLaunch {
		if !hex64.MatchString(h) || !trustNameRe.MatchString(n) {
			return fmt.Errorf("trust list: bad pre-launch script %q", h)
		}
	}
	for k, n := range l.KMSIDs {
		if _, err := ParseKey(k); err != nil || k != KeyString(mustKey(k)) || !trustNameRe.MatchString(n) {
			return fmt.Errorf("trust list: bad KMS id %q", k)
		}
	}
	for _, b := range l.BootMeasurements {
		if !trustNameRe.MatchString(b.Name) || !hex64.MatchString(b.OSImage) || b.Source == "" {
			return fmt.Errorf("trust list: bad boot measurement set %q", b.Name)
		}
		for _, r := range []string{b.MRTD, b.RTMR0, b.RTMR1, b.RTMR2} {
			if !hex96.MatchString(r) {
				return fmt.Errorf("trust list: boot measurement set %q: a register isn't 48 bytes of lowercase hex", b.Name)
			}
		}
	}
	return nil
}

func mustKey(s string) ed25519.PublicKey {
	k, _ := ParseKey(s)
	return k
}

// DecodeTrustList reads one trust list envelope (JSON), strictly, as DecodeEnvelopes reads other documents, but with
// the trust list's own size bound (MaxTrustListPayload: its releases carry their bundles). VerifyTrustList checks it.
func DecodeTrustList(b []byte) (*Envelope, error) {
	b = bytes.TrimSpace(b)
	if len(b) == 0 || len(b) > 2*MaxTrustListPayload {
		return nil, errors.New("trust list: empty or oversize envelope")
	}
	if b[0] != '{' {
		return nil, errors.New("trust list: one envelope expected")
	}
	var e Envelope
	if err := json.Unmarshal(b, &e, json.RejectUnknownMembers(true)); err != nil {
		return nil, fmt.Errorf("trust list: bad envelope: %w", err)
	}
	return &e, nil
}

// VerifyTrustList checks e is a trust list signed by at least threshold of keys, valid at now (not issued more than
// MaxSkew ahead; not expired, when it names an expiry), and with a seq of at least minSeq (the highest the caller has taken: the same list
// again is fine, an older one is refused).
func VerifyTrustList(e *Envelope, keys []ed25519.PublicKey, threshold int, minSeq uint64, now time.Time) (*TrustList, error) {
	l, err := verifyTrustList(e, keys, threshold)
	if err != nil {
		return nil, err
	}
	switch {
	case l.IssuedAt.After(now.Add(MaxSkew)):
		return nil, errors.New("trust list: issued in the future")
	case !l.Expires.IsZero() && !now.Before(l.Expires):
		return nil, fmt.Errorf("trust list %d expired at %s", l.Seq, l.Expires.UTC().Format(time.RFC3339))
	case l.Seq < minSeq:
		return nil, fmt.Errorf("trust list %d is older than list %d already taken", l.Seq, minSeq)
	}
	return l, nil
}

// DecodeTrustListChain reads either one trust list envelope or a JSON array of them: the admin key rotations a
// verifier must follow (each a list naming next_admin_keys, oldest first) and then the list to take, last. The whole
// chain is bounded to MaxTrustChain+1 envelopes and 16 times one payload's size.
func DecodeTrustListChain(b []byte) (links []*Envelope, list *Envelope, err error) {
	b = bytes.TrimSpace(b)
	if len(b) > 0 && b[0] == '[' {
		if len(b) > 16*MaxTrustListPayload {
			return nil, nil, errors.New("trust list: oversize chain")
		}
		var raw []jsontext.Value
		if err := json.Unmarshal(b, &raw); err != nil {
			return nil, nil, fmt.Errorf("trust list: bad chain: %w", err)
		}
		if len(raw) == 0 || len(raw) > MaxTrustChain+1 {
			return nil, nil, fmt.Errorf("trust list: a chain is 1 to %d envelopes", MaxTrustChain+1)
		}
		for i, r := range raw {
			e, err := DecodeTrustList(r)
			if err != nil {
				return nil, nil, fmt.Errorf("trust list: chain envelope %d: %w", i, err)
			}
			links = append(links, e)
		}
		return links[:len(links)-1], links[len(links)-1], nil
	}
	e, err := DecodeTrustList(b)
	return nil, e, err
}

// VerifyTrustListLink checks e is a list that rotates the admin keys (names next_admin_keys), signed by at least
// threshold of keys, after the link before it (a seq above afterSeq) and not issued ahead of now. Its expiry doesn't
// count: a rotation holds until a later one replaces it.
func VerifyTrustListLink(e *Envelope, keys []ed25519.PublicKey, threshold int, afterSeq uint64, now time.Time) (*TrustList, error) {
	l, err := verifyTrustList(e, keys, threshold)
	if err != nil {
		return nil, err
	}
	switch {
	case l.IssuedAt.After(now.Add(MaxSkew)):
		return nil, errors.New("trust list: a key rotation issued in the future")
	case len(l.NextAdminKeys) == 0:
		return nil, fmt.Errorf("trust list %d in a chain names no next admin keys", l.Seq)
	case l.Seq <= afterSeq:
		return nil, fmt.Errorf("trust list %d in a chain isn't after %d", l.Seq, afterSeq)
	}
	return l, nil
}

// NextAdminKeys are the keys that sign the lists after l (any one of them): l's next_admin_keys when it names some,
// else keys and threshold unchanged.
func NextAdminKeys(l *TrustList, keys []ed25519.PublicKey, threshold int) ([]ed25519.PublicKey, int) {
	if l == nil || len(l.NextAdminKeys) == 0 {
		return keys, threshold
	}
	next := make([]ed25519.PublicKey, 0, len(l.NextAdminKeys))
	for _, k := range l.NextAdminKeys {
		next = append(next, mustKey(k))
	}
	return next, 1
}

// verifyTrustList checks e's kind, size and signatures, and decodes and validates its payload (no time checks).
func verifyTrustList(e *Envelope, keys []ed25519.PublicKey, threshold int) (*TrustList, error) {
	if e.Kind != KindTrustList {
		return nil, fmt.Errorf("trust list: kind %q", e.Kind)
	}
	if len(e.Payload) == 0 || len(e.Payload) > MaxTrustListPayload || len(e.Sigs) == 0 || len(e.Sigs) > 8 {
		return nil, errors.New("trust list: bad envelope size")
	}
	if threshold < 1 || len(keys) == 0 {
		return nil, errors.New("trust list: no signing keys pinned")
	}
	if n := e.signers(keys); n < threshold {
		return nil, fmt.Errorf("trust list: signed by %d of the pinned admin keys, needs %d", n, threshold)
	}
	var l TrustList
	if err := strict(e.Payload, &l); err != nil {
		return nil, fmt.Errorf("trust list: %w", err)
	}
	if err := l.Validate(); err != nil {
		return nil, err
	}
	return &l, nil
}
