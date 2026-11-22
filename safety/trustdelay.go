package safety

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
)

// The trust list's delay at each client (privacy review 2026-11-20 #3, the keys plan §11): everything a signed trust list
// adds waits TrustDelay at each verifier (a browser, the Mac and iPhone apps, the chat Worker) from when that verifier
// first saw it, while everything it takes away applies at once. The same rule as the key holders' unlock policy
// (kms/split items.go, holder.go delayed): a single stolen admin key can sign a list, but nothing it adds is
// trusted anywhere for a day, and every client and holder alerts or shows it meanwhile. The holders' delay doesn't
// cover clients: message plaintext goes from a client to the VM it verified, a path that never needs a key share.
//
// A list is reduced to items, one per thing it adds (TrustItems). A verifier keeps a TrustSeen record (first seen,
// withdrawn) per item: an item counts once it has been in every list since TrustDelay; one withdrawn and listed
// again waits again; a lowered vm_release_floor keeps the old floor in force for TrustDelay. Withdrawals
// (revoked_releases), a higher floor, a rotation of the admin keys (next_admin_keys: the lists the new keys sign are
// delayed the same way) and the fields only parsed (start_ticket_keys, rollback_witness, optional) apply at once.
//
// Un-revoking a release is an addition (second keys review H1). A verifier keeps every version any list it took
// revoked (TrustSeen.RevokedReleases, as it keeps machine revocations), and a newer list that leaves one out adds
// the item unrevoke:vX: the version stays revoked at that verifier for TrustDelay from when it first saw it left
// out, and only while every list since leaves it out. Revoked again, it is revoked at once; left out again, it waits
// a full day again. This is the holders' rule: there a revoked release is a withdrawn pin, and pinning it again is a
// new release item that waits 24 h. kmsctl approve -release vX on a revoked version is that new approval (it drops
// vX from revoked_releases in the same list), and the emergency override may name unrevoke:vX to skip the wait.
//
// Whose clock (2026-11-21, accepted): each verifier's own. A device's clock decides when an
// addition counts on that device: a browser, Mac or iPhone whose clock runs a day ahead (or is set ahead) counts an
// addition at once. Accepted because the holders keep their own 24 h on their own clocks (kms/split/holder delayed):
// a new release still gets no key share for a day, so a device that trusts it early can only talk to a VM that
// can't unlock. The chat Worker's record uses Cloudflare's clock.
//
// The emergency override (the no-downtime plan row 13) is the holders' (kms/split emergency.go): an optional member "emergency",
// signed by the build's pinned Tacy KMS id, whose key derives only from M (two of the admin's passphrase shares),
// names the list's seq and the items it expedites. The admin key alone can't skip the delay. A list whose override
// doesn't verify is refused whole, as a holder refuses such a policy. An older verifier ignores the optional member
// (it has no delay to skip).

// TrustDelay is how long a trust-list addition waits at a verifier (split.PinDelay's default at the holders).
const TrustDelay = 24 * time.Hour

// Trust-list items (the unlock policy's prefixes where the thing is the same).
const (
	TrustItemOS        = "os:"        // an OS image hash
	TrustItemBoot      = "boot:"      // a boot set: TrustBootItem, the holders' split.BootItem
	TrustItemPreLaunch = "prelaunch:" // a pre-launch script's sha256
	TrustItemKMSID     = "kmsid:"     // a Tacy KMS id
	TrustItemKMSRoot   = "kmsroot:"   // a dstack KMS root
	TrustItemRelease   = "release:"   // a VM release: TrustReleaseItem
	TrustItemService   = "service:"   // a docker compose service name
	TrustItemPlatform  = "platform:"  // an attestation platform other than dstack
	TrustItemTCBGrace  = "tcb-grace:" // a TCB grace: TrustGraceItem
	TrustItemFloor     = "floor:"     // the vm_release_floor (lowering it is an expansion)
	// TrustItemUnrevoke is a release version a verifier kept revoked that a newer list leaves out of
	// revoked_releases (unrevoke:vX): not one of TrustItems (it depends on the verifier's record, not the list alone).
	TrustItemUnrevoke = "unrevoke:"
)

// MaxRevokedReleasesKept bounds a verifier's kept union of revoked releases (a list names at most 64).
const MaxRevokedReleasesKept = 256

// TrustEmergencyMember is the optional member that carries the emergency override (SignedTrustEmergency JSON).
const TrustEmergencyMember = "emergency"

const sigTrustEmergency = "tacy-trust-list/emergency/v1" // Ed25519 label (KMS id); not the policy's, so neither stands in for the other

// TrustBootItem names a boot set as the holders' split.BootItem does: sha256 of os|mrtd|rtmr0|rtmr1|rtmr2.
func TrustBootItem(b TrustBoot) string {
	h := sha256.Sum256([]byte(strings.Join([]string{b.OSImage, b.MRTD, b.RTMR0, b.RTMR1, b.RTMR2}, "|")))
	return hex.EncodeToString(h[:])
}

// TrustReleaseItem names a release entry: sha256 of version|commit|compose|platform, so relabelling a compose with
// another version is a new item. (The bundle isn't in it: it only proves the release, and is checked on every use.)
func TrustReleaseItem(r TrustRelease) string {
	p := r.Platform
	if p == "" {
		p = PlatformDstack
	}
	h := sha256.Sum256([]byte(strings.Join([]string{r.Version, r.Commit, r.ComposeSHA256, p}, "|")))
	return TrustItemRelease + hex.EncodeToString(h[:])
}

// TrustGraceItem names a TCB grace by the sha256 of its JSON.
func TrustGraceItem(g *TCBGrace) string {
	b, _ := json.Marshal(g)
	h := sha256.Sum256(b)
	return TrustItemTCBGrace + hex.EncodeToString(h[:])
}

// TrustItems are the items list l adds, sorted. The floor is an item so a lowering is seen; platform dstack isn't
// one (it is every verifier's built-in platform).
func TrustItems(l *TrustList) []string {
	var out []string
	for h := range l.OSImages {
		out = append(out, TrustItemOS+h)
	}
	for _, b := range l.BootMeasurements {
		out = append(out, TrustItemBoot+TrustBootItem(b))
	}
	for h := range l.PreLaunch {
		out = append(out, TrustItemPreLaunch+h)
	}
	for k := range l.KMSIDs {
		out = append(out, TrustItemKMSID+k)
	}
	for h := range l.KMSRoots {
		out = append(out, TrustItemKMSRoot+h)
	}
	for _, r := range l.Releases {
		out = append(out, TrustReleaseItem(r))
	}
	for _, s := range l.Services {
		out = append(out, TrustItemService+s)
	}
	for _, p := range l.Platforms {
		if p != PlatformDstack {
			out = append(out, TrustItemPlatform+p)
		}
	}
	if l.TCBGrace != nil {
		out = append(out, TrustGraceItem(l.TCBGrace))
	}
	if l.VMReleaseFloor != "" {
		out = append(out, TrustItemFloor+l.VMReleaseFloor)
	}
	sort.Strings(out)
	return slices.Compact(out)
}

// TrustItemState is when a verifier first saw an item, and when it saw it withdrawn (zero: still listed).
type TrustItemState struct {
	First     time.Time `json:"first"`
	Withdrawn time.Time `json:"withdrawn,omitzero"`
}

// TrustSeen is a verifier's record of trust-list items: kept by the verifier itself (a device's local storage, the
// Worker's D1), never taken from the server that serves the lists. Seq is the list it was last updated by.
type TrustSeen struct {
	Seq   uint64                    `json:"seq"`
	Items map[string]TrustItemState `json:"items"`
	// RevokedMachines is the union of every machines_revoked this verifier has taken (safety/machine.go): kept
	// forever (bounded by MaxRevokedKept), so a newer list that leaves a hash out revokes nothing back. An older
	// verifier drops the member when it rewrites the record; the next list it takes from a newer one brings the
	// list's own revocations back.
	RevokedMachines []string `json:"revoked_machines,omitzero"`
	// RevokedReleases is the union of every revoked_releases this verifier has taken (review2 H1): each stays
	// revoked here until a newer list has left it out for TrustDelay (item unrevoke:vX). Bounded by
	// MaxRevokedReleasesKept; past it, a list's own revocations still apply (only the delay on un-revoking is lost).
	RevokedReleases []string `json:"revoked_releases,omitzero"`
	// OverlapEnded: a list this verifier took ended the KMS-fallback overlap (overlapend.go). Kept for good, from
	// any verified list, older ones too: no later list, and no missing one, brings the overlap back.
	OverlapEnded bool `json:"overlap_ended,omitzero"`
}

// MaxTrustSeen bounds a record (a list has at most a few hundred items; withdrawn ones are kept TrustDelay).
const MaxTrustSeen = 2048

// ParseTrustSeen reads a record a verifier kept. Unreadable items are none: every item then waits (fail closed),
// never counts at once. The revocations are read on their own (review2 L4): a record whose items or seq can't be
// kept (too many items, a bad time, a seq above MaxTrustListSeq) keeps its revoked machines and releases; only a
// record that isn't JSON at all loses them (the build's MachinesRevoked still apply).
func ParseTrustSeen(b []byte) TrustSeen {
	s := TrustSeen{Items: map[string]TrustItemState{}}
	var raw map[string]jsontext.Value
	if len(b) == 0 || json.Unmarshal(b, &raw) != nil {
		return s
	}
	var full TrustSeen
	if json.Unmarshal(b, &full) == nil && len(full.Items) <= MaxTrustSeen && full.Seq <= MaxTrustListSeq {
		s.Seq = full.Seq
		for k, v := range full.Items {
			s.Items[k] = v
		}
	}
	var machines, releases []string
	if v, ok := raw["revoked_machines"]; ok && json.Unmarshal(v, &machines) == nil {
		machines = slices.DeleteFunc(machines, func(h string) bool { return !hex64.MatchString(h) })
		slices.Sort(machines)
		s.RevokedMachines = slices.Compact(machines)
		if len(s.RevokedMachines) > MaxRevokedKept {
			s.RevokedMachines = s.RevokedMachines[:MaxRevokedKept]
		}
	}
	if v, ok := raw["overlap_ended"]; ok {
		_ = json.Unmarshal(v, &s.OverlapEnded)
	}
	if v, ok := raw["revoked_releases"]; ok && json.Unmarshal(v, &releases) == nil {
		releases = slices.DeleteFunc(releases, func(r string) bool { return !versionRe.MatchString(r) })
		slices.Sort(releases)
		s.RevokedReleases = slices.Compact(releases)
		if len(s.RevokedReleases) > MaxRevokedReleasesKept {
			s.RevokedReleases = s.RevokedReleases[:MaxRevokedReleasesKept]
		}
	}
	return s
}

// Marshal is the record's JSON, for the verifier to keep.
func (s TrustSeen) Marshal() []byte {
	b, _ := json.Marshal(s)
	return b
}

// Observe is s after list l was taken at now: an item new to s, or listed again after a withdrawal, is first seen
// now; one s has that l doesn't list is withdrawn now; expedite (the items a verified emergency override names) count
// from now - TrustDelay. A list older than the one s was last updated by changes nothing (a fallback to a kept list).
// Withdrawn items are forgotten after TrustDelay (listed again, they are new).
func (s TrustSeen) Observe(l *TrustList, expedite []string, now time.Time) TrustSeen {
	out := TrustSeen{Seq: s.Seq, Items: make(map[string]TrustItemState, len(s.Items)), RevokedMachines: slices.Clone(s.RevokedMachines),
		RevokedReleases: slices.Clone(s.RevokedReleases), OverlapEnded: s.OverlapEnded || l.OverlapEnded()}
	for k, v := range s.Items {
		out.Items[k] = v
	}
	if l != nil {
		// Machine revocations are permanent: taken from any verified list, older ones too, and never dropped.
		if _, revoked, _, err := l.TrustMachines(); err == nil {
			for _, h := range revoked {
				if !slices.Contains(out.RevokedMachines, h) && len(out.RevokedMachines) < MaxRevokedKept {
					out.RevokedMachines = append(out.RevokedMachines, h)
				}
			}
			sort.Strings(out.RevokedMachines)
		}
		// Release revocations are kept the same way (review2 H1), from older lists too: leaving one out is an
		// un-revocation, which waits (below).
		for _, v := range l.RevokedReleases {
			if !slices.Contains(out.RevokedReleases, v) && len(out.RevokedReleases) < MaxRevokedReleasesKept {
				out.RevokedReleases = append(out.RevokedReleases, v)
			}
		}
		sort.Strings(out.RevokedReleases)
	}
	if l == nil || l.Seq < s.Seq {
		return out
	}
	items := append(TrustItems(l), unrevokes(out.RevokedReleases, l)...)
	for _, it := range items {
		if st, ok := out.Items[it]; !ok || !st.Withdrawn.IsZero() {
			out.Items[it] = TrustItemState{First: now}
		}
	}
	for it, st := range out.Items {
		if st.Withdrawn.IsZero() && !slices.Contains(items, it) {
			st.Withdrawn = now
			out.Items[it] = st
		}
		if !st.Withdrawn.IsZero() && now.Sub(st.Withdrawn) >= TrustDelay {
			delete(out.Items, it)
		}
	}
	for _, it := range expedite {
		if st, ok := out.Items[it]; ok && st.Withdrawn.IsZero() && st.First.After(now.Add(-TrustDelay)) {
			st.First = now.Add(-TrustDelay)
			out.Items[it] = st
		}
	}
	out.Seq = l.Seq
	for len(out.Items) > MaxTrustSeen { // can't happen with valid lists; never grow without bound
		for k := range out.Items {
			delete(out.Items, k)
			break
		}
	}
	return out
}

// unrevokes are the unrevoke:vX items of list l under kept (the revoked versions a verifier kept): each kept version
// l leaves out of revoked_releases.
func unrevokes(kept []string, l *TrustList) []string {
	var out []string
	for _, v := range kept {
		if !slices.Contains(l.RevokedReleases, v) {
			out = append(out, TrustItemUnrevoke+v)
		}
	}
	return out
}

// Ripe says whether item counts at now: listed, not withdrawn, first seen at least TrustDelay ago.
func (s TrustSeen) Ripe(item string, now time.Time) bool {
	st, ok := s.Items[item]
	return ok && st.Withdrawn.IsZero() && !now.Before(st.First.Add(TrustDelay))
}

// TrustPending is an addition that doesn't count yet, and from when it will (if it stays listed).
type TrustPending struct {
	Item string    `json:"item"`
	From time.Time `json:"from"`
}

// InForce is l with only its additions that count at now (Ripe), and the ones that don't yet. Withdrawals and the
// fields that only narrow or are only parsed are l's own, plus every release s kept revoked whose un-revocation
// (unrevoke:vX) doesn't count yet. The vm_release_floor is l's, raised to any floor s saw withdrawn less than
// TrustDelay ago (a lowered floor keeps the old one in force). The overlap's end is l's or s's (OverlapEnded).
func (s TrustSeen) InForce(l *TrustList, now time.Time) (*TrustList, []TrustPending) {
	in := *l
	var pending []TrustPending
	ripe := func(it string) bool {
		if s.Ripe(it, now) {
			return true
		}
		from := now.Add(TrustDelay)
		if st, ok := s.Items[it]; ok && st.Withdrawn.IsZero() {
			from = st.First.Add(TrustDelay)
		}
		pending = append(pending, TrustPending{Item: it, From: from.UTC()})
		return false
	}
	filterMap := func(m map[string]string, prefix string) map[string]string {
		if m == nil {
			return nil
		}
		out := map[string]string{}
		for _, k := range sortedKeys(m) {
			if ripe(prefix + k) {
				out[k] = m[k]
			}
		}
		return out
	}
	in.OSImages = filterMap(l.OSImages, TrustItemOS)
	in.PreLaunch = filterMap(l.PreLaunch, TrustItemPreLaunch)
	in.KMSIDs = filterMap(l.KMSIDs, TrustItemKMSID)
	in.KMSRoots = filterMap(l.KMSRoots, TrustItemKMSRoot)
	in.BootMeasurements = nil
	for _, b := range l.BootMeasurements {
		if ripe(TrustItemBoot + TrustBootItem(b)) {
			in.BootMeasurements = append(in.BootMeasurements, b)
		}
	}
	in.Releases = nil
	for _, r := range l.Releases {
		if ripe(TrustReleaseItem(r)) {
			in.Releases = append(in.Releases, r)
		}
	}
	in.Services = nil
	for _, sv := range l.Services {
		if ripe(TrustItemService + sv) {
			in.Services = append(in.Services, sv)
		}
	}
	in.Platforms = nil
	for _, p := range l.Platforms {
		if p == PlatformDstack || ripe(TrustItemPlatform+p) {
			in.Platforms = append(in.Platforms, p)
		}
	}
	if l.TCBGrace != nil && !ripe(TrustGraceItem(l.TCBGrace)) {
		in.TCBGrace = nil
	}
	// Un-revocations wait (review2 H1): a version s kept revoked stays revoked until leaving it out has counted.
	in.RevokedReleases = slices.Clone(l.RevokedReleases)
	for _, v := range s.RevokedReleases {
		if !slices.Contains(in.RevokedReleases, v) && !ripe(TrustItemUnrevoke+v) {
			in.RevokedReleases = append(in.RevokedReleases, v)
		}
	}
	// The floor: l's at once (a raise narrows); a lowering waits, so a floor withdrawn within the delay stays.
	// (Unless the lowered floor itself counts: an emergency override expedited it.)
	for it, st := range s.Items {
		if l.VMReleaseFloor != "" && s.Ripe(TrustItemFloor+l.VMReleaseFloor, now) {
			break
		}
		if v, ok := strings.CutPrefix(it, TrustItemFloor); ok && !st.Withdrawn.IsZero() && now.Sub(st.Withdrawn) < TrustDelay {
			if newerVersion(v, in.VMReleaseFloor) == v && v != in.VMReleaseFloor {
				lowered := l.VMReleaseFloor
				if lowered == "" {
					lowered = "none"
				}
				in.VMReleaseFloor = v
				pending = append(pending, TrustPending{Item: TrustItemFloor + lowered, From: st.Withdrawn.Add(TrustDelay).UTC()})
			}
		}
	}
	// The overlap's end (overlapend.go): l's, or any this verifier kept, at once.
	if s.OverlapEnded && !in.OverlapEnded() {
		in.SetOverlapEnded()
	}
	sort.Slice(pending, func(i, j int) bool { return pending[i].Item < pending[j].Item })
	return &in, pending
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// newerVersion is the newer of two vX.Y.Z ("" or malformed counts as none).
func newerVersion(a, b string) string {
	pa, pb := versionParts(a), versionParts(b)
	switch {
	case pa == nil:
		return b
	case pb == nil:
		return a
	}
	for i := range 3 {
		if pa[i] != pb[i] {
			if pa[i] > pb[i] {
				return a
			}
			return b
		}
	}
	return a
}

func versionParts(v string) []int {
	if !versionRe.MatchString(v) {
		return nil
	}
	f := strings.Split(v[1:], ".")
	out := make([]int, 3)
	for i := range 3 {
		out[i], _ = strconv.Atoi(f[i])
	}
	return out
}

// TrustEmergency expedites Items of the trust list of seq ListSeq (kms/split Emergency's counterpart).
type TrustEmergency struct {
	KMSID    string    `json:"kms_id"`
	ListSeq  uint64    `json:"list_seq"`
	Items    []string  `json:"items"`
	Reason   string    `json:"reason"` // shown wherever it is taken
	IssuedAt time.Time `json:"issued_at"`
}

// SignedTrustEmergency is a TrustEmergency's exact JSON and the KMS id's signature over label ‖ 0 ‖ doc.
type SignedTrustEmergency struct {
	Doc []byte `json:"doc"`
	Sig []byte `json:"sig"`
}

func (e *TrustEmergency) validate() error {
	if e.ListSeq == 0 || len(e.Items) == 0 || len(e.Items) > 8 || e.Reason == "" || len(e.Reason) > 200 || e.IssuedAt.IsZero() {
		return errors.New("trust list: an emergency names its list seq, 1 to 8 items, a reason (at most 200 bytes) and its time")
	}
	for _, it := range e.Items {
		if !strings.Contains(it, ":") || len(it) > 200 {
			return fmt.Errorf("trust list: emergency item %q isn't a trust-list item", it)
		}
	}
	return nil
}

// SignTrustEmergency signs e with the KMS id's private key (kmsctl approve -emergency: M from two passphrase shares).
func SignTrustEmergency(kmsID ed25519.PrivateKey, e TrustEmergency) (*SignedTrustEmergency, error) {
	e.KMSID, e.IssuedAt = KeyString(kmsID.Public().(ed25519.PublicKey)), e.IssuedAt.UTC()
	if err := e.validate(); err != nil {
		return nil, err
	}
	doc, err := json.Marshal(e)
	if err != nil {
		return nil, err
	}
	return &SignedTrustEmergency{Doc: doc, Sig: ed25519.Sign(kmsID, append(append([]byte(sigTrustEmergency), 0), doc...))}, nil
}

// SetEmergency puts a signed override into l's optional members (before l is signed).
func (l *TrustList) SetEmergency(e *SignedTrustEmergency) error {
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	if l.Optional == nil {
		l.Optional = map[string]jsontext.Value{}
	}
	l.Optional[TrustEmergencyMember] = jsontext.Value(b)
	return nil
}

// OpenEmergency is l's emergency override, checked: signed by kmsID (the verifier's build-pinned KMS id), for l's seq,
// naming only items l adds. nil and no error when l has none; an error when it has one that doesn't hold (refuse l).
func (l *TrustList) OpenEmergency(kmsID ed25519.PublicKey) (*TrustEmergency, error) {
	raw, ok := l.Optional[TrustEmergencyMember]
	if !ok {
		return nil, nil
	}
	var se SignedTrustEmergency
	if err := strict(raw, &se); err != nil {
		return nil, fmt.Errorf("trust list %d: emergency: %w", l.Seq, err)
	}
	if len(kmsID) != ed25519.PublicKeySize || len(se.Sig) != ed25519.SignatureSize ||
		!ed25519.Verify(kmsID, append(append([]byte(sigTrustEmergency), 0), se.Doc...), se.Sig) {
		return nil, fmt.Errorf("trust list %d: the emergency override isn't signed by the pinned KMS id (it takes two passphrase shares)", l.Seq)
	}
	var e TrustEmergency
	if err := strict(se.Doc, &e); err != nil {
		return nil, fmt.Errorf("trust list %d: emergency: %w", l.Seq, err)
	}
	if err := e.validate(); err != nil {
		return nil, err
	}
	if e.KMSID != KeyString(kmsID) || e.ListSeq != l.Seq {
		return nil, fmt.Errorf("trust list %d: the emergency override is for list %d", l.Seq, e.ListSeq)
	}
	items := TrustItems(l)
	for _, it := range e.Items {
		// An un-revocation (review2 H1): any version the list leaves out of revoked_releases; it expedites only a
		// verifier that kept that version revoked (Observe).
		if v, ok := strings.CutPrefix(it, TrustItemUnrevoke); ok && versionRe.MatchString(v) && !slices.Contains(l.RevokedReleases, v) {
			continue
		}
		if !slices.Contains(items, it) {
			return nil, fmt.Errorf("trust list %d: the emergency override names %s, which the list doesn't add", l.Seq, it)
		}
	}
	return &e, nil
}
