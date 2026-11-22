package verifier

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/tacyhq/tacy/internal/tdx"
	"github.com/tacyhq/tacy/safety"
)

// TrustListKeys are the admin keys a signed trust list (safety.KindTrustList) must be signed by, TrustListThreshold
// of them: the offline admin key (SAFETY_ADMIN_KEYS in the chat's wrangler.jsonc; the kind is bound into
// what is signed, so its policy signatures can't stand in for a trust list). Changing them is a rebuild.
var TrustListKeys = []string{"ed25519:Ii1apdLLHa+9d1d/vAjiipxNV7fS9m2lwFva67v4VFg="}

// TrustListThreshold is how many of TrustListKeys must sign a trust list.
const TrustListThreshold = 1

// ReleaseKMSID is the RELEASE PIN of the production Tacy KMS id (the key service's Ed25519 key, ed25519:<base64>, from
// its genesis: kmsctl genesis prints it and writes kms-id.txt). The release step fills it in; cmd/compose's kmsID is
// this constant, so the compose names exactly the id the verifier accepts. Empty until genesis: KMSIDs is then empty
// and a compose naming any -kms-key is refused, unless a signed trust list names that id (kms_ids).
const ReleaseKMSID = "ed25519:1LPZHjHaCjYvuibeGa0PcuFHEIadIxsp8x9EbNNMmEg="

// ReleaseKMSName is how the verifier's facts name ReleaseKMSID.
const ReleaseKMSName = "Tacy KMS (production)"

// KMSIDs are the Tacy KMS identities a VM's compose may name as -kms-key: ReleaseKMSID once it is pinned, else none.
var KMSIDs = releaseKMSIDs(ReleaseKMSID)

// releaseKMSIDs is {id: ReleaseKMSName} for a well-formed id (ed25519:<base64 of 32 bytes>, canonical), else empty:
// an empty or malformed pin accepts no id at all (TestReleaseKMSID fails on a malformed one).
func releaseKMSIDs(id string) map[string]string {
	k, err := safety.ParseKey(id)
	if id == "" || err != nil || safety.KeyString(k) != id {
		return map[string]string{}
	}
	return map[string]string{id: ReleaseKMSName}
}

// KMSIDCheck is the check of the Tacy KMS the compose names. The chat maps its "Tacy KMS:" prefix to "kms_id".
const KMSIDCheck = "Tacy KMS: the compose names only pinned KMS ids (-kms-key)"

// TrustListFloorSeq is the lowest trust list seq this build takes: set at a client release to the seq of the newest
// list then, so a fresh install (no highest seq kept yet) can't be handed an older list that still lists something
// since withdrawn. Lists don't expire; a newer seq withdraws.
var TrustListFloorSeq uint64 = 1 // no list published yet; each client release sets the newest signed list's seq

// ParseTrustList verifies a signed trust list against TrustListKeys at now, refusing a seq below minSeq (the highest
// the caller already took) or TrustListFloorSeq, and a list past an expiry it names. envelope is one envelope (JSON),
// or a chain (safety.DecodeTrustListChain): the admin key rotations oldest first, each signed by the keys the one
// before it names (the first by TrustListKeys), then the list, signed by the keys the last rotation names. A client
// keeps the rotations it took and puts them first, so a server can't swap the keys back: a list signed only by a
// rotated-out key is refused.
func ParseTrustList(envelope []byte, minSeq uint64, now time.Time) (*safety.TrustList, error) {
	minSeq = max(minSeq, TrustListFloorSeq)
	links, env, err := safety.DecodeTrustListChain(envelope)
	if err != nil {
		return nil, err
	}
	keys, err := safety.ParseKeys(strings.Join(TrustListKeys, ","))
	if err != nil {
		return nil, err
	}
	// The list may be the last rotation itself (a client that keeps its rotations and was given the same list again).
	if n := len(links); n > 0 && string(links[n-1].Payload) == string(env.Payload) {
		links = links[:n-1]
	}
	threshold := TrustListThreshold
	var after uint64
	for i, e := range links {
		l, err := safety.VerifyTrustListLink(e, keys, threshold, after, now)
		if err != nil {
			return nil, fmt.Errorf("admin key rotation %d: %w", i+1, err)
		}
		keys, threshold = safety.NextAdminKeys(l, keys, threshold)
		after = l.Seq
	}
	if len(links) > 0 {
		after++ // the list comes after the last rotation
	}
	return safety.VerifyTrustList(env, keys, threshold, max(minSeq, after), now)
}

// Revoked says whether the trust list p took withdrew release version (revoked_releases): such a VM is refused
// whatever else accepts it. Clients check it on the release a verification names (verifier-core.ts).
func (p Policy) Revoked(version string) bool {
	return p.trust != nil && slices.Contains(p.trust.RevokedReleases, version)
}

// WithTrustList returns p with l's values added to what p uses (its own, or the built-in ones where p has none):
// OS images, boot measurement sets, pre-launch scripts, KMS ids, VM releases (MergeReleases), and the higher of the
// two release floors. It never removes a value, and refuses a list that brings back a retired OS image, adds a set
// for an unknown image, or adds a set with a retired image's kernel or command line (retiredBoot), under any label.
// It also refuses a list naming a platform other than dstack, the only one this verifier has checks for (KnownPlatform):
// fail closed, so a list can't switch on a host this build doesn't know (the v1 Google host removal: "dstack-gcp" is unknown).
func (p Policy) WithTrustList(l *safety.TrustList) (Policy, error) {
	if l == nil {
		return p, nil
	}
	for _, pl := range l.Platforms {
		if !KnownPlatform(pl) {
			return p, fmt.Errorf("trust list %d: unknown platform %q (this verifier checks only %q)", l.Seq, pl, safety.PlatformDstack)
		}
	}
	images := maps.Clone(cmpOr(p.ProdImages, ProdImages))
	for h, n := range l.OSImages {
		if old, ok := RetiredImages[h]; ok {
			return p, fmt.Errorf("trust list %d: OS image %s is retired (%s)", l.Seq, short(h), old)
		}
		if _, ok := images[h]; !ok {
			images[h] = n
		}
	}
	boot := slices.Clone(p.Boot)
	if boot == nil {
		boot = slices.Clone(BootMeasurements)
	}
	for _, b := range l.BootMeasurements {
		if _, ok := images[b.OSImage]; !ok {
			return p, fmt.Errorf("trust list %d: boot measurements %q are for an OS image it doesn't accept", l.Seq, b.Name)
		}
		if why := retiredBoot(b.RTMR1, b.RTMR2); why != "" {
			return p, fmt.Errorf("trust list %d: boot measurements %q have %s", l.Seq, b.Name, why)
		}
		boot = append(boot, BootMeasurement{Name: b.Name, OSImage: b.OSImage, MRTD: b.MRTD, RTMR0: b.RTMR0, RTMR1: b.RTMR1,
			RTMR2: b.RTMR2, Source: fmt.Sprintf("signed trust list %d: %s", l.Seq, b.Source)})
	}
	pre := maps.Clone(cmpOr(p.PreLaunch, PreLaunchScripts))
	for h, n := range l.PreLaunch {
		if _, ok := pre[h]; !ok {
			pre[h] = n
		}
	}
	ids := maps.Clone(cmpOr(p.KMSIDs, KMSIDs))
	for k, n := range l.KMSIDs {
		if _, ok := ids[k]; !ok {
			ids[k] = n
		}
	}
	roots := maps.Clone(cmpOr(p.KMSRoots, KMSRoots))
	for h, n := range l.KMSRoots {
		if old, ok := RetiredKMSRoots[h]; ok {
			return p, fmt.Errorf("trust list %d: KMS root %s is retired (%s)", l.Seq, short(h), old)
		}
		if _, ok := roots[h]; !ok {
			roots[h] = n
		}
	}
	services := slices.Clone(p.Services)
	if services == nil {
		services = slices.Clone(ReleaseServices)
	}
	for _, s := range l.Services {
		if !slices.Contains(services, s) {
			services = append(services, s)
		}
	}
	p.ProdImages, p.Boot, p.PreLaunch, p.KMSIDs, p.KMSRoots, p.Services = images, boot, pre, ids, roots, services
	p.Releases = slices.DeleteFunc(MergeReleases(p.Releases, l.Releases), func(r safety.TrustRelease) bool {
		// Withdrawn, or for a platform this verifier has no checks for (a client says to update the app).
		return slices.Contains(l.RevokedReleases, r.Version) || !dstackRelease(r)
	})
	p.ReleaseFloor = NewerVersion(p.ReleaseFloor, l.VMReleaseFloor)
	p.trust = l
	return p, nil
}

// retiredBoot says which retired image's measurements rtmr1 or rtmr2 are ("" if none's). With key provider none
// the OS image is the label of the set the registers match (osImageFromBoot), so a signed list that put a retired
// image's kernel (RTMR1) or command line and initramfs (RTMR2, with the root filesystem's dm-verity hash) under a
// current label would let that image boot unseen. MRTD and RTMR0 aren't compared: firmware and VM shape are shared
// across images (0.6.0 to 0.6.5 have the same MRTD and RTMR0). The same image on another VM size has another RTMR1
// but the same RTMR2, so RTMR2 alone catches it.
func retiredBoot(rtmr1, rtmr2 string) string {
	for _, r := range RetiredBootMeasurements {
		switch {
		case strings.EqualFold(rtmr1, r.RTMR1):
			return "the kernel (RTMR1) of the retired " + r.Name
		case strings.EqualFold(rtmr2, r.RTMR2):
			return "the command line and initramfs (RTMR2) of the retired " + r.Name
		}
	}
	return ""
}

// dstackRelease: r runs on dstack, the one platform this verifier checks.
func dstackRelease(r safety.TrustRelease) bool {
	return r.Platform == "" || r.Platform == safety.PlatformDstack
}

// KnownPlatform: name is an attestation platform this verifier has checks for. Only dstack on Phala (the Google
// Cloud host fallback, "dstack-gcp", was taken out of v1: the v1 Google host removal). A signed trust list naming any other is
// refused whole (WithTrustList), and kmsctl signs no unlock policy or trust list naming one; a holder refuses a policy
// naming a platform it has no checks for (kms/split/holder, Config.Platforms).
func KnownPlatform(name string) bool { return name == safety.PlatformDstack }

// WithTCBGrace is p accepting a TCB status other than UpToDate when the trust list p took grants a grace window that
// is open at now (tcb_grace, safety.TCBGrace.Allows: at most 30 days), and only for the TCB and QE
// statuses it names (never Revoked), at or above its minimum TCB date. The quote check (VerifyQuote) refuses any
// other non-UpToDate quote, and the verifier's own TCB check then lets the allowed ones pass. internal/tdx doesn't
// read the TCB evaluation number, so a grace naming min_tcb_eval refuses every non-UpToDate quote (fail closed).
func (p Policy) WithTCBGrace(now time.Time) Policy {
	if p.trust == nil || p.trust.TCBGrace == nil || !now.Before(p.trust.TCBGrace.Until) || p.trust.TCBGrace.MinTCBEval > 0 {
		return p
	}
	g := p.trust.TCBGrace
	inner := p.VerifyQuote
	getter, at := p.Getter, p.Now
	p.VerifyQuote = func(ctx context.Context, raw []byte) (*tdx.Quote, error) {
		var q *tdx.Quote
		var err error
		if inner != nil {
			q, err = inner(ctx, raw)
		} else {
			q, err = tdx.VerifyWith(ctx, raw, tdx.Options{Getter: getter, Now: at})
		}
		if err != nil || q == nil || q.TcbStatus == "UpToDate" {
			return q, err
		}
		if aerr := g.Allows(q.TcbStatus, q.QeStatus, q.TcbDate, 0, now); aerr != nil {
			return q, aerr
		}
		return q, nil
	}
	p.AllowStaleTCB = true
	return p
}

// MergeReleases is base (a verifier's built-in releases) with the trust list's added after it: an entry already in
// base (same version and compose) is not added again, and none of base is removed or replaced. Nothing here makes an
// entry trusted: a release-mode verifier still checks each one's bundle for the attested compose (ReleaseBundles).
func MergeReleases(base, add []safety.TrustRelease) []safety.TrustRelease {
	out := slices.Clone(base)
	for _, r := range add {
		if !slices.ContainsFunc(out, func(b safety.TrustRelease) bool { return b.Version == r.Version && b.ComposeSHA256 == r.ComposeSHA256 }) {
			out = append(out, r)
		}
	}
	return out
}

// ReleaseBundles are the Sigstore bundles p's releases (Policy.Releases) have for a compose's sha256 (hex), in order;
// none when no release lists it. A wrong bundle can only make the release check fail.
func (p Policy) ReleaseBundles(composeSHA256 string) [][]byte {
	var out [][]byte
	for _, r := range p.Releases {
		if r.ComposeSHA256 == composeSHA256 {
			out = append(out, slices.Clone([]byte(r.Bundle)))
		}
	}
	return out
}

// TrustInfo is what a verifier reports about a signed trust list it was given (the WASM's setTrustList, and each
// verification's trustList): whether it was taken, why not, and what it adds. Releases (the entries themselves, with
// their bundles) only where a caller asked for them (TrustInfoOf), for a release-mode client's bundle lookup.
type TrustInfo struct {
	OK               bool                  `json:"ok"`
	Error            string                `json:"error,omitempty"`
	Seq              uint64                `json:"seq,omitempty"`
	IssuedAt         string                `json:"issuedAt,omitempty"`
	Expires          string                `json:"expires,omitempty"`
	OSImages         int                   `json:"osImages"`
	BootMeasurements int                   `json:"bootMeasurements"`
	PreLaunch        int                   `json:"preLaunch"`
	KMSIDs           int                   `json:"kmsIds"`
	Releases         int                   `json:"releases"`
	ReleaseFloor     string                `json:"releaseFloor,omitempty"`
	ReleaseEntries   []safety.TrustRelease `json:"releaseEntries,omitempty"`
	// RevokedReleases are the list's withdrawn releases (always given: a client refuses a VM running one).
	RevokedReleases []string `json:"revokedReleases,omitempty"`
	Services        int      `json:"services"`
	KMSRoots        int      `json:"kmsRoots"`
	// TCBGraceUntil and TCBGraceStatuses are the list's TCB grace window, if any (RFC 3339).
	TCBGraceUntil    string   `json:"tcbGraceUntil,omitempty"`
	TCBGraceStatuses []string `json:"tcbGraceStatuses,omitempty"`
	// AdminKeys are the list's next_admin_keys, the keys that sign the lists after it: a key rotation, which a client
	// keeps and puts before later lists (trust-list.ts). Empty: the keys stay as they are.
	AdminKeys       []string `json:"adminKeys,omitempty"`
	StartTicketKeys int      `json:"startTicketKeys"`
	// Platforms are the attestation platforms the list accepts (empty: dstack).
	Platforms []string `json:"platforms,omitempty"`
	// Pending are the list's additions that don't count yet at this verifier (safety.TrustDelay from when it first
	// saw each), and from when each will; the counts above are what the list names, ReleaseEntries only what counts.
	Pending []safety.TrustPending `json:"pending,omitempty"`
	// Seen is this verifier's item record after taking the list (safety.TrustSeen JSON): the caller keeps it (a
	// device's storage, the Worker's D1) and gives it back with the next setTrustList.
	Seen string `json:"seen,omitempty"`
	// Emergency is the reason of the emergency override the list carries (signed by the pinned KMS id), if any.
	Emergency string `json:"emergency,omitempty"`
	// Machines are the labels of the machines a VM may run on under this list (its machine_certs when it carries
	// them, else the build's own), and MachinesRevoked how many certificate hashes this verifier refuses for good.
	Machines        []string `json:"machines,omitempty"`
	MachinesRevoked int      `json:"machinesRevoked"`
	// OverlapEnded: the KMS-fallback overlap is over at this verifier (the list's overlap_ended, or one it took
	// before: safety/overlapend.go); the overlap release is refused.
	OverlapEnded bool `json:"overlapEnded,omitempty"`
}

// TrustInfoOf summarizes a taken list; withReleases adds its release entries.
func TrustInfoOf(l *safety.TrustList, withReleases bool) TrustInfo {
	i := TrustInfo{OK: true, Seq: l.Seq, IssuedAt: l.IssuedAt.UTC().Format(time.RFC3339),
		OSImages: len(l.OSImages), BootMeasurements: len(l.BootMeasurements), PreLaunch: len(l.PreLaunch), KMSIDs: len(l.KMSIDs),
		Releases: len(l.Releases), ReleaseFloor: l.VMReleaseFloor, RevokedReleases: slices.Clone(l.RevokedReleases),
		Services: len(l.Services), KMSRoots: len(l.KMSRoots), AdminKeys: slices.Clone(l.NextAdminKeys),
		StartTicketKeys: len(l.StartTicketKeys), Platforms: slices.Clone(l.Platforms), OverlapEnded: l.OverlapEnded()}
	if !l.Expires.IsZero() {
		i.Expires = l.Expires.UTC().Format(time.RFC3339)
	}
	if g := l.TCBGrace; g != nil {
		i.TCBGraceUntil, i.TCBGraceStatuses = g.Until.UTC().Format(time.RFC3339), slices.Clone(g.Statuses)
	}
	if withReleases {
		i.ReleaseEntries = slices.Clone(l.Releases)
	}
	return i
}

// TrustState is the signed trust list a long-running verifier took (the WASM in a browser, an app or the chat's
// Worker): the envelope, checked again at every use, since it may have expired since, and the verifier's record of
// the list's items (safety.TrustSeen): only the additions that have counted for safety.TrustDelay are applied.
type TrustState struct {
	mu   sync.Mutex
	env  []byte
	seen safety.TrustSeen
}

// trustKMSID is the KMS id an emergency override must be signed by: this build's pinned ReleaseKMSID, never one a
// trust list adds (else the admin key alone could add an id and sign an override with it). nil when unpinned.
var trustKMSID = func() []byte {
	k, err := safety.ParseKey(ReleaseKMSID)
	if err != nil {
		return nil
	}
	return k
}()

// trustEmergency checks l's emergency override against the pinned KMS id: its items, or an error (refuse l).
func trustEmergency(l *safety.TrustList) (*safety.TrustEmergency, error) {
	return l.OpenEmergency(trustKMSID)
}

// Take is TakeSeen with no record kept yet: every addition waits.
func (s *TrustState) Take(env []byte, minSeq uint64, now time.Time) TrustInfo {
	return s.TakeSeen(env, minSeq, now, nil)
}

// TakeSeen checks env (one signed trust list, or a chain: ParseTrustList) at now against minSeq (the highest seq the
// caller has taken) and keeps it for Apply, with seen (the caller's safety.TrustSeen record, JSON; empty or
// unreadable: none) updated by the list (safety.TrustSeen.Observe, an emergency override's items expedited). The
// info's Seen is that record, for the caller to keep. An empty env clears the list (TrustInfo{OK: true}, Seq 0). A
// refused list leaves the one taken before.
func (s *TrustState) TakeSeen(env []byte, minSeq uint64, now time.Time, seen []byte) TrustInfo {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(env) == 0 {
		s.env = nil
		return TrustInfo{OK: true}
	}
	l, err := ParseTrustList(env, minSeq, now)
	kept := safety.ParseTrustSeen(seen)
	// The jump limit (review2 M1, the holders' split.MaxSeqJump): from the highest seq the caller or its own
	// record took, at least the build's floor.
	if base := max(minSeq, kept.Seq, TrustListFloorSeq); err == nil && l.Seq > base+safety.MaxTrustSeqJump {
		err = fmt.Errorf("trust list %d jumps more than %d above list %d", l.Seq, safety.MaxTrustSeqJump, base)
	}
	var em *safety.TrustEmergency
	if err == nil {
		_, err = Policy{}.WithTrustList(l)
	}
	if err == nil {
		em, err = trustEmergency(l)
	}
	if err == nil {
		_, err = trustMachines(l, nil) // a machine certificate that doesn't verify refuses the list, as a bad override does
	}
	if err != nil {
		return TrustInfo{Error: err.Error()}
	}
	var expedite []string
	if em != nil {
		expedite = em.Items
	}
	s.env, s.seen = slices.Clone(env), kept.Observe(l, expedite, now)
	in, pending := s.inForce(Policy{}, l, now)
	i := TrustInfoOf(l, false)
	// The releases in force, and the revocations in force: the list's own and every one this verifier keeps whose
	// un-revocation doesn't count yet (review2 H1; verifier-core.ts refuses a VM running one).
	i.ReleaseEntries, i.RevokedReleases, i.Pending, i.Seen = slices.Clone(in.Releases), slices.Clone(in.RevokedReleases), pending, string(s.seen.Marshal())
	i.OverlapEnded = in.OverlapEnded()
	if em != nil {
		i.Emergency = em.Reason
	}
	if ms, err := trustMachines(l, s.seen.RevokedMachines); err == nil {
		i.Machines, i.MachinesRevoked = machineSummary(ms), len(ms.Revoked)
	}
	return i
}

// inForce is l with only what counts at now under the kept record, and what doesn't yet; a boot set whose OS image p
// doesn't accept (built in, or listed and counting) waits with its image.
func (s *TrustState) inForce(p Policy, l *safety.TrustList, now time.Time) (*safety.TrustList, []safety.TrustPending) {
	in, pending := s.seen.InForce(l, now)
	images := cmpOr(p.ProdImages, ProdImages)
	kept := in.BootMeasurements[:0:0]
	for _, b := range in.BootMeasurements {
		if _, ok := images[b.OSImage]; ok || in.OSImages[b.OSImage] != "" {
			kept = append(kept, b)
		} else {
			pending = append(pending, safety.TrustPending{Item: safety.TrustItemBoot + safety.TrustBootItem(b), From: now.Add(safety.TrustDelay).UTC()})
		}
	}
	in.BootMeasurements = kept
	return in, pending
}

// Apply adds what of the list taken counts at now to p, if the list still holds at now, with its TCB grace window
// if open at now (WithTCBGrace); else p (the built-in values only) and why. The info is nil when no list was taken.
func (s *TrustState) Apply(p Policy, now time.Time) (Policy, *TrustInfo) {
	s.mu.Lock()
	env := s.env
	s.mu.Unlock()
	if env == nil {
		return p, nil
	}
	l, err := ParseTrustList(env, 0, now)
	if err == nil {
		_, err = trustEmergency(l)
	}
	if err == nil {
		s.mu.Lock()
		in, pending := s.inForce(p, l, now)
		kept := slices.Clone(s.seen.RevokedMachines)
		s.mu.Unlock()
		var q Policy
		var ms *safety.MachineSet
		if ms, err = trustMachines(l, kept); err == nil {
			q, err = p.WithTrustList(in)
		}
		if err == nil {
			// q.trust is the list in force (its withdrawals are the list's own; a pending TCB grace isn't in it).
			// The machines: the list's certificates when it carries them, else the build's, minus every revocation
			// this verifier took (no delay: each certificate needs the KMS id; revocations narrow).
			q.Machines = ms
			i := TrustInfoOf(l, false)
			i.RevokedReleases, i.Pending, i.OverlapEnded = slices.Clone(in.RevokedReleases), pending, in.OverlapEnded()
			i.Machines, i.MachinesRevoked = machineSummary(ms), len(ms.Revoked)
			return q.WithTCBGrace(now), &i
		}
	}
	return p, &TrustInfo{Error: err.Error()}
}

func cmpOr(m, def map[string]string) map[string]string {
	if m != nil {
		return m
	}
	return def
}

var versionRe = regexp.MustCompile(`^v(\d{1,6})\.(\d{1,6})\.(\d{1,6})$`)

// NewerVersion is the newer of two vX.Y.Z versions ("" or a malformed one counts as none).
func NewerVersion(a, b string) string {
	ma, mb := versionRe.FindStringSubmatch(a), versionRe.FindStringSubmatch(b)
	switch {
	case ma == nil && mb == nil:
		return ""
	case ma == nil:
		return b
	case mb == nil:
		return a
	}
	for i := 1; i <= 3; i++ {
		x, y := atoi(ma[i]), atoi(mb[i])
		if x != y {
			if x > y {
				return a
			}
			return b
		}
	}
	return a
}

func atoi(s string) int {
	n := 0
	for _, c := range s {
		n = n*10 + int(c-'0')
	}
	return n
}

// composeKMS reads the Tacy KMS the docker compose's services are pointed at: every -kms-key and -kms-url argument
// (also --name and -name=value) in a service's command or entrypoint.
func composeKMS(compose string) (keys, urls []string, err error) {
	var doc struct {
		Services map[string]map[string]any `yaml:"services"`
	}
	if err := yaml.Unmarshal([]byte(compose), &doc); err != nil {
		return nil, nil, fmt.Errorf("docker compose isn't YAML: %w", err)
	}
	for _, svc := range doc.Services {
		var args []string
		for _, k := range []string{"entrypoint", "command"} {
			switch v := svc[k].(type) {
			case string:
				args = append(args, strings.Fields(v)...)
			case []any:
				for _, a := range v {
					args = append(args, fmt.Sprint(a))
				}
			}
		}
		for i, a := range args {
			name, val, eq := strings.Cut(strings.TrimPrefix(strings.TrimPrefix(a, "-"), "-"), "=")
			if !strings.HasPrefix(a, "-") || (name != "kms-key" && name != "kms-url") {
				continue
			}
			if !eq {
				if i+1 >= len(args) {
					return nil, nil, fmt.Errorf("-%s has no value", name)
				}
				val = args[i+1]
			}
			if name == "kms-key" {
				keys = append(keys, val)
			} else {
				urls = append(urls, val)
			}
		}
	}
	slices.Sort(keys)
	slices.Sort(urls)
	return slices.Compact(keys), slices.Compact(urls), nil
}

// checkKMSID: every Tacy KMS the compose names is a pinned one (KMSIDs or a trust list), at an https URL.
func (r *Result) checkKMSID(compose string, ids map[string]string) bool {
	keys, urls, err := composeKMS(compose)
	var names []string
	for _, k := range keys {
		if err == nil && ids[k] == "" {
			err = fmt.Errorf("the compose names Tacy KMS %s, which isn't a pinned one", short(k))
		}
		names = append(names, ids[k])
	}
	for _, u := range urls {
		if err == nil && !strings.HasPrefix(u, "https://") {
			err = fmt.Errorf("-kms-url %q isn't https", u)
		}
	}
	if err == nil && len(urls) > 0 && len(keys) == 0 {
		err = errors.New("-kms-url without -kms-key (the KMS's answers would be unchecked)")
	}
	detail := "none named (keys made in the VM, nothing kept)"
	if len(keys) > 0 {
		detail = strings.Join(names, ", ")
		r.Facts["Tacy KMS"] = strings.Join(keys, ", ")
		r.Facts["Tacy KMS url"] = strings.Join(urls, ", ")
	}
	return r.add(KMSIDCheck, err, detail)
}
