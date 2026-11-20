package verifier

import (
	"errors"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"go.yaml.in/yaml/v3"

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

// ParseTrustList verifies a signed trust list (one envelope, JSON) against TrustListKeys at now, refusing a seq
// below minSeq (the highest the caller already took) and an expired list.
func ParseTrustList(envelope []byte, minSeq uint64, now time.Time) (*safety.TrustList, error) {
	env, err := safety.DecodeTrustList(envelope)
	if err != nil {
		return nil, err
	}
	keys, err := safety.ParseKeys(strings.Join(TrustListKeys, ","))
	if err != nil {
		return nil, err
	}
	return safety.VerifyTrustList(env, keys, TrustListThreshold, minSeq, now)
}

// WithTrustList returns p with l's values added to what p uses (its own, or the built-in ones where p has none):
// OS images, boot measurement sets, pre-launch scripts, KMS ids, VM releases (MergeReleases), and the higher of the
// two release floors. It never removes a value, and refuses a list that brings back a retired OS image or adds a set
// for an unknown image.
func (p Policy) WithTrustList(l *safety.TrustList) (Policy, error) {
	if l == nil {
		return p, nil
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
	p.ProdImages, p.Boot, p.PreLaunch, p.KMSIDs = images, boot, pre, ids
	p.Releases = MergeReleases(p.Releases, l.Releases)
	p.ReleaseFloor = NewerVersion(p.ReleaseFloor, l.VMReleaseFloor)
	p.trust = l
	return p, nil
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
}

// TrustInfoOf summarizes a taken list; withReleases adds its release entries.
func TrustInfoOf(l *safety.TrustList, withReleases bool) TrustInfo {
	i := TrustInfo{OK: true, Seq: l.Seq, IssuedAt: l.IssuedAt.UTC().Format(time.RFC3339), Expires: l.Expires.UTC().Format(time.RFC3339),
		OSImages: len(l.OSImages), BootMeasurements: len(l.BootMeasurements), PreLaunch: len(l.PreLaunch), KMSIDs: len(l.KMSIDs),
		Releases: len(l.Releases), ReleaseFloor: l.VMReleaseFloor}
	if withReleases {
		i.ReleaseEntries = slices.Clone(l.Releases)
	}
	return i
}

// TrustState is the signed trust list a long-running verifier took (the WASM in a browser, an app or the chat's
// Worker): the envelope, checked again at every use, since it may have expired since.
type TrustState struct {
	mu  sync.Mutex
	env []byte
}

// Take checks env (one signed trust list) at now against minSeq (the highest seq the caller has taken) and keeps it
// for Apply; an empty env clears it (TrustInfo{OK: true}, Seq 0). A refused list leaves the one taken before.
func (s *TrustState) Take(env []byte, minSeq uint64, now time.Time) TrustInfo {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(env) == 0 {
		s.env = nil
		return TrustInfo{OK: true}
	}
	l, err := ParseTrustList(env, minSeq, now)
	if err == nil {
		_, err = Policy{}.WithTrustList(l)
	}
	if err != nil {
		return TrustInfo{Error: err.Error()}
	}
	s.env = slices.Clone(env)
	return TrustInfoOf(l, true)
}

// Apply adds the list taken to p, if it still holds at now; else p (the built-in values only) and why. The info is
// nil when no list was taken.
func (s *TrustState) Apply(p Policy, now time.Time) (Policy, *TrustInfo) {
	s.mu.Lock()
	env := s.env
	s.mu.Unlock()
	if env == nil {
		return p, nil
	}
	l, err := ParseTrustList(env, 0, now)
	if err == nil {
		var q Policy
		if q, err = p.WithTrustList(l); err == nil {
			i := TrustInfoOf(l, false)
			return q, &i
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
