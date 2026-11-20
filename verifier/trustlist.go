package verifier

import (
	"errors"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"
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

// KMSIDs are the Tacy KMS identities (the key service's Ed25519 key, ed25519:<base64>) a VM's compose may name as
// -kms-key. None yet: the key service isn't running, and a release that names one before it is pinned (here or in a
// signed trust list) is refused.
var KMSIDs = map[string]string{}

// KMSIDCheck is the check of the Tacy KMS the compose names. The chat maps its "Tacy KMS:" prefix to "kms_id".
const KMSIDCheck = "Tacy KMS: the compose names only pinned KMS ids (-kms-key)"

// ParseTrustList verifies a signed trust list (one envelope, JSON) against TrustListKeys at now, refusing a seq
// below minSeq (the highest the caller already took) and an expired list.
func ParseTrustList(envelope []byte, minSeq uint64, now time.Time) (*safety.TrustList, error) {
	envs, err := safety.DecodeEnvelopes(envelope)
	if err != nil {
		return nil, err
	}
	if len(envs) != 1 {
		return nil, errors.New("trust list: one envelope expected")
	}
	keys, err := safety.ParseKeys(strings.Join(TrustListKeys, ","))
	if err != nil {
		return nil, err
	}
	return safety.VerifyTrustList(&envs[0], keys, TrustListThreshold, minSeq, now)
}

// WithTrustList returns p with l's values added to what p uses (its own, or the built-in ones where p has none):
// OS images, boot measurement sets, pre-launch scripts, KMS ids, and the higher of the two release floors. It never
// removes a value, and refuses a list that brings back a retired OS image or adds a set for an unknown image.
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
	p.ReleaseFloor = NewerVersion(p.ReleaseFloor, l.VMReleaseFloor)
	p.trust = l
	return p, nil
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
