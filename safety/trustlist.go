package safety

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"regexp"
	"time"
)

// KindTrustList is the signed trust list: what agent VM software and keys the verifiers accept besides what they
// were built with, so a new dstack OS image (or boot measurements, a pre-launch script, a Tacy KMS key, a higher VM
// release floor) is approved by a signature instead of a rebuild of every app. Signed by the offline admin
// keys (verifier.TrustListKeys pins them, SAFETY_ADMIN_KEYS-style ed25519:<base64>), served by the chat's Worker,
// checked by the verifier wherever it runs (the browser's WASM, the apps, kmsd). It can only add to the values a
// verifier was built with (they stay the floor), never remove one.
const KindTrustList = "trust-list"

// TrustListType names this trust list format.
const TrustListType = "tacy.trust-list/v1"

// MaxTrustListLifetime bounds a list's validity: an unattended old list stops counting, and the verifier falls back
// to what it was built with.
const MaxTrustListLifetime = 400 * 24 * time.Hour

// TrustList is one signed trust list. A verifier keeps the highest Seq it has taken and refuses lower ones (a
// replayed older list), and refuses an expired one.
type TrustList struct {
	Type     string    `json:"type"`
	Seq      uint64    `json:"seq"`
	IssuedAt time.Time `json:"issued_at"`
	Expires  time.Time `json:"expires"`
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
	versionRe   = regexp.MustCompile(`^v[0-9]{1,6}\.[0-9]{1,6}\.[0-9]{1,6}$`)
	trustNameRe = regexp.MustCompile(`^[^\x00-\x1f\x7f]{1,200}$`)
)

// Validate checks a trust list's shape (not its signature or its time).
func (l *TrustList) Validate() error {
	switch {
	case l.Type != TrustListType:
		return errors.New("trust list: type must be " + TrustListType)
	case l.Seq == 0 || l.IssuedAt.IsZero() || l.Expires.IsZero():
		return errors.New("trust list: seq, issued_at and expires are required")
	case !l.Expires.After(l.IssuedAt) || l.Expires.Sub(l.IssuedAt) > MaxTrustListLifetime:
		return errors.New("trust list: expires must be after issued_at, within 400 days")
	case len(l.OSImages) > 64 || len(l.BootMeasurements) > 64 || len(l.PreLaunch) > 64 || len(l.KMSIDs) > 64:
		return errors.New("trust list: at most 64 entries of each kind")
	case l.VMReleaseFloor != "" && !versionRe.MatchString(l.VMReleaseFloor):
		return errors.New("trust list: vm_release_floor must be vX.Y.Z")
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

// VerifyTrustList checks e is a trust list signed by at least threshold of keys, valid at now (not expired, not
// issued more than MaxSkew ahead), and with a seq of at least minSeq (the highest the caller has taken: the same list
// again is fine, an older one is refused).
func VerifyTrustList(e *Envelope, keys []ed25519.PublicKey, threshold int, minSeq uint64, now time.Time) (*TrustList, error) {
	if e.Kind != KindTrustList {
		return nil, fmt.Errorf("trust list: kind %q", e.Kind)
	}
	if len(e.Payload) == 0 || len(e.Payload) > MaxEnvelope || len(e.Sigs) == 0 || len(e.Sigs) > 8 {
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
	switch {
	case l.IssuedAt.After(now.Add(MaxSkew)):
		return nil, errors.New("trust list: issued in the future")
	case !now.Before(l.Expires):
		return nil, fmt.Errorf("trust list %d expired at %s", l.Seq, l.Expires.UTC().Format(time.RFC3339))
	case l.Seq < minSeq:
		return nil, fmt.Errorf("trust list %d is older than list %d already taken", l.Seq, minSeq)
	}
	return &l, nil
}
