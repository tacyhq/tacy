package verifier

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

// The Fix B switch-over (the no-downtime plan row 27): one client build verifies both the live KMS-fallback release and the Fix B
// release, each in its own key mode and only by exact pins. Clients ship first (web, Mac, iPhone after review), so
// this build must accept the VM that is live when it ships, which is v0.20.0 (key_provider kms behind Phala's gateway,
// no unlockd), and the Fix B release that replaces it.
//
// What the overlap allows, and nothing else:
//
//   - A Fix B build (Policy.KMSFallback off) takes the KMS key mode only for an app-compose.json whose sha256 is a
//     KMSOverlapReleases entry's, whose docker compose's sha256 is that entry's too, which has no unlockd (the Fix B
//     shape) and asks for key_provider kms. Any other KMS-mode pin is refused as before ("allowed only in the explicit
//     KMS fallback"), so the KMS mode can't reach a Fix B release or any other compose.
//   - Only for a verifier that doesn't check a key release (no KeyRelease, no RequireUnlockd: a browser, the apps, the
//     test tools, and the chat Worker, which then pushes the v0.20.0 VM its API keys after this check, as it does
//     today) and pins the release by its bytes (Policy.AppCompose, or release mode's own pin), never by a hash list
//     (kmsd's, a holder's signed policy): those keep their signed kms_fallback switch.
//   - Every other check runs on that release as on any KMS-fallback one: the pinned KMS root (KMSRoots) in the
//     attested key-provider event and as key_provider_id, nothing on the disk (memory volumes only), no deployer env,
//     the app-compose flags, the image digests and the old denylist for a compose without unlockd, the boot set, the
//     OS image, and the machine where the verifier has the machine check. A release-mode verifier also requires the
//     signed release's version to be the entry's, and the version floors (the chat's min_version, a trust list's
//     vm_release_floor) must stay at or below it, or the overlap ends there (fails closed).
//   - Until KMSOverlapUntil, the removal date (kms.KMSFallbackRemoveBy): from then a client refuses it, whatever it
//     was built with. The Worker answers app builds older than the overlap with the update text from the same date.
//   - Or until a signed trust list ends it: "overlap_ended": true (safety/overlapend.go). A build
//     that has verified one refuses the overlap release from then on, at once and for good (its own record keeps it);
//     routing alone can't keep v1 builds off v0.20.0 against a hostile Cloudflare, this can.
//
// In release mode (tacyhq/tacy verifier.go) the pin comes from ReleaseModeAppCompose: a Fix B build pins the overlap
// release's exact KMS app-compose for its exact docker compose, the none-mode app-compose for a release with unlockd,
// and refuses a release without unlockd that isn't an overlap one.

// KMSOverlapRelease is a KMS-fallback release a Fix B build accepts during the switch-over, by its exact pins.
type KMSOverlapRelease struct {
	Version          string // the signed release (vX.Y.Z)
	ComposeSHA256    string // sha256 of its docker compose (compose.yaml), the signed artifact
	AppComposeSHA256 string // sha256 of the app-compose.json its CVM attests (ReleaseAppCompose in the KMS mode)
}

// KMSOverlapReleases are the KMS-fallback releases this build still accepts: v0.20.0, the live VM since 2026-11-20
// (Phala prod5, dstack-0.6.5). Its compose is the signed release's (the chat's releases.json), its app-compose.json the
// one a fresh CVM of it attests (the r0200 recording, testdata/attest-r0200.json). Removal: empty this list in the
// first client build after the switch (the no-downtime plan row 27 step 4).
var KMSOverlapReleases = []KMSOverlapRelease{
	{
		Version:          "v0.20.0",
		ComposeSHA256:    "502e1e432dea62d5f36f42340f2bf2f4811579e781b56d54ead49fa49cd13dae",
		AppComposeSHA256: "656e16a2d5c34522924e3fc8747443f6ee830d5d6cc6915dcc92c1174443a3b5",
	},
}

// KMSOverlapUntil is when the overlap ends at every client: kms.KMSFallbackRemoveBy (agentvm TestOverlapDates keeps
// the two, and the chat Worker's OLD_APPS_UNTIL, the same).
var KMSOverlapUntil = time.Date(2027, 1, 15, 0, 0, 0, 0, time.UTC)

// KMSOverlapFact is the verification fact that names an overlap release.
const KMSOverlapFact = "KMS overlap"

func sha256Hex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// overlapAllowed: the policy is one the overlap may apply to (see the top of this file).
func overlapAllowed(p Policy) bool {
	return !p.KMSFallback && !p.KeyRelease && !p.RequireUnlockd && len(p.AppComposeSHA256) == 0 && !p.legacy
}

// kmsOverlap is the overlap release pinned exactly as pinnedBytes, or nil when pinnedBytes isn't one (no error). An
// error when it is one but can't be taken: after KMSOverlapUntil, once a signed trust list ended the overlap (ended:
// the policy's list in force, safety.TrustList.OverlapEnded), or an entry that doesn't meet the rules.
func kmsOverlap(pinned *appCompose, pinnedBytes []byte, now time.Time, ended bool) (*KMSOverlapRelease, error) {
	sum := sha256Hex(pinnedBytes)
	for i := range KMSOverlapReleases {
		o := &KMSOverlapReleases[i]
		if o.AppComposeSHA256 != sum {
			continue
		}
		switch {
		case sha256Hex([]byte(pinned.DockerComposeFile)) != o.ComposeSHA256:
			return nil, fmt.Errorf("the overlap release %s's app-compose.json runs another docker compose", o.Version)
		case HasUnlockd(pinned.DockerComposeFile):
			return nil, fmt.Errorf("the overlap release %s has unlockd: the KMS mode never takes the Fix B shape", o.Version)
		case pinned.keyMode() != KeyProviderKMS:
			return nil, fmt.Errorf("the overlap release %s's app-compose.json has key provider %q, want kms", o.Version, pinned.keyMode())
		case !now.Before(KMSOverlapUntil):
			return nil, fmt.Errorf("the KMS-fallback release %s was accepted only until %s (the no-downtime plan row 27)", o.Version, KMSOverlapUntil.Format(time.DateOnly))
		case ended:
			return nil, fmt.Errorf("the KMS-fallback release %s is no longer accepted: a signed trust list ended the overlap", o.Version)
		}
		return o, nil
	}
	return nil, nil
}

// overlapForCompose is the overlap release whose docker compose is exactly compose, or nil.
func overlapForCompose(compose string) *KMSOverlapRelease {
	sum := sha256Hex([]byte(compose))
	for i := range KMSOverlapReleases {
		if KMSOverlapReleases[i].ComposeSHA256 == sum {
			return &KMSOverlapReleases[i]
		}
	}
	return nil
}

// ErrNoUnlockdOutsideOverlap: a Fix B build in release mode takes a release without unlockd only as an overlap one.
var ErrNoUnlockdOutsideOverlap = errors.New("a release without unlockd is accepted only as a pinned KMS overlap release (the no-downtime plan row 27)")

// ReleaseModeAppCompose is the app-compose.json a release-mode verifier pins for the attested docker compose
// (tacyhq/tacy verifier.go, when the policy pins no compose, app-compose or hash): ReleaseAppCompose in the build's
// key mode (with the memory-root pre-launch script for a release with unlockd in the KMS fallback). In a Fix B build
// (kmsFallback off) an overlap release's exact docker compose gets its KMS-mode app-compose, which must hash to the
// entry's pin, and is returned with it: the caller then requires the signed release to be o.Version (CheckVersion);
// a docker compose without unlockd that isn't an overlap release's is refused (ErrNoUnlockdOutsideOverlap). The
// bundle check proves the docker compose is a signed release; Verify then requires the attested app-compose.json to
// be exactly the pin, in the pin's key mode.
func ReleaseModeAppCompose(compose string, kmsFallback bool, now time.Time) ([]byte, *KMSOverlapRelease, error) {
	if kmsFallback {
		var pre []byte
		if HasUnlockd(compose) {
			pre = []byte(MemoryRootScript)
		}
		pin, err := ReleaseAppCompose([]byte(compose), pre, true)
		return pin, nil, err
	}
	if o := overlapForCompose(compose); o != nil {
		pin, err := ReleaseAppCompose([]byte(compose), nil, true)
		if err != nil {
			return nil, nil, fmt.Errorf("the overlap release %s: %w", o.Version, err)
		}
		if got := sha256Hex(pin); got != o.AppComposeSHA256 {
			return nil, nil, fmt.Errorf("the overlap release %s's app-compose.json would be %s, its pin is %s", o.Version, short(got), short(o.AppComposeSHA256))
		}
		parsed, err := parseAppCompose(pin)
		if err != nil {
			return nil, nil, err
		}
		if _, err := kmsOverlap(parsed, pin, now, false); err != nil { // the list's end: Verify's own kmsOverlap call
			return nil, nil, err
		}
		return pin, o, nil
	}
	if !HasUnlockd(compose) {
		return nil, nil, ErrNoUnlockdOutsideOverlap
	}
	pin, err := ReleaseAppCompose([]byte(compose), nil, false)
	return pin, nil, err
}

// CheckVersion: the signed release a release-mode verifier found for the overlap release's compose is that release.
func (o *KMSOverlapRelease) CheckVersion(version string) error {
	if version != o.Version {
		return fmt.Errorf("the signed release for the KMS overlap compose is %s, the overlap pins %s", version, o.Version)
	}
	return nil
}
