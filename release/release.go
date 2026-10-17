// Package release checks that a compose.yaml is a signed release of this repository.
//
// A release is made by .github/workflows/release.yml on a tag vX.Y.Z. GitHub Actions gets a short-lived Sigstore
// certificate (Fulcio) for the workflow's OIDC identity, signs an in-toto statement whose subject is compose.yaml
// (name "compose.yaml", sha256 of the file), and logs it in Sigstore's public transparency log (Rekor). The same
// format and checks as internal/tinfoil, which verifies Tinfoil's releases this way.
//
// Verify accepts a bundle only if:
//
//   - the certificate chains to Sigstore's Fulcio, has an embedded SCT, and was valid when the signature was logged
//   - the signature is in the transparency log (inclusion proof and signed entry timestamp)
//   - the identity is exactly this repo's release workflow on a version tag:
//     issuer https://token.actions.githubusercontent.com,
//     SAN https://github.com/tacyhq/tacy/.github/workflows/release.yml@refs/tags/vX.Y.Z,
//     source repository https://github.com/tacyhq/tacy, ref refs/tags/vX.Y.Z, trigger push, GitHub-hosted runner
//   - the repository and its owner are the ones with GitHub's numeric ids RepoID and OwnerID, so a tacyhq/tacy
//     deleted and recreated (or an org renamed and the name taken) can't sign releases
//   - the statement is SLSA provenance v1 with a subject "compose.yaml" whose sha256 is the compose's
//   - the tag's version is at least MinVersion (rollback protection: older releases stop being accepted), and at
//     least Policy.LastSeen, the newest release the caller has seen before (so a relay can't serve it an older one)
//
// The Sigstore trusted root is embedded (trusted_root.json, from Sigstore's TUF repository), so verification needs
// no network and works the same in the browser.
package release

import (
	_ "embed"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	sigverify "github.com/sigstore/sigstore-go/pkg/verify"
)

const (
	// Repo is the GitHub repository releases come from.
	Repo = "tacyhq/tacy"
	// RepoID and OwnerID are GitHub's numeric ids of Repo and its owner (gh api repos/tacyhq/tacy: .id, .owner.id).
	// Names can be reused; ids can't. Fulcio puts them in the signing certificate (OIDs 1.3.6.1.4.1.57264.1.15
	// and .17).
	RepoID  = "1421733570"
	OwnerID = "233153967"
	// Workflow is the only workflow file that may sign a release.
	Workflow = ".github/workflows/release.yml"
	// Issuer is GitHub Actions' OIDC issuer.
	Issuer = "https://token.actions.githubusercontent.com"
	// MinVersion is the oldest release this verifier accepts. Raise it when a release must stop being used (a
	// security fix): a relay can then no longer serve an older, validly signed compose.
	MinVersion = "v0.1.0"
	// Subject is the in-toto subject name of the compose.
	Subject = "compose.yaml"
	// PredicateType is what actions/attest-build-provenance signs.
	PredicateType = "https://slsa.dev/provenance/v1"
)

//go:embed trusted_root.json
var trustedRootJSON []byte

var (
	embeddedOnce sync.Once
	embedded     root.TrustedMaterial
	embeddedErr  error
)

// TrustedRoot is Sigstore's public-good trusted root as embedded in this package.
func TrustedRoot() (root.TrustedMaterial, error) {
	embeddedOnce.Do(func() {
		embedded, embeddedErr = root.NewTrustedRootFromJSON(trustedRootJSON)
	})
	return embedded, embeddedErr
}

// Policy is what Verify requires. The zero value is the production policy.
type Policy struct {
	Repo       string               // "" = Repo
	RepoID     string               // "" = RepoID; set it (and OwnerID) when Repo is another repository
	OwnerID    string               // "" = OwnerID
	Workflow   string               // "" = Workflow
	MinVersion string               // "" = MinVersion; may only be raised (a lower value is an error)
	Trusted    root.TrustedMaterial // nil = the embedded Sigstore trusted root; tests pass their own
	// LastSeen is the newest release version the caller has accepted before ("" = none), e.g. kept by a client
	// from Release.Version. Older releases are refused. Unlike MinVersion, a value below the pinned minimum is fine
	// (the pinned minimum still applies).
	LastSeen string
}

func (p Policy) repo() string {
	if p.Repo == "" {
		return Repo
	}
	return p.Repo
}

func (p Policy) repoID() string {
	if p.RepoID == "" {
		return RepoID
	}
	return p.RepoID
}

func (p Policy) ownerID() string {
	if p.OwnerID == "" {
		return OwnerID
	}
	return p.OwnerID
}

func (p Policy) workflow() string {
	if p.Workflow == "" {
		return Workflow
	}
	return p.Workflow
}

// Minimum is the oldest version p accepts.
func (p Policy) Minimum() string {
	if p.MinVersion == "" {
		return MinVersion
	}
	return p.MinVersion
}

// Identity is the certificate SAN prefix a release must have: the workflow URL at a tag. The tag follows it.
func (p Policy) Identity() string {
	return "https://github.com/" + p.repo() + "/" + p.workflow() + "@refs/tags/"
}

// Release is what a verified bundle established.
type Release struct {
	Version       string    `json:"version"`        // the tag, vX.Y.Z
	Commit        string    `json:"commit"`         // the commit the workflow ran on
	ComposeSHA256 string    `json:"compose_sha256"` // the subject digest (hex)
	Identity      string    `json:"identity"`       // the certificate SAN
	RunURL        string    `json:"run_url"`        // the GitHub Actions run that signed it
	LogIndex      int64     `json:"log_index"`      // the Rekor entry
	SignedAt      time.Time `json:"signed_at"`      // when Rekor logged it
}

// Version is a release version vMAJOR.MINOR.PATCH (no pre-release or build suffix).
type Version [3]int

var versionRe = regexp.MustCompile(`^v(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})$`)

// ParseVersion parses "vX.Y.Z".
func ParseVersion(s string) (Version, error) {
	m := versionRe.FindStringSubmatch(s)
	if m == nil {
		return Version{}, fmt.Errorf("version %q isn't vMAJOR.MINOR.PATCH", s)
	}
	var v Version
	for i := range v {
		v[i], _ = strconv.Atoi(m[i+1])
	}
	return v, nil
}

// Less reports whether v is older than w.
func (v Version) Less(w Version) bool {
	for i := range v {
		if v[i] != w[i] {
			return v[i] < w[i]
		}
	}
	return false
}

func (v Version) String() string { return fmt.Sprintf("v%d.%d.%d", v[0], v[1], v[2]) }

// Verify checks that bundleJSON (a Sigstore bundle, as GitHub's attestations API and the release assets serve it)
// proves composeSHA256 (32 bytes) is a release allowed by p.
func Verify(bundleJSON []byte, composeSHA256 []byte, p Policy) (*Release, error) {
	if len(composeSHA256) != 32 {
		return nil, fmt.Errorf("compose digest is %d bytes, want 32", len(composeSHA256))
	}
	minV, err := ParseVersion(MinVersion)
	if err != nil {
		return nil, err
	}
	if p.MinVersion != "" {
		v, err := ParseVersion(p.MinVersion)
		if err != nil {
			return nil, fmt.Errorf("policy: %w", err)
		}
		if v.Less(minV) {
			return nil, fmt.Errorf("policy: minimum version %s is below the pinned %s", v, minV)
		}
		minV = v
	}
	var lastSeen *Version
	if p.LastSeen != "" {
		v, err := ParseVersion(p.LastSeen)
		if err != nil {
			return nil, fmt.Errorf("policy: last seen %w", err)
		}
		lastSeen = &v
	}
	tm := p.Trusted
	if tm == nil {
		if tm, err = TrustedRoot(); err != nil {
			return nil, fmt.Errorf("sigstore trusted root: %w", err)
		}
	}

	var b bundle.Bundle
	if err := b.UnmarshalJSON(bundleJSON); err != nil {
		return nil, fmt.Errorf("sigstore bundle: %w", err)
	}
	v, err := sigverify.NewVerifier(tm, sigverify.WithSignedCertificateTimestamps(1),
		sigverify.WithTransparencyLog(1), sigverify.WithObserverTimestamps(1))
	if err != nil {
		return nil, err
	}
	prefix := p.Identity()
	id, err := sigverify.NewShortCertificateIdentity(Issuer, "", "",
		"^"+regexp.QuoteMeta(prefix)+`v[0-9]+\.[0-9]+\.[0-9]+$`)
	if err != nil {
		return nil, err
	}
	res, err := v.Verify(&b, sigverify.NewPolicy(sigverify.WithArtifactDigest("sha256", composeSHA256),
		sigverify.WithCertificateIdentity(id)))
	if err != nil {
		return nil, fmt.Errorf("sigstore verification: %w", err)
	}

	// The SAN is checked above; the rest of the certificate must tell the same story.
	cert := res.Signature.Certificate
	if cert == nil {
		return nil, errors.New("no signing certificate")
	}
	tag := strings.TrimPrefix(cert.SubjectAlternativeName, prefix)
	ref := "refs/tags/" + tag
	switch {
	case cert.SourceRepositoryURI != "https://github.com/"+p.repo():
		err = fmt.Errorf("source repository %q", cert.SourceRepositoryURI)
	case cert.SourceRepositoryIdentifier != p.repoID():
		err = fmt.Errorf("source repository id %q, want %s (the name was reused by another repository?)",
			cert.SourceRepositoryIdentifier, p.repoID())
	case cert.SourceRepositoryOwnerIdentifier != p.ownerID():
		err = fmt.Errorf("source repository owner id %q, want %s (the owner name was reused?)",
			cert.SourceRepositoryOwnerIdentifier, p.ownerID())
	case cert.SourceRepositoryRef != ref:
		err = fmt.Errorf("source ref %q, want %q", cert.SourceRepositoryRef, ref)
	case cert.BuildSignerURI != cert.SubjectAlternativeName:
		err = fmt.Errorf("build signer %q", cert.BuildSignerURI)
	case cert.BuildConfigURI != cert.SubjectAlternativeName:
		err = fmt.Errorf("build config %q (the release workflow must be the top-level workflow)", cert.BuildConfigURI)
	case cert.BuildTrigger != "push":
		err = fmt.Errorf("trigger %q, want push (of the tag)", cert.BuildTrigger)
	case cert.RunnerEnvironment != "github-hosted":
		err = fmt.Errorf("runner %q, want github-hosted", cert.RunnerEnvironment)
	case !regexp.MustCompile(`^[0-9a-f]{40}$`).MatchString(cert.SourceRepositoryDigest):
		err = fmt.Errorf("source commit %q", cert.SourceRepositoryDigest)
	}
	if err != nil {
		return nil, fmt.Errorf("signing certificate isn't a release of %s: %w", p.repo(), err)
	}

	st := res.Statement
	if st == nil || st.PredicateType != PredicateType {
		return nil, fmt.Errorf("predicate type isn't %s", PredicateType)
	}
	want := hex.EncodeToString(composeSHA256)
	named := false
	for _, s := range st.Subject {
		if s.GetName() == Subject && s.GetDigest()["sha256"] == want {
			named = true
		}
	}
	if !named {
		return nil, fmt.Errorf("no subject %q with this compose's digest", Subject)
	}

	ver, err := ParseVersion(tag)
	if err != nil {
		return nil, err
	}
	if ver.Less(minV) {
		return nil, fmt.Errorf("release %s is older than the minimum %s (rollback protection)", ver, minV)
	}
	if lastSeen != nil && ver.Less(*lastSeen) {
		return nil, fmt.Errorf("release %s is older than %s, the newest this client has seen (rollback protection)",
			ver, *lastSeen)
	}

	r := &Release{Version: tag, Commit: cert.SourceRepositoryDigest, ComposeSHA256: want,
		Identity: cert.SubjectAlternativeName, RunURL: cert.RunInvocationURI}
	for _, ts := range res.VerifiedTimestamps {
		if ts.Type == "Tlog" && (r.SignedAt.IsZero() || ts.Timestamp.Before(r.SignedAt)) {
			r.SignedAt = ts.Timestamp.UTC()
		}
	}
	if es := b.GetVerificationMaterial().GetTlogEntries(); len(es) > 0 {
		r.LogIndex = es[0].GetLogIndex()
	}
	return r, nil
}

// VerifyAny tries each bundle (a digest can have more than one attestation, e.g. after a re-run) and returns the
// first release that verifies, or the first error.
func VerifyAny(bundles [][]byte, composeSHA256 []byte, p Policy) (*Release, error) {
	if len(bundles) == 0 {
		return nil, errors.New("no release attestation for this compose")
	}
	var first error
	for _, b := range bundles {
		r, err := Verify(b, composeSHA256, p)
		if err == nil {
			return r, nil
		}
		if first == nil {
			first = err
		}
	}
	return nil, first
}
