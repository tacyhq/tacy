package release_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"regexp"
	"strings"
	"testing"

	sgbundle "github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/tuf"
	sigverify "github.com/sigstore/sigstore-go/pkg/verify"

	"github.com/tacyhq/tacy/release"
	"github.com/tacyhq/tacy/release/releasetest"
)

var compose = sha256.Sum256([]byte("services: {}\n"))

func setup(t *testing.T) (*releasetest.Sigstore, release.Policy) {
	t.Helper()
	s, err := releasetest.New()
	if err != nil {
		t.Fatal(err)
	}
	return s, release.Policy{Trusted: s.Trusted()}
}

func bundle(t *testing.T, s *releasetest.Sigstore, o releasetest.Options) []byte {
	t.Helper()
	if o.Subjects == nil {
		o.Subjects = map[string][]byte{release.Subject: compose[:]}
	}
	b, err := s.Bundle(o)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestValidRelease(t *testing.T) {
	s, p := setup(t)
	b := bundle(t, s, releasetest.Options{Version: "v1.2.3", Subjects: map[string][]byte{
		release.Subject: compose[:], "release.json": make([]byte, 32)}})
	r, err := release.Verify(b, compose[:], p)
	if err != nil {
		t.Fatal(err)
	}
	if r.Version != "v1.2.3" || len(r.Commit) != 40 || r.SignedAt.IsZero() ||
		r.Identity != "https://github.com/tacyhq/tacy/.github/workflows/release.yml@refs/tags/v1.2.3" {
		t.Fatalf("%+v", r)
	}
	// The minimum can be raised to exactly this version.
	p.MinVersion = "v1.2.3"
	if _, err := release.Verify(b, compose[:], p); err != nil {
		t.Fatal(err)
	}
}

func TestRejected(t *testing.T) {
	other := sha256.Sum256([]byte("services: {evil: {}}\n"))
	cases := []struct {
		name, want string
		opts       releasetest.Options
		policy     func(*release.Policy)
		edit       func(b []byte) []byte
	}{
		{name: "another repository", want: "certificate identity", opts: releasetest.Options{Repo: "tacyhq/tacy-fork"}},
		{name: "another workflow in the repo", want: "certificate identity", opts: releasetest.Options{Workflow: ".github/workflows/ci.yml"}},
		{name: "branch instead of tag", want: "certificate identity", opts: releasetest.Options{Ref: "refs/heads/main"}},
		{name: "pre-release tag", want: "certificate identity", opts: releasetest.Options{Version: "v1.0.0-rc1"}},
		{name: "another OIDC issuer", want: "certificate identity", opts: releasetest.Options{Issuer: "https://accounts.example.com"}},
		{name: "same name, another repository id (deleted and recreated)", want: "repository id",
			opts: releasetest.Options{RepoID: "999"}},
		{name: "same name, another owner id", want: "owner id", opts: releasetest.Options{OwnerID: "999"}},
		{name: "certificate without repository ids", want: "repository id", opts: releasetest.Options{NoIDs: true}},
		{name: "fork whose policy pins only its name", want: "repository id",
			opts:   releasetest.Options{Repo: "someone/tacy", RepoID: "5", OwnerID: "6"},
			policy: func(p *release.Policy) { p.Repo = "someone/tacy" }},
		{name: "self-hosted runner", want: "runner", opts: releasetest.Options{Runner: "self-hosted"}},
		{name: "manual trigger", want: "trigger", opts: releasetest.Options{Trigger: "workflow_dispatch"}},
		{name: "older than the minimum (rollback)", want: "rollback", opts: releasetest.Options{Version: "v1.0.0"},
			policy: func(p *release.Policy) { p.MinVersion = "v1.0.1" }},
		{name: "older than the pinned minimum", want: "rollback", opts: releasetest.Options{Version: "v0.0.9"}},
		{name: "digest mismatch", want: "artifact", opts: releasetest.Options{Subjects: map[string][]byte{release.Subject: other[:]}}},
		{name: "right digest under another name", want: "no subject", opts: releasetest.Options{Subjects: map[string][]byte{"other.yaml": compose[:]}}},
		{name: "another predicate type", want: "predicate", opts: releasetest.Options{PredicateType: "https://example.com/other/v1"}},
		{name: "no transparency log entry", want: "transparency log", opts: releasetest.Options{NoTlog: true}},
		{name: "no SCT", want: "SCT", opts: releasetest.Options{NoSCT: true}},
		{name: "signed by another Sigstore", want: "log", policy: func(p *release.Policy) {
			o, _ := releasetest.New()
			p.Trusted = o.Trusted()
		}},
		{name: "production root (test bundles aren't Sigstore's)", want: "log", policy: func(p *release.Policy) { p.Trusted = nil }},
		{name: "statement edited after signing", want: "hash", edit: func(b []byte) []byte {
			var m map[string]any
			json.Unmarshal(b, &m)
			env := m["dsseEnvelope"].(map[string]any)
			pl := env["payload"].(string)
			i := len(pl) / 2
			c := byte('A')
			if pl[i] == 'A' {
				c = 'B'
			}
			env["payload"] = pl[:i] + string(c) + pl[i+1:]
			out, _ := json.Marshal(m)
			return out
		}},
		{name: "not a bundle", want: "bundle", edit: func([]byte) []byte { return []byte(`{"mediaType":"x"}`) }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s, p := setup(t)
			b := bundle(t, s, c.opts)
			if c.policy != nil {
				c.policy(&p)
			}
			if c.edit != nil {
				b = c.edit(b)
			}
			r, err := release.Verify(b, compose[:], p)
			if err == nil {
				t.Fatalf("accepted: %+v", r)
			}
			if !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(c.want)) {
				t.Fatalf("failed for another reason: %v", err)
			}
		})
	}
}

// Another repository (a fork testing its own releases) verifies when its policy pins its name and both ids.
func TestPolicyOtherRepo(t *testing.T) {
	s, p := setup(t)
	b := bundle(t, s, releasetest.Options{Repo: "someone/tacy", RepoID: "5", OwnerID: "6"})
	p.Repo, p.RepoID, p.OwnerID = "someone/tacy", "5", "6"
	if _, err := release.Verify(b, compose[:], p); err != nil {
		t.Fatal(err)
	}
}

func TestLastSeen(t *testing.T) {
	s, p := setup(t)
	b := bundle(t, s, releasetest.Options{Version: "v1.2.3"})
	for seen, want := range map[string]string{
		"":         "",
		"v0.0.1":   "", // below the pinned minimum: fine, the pinned minimum still applies
		"v1.2.2":   "",
		"v1.2.3":   "",
		"v1.2.4":   "older than v1.2.4, the newest this client has seen (rollback protection)",
		"v2.0.0":   "rollback",
		"1.2.3":    "policy: last seen",
		"v1.2.3-x": "policy: last seen",
	} {
		p.LastSeen = seen
		_, err := release.Verify(b, compose[:], p)
		if (want == "") != (err == nil) || (err != nil && !strings.Contains(err.Error(), want)) {
			t.Errorf("last seen %q: want %q, got %v", seen, want, err)
		}
	}
}

func TestPolicyCantLowerMinimum(t *testing.T) {
	s, p := setup(t)
	b := bundle(t, s, releasetest.Options{Version: "v0.0.1"})
	p.MinVersion = "v0.0.0"
	if _, err := release.Verify(b, compose[:], p); err == nil || !strings.Contains(err.Error(), "below the pinned") {
		t.Fatal(err)
	}
}

func TestVerifyAny(t *testing.T) {
	s, p := setup(t)
	bad := bundle(t, s, releasetest.Options{Ref: "refs/heads/main"})
	good := bundle(t, s, releasetest.Options{})
	if _, err := release.VerifyAny([][]byte{bad, good}, compose[:], p); err != nil {
		t.Fatal(err)
	}
	if _, err := release.VerifyAny([][]byte{bad}, compose[:], p); err == nil {
		t.Fatal("accepted")
	}
	if _, err := release.VerifyAny(nil, compose[:], p); err == nil {
		t.Fatal("accepted")
	}
}

func TestVersion(t *testing.T) {
	for _, bad := range []string{"1.0.0", "v1.0", "v1.0.0-rc1", "v01.0.0", "v1.0.0+x", "v1.0.0 "} {
		if _, err := release.ParseVersion(bad); err == nil {
			t.Errorf("%q parsed", bad)
		}
	}
	a, _ := release.ParseVersion("v0.9.10")
	b, _ := release.ParseVersion("v0.10.0")
	if !a.Less(b) || b.Less(a) || a.Less(a) {
		t.Fatal("ordering")
	}
}

// The embedded trusted root parses, and it is Sigstore's public-good instance (Fulcio and Rekor).
func TestEmbeddedTrustedRoot(t *testing.T) {
	tr, err := release.TrustedRoot()
	if err != nil {
		t.Fatal(err)
	}
	if len(tr.FulcioCertificateAuthorities()) == 0 || len(tr.RekorLogs()) == 0 || len(tr.CTLogs()) == 0 {
		t.Fatal("incomplete trusted root")
	}
	raw, _ := os.ReadFile("trusted_root.json")
	if !strings.Contains(string(raw), "https://fulcio.sigstore.dev") || !strings.Contains(string(raw), "rekor.sigstore.dev") {
		t.Fatal("not Sigstore's public-good root")
	}
}

func TestParseAttestations(t *testing.T) {
	got, err := release.ParseAttestations([]byte(`{"attestations":[{"bundle":{"a":1},"repository_id":1},{"bundle":null,"bundle_url":"https://x"}]}`))
	if err != nil || len(got) != 1 || string(got[0]) != `{"a":1}` {
		t.Fatal(got, err)
	}
	if _, err := release.ParseAttestations([]byte(`{"attestations":[]}`)); err == nil {
		t.Fatal("empty accepted")
	}
	if u := release.AttestationsURL("", compose[:]); !strings.HasPrefix(u, "https://api.github.com/repos/tacyhq/tacy/attestations/sha256:") {
		t.Fatal(u)
	}
}

// A real bundle made by GitHub Actions on Sigstore's public-good instance (Tinfoil's router release, recorded in
// internal/tinfoil/testdata) verifies against the embedded trusted root, and the release policy refuses it because
// it isn't this repo's release workflow.
func TestRealGitHubBundle(t *testing.T) {
	raw, err := os.ReadFile("../internal/tinfoil/testdata/router-release.json")
	if err != nil {
		t.Fatal(err)
	}
	var rec struct {
		Repo, Digest string
		Bundle       json.RawMessage
	}
	json.Unmarshal(raw, &rec)
	d, _ := hex.DecodeString(rec.Digest)
	tr, err := release.TrustedRoot()
	if err != nil {
		t.Fatal(err)
	}
	var b sgbundle.Bundle
	if err := b.UnmarshalJSON(rec.Bundle); err != nil {
		t.Fatal(err)
	}
	v, _ := sigverify.NewVerifier(tr, sigverify.WithSignedCertificateTimestamps(1), sigverify.WithTransparencyLog(1),
		sigverify.WithObserverTimestamps(1))
	id, _ := sigverify.NewShortCertificateIdentity(release.Issuer, "", "", "^https://github.com/"+rec.Repo+"/")
	res, err := v.Verify(&b, sigverify.NewPolicy(sigverify.WithArtifactDigest("sha256", d), sigverify.WithCertificateIdentity(id)))
	if err != nil {
		t.Fatalf("embedded root doesn't verify a real bundle: %v", err)
	}
	// GitHub's certificates carry the numeric repository and owner ids the release policy pins.
	if c := res.Signature.Certificate; !regexp.MustCompile(`^[1-9][0-9]*$`).MatchString(c.SourceRepositoryIdentifier) ||
		!regexp.MustCompile(`^[1-9][0-9]*$`).MatchString(c.SourceRepositoryOwnerIdentifier) {
		t.Fatalf("repository ids %q, %q", c.SourceRepositoryIdentifier, c.SourceRepositoryOwnerIdentifier)
	}
	if _, err := release.Verify(rec.Bundle, d, release.Policy{}); err == nil || !strings.Contains(err.Error(), "certificate identity") {
		t.Fatalf("another repo's release: %v", err)
	}
}

// Refreshes trusted_root.json from Sigstore's TUF repository (signed by the TUF root embedded in sigstore-go):
//
//	RECORD=1 go test ./release -run TestRecordTrustedRoot
//
// Needed when Sigstore adds or rotates a Fulcio CA, Rekor log, CT log or timestamp authority; review the diff.
func TestRecordTrustedRoot(t *testing.T) {
	if os.Getenv("RECORD") == "" {
		t.Skip("set RECORD=1 to refresh trusted_root.json")
	}
	tr, err := root.FetchTrustedRootWithOptions(tuf.DefaultOptions().WithDisableLocalCache())
	if err != nil {
		t.Fatal(err)
	}
	j, err := tr.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	var v any
	json.Unmarshal(j, &v)
	out, _ := json.MarshalIndent(v, "", " ")
	if err := os.WriteFile("trusted_root.json", append(out, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
}
