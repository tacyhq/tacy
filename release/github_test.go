package release_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"

	sgbundle "github.com/sigstore/sigstore-go/pkg/bundle"
	sigverify "github.com/sigstore/sigstore-go/pkg/verify"

	"github.com/tacyhq/tacy/release"
)

// testdata/github-attestations-cli.json is GitHub's attestations API response for gh_2.102.0_linux_amd64.tar.gz
// (cli/cli, a public repository), recorded 2026-10-16: both entries have "bundle": null and only a bundle_url
// (the storage access signature in the URLs is replaced by sig=REDACTED). testdata/cli-*.json.sn are what those
// URLs served (application/x-snappy). 51331539 is "initiator": "user" (actions/attest-build-provenance on
// Sigstore's public-good instance, what our release workflow makes); 51331930 is "initiator": "github", GitHub's
// own immutable-release attestation on its private Sigstore instance.
const cliDigest = "bb766f710eef8ede859c18578c72c327597cd4c8a85b06001b1f3843c6019386"

var cliBlobs = map[string]string{
	"https://tmaproduction.blob.core.windows.net/attestations/212613049/2026/09/30/51331930.json.sn": "testdata/cli-51331930.json.sn",
	"https://tmaproduction.blob.core.windows.net/attestations/212613049/2026/09/30/51331539.json.sn": "testdata/cli-51331539.json.sn",
}

func read(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

type route struct {
	status int
	body   []byte
	header http.Header
}

// fakeGitHub serves routes by URL without query; anything else is a 404. No network.
type fakeGitHub struct {
	routes map[string]route
	got    []string
}

func (f *fakeGitHub) RoundTrip(r *http.Request) (*http.Response, error) {
	u := r.URL.Scheme + "://" + r.URL.Host + r.URL.Path
	f.got = append(f.got, u)
	rt, ok := f.routes[u]
	if !ok {
		rt = route{status: 404, body: []byte(`{"message":"Not Found"}`)}
	}
	h := rt.header
	if h == nil {
		h = http.Header{}
	}
	return &http.Response{StatusCode: rt.status, Header: h, Body: io.NopCloser(bytes.NewReader(rt.body)), Request: r}, nil
}

func recordedGitHub(t *testing.T) *fakeGitHub {
	d, _ := hex.DecodeString(cliDigest)
	f := &fakeGitHub{routes: map[string]route{
		release.AttestationsURL("cli/cli", d): {status: 200, body: read(t, "testdata/github-attestations-cli.json")},
	}}
	for u, path := range cliBlobs {
		f.routes[u] = route{status: 200, body: read(t, path)}
	}
	return f
}

// The recorded bundle_url blobs decode to bundles. The "user" one (actions/attest-build-provenance, like our
// releases) verifies on Sigstore's public-good instance with the embedded trusted root, and the release policy
// then refuses it as not this repository's release. The "github" one is GitHub's own release attestation
// (immutable releases), signed by GitHub's private Sigstore instance with no Rekor entry: refused outright.
func TestBundleURLRecorded(t *testing.T) {
	d, _ := hex.DecodeString(cliDigest)
	tr, err := release.TrustedRoot()
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range cliBlobs {
		b, err := release.DecodeBundleBlob(read(t, path))
		if err != nil {
			t.Fatal(path, err)
		}
		if strings.Contains(path, "51331930") {
			if _, err := release.Verify(b, d, release.Policy{}); err == nil || !strings.Contains(err.Error(), "transparency log") {
				t.Fatalf("GitHub-instance bundle: %v", err)
			}
			continue
		}
		var sb sgbundle.Bundle
		if err := sb.UnmarshalJSON(b); err != nil {
			t.Fatal(path, err)
		}
		v, _ := sigverify.NewVerifier(tr, sigverify.WithSignedCertificateTimestamps(1), sigverify.WithTransparencyLog(1),
			sigverify.WithObserverTimestamps(1))
		id, _ := sigverify.NewShortCertificateIdentity(release.Issuer, "", "", "^https://github.com/cli/cli/")
		res, err := v.Verify(&sb, sigverify.NewPolicy(sigverify.WithArtifactDigest("sha256", d), sigverify.WithCertificateIdentity(id)))
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		if c := res.Signature.Certificate; c.SourceRepositoryIdentifier != "212613049" {
			t.Fatalf("%s: repository id %q", path, c.SourceRepositoryIdentifier)
		}
		if _, err := release.Verify(b, d, release.Policy{}); err == nil || !strings.Contains(err.Error(), "certificate identity") {
			t.Fatalf("%s: another repo's bundle: %v", path, err)
		}
		// Plain JSON passes through unchanged.
		if again, err := release.DecodeBundleBlob(b); err != nil || !bytes.Equal(again, b) {
			t.Fatal("JSON bundle changed")
		}
	}
}

func TestFetchBundlesFollowsBundleURL(t *testing.T) {
	d, _ := hex.DecodeString(cliDigest)
	f := recordedGitHub(t)
	bundles, err := release.FetchBundles(context.Background(), &http.Client{Transport: f}, "cli/cli", d)
	if err != nil {
		t.Fatal(err)
	}
	if len(bundles) != 2 || len(f.got) != 3 {
		t.Fatalf("%d bundles, requests %v", len(bundles), f.got)
	}
	for _, b := range bundles {
		if !bytes.HasPrefix(b, []byte(`{"mediaType":"application/vnd.dev.sigstore.bundle`)) {
			t.Fatalf("not a bundle: %.80s", b)
		}
	}
	// The same bundles from a response with them inline: what a relay that resolves bundle_url sends.
	inline := []byte(`{"attestations":[{"bundle":` + string(bundles[0]) + `},{"bundle":` + string(bundles[1]) + `}]}`)
	got, err := release.ParseAttestations(inline)
	if err != nil || len(got) != 2 || !bytes.Equal(got[0], bundles[0]) {
		t.Fatal("inline", err)
	}
	f.got = nil
	if got, err = release.ResolveAttestations(context.Background(), &http.Client{Transport: f}, inline); err != nil ||
		len(got) != 2 || len(f.got) != 0 {
		t.Fatal("inline bundles shouldn't be fetched", err, f.got)
	}
	// No release for a digest: GitHub answers 404.
	if _, err := release.FetchBundles(context.Background(), &http.Client{Transport: f}, "", d); err == nil ||
		!strings.Contains(err.Error(), "HTTP 404") {
		t.Fatal(err)
	}
}

func TestBundleURLRefused(t *testing.T) {
	blob := read(t, "testdata/cli-51331930.json.sn")
	good := "https://tmaproduction.blob.core.windows.net/attestations/1.json.sn"
	cases := []struct {
		name, url, want string
		r               route
	}{
		{"plain http", "http://tmaproduction.blob.core.windows.net/a.json.sn", "isn't https", route{}},
		{"another host", "https://attacker.example/a.json.sn", "isn't https", route{}},
		{"local network", "https://127.0.0.1/a.json.sn", "isn't https", route{}},
		{"suffix trick", "https://x.blob.core.windows.net.attacker.example/a", "isn't https", route{}},
		{"userinfo", "https://u:p@tmaproduction.blob.core.windows.net/a", "isn't https", route{}},
		{"other port", "https://tmaproduction.blob.core.windows.net:8443/a", "isn't https", route{}},
		{"expired link", good, "HTTP 403", route{status: 403, body: []byte("AuthenticationFailed")}},
		{"redirect isn't followed", good, "HTTP 302", route{status: 302, header: http.Header{"Location": {"https://attacker.example/"}}}},
		{"over the size limit", good, "limit", route{status: 200, body: make([]byte, release.MaxBundleBlob+1)}},
		{"truncated blob", good, "snappy", route{status: 200, body: blob[:len(blob)/2]}},
		{"not snappy", good, "snappy", route{status: 200, body: []byte("\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff")}},
		{"decodes to non-JSON", good, "isn't JSON", route{status: 200, body: []byte{3, 0x08, 'a', 'b', 'c'}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := &fakeGitHub{routes: map[string]route{good: c.r}}
			_, err := release.FetchBundleURL(context.Background(), &http.Client{Transport: f}, c.url+"?sig=secret")
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("want %q, got %v", c.want, err)
			}
			if strings.Contains(err.Error(), "secret") {
				t.Fatal("error leaks the access signature")
			}
			if c.r.status == 0 && len(f.got) != 0 {
				t.Fatal("refused URL was requested")
			}
		})
	}
}

func TestResolveAttestationsPartial(t *testing.T) {
	f := &fakeGitHub{routes: map[string]route{}}
	c := &http.Client{Transport: f}
	// One inline bundle and one bundle_url that fails: the inline one is returned.
	got, err := release.ResolveAttestations(context.Background(), c,
		[]byte(`{"attestations":[{"bundle":null,"bundle_url":"https://x.blob.core.windows.net/gone"},{"bundle":{"a":1}}]}`))
	if err != nil || len(got) != 1 || string(got[0]) != `{"a":1}` {
		t.Fatal(got, err)
	}
	// Nothing usable: the first error.
	for body, want := range map[string]string{
		`{"attestations":[{"bundle":null,"bundle_url":"https://x.blob.core.windows.net/gone"}]}`: "HTTP 404",
		`{"attestations":[{"bundle":null}]}`:                                                     "neither bundle nor bundle_url",
		`{"attestations":[]}`:                                                                    "no attestation",
		`not json`:                                                                               "attestations response",
	} {
		if _, err := release.ResolveAttestations(context.Background(), c, []byte(body)); err == nil ||
			!strings.Contains(err.Error(), want) {
			t.Errorf("%s: want %q, got %v", body, want, err)
		}
	}
}
