// Package tinfoil verifies a Tinfoil model router enclave with our own code on Apache-2.0 libraries (Tinfoil's
// Go verifier, which tinfoil-go imports, is AGPL-3.0), then returns an http.Client that EHBP-encrypts every request
// body to the enclave's attested HPKE key (encrypted-http-body-protocol, MIT).
//
// The checks follow Tinfoil's published verifier (the Apache-2.0 @tinfoilsh/verifier JS package):
//
//  1. The enclave's attestation (/.well-known/tinfoil-attestation, format sev-snp-guest/v2) is an AMD SEV-SNP
//     report signed by a VCEK that chains to AMD's root (go-sev-guest, VCEK from AMD KDS, CRL checked), with debug
//     and the migration agent off.
//  2. The latest release of tinfoilsh/confidential-model-router is signed with Sigstore by a GitHub Actions workflow
//     of that repo running on a tag (sigstore-go: Fulcio chain, SCT, Rekor entry, identity policy), and its in-toto
//     statement covers the release digest.
//  3. The report's launch measurement equals the release's snp_measurement.
//  4. REPORT_DATA = TLS key fingerprint (32 bytes) || HPKE public key (32 bytes); requests are encrypted to that key.
package tinfoil

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/google/go-sev-guest/abi"
	sevvalidate "github.com/google/go-sev-guest/validate"
	sevverify "github.com/google/go-sev-guest/verify"
	"github.com/google/go-sev-guest/verify/trust"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/tuf"
	sigverify "github.com/sigstore/sigstore-go/pkg/verify"
	ehbpclient "github.com/tinfoilsh/encrypted-http-body-protocol/client"
	ehbpidentity "github.com/tinfoilsh/encrypted-http-body-protocol/identity"
)

const (
	DefaultEnclave = "inference.tinfoil.sh"
	DefaultRepo    = "tinfoilsh/confidential-model-router"

	snpV2           = "https://tinfoil.sh/predicate/sev-snp-guest/v2"
	multiplatformV1 = "https://tinfoil.sh/predicate/snp-tdx-multiplatform/v1"
	githubIssuer    = "https://token.actions.githubusercontent.com"
	// GitHub's API through Tinfoil's caching proxy (as their SDKs do): avoids GitHub's 60/hour anonymous limit.
	// Nothing fetched from it is trusted: the release is checked with Sigstore.
	githubProxy = "https://github-proxy.tinfoil.sh"
	amdKDS      = "https://kdsintf.amd.com"
	kdsProxy    = "https://kds-proxy.tinfoil.sh" // fallback mirror of AMD KDS; certificates are checked against AMD's root
)

// Verified is the result of one verification.
type Verified struct {
	Enclave     string
	Repo        string
	Release     string // tag the Sigstore certificate was issued for
	Digest      string // release digest (sha256 of the in-toto subject)
	Measurement string // SEV-SNP launch measurement (hex)
	TLSKeyFP    string // sha256 of the enclave's TLS public key (hex), from REPORT_DATA
	HPKEKey     string // X25519 HPKE public key (hex), from REPORT_DATA
	At          time.Time
}

var web = &http.Client{Timeout: 30 * time.Second}

func get(ctx context.Context, url string) ([]byte, error) {
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	req.Header.Set("User-Agent", "Tacy/1.0")
	res, err := web.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	b, err := io.ReadAll(io.LimitReader(res.Body, 8<<20))
	if err != nil {
		return nil, err
	}
	if res.StatusCode != 200 {
		return nil, fmt.Errorf("GET %s: %d", url, res.StatusCode)
	}
	return b, nil
}

// kdsGetter fetches VCEK certificates and CRLs from AMD, falling back to Tinfoil's mirror.
type kdsGetter struct{ ctx context.Context }

func (g kdsGetter) Get(url string) ([]byte, error) {
	b, err := get(g.ctx, url)
	if err != nil && strings.HasPrefix(url, amdKDS) {
		return get(g.ctx, kdsProxy+strings.TrimPrefix(url, amdKDS))
	}
	return b, err
}

var _ trust.HTTPSGetter = kdsGetter{}

// SNPReport verifies an attestation document's SEV-SNP report and returns it as raw fields.
func SNPReport(ctx context.Context, format, body string) (measurement, reportData []byte, err error) {
	if format != snpV2 {
		return nil, nil, fmt.Errorf("unsupported attestation format %q", format)
	}
	gz, err := base64.StdEncoding.DecodeString(body)
	if err != nil {
		return nil, nil, fmt.Errorf("attestation body: %w", err)
	}
	zr, err := gzip.NewReader(bytes.NewReader(gz))
	if err != nil {
		return nil, nil, fmt.Errorf("attestation body: %w", err)
	}
	raw, err := io.ReadAll(io.LimitReader(zr, 1<<16))
	if err != nil {
		return nil, nil, fmt.Errorf("attestation body: %w", err)
	}
	report, err := abi.ReportToProto(raw)
	if err != nil {
		return nil, nil, fmt.Errorf("parse SEV-SNP report: %w", err)
	}
	opts := sevverify.DefaultOptions()
	opts.CheckRevocations = true
	opts.Getter = kdsGetter{ctx}
	att, err := sevverify.GetAttestationFromReportContext(ctx, report, opts)
	if err != nil {
		return nil, nil, fmt.Errorf("VCEK: %w", err)
	}
	if err := sevverify.SnpAttestationContext(ctx, att, opts); err != nil {
		return nil, nil, fmt.Errorf("SEV-SNP signature chain: %w", err)
	}
	vmpl := 0
	if err := sevvalidate.SnpAttestation(att, &sevvalidate.Options{
		GuestPolicy: abi.SnpPolicy{SMT: true}, // the most we accept: no debug, no migration agent
		VMPL:        &vmpl,
	}); err != nil {
		return nil, nil, fmt.Errorf("SEV-SNP policy: %w", err)
	}
	return report.GetMeasurement(), report.GetReportData(), nil
}

var (
	trustedRoot   root.TrustedMaterial
	trustedRootMu sync.Mutex
)

// sigstoreRoot fetches Sigstore's public-good trusted root through TUF (signed by Sigstore's embedded TUF root),
// in memory only.
func sigstoreRoot() (root.TrustedMaterial, error) {
	trustedRootMu.Lock()
	defer trustedRootMu.Unlock()
	if trustedRoot != nil {
		return trustedRoot, nil
	}
	tr, err := root.FetchTrustedRootWithOptions(tuf.DefaultOptions().WithDisableLocalCache())
	if err != nil {
		return nil, fmt.Errorf("sigstore trusted root (TUF): %w", err)
	}
	trustedRoot = tr
	return tr, nil
}

var tagRef = regexp.MustCompile(`^refs/tags/`)

// Release verifies a Sigstore bundle for repo at digest and returns the release's SNP measurement and tag.
func Release(bundleJSON []byte, digest, repo string, tr root.TrustedMaterial) (measurement, tag string, err error) {
	var b bundle.Bundle
	if err := b.UnmarshalJSON(bundleJSON); err != nil {
		return "", "", fmt.Errorf("sigstore bundle: %w", err)
	}
	v, err := sigverify.NewVerifier(tr, sigverify.WithSignedCertificateTimestamps(1),
		sigverify.WithTransparencyLog(1), sigverify.WithObserverTimestamps(1))
	if err != nil {
		return "", "", err
	}
	id, err := sigverify.NewShortCertificateIdentity(githubIssuer, "", "",
		"^https://github.com/"+regexp.QuoteMeta(repo)+"/")
	if err != nil {
		return "", "", err
	}
	d, err := hex.DecodeString(digest)
	if err != nil || len(d) != 32 {
		return "", "", fmt.Errorf("bad release digest %q", digest)
	}
	res, err := v.Verify(&b, sigverify.NewPolicy(sigverify.WithArtifactDigest("sha256", d),
		sigverify.WithCertificateIdentity(id)))
	if err != nil {
		return "", "", fmt.Errorf("sigstore verification: %w", err)
	}
	cert := res.Signature.Certificate
	if cert == nil || cert.SourceRepositoryURI != "https://github.com/"+repo || !tagRef.MatchString(cert.GithubWorkflowRef) {
		return "", "", fmt.Errorf("signing certificate isn't from a tagged workflow of %s", repo)
	}
	st := res.Statement
	if st == nil || st.PredicateType != multiplatformV1 {
		return "", "", fmt.Errorf("unexpected predicate type")
	}
	snp := st.Predicate.GetFields()["snp_measurement"].GetStringValue()
	if snp == "" {
		return "", "", fmt.Errorf("release has no snp_measurement")
	}
	return snp, strings.TrimPrefix(cert.GithubWorkflowRef, "refs/tags/"), nil
}

// Verify checks enclave against the latest signed release of repo.
func Verify(ctx context.Context, enclave, repo string) (*Verified, error) {
	var doc struct {
		Format string `json:"format"`
		Body   string `json:"body"`
	}
	raw, err := get(ctx, "https://"+enclave+"/.well-known/tinfoil-attestation")
	if err == nil {
		err = json.Unmarshal(raw, &doc)
	}
	if err != nil {
		return nil, fmt.Errorf("enclave attestation: %w", err)
	}
	measurement, reportData, err := SNPReport(ctx, doc.Format, doc.Body)
	if err != nil {
		return nil, err
	}

	var rel struct {
		Tag string `json:"tag_name"`
	}
	raw, err = get(ctx, githubProxy+"/repos/"+repo+"/releases/latest")
	if err == nil {
		err = json.Unmarshal(raw, &rel)
	}
	if err != nil || rel.Tag == "" {
		return nil, fmt.Errorf("latest release: %v", err)
	}
	hash, err := get(ctx, githubProxy+"/"+repo+"/releases/download/"+rel.Tag+"/tinfoil.hash")
	if err != nil {
		return nil, fmt.Errorf("release digest: %w", err)
	}
	digest := strings.TrimSpace(string(hash))
	var atts struct {
		Attestations []struct {
			Bundle json.RawMessage `json:"bundle"`
		} `json:"attestations"`
	}
	raw, err = get(ctx, githubProxy+"/repos/"+repo+"/attestations/sha256:"+digest)
	if err == nil {
		err = json.Unmarshal(raw, &atts)
	}
	if err != nil || len(atts.Attestations) == 0 {
		return nil, fmt.Errorf("release attestation: %v", err)
	}
	tr, err := sigstoreRoot()
	if err != nil {
		return nil, err
	}
	want, tag, err := Release(atts.Attestations[0].Bundle, digest, repo, tr)
	if err != nil {
		return nil, err
	}
	if tag != rel.Tag {
		return nil, fmt.Errorf("release %s was signed from tag %s", rel.Tag, tag)
	}
	if got := hex.EncodeToString(measurement); got != want {
		return nil, fmt.Errorf("enclave measurement %s isn't release %s's %s", got, tag, want)
	}
	return &Verified{Enclave: enclave, Repo: repo, Release: tag, Digest: digest, Measurement: want,
		TLSKeyFP: hex.EncodeToString(reportData[:32]), HPKEKey: hex.EncodeToString(reportData[32:64]),
		At: time.Now().UTC()}, nil
}

// Client is a verified connection to a Tinfoil router: requests go only to the verified host, with bodies
// encrypted to its attested HPKE key. It re-verifies after a key-config error (key rotation) or every MaxAge.
type Client struct {
	Enclave, Repo string
	MaxAge        time.Duration

	mu   sync.Mutex
	v    *Verified
	http *http.Client
}

func NewClient(enclave, repo string) *Client {
	if enclave == "" {
		enclave = DefaultEnclave
	}
	if repo == "" {
		repo = DefaultRepo
	}
	return &Client{Enclave: enclave, Repo: repo, MaxAge: time.Hour}
}

// Current returns the verified state and its HTTP client, verifying first when needed.
func (c *Client) Current(ctx context.Context) (*Verified, *http.Client, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.v != nil && time.Since(c.v.At) < c.MaxAge {
		return c.v, c.http, nil
	}
	v, err := Verify(ctx, c.Enclave, c.Repo)
	if err != nil {
		return nil, nil, err
	}
	key, _ := hex.DecodeString(v.HPKEKey)
	id, err := ehbpidentity.FromPublicKeyBytes(key)
	if err != nil {
		return nil, nil, fmt.Errorf("attested HPKE key: %w", err)
	}
	tr, err := ehbpclient.NewTransportWithIdentity(id, ehbpclient.WithHTTPClient(&http.Client{Timeout: 10 * time.Minute}))
	if err != nil {
		return nil, nil, err
	}
	c.v, c.http = v, &http.Client{Transport: hostOnly{host: v.Enclave, next: tr}}
	return c.v, c.http, nil
}

// Invalidate forces re-verification on the next request (after a key-config error).
func (c *Client) Invalidate() {
	c.mu.Lock()
	c.v = nil
	c.mu.Unlock()
}

// hostOnly refuses any host other than the verified enclave, so the API key header can't go elsewhere.
type hostOnly struct {
	host string
	next http.RoundTripper
}

func (h hostOnly) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.Scheme != "https" || r.URL.Host != h.host {
		return nil, fmt.Errorf("refusing request to %s://%s: bound to %s", r.URL.Scheme, r.URL.Host, h.host)
	}
	return h.next.RoundTrip(r)
}

// Fingerprint is a short id for logs and UI.
func (v *Verified) Fingerprint() string {
	s := sha256.Sum256([]byte(v.Measurement + v.HPKEKey))
	return hex.EncodeToString(s[:6])
}
