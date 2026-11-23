// Package gcetcb checks that a TDX MRTD is Google Compute Engine's firmware. For every TDX firmware build Google
// publishes a launch endorsement, gs://gce_tcb_integrity/ovmf_x64_csm/tdx/<MRTD hex>.binarypb, that lists the MRTD
// the build gives for each legal VM configuration (RAM size, early accept), with the build's security version (SVN),
// date, source commit and the SHA-384 of the firmware binary. It is signed (RSA-PSS, SHA-256) by a key whose
// certificate is signed by Google's GCE-cc-tcb-root.
//
// Trust: the root is compiled in (GCE-cc-tcb-root_1.crt, from https://pki.goog/cloud_integrity/GCE-cc-tcb-root_1.crt,
// sha256 e876bc69…b0f18c, valid until 2048). The endorsement itself is fetched (Check) or supplied (Verify) and then
// checked offline against that root, so whoever serves it (Google's bucket, a relay, a cache, a test file) can only
// withhold it, never forge one. What is checked is what google/gce-tcb-verifier's verify.Endorsement checks for TDX
// (the format is its proto/endorsement.proto, Apache-2.0): the signer certificate chains to the root, the
// signature over the serialized golden measurement, a timestamp and provenance (a changelist or a commit); plus that
// the signed list holds the quote's MRTD, which the URL alone doesn't prove.
//
// The messages are decoded with protowire, so the verifier (also compiled to WebAssembly, and vendored by the key
// holders) takes no new dependency.
package gcetcb

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	_ "embed"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/google/go-tdx-guest/verify/trust"
	"google.golang.org/protobuf/encoding/protowire"
)

// URLPrefix is where Google publishes the TDX endorsements, one object per MRTD (lower-case hex).
const URLPrefix = "https://storage.googleapis.com/gce_tcb_integrity/ovmf_x64_csm/tdx/"

// SignerName is the common name of the certificates Google signs TDX endorsements with (one per build).
const SignerName = "GCE-uefi-signer"

// MaxSize caps an endorsement (Google's are about 5 KB), so a relay or cache can't make a verifier read without end.
const MaxSize = 64 << 10

// RootSHA256 is the sha256 of the compiled-in root certificate (DER), as pki.goog serves it.
const RootSHA256 = "e876bc6978bf4f3da445f98a0a82363c8c0bae5a1fc033c6df65846a6cb0f18c"

//go:embed GCE-cc-tcb-root_1.crt
var rootDER []byte

var root *x509.Certificate

func init() {
	sum := sha256.Sum256(rootDER)
	if hex.EncodeToString(sum[:]) != RootSHA256 {
		panic("gcetcb: the embedded GCE-cc-tcb-root isn't the pinned one")
	}
	var err error
	if root, err = x509.ParseCertificate(rootDER); err != nil {
		panic("gcetcb: " + err.Error())
	}
}

// URL is the endorsement object for mrtd.
func URL(mrtd []byte) string { return URLPrefix + hex.EncodeToString(mrtd) + ".binarypb" }

// Measurement is one MRTD a firmware build gives, for one VM configuration.
type Measurement struct {
	RAMGiB      uint32
	EarlyAccept bool
	MRTD        []byte
}

// Firmware is what a verified endorsement says about one firmware build.
type Firmware struct {
	SVN          uint32    // Google's security version number of this firmware on TDX
	Built        time.Time // the endorsement's timestamp
	ClSpec       uint64    // the changelist it was built from (0 if a commit is given)
	Commit       string    // hex of the source commit (may be empty if ClSpec is set)
	UEFISHA384   string    // hex of the SHA-384 of the firmware binary
	Signer       string    // the signing certificate's subject common name
	SignerExpiry time.Time // the signing certificate's NotAfter: after it, this endorsement no longer verifies
	Measurements []Measurement
}

// Lists returns the configuration whose MRTD is mrtd, if the signed list holds it.
func (f *Firmware) Lists(mrtd []byte) (Measurement, bool) {
	for _, m := range f.Measurements {
		if bytes.Equal(m.MRTD, mrtd) {
			return m, true
		}
	}
	return Measurement{}, false
}

// Provenance is the build's source in one line, for facts and errors.
func (f *Firmware) Provenance() string {
	if f.Commit != "" {
		return "commit " + f.Commit
	}
	return fmt.Sprintf("cl %d", f.ClSpec)
}

// Verify checks a serialized VMLaunchEndorsement against the compiled-in root at now (zero = time.Now()) and
// returns the firmware it endorses. It doesn't look at any MRTD; Check does.
func Verify(raw []byte, now time.Time) (*Firmware, error) {
	if now.IsZero() {
		now = time.Now()
	}
	golden, sig, err := parseLaunch(raw)
	if err != nil {
		return nil, fmt.Errorf("endorsement: %w", err)
	}
	g, err := parseGolden(golden)
	if err != nil {
		return nil, fmt.Errorf("endorsement's golden measurement: %w", err)
	}
	if g.timestamp == nil {
		return nil, errors.New("endorsement has no timestamp")
	}
	if g.clSpec == 0 && len(g.commit) == 0 {
		return nil, errors.New("endorsement has no provenance (changelist or commit)")
	}
	if len(g.cert) == 0 {
		return nil, errors.New("endorsement has no signer certificate")
	}
	cert, err := x509.ParseCertificate(g.cert)
	if err != nil {
		return nil, fmt.Errorf("endorsement signer certificate: %w", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	// Stricter than gce-tcb-verifier (review L3): the signer is Google's UEFI signer, a signing-only leaf.
	if cert.Subject.CommonName != SignerName || cert.IsCA || cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return nil, fmt.Errorf("endorsement signer %q isn't a %s signing certificate", cert.Subject.CommonName, SignerName)
	}
	// As gce-tcb-verifier: the signer is issued by the root itself (no intermediates), at now.
	if _, err := cert.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: now,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		return nil, fmt.Errorf("endorsement signer %q isn't certified by GCE-cc-tcb-root: %w", cert.Subject.CommonName, err)
	}
	if err := cert.CheckSignature(x509.SHA256WithRSAPSS, golden, sig); err != nil {
		return nil, fmt.Errorf("endorsement signature: %w", err)
	}
	if g.tdx == nil {
		return nil, errors.New("endorsement has no TDX section")
	}
	f := &Firmware{SVN: g.tdx.svn, Built: *g.timestamp, ClSpec: g.clSpec, Commit: hex.EncodeToString(g.commit),
		UEFISHA384: hex.EncodeToString(g.digest), Signer: cert.Subject.CommonName, SignerExpiry: cert.NotAfter, Measurements: g.tdx.measurements}
	return f, nil
}

// Check fetches mrtd's endorsement with getter (nil = net/http), verifies it (Verify) and requires that its signed
// list holds mrtd. A missing object (Google never endorsed this MRTD) is an error like any other.
func Check(ctx context.Context, getter trust.HTTPSGetter, mrtd []byte, now time.Time) (*Firmware, Measurement, error) {
	if len(mrtd) != 48 {
		return nil, Measurement{}, fmt.Errorf("MRTD is %d bytes, want 48", len(mrtd))
	}
	if getter == nil {
		getter = limitedGetter{}
	}
	_, raw, err := trust.GetWith(ctx, getter, URL(mrtd))
	if err == nil && len(raw) > MaxSize {
		err = fmt.Errorf("%d bytes, more than %d", len(raw), MaxSize)
	}
	if err != nil {
		return nil, Measurement{}, fmt.Errorf("no Google endorsement for MRTD %s…: %v", hex.EncodeToString(mrtd[:8]), err)
	}
	f, err := Verify(raw, now)
	if err != nil {
		return nil, Measurement{}, err
	}
	m, ok := f.Lists(mrtd)
	if !ok {
		return nil, Measurement{}, fmt.Errorf("Google's signed endorsement (firmware SVN %d, %s) doesn't list MRTD %s…",
			f.SVN, f.Built.UTC().Format("2006-01-02"), hex.EncodeToString(mrtd[:8]))
	}
	return f, m, nil
}

// limitedGetter is the default fetch: net/http with a 20 s deadline and at most MaxSize+1 bytes read.
type limitedGetter struct{}

func (limitedGetter) Get(url string) (map[string][]string, []byte, error) {
	return limitedGetter{}.GetContext(context.Background(), url)
}

func (limitedGetter) GetContext(ctx context.Context, url string) (map[string][]string, []byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("%s: status %d", url, resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, MaxSize+1))
	return resp.Header, b, err
}

// --- protobuf (proto3) decoding of cloud_vmm_proto.VMLaunchEndorsement, VMGoldenMeasurement and VMTdx ---

type golden struct {
	timestamp *time.Time
	clSpec    uint64
	commit    []byte
	cert      []byte
	digest    []byte
	tdx       *tdxSection
}

type tdxSection struct {
	svn          uint32
	measurements []Measurement
}

// fields walks one message: each field's number, wire type and value (varint, or bytes for length-delimited).
// Other wire types (fixed32/64, groups) aren't used by these messages and are refused.
func fields(b []byte, f func(num protowire.Number, typ protowire.Type, v uint64, bs []byte) error) error {
	for len(b) > 0 {
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			return protowire.ParseError(n)
		}
		b = b[n:]
		var v uint64
		var bs []byte
		switch typ {
		case protowire.VarintType:
			v, n = protowire.ConsumeVarint(b)
		case protowire.BytesType:
			bs, n = protowire.ConsumeBytes(b)
		default:
			return fmt.Errorf("field %d: unexpected wire type %d", num, typ)
		}
		if n < 0 {
			return protowire.ParseError(n)
		}
		b = b[n:]
		if err := f(num, typ, v, bs); err != nil {
			return err
		}
	}
	return nil
}

func want(num protowire.Number, typ, w protowire.Type) error {
	if typ != w {
		return fmt.Errorf("field %d: wire type %d, want %d", num, typ, w)
	}
	return nil
}

func parseLaunch(b []byte) (golden, sig []byte, err error) {
	err = fields(b, func(num protowire.Number, typ protowire.Type, _ uint64, bs []byte) error {
		switch num {
		case 1:
			golden = bs
			return want(num, typ, protowire.BytesType)
		case 2:
			sig = bs
			return want(num, typ, protowire.BytesType)
		}
		return nil
	})
	if err == nil && (len(golden) == 0 || len(sig) == 0) {
		err = errors.New("no signed golden measurement or no signature")
	}
	return golden, sig, err
}

func parseGolden(b []byte) (*golden, error) {
	g := &golden{}
	err := fields(b, func(num protowire.Number, typ protowire.Type, v uint64, bs []byte) error {
		switch num {
		case 1: // google.protobuf.Timestamp
			if err := want(num, typ, protowire.BytesType); err != nil {
				return err
			}
			var sec, nsec uint64
			if err := fields(bs, func(n protowire.Number, t protowire.Type, v uint64, _ []byte) error {
				switch n {
				case 1:
					sec = v
					return want(n, t, protowire.VarintType)
				case 2:
					nsec = v
					return want(n, t, protowire.VarintType)
				}
				return nil
			}); err != nil {
				return fmt.Errorf("timestamp: %w", err)
			}
			ts := time.Unix(int64(sec), int64(int32(nsec))).UTC()
			g.timestamp = &ts
		case 2:
			g.clSpec = v
			return want(num, typ, protowire.VarintType)
		case 3:
			g.commit = bs
			return want(num, typ, protowire.BytesType)
		case 4:
			g.cert = bs
			return want(num, typ, protowire.BytesType)
		case 5:
			g.digest = bs
			return want(num, typ, protowire.BytesType)
		case 8:
			if err := want(num, typ, protowire.BytesType); err != nil {
				return err
			}
			t, err := parseTDX(bs)
			if err != nil {
				return fmt.Errorf("tdx: %w", err)
			}
			g.tdx = t
		}
		return nil // 6 (ca_bundle), 7 (sev_snp) and unknown fields: not used
	})
	return g, err
}

func parseTDX(b []byte) (*tdxSection, error) {
	t := &tdxSection{}
	err := fields(b, func(num protowire.Number, typ protowire.Type, v uint64, bs []byte) error {
		switch num {
		case 1:
			t.svn = uint32(v)
			return want(num, typ, protowire.VarintType)
		case 2:
			if err := want(num, typ, protowire.BytesType); err != nil {
				return err
			}
			var m Measurement
			if err := fields(bs, func(n protowire.Number, ty protowire.Type, v uint64, bs []byte) error {
				switch n {
				case 1:
					m.RAMGiB = uint32(v)
					return want(n, ty, protowire.VarintType)
				case 2:
					m.EarlyAccept = v != 0
					return want(n, ty, protowire.VarintType)
				case 3:
					m.MRTD = bs
					return want(n, ty, protowire.BytesType)
				}
				return nil
			}); err != nil {
				return err
			}
			if len(m.MRTD) != 48 {
				return fmt.Errorf("measurement MRTD is %d bytes", len(m.MRTD))
			}
			t.measurements = append(t.measurements, m)
		}
		return nil
	})
	return t, err
}

// Describe is f in one line, for facts.
func (f *Firmware) Describe(m Measurement) string {
	cfg := "any RAM size"
	if m.RAMGiB > 0 {
		cfg = fmt.Sprintf("%d GiB", m.RAMGiB)
	}
	if m.EarlyAccept {
		cfg += ", early accept"
	}
	return fmt.Sprintf("Google TDX firmware SVN %d, built %s, %s, UEFI sha384 %s, signed by %s (%s)", f.SVN,
		f.Built.UTC().Format("2006-01-02"), f.Provenance(), f.UEFISHA384[:min(16, len(f.UEFISHA384))]+"…", f.Signer, cfg)
}
