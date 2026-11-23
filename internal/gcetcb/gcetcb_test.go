package gcetcb

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protowire"
)

// testdata/<MRTD>.binarypb are Google's TDX launch endorsements as storage.googleapis.com served them on
// 2026-11-21 (URL(mrtd)): f21e6b48… is the firmware every GCP quote of 2026-11-20 and -21 carries, c1ee9c16… the
// one an earlier Google Cloud test VM's quote carried on 2026-10-13 (Google updated its firmware in between).
const (
	mrtdNov = "f21e6b48743fe14c2d090078ca1197f09ae4c99438677f2c79901ef80e2aeefe2f9a7eb6e3eb3b5047c4f1511731e5d3"
	mrtdOct = "c1ee9c16e3afc506cfe042c5b846a368528f3b37618eafb27469bc114cf914e9222c91618470e7f2b28ac360968270a5"
)

// when is a time both endorsements' signer certificates are valid at (recorded 2026-11-21).
var when = time.Date(2026, 11, 21, 5, 0, 0, 0, time.UTC)

func endorsement(t *testing.T, mrtd string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/" + mrtd + ".binarypb")
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func unhex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// files serves the recorded endorsements by URL, or serves serve for every URL; it counts calls.
type files struct {
	t     *testing.T
	serve []byte
	calls int
}

func (f *files) Get(url string) (map[string][]string, []byte, error) {
	f.calls++
	if f.serve != nil {
		return nil, f.serve, nil
	}
	name, ok := strings.CutPrefix(url, URLPrefix)
	if !ok {
		return nil, nil, errors.New("not Google's bucket: " + url)
	}
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		return nil, nil, errors.New("failed to retrieve " + url + ", status code received 404")
	}
	return nil, b, nil
}

func TestRootPinned(t *testing.T) {
	sum := sha256.Sum256(rootDER)
	if hex.EncodeToString(sum[:]) != RootSHA256 || root.Subject.CommonName != "GCE-cc-tcb-root" || !root.IsCA ||
		root.NotAfter.Year() != 2048 {
		t.Fatalf("root %s %v %v", root.Subject, root.IsCA, root.NotAfter)
	}
}

func TestURL(t *testing.T) {
	if got := URL(unhex(mrtdNov)); got != "https://storage.googleapis.com/gce_tcb_integrity/ovmf_x64_csm/tdx/"+mrtdNov+".binarypb" {
		t.Fatal(got)
	}
}

// Both recorded endorsements verify against the compiled-in root and list their own MRTD (and not the other's).
func TestRecordedEndorsements(t *testing.T) {
	for _, c := range []struct {
		mrtd, other, built, cl, uefi string
	}{
		{mrtdNov, mrtdOct, "2026-07-31", "cl 957008435", "624ac419f063f0d1"},
		{mrtdOct, mrtdNov, "2026-05-21", "cl 919307640", "53c558fe06714203"},
	} {
		f, err := Verify(endorsement(t, c.mrtd), when)
		if err != nil {
			t.Fatal(err)
		}
		if f.SVN != 2 || f.Built.Format("2006-01-02") != c.built || f.Provenance() != c.cl || !strings.HasPrefix(f.UEFISHA384, c.uefi) ||
			f.Signer != "GCE-uefi-signer" || len(f.Measurements) != 1 || f.SignerExpiry.Year() != 2031 {
			t.Fatalf("%+v", f)
		}
		m, ok := f.Lists(unhex(c.mrtd))
		if !ok || m.RAMGiB != 0 || m.EarlyAccept {
			t.Fatalf("own MRTD %v %+v", ok, m)
		}
		if _, ok := f.Lists(unhex(c.other)); ok {
			t.Fatal("lists the other build's MRTD")
		}
		g := &files{t: t}
		f2, m2, err := Check(context.Background(), g, unhex(c.mrtd), when)
		if err != nil || g.calls != 1 || f2.SVN != 2 || m2.RAMGiB != 0 {
			t.Fatalf("Check: %v (%d calls)", err, g.calls)
		}
		if d := f2.Describe(m2); !strings.Contains(d, "SVN 2") || !strings.Contains(d, c.built) || !strings.Contains(d, "any RAM size") {
			t.Fatal(d)
		}
	}
}

func TestCheckRefuses(t *testing.T) {
	nov, oct := endorsement(t, mrtdNov), endorsement(t, mrtdOct)
	golden, sig, err := parseLaunch(nov)
	if err != nil {
		t.Fatal(err)
	}
	launch := func(golden, sig []byte) []byte {
		var b []byte
		b = protowire.AppendTag(b, 1, protowire.BytesType)
		b = protowire.AppendBytes(b, golden)
		b = protowire.AppendTag(b, 2, protowire.BytesType)
		return protowire.AppendBytes(b, sig)
	}
	if string(launch(golden, sig)) != string(nov) {
		t.Fatal("re-encoding the recorded endorsement doesn't give its bytes")
	}
	flipAt := func(b []byte, i int) []byte {
		c := append([]byte{}, b...)
		c[i] ^= 1
		return c
	}
	cases := []struct {
		name  string
		mrtd  string
		serve []byte // nil: the recorded files by URL
		now   time.Time
		want  string
	}{
		{"an MRTD Google never endorsed (404)", strings.Repeat("ab", 48), nil, when, "no Google endorsement"},
		{"a genuine endorsement of another build served for this MRTD", mrtdNov, oct, when, "doesn't list MRTD f21e6b48"},
		{"signature changed", mrtdNov, launch(golden, flipAt(sig, 10)), when, "endorsement signature"},
		{"signed content changed (one byte of the golden measurement)", mrtdNov, launch(flipAt(golden, len(golden)-3), sig), when, "endorsement signature"},
		{"no signature", mrtdNov, launch(golden, nil), when, "no signed golden measurement or no signature"},
		{"truncated", mrtdNov, nov[:len(nov)-7], when, "endorsement"},
		{"empty", mrtdNov, []byte{}, when, "no signed golden measurement"},
		{"after the signer certificate expired", mrtdNov, nil, time.Date(2031, 8, 1, 0, 0, 0, 0, time.UTC), "isn't certified by GCE-cc-tcb-root"},
		{"before the signer certificate was issued", mrtdNov, nil, time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC), "isn't certified by GCE-cc-tcb-root"},
		{"an MRTD of the wrong length", "abcd", nil, when, "MRTD is 2 bytes"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, _, err := Check(context.Background(), &files{t: t, serve: c.serve}, unhex(c.mrtd), c.now)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("want %q: %v", c.want, err)
			}
		})
	}
}

// The root itself as the signer (a CA certificate, not Google's UEFI signer) is refused by name before anything else.
func TestSignerMustSign(t *testing.T) {
	nov := endorsement(t, mrtdNov)
	golden, sig, _ := parseLaunch(nov)
	var out []byte
	err := fields(golden, func(num protowire.Number, typ protowire.Type, v uint64, bs []byte) error {
		out = protowire.AppendTag(out, num, typ)
		switch {
		case num == 4:
			out = protowire.AppendBytes(out, rootDER)
		case typ == protowire.VarintType:
			out = protowire.AppendVarint(out, v)
		default:
			out = protowire.AppendBytes(out, bs)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	var b []byte
	b = protowire.AppendTag(b, 1, protowire.BytesType)
	b = protowire.AppendBytes(b, out)
	b = protowire.AppendTag(b, 2, protowire.BytesType)
	b = protowire.AppendBytes(b, sig)
	if _, err := Verify(b, when); err == nil || !strings.Contains(err.Error(), "isn't a GCE-uefi-signer signing certificate") {
		t.Fatalf("root as signer: %v", err)
	}
}

// reSign rebuilds the recorded endorsement with cert as its signer and a valid RSA-PSS signature by key.
func reSign(t *testing.T, cert []byte, key *rsa.PrivateKey) []byte {
	t.Helper()
	golden, _, _ := parseLaunch(endorsement(t, mrtdNov))
	var out []byte
	fields(golden, func(num protowire.Number, typ protowire.Type, v uint64, bs []byte) error {
		out = protowire.AppendTag(out, num, typ)
		switch {
		case num == 4:
			out = protowire.AppendBytes(out, cert)
		case typ == protowire.VarintType:
			out = protowire.AppendVarint(out, v)
		default:
			out = protowire.AppendBytes(out, bs)
		}
		return nil
	})
	h := sha256.Sum256(out)
	sig, err := rsa.SignPSS(rand.Reader, key, crypto.SHA256, h[:], nil)
	if err != nil {
		t.Fatal(err)
	}
	var b []byte
	b = protowire.AppendTag(b, 1, protowire.BytesType)
	b = protowire.AppendBytes(b, out)
	b = protowire.AppendTag(b, 2, protowire.BytesType)
	return protowire.AppendBytes(b, sig)
}

// Forged endorsements with valid signatures: a self-signed "GCE-uefi-signer", and one issued by a look-alike
// "GCE-cc-tcb-root". Both are refused: only the compiled-in root's key counts, not its name.
func TestForgedSigner(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	name := func(cn string) pkix.Name { return pkix.Name{CommonName: cn, Organization: []string{"Google"}} }
	leaf := &x509.Certificate{SerialNumber: big.NewInt(32), Subject: name(SignerName), NotBefore: when.AddDate(-1, 0, 0),
		NotAfter: when.AddDate(1, 0, 0), KeyUsage: x509.KeyUsageDigitalSignature, BasicConstraintsValid: true}
	self, err := x509.CreateCertificate(rand.Reader, leaf, leaf, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: name("GCE-cc-tcb-root"), NotBefore: when.AddDate(-1, 0, 0),
		NotAfter: when.AddDate(5, 0, 0), KeyUsage: x509.KeyUsageCertSign, IsCA: true, BasicConstraintsValid: true}
	caKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	issued, err := x509.CreateCertificate(rand.Reader, leaf, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	for what, cert := range map[string][]byte{"self-signed": self, "look-alike root": issued} {
		raw := reSign(t, cert, key)
		if _, err := Verify(raw, when); err == nil || !strings.Contains(err.Error(), "isn't certified by GCE-cc-tcb-root") {
			t.Fatalf("%s: %v", what, err)
		}
	}
}

// An endorsement larger than MaxSize is refused before it is parsed.
func TestTooLarge(t *testing.T) {
	big := append(endorsement(t, mrtdNov), make([]byte, MaxSize)...)
	if _, _, err := Check(context.Background(), &files{t: t, serve: big}, unhex(mrtdNov), when); err == nil ||
		!strings.Contains(err.Error(), "more than") {
		t.Fatal(err)
	}
}

// Wire types the messages don't use are refused rather than skipped.
func TestStrictWire(t *testing.T) {
	var b []byte
	b = protowire.AppendTag(b, 1, protowire.Fixed64Type)
	b = protowire.AppendFixed64(b, 1)
	if _, err := Verify(b, when); err == nil || !strings.Contains(err.Error(), "unexpected wire type") {
		t.Fatal(err)
	}
	b = nil
	b = protowire.AppendTag(b, 1, protowire.VarintType) // golden as a varint
	b = protowire.AppendVarint(b, 1)
	if _, err := Verify(b, when); err == nil || !strings.Contains(err.Error(), "wire type") {
		t.Fatal(err)
	}
}
