package tdx

import (
	"testing"
	"time"
)

// VerifySignature (second keys review M2): the recorded quotes' signatures verify offline up to Intel's root, with no
// collateral; a quote with one byte of its body changed (report_data, as the holders' rig patches it), its attestation
// signature changed, or its PCK certificate changed is refused; so is junk. The PPID is the checked chain's.
func TestVerifySignatureOffline(t *testing.T) {
	now := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)
	const prod5 = "3e306e133b7fdaa7bb79f67634cb520c"
	for _, name := range []string{"attest-061.json", "attest-064.json", "attest-065-kms.json", "attest-v1.json"} {
		if missingPrivate(t, name) {
			continue
		}
		raw := recordedQuote(t, name)
		q, err := VerifySignature(raw, now)
		if err != nil || q.PPID == "" || q.FMSPC != "20a06f000000" {
			t.Fatalf("%s: %+v, %v", name, q, err)
		}
		if name == "attest-065-kms.json" && q.PPID != prod5 {
			t.Fatalf("%s: PPID %s", name, q.PPID)
		}
		for what, off := range map[string]int{"report_data": 48 + 520, "the quote signature": 632 + 4 + 10, "the PCK certificate": len(raw) - 900} {
			b := append([]byte(nil), raw...)
			b[off] ^= 0x01
			if _, err := VerifySignature(b, now); err == nil {
				t.Errorf("%s: a quote with %s changed verified", name, what)
			}
		}
	}
	if _, err := VerifySignature([]byte("not a quote"), now); err == nil {
		t.Fatal("junk verified")
	}
	// Certificates are checked at the given time: long after the PCK certificate's expiry, refused.
	if _, err := VerifySignature(recordedQuote(t, "attest-065-kms.json"), now.AddDate(30, 0, 0)); err == nil {
		t.Fatal("verified in 2056")
	}
}
