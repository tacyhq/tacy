package tdx

import (
	"context"
	"strings"
	"testing"
)

// The machine allowlist reads the PPID and FMSPC from the quote's PCK certificate (V1-DESIGN §3.3). On the recorded
// Phala quotes: prod5's PPID in the 0.6.1, 0.6.4 and 0.6.5 recordings, prod9's in attest-v1 (both FMSPC 20a06f000000;
// a research note). VerifyWith reads them from the chain it checked (Intel's
// recorded collateral), Parse and PCKIdentity without any check (tests, the holders' pre-gate).
func TestQuotePPIDFromRecordedQuotes(t *testing.T) {
	const prod5, prod9, fmspc = "3e306e133b7fdaa7bb79f67634cb520c", "62d54040cb9dfc08bb13006fa75ece56", "20a06f000000"
	for _, c := range []struct{ file, ppid string }{
		{"attest-061.json", prod5}, {"attest-064.json", prod5}, {"attest-065-none.json", prod5},
		{"attest-065-none-restart.json", prod5}, {"attest-065-kms.json", prod5}, {"attest-v1.json", prod9},
	} {
		if missingPrivate(t, c.file) {
			continue
		}
		raw := recordedQuote(t, c.file)
		q, err := Parse(raw)
		if err != nil || q.PPID != c.ppid || q.FMSPC != fmspc || strings.Trim(q.MrOwner, "0") != "" {
			t.Errorf("%s: Parse: ppid %q fmspc %q mr_owner %q, %v", c.file, q.PPID, q.FMSPC, q.MrOwner, err)
		}
		ppid, f, err := PCKIdentity(raw)
		if err != nil || ppid != c.ppid || f != fmspc {
			t.Errorf("%s: PCKIdentity: %q %q %v", c.file, ppid, f, err)
		}
	}
	for _, name := range []string{"attest-064.json", "attest-061.json"} {
		q, err := VerifyWith(context.Background(), recordedQuote(t, name), Options{Getter: loadReplay(t), Now: collateralTime})
		if err != nil || q.PPID != prod5 || q.FMSPC != fmspc {
			t.Fatalf("%s: VerifyWith: ppid %q fmspc %q, %v", name, q.PPID, q.FMSPC, err)
		}
	}
	if _, _, err := PCKIdentity([]byte("not a quote")); err == nil {
		t.Fatal("PCKIdentity read junk")
	}
}
