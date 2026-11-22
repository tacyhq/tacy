package verifier

import (
	"context"
	"strings"
	"testing"

	"github.com/tacyhq/tacy/internal/tdx"
)

const tcbCheck = "TCB up to date, debug off"

// The TCB rule on the 0.6.4 recording (every other check passes): the TD's status and the quoting enclave's must both
// be UpToDate, and Revoked is refused even where a stale TCB is allowed (tests, a holder's signed TCB grace).
// internal/tdx's tests show how the statuses are read from Intel's collateral.
func TestTCBPolicy(t *testing.T) {
	cases := []struct {
		tcb, qe    string
		allowStale bool
		refused    string
	}{
		{"UpToDate", "UpToDate", false, ""},
		{"OutOfDate", "UpToDate", false, "TCB status OutOfDate"},
		{"UpToDate", "OutOfDate", false, "QE TCB status OutOfDate"},
		{"UpToDate", "Revoked", false, "QE TCB status Revoked"},
		{"ConfigurationNeeded", "UpToDate", false, "TCB status ConfigurationNeeded"},
		{"OutOfDate", "OutOfDate", true, ""},
		{"Revoked", "UpToDate", true, "TCB status Revoked"},
		{"UpToDate", "Revoked", true, "QE TCB status Revoked"},
	}
	for _, c := range cases {
		a, nonce, compose := load064(t)
		p := Policy{AllowStaleTCB: c.allowStale, Compose: compose, legacy: true, PreLaunch: RetiredPreLaunchScripts, ProdImages: allImages(),
			Boot: allSets(), VerifyQuote: changeQuote(func(q *tdx.Quote) { q.TcbStatus, q.QeStatus = c.tcb, c.qe })}
		_, err := Verify(context.Background(), a, nonce, p)
		name := c.tcb + "/QE " + c.qe
		if c.allowStale {
			name += " (stale allowed)"
		}
		if c.refused == "" {
			if err != nil {
				t.Errorf("%s: %v", name, err)
			}
			continue
		}
		if err == nil || !strings.HasPrefix(err.Error(), tcbCheck+": ") || !strings.HasSuffix(err.Error(), c.refused) {
			t.Errorf("%s: want refused at the TCB check (%s), got %v", name, c.refused, err)
		}
	}
}
