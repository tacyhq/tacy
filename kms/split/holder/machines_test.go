package holder

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/tacyhq/tacy/kms/split"
	"github.com/tacyhq/tacy/safety"
)

// The machine allowlist at a holder (V1-DESIGN §3.3). The rig's VM is the recorded prod5 quote.

// A VM on a machine the policy doesn't certify gets no share: here the policy certifies only prod9, and both
// holders refuse prod5's quote at the machine check (no share served, no unlock).
func TestHolderUnlistedPPIDRefused(t *testing.T) {
	r := newRig(t, twoOfTwo, 2)
	r.pol.MachineCerts = []safety.SignedMachineCert{r.machineCert(prod9, r.now)}
	_, rep, err := r.unlock(r.transports(nil), nil)
	if err == nil {
		t.Fatal("prod5 unlocked under a policy certifying only prod9")
	}
	for _, h := range r.ids {
		if !strings.Contains(rep.Outcome[h], "platform "+prod5+" (FMSPC 20a06f000000) has no machine certificate") {
			t.Fatalf("%s: %q", h, rep.Outcome[h])
		}
	}
	for _, e := range r.events {
		if e.Kind == "unlock" && e.OK {
			t.Fatalf("a share served: %+v", e)
		}
	}
	// Certified again: the same VM unlocks, and every served unlock records the platform and the machine.
	r.pol.Seq++
	r.pol.MachineCerts = append(r.pol.MachineCerts, r.machineCert(prod5, r.now))
	if _, rep, err := r.unlock(r.transports(nil), nil); err != nil {
		t.Fatalf("%v %v", err, rep.Outcome)
	}
	served := 0
	for _, e := range r.events {
		if e.Kind == "unlock" && e.OK {
			served++
			if e.PPID != prod5 || !strings.Contains(e.Machine, "not defended by the machine list") {
				t.Fatalf("event %+v", e)
			}
		}
	}
	if served != 2 {
		t.Fatalf("%d shares served", served)
	}
}

// Revocations are permanent at a holder (second review N8): policy 6 revokes prod5's certificate (an admin key alone
// may); policy 7, signed by the admin key alone, lists the same genuine certificate again and leaves the revocation
// out: still refused, from the holder's store, with an alert. Re-allowing needs a new certificate (the KMS id): with
// one, prod5 unlocks again. Restarting the holder (same store) changes nothing.
func TestHolderMachineRevocationMonotonic(t *testing.T) {
	r := newRig(t, twoOfTwo, 2)
	if _, rep, err := r.unlock(r.transports(nil), nil); err != nil {
		t.Fatalf("%v %v", err, rep.Outcome)
	}
	c5 := r.pol.MachineCerts[0]
	r.pol.Seq, r.pol.MachinesRevoked = 6, []string{c5.Hash()}
	r.push(t)
	r.wantOutcome(t, "is revoked")
	r.pol.Seq, r.pol.MachinesRevoked = 7, nil
	r.push(t)
	for _, h := range r.ids {
		r.holders[h] = r.newHolder(h, nil) // a restart: the same durable store
	}
	r.wantOutcome(t, "its certificate was revoked at this holder (permanent")
	alerts := 0
	for _, e := range r.events {
		if e.Kind == "change" && e.Item == split.ItemMachineRevoked+c5.Hash() && strings.Contains(e.Reason, "still revoked") {
			alerts++
		}
	}
	if alerts == 0 {
		t.Fatal("no alert on a policy that leaves out a kept revocation")
	}
	// The store kept it although policies 7 and later don't list it, past the 30-day prune of withdrawn items.
	r.advance(40 * 24 * time.Hour)
	r.pol.Seq, r.pol.IssuedAt = 8, r.clock().Add(-time.Hour)
	r.wantOutcome(t, "its certificate was revoked at this holder (permanent")
	// TestUnrevokeNeedsNewCertificate: a new certificate (another issued_at, another hash) for prod5.
	r.pol.Seq = 9
	r.pol.MachineCerts[0] = r.machineCert(prod5, r.clock())
	if _, rep, err := r.unlock(r.transports(nil), nil); err != nil {
		t.Fatalf("prod5's new certificate: %v %v", err, rep.Outcome)
	}
}

// A policy whose machine certificate isn't the KMS id's (here signed by the admin key) is refused whole.
func TestHolderMachineCertNeedsKMSID(t *testing.T) {
	r := newRig(t, twoOfTwo, 2)
	bad, err := safety.SignMachineCert(r.admin, safety.MachineDoc{Type: safety.MachineType, Platform: "dstack", Host: "phala",
		Mode: "ppid", PPID: strings.Repeat("ab", 16), FMSPC: "20a06f000000", Label: "rogue", IssuedAt: r.now})
	if err != nil {
		t.Fatal(err)
	}
	r.pol.MachineCerts = append(r.pol.MachineCerts, *bad)
	r.wantOutcome(t, "isn't signed by the KMS id")
}

// Fail closed on platforms (the v1 Google host removal): a policy naming one this holder has no checks for (Config.Platforms,
// "dstack" by default) is refused whole, at the push and at an unlock, so "dstack-gcp" (the Google Cloud host fallback
// taken out of v1) is refused as unknown and nothing is unlocked; the same policy without it unlocks. Before the
// change, dstack-gcp was taken (and turned Google Cloud's boot sets on at this holder after the pin delay).
func TestHolderRefusesUnknownPlatform(t *testing.T) {
	r := newRig(t, twoOfTwo, 2)
	for _, plats := range [][]string{{"dstack", "dstack-gcp"}, {"dstack-gcp"}, {"dstack", "tdx-other"}} {
		r.pol.Seq++
		r.pol.Platforms = plats
		r.wantOutcome(t, "which this holder has no checks for")
		raw := r.policyEnv()
		if _, err := r.holders["cloudflare"].PushPolicy(context.Background(), raw); err == nil ||
			!strings.Contains(err.Error(), "which this holder has no checks for") {
			t.Fatalf("push, platforms %v: %v", plats, err)
		}
	}
	r.pol.Seq++
	r.pol.Platforms = []string{"dstack"}
	if _, rep, err := r.unlock(r.transports(nil), nil); err != nil {
		t.Fatalf("a dstack-only policy: %v %v", err, rep.Outcome)
	}
}
