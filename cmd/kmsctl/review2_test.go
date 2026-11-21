package main

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/tacyhq/tacy/kms/split/splitdev"
	"github.com/tacyhq/tacy/safety"
	"github.com/tacyhq/tacy/verifier"
)

// The second keys review (a research note), kmsctl's side.

// H1: approving a revoked version again un-revokes it in the same trust list (before, the list was refused: "both
// listed and revoked"), and -emergency names its un-revocation with its release, so clients take both at once.
func TestReview2ApproveUnrevokes(t *testing.T) {
	now := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)
	d, err := splitdev.New([]string{"cloudflare", "vercel"}, 2, now.Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	ac, cy := filepath.Join(dir, "app-compose.json"), filepath.Join(dir, "compose.yaml")
	os.WriteFile(ac, []byte(`{"name":"agent-vm"}`), 0o644)
	os.WriteFile(cy, []byte("services: {}\n"), 0o644)
	tl := &safety.TrustList{Type: safety.TrustListType, Seq: 3, IssuedAt: now.Add(-24 * time.Hour), RevokedReleases: []string{"v0.22.1", "v0.20.0"}}
	entry := &safety.TrustRelease{Version: "v0.22.1", Commit: strings.Repeat("3", 40), ComposeSHA256: fileSHA256(cy), Bundle: []byte(`{}`)}
	add := releaseSpec{App: splitdev.App, Version: "v0.22.1", AppCompose: ac, Compose: cy}
	np, ntl, err := approve(d.Policy, tl, []releaseSpec{add}, nil, entry, nil, nil, nil, now)
	if err != nil {
		t.Fatalf("approving a revoked version again: %v", err)
	}
	if slices.Contains(ntl.RevokedReleases, "v0.22.1") || !slices.Contains(ntl.RevokedReleases, "v0.20.0") {
		t.Fatalf("revoked_releases after: %v", ntl.RevokedReleases)
	}
	if err := attachTrustEmergency(ntl, tl.RevokedReleases, d.Master, np.KMSID, []releaseSpec{add}, nil, "re-allow", now); err != nil {
		t.Fatal(err)
	}
	em, err := ntl.OpenEmergency(d.IDPub)
	if err != nil || !slices.Contains(em.Items, safety.TrustItemUnrevoke+"v0.22.1") || !slices.Contains(em.Items, safety.TrustReleaseItem(*entry)) {
		t.Fatalf("the override should name the release and its un-revocation: %+v %v", em, err)
	}
}

// L3: revoking one certificate of a machine revokes every certificate kmsctl knows for that PPID (the policy's and
// the built-in document), so a second certificate for the same machine can't be listed by an admin key.
func TestReview2RevokeWholeMachine(t *testing.T) {
	now := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)
	d, err := splitdev.New([]string{"cloudflare", "vercel"}, 2, now.Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	tl := &safety.TrustList{Type: safety.TrustListType, Seq: 3, IssuedAt: now.Add(-24 * time.Hour)}
	// A second prod5 certificate (issued now, not the built-in document), beside the policy's.
	again, err := d.MachineCert(safety.MachineDoc{Type: safety.MachineType, Platform: "dstack", Host: "phala", Mode: "ppid",
		PPID: verifier.MachineDocs[0].PPID, FMSPC: verifier.MachineDocs[0].FMSPC, Label: "phala prod5", IssuedAt: now})
	if err != nil {
		t.Fatal(err)
	}
	np, ntl, _ := nextSeqs(d.Policy, tl, now)
	if err := changeMachines(np, ntl, []safety.SignedMachineCert{*again}, nil); err != nil {
		t.Fatal(err)
	}
	var first string
	for _, c := range np.MachineCerts {
		if doc, _ := machineDocOf(c); doc.PPID == verifier.MachineDocs[0].PPID && c.Hash() != again.Hash() {
			first = c.Hash()
		}
	}
	if first == "" {
		t.Fatal("setup: no first prod5 certificate in the policy")
	}
	np2, ntl2, _ := nextSeqs(*np, ntl, now)
	if err := changeMachines(np2, ntl2, nil, []string{first}); err != nil {
		t.Fatal(err)
	}
	builtin, _ := safety.MachineDocHash(verifier.MachineDocs[0])
	for _, h := range []string{first, again.Hash(), builtin} {
		if !slices.Contains(np2.MachinesRevoked, h) {
			t.Errorf("%s isn't revoked after revoking prod5's first certificate: %v", h[:12], np2.MachinesRevoked)
		}
	}
	for _, c := range np2.MachineCerts {
		if doc, _ := machineDocOf(c); doc.PPID == verifier.MachineDocs[0].PPID {
			t.Errorf("a prod5 certificate stays in machine_certs: %s", c.Hash()[:12])
		}
	}
	if _, revoked, _, _ := ntl2.TrustMachines(); !slices.Contains(revoked, again.Hash()) {
		t.Errorf("the trust list doesn't revoke the second certificate: %v", revoked)
	}
}

// L2: a policy for a new admin-key generation carries the old one's machine revocations (-previous).
func TestReview2RevocationsCarryOver(t *testing.T) {
	now := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)
	d, err := splitdev.New([]string{"cloudflare", "vercel"}, 2, now.Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	prev := d.Policy
	revoked := prev.MachineCerts[0].Hash()
	prev.MachinesRevoked = []string{revoked}
	fresh := d.Policy // a new generation's policy built from the key service's policy: no revocations
	if err := carryRevocations(&fresh, &prev); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(fresh.MachinesRevoked, revoked) || slices.ContainsFunc(fresh.MachineCerts, func(c safety.SignedMachineCert) bool { return c.Hash() == revoked }) {
		t.Fatalf("revocation not carried over: %v", fresh.MachinesRevoked)
	}
}
