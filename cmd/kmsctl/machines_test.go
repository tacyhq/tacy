package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/tacyhq/tacy/kms/split/splitdev"
	"github.com/tacyhq/tacy/safety"
	"github.com/tacyhq/tacy/verifier"
)

// machine-cert -builtin signs exactly the built-in document, so the ceremony's certificate has the built-in hash (one
// revocation covers both); the flags' form is checked; a Google certificate needs the fallback named.
func TestMachineCertCommand(t *testing.T) {
	now := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)
	for i, node := range []string{"prod5", "prod9"} {
		d, err := machineDoc(node, "", "", "", "phala", "ppid", "", "", now)
		if err != nil {
			t.Fatal(err)
		}
		want, _ := safety.MachineDocHash(verifier.MachineDocs[i])
		got, _ := safety.MachineDocHash(d)
		if got != want || verifier.BuiltinMachines().Machines[i].Hash != want {
			t.Fatalf("%s: ceremony document hash %s, built in %s", node, got, want)
		}
	}
	for name, args := range map[string][]string{
		"unknown node":         {"prod7", "", "", "", "phala", "ppid", "", ""},
		"builtin and flags":    {"prod5", "3e306e133b7fdaa7bb79f67634cb520c", "", "", "phala", "ppid", "", ""},
		"short ppid":           {"", "3e30", "20a06f000000", "phala x", "phala", "ppid", "", ""},
		"registry, no project": {"", "", "00806f050000", "gcp c3", "google", "gcp-registry", "", ""},
		"registry on phala":    {"", "", "00806f050000", "gcp c3", "phala", "gcp-registry", "123", ""},
	} {
		if _, err := machineDoc(args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7], now); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
	if d, err := machineDoc("", "", "00806f050000", "gcp c3", "google", "gcp-registry", "123456789012", "", now); err != nil || d.PPID != "" {
		t.Fatalf("registry document: %v", err)
	}
}

// approve -machine-cert / -revoke-machine: the admin key adds a KMS-signed certificate or revokes one in both
// documents; a revocation stays in every later policy and trust list approve makes, the certificate leaves
// machine_certs, and the same certificate can't be added back (a new one is needed). A Google certificate is refused
// while the policy doesn't name the fallback.
func TestApproveMachines(t *testing.T) {
	now := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)
	d, err := splitdev.New([]string{"cloudflare", "vercel"}, 2, now.Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	d.AddRelease("v0.21.0", strings.Repeat("a", 64), "")
	tl := &safety.TrustList{Type: safety.TrustListType, Seq: 3, IssuedAt: now.Add(-24 * time.Hour)}
	newNode, err := d.MachineCert(safety.MachineDoc{Type: safety.MachineType, Platform: "dstack", Host: "phala", Mode: "ppid",
		PPID: strings.Repeat("cd", 16), FMSPC: "20a06f000000", Label: "phala prod11", IssuedAt: now})
	if err != nil {
		t.Fatal(err)
	}
	np, ntl, err := nextSeqs(d.Policy, tl, now)
	if err == nil {
		err = changeMachines(np, ntl, []safety.SignedMachineCert{*newNode}, nil)
	}
	if err != nil || len(np.MachineCerts) != 3 || np.Seq != d.Policy.Seq+1 || ntl.Seq != 4 {
		t.Fatalf("add: %v", err)
	}
	certs, revoked, present, err := ntl.TrustMachines()
	if err != nil || !present || len(certs) != 3 || len(revoked) != 0 {
		t.Fatalf("trust list machines: %d %v %v %v", len(certs), revoked, present, err)
	}
	prod5 := np.MachineCerts[0].Hash()
	np2, ntl2, _ := nextSeqs(*np, ntl, now)
	if err := changeMachines(np2, ntl2, nil, []string{prod5}); err != nil {
		t.Fatal(err)
	}
	_, revoked, _, _ = ntl2.TrustMachines()
	// The built-in prod5 document is revoked with it (the same machine: review2 L3).
	builtin5, _ := safety.MachineDocHash(verifier.MachineDocs[0])
	if len(np2.MachineCerts) != 2 || len(np2.MachinesRevoked) != 2 || len(revoked) != 2 || !slices.Contains(revoked, prod5) || !slices.Contains(revoked, builtin5) {
		t.Fatalf("revoke: %d certs, %v, trust list %v", len(np2.MachineCerts), np2.MachinesRevoked, revoked)
	}
	// A later, unrelated approve keeps it; adding the revoked certificate back is refused.
	np3, ntl3, _ := nextSeqs(*np2, ntl2, now)
	if err := changeMachines(np3, ntl3, nil, nil); err != nil || len(np3.MachinesRevoked) != 2 {
		t.Fatalf("kept: %v %v", err, np3.MachinesRevoked)
	}
	np4, ntl4, _ := nextSeqs(*np3, ntl3, now)
	if err := changeMachines(np4, ntl4, []safety.SignedMachineCert{d.Policy.MachineCerts[0]}, nil); err == nil || !strings.Contains(err.Error(), "revoked") {
		t.Fatalf("re-adding a revoked certificate: %v", err)
	}
	// Even if the policy base lost the revocation (edited by hand), the trust list keeps the union.
	np5, ntl5, _ := nextSeqs(*np3, ntl3, now)
	np5.MachinesRevoked = nil
	if err := changeMachines(np5, ntl5, nil, nil); err != nil {
		t.Fatal(err)
	}
	if _, revoked, _, _ = ntl5.TrustMachines(); len(revoked) != 2 {
		t.Fatalf("the trust list dropped a revocation: %v", revoked)
	}
	// A Google certificate on Phala.
	reg, _ := d.MachineCert(safety.MachineDoc{Type: safety.MachineType, Platform: "dstack", Host: "google", Mode: "gcp-registry",
		FMSPC: "00806f050000", ProjectNumber: "123456789012", Label: "gcp c3", IssuedAt: now})
	np6, ntl6, _ := nextSeqs(*np3, ntl3, now)
	if err := changeMachines(np6, ntl6, []safety.SignedMachineCert{*reg}, nil); err == nil || !strings.Contains(err.Error(), "Google fallback") {
		t.Fatalf("a registry certificate while on Phala: %v", err)
	}
	// A certificate the admin key signed isn't accepted.
	_, admin, _ := ed25519.GenerateKey(rand.Reader)
	bad, _ := safety.SignMachineCert(admin, safety.MachineDoc{Type: safety.MachineType, Platform: "dstack", Host: "phala", Mode: "ppid",
		PPID: strings.Repeat("ef", 16), FMSPC: "20a06f000000", Label: "rogue", IssuedAt: now})
	np7, ntl7, _ := nextSeqs(*np3, ntl3, now)
	if err := changeMachines(np7, ntl7, []safety.SignedMachineCert{*bad}, nil); err == nil || !strings.Contains(err.Error(), "isn't signed by the KMS id") {
		t.Fatalf("an admin-signed certificate: %v", err)
	}
}

// Fail closed on platforms (kept from the v1 Google host removal, dstack-gcp known again): kmsctl doesn't make an unlock policy or
// a trust list naming a platform holders and clients have no checks for.
func TestApproveRefusesUnknownPlatform(t *testing.T) {
	now := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)
	d, err := splitdev.New([]string{"cloudflare", "vercel"}, 2, now.Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	tl := &safety.TrustList{Type: safety.TrustListType, Seq: 3, IssuedAt: now.Add(-24 * time.Hour)}
	for _, plats := range [][]string{{"dstack", "tdx-other"}, {"tdx-other"}, {"dstack", "dstack-gcp", "tdx-other"}} {
		np, ntl, err := nextSeqs(d.Policy, tl, now)
		if err != nil {
			t.Fatal(err)
		}
		np.Platforms = plats
		if err := checkUnlockPolicy(np); err == nil || !strings.Contains(err.Error(), `unknown platform "tdx-other"`) {
			t.Fatalf("policy, platforms %v: %v", plats, err)
		}
		np.Platforms = nil
		ntl.Platforms = plats
		if err := changeMachines(np, ntl, nil, nil); err == nil || !strings.Contains(err.Error(), `unknown platform "tdx-other"`) {
			t.Fatalf("trust list, platforms %v: %v", plats, err)
		}
	}
	for _, plats := range [][]string{{"dstack"}, {"dstack", "dstack-gcp"}} {
		np, ntl, _ := nextSeqs(d.Policy, tl, now)
		np.Platforms, ntl.Platforms = plats, plats
		if err := changeMachines(np, ntl, nil, nil); err != nil {
			t.Fatalf("platforms %v: %v", plats, err)
		}
	}
}
