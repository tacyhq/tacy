package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/tacyhq/tacy/kms"
	"github.com/tacyhq/tacy/kms/split/splitdev"
	"github.com/tacyhq/tacy/safety"
	"github.com/tacyhq/tacy/verifier"
)

// machine-cert -builtin signs exactly the built-in document, so the ceremony's certificate has the built-in hash (one
// revocation covers both); the flags' form is checked; every document is one Phala machine (the v1 Google host removal).
func TestMachineCertCommand(t *testing.T) {
	now := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)
	for i, node := range []string{"prod5", "prod9"} {
		d, err := machineDoc(node, "", "", "", "", now)
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
		"unknown node":      {"prod7", "", "", "", ""},
		"builtin and flags": {"prod5", "3e306e133b7fdaa7bb79f67634cb520c", "", "", ""},
		"short ppid":        {"", "3e30", "20a06f000000", "phala x", ""},
		"no ppid":           {"", "", "00806f050000", "gcp c3", ""},
	} {
		if _, err := machineDoc(args[0], args[1], args[2], args[3], args[4], now); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
	if d, err := machineDoc("", strings.Repeat("ab", 16), "20a06f000000", "phala prod7", "", now); err != nil ||
		d.Host != safety.MachineHostPhala || d.Mode != safety.MachineModePPID {
		t.Fatalf("a Phala document from the flags: %+v, %v", d, err)
	}
	// Signing a non-Phala document is refused (what -host google -mode gcp-registry made before the v1 Google host removal).
	for _, d := range []safety.MachineDoc{
		{Type: safety.MachineType, Platform: "dstack", Host: "google", Mode: "ppid", PPID: strings.Repeat("ab", 16), FMSPC: "00806f050000", Label: "gcp host", IssuedAt: now},
		{Type: safety.MachineType, Platform: "dstack", Host: "google", Mode: "gcp-registry", FMSPC: "00806f050000", Label: "gcp c3", IssuedAt: now},
	} {
		if _, err := safety.MarshalMachineDoc(d); err == nil {
			t.Fatalf("a %s/%s document: accepted", d.Host, d.Mode)
		}
	}
}

// approve -machine-cert / -revoke-machine: the admin key adds a KMS-signed certificate or revokes one in both
// documents; a revocation stays in every later policy and trust list approve makes, the certificate leaves
// machine_certs, and the same certificate can't be added back (a new one is needed). A Google certificate is refused.
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
	// A Google certificate (the old -host google, KMS-signed over its exact bytes): refused (the v1 Google host removal).
	k, _ := kms.DeriveID(d.Master)
	gdoc := []byte(`{"type":"tacy.machine/v1","kms_id":"` + d.KMSID + `","platform":"dstack","host":"google","mode":"ppid","ppid":"` +
		strings.Repeat("cd", 16) + `","fmspc":"00806f050000","label":"gcp host","issued_at":"` + now.Format(time.RFC3339) + `"}`)
	reg := safety.SignedMachineCert{Doc: gdoc, Sig: ed25519.Sign(k, append([]byte("tacy-split/machine/v1\x00"), gdoc...))}
	np6, ntl6, _ := nextSeqs(*np3, ntl3, now)
	if err := changeMachines(np6, ntl6, []safety.SignedMachineCert{reg}, nil); err == nil || !strings.Contains(err.Error(), "unknown host") {
		t.Fatalf("a Google certificate: %v", err)
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

// Fail closed on platforms (the v1 Google host removal): kmsctl doesn't make an unlock policy or a trust list naming a platform
// other than dstack ("dstack-gcp" included), since holders and clients built from this tree refuse either whole.
// Before the change, both were made, and turned the Google Cloud host fallback on.
func TestApproveRefusesUnknownPlatform(t *testing.T) {
	now := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)
	d, err := splitdev.New([]string{"cloudflare", "vercel"}, 2, now.Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	tl := &safety.TrustList{Type: safety.TrustListType, Seq: 3, IssuedAt: now.Add(-24 * time.Hour)}
	for _, plats := range [][]string{{"dstack", "dstack-gcp"}, {"dstack-gcp"}} {
		np, ntl, err := nextSeqs(d.Policy, tl, now)
		if err != nil {
			t.Fatal(err)
		}
		np.Platforms = plats
		if err := checkUnlockPolicy(np); err == nil || !strings.Contains(err.Error(), `unknown platform "dstack-gcp"`) {
			t.Fatalf("policy, platforms %v: %v", plats, err)
		}
		np.Platforms = nil
		ntl.Platforms = plats
		if err := changeMachines(np, ntl, nil, nil); err == nil || !strings.Contains(err.Error(), `unknown platform "dstack-gcp"`) {
			t.Fatalf("trust list, platforms %v: %v", plats, err)
		}
	}
	np, ntl, _ := nextSeqs(d.Policy, tl, now)
	np.Platforms, ntl.Platforms = []string{"dstack"}, []string{"dstack"}
	if err := changeMachines(np, ntl, nil, nil); err != nil {
		t.Fatalf("dstack only: %v", err)
	}
}
