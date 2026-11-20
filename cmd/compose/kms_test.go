package main

import (
	"strings"
	"testing"

	"github.com/tacyhq/tacy/kms/server"
	"github.com/tacyhq/tacy/verifier"
)

const testKMSRef = Registry + "/kmsd@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func TestKMSCompose(t *testing.T) {
	id := "ed25519:" + strings.Repeat("A", 43) + "="
	out, err := generateKMS(testKMSRef, strings.Repeat("ab", 32), KMSArgs{AdminKeys: adminKeys, AdminThreshold: 1, KMSID: id,
		Floor: "v0.20.0", Peers: "https://kms-2.example"})
	if err != nil {
		t.Fatal(err)
	}
	if err := server.CheckCompose(out); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"image: " + testKMSRef, `"-kms-id", "` + id + `"`, `"-floor", "v0.20.0"`, "driver: none",
		"memswap_limit: 512m", "read_only: true", "cap_drop: [ALL]", "- /var/run/dstack.sock:/var/run/dstack.sock"} {
		if !strings.Contains(out, want) {
			t.Errorf("kms-compose.yaml lacks %q", want)
		}
	}
	for _, bad := range []string{"\n    environment:", "${", "\nvolumes:", "env_file", "privileged"} {
		if strings.Contains(out, bad) {
			t.Errorf("kms-compose.yaml has %q", bad)
		}
	}
	// Its app-compose.json is the KMS fallback's, on port 8000 (server.KMSAppCompose checks the verifier's rules).
	ac, err := server.KMSAppCompose([]byte(out))
	if err != nil || !strings.Contains(string(ac), `"port":8000`) || !strings.Contains(string(ac), `"key_provider":"kms"`) {
		t.Fatalf("kms app-compose: %v", err)
	}
	// The agent VM's verifier never takes it for an agent VM release.
	if _, err := verifier.ComposeImages(out); err == nil {
		t.Fatal("the agent VM image rule accepts the key service compose")
	}
	// Without a KMS id it starts empty (genesis).
	if out, err := generateKMS(testKMSRef, strings.Repeat("ab", 32), KMSArgs{AdminKeys: adminKeys, AdminThreshold: 1}); err != nil || strings.Contains(out, "-kms-id") {
		t.Fatalf("genesis compose: %v", err)
	}
	for name, a := range map[string]KMSArgs{
		"no admin keys":    {AdminThreshold: 1},
		"threshold > keys": {AdminKeys: adminKeys, AdminThreshold: 2},
		"bad kms id":       {AdminKeys: adminKeys, AdminThreshold: 1, KMSID: "ed25519:xx"},
		"bad floor":        {AdminKeys: adminKeys, AdminThreshold: 1, Floor: "latest"},
		"http peer":        {AdminKeys: adminKeys, AdminThreshold: 1, Peers: "http://kms-2"},
		"bad role":         {AdminKeys: adminKeys, AdminThreshold: 1, Role: "leader"},
		// H3 (security review 2026-11-20): a staging key service has admin keys of its own.
		"staging under a production admin key": {AdminKeys: stagingKey + "," + adminKeys, AdminThreshold: 1, Staging: true},
	} {
		if _, err := generateKMS(testKMSRef, "00", a); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := generateKMS(Registry+"/kmsd:latest", "00", KMSArgs{AdminKeys: adminKeys, AdminThreshold: 1}); err == nil {
		t.Fatal("tagged image accepted")
	}
	// The role is a flag in the attested compose (the verifier matches it to the pin's role).
	if out, err := generateKMS(testKMSRef, "00", KMSArgs{AdminKeys: stagingKey, AdminThreshold: 1, Role: "standby", Staging: true}); err != nil ||
		!strings.Contains(out, `"-role", "standby"`) {
		t.Fatalf("a staging standby: %v", err)
	}
	if flags, err := server.KMSFlags(out); err != nil || flags["role"] != "primary" || flags["admin-keys"] != adminKeys {
		t.Fatalf("flags %v %v", flags, err)
	}
}

// stagingKey is a staging key service's own admin key (not a production one).
const stagingKey = "ed25519:1yGqNLlbr4e1e0SN64xq8J81Pdp6Ve0r7ZfMvN7w6hw="

// --kms-release: the production key service's flags come only from the pins (kmsAdminKeys, the release's KMS id).
func TestReleaseKMSArgs(t *testing.T) {
	if _, err := releaseKMSArgsWith("", 1, ""); err == nil {
		t.Fatal("an unpinned admin key accepted")
	}
	if _, err := releaseKMSArgsWith(stagingKey+","+adminKeys, 1, ""); err == nil {
		t.Fatal("a safety admin key accepted as the key service's")
	}
	a, err := releaseKMSArgsWith(stagingKey, 1, "")
	if err != nil || a.Staging || a.KMSID != "" || a.Role != "primary" || a.AdminThreshold != 1 {
		t.Fatalf("genesis release args %+v %v", a, err)
	}
	out, err := generateKMS(testKMSRef, "00", a)
	if err != nil || strings.Contains(out, "-staging") || strings.Contains(out, "-kms-id") {
		t.Fatalf("genesis release compose: %v", err)
	}
	id := "ed25519:" + strings.Repeat("A", 43) + "="
	if a, err := releaseKMSArgsWith(stagingKey, 1, id); err != nil || a.KMSID != id {
		t.Fatalf("locked release args %+v %v", a, err)
	}
	if kmsAdminKeys == "" {
		if _, err := releaseKMSArgs(); err == nil {
			t.Fatal("--kms-release accepted without kmsAdminKeys")
		}
	}
}
