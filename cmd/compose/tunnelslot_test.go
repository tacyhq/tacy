package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/tacyhq/tacy/vault"
)

// The tunnel slot is chosen per release: writing the release compose needs --tunnel-slot (no default: two VMs on one
// slot share one tunnel), --check and --dev-out follow the committed compose, and the slot picks gatewayd's secret.
func TestTunnelSlot(t *testing.T) {
	onA := []byte(`command: ["/tacy/gatewayd", "-tunnel-secret", "CF_TUNNEL_TOKEN_VMA"]`)
	onB := []byte(`command: ["/tacy/gatewayd", "-tunnel-secret", "CF_TUNNEL_TOKEN_VMB"]`)
	ok := []struct {
		flag          string
		follow, check bool
		committed     []byte
		want          string
	}{
		{"a", false, false, onB, "a"}, // writing: the flag, whatever was committed
		{"b", false, false, onA, "b"},
		{"", true, true, onA, "a"}, // --check: the committed slot
		{"", true, true, onB, "b"},
		{"b", true, true, onB, "b"},
		{"", true, false, onB, "b"},  // --dev-out: the committed slot
		{"b", true, false, onA, "b"}, // or the other one, for a throwaway
		{"a", true, false, nil, "a"}, // a development compose without a committed one
	}
	for _, c := range ok {
		got, err := tunnelSlot(c.flag, c.follow, c.check, c.committed)
		if err != nil || got != c.want {
			t.Errorf("tunnelSlot(%q, follow %v, check %v, %s) = %q, %v; want %q", c.flag, c.follow, c.check, c.committed, got, err, c.want)
		}
	}
	bad := []struct {
		flag          string
		follow, check bool
		committed     []byte
		want          string
	}{
		{"", false, false, onA, "is required"}, // writing the release compose with no slot
		{"c", false, false, onA, "a or b"},
		{"A", false, false, onA, "a or b"},
		{"vm-a", true, true, onA, "a or b"},
		{"a", true, true, onB, "on slot b"},          // --check against a compose on the other slot
		{"", true, true, nil, "0 tunnel slots"},      // nothing committed to follow
		{"a", true, true, nil, "0 tunnel slots"},     // --check needs the committed compose
		{"", true, false, append(onA, onB...), "2 "}, // two slots named
	}
	for _, c := range bad {
		if got, err := tunnelSlot(c.flag, c.follow, c.check, c.committed); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("tunnelSlot(%q, follow %v, check %v, %s) = %q, %v; want an error with %q", c.flag, c.follow, c.check, c.committed, got, err, c.want)
		}
	}
	// The two slots are vault's two tunnel secrets, a then b, and the verifier's shape rule takes exactly those.
	if tunnelSlots["a"] != vault.TunnelSecrets[0] || tunnelSlots["b"] != vault.TunnelSecrets[1] || len(tunnelSlots) != len(vault.TunnelSecrets) {
		t.Fatalf("tunnelSlots %v isn't vault.TunnelSecrets %v", tunnelSlots, vault.TunnelSecrets)
	}
	// The repository's compose names one slot.
	cur, err := os.ReadFile("../../compose.yaml")
	if err != nil {
		cur, err = os.ReadFile("compose.yaml") // TestComposeCurrent changed to the module root
	}
	if err != nil {
		t.Fatal(err)
	}
	// Exactly one slot, a or b: v1's first release is on slot a, and a release on Google goes on the slot the live
	// release isn't on (RUNBOOK-gcp.md R2), so a release tree may name either.
	if s, err := committedSlot(cur); err != nil || (s != "a" && s != "b") {
		t.Fatalf("compose.yaml's slot: %q, %v", s, err)
	}
}

// setReleaseTunnel puts the slot's secret on gatewayd's command line, and refuses anything but a or b before it
// reads the binary.
func TestSetReleaseTunnelSlot(t *testing.T) {
	saved := cfd
	defer func() { cfd = saved }()
	bad := filepath.Join(t.TempDir(), "cloudflared")
	if err := os.WriteFile(bad, []byte("not cloudflared"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TACY_CLOUDFLARED_BIN", bad)
	for _, slot := range []string{"", "c", "vm-b"} {
		if err := setReleaseTunnel(false, slot); err == nil || !strings.Contains(err.Error(), "a or b") {
			t.Fatalf("slot %q: %v", slot, err)
		}
	}
	if err := setReleaseTunnel(false, "b"); err == nil || !strings.Contains(err.Error(), "isn't the pinned") {
		t.Fatalf("slot b with the wrong binary: %v", err)
	}
	cache, err := os.UserCacheDir()
	if err != nil {
		t.Skip("no cache dir")
	}
	bin := filepath.Join(cache, "tacy", "cloudflared-"+ReleaseCloudflaredVersion+"-linux-amd64")
	if _, err := os.Stat(bin); err != nil {
		t.Skip("the pinned cloudflared isn't cached (go run ./cmd/compose builds it)")
	}
	t.Setenv("TACY_CLOUDFLARED_BIN", bin)
	for slot, secret := range map[string]string{"a": "CF_TUNNEL_TOKEN_VMA", "b": "CF_TUNNEL_TOKEN_VMB"} {
		cfd = saved
		if err := setReleaseTunnel(false, slot); err != nil {
			t.Fatal(err)
		}
		a := cloudflaredArgs()
		if i := slices.Index(a, "-tunnel-secret"); i < 0 || a[i+1] != secret {
			t.Fatalf("slot %s: gatewayd's args %v", slot, a)
		}
	}
}

// The command refuses to write the release compose without --tunnel-slot, before anything is fetched or built, and
// the manifest records the slot.
func TestComposeNeedsTunnelSlot(t *testing.T) {
	dir := t.TempDir()
	cmd := exec.Command(os.Args[0], "-test.run=^$", "--")
	cmd.Dir = dir // no compose.yaml here: nothing to follow, nothing written over
	cmd.Env = append(os.Environ(), mainEnv+"=1", "TACY_CLOUDFLARED_BIN=/nonexistent")
	out, err := cmd.CombinedOutput()
	if err == nil || !strings.Contains(string(out), "--tunnel-slot a|b is required") {
		t.Fatalf("compose without --tunnel-slot: %v\n%s", err, out)
	}
	if _, err := os.Stat(filepath.Join(dir, "compose.yaml")); !os.IsNotExist(err) {
		t.Fatalf("a compose was written: %v", err)
	}
	j, _ := json.Marshal(Manifest{TunnelSlot: "b"})
	if !strings.Contains(string(j), `"tunnel_slot":"b"`) {
		t.Fatalf("the manifest: %s", j)
	}
}
