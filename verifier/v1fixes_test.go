package verifier

import (
	"context"
	"strings"
	"testing"
)

// The release compose (compose.yaml) edited one way each: what a production verifier must refuse (review L1,
// 2026-11-21: a rushed pinned release reopening 8080 or turning dev checks off), and what the e2e levels still take.
func TestReleaseRefusesDevFlagsAndPorts(t *testing.T) {
	c := string(composeYAML(t))
	if _, err := ComposeImages(c); err != nil {
		t.Fatalf("compose.yaml: %v", err)
	}
	gw := `"-socket", "/run/tacy/agent/gateway.sock"`
	if !strings.Contains(c, gw) {
		t.Fatal("compose.yaml: no gatewayd -socket")
	}
	bad := map[string]string{
		"-listen":              strings.Replace(c, gw, `"-listen", ":8080", `+gw, 1),
		"--listen=":            strings.Replace(c, gw, `"--listen=:8080", `+gw, 1),
		"-dev-fixed-http":      strings.Replace(c, gw, `"-dev-fixed-http", `+gw, 1),
		"-tunnel-spike-routes": strings.Replace(c, gw, `"-tunnel-spike-routes", `+gw, 1),
		"-tunnel-confined":     strings.Replace(c, gw, `"-tunnel-confined", "/run/tacy/cft", `+gw, 1),
		"ports on gatewayd":    strings.Replace(c, "  agentvm:\n", "  agentvm:\n    ports: [\"8080:8080\"]\n", 1),
		"ports on agentd":      strings.Replace(c, "  agentd:\n", "  agentd:\n    ports: [\"9000:9000\"]\n", 1),
	}
	for name, b := range bad {
		if b == c {
			t.Fatalf("%s: the edit didn't apply", name)
		}
		if _, err := ComposeImages(b); err == nil {
			t.Errorf("%s: accepted by a production verifier", name)
		}
	}
	// The e2e levels (test tools, staging holders) still take the development composes (cmd/e2e reaches a throwaway
	// through Phala's 8080).
	for _, name := range []string{"-listen", "ports on gatewayd", "-dev-fixed-http"} {
		if _, err := ComposeImagesE2E(bad[name]); err != nil {
			t.Errorf("%s at the e2e level: %v", name, err)
		}
	}
	// agentd's own -listen-unix and -listen-uid aren't gatewayd's -listen.
	if !strings.Contains(c, `"-listen-unix"`) {
		t.Fatal("compose.yaml: agentd has no -listen-unix")
	}
	// A release without unlockd (the KMS releases live before v1) keeps its published 8080.
	old := "services:\n  agentvm:\n    image: ghcr.io/a/b" + d + "\n    ports: [\"8080:8080\"]\n    command: [\"-listen\", \":8080\"]\n"
	if _, err := ComposeImages(old); err != nil {
		t.Fatalf("a release without unlockd: %v", err)
	}
}

// Review H1: gatewayd's container may start as root with SETUID and SETGID only for the launcher (-tunnel-uid);
// nothing else.
func TestGatewaydLaunchException(t *testing.T) {
	c := string(composeYAML(t))
	if !strings.Contains(c, `"-`+TunnelUIDFlag+`"`) || !strings.Contains(c, "cap_add: [SETGID, SETUID]") {
		t.Fatal("compose.yaml: gatewayd isn't started by the launcher")
	}
	tu := `"-` + TunnelUIDFlag + `", "10006", `
	bad := map[string]string{
		"no -tunnel-uid":   strings.Replace(c, tu, "", 1),
		"another cap":      strings.Replace(c, "cap_add: [SETGID, SETUID]", "cap_add: [SETGID, SETUID, DAC_OVERRIDE]", 1),
		"cap_add ALL":      strings.Replace(c, "cap_add: [SETGID, SETUID]", "cap_add: [ALL]", 1),
		"no cap_drop":      strings.Replace(c, "    cap_drop: [ALL]\n    cap_add: [SETGID, SETUID]\n", "    cap_add: [SETGID, SETUID]\n", 1),
		"no no-new-privs":  strings.Replace(c, "    cap_add: [SETGID, SETUID]\n    security_opt: [\"no-new-privileges:true\"]\n", "    cap_add: [SETGID, SETUID]\n", 1),
		"confined variant": strings.Replace(c, tu, tu+`"-tunnel-confined", "/run/tacy/cft", `, 1),
		"caps on vaultd":   strings.Replace(c, "  vaultd:\n", "  vaultd:\n    cap_add: [SETUID]\n", 1),
	}
	for name, b := range bad {
		if b == c {
			t.Fatalf("%s: the edit didn't apply", name)
		}
		if _, err := ComposeImages(b); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// Root without the launcher's flag, even with no capabilities.
	root := "services:\n  agentvm:\n    image: ghcr.io/a/b" + d + "\n    user: \"0:0\"\n    cap_drop: [ALL]\n"
	if _, err := ComposeImages(root); err == nil {
		t.Error("gatewayd as root without the launcher: accepted")
	}
}

// Review L3: a split-key holder (Policy.RequireUnlockd) refuses a key release from a compose without unlockd;
// kmsd's release check (no RequireUnlockd) keeps the releases before v1.
func TestHolderRequiresUnlockd(t *testing.T) {
	fc := string(fallbackCompose(t))
	i, j := strings.Index(fc, "\n  unlockd:\n"), strings.Index(fc, "\nvolumes:\n")
	if i < 0 || j < i {
		t.Fatal("compose.yaml: no unlockd before volumes:")
	}
	noUnlockd := fc[:i] + fc[j:]
	if HasUnlockd(noUnlockd) {
		t.Fatal("unlockd still there")
	}
	c := bootWith(t, []byte(noUnlockd), true, nil, keyEvent(true))
	c.p.KeyRelease = true
	if _, err := Verify(context.Background(), c.a, c.nonce, c.p); err != nil {
		t.Fatalf("kmsd's release check of a release without unlockd: %v", err)
	}
	c.p.RequireUnlockd = true
	if _, err := Verify(context.Background(), c.a, c.nonce, c.p); err == nil || !strings.Contains(err.Error(), "unlockd") {
		t.Fatalf("a holder's check of a release without unlockd: %v", err)
	}
}
