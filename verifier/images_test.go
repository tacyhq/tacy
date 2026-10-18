package verifier

import (
	"os"
	"strings"
	"testing"
)

const d = "@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func TestComposeImages(t *testing.T) {
	ok := "services:\n  agentd:\n    image: ghcr.io/tacyhq/tacy/agentd" + d + "\n  vaultd:\n    image: localhost:5000/x/y-z" + d + "\nvolumes:\n  v:\n"
	images, err := ComposeImages(ok)
	if err != nil || len(images) != 2 || images["agentd"] != "ghcr.io/tacyhq/tacy/agentd"+d {
		t.Fatal(images, err)
	}
	// Anchors resolve to the same rule (a digest by alias is still a digest).
	if _, err := ComposeImages("x-img: &i ghcr.io/a/b" + d + "\nservices:\n  agentd:\n    image: *i\n"); err != nil {
		t.Fatal(err)
	}
	for name, bad := range map[string]string{
		"tag":                "services:\n  agentd:\n    image: ghcr.io/a/b:v1\n",
		"tag and digest":     "services:\n  agentd:\n    image: ghcr.io/a/b:v1" + d + "\n",
		"no registry path":   "services:\n  agentd:\n    image: busybox" + d + "\n",
		"short digest":       "services:\n  agentd:\n    image: ghcr.io/a/b@sha256:0123\n",
		"upper-case digest":  "services:\n  agentd:\n    image: ghcr.io/a/b" + strings.ToUpper(d) + "\n",
		"other algorithm":    "services:\n  agentd:\n    image: ghcr.io/a/b@sha512:" + strings.Repeat("0", 128) + "\n",
		"variable":           "services:\n  agentd:\n    image: ghcr.io/a/b@sha256:${DIGEST}\n",
		"variable name":      "services:\n  agentd:\n    image: ${IMAGE}\n",
		"build":              "services:\n  agentd:\n    image: ghcr.io/a/b" + d + "\n    build: .\n",
		"build only":         "services:\n  agentd:\n    build: .\n",
		"extends":            "services:\n  agentd:\n    image: ghcr.io/a/b" + d + "\n    extends:\n      file: other.yaml\n      service: x\n",
		"include":            "include:\n  - other.yaml\nservices:\n  agentd:\n    image: ghcr.io/a/b" + d + "\n",
		"no services":        "volumes:\n  v:\n",
		"service not a map":  "services:\n  agentd: ghcr.io/a/b" + d + "\n",
		"image not a string": "services:\n  agentd:\n    image: [ghcr.io/a/b" + d + "]\n",
		"two documents":      "services:\n  agentd:\n    image: ghcr.io/a/b" + d + "\n---\nservices:\n  vaultd:\n    build: .\n",
		"duplicate key":      "services:\n  agentd:\n    image: ghcr.io/a/b" + d + "\n    image: ghcr.io/a/b:v1\n",
		"merge key build":    "x-b: &b\n  build: .\nservices:\n  agentd:\n    <<: *b\n    image: ghcr.io/a/b" + d + "\n",
		"newline":            "services:\n  agentd:\n    image: \"ghcr.io/a/b" + d + "\\n\"\n",
		"not yaml":           "services: [\n",
		"unknown service":    "services:\n  agentd:\n    image: ghcr.io/a/b" + d + "\n  miner:\n    image: ghcr.io/a/c" + d + "\n",
		"privileged":         "services:\n  agentd:\n    image: ghcr.io/a/b" + d + "\n    privileged: true\n",
		"pid host":           "services:\n  agentd:\n    image: ghcr.io/a/b" + d + "\n    pid: host\n",
		"pid service":        "services:\n  vaultd:\n    image: ghcr.io/a/b" + d + "\n    pid: \"service:agentd\"\n",
		"e2e diag":           "services:\n  agentd:\n    image: ghcr.io/a/b" + d + "\n  e2ediag:\n    image: ghcr.io/a/c" + d + "\n    pid: host\n",
		"e2e model fault":    "services:\n  agentvm:\n    image: ghcr.io/a/b" + d + "\n    command: [\"-socket\", \"/s\", \"-e2e-model-fault\", \"kimi-k3=slow\"]\n",
	} {
		if _, err := ComposeImages(bad); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// The e2e tools accept the overlay's diag service with its pid namespace, still never privileged or another
// unknown service; this folder's compose (a v0.8.x release) passes the browser's rule.
func TestComposeImagesE2E(t *testing.T) {
	diag := "services:\n  agentd:\n    image: ghcr.io/a/b" + d + "\n  e2ediag:\n    image: ghcr.io/a/c" + d + "\n    pid: host\n"
	if _, err := ComposeImagesE2E(diag); err != nil {
		t.Fatal(err)
	}
	// The overlay's fake slow models (gatewayd -e2e-model-fault) are the e2e tools' only.
	if _, err := ComposeImagesE2E(diag + "  agentvm:\n    image: ghcr.io/a/e" + d + "\n    command: [\"-e2e-model-fault\", \"kimi-k3=slow\"]\n"); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{diag + "    privileged: true\n", diag + "  miner:\n    image: ghcr.io/a/d" + d + "\n",
		strings.Replace(diag, "  agentd:\n    image: ghcr.io/a/b"+d+"\n", "  agentd:\n    image: ghcr.io/a/b"+d+"\n    pid: host\n", 1)} {
		if _, err := ComposeImagesE2E(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	compose, err := os.ReadFile("../compose.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if images, err := ComposeImages(string(compose)); err != nil || len(images) != 5 {
		t.Fatalf("this folder's compose: %v %v", images, err)
	}
}

// The brain's sandbox, read from the runner's arguments in this folder's compose; none from a compose without a
// runner, or with arguments that don't look like a release, a platform or a hash.
func TestSandboxFacts(t *testing.T) {
	compose, err := os.ReadFile("../compose.yaml")
	if err != nil {
		t.Fatal(err)
	}
	f := SandboxFacts(string(compose))
	if !strings.HasPrefix(f["brain sandbox"], "gVisor ") || !strings.HasSuffix(f["brain sandbox"], " (systrap, rootless runsc), no network") ||
		len(f["gvisor runsc sha256"]) != 64 || len(f["brain binary sha256"]) != 64 || f["gvisor release"] == "" ||
		!strings.Contains(string(compose), `"-runsc-sha256", "`+f["gvisor runsc sha256"]+`"`) {
		t.Fatalf("facts %v", f)
	}
	runner := func(cmd string) string {
		return "services:\n  runner:\n    image: ghcr.io/a/b" + d + "\n    network_mode: none\n    command: [" + cmd + "]\n"
	}
	h := strings.Repeat("ab", 32)
	if f := SandboxFacts(runner(`"-gvisor-release", "20260928.0", "-platform", "ptrace", "-runsc-sha256", "` + h + `"`)); f["brain sandbox"] !=
		"gVisor 20260928.0 (ptrace), no network" || f["gvisor runsc sha256"] != h || f["brain binary sha256"] != "" {
		t.Fatalf("not rootless: %v", f)
	}
	for name, c := range map[string]string{
		"no runner":     "services:\n  brain:\n    image: ghcr.io/a/b" + d + "\n",
		"no release":    runner(`"-platform", "systrap", "-rootless"`),
		"odd release":   runner(`"-gvisor-release", "latest", "-platform", "systrap"`),
		"odd platform":  runner(`"-gvisor-release", "20260928.0", "-platform", "Sys trap"`),
		"not yaml":      "services: [\n",
		"flag as value": runner(`"-gvisor-release", "-platform", "systrap"`),
	} {
		if f := SandboxFacts(c); len(f) != 0 {
			t.Errorf("%s: %v", name, f)
		}
	}
	if f := SandboxFacts(runner(`"-gvisor-release", "20260928.0", "-platform", "systrap", "-runsc-sha256", "abc"`)); f["gvisor runsc sha256"] != "" || f["gvisor release"] == "" {
		t.Errorf("short hash: %v", f)
	}
}
