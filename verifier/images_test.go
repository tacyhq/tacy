package verifier

import (
	"os"
	"strings"
	"testing"
)

const d = "@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func TestComposeImages(t *testing.T) {
	ok := "services:\n  a:\n    image: ghcr.io/tacyhq/tacy/agentd" + d + "\n  b:\n    image: localhost:5000/x/y-z" + d + "\nvolumes:\n  v:\n"
	images, err := ComposeImages(ok)
	if err != nil || len(images) != 2 || images["a"] != "ghcr.io/tacyhq/tacy/agentd"+d {
		t.Fatal(images, err)
	}
	// Anchors resolve to the same rule (a digest by alias is still a digest).
	if _, err := ComposeImages("x-img: &i ghcr.io/a/b" + d + "\nservices:\n  a:\n    image: *i\n"); err != nil {
		t.Fatal(err)
	}
	for name, bad := range map[string]string{
		"tag":                "services:\n  a:\n    image: ghcr.io/a/b:v1\n",
		"tag and digest":     "services:\n  a:\n    image: ghcr.io/a/b:v1" + d + "\n",
		"no registry path":   "services:\n  a:\n    image: busybox" + d + "\n",
		"short digest":       "services:\n  a:\n    image: ghcr.io/a/b@sha256:0123\n",
		"upper-case digest":  "services:\n  a:\n    image: ghcr.io/a/b" + strings.ToUpper(d) + "\n",
		"other algorithm":    "services:\n  a:\n    image: ghcr.io/a/b@sha512:" + strings.Repeat("0", 128) + "\n",
		"variable":           "services:\n  a:\n    image: ghcr.io/a/b@sha256:${DIGEST}\n",
		"variable name":      "services:\n  a:\n    image: ${IMAGE}\n",
		"build":              "services:\n  a:\n    image: ghcr.io/a/b" + d + "\n    build: .\n",
		"build only":         "services:\n  a:\n    build: .\n",
		"extends":            "services:\n  a:\n    image: ghcr.io/a/b" + d + "\n    extends:\n      file: other.yaml\n      service: x\n",
		"include":            "include:\n  - other.yaml\nservices:\n  a:\n    image: ghcr.io/a/b" + d + "\n",
		"no services":        "volumes:\n  v:\n",
		"service not a map":  "services:\n  a: ghcr.io/a/b" + d + "\n",
		"image not a string": "services:\n  a:\n    image: [ghcr.io/a/b" + d + "]\n",
		"two documents":      "services:\n  a:\n    image: ghcr.io/a/b" + d + "\n---\nservices:\n  b:\n    build: .\n",
		"duplicate key":      "services:\n  a:\n    image: ghcr.io/a/b" + d + "\n    image: ghcr.io/a/b:v1\n",
		"merge key build":    "x-b: &b\n  build: .\nservices:\n  a:\n    <<: *b\n    image: ghcr.io/a/b" + d + "\n",
		"newline":            "services:\n  a:\n    image: \"ghcr.io/a/b" + d + "\\n\"\n",
		"not yaml":           "services: [\n",
	} {
		if _, err := ComposeImages(bad); err == nil {
			t.Errorf("%s: accepted", name)
		}
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
