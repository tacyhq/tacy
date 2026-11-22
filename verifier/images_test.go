package verifier

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
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

// Review L1 (2026-11-21): no service has more than its own container, whatever else a verifier pins. Each case is
// one key on agentd (or the named service) of an otherwise accepted compose; the release's own exceptions are
// named: setup's three capabilities after cap_drop ALL and the runner's seccomp unconfined (gVisor).
func TestServicePrivileges(t *testing.T) {
	svc := func(name, extra string) string {
		return "services:\n  " + name + ":\n    image: ghcr.io/a/b" + d + "\n" + extra
	}
	for name, ok := range map[string]string{
		"setup's capabilities":   svc("setup", "    cap_drop: [ALL]\n    cap_add: [CHOWN, DAC_OVERRIDE, FOWNER]\n"),
		"setup's, CAP_ prefixed": svc("setup", "    cap_drop: [ALL]\n    cap_add: [CAP_CHOWN]\n"),
		"runner's seccomp":       svc("runner", "    security_opt: [\"no-new-privileges:true\", \"seccomp:unconfined\"]\n"),
		"no network":             svc("agentd", "    network_mode: none\n"),
		"no-new-privileges":      svc("agentd", "    security_opt: [\"no-new-privileges:true\"]\n"),
		"cap_drop only":          svc("agentd", "    cap_drop: [ALL]\n"),
		"the release's compose.yaml": func() string {
			b, err := os.ReadFile("../compose.yaml")
			if err != nil {
				t.Fatal(err)
			}
			return string(b)
		}(),
	} {
		if _, err := ComposeImages(ok); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	for name, bad := range map[string]string{
		"cap_add":                   svc("agentd", "    cap_drop: [ALL]\n    cap_add: [NET_ADMIN]\n"),
		"cap_add ALL":               svc("agentd", "    cap_add: [ALL]\n"),
		"setup without cap_drop":    svc("setup", "    cap_add: [CHOWN]\n"),
		"setup, another capability": svc("setup", "    cap_drop: [ALL]\n    cap_add: [CHOWN, SYS_ADMIN]\n"),
		"privileged":                svc("agentd", "    privileged: true\n"),
		"network host":              svc("agentd", "    network_mode: host\n"),
		"another container's net":   svc("agentd", "    network_mode: \"service:agentvm\"\n"),
		"pid host":                  svc("agentd", "    pid: host\n"),
		"ipc host":                  svc("agentd", "    ipc: host\n"),
		"uts host":                  svc("agentd", "    uts: host\n"),
		"userns host":               svc("agentd", "    userns_mode: host\n"),
		"cgroup host":               svc("agentd", "    cgroup: host\n"),
		"devices":                   svc("agentd", "    devices: [\"/dev/vda:/dev/vda\"]\n"),
		"device cgroup rules":       svc("agentd", "    device_cgroup_rules: [\"b *:* rwm\"]\n"),
		"volumes_from":              svc("agentd", "    volumes_from: [unlockd]\n"),
		"service configs":           svc("agentd", "    configs: [c]\n"),
		"service secrets":           svc("agentd", "    secrets: [s]\n"),
		"top-level configs file":    svc("agentd", "") + "configs:\n  c:\n    file: /etc/shadow\n",
		"top-level secrets file":    svc("agentd", "") + "secrets:\n  s:\n    file: /dstack/.host-shared/.appkeys.json\n",
		"seccomp unconfined":        svc("agentd", "    security_opt: [\"seccomp:unconfined\"]\n"),
		"apparmor unconfined":       svc("runner", "    security_opt: [\"apparmor:unconfined\"]\n"),
		"label disable":             svc("agentd", "    security_opt: [\"label:disable\"]\n"),
		"systempaths unconfined":    svc("agentd", "    security_opt: [\"systempaths=unconfined\"]\n"),
		"sysctls":                   svc("agentd", "    sysctls: {net.ipv4.ip_forward: 1}\n"),
		"another runtime":           svc("agentd", "    runtime: runc\n"),
		"security_opt not a list":   svc("agentd", "    security_opt: seccomp:unconfined\n"),
	} {
		_, err := ComposeImages(bad)
		if err == nil {
			t.Errorf("%s: accepted", name)
			continue
		}
		// The e2e diag's exceptions are its own: the same key on a release service is refused there too.
		if _, err := ComposeImagesE2ERoot(bad); err == nil {
			t.Errorf("%s: accepted with the e2e root exception", name)
		}
	}
}

// The e2e diag service's two named exceptions (review L1): the overlay's bounded one (E2EDiagException, which a
// staging key service or staging holders may allow), and the push diag's root one (E2EDiagRootException), which
// only cmd/e2e fixb asks for. A staging policy (ComposeImagesE2E) refuses the push diag; a production one
// (ComposeImages) refuses both.
func TestE2EDiagExceptions(t *testing.T) {
	base := "services:\n  agentd:\n    image: ghcr.io/a/b" + d + "\n  e2ediag:\n    image: ghcr.io/a/c" + d + "\n"
	httpd := base + "    pid: \"host\"\n    user: \"0:0\"\n    read_only: true\n    cap_drop: [ALL]\n    cap_add: [KILL, DAC_READ_SEARCH, SYS_PTRACE]\n" +
		"    security_opt: [\"no-new-privileges:true\"]\n    volumes:\n      - \"/:/host:ro,rslave\"\n"
	runnerPID := strings.Replace(httpd, `pid: "host"`, `pid: "service:runner"`, 1)
	push := base + "    pid: \"host\"\n    network_mode: host\n    user: \"0:0\"\n    cap_add: [ALL]\n    security_opt: [\"seccomp:unconfined\"]\n" +
		"    device_cgroup_rules: [\"b *:* rwm\", \"c 10:* rwm\", \"c 1:11 w\"]\n    volumes:\n      - \"/:/host:ro,rslave\"\n"
	for _, c := range []struct {
		name            string
		compose         string
		prod, e2e, root bool // accepted by ComposeImages, ComposeImagesE2E, ComposeImagesE2ERoot
	}{
		{"the overlay's httpd diag", httpd, false, true, true},
		{"its pid in the runner's namespace", runnerPID, false, true, true},
		{"fixb's push diag", push, false, false, true},
		{"httpd diag with another capability", strings.Replace(httpd, "SYS_PTRACE]", "SYS_PTRACE, SYS_ADMIN]", 1), false, false, true},
		{"httpd diag without cap_drop", strings.Replace(httpd, "    cap_drop: [ALL]\n", "", 1), false, false, true},
		{"httpd diag on the host network", httpd + "    network_mode: host\n", false, false, true},
		{"httpd diag with seccomp unconfined", strings.Replace(httpd, `["no-new-privileges:true"]`, `["seccomp:unconfined"]`, 1), false, false, true},
		{"httpd diag with block devices", httpd + "    device_cgroup_rules: [\"b *:* rwm\"]\n", false, false, true},
		{"push diag privileged", push + "    privileged: true\n", false, false, false},
		{"push diag with devices", push + "    devices: [\"/dev/vda\"]\n", false, false, false},
		{"push diag in another container's pid", strings.Replace(push, `pid: "host"`, `pid: "service:agentd"`, 1), false, false, false},
	} {
		for _, f := range []struct {
			what string
			fn   func(string) (map[string]string, error)
			want bool
		}{{"production", ComposeImages, c.prod}, {"e2e (staging)", ComposeImagesE2E, c.e2e}, {"e2e root (fixb)", ComposeImagesE2ERoot, c.root}} {
			if _, err := f.fn(c.compose); (err == nil) != f.want {
				t.Errorf("%s, %s: accepted %v, want %v (%v)", c.name, f.what, err == nil, f.want, err)
			}
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
	if images, err := ComposeImages(string(compose)); err != nil || len(images) != 6 {
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

// The root exception is the e2e tool's alone (review L1): outside this package and cmd/e2e, no production code
// names Policy.AllowE2EDiagRoot or ComposeImagesE2ERoot (a key service's, a holder's, the browser's verifier, and
// kms.Policy, whose signed documents could otherwise turn it on). Tests may.
func TestE2EDiagRootOnlyInTestTools(t *testing.T) {
	roots := []string{".."}
	if _, err := os.Stat("../../key-holders"); err == nil {
		roots = append(roots, "../../key-holders")
	}
	n := 0
	for _, root := range roots {
		filepath.WalkDir(root, func(p string, e fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if e.IsDir() && (e.Name() == "vendor" || e.Name() == "node_modules" || strings.HasPrefix(e.Name(), ".")) && p != root {
				return filepath.SkipDir
			}
			if e.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
				return nil
			}
			n++
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			rel := filepath.ToSlash(p)
			allowed := filepath.Dir(rel) == "../verifier" || filepath.Dir(rel) == "../cmd/e2e"
			if !allowed && (bytes.Contains(b, []byte("AllowE2EDiagRoot")) || bytes.Contains(b, []byte("ComposeImagesE2ERoot"))) {
				t.Errorf("%s names the e2e diag's root exception", rel)
			}
			return nil
		})
	}
	if n < 100 {
		t.Fatalf("walked only %d Go files", n)
	}
}
