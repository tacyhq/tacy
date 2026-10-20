package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"go.yaml.in/yaml/v3"

	"github.com/tacyhq/tacy/safety"
	"github.com/tacyhq/tacy/sandbox"
	"github.com/tacyhq/tacy/verifier"
)

// compose.yaml must be what the current source generates: the reproducible binaries, their images on the pinned
// base (fetched from its registry by digest), and the compose naming them. Skipped with -short (network, builds).
func TestComposeCurrent(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the binaries and fetches the base image")
	}
	os.Chdir("../..")
	rel, err := build()
	if err != nil {
		t.Fatal(err)
	}
	out, err := generate(rel)
	if err != nil {
		t.Fatal(err)
	}
	cur, _ := os.ReadFile("compose.yaml")
	if string(cur) != out {
		t.Fatal("compose.yaml is stale: run go run ./cmd/compose")
	}
}

func readCompose(t *testing.T) []byte {
	out, err := os.ReadFile("../../compose.yaml")
	if err != nil {
		out, err = os.ReadFile("compose.yaml") // TestComposeCurrent changed to the module root
	}
	if err != nil {
		t.Fatal(err)
	}
	return out
}

type service struct {
	Image       string            `yaml:"image"`
	Entrypoint  []string          `yaml:"entrypoint"`
	Command     []string          `yaml:"command"`
	NetworkMode string            `yaml:"network_mode"`
	User        string            `yaml:"user"`
	ReadOnly    bool              `yaml:"read_only"`
	CapDrop     []string          `yaml:"cap_drop"`
	CapAdd      []string          `yaml:"cap_add"`
	SecurityOpt []string          `yaml:"security_opt"`
	Ports       []string          `yaml:"ports"`
	Volumes     []string          `yaml:"volumes"`
	Environment map[string]string `yaml:"environment"`
	GroupAdd    []string          `yaml:"group_add"`
	DependsOn   map[string]struct {
		Condition string `yaml:"condition"`
	} `yaml:"depends_on"`
	Restart      string   `yaml:"restart"`
	Tmpfs        []string `yaml:"tmpfs"`
	MemLimit     string   `yaml:"mem_limit"`
	MemswapLimit string   `yaml:"memswap_limit"`
	PidsLimit    int      `yaml:"pids_limit"`
}

func services(t *testing.T) map[string]service {
	var doc struct {
		Services map[string]service `yaml:"services"`
		Volumes  map[string]any     `yaml:"volumes"`
	}
	dec := yaml.NewDecoder(bytes.NewReader(readCompose(t)))
	dec.KnownFields(true)
	if err := dec.Decode(&doc); err != nil {
		t.Fatal(err)
	}
	return doc.Services
}

// The process layout (docs/21, docs/22): only gatewayd (service agentvm) has a network; agentd, the runner (the
// brain's gVisor sandbox), vaultd and setup have none. The keys go to vaultd only, the run token to agentd only.
// Every image is ours, by digest, and runs the binary of its name. Only setup adds capabilities; only the runner
// has Docker's seccomp profile off.
func TestComposeLayout(t *testing.T) {
	out := readCompose(t)
	if len(out) > MaxCompose {
		t.Fatalf("compose.yaml is %d bytes (limit %d)", len(out), MaxCompose)
	}
	images, err := verifier.ComposeImages(string(out))
	if err != nil {
		t.Fatal(err)
	}
	byName := services(t)
	binOf := map[string]string{"setup": "setup", "agentd": "agentd", "runner": "runnerd", "agentvm": "gatewayd", "vaultd": "vaultd"}
	if len(byName) != len(binOf) || len(images) != len(binOf) {
		t.Fatalf("%d services", len(byName))
	}
	for name, bin := range binOf {
		s, ok := byName[name]
		if !ok {
			t.Fatalf("no service %s", name)
		}
		if !strings.HasPrefix(s.Image, Registry+"/"+bin+"@sha256:") || len(s.Entrypoint) != 1 || s.Entrypoint[0] != "/tacy/"+bin {
			t.Errorf("%s: image %s, entrypoint %v", name, s.Image, s.Entrypoint)
		}
		if (s.NetworkMode == "none") != (name != "agentvm") {
			t.Errorf("%s: network_mode %q", name, s.NetworkMode)
		}
		if (len(s.Ports) > 0) != (name == "agentvm") {
			t.Errorf("%s: published ports", name)
		}
		sec := []string{"no-new-privileges:true"}
		if name == "runner" {
			sec = append(sec, "seccomp:unconfined")
		}
		if !s.ReadOnly || len(s.CapDrop) != 1 || s.CapDrop[0] != "ALL" || strings.Join(s.SecurityOpt, ",") != strings.Join(sec, ",") {
			t.Errorf("%s isn't hardened: %v", name, s.SecurityOpt)
		}
		if (len(s.CapAdd) > 0) != (name == "setup") {
			t.Errorf("%s: cap_add %v", name, s.CapAdd)
		}
		for _, env := range []string{"TINFOIL_API_KEY", "TAVILY_API_KEY", "BRAVE_SEARCH_API_KEY", "EXA_API_KEY"} {
			if (s.Environment[env] == "${"+env+"}") != (name == "vaultd") {
				t.Errorf("%s: %s", name, env)
			}
		}
		if (s.Environment["AGENT_VM_TOKEN"] != "") != (name == "agentd") {
			t.Errorf("%s: AGENT_VM_TOKEN", name)
		}
		for _, v := range s.Volumes {
			if strings.Contains(v, "dstack.sock") && name != "agentd" {
				t.Errorf("%s mounts dstack's socket", name)
			}
		}
		if name == "setup" {
			if s.User != "0:0" || s.Restart != "no" || strings.Join(s.CapAdd, ",") != "CHOWN,DAC_OVERRIDE,FOWNER" || len(s.Environment) != 0 {
				t.Errorf("setup: user %q restart %q caps %v env %v", s.User, s.Restart, s.CapAdd, s.Environment)
			}
			continue
		}
		// No long-running process is root; each waits for setup.
		if s.User == "" || strings.HasPrefix(s.User, "0") || s.DependsOn["setup"].Condition != "service_completed_successfully" ||
			s.Restart != "unless-stopped" {
			t.Errorf("%s: user %q, depends_on %v, restart %q", name, s.User, s.DependsOn, s.Restart)
		}
	}
	if !strings.Contains(strings.Join(byName["agentd"].Volumes, " "), "/var/run/dstack.sock:/var/run/dstack.sock") {
		t.Error("agentd doesn't mount dstack's socket")
	}
	agentd, gw, setup := byName["agentd"], byName["agentvm"], strings.Join(byName["setup"].Command, " ")
	if agentd.User != agentdUID+":"+agentdUID || !strings.Contains(strings.Join(gw.Command, " "), "-agent-uid "+agentdUID+" ") {
		t.Error("agentd's uid and gatewayd's -agent-uid differ")
	}
	if byName["runner"].User != runnerdUID+":"+agentdUID || byName["vaultd"].User != vaultdUID+":"+gatewaydUID || gw.User != gatewaydUID+":"+gatewaydUID {
		t.Error("uids")
	}
	if strings.Join(agentd.GroupAdd, ",") != gatewaydUID {
		t.Errorf("agentd's groups %v", agentd.GroupAdd)
	}
	// agentd's queue directory and runnerd's socket directory, set by setup.
	if !strings.Contains(strings.Join(agentd.Command, " "), "-storage /state/agentd ") ||
		!strings.Contains(strings.Join(agentd.Command, " "), "-runner-socket /run/tacy/runner/runner.sock ") ||
		!strings.Contains(setup, "-tree /state/agentd="+agentdUID+":"+agentdUID+":0700") ||
		!strings.Contains(setup, "-dir /run/tacy/runner="+runnerdUID+":"+agentdUID+":0750") ||
		!strings.Contains(setup, "-dir /run/tacy/agent="+agentdUID+":"+gatewaydUID+":0770") ||
		!strings.Contains(setup, "-dir /run/tacy/vault="+vaultdUID+":"+gatewaydUID+":0750") ||
		!strings.Contains(setup, "-remove /state/queue.db ") {
		t.Errorf("setup: %s", setup)
	}
	// Each socket directory is mounted only by its two containers (and setup).
	for vol, who := range map[string]string{"agentsock": "agentd agentvm setup", "vaultsock": "agentvm setup vaultd",
		"runnersock": "agentd runner setup", "state": "agentd setup"} {
		var got []string
		for _, name := range []string{"agentd", "agentvm", "runner", "setup", "vaultd"} {
			for _, v := range byName[name].Volumes {
				if strings.HasPrefix(v, vol+":") {
					got = append(got, name)
				}
			}
		}
		if strings.Join(got, " ") != who {
			t.Errorf("volume %s mounted by %v", vol, got)
		}
	}
}

// The runner (docs/22): rootless runsc on systrap from its own image's gVisor, the pinned release and runsc named
// (runnerd refuses others), the brain from its image with its pin, only agentd's uid allowed, container limits that
// bound its sandboxes, an exec tmpfs for runsc's state and the brain's root, and nothing of the other processes:
// only its socket volume, no environment.
func TestComposeRunner(t *testing.T) {
	r := services(t)["runner"]
	cmd := " " + strings.Join(r.Command, " ") + " "
	brain := ""
	for _, ln := range strings.Split(string(readCompose(t)), "\n") {
		if f := strings.Fields(ln); len(f) == 3 && f[0] == "#" && f[1] == "brain" {
			brain = f[2]
		}
	}
	if len(brain) != 64 {
		t.Fatal("no brain hash in the header")
	}
	for _, want := range []string{" -socket /run/tacy/runner/runner.sock ", " -agent-uid " + agentdUID + " ",
		" -gvisor " + gvisorDir + " ", " -gvisor-release " + sandbox.GVisorRelease + " ", " -runsc-sha256 " + sandbox.GVisorFiles[0][1] + " ",
		" -brain /tacy/brain ", " -brain-sha256 " + brain + " ", " -dir /run/runner ", " -platform systrap ", " -rootless "} {
		if !strings.Contains(cmd, want) {
			t.Errorf("runner's command lacks %q: %s", want, cmd)
		}
	}
	if sandbox.CheckPins(sandbox.GVisorRelease, sandbox.GVisorFiles[0][1]) != nil || sandbox.CheckPins("20250101.0", sandbox.GVisorFiles[0][1]) == nil ||
		sandbox.CheckPins(sandbox.GVisorRelease, strings.Repeat("0", 64)) == nil {
		t.Error("CheckPins")
	}
	if r.MemLimit != runnerMem || r.MemswapLimit != runnerMem || fmt.Sprint(r.PidsLimit) != runnerPids {
		t.Errorf("limits %s %s %d", r.MemLimit, r.MemswapLimit, r.PidsLimit)
	}
	if strings.Join(r.Tmpfs, " ") != "/run/runner:exec,size=64m,mode=0700,uid="+runnerdUID+",gid="+agentdUID+" /tmp:size=16m" {
		t.Errorf("tmpfs %v", r.Tmpfs)
	}
	if strings.Join(r.Volumes, " ") != "runnersock:/run/tacy/runner" || len(r.Environment) != 0 || len(r.GroupAdd) != 0 || len(r.Ports) != 0 {
		t.Errorf("runner: volumes %v env %v groups %v", r.Volumes, r.Environment, r.GroupAdd)
	}
	// Nothing else privileged anywhere (the strict decoder above refuses unknown keys such as privileged, pid,
	// userns_mode, devices or cgroup).
	for _, ln := range strings.Split(string(readCompose(t)), "\n") {
		if strings.Contains(ln, "seccomp") && !strings.Contains(ln, `security_opt: ["no-new-privileges:true", "seccomp:unconfined"]`) {
			t.Errorf("seccomp line %q", ln)
		}
	}
	if n := strings.Count(string(readCompose(t)), "seccomp:unconfined"); n != 1 {
		t.Errorf("seccomp:unconfined %d times", n)
	}
}

// Phala refuses a compose with a refused word in it (terms of use).
func TestComposeNoRefusedWords(t *testing.T) {
	if w := refusedWord(string(readCompose(t))); w != "" {
		t.Fatalf("compose.yaml contains %q", w)
	}
}

// fakeBase stands in for the distroless base (offline): one layer, an OCI manifest.
func fakeBase(t *testing.T) v1.Image {
	t.Helper()
	img, err := buildImage(mutate.MediaType(empty.Image, types.OCIManifestSchema1), "base", []byte("base"))
	if err != nil {
		t.Fatal(err)
	}
	return img
}

// An image is the base plus one layer: /tacy/ (0755) and /tacy/<name> (0555), root-owned, time 0, nothing else;
// the entrypoint is the binary. The same binary gives the same digest; another binary another one. The OCI layout
// holds exactly that image.
func TestImageLayout(t *testing.T) {
	base := fakeBase(t)
	bin := []byte("\x7fELF not really a binary")
	img, err := buildImage(base, "agentd", bin)
	if err != nil {
		t.Fatal(err)
	}
	again, _ := buildImage(fakeBase(t), "agentd", append([]byte{}, bin...))
	other, _ := buildImage(base, "agentd", append(append([]byte{}, bin...), 0))
	d1, _ := img.Digest()
	d2, _ := again.Digest()
	d3, _ := other.Digest()
	if d1 != d2 || d1 == d3 {
		t.Fatalf("digests %s %s %s", d1, d2, d3)
	}
	layers, _ := img.Layers()
	baseLayers, _ := base.Layers()
	if len(layers) != len(baseLayers)+1 {
		t.Fatalf("%d layers on a %d-layer base", len(layers), len(baseLayers))
	}
	top := layers[len(layers)-1]
	if mt, _ := top.MediaType(); mt != types.OCILayer {
		t.Fatalf("layer media type %s", mt)
	}
	rc, err := top.Compressed()
	if err != nil {
		t.Fatal(err)
	}
	gz, err := gzip.NewReader(rc)
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(gz)
	var got []string
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if h.Uid != 0 || h.Gid != 0 || h.ModTime.Unix() != 0 || h.Uname != "" || h.Gname != "" {
			t.Errorf("%s: owner %d:%d %q:%q, time %v", h.Name, h.Uid, h.Gid, h.Uname, h.Gname, h.ModTime)
		}
		got = append(got, h.Name)
		switch h.Name {
		case "tacy/":
			if h.Mode != 0o755 || h.Typeflag != tar.TypeDir {
				t.Errorf("tacy/: %o", h.Mode)
			}
		case "tacy/agentd":
			b, _ := io.ReadAll(tr)
			if h.Mode != 0o555 || h.Typeflag != tar.TypeReg || !bytes.Equal(b, bin) {
				t.Errorf("tacy/agentd: mode %o", h.Mode)
			}
		default:
			t.Errorf("unexpected entry %s", h.Name)
		}
	}
	if len(got) != 2 {
		t.Fatalf("entries %v", got)
	}
	cf, _ := img.ConfigFile()
	if strings.Join(cf.Config.Entrypoint, " ") != "/tacy/agentd" || len(cf.Config.Cmd) != 0 || cf.Created.Unix() != 0 ||
		cf.History[len(cf.History)-1].Created.Unix() != 0 {
		t.Fatalf("config %+v", cf.Config)
	}
	if mt, _ := img.MediaType(); mt != types.OCIManifestSchema1 {
		t.Fatalf("manifest media type %s", mt)
	}
	dir := t.TempDir()
	if err := writeLayout(dir, img); err != nil {
		t.Fatal(err)
	}
	idx, err := layout.ImageIndexFromPath(dir)
	if err != nil {
		t.Fatal(err)
	}
	im, _ := idx.IndexManifest()
	if len(im.Manifests) != 1 || im.Manifests[0].Digest != d1 || len(im.Manifests[0].Annotations) != 0 {
		t.Fatalf("layout index %+v", im)
	}
}

// The binary layer is deterministic: the same bytes give the same gzip'd tar.
func TestBinaryLayerDeterministic(t *testing.T) {
	a, _ := binaryLayer("x", []byte("abc"))
	b, _ := binaryLayer("x", []byte("abc"))
	if !bytes.Equal(a, b) {
		t.Fatal("layer isn't deterministic")
	}
}

// layerEntries lists a gzip'd tar layer: name -> mode, and each file's sha256; it fails on anything not 0:0 at time 0.
func layerEntries(t *testing.T, gz []byte) (map[string]int64, map[string]string, []string) {
	t.Helper()
	zr, err := gzip.NewReader(bytes.NewReader(gz))
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(zr)
	modes, sums, order := map[string]int64{}, map[string]string{}, []string{}
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if h.Uid != 0 || h.Gid != 0 || h.ModTime.Unix() != 0 || h.Uname != "" || h.Gname != "" {
			t.Errorf("%s: owner %d:%d, time %v", h.Name, h.Uid, h.Gid, h.ModTime)
		}
		modes[h.Name] = h.Mode
		order = append(order, h.Name)
		if h.Typeflag == tar.TypeReg {
			b, _ := io.ReadAll(tr)
			s := sha256.Sum256(b)
			sums[h.Name] = hex.EncodeToString(s[:])
		}
	}
	return modes, sums, order
}

// A layer of several files: sorted, each after its directories (0755), files 0555; one file gives exactly the
// single-binary layer's bytes (the other images' digests don't move). Bad paths are refused.
func TestFilesLayer(t *testing.T) {
	gz, err := filesLayer([]file{{path: "runnerd", data: []byte("r")}, {path: "gvisor/gvisor-bin/x", data: []byte("x")}, {path: "brain", data: []byte("b")}, {path: "gvisor/runsc", data: []byte("s")}})
	if err != nil {
		t.Fatal(err)
	}
	modes, _, order := layerEntries(t, gz)
	want := "tacy/ tacy/brain tacy/gvisor/ tacy/gvisor/gvisor-bin/ tacy/gvisor/gvisor-bin/x tacy/gvisor/runsc tacy/runnerd"
	if strings.Join(order, " ") != want {
		t.Fatalf("entries %v", order)
	}
	for n, m := range modes {
		if (strings.HasSuffix(n, "/") && m != 0o755) || (!strings.HasSuffix(n, "/") && m != 0o555) {
			t.Errorf("%s: %o", n, m)
		}
	}
	one, _ := filesLayer([]file{{path: "agentd", data: []byte("a")}})
	bin, _ := binaryLayer("agentd", []byte("a"))
	if !bytes.Equal(one, bin) {
		t.Fatal("single-file layer differs")
	}
	for _, bad := range []string{"", "/abs", "dir/", "../x", "a/../../x"} {
		if _, err := filesLayer([]file{{path: bad, data: []byte("x")}}); err == nil {
			t.Errorf("path %q accepted", bad)
		}
	}
}

// gVisor in runnerd's image: exactly the pinned binaries from the pinned tarball and its license, under /tacy/gvisor; a tarball
// that isn't the pinned one is refused, wherever it comes from. Skipped with -short (downloads 167 MB once, then
// the user's cache).
func TestGVisorLayer(t *testing.T) {
	if testing.Short() {
		t.Skip("needs gVisor's release tarball")
	}
	tb, err := gvisorTarball()
	if err != nil {
		t.Fatal(err)
	}
	gz, err := gvisorLayer(tb)
	if err != nil {
		t.Fatal(err)
	}
	modes, sums, _ := layerEntries(t, gz)
	if len(modes) != 4+len(sandbox.GVisorFiles) || modes["tacy/"] != 0o755 || modes["tacy/gvisor/"] != 0o755 || modes["tacy/gvisor/gvisor-bin/"] != 0o755 {
		t.Fatalf("entries %v", modes)
	}
	// gVisor's license ships next to its binaries, read-only, the pinned text.
	if p := "tacy/gvisor/LICENSE"; sums[p] != gvisorLicenseSHA256 || modes[p] != 0o444 {
		t.Errorf("%s: %s %o", p, sums[p], modes[p])
	}
	for _, f := range sandbox.GVisorFiles {
		if p := "tacy/gvisor/" + f[0]; sums[p] != f[1] || modes[p] != 0o555 {
			t.Errorf("%s: %s %o", p, sums[p], modes[p])
		}
	}
	again, _ := gvisorLayer(tb)
	if !bytes.Equal(gz, again) {
		t.Fatal("gVisor layer isn't deterministic")
	}
	// Another tarball: refused by its hash; a damaged one (its pin aside) by the binaries' hashes or bzip2.
	bad := filepath.Join(t.TempDir(), "gvisor.tar.bz2")
	os.WriteFile(bad, append(append([]byte{}, tb[:len(tb)/2]...), 0), 0o644)
	t.Setenv("TACY_GVISOR_TARBALL", bad)
	if _, err := gvisorTarball(); err == nil || !strings.Contains(err.Error(), "isn't the pinned") {
		t.Fatalf("other tarball: %v", err)
	}
	cut := append([]byte{}, tb[:len(tb)/3]...)
	if _, err := gvisorLayer(cut); err == nil {
		t.Fatal("cut tarball accepted")
	}
}

// Keys v2 slice 5: the compose pins either the admin keys or the key log genesis (with the carried chat policy and
// the key log source for gatewayd), never both; and every guard process gets the same trust roots.
func TestTrustArgs(t *testing.T) {
	legacy := strings.Join(trustArgs(adminKeys, "", keylogCarry), " ")
	if !strings.Contains(legacy, "-admin-keys "+adminKeys) || strings.Contains(legacy, "-keylog") {
		t.Errorf("without a genesis: %s", legacy)
	}
	g := strings.Repeat("ab", 32)
	logged := strings.Join(trustArgs(adminKeys, g, keylogCarry), " ")
	if strings.Contains(logged, "-admin-keys") || !strings.Contains(logged, "-keylog-genesis "+g) || !strings.Contains(logged, "-keylog-carry "+keylogCarry) ||
		!strings.Contains(logged, "-operator-key "+operatorKey) {
		t.Errorf("with a genesis: %s", logged)
	}
	if keylogCarry != safety.ChatPolicyV1 || !strings.HasPrefix(keylogCarry, "e6f08a76") {
		t.Error("the carried document is the live chat policy")
	}
	if p := strings.Join(pullArgs(g), " "); !strings.Contains(p, "-keylog-url "+keylogURL) || !strings.Contains(p, "-safety-url "+safetyURL) {
		t.Errorf("gatewayd pulls: %s", p)
	}
	if p := strings.Join(pullArgs(""), " "); strings.Contains(p, "-keylog-url") {
		t.Errorf("no key log without a genesis: %s", p)
	}
	// The generated compose matches the constants: each of agentd, gatewayd and vaultd gets safetyArgs().
	out := string(readCompose(t))
	want := flowArgs(safetyArgs())
	if n := strings.Count(out, want); n != 3 {
		t.Errorf("safety args in %d services, want 3 (%s)", n, want)
	}
	if (keylogGenesis == "") == strings.Contains(out, "-keylog-genesis") {
		t.Error("compose.yaml and keylogGenesis disagree")
	}
}

// flowArgs is how args appear inside a service's command flow sequence.
func flowArgs(a []string) string {
	q := make([]string, len(a))
	for i, s := range a {
		q[i] = fmt.Sprintf("%q", s)
	}
	return strings.Join(q, ", ")
}
