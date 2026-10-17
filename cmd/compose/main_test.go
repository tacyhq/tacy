package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"strings"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"go.yaml.in/yaml/v3"

	"github.com/tacyhq/tacy/verifier"
)

// compose.yaml must be what the current source generates: the reproducible binaries, their images on the pinned
// base (fetched from its registry by digest), and the compose naming them. Skipped with -short (network, builds).
func TestComposeCurrent(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the binaries and fetches the base image")
	}
	os.Chdir("../..")
	images, err := build()
	if err != nil {
		t.Fatal(err)
	}
	out, err := generate(images)
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
	Restart string   `yaml:"restart"`
	Tmpfs   []string `yaml:"tmpfs"`
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

// The process layout of docs/21: only gatewayd (service agentvm) has a network; agentd, the brain, vaultd and setup
// have none. The keys go to vaultd only, the run token to agentd only. Every image is ours, by digest, and runs
// the binary of its name.
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
	binOf := map[string]string{"setup": "setup", "agentd": "agentd", "brain": "brain", "agentvm": "gatewayd", "vaultd": "vaultd"}
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
		if !s.ReadOnly || len(s.CapDrop) != 1 || s.CapDrop[0] != "ALL" || len(s.SecurityOpt) != 1 || s.SecurityOpt[0] != "no-new-privileges:true" {
			t.Errorf("%s isn't hardened", name)
		}
		if (len(s.CapAdd) > 0) != (name == "setup") {
			t.Errorf("%s: cap_add %v", name, s.CapAdd)
		}
		for _, env := range []string{"TINFOIL_API_KEY", "TAVILY_API_KEY", "BRAVE_SEARCH_API_KEY"} {
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
	if byName["brain"].User != brainUID+":"+brainUID || byName["vaultd"].User != vaultdUID+":"+gatewaydUID || gw.User != gatewaydUID+":"+gatewaydUID {
		t.Error("uids")
	}
	// agentd's queue directory and the brain's socket directory are its own, set by setup.
	if !strings.Contains(strings.Join(agentd.Command, " "), "-storage /state/agentd ") ||
		!strings.Contains(setup, "-tree /state/agentd="+agentdUID+":"+agentdUID+":0700") ||
		!strings.Contains(setup, "-dir /run/tacy/brain="+agentdUID+":"+brainUID+":0750") ||
		!strings.Contains(setup, "-dir /run/tacy/agent="+agentdUID+":"+gatewaydUID+":0770") ||
		!strings.Contains(setup, "-dir /run/tacy/vault="+vaultdUID+":"+gatewaydUID+":0750") ||
		!strings.Contains(setup, "-remove /state/queue.db ") {
		t.Errorf("setup: %s", setup)
	}
	// Each socket directory is mounted only by its two containers (and setup).
	for vol, who := range map[string]string{"agentsock": "agentd agentvm setup", "vaultsock": "agentvm setup vaultd",
		"brainsock2": "agentd brain setup", "state": "agentd setup"} {
		var got []string
		for _, name := range []string{"agentd", "agentvm", "brain", "setup", "vaultd"} {
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
