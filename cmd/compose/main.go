// compose writes compose.yaml for the agent VM and builds the OCI images it runs. Each binary is built
// reproducibly (linux/amd64, CGO off, -trimpath, -buildvcs=false, the Go version of the pinned toolchain image) and
// becomes one image: the pinned distroless base plus one layer holding only the binary (fixed times, owner 0:0,
// mode 0555). Same binaries, same base: same image digests, on any machine. The compose names every image by
// digest only (no tag, no build:), so the CVM's attested compose hash covers exactly the binaries that run.
//
// Four processes (docs/21-gateway-v0.md), each its own container with its own uid, linked only by unix
// sockets in volumes shared by exactly two containers:
//
//   - agentd (./app, service "agentd"): the front door and the runtime (journal and queue, the harness to the
//     brain). No network at all (network_mode none) and no keys: it gets only AGENT_VM_TOKEN, which it checks.
//   - brain (./cmd/brain): our agent loop, untrusted. No network, uid 65534, no secrets; its only link is agentd's
//     socket (harness/v1).
//   - gatewayd (./cmd/gatewayd, service "agentvm"): the only container with a network. The model gateway and the
//     web connector; it leases each key from vaultd per call, scans and redacts (leakscan), and forwards the
//     published port to agentd's HTTP socket. The service keeps the name "agentvm" because it owns port 8080, as
//     the old single container did: an update or a rollback recreates it in place, whatever dstack does with
//     services a compose no longer names.
//   - vaultd (./cmd/vaultd): holds the keys (the only container given TINFOIL_API_KEY and the search keys), no
//     network, releases one key per call to gatewayd's uid only, for a granted connector and exact host.
//
// A one-shot "setup" container (./cmd/setup: root, no network, three capabilities) gives the processes their
// directories on the shared volumes first; every other container waits for it to exit cleanly.
//
//	go run ./cmd/compose                  # after editing anything the binaries build from
//	go run ./cmd/compose --check          # verify compose.yaml matches the source (no write)
//	go run ./cmd/compose --oci DIR        # also write each image as an OCI layout, DIR/<name> (the release pushes them)
//	go run ./cmd/compose --check --manifest release.json --version v0.2.0 --commit <sha>
//	                                      # also write the release manifest (release.yml, scripts/reproduce.sh)
//
// The compose hash is sha256(compose.yaml): dstack puts the file unchanged in app-compose.json as
// docker_compose_file (whose own hash is the attested compose-hash), and the verifier hashes that string. It is the
// subject a release signs, together with release.json and the image digests.
package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"github.com/google/go-containerregistry/pkg/v1/types"

	"github.com/tacyhq/tacy/verifier"
)

// Go toolchain image, pinned by digest. Its Go version must equal mise.toml's: the binaries are built with that
// version, natively or in this container (release.yml and scripts/reproduce.sh build in it), and give the same bytes.
const image = "golang:1.27.2-alpine@sha256:f92b6ef800e499660581efdabdf25d9d817a9d124eaf900924f0504e7e27e12d"

// baseImage is every image's base: Google's distroless static (Debian 13, tag nonroot: no shell, no package manager;
// CA certificates, /etc/passwd, /tmp), pinned by its linux/amd64 manifest digest. A new digest is a reviewed change.
const baseImage = "gcr.io/distroless/static-debian13@sha256:2293b36c7c9082bf4115aab724b4d2cddec82c8eba39bf27ac0517e159acf150"

// Registry is where the release pushes the images; the compose names them here, by digest.
const Registry = "ghcr.io/tacyhq/tacy"

const modulePath = "github.com/tacyhq/tacy"

// The CVM's Phala encrypted environment variables (names only; values never touch the compose), by the one
// container each goes to: the keys to vaultd only, the run token to agentd (it checks it, never sends it), the
// search provider choice (not a secret) to gatewayd. The brain and setup get none.
var (
	vaultEnv   = []string{"TINFOIL_API_KEY", "BRAVE_SEARCH_API_KEY", "TAVILY_API_KEY"}
	agentEnv   = []string{"AGENT_VM_TOKEN"}
	gatewayEnv = []string{"SEARCH_PROVIDER"}
)

// uids. Each process has its own; none is root (agentd was until VM release 2). Each socket is 0660, owned by the
// process that listens, with the group of the one peer (also checked by uid with SO_PEERCRED). agentd needs no
// root: dstack's guest agent socket is mode 0777 (dstack v0.6.1, os/common/rootfs/dstack-guest-agent.socket,
// SocketMode=0777; the guest agent doesn't check the caller's uid), and setup gives agentd its queue directory and
// its socket directories.
//
// Rollback: an older compose runs agentd as root without capabilities (no DAC override), which can't open files
// this uid owns with mode 0600. So the new layout leaves what an older agentd uses as it was: the queue moves to
// /state/agentd (the older one used /state/queue.db, which setup removes; the runs it held ended with the process
// anyway), and the brain's socket directory is a new volume (brainsock2; brainsock stays root's). The agent socket
// directory is reset at every start, so it needs nothing. The build-on-CVM composes' volumes (bin, gocache, gomod)
// aren't named here and stay on disk unused, so a rollback to one finds its cached binaries.
const (
	agentdUID   = "10003"
	brainUID    = "65534" // nobody
	gatewaydUID = "10001"
	vaultdUID   = "10002"
)

// bins are the binaries, one image each: name (the image's name under Registry and its path /tacy/<name>) and
// package. Adding one: an entry here and a service below that uses its image (README "Adding a process or binary").
var bins = []struct{ name, pkg string }{
	{"agentd", "./app"},
	{"brain", "./cmd/brain"},
	{"gatewayd", "./cmd/gatewayd"},
	{"setup", "./cmd/setup"},
	{"vaultd", "./cmd/vaultd"},
}

func run(env []string, name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	cmd.Env = append(os.Environ(), env...)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("%s %v: %v\n%s", name, args, err, errb.String())
	}
	return out.String(), nil
}

// target is the CVM's platform (peer_linux.go, not peer_other.go).
var target = []string{"CGO_ENABLED=0", "GOOS=linux", "GOARCH=amd64", "GOAMD64=v1", "GOFLAGS=", "GOEXPERIMENT="}

// goVersion is the toolchain image's Go version ("go1.27.2").
func goVersion() string {
	return "go" + strings.SplitN(strings.TrimPrefix(image, "golang:"), "-", 2)[0]
}

// buildBinary builds pkg for the CVM and returns the binary.
func buildBinary(pkg string) ([]byte, error) {
	tmp, err := os.MkdirTemp("", "agentvm-build")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmp)
	bin := filepath.Join(tmp, "bin")
	if _, err := run(target, "go", "build", "-trimpath", "-buildvcs=false", "-o", bin, pkg); err != nil {
		return nil, err
	}
	return os.ReadFile(bin)
}

// epoch is every time in a layer and in the image config.
var epoch = time.Unix(0, 0).UTC()

// binaryLayer is a deterministic gzip'd tar holding /tacy/ (0755) and /tacy/<name> (0555), owner 0:0, time 0.
// compress/gzip's output depends only on the input and the Go version, which is pinned.
func binaryLayer(name string, bin []byte) ([]byte, error) {
	var buf bytes.Buffer
	gz, err := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if err != nil {
		return nil, err
	}
	tw := tar.NewWriter(gz)
	for _, h := range []*tar.Header{
		{Name: "tacy/", Typeflag: tar.TypeDir, Mode: 0o755},
		{Name: "tacy/" + name, Typeflag: tar.TypeReg, Mode: 0o555, Size: int64(len(bin))},
	} {
		h.ModTime, h.Format = epoch, tar.FormatUSTAR
		if err := tw.WriteHeader(h); err != nil {
			return nil, err
		}
		if h.Typeflag == tar.TypeReg {
			if _, err := tw.Write(bin); err != nil {
				return nil, err
			}
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// buildImage is base plus the binary's layer, with /tacy/<name> as the entrypoint and fixed times. The digest
// depends only on base and bin.
func buildImage(base v1.Image, name string, bin []byte) (v1.Image, error) {
	gz, err := binaryLayer(name, bin)
	if err != nil {
		return nil, err
	}
	layer, err := tarball.LayerFromOpener(func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(gz)), nil },
		tarball.WithMediaType(types.OCILayer))
	if err != nil {
		return nil, err
	}
	img, err := mutate.Append(base, mutate.Addendum{Layer: layer, MediaType: types.OCILayer,
		History: v1.History{Created: v1.Time{Time: epoch}, CreatedBy: "tacy cmd/compose: /tacy/" + name}})
	if err != nil {
		return nil, err
	}
	cf, err := img.ConfigFile()
	if err != nil {
		return nil, err
	}
	cf = cf.DeepCopy()
	cf.Created = v1.Time{Time: epoch}
	cf.Config.Entrypoint = []string{"/tacy/" + name}
	cf.Config.Cmd = nil
	return mutate.ConfigFile(img, cf)
}

// fetchBase gets the base image by digest from its registry, anonymously (the digest is checked on every read).
func fetchBase() (v1.Image, error) {
	ref, err := name.NewDigest(baseImage)
	if err != nil {
		return nil, err
	}
	img, err := remote.Image(ref, remote.WithAuth(authn.Anonymous))
	if err != nil {
		return nil, fmt.Errorf("base image %s: %w", baseImage, err)
	}
	if mt, err := img.MediaType(); err != nil || mt != types.OCIManifestSchema1 {
		return nil, fmt.Errorf("base image %s: media type %q (want one platform's OCI manifest): %v", baseImage, mt, err)
	}
	cf, err := img.ConfigFile()
	if err != nil || cf.OS != "linux" || cf.Architecture != "amd64" {
		return nil, fmt.Errorf("base image %s isn't linux/amd64: %v", baseImage, err)
	}
	return img, nil
}

// Image is one built binary and its image.
type Image struct {
	Name   string
	SHA256 string // the binary's
	Ref    string // Registry/<name>@sha256:<digest>
	img    v1.Image
}

// MaxCompose is the most compose.yaml may take: Phala refuses a compose that, with its pre-launch script (~1 KiB),
// is over 200 KiB. Kept with some room.
const MaxCompose = 196 << 10

// refusedWords are words Phala refuses anywhere in a compose, case-insensitively, whatever the context:
// provisioning answers 400 "You are not allowed to deploy the target applications since it violates our terms of
// use". "frp" (a tunneling tool's name) is one. Found 2026-10-16 by bisecting the compose against Phala's provision
// endpoint, which creates nothing until a commit. Add a word here if Phala ever refuses a compose for it.
var refusedWords = []string{"frp"}

// refusedWord returns the first refused word some line of s contains, or "".
func refusedWord(s string) string {
	for _, ln := range strings.Split(strings.ToLower(s), "\n") {
		for _, w := range refusedWords {
			if strings.Contains(ln, w) {
				return w
			}
		}
	}
	return ""
}

// build builds every binary and its image.
func build() ([]Image, error) {
	if v, err := run(nil, "go", "env", "GOVERSION"); err != nil || strings.TrimSpace(v) != goVersion() {
		return nil, fmt.Errorf("go is %q, want %s (the toolchain image's; reproducible binaries need the same version): %v",
			strings.TrimSpace(v), goVersion(), err)
	}
	base, err := fetchBase()
	if err != nil {
		return nil, err
	}
	var out []Image
	for _, b := range bins {
		bin, err := buildBinary(b.pkg)
		if err != nil {
			return nil, err
		}
		img, err := buildImage(base, b.name, bin)
		if err != nil {
			return nil, err
		}
		d, err := img.Digest()
		if err != nil {
			return nil, err
		}
		h := sha256.Sum256(bin)
		out = append(out, Image{Name: b.name, SHA256: hex.EncodeToString(h[:]), Ref: Registry + "/" + b.name + "@" + d.String(), img: img})
	}
	return out, nil
}

// generate returns compose.yaml for the images.
func generate(images []Image) (string, error) {
	ref := map[string]string{}
	for _, im := range images {
		ref[im.Name] = im.Ref
	}
	var b strings.Builder
	b.WriteString(`# Generated by go run ./cmd/compose from the agent VM source. Don't edit by hand.
#
# Four processes, each in its own container with its own uid, linked only by unix sockets: agentd (front door
# and runtime; no network, no keys), brain (no network, no secrets), gatewayd (service "agentvm": the only network
# and the published port) and vaultd (the keys; no network). A one-shot setup container (root, no network) gives
# them their directories first.
#
# Every image is named by digest only: the pinned distroless base (` + baseImage + `)
# plus one layer with the binary at /tacy/<name>. Rebuild them from the tagged source (scripts/reproduce.sh) to get
# the same digests. Binaries (linux/amd64, sha256):
`)
	for _, im := range images {
		fmt.Fprintf(&b, "#   %-8s %s\n", im.Name, im.SHA256)
	}
	env := func(names []string) {
		b.WriteString("    environment:\n")
		for _, s := range names {
			b.WriteString("      " + s + ": ${" + s + "}\n")
		}
	}
	// args writes the command (the image's entrypoint is the binary) as a flow list.
	args := func(a ...string) {
		q := make([]string, len(a))
		for i, s := range a {
			q[i] = `"` + s + `"`
		}
		b.WriteString("    command: [" + strings.Join(q, ", ") + "]\n")
	}
	// service: a long-running process's container.
	service := func(svc, bin, user string, network bool) {
		b.WriteString("  " + svc + ":\n    image: " + ref[bin] + "\n    entrypoint: [\"/tacy/" + bin + "\"]\n")
		if !network {
			b.WriteString("    network_mode: none\n")
		}
		b.WriteString(`    restart: unless-stopped
    depends_on:
      setup:
        condition: service_completed_successfully
    user: "` + user + `"
    read_only: true
    cap_drop: [ALL]
    security_opt: ["no-new-privileges:true"]
`)
	}
	// setup: root, no network, only the capabilities chown, chmod and rm on others' files need. Socket directories,
	// each in a volume only its two containers mount: agentd's HTTP socket and gatewayd's gateway/v0 socket (agentd,
	// gatewayd by group); vaultd's socket (gatewayd may only enter); the brain's socket (agentd listens, the brain
	// may only enter). agentd's queue on the encrypted disk is its uid's only; the queue a root agentd kept (before
	// VM release 2, or after a rollback) is removed: its runs ended with that process.
	b.WriteString(`services:
  setup:
    image: ` + ref["setup"] + `
    entrypoint: ["/tacy/setup"]
    network_mode: none
    restart: "no"
    user: "0:0"
    read_only: true
    cap_drop: [ALL]
    cap_add: [CHOWN, DAC_OVERRIDE, FOWNER]
    security_opt: ["no-new-privileges:true"]
    volumes:
      - agentsock:/run/tacy/agent
      - vaultsock:/run/tacy/vault
      - brainsock2:/run/tacy/brain
      - state:/state
`)
	args("-dir", "/run/tacy/agent="+agentdUID+":"+gatewaydUID+":0770",
		"-dir", "/run/tacy/vault="+vaultdUID+":"+gatewaydUID+":0750",
		"-dir", "/run/tacy/brain="+agentdUID+":"+brainUID+":0750",
		"-remove", "/state/queue.db", "-remove", "/state/queue.db-wal", "-remove", "/state/queue.db-shm",
		"-remove", "/state/queue.db-journal",
		"-tree", "/state/agentd="+agentdUID+":"+agentdUID+":0700")
	service("agentd", "agentd", agentdUID+":"+agentdUID, false)
	b.WriteString(`    group_add: ["` + brainUID + `", "` + gatewaydUID + `"]
    volumes:
      - /var/run/dstack.sock:/var/run/dstack.sock
      - state:/state
      - brainsock2:/run/tacy/brain
      - agentsock:/run/tacy/agent
`)
	env(agentEnv)
	args("-storage", "/state/agentd", "-brain-socket", "/run/tacy/brain/brain.sock", "-brain-uid", brainUID, "-brain-gid", brainUID,
		"-gateway-socket", "/run/tacy/agent/gateway.sock", "-listen-unix", "/run/tacy/agent/http.sock", "-listen-uid", gatewaydUID,
		"-listen-gid", gatewaydUID, "-mem-limit-mib", "600")
	service("brain", "brain", brainUID+":"+brainUID, false)
	b.WriteString(`    volumes:
      - brainsock2:/run/tacy/brain
`)
	args("--socket", "/run/tacy/brain/brain.sock")
	service("agentvm", "gatewayd", gatewaydUID+":"+gatewaydUID, true)
	b.WriteString(`    ports:
      - "8080:8080"
    tmpfs: [/tmp]
    volumes:
      - agentsock:/run/tacy/agent
      - vaultsock:/run/tacy/vault
`)
	env(gatewayEnv)
	b.WriteString("      HOME: /tmp\n")
	args("-socket", "/run/tacy/agent/gateway.sock", "-agent-uid", agentdUID, "-vault-socket", "/run/tacy/vault/vault.sock",
		"-listen", ":8080", "-forward", "/run/tacy/agent/http.sock")
	service("vaultd", "vaultd", vaultdUID+":"+gatewaydUID, false) // primary group: gatewayd's, so its socket is the gateway's to open
	b.WriteString(`    volumes:
      - vaultsock:/run/tacy/vault
`)
	env(vaultEnv)
	args("-socket", "/run/tacy/vault/vault.sock", "-gateway-uid", gatewaydUID, "-group-mode")
	b.WriteString(`volumes:
  state:
  brainsock2:
  agentsock:
  vaultsock:
`)
	// The verifier's rule (every image by digest, no tag, no build:), on what it will see.
	if _, err := verifier.ComposeImages(b.String()); err != nil {
		return "", err
	}
	if w := refusedWord(b.String()); w != "" {
		return "", fmt.Errorf("compose.yaml would contain %q, which Phala refuses (terms of use)", w)
	}
	if b.Len() > MaxCompose {
		return "", fmt.Errorf("compose.yaml would be %d bytes; Phala takes at most 200 KiB with the pre-launch script (limit here %d)", b.Len(), MaxCompose)
	}
	return b.String(), nil
}

// writeLayout writes img as an OCI image layout at dir (one image, nothing else), for the release to push.
func writeLayout(dir string, img v1.Image) error {
	if err := os.RemoveAll(dir); err != nil {
		return err
	}
	p, err := layout.Write(dir, empty.Index)
	if err != nil {
		return err
	}
	return p.AppendImage(img)
}

// Manifest describes one release (release.json, a release asset). Everything in it can be recomputed from the
// tagged source with scripts/reproduce.sh.
type Manifest struct {
	Schema        string            `json:"schema"` // tacy-release/v2 (v1 had no images: the CVM built the binaries)
	Repository    string            `json:"repository"`
	Version       string            `json:"version"`
	Commit        string            `json:"commit"`
	ComposeSHA256 string            `json:"compose_sha256"` // sha256(compose.yaml), the signed subject and the attested value
	Binaries      map[string]string `json:"binaries"`       // name -> sha256 of the binary (linux/amd64)
	Images        map[string]string `json:"images"`         // name -> Registry/<name>@sha256:<digest>, as compose.yaml names them
	BaseImage     string            `json:"base_image"`     // every image's base, by digest
	GoVersion     string            `json:"go_version"`
	BuildImage    string            `json:"build_image"` // the toolchain image the release builds in
}

// Schema is release.json's schema.
const Schema = "tacy-release/v2"

func fail(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}

func main() {
	check := flag.Bool("check", false, "compare with compose.yaml instead of writing it")
	ociDir := flag.String("oci", "", "also write each image as an OCI image layout in this directory (<dir>/<name>)")
	manifest := flag.String("manifest", "", "also write the release manifest (JSON) to this path")
	version := flag.String("version", "", "release version for the manifest (vX.Y.Z)")
	commit := flag.String("commit", "", "release commit for the manifest")
	flag.Parse()
	if *manifest != "" && (*version == "" || *commit == "") {
		fail(fmt.Errorf("--manifest needs --version and --commit"))
	}
	images, err := build()
	if err != nil {
		fail(err)
	}
	out, err := generate(images)
	if err != nil {
		fail(err)
	}
	h := sha256.Sum256([]byte(out))
	if *check {
		cur, _ := os.ReadFile("compose.yaml")
		if string(cur) != out {
			fmt.Println("compose.yaml is stale or was edited: run go run ./cmd/compose")
			os.Exit(1)
		}
		fmt.Printf("compose.yaml matches the source, the reproducible binaries and their images\n")
	} else {
		if err := os.WriteFile("compose.yaml", []byte(out), 0o644); err != nil {
			fail(err)
		}
		fmt.Printf("wrote compose.yaml (%d bytes)\n", len(out))
	}
	fmt.Printf("compose sha256 %x (%d bytes)\n", h, len(out))
	m := Manifest{Schema: Schema, Repository: "https://" + modulePath, Version: *version, Commit: *commit,
		ComposeSHA256: hex.EncodeToString(h[:]), Binaries: map[string]string{}, Images: map[string]string{},
		BaseImage: baseImage, GoVersion: goVersion(), BuildImage: image}
	for _, im := range images {
		m.Binaries[im.Name], m.Images[im.Name] = im.SHA256, im.Ref
		fmt.Printf("%-8s binary sha256 %s\n%-8s image %s\n", im.Name, im.SHA256, "", im.Ref)
		if *ociDir != "" {
			if err := writeLayout(filepath.Join(*ociDir, im.Name), im.img); err != nil {
				fail(err)
			}
		}
	}
	if *ociDir != "" {
		names := make([]string, 0, len(images))
		for _, im := range images {
			names = append(names, im.Name)
		}
		sort.Strings(names)
		fmt.Printf("wrote OCI layouts %s/{%s}\n", *ociDir, strings.Join(names, ","))
	}
	if *manifest != "" {
		j, _ := json.MarshalIndent(m, "", "  ")
		if err := os.WriteFile(*manifest, append(j, '\n'), 0o644); err != nil {
			fail(err)
		}
		fmt.Printf("wrote %s\n", *manifest)
	}
}
