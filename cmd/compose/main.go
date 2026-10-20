// compose writes compose.yaml for the agent VM and builds the OCI images it runs. Each binary is built
// reproducibly (linux/amd64, CGO off, -trimpath, -buildvcs=false, the Go version of the pinned toolchain image) and
// becomes one image: the pinned distroless base plus one layer holding only the binary (fixed times, owner 0:0,
// mode 0555). Same binaries, same base: same image digests, on any machine. The compose names every image by
// digest only (no tag, no build:), so the CVM's attested compose hash covers exactly the binaries that run.
//
// Four processes (docs/21-gateway-v0.md, docs/22-sandbox-runner.md), each its own container with its own uid,
// linked only by unix sockets in volumes shared by exactly two containers:
//
//   - agentd (./app, service "agentd"): the front door and the runtime (journal and queue, the harness to the
//     brain). No network at all (network_mode none) and no keys: it gets only AGENT_VM_TOKEN, which it checks.
//   - runnerd (./cmd/runnerd, service "runner"): runs the brain (./cmd/brain, our agent loop, untrusted) in a gVisor
//     sandbox for agentd: no network, no keys, no capabilities, rootless runsc, Docker's seccomp profile off (runsc
//     brings its own), memory and process limits on the container. The brain's sandbox has a root holding only its
//     binary, no network, and its one link to agentd, a socketpair end passed in as fd 3 (harness/v1). Its image
//     holds runnerd, the brain and gVisor (Google's release, pinned by sha256: see gvisorLayer).
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
// gVisor (runsc and the sidecars it runs from gvisor-bin/) is Google's release tarball, downloaded once into the
// user's cache and checked against the tarball's sha256 and each binary's (sandbox/gvisor.go) before it goes into
// runnerd's image, as its own layer (it changes less often than runnerd and the brain, so an update pulls only the
// small layer), with gVisor's LICENSE next to the binaries (cmd/compose/gvisor-LICENSE, pinned by sha256: the
// tarball has none). Same pinned bytes, same layer: the image stays reproducible.
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
	"cmp"
	"compress/bzip2"
	"compress/gzip"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
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

	"github.com/tacyhq/tacy/safety"
	"github.com/tacyhq/tacy/sandbox"
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
// search provider choice (not a secret) to gatewayd. runnerd, the brain and setup get none.
var (
	vaultEnv   = []string{"TINFOIL_API_KEY", "BRAVE_SEARCH_API_KEY", "TAVILY_API_KEY", "EXA_API_KEY"}
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
// anyway). Since v0.4.0 runnerd's socket directory is a new volume (runnersock); the brain's (brainsock2, and
// brainsock before it) is no longer named and stays on disk as it was, for a rollback. The agent socket directory is
// reset at every start, so it needs nothing. The build-on-CVM composes' volumes (bin, gocache, gomod) aren't named
// here and stay on disk unused, so a rollback to one finds its cached binaries.
const (
	agentdUID   = "10003"
	gatewaydUID = "10001"
	vaultdUID   = "10002"
	runnerdUID  = "10004" // its primary group is agentd's, so its socket is agentd's to open
)

// The brain runs as 65534 (nobody) inside its sandbox (sandbox/runsc.go), in a user namespace of runnerd's.

// The runner's container limits, which bound every sandbox in it (rootless runsc runs with --ignore-cgroups).
const (
	runnerMem  = "640m"
	runnerPids = "512"
)

// bins are the binaries: name (its path /tacy/<name> in an image) and package.
var bins = []struct{ name, pkg string }{
	{"agentd", "./app"},
	{"brain", "./cmd/brain"},
	{"gatewayd", "./cmd/gatewayd"},
	{"runnerd", "./cmd/runnerd"},
	{"setup", "./cmd/setup"},
	{"vaultd", "./cmd/vaultd"},
}

// Safety trust roots (docs/23-safety-controls.md), pinned here so the attested compose names them; the same in
// agentd, gatewayd and vaultd. Public keys only ("ed25519:<base64>"). Stage 2 (v0.6.0): both made offline on
// 2026-10-18. The admin key signs policies (and the firm's stop lists); its private half never goes online. The
// operator key signs the heartbeat and the global stop; its private half is only the chat Worker's secret. With admin keys pinned nothing runs until a signed policy covers the space
// (policy_missing). safetyURL: the chat Worker's route that serves the newest heartbeat and the signed policy;
// gatewayd pulls it every 10 s (empty: pushes to POST /safety only). Changing any of these is a release.
const (
	safetyFirm  = "f_chat"
	operatorKey = "ed25519:UjnT9P6APMBeNg5pJlGCLbwOKDlVJQO3m3+yDzby2os="
	adminKeys   = "ed25519:Ii1apdLLHa+9d1d/vAjiipxNV7fS9m2lwFva67v4VFg="
	safetyURL   = "https://chat.tacy.io/api/safety/docs"
)

// Keys v2 slice 5 (docs/26 section 4, decisions 5 and 6): once f_chat's firm key log exists, keylogGenesis is
// its genesis entry's hash (safetysign keylog-check prints it) and the admin key leaves the compose: the VM takes
// admin signers from the log's current key admins and verifies the log itself (entries from keylogURL, pulled by
// gatewayd with the documents, or POST /keylog). Our offline admin key becomes the log's recovery kit, so
// the policy it signed (chat-v1, safety.ChatPolicyV1) is carried: taken as signed by the key admins while it is
// the one in force, nothing else the kit signs is. Empty: the release pins adminKeys as before.
//
// f_chat's genesis was signed offline on 2026-10-18 (its owner's identity i_nrqykwaqqhlrcbdruyhwgqty2i as the
// first key admin, the offline admin key as the kit); the entry is testdata/fchat-genesis.json. Pinned from v0.9.0.
const (
	keylogGenesis = "a35f4cb79bd5066638a0fd0aa8dc855b951febba003e6a6fd3e335adc8d47cfd"
	keylogCarry   = safety.ChatPolicyV1
	keylogURL     = "https://chat.tacy.io/api/safety/keylog"
)

// safetyArgs are the trust-root flags every guard process gets.
func safetyArgs() []string { return trustArgs(adminKeys, keylogGenesis, keylogCarry) }

// trustArgs: the firm, the operator key, and either the admin keys or the key log genesis (with the carried
// documents), never both.
func trustArgs(admins, genesis, carry string) []string {
	a := []string{"-firm", safetyFirm}
	if operatorKey != "" {
		a = append(a, "-operator-key", operatorKey)
	}
	switch {
	case genesis != "":
		a = append(a, "-keylog-genesis", genesis)
		if carry != "" {
			a = append(a, "-keylog-carry", carry)
		}
	case admins != "":
		a = append(a, "-admin-keys", admins)
	}
	return a
}

// pullArgs are gatewayd's sources: the documents, and the key log when one is pinned.
func pullArgs(genesis string) []string {
	var a []string
	if safetyURL != "" {
		a = append(a, "-safety-url", safetyURL)
	}
	if genesis != "" && keylogURL != "" {
		a = append(a, "-keylog-url", keylogURL)
	}
	return a
}

// images are the images: name (under Registry; its entrypoint is the binary of that name), the other binaries in
// its layer, and whether it carries gVisor (its own layer, /tacy/gvisor). Every binary is in exactly one image; the
// brain runs inside runnerd's sandbox, so it ships in runnerd's image. Adding a binary: an entry in bins, here, and
// a service below that uses its image (README "Adding a process or binary").
var images = []struct {
	name   string
	with   []string
	gvisor bool
}{
	{name: "agentd"},
	{name: "gatewayd"},
	{name: "runnerd", with: []string{"brain"}, gvisor: true},
	{name: "setup"},
	{name: "vaultd"},
}

// gvisorDir is where runnerd's image holds gVisor: runsc, and gvisor-bin/ next to it.
const gvisorDir = "/tacy/gvisor"

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

// file is one file of a layer: its path under /tacy/ and its bytes (mode 0555).
type file struct {
	path string
	data []byte
	mode int64 // 0: 0555 (a binary)
}

// filesLayer is a deterministic gzip'd tar holding the files under /tacy/ (0555) in sorted order, each after its
// directories (0755), owner 0:0, time 0. compress/gzip's output depends only on the input and the Go version, which
// is pinned.
func filesLayer(files []file) ([]byte, error) {
	files = append([]file(nil), files...)
	sort.Slice(files, func(i, j int) bool { return files[i].path < files[j].path })
	var buf bytes.Buffer
	gz, err := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if err != nil {
		return nil, err
	}
	tw := tar.NewWriter(gz)
	dirs := map[string]bool{}
	write := func(h *tar.Header, data []byte) error {
		h.ModTime, h.Format = epoch, tar.FormatUSTAR
		if err := tw.WriteHeader(h); err != nil {
			return err
		}
		_, err := tw.Write(data)
		return err
	}
	for _, f := range files {
		if f.path == "" || strings.HasPrefix(f.path, "/") || strings.HasSuffix(f.path, "/") || strings.Contains(f.path, "..") {
			return nil, fmt.Errorf("bad layer path %q", f.path)
		}
		parts := strings.Split("tacy/"+f.path, "/")
		for i := 1; i < len(parts); i++ {
			if d := strings.Join(parts[:i], "/") + "/"; !dirs[d] {
				dirs[d] = true
				if err := write(&tar.Header{Name: d, Typeflag: tar.TypeDir, Mode: 0o755}, nil); err != nil {
					return nil, err
				}
			}
		}
		mode := cmp.Or(f.mode, 0o555)
		if err := write(&tar.Header{Name: "tacy/" + f.path, Typeflag: tar.TypeReg, Mode: mode, Size: int64(len(f.data))}, f.data); err != nil {
			return nil, err
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

// binaryLayer is the layer of an image holding one binary: /tacy/ (0755) and /tacy/<name> (0555).
func binaryLayer(name string, bin []byte) ([]byte, error) {
	return filesLayer([]file{{path: name, data: bin}})
}

// layer is one gzip'd layer of an image and its history line.
type layer struct {
	gz []byte
	by string
}

// buildImage is base plus the binary's layer, with /tacy/<name> as the entrypoint and fixed times. The digest
// depends only on base and bin.
func buildImage(base v1.Image, name string, bin []byte) (v1.Image, error) {
	gz, err := binaryLayer(name, bin)
	if err != nil {
		return nil, err
	}
	return buildLayers(base, name, layer{gz, "tacy cmd/compose: /tacy/" + name})
}

// buildLayers is base plus the layers in order, with /tacy/<name> as the entrypoint and fixed times. The digest
// depends only on base and the layers' bytes.
func buildLayers(base v1.Image, name string, layers ...layer) (v1.Image, error) {
	img := base
	for _, l := range layers {
		gz := l.gz
		tl, err := tarball.LayerFromOpener(func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(gz)), nil },
			tarball.WithMediaType(types.OCILayer))
		if err != nil {
			return nil, err
		}
		if img, err = mutate.Append(img, mutate.Addendum{Layer: tl, MediaType: types.OCILayer,
			History: v1.History{Created: v1.Time{Time: epoch}, CreatedBy: l.by}}); err != nil {
			return nil, err
		}
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

// Binary is one built binary.
type Binary struct {
	Name   string
	SHA256 string
}

// Image is one built image.
type Image struct {
	Name string
	Ref  string // Registry/<name>@sha256:<digest>
	img  v1.Image
}

// Release is what build makes: every binary and every image.
type Release struct {
	Binaries []Binary
	Images   []Image
}

func (r *Release) binary(name string) string {
	for _, b := range r.Binaries {
		if b.Name == name {
			return b.SHA256
		}
	}
	return ""
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

// gvisorTarball returns Google's gVisor release tarball, checked against its pin (sandbox.GVisorTarSHA256): from
// $TACY_GVISOR_TARBALL if set, else from the user's cache, else downloaded (then cached). Wherever it comes from,
// only the pinned bytes are used.
func gvisorTarball() ([]byte, error) {
	check := func(b []byte, from string) ([]byte, error) {
		if h := sha256.Sum256(b); hex.EncodeToString(h[:]) != sandbox.GVisorTarSHA256 {
			return nil, fmt.Errorf("gVisor tarball from %s: sha256 %x isn't the pinned %s", from, h, sandbox.GVisorTarSHA256)
		}
		return b, nil
	}
	if p := os.Getenv("TACY_GVISOR_TARBALL"); p != "" {
		b, err := os.ReadFile(p)
		if err != nil {
			return nil, err
		}
		return check(b, p)
	}
	cache := ""
	if d, err := os.UserCacheDir(); err == nil {
		cache = filepath.Join(d, "tacy", "gvisor-"+sandbox.GVisorRelease+"-x86_64.tar.bz2")
		if b, err := os.ReadFile(cache); err == nil {
			if b, err := check(b, cache); err == nil {
				return b, nil
			}
		}
	}
	resp, err := http.Get(sandbox.GVisorURL)
	if err != nil {
		return nil, fmt.Errorf("gVisor tarball: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("gVisor tarball %s: %s", sandbox.GVisorURL, resp.Status)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 512<<20))
	if err != nil {
		return nil, fmt.Errorf("gVisor tarball: %w", err)
	}
	if b, err = check(b, sandbox.GVisorURL); err != nil {
		return nil, err
	}
	if cache != "" && os.MkdirAll(filepath.Dir(cache), 0o755) == nil {
		if tmp, err := os.CreateTemp(filepath.Dir(cache), ".gvisor-*"); err == nil {
			_, werr := tmp.Write(b)
			if cerr := tmp.Close(); werr == nil && cerr == nil {
				os.Rename(tmp.Name(), cache)
			}
			os.Remove(tmp.Name())
		}
	}
	return b, nil
}

// gVisor's license (Apache-2.0, with the BSD note for some files) as published in its repository at the release's
// tag (gvisorLicenseURL); the tarball has none. It ships next to the binaries, at /tacy/gvisor/LICENSE in runnerd's
// image, from this copy (cmd/compose/gvisor-LICENSE), checked against gvisorLicenseSHA256. Here rather than in
// sandbox/gvisor.go so runnerd's binary doesn't change with it.
const (
	gvisorLicenseURL    = "https://raw.githubusercontent.com/google/gvisor/release-" + sandbox.GVisorRelease + "/LICENSE"
	gvisorLicenseSHA256 = "0fbab5c58efbdf6d31e8085214f2dd821659c03d73cff3ed2b08e98826ea1cd9"
)

//go:embed gvisor-LICENSE
var gvisorLicense []byte

// gvisorLayer is the layer holding gVisor's binaries at /tacy/gvisor (runsc, gvisor-bin/...): taken from the
// pinned tarball, each checked against its own pin (sandbox.GVisorFiles), nothing else from the tarball; and its
// license next to them (/tacy/gvisor/LICENSE, 0444), which the tarball doesn't carry.
func gvisorLayer(tarball []byte) ([]byte, error) {
	if h := sha256.Sum256(gvisorLicense); hex.EncodeToString(h[:]) != gvisorLicenseSHA256 {
		return nil, fmt.Errorf("gVisor LICENSE: sha256 %x isn't the pinned %s", h, gvisorLicenseSHA256)
	}
	gvisorRel := strings.TrimPrefix(gvisorDir, "/tacy/")
	want := map[string]string{}
	for _, f := range sandbox.GVisorFiles {
		want[f[0]] = f[1]
	}
	var files []file
	tr := tar.NewReader(bzip2.NewReader(bytes.NewReader(tarball)))
	for len(want) > 0 {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("gVisor tarball: %w", err)
		}
		sum, ok := want[h.Name]
		if !ok {
			continue
		}
		if h.Typeflag != tar.TypeReg {
			return nil, fmt.Errorf("gVisor tarball: %s isn't a regular file", h.Name)
		}
		b, err := io.ReadAll(tr)
		if err != nil {
			return nil, err
		}
		if got := sha256.Sum256(b); hex.EncodeToString(got[:]) != sum {
			return nil, fmt.Errorf("gVisor %s: sha256 %x isn't the pinned %s", h.Name, got, sum)
		}
		delete(want, h.Name)
		files = append(files, file{path: gvisorRel + "/" + h.Name, data: b})
	}
	for n := range want {
		return nil, fmt.Errorf("gVisor tarball has no %s", n)
	}
	files = append(files, file{path: gvisorRel + "/LICENSE", data: gvisorLicense, mode: 0o444})
	return filesLayer(files)
}

// build builds every binary and every image.
func build() (*Release, error) {
	if v, err := run(nil, "go", "env", "GOVERSION"); err != nil || strings.TrimSpace(v) != goVersion() {
		return nil, fmt.Errorf("go is %q, want %s (the toolchain image's; reproducible binaries need the same version): %v",
			strings.TrimSpace(v), goVersion(), err)
	}
	base, err := fetchBase()
	if err != nil {
		return nil, err
	}
	r := &Release{}
	bin := map[string][]byte{}
	for _, b := range bins {
		if bin[b.name], err = buildBinary(b.pkg); err != nil {
			return nil, err
		}
		h := sha256.Sum256(bin[b.name])
		r.Binaries = append(r.Binaries, Binary{b.name, hex.EncodeToString(h[:])})
	}
	used := map[string]bool{}
	for _, im := range images {
		var layers []layer
		if im.gvisor {
			tb, err := gvisorTarball()
			if err != nil {
				return nil, err
			}
			gz, err := gvisorLayer(tb)
			if err != nil {
				return nil, err
			}
			layers = append(layers, layer{gz, "tacy cmd/compose: " + gvisorDir + " (gVisor " + sandbox.GVisorRelease + ", " + sandbox.GVisorURL + ")"})
		}
		files := []file{{path: im.name, data: bin[im.name]}}
		for _, w := range im.with {
			files = append(files, file{path: w, data: bin[w]})
		}
		by := "tacy cmd/compose:"
		for _, f := range files {
			if f.data == nil || used[f.path] {
				return nil, fmt.Errorf("image %s: binary %s isn't built or is in another image", im.name, f.path)
			}
			used[f.path] = true
			by += " /tacy/" + f.path
		}
		gz, err := filesLayer(files)
		if err != nil {
			return nil, err
		}
		img, err := buildLayers(base, im.name, append(layers, layer{gz, by})...)
		if err != nil {
			return nil, err
		}
		d, err := img.Digest()
		if err != nil {
			return nil, err
		}
		r.Images = append(r.Images, Image{Name: im.name, Ref: Registry + "/" + im.name + "@" + d.String(), img: img})
	}
	if len(used) != len(bins) {
		return nil, fmt.Errorf("%d binaries, %d in images", len(bins), len(used))
	}
	return r, nil
}

// generate returns compose.yaml for the release's images.
func generate(r *Release) (string, error) {
	ref := map[string]string{}
	for _, im := range r.Images {
		ref[im.Name] = im.Ref
	}
	brainSum, runscSum := r.binary("brain"), sandbox.GVisorFiles[0][1]
	if brainSum == "" || sandbox.GVisorFiles[0][0] != "runsc" {
		return "", fmt.Errorf("no brain binary or runsc pin")
	}
	var b strings.Builder
	b.WriteString(`# Generated by go run ./cmd/compose from the agent VM source. Don't edit by hand.
#
# Four processes (docs/22), each in its own container with its own uid, linked only by unix sockets: agentd
# (front door and runtime; no network, no keys), runner (runnerd: the brain in a gVisor sandbox, rootless runsc; no
# network, no keys, no capabilities), gatewayd (service "agentvm": the only network and the published port) and
# vaultd (the keys; no network). A one-shot setup container (root, no network) gives them their directories first.
#
# Every image is named by digest only: the pinned distroless base (` + baseImage + `)
# plus one layer with the binaries at /tacy/<name>; runnerd's image also holds the brain and, in a layer of its own,
# gVisor ` + sandbox.GVisorRelease + ` at ` + gvisorDir + ` (Google's release ` + sandbox.GVisorURL + `,
# sha256 ` + sandbox.GVisorTarSHA256 + `, each binary checked; its Apache-2.0 LICENSE at
# ` + gvisorDir + `/LICENSE). Rebuild them from the tagged source (scripts/reproduce.sh) to get the same digests.
# Binaries (linux/amd64, sha256):
`)
	for _, bin := range r.Binaries {
		fmt.Fprintf(&b, "#   %-8s %s\n", bin.Name, bin.SHA256)
	}
	for _, f := range sandbox.GVisorFiles {
		fmt.Fprintf(&b, "#   %-8s %s (gVisor %s)\n", "", f[1], f[0])
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
	// service: a long-running process's container. opts are extra security options (the runner's).
	service := func(svc, img, user string, network bool, opts ...string) {
		b.WriteString("  " + svc + ":\n    image: " + ref[img] + "\n    entrypoint: [\"/tacy/" + img + "\"]\n")
		if !network {
			b.WriteString("    network_mode: none\n")
		}
		sec := `"no-new-privileges:true"`
		for _, o := range opts {
			sec += `, "` + o + `"`
		}
		b.WriteString(`    restart: unless-stopped
    depends_on:
      setup:
        condition: service_completed_successfully
    user: "` + user + `"
    read_only: true
    cap_drop: [ALL]
    security_opt: [` + sec + `]
`)
	}
	// setup: root, no network, only the capabilities chown, chmod and rm on others' files need. Socket directories,
	// each in a volume only its two containers mount: agentd's HTTP socket and gatewayd's gateway/v0 socket (agentd,
	// gatewayd by group); vaultd's socket (gatewayd may only enter); runnerd's socket (runnerd listens, agentd may
	// only enter). agentd's queue on the encrypted disk is its uid's only; the queue a root agentd kept (before VM
	// release 2, or after a rollback) is removed: its runs ended with that process.
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
      - runnersock:/run/tacy/runner
      - state:/state
`)
	args("-dir", "/run/tacy/agent="+agentdUID+":"+gatewaydUID+":0770",
		"-dir", "/run/tacy/vault="+vaultdUID+":"+gatewaydUID+":0750",
		"-dir", "/run/tacy/runner="+runnerdUID+":"+agentdUID+":0750",
		"-remove", "/state/queue.db", "-remove", "/state/queue.db-wal", "-remove", "/state/queue.db-shm",
		"-remove", "/state/queue.db-journal",
		"-tree", "/state/agentd="+agentdUID+":"+agentdUID+":0700")
	service("agentd", "agentd", agentdUID+":"+agentdUID, false)
	b.WriteString(`    group_add: ["` + gatewaydUID + `"]
    volumes:
      - /var/run/dstack.sock:/var/run/dstack.sock
      - state:/state
      - runnersock:/run/tacy/runner
      - agentsock:/run/tacy/agent
`)
	env(agentEnv)
	args(append([]string{"-storage", "/state/agentd", "-runner-socket", "/run/tacy/runner/runner.sock",
		"-gateway-socket", "/run/tacy/agent/gateway.sock", "-listen-unix", "/run/tacy/agent/http.sock", "-listen-uid", gatewaydUID,
		"-listen-gid", gatewaydUID, "-mem-limit-mib", "600"}, safetyArgs()...)...)
	// runner: rootless runsc needs no capabilities, only Docker's seccomp profile off (it refuses the user and mount
	// namespaces runsc makes; runsc filters its own sandbox and gofer). The container's memory and pids limits bound
	// every sandbox in it (runsc runs with --ignore-cgroups). A tmpfs holds runsc's state and the brain's root; it
	// must allow exec (Docker's default tmpfs is noexec, and gVisor maps the brain's binary from it). runnerd checks
	// that the gVisor release and runsc hash it's given are the ones it was built with, and the brain's hash.
	service("runner", "runnerd", runnerdUID+":"+agentdUID, false, "seccomp:unconfined")
	b.WriteString(`    mem_limit: ` + runnerMem + `
    memswap_limit: ` + runnerMem + `
    pids_limit: ` + runnerPids + `
    tmpfs: ["/run/runner:exec,size=64m,mode=0700,uid=` + runnerdUID + `,gid=` + agentdUID + `", "/tmp:size=16m"]
    volumes:
      - runnersock:/run/tacy/runner
`)
	args("-socket", "/run/tacy/runner/runner.sock", "-agent-uid", agentdUID,
		"-gvisor", gvisorDir, "-gvisor-release", sandbox.GVisorRelease, "-runsc-sha256", runscSum,
		"-brain", "/tacy/brain", "-brain-sha256", brainSum, "-dir", "/run/runner", "-platform", "systrap", "-rootless")
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
	gw := append([]string{"-socket", "/run/tacy/agent/gateway.sock", "-agent-uid", agentdUID, "-vault-socket", "/run/tacy/vault/vault.sock",
		"-listen", ":8080", "-forward", "/run/tacy/agent/http.sock"}, safetyArgs()...)
	gw = append(gw, pullArgs(keylogGenesis)...)
	args(gw...)
	service("vaultd", "vaultd", vaultdUID+":"+gatewaydUID, false) // primary group: gatewayd's, so its socket is the gateway's to open
	b.WriteString(`    volumes:
      - vaultsock:/run/tacy/vault
`)
	env(vaultEnv)
	args(append([]string{"-socket", "/run/tacy/vault/vault.sock", "-gateway-uid", gatewaydUID, "-group-mode"}, safetyArgs()...)...)
	b.WriteString(`volumes:
  state:
  runnersock:
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
	BuildImage    string            `json:"build_image"`      // the toolchain image the release builds in
	GVisor        *GVisor           `json:"gvisor,omitempty"` // the gVisor release in runnerd's image (since v0.4.0)
}

// GVisor is the third-party release an image carries: Google's tarball and the binaries taken from it.
type GVisor struct {
	Release       string            `json:"release"`
	URL           string            `json:"url"`
	TarballSHA256 string            `json:"tarball_sha256"`
	Files         map[string]string `json:"files"` // path under the image's /tacy/gvisor -> sha256
	Image         string            `json:"image"` // the image holding it
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
	rel, err := build()
	if err != nil {
		fail(err)
	}
	out, err := generate(rel)
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
	for _, b := range rel.Binaries {
		m.Binaries[b.Name] = b.SHA256
		fmt.Printf("%-8s binary sha256 %s\n", b.Name, b.SHA256)
	}
	for _, im := range images {
		if im.gvisor {
			m.GVisor = &GVisor{Release: sandbox.GVisorRelease, URL: sandbox.GVisorURL, TarballSHA256: sandbox.GVisorTarSHA256,
				Files: map[string]string{}, Image: im.name}
			for _, f := range sandbox.GVisorFiles {
				m.GVisor.Files[f[0]] = f[1]
			}
			m.GVisor.Files["LICENSE"] = gvisorLicenseSHA256
		}
	}
	for _, im := range rel.Images {
		m.Images[im.Name] = im.Ref
		fmt.Printf("%-8s image %s\n", im.Name, im.Ref)
		if *ociDir != "" {
			if err := writeLayout(filepath.Join(*ociDir, im.Name), im.img); err != nil {
				fail(err)
			}
		}
	}
	if *ociDir != "" {
		names := make([]string, 0, len(rel.Images))
		for _, im := range rel.Images {
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
