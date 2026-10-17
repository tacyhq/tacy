// compose writes compose.yaml for the agent VM. The compose embeds the source (every package of this module that
// the four binaries import, plus go.mod and go.sum), so the CVM's attested compose hash covers the exact code, and
// it pins the SHA-256 of the binaries that source builds to. Four processes (docs/21-gateway-v0.md), each its
// own container with its own uid, linked only by unix sockets in volumes shared by exactly two containers:
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
// A one-shot "build" container (the only other one with a network, and only while it runs at boot: Go modules
// for a cold build) builds the four binaries reproducibly (linux/amd64, CGO off, -trimpath, -buildvcs=false, same
// Go version as the pinned image) and refuses to finish unless each matches its pin; it also sets the socket
// directories' owners. Every other container waits for it, then checks its own binary's pin again before it runs
// it from a read-only volume. So the build cache on the encrypted disk speeds up restarts but can't change what
// runs.
//
// The source is one gzip'd tar, base64, in x-agentvm-source: as plain YAML it would be over Phala's 200 KiB cap.
// It's deterministic (sorted, fixed headers, no timestamps), so the same source gives the same compose.
//
//	go run ./cmd/compose                  # after editing anything the binaries build from
//	go run ./cmd/compose --check          # verify compose.yaml matches the source and the binary hashes (no write)
//	go run ./cmd/compose --extract DIR    # unpack the source a compose.yaml embeds (review what a CVM runs)
//	go run ./cmd/compose --check --manifest release.json --version v0.1.0 --commit <sha>
//	                                      # also write the release manifest (release.yml, scripts/reproduce.sh)
//
// The compose hash is sha256(compose.yaml): dstack puts the file unchanged in app-compose.json as
// docker_compose_file (whose own hash is the attested compose-hash), and the verifier hashes that string. It is the
// subject a release signs.
package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Go toolchain image, pinned by digest. Its Go version must equal mise.toml's. Every container runs
// the same image (already pulled; the four processes only need sh and sha256sum to check their pin).
const image = "golang:1.27.2-alpine@sha256:f92b6ef800e499660581efdabdf25d9d817a9d124eaf900924f0504e7e27e12d"

const modulePath = "github.com/tacyhq/tacy"

// The CVM's Phala encrypted environment variables (names only; values never touch the compose), by the one
// container each goes to: the keys to vaultd only, the run token to agentd (it checks it, never sends it), the
// search provider choice (not a secret) to gatewayd. The brain gets none.
var (
	vaultEnv   = []string{"TINFOIL_API_KEY", "BRAVE_SEARCH_API_KEY", "TAVILY_API_KEY"}
	agentEnv   = []string{"AGENT_VM_TOKEN"}
	gatewayEnv = []string{"SEARCH_PROVIDER"}
)

// uids. Each process has its own; none is root (agentd was until VM release 2). Each socket is 0660, owned by the
// process that listens, with the group of the one peer (also checked by uid with SO_PEERCRED). agentd needs no
// root: dstack's guest agent socket is mode 0777 (dstack v0.6.1, os/common/rootfs/dstack-guest-agent.socket,
// SocketMode=0777; the guest agent doesn't check the caller's uid), and the build container gives agentd its queue
// directory and its socket directories.
//
// Rollback: an older compose runs agentd as root without capabilities (no DAC override), which can't open files
// this uid owns with mode 0600. So the new layout leaves what an older agentd uses as it was: the queue moves to
// /state/agentd (the older one used /state/queue.db, which the build removes; the runs it held ended with the
// process anyway), and the brain's socket directory is a new volume (brainsock2; brainsock stays root's). The
// agent socket directory is reset by every compose's build, so it needs nothing.
const (
	agentdUID   = "10003"
	brainUID    = "65534" // nobody
	gatewaydUID = "10001"
	vaultdUID   = "10002"
)

// bins are the binaries the CVM builds: name, package, and the variable that pins it.
var bins = []struct{ name, pkg, pin string }{
	{"agentd", "./app", "AGENTD_SHA256"},
	{"brain", "./cmd/brain", "BRAIN_SHA256"},
	{"gatewayd", "./cmd/gatewayd", "GATEWAYD_SHA256"},
	{"vaultd", "./cmd/vaultd", "VAULTD_SHA256"},
}

// The packages the CVM builds.
var mains = []string{"./app", "./cmd/brain", "./cmd/gatewayd", "./cmd/vaultd"}

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

// target is the CVM's platform: file lists and builds both use it (peer_linux.go, not peer_other.go).
var target = []string{"CGO_ENABLED=0", "GOOS=linux", "GOARCH=amd64", "GOAMD64=v1", "GOFLAGS=", "GOEXPERIMENT="}

// sources returns the files to embed: go.mod, go.sum and the non-test Go files of every in-module package the
// mains depend on (for linux/amd64), relative to the module root, sorted.
func sources() ([]string, error) {
	out, err := run(target, "go", append([]string{"list", "-deps", "-f",
		`{{if .Module}}{{if eq .Module.Path "` + modulePath + `"}}{{$d := .Dir}}{{range .GoFiles}}{{$d}}/{{.}}{{"\n"}}{{end}}{{end}}{{end}}`}, mains...)...)
	if err != nil {
		return nil, err
	}
	root, _ := os.Getwd()
	seen := map[string]bool{}
	var files []string
	for _, f := range strings.Fields(out) {
		rel, err := filepath.Rel(root, f)
		if err != nil {
			return nil, err
		}
		if rel = filepath.ToSlash(rel); !seen[rel] {
			seen[rel] = true
			files = append(files, rel)
		}
	}
	sort.Strings(files)
	return append([]string{"go.mod", "go.sum"}, files...), nil
}

// minimalSum is the go.sum the CVM's build needs: only the lines go records when it builds the four binaries from
// an empty go.sum (in a copy of the module, offline: GOPROXY=off, GOSUMDB=off, everything from the local module
// cache), each of which must also be in the repository's go.sum, so nothing in it is new or unchecked. The full
// go.sum (test and tool dependencies too) would take a sixth of Phala's size cap.
func minimalSum(files []string) ([]byte, error) {
	full, err := os.ReadFile("go.sum")
	if err != nil {
		return nil, err
	}
	tmp, err := os.MkdirTemp("", "agentvm-sum")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmp)
	for _, f := range files {
		if f == "go.sum" {
			continue
		}
		data, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		dst := filepath.Join(tmp, filepath.FromSlash(f))
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return nil, err
		}
		if err := os.WriteFile(dst, data, 0o644); err != nil {
			return nil, err
		}
	}
	if err := os.WriteFile(filepath.Join(tmp, "go.sum"), nil, 0o644); err != nil {
		return nil, err
	}
	cmd := exec.Command("go", append([]string{"build", "-o", os.DevNull}, mains...)...)
	cmd.Dir = tmp
	cmd.Env = append(os.Environ(), append(target, "GOFLAGS=-mod=mod", "GOPROXY=off", "GOSUMDB=off")...)
	if out, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("go build with an empty go.sum: %v\n%s", err, out)
	}
	sum, err := os.ReadFile(filepath.Join(tmp, "go.sum"))
	if err != nil {
		return nil, err
	}
	have := map[string]bool{}
	for _, ln := range strings.Split(string(full), "\n") {
		have[ln] = true
	}
	for _, ln := range strings.Split(strings.TrimSpace(string(sum)), "\n") {
		if !have[ln] {
			return nil, fmt.Errorf("go.sum line %q isn't in the repository's go.sum", ln)
		}
	}
	return sum, nil
}

// archive is the files as a deterministic tar.gz: directories then files in sorted order, fixed modes, zero
// times and owners, no names in the gzip header. content replaces a file's bytes (the minimal go.sum).
func archive(files []string, content ...map[string][]byte) ([]byte, error) {
	var buf bytes.Buffer
	gz, err := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if err != nil {
		return nil, err
	}
	tw := tar.NewWriter(gz)
	dirs := map[string]bool{}
	var names []string
	for _, f := range files {
		for d := path.Dir(f); d != "."; d = path.Dir(d) {
			dirs[d+"/"] = true
		}
	}
	for d := range dirs {
		names = append(names, d)
	}
	names = append(names, files...)
	sort.Strings(names)
	for _, n := range names {
		h := &tar.Header{Name: n, ModTime: time.Unix(0, 0), Format: tar.FormatUSTAR}
		var data []byte
		if strings.HasSuffix(n, "/") {
			h.Typeflag, h.Mode = tar.TypeDir, 0o755
		} else {
			if c, ok := firstOf(content, n); ok {
				data = c
			} else if data, err = os.ReadFile(n); err != nil {
				return nil, err
			}
			h.Typeflag, h.Mode, h.Size = tar.TypeReg, 0o644, int64(len(data))
		}
		if err := tw.WriteHeader(h); err != nil {
			return nil, err
		}
		if _, err := tw.Write(data); err != nil {
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

// buildHash builds pkg exactly as the CVM does and returns the binary's SHA-256.
func buildHash(pkg string) (string, error) {
	tmp, err := os.MkdirTemp("", "agentvm-build")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(tmp)
	bin := filepath.Join(tmp, "bin")
	if _, err := run(target, "go", "build", "-trimpath", "-buildvcs=false", "-o", bin, pkg); err != nil {
		return "", err
	}
	b, err := os.ReadFile(bin)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:]), nil
}

func firstOf(ms []map[string][]byte, name string) ([]byte, bool) {
	for _, m := range ms {
		if c, ok := m[name]; ok {
			return c, true
		}
	}
	return nil, false
}

// MaxCompose is the most compose.yaml may take: Phala refuses a compose that, with its pre-launch script (~1 KiB),
// is over 200 KiB. Kept with some room.
const MaxCompose = 196 << 10

// chunkSize is the most base64 one command argument carries (Linux caps a single argument at 128 KiB).
const chunkSize = 64 << 10

// lineLen is the base64 line length inside a chunk (readable diffs; the script drops the newlines).
const lineLen = 100

// refusedWords are words Phala refuses anywhere in a compose, case-insensitively, whatever the context:
// provisioning answers 400 "You are not allowed to deploy the target applications since it violates our terms of
// use". "frp" (a tunneling tool's name) is one, and random base64 contains it now and then (the switchover's
// source had it three times). Found 2026-10-16 by bisecting the compose against Phala's provision endpoint, which
// creates nothing until a commit. Add a word here if Phala ever refuses a compose for it.
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

// wrap splits base64 into lines of at most lineLen, and breaks a line inside any refused word, so no line contains
// one. The start script drops the newlines, so the bytes it decodes are the same.
func wrap(s string) []string {
	var lines []string
	for i := 0; i < len(s); {
		end := min(i+lineLen, len(s))
		low := strings.ToLower(s[i:end])
		for _, w := range refusedWords {
			if k := strings.Index(low, w); k >= 0 && i+k+1 < end {
				end = i + k + 1 // the line ends after the word's first letter
				low = low[:k+1]
			}
		}
		lines = append(lines, s[i:end])
		i = end
	}
	return lines
}

func generate() (string, error) {
	files, err := sources()
	if err != nil {
		return "", err
	}
	gosum, err := minimalSum(files)
	if err != nil {
		return "", err
	}
	tgz, err := archive(files, map[string][]byte{"go.sum": gosum})
	if err != nil {
		return "", err
	}
	hash := map[string]string{}
	for _, b := range bins {
		if hash[b.name], err = buildHash(b.pkg); err != nil {
			return "", err
		}
	}
	src := base64.StdEncoding.EncodeToString(tgz)
	sum := sha256.Sum256(tgz)
	var b strings.Builder
	b.WriteString(`# Generated by go run ./cmd/compose from the agent VM source. Don't edit by hand.
#
# Four processes, each in its own container with its own uid, linked only by unix sockets: agentd (front door
# and runtime; no network, no keys), brain (no network, no secrets), gatewayd (service "agentvm": the only network
# and the published port) and vaultd (the keys; no network). A one-shot build container builds and pins them.
#
# x-agentvm-source is the source (go.mod, the go.sum lines the build needs, and the Go files the four binaries build
# from) as one gzip'd tar in base64, split in chunks the build command passes to its script by alias, one argument
# each. To read it: go run ./cmd/compose --extract DIR. Files (` + fmt.Sprint(len(files)) + `), tar.gz sha256 ` + hex.EncodeToString(sum[:]) + `:
`)
	for _, f := range files {
		b.WriteString("#   " + f + "\n")
	}
	b.WriteString("x-agentvm-source:\n")
	var chunks []string
	for i := 0; i < len(src); i += chunkSize {
		chunks = append(chunks, src[i:min(i+chunkSize, len(src))])
	}
	for i, c := range chunks {
		fmt.Fprintf(&b, "- &src%d |\n", i)
		for _, ln := range wrap(c) {
			b.WriteString("  " + ln + "\n")
		}
	}
	env := func(names []string) {
		b.WriteString("    environment:\n")
		for _, s := range names {
			b.WriteString("      " + s + ": ${" + s + "}\n")
		}
	}
	// hardened: a long-running process's container (not the build).
	hardened := func(user string) {
		b.WriteString(`    restart: unless-stopped
    depends_on:
      build:
        condition: service_completed_successfully
    user: "` + user + `"
    read_only: true
    cap_drop: [ALL]
    security_opt: ["no-new-privileges:true"]
`)
	}
	// run is the start script of a process's container: wait for its binary, check the pin, exec it.
	run := func(name, args string) {
		var pin, want string
		for _, x := range bins {
			if x.name == name {
				pin, want = x.pin, hash[name]
			}
		}
		b.WriteString(`    entrypoint: ["sh", "-c"]
    command:
      - |
        ` + pin + `=` + want + `
        bin=/cache/` + name + `-$$` + pin + `
        until [ -f "$$bin" ]; do sleep 2; done
        if ! echo "$$` + pin + `  $$bin" | sha256sum -c -s; then echo "the ` + name + ` binary isn't the pinned one: refusing to start"; sleep 60; exit 1; fi
        exec "$$bin" ` + args + `
`)
	}
	b.WriteString(`services:
  build:
    image: ` + image + `
    restart: "no"
    volumes:
      - gocache:/root/.cache/go-build
      - gomod:/go/pkg/mod
      - bin:/cache
      - agentsock:/run/tacy/agent
      - vaultsock:/run/tacy/vault
      - brainsock2:/run/tacy/brain
      - state:/state
    environment:
      CGO_ENABLED: "0"
      GOFLAGS: ""
    entrypoint: ["sh", "-c"]
    command:
      - |
        set -e
`)
	var list []string
	for _, x := range bins {
		b.WriteString("        " + x.pin + "=" + hash[x.name] + "\n")
		list = append(list, x.name+":"+x.pkg+":$$"+x.pin)
	}
	b.WriteString(`        pinned() { [ -f "$$2" ] && echo "$$1  $$2" | sha256sum -c -s; }
        todo=""
        for p in ` + strings.Join(list, " ") + `; do
          name=$${p%%:*}; want=$${p##*:}
          pinned "$$want" "/cache/$$name-$$want" || todo="$$todo $$p"
        done
        if [ -z "$$todo" ]; then
          echo "cached binaries match the pins"
        else
          rm -rf /src && mkdir -p /src && cd /src
          # The arguments after this script are the source's base64 chunks, in order.
          for c in "$$@"; do printf '%s' "$$c"; done | tr -d '\n' | base64 -d | tar -xzf -
          echo "building$$todo (a cold build takes a few minutes on 1 vCPU)"
          for p in $$todo; do
            name=$${p%%:*}; rest=$${p#*:}; pkg=$${rest%%:*}; want=$${rest#*:}
            go build -trimpath -buildvcs=false -o /cache/$$name.tmp $$pkg
            got=$$(sha256sum /cache/$$name.tmp | cut -d' ' -f1)
            if [ "$$got" != "$$want" ]; then echo "built $$name $$got isn't the pinned $$want: refusing to start"; rm -f /cache/$$name.tmp; sleep 60; exit 1; fi
            chmod 0555 /cache/$$name.tmp && mv /cache/$$name.tmp /cache/$$name-$$want
          done
        fi
        # Socket directories, each in a volume only its two containers mount: agentd's HTTP socket and gatewayd's
        # gateway/v0 socket (agentd, gatewayd by group); vaultd's socket (gatewayd may only enter); the brain's
        # socket (agentd listens, the brain may only enter).
        chown ` + agentdUID + `:` + gatewaydUID + ` /run/tacy/agent && chmod 0770 /run/tacy/agent
        chown ` + vaultdUID + `:` + gatewaydUID + ` /run/tacy/vault && chmod 0750 /run/tacy/vault
        chown ` + agentdUID + `:` + brainUID + ` /run/tacy/brain && chmod 0750 /run/tacy/brain
        # agentd's queue on the encrypted disk, its uid's only. The queue a root agentd kept (before VM release 2,
        # or after a rollback) is removed: its runs ended with that process.
        rm -f /state/queue.db /state/queue.db-wal /state/queue.db-shm /state/queue.db-journal
        mkdir -p /state/agentd && chown -R ` + agentdUID + `:` + agentdUID + ` /state/agentd && chmod 0700 /state/agentd
      - build
`)
	for i := range chunks {
		fmt.Fprintf(&b, "      - *src%d\n", i)
	}
	b.WriteString(`  agentd:
    image: ` + image + `
    network_mode: none
`)
	hardened(agentdUID + ":" + agentdUID)
	b.WriteString(`    group_add: ["` + brainUID + `", "` + gatewaydUID + `"]
    volumes:
      - /var/run/dstack.sock:/var/run/dstack.sock
      - bin:/cache:ro
      - state:/state
      - brainsock2:/run/tacy/brain
      - agentsock:/run/tacy/agent
`)
	env(agentEnv)
	run("agentd", "-storage /state/agentd -brain-socket /run/tacy/brain/brain.sock -brain-uid "+brainUID+" -brain-gid "+brainUID+
		" -gateway-socket /run/tacy/agent/gateway.sock -listen-unix /run/tacy/agent/http.sock -listen-uid "+gatewaydUID+
		" -listen-gid "+gatewaydUID+" -mem-limit-mib 600")
	b.WriteString(`  brain:
    image: ` + image + `
    network_mode: none
`)
	hardened(brainUID + ":" + brainUID)
	b.WriteString(`    volumes:
      - bin:/cache:ro
      - brainsock2:/run/tacy/brain
`)
	run("brain", "--socket /run/tacy/brain/brain.sock")
	b.WriteString(`  agentvm:
    image: ` + image + `
`)
	hardened(gatewaydUID + ":" + gatewaydUID)
	b.WriteString(`    ports:
      - "8080:8080"
    tmpfs: [/tmp]
    volumes:
      - bin:/cache:ro
      - agentsock:/run/tacy/agent
      - vaultsock:/run/tacy/vault
`)
	env(gatewayEnv)
	b.WriteString("      HOME: /tmp\n")
	run("gatewayd", "-socket /run/tacy/agent/gateway.sock -agent-uid "+agentdUID+" -vault-socket /run/tacy/vault/vault.sock"+
		" -listen :8080 -forward /run/tacy/agent/http.sock")
	b.WriteString(`  vaultd:
    image: ` + image + `
    network_mode: none
`)
	hardened(vaultdUID + ":" + gatewaydUID) // primary group: gatewayd's, so its socket is the gateway's to open
	b.WriteString(`    volumes:
      - bin:/cache:ro
      - vaultsock:/run/tacy/vault
`)
	env(vaultEnv)
	run("vaultd", "-socket /run/tacy/vault/vault.sock -gateway-uid "+gatewaydUID+" -group-mode")
	b.WriteString(`volumes:
  gocache:
  gomod:
  bin:
  state:
  brainsock2:
  agentsock:
  vaultsock:
`)
	if w := refusedWord(b.String()); w != "" {
		return "", fmt.Errorf("compose.yaml would contain %q, which Phala refuses (terms of use)", w)
	}
	if b.Len() > MaxCompose {
		return "", fmt.Errorf("compose.yaml would be %d bytes; Phala takes at most 200 KiB with the pre-launch script (limit here %d)", b.Len(), MaxCompose)
	}
	return b.String(), nil
}

// embedded returns the tar.gz a compose.yaml embeds.
func embedded(compose []byte) ([]byte, error) {
	s := string(compose)
	i := strings.Index(s, "\nx-agentvm-source:\n")
	j := strings.Index(s, "\nservices:\n")
	if i < 0 || j < i {
		return nil, fmt.Errorf("no x-agentvm-source in the compose")
	}
	var src strings.Builder
	for _, ln := range strings.Split(s[i+len("\nx-agentvm-source:\n"):j], "\n") {
		if strings.HasPrefix(ln, "  ") {
			src.WriteString(strings.TrimSpace(ln))
		}
	}
	return base64.StdEncoding.DecodeString(src.String())
}

var safeName = regexp.MustCompile(`^[A-Za-z0-9_./-]+\z`)

// extract unpacks a compose's embedded source into dir (regular files and directories only, no paths out of dir).
func extract(compose []byte, dir string) error {
	tgz, err := embedded(compose)
	if err != nil {
		return err
	}
	gz, err := gzip.NewReader(bytes.NewReader(tgz))
	if err != nil {
		return err
	}
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		name := path.Clean(h.Name)
		if !safeName.MatchString(h.Name) || strings.HasPrefix(name, "..") || path.IsAbs(name) {
			return fmt.Errorf("refusing %q", h.Name)
		}
		dst := filepath.Join(dir, filepath.FromSlash(name))
		switch h.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(dst, 0o755); err != nil {
				return err
			}
		case tar.TypeReg:
			data, err := io.ReadAll(io.LimitReader(tr, 4<<20))
			if err != nil {
				return err
			}
			if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
				return err
			}
			if err := os.WriteFile(dst, data, 0o644); err != nil {
				return err
			}
		default:
			return fmt.Errorf("refusing %q: not a file or directory", h.Name)
		}
	}
}

// Manifest describes one release (release.json, a release asset). Everything in it can be recomputed from the
// tagged source with scripts/reproduce.sh.
type Manifest struct {
	Schema        string            `json:"schema"` // tacy-release/v1
	Repository    string            `json:"repository"`
	Version       string            `json:"version"`
	Commit        string            `json:"commit"`
	ComposeSHA256 string            `json:"compose_sha256"` // sha256(compose.yaml), the signed subject and the attested value
	Binaries      map[string]string `json:"binaries"`       // the binaries compose.yaml pins (linux/amd64): name -> sha256
	GoVersion     string            `json:"go_version"`
	BuildImage    string            `json:"build_image"` // the toolchain image the VM builds in
}

var pinRE = regexp.MustCompile(`\b([A-Z]+)_SHA256=([0-9a-f]{64})\b`)

// pins returns the binary pins in a compose's start scripts (AGENTVM_SHA256=… -> "agentvm", BRAIN_SHA256=… ->
// "brain"); nil if one name is pinned to two different hashes.
func pins(compose string) map[string]string {
	out := map[string]string{}
	for _, m := range pinRE.FindAllStringSubmatch(compose, -1) {
		n := strings.ToLower(m[1])
		if prev, ok := out[n]; ok && prev != m[2] {
			return nil
		}
		out[n] = m[2]
	}
	return out
}

func main() {
	check := flag.Bool("check", false, "compare with compose.yaml instead of writing it")
	extractTo := flag.String("extract", "", "unpack the source compose.yaml embeds into this directory, then exit")
	manifest := flag.String("manifest", "", "also write the release manifest (JSON) to this path")
	version := flag.String("version", "", "release version for the manifest (vX.Y.Z)")
	commit := flag.String("commit", "", "release commit for the manifest")
	flag.Parse()
	if *extractTo != "" {
		cur, err := os.ReadFile("compose.yaml")
		if err == nil {
			err = extract(cur, *extractTo)
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Println("extracted the embedded source to", *extractTo)
		return
	}
	out, err := generate()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	h := sha256.Sum256([]byte(out))
	bins := pins(out)
	if len(bins) == 0 {
		fmt.Fprintln(os.Stderr, "no binary pins, or conflicting ones, in the generated compose")
		os.Exit(1)
	}
	if *check {
		cur, _ := os.ReadFile("compose.yaml")
		if string(cur) != out {
			fmt.Println("compose.yaml is stale or was edited: run go run ./cmd/compose")
			os.Exit(1)
		}
		fmt.Printf("compose.yaml matches the source and the reproducible binary hashes\ncompose sha256 %x\n", h)
	} else {
		if err := os.WriteFile("compose.yaml", []byte(out), 0o644); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Printf("wrote compose.yaml (%d bytes, sha256 %x)\n", len(out), h)
	}
	names := make([]string, 0, len(bins))
	for n := range bins {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		fmt.Printf("%-8s sha256 %s\n", n, bins[n])
	}
	if *manifest != "" {
		gover, err := run(nil, "go", "env", "GOVERSION")
		if err != nil || *version == "" || *commit == "" {
			fmt.Fprintln(os.Stderr, "--manifest needs --version and --commit", err)
			os.Exit(1)
		}
		m := Manifest{Schema: "tacy-release/v1", Repository: "https://" + modulePath, Version: *version, Commit: *commit,
			ComposeSHA256: hex.EncodeToString(h[:]), Binaries: bins, GoVersion: strings.TrimSpace(gover), BuildImage: image}
		j, _ := json.MarshalIndent(m, "", "  ")
		if err := os.WriteFile(*manifest, append(j, '\n'), 0o644); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Printf("wrote %s\n", *manifest)
	}
}
