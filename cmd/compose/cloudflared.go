package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/tacyhq/tacy/gateway/cftunnel"
	"github.com/tacyhq/tacy/verifier"
)

// The tunnel (a research note; chosen 2026-11-21: Phala Fix B plus our
// patched cloudflared, in-container, as the only way in). Since vm-v1 the release has it: gatewayd's image gets one
// more layer, the pinned cloudflared binary at /tacy/cloudflared, and gatewayd's command line names it, the Access app
// its locally-managed config checks (-cloudflared-access team,aud: gatewayd's launcher writes gateway/cftunnel.Config
// into a memfd it hands cloudflared, so a staging compose changes the Access app as a pin, not as an image;
// vm-v1-gate) and the tunnel token's secret name; there is no gatewayd -listen and no published 8080 (go-condition
// 3), so the tunnel is the only way in. The spike's flags (--cloudflared, --cloudflared-confined,
// --tunnel-spike-routes, --listen) are for development composes only (--dev-out).
var cfd struct {
	bin      []byte
	sha      string
	config   []byte
	secret   string
	spike    bool
	confined bool // the confined variant: cloudflared in its own service (cftunnel), not gatewayd's child
	// access (the release's form): the Access app as gatewayd's -cloudflared-access team,aud, so the image carries no
	// config file and gatewayd's launcher writes cftunnel.Config into a memfd for cloudflared. "" (the spike's
	// --cloudflared): the config is a file of gatewayd's image (-cloudflared-config).
	access   string
	noListen bool // no gatewayd -listen, no published 8080 (go-condition 3): the release's
}

// The release's tunnel pins.
//   - ReleaseCloudflaredSHA256: cloudflared 2026.10.7 (upstream commit ReleaseCloudflaredCommit, fetched by commit,
//     not by tag) with cloudflared/cloudflared-2026.10.7-tacy2.patch (refuses every config the edge pushes; no
//     management service; no WARP or private-network routing: TCP, UDP and ICMP from the edge are refused),
//     fetched by cloudflared/fetch.sh and built by cloudflared/build.sh: byte for byte the same on macOS and in
//     Linux (Docker), and in scripts/reproduce.sh.
//   - tunnelSlots: the vault secret (vault.TunnelSecrets, in the epoch's sealed secrets bundle) gatewayd leases the
//     tunnel token from, per slot: --tunnel-slot a (vm-a) or b (vm-b), chosen per release (blue/green by the
//     Worker's target, never DNS): a release goes on the slot the live one isn't on.
//   - releaseAccessTeam, releaseAccessAUD: the Cloudflare Access app cloudflared checks the JWT of in the TD: the
//     production app tacy-agent-vm over vm-a.tacy.dev and vm-b.tacy.dev (its one policy includes only the chat
//     Worker's service token), made by scripts/ceremony-tunnels.sh on 2026-11-22: verifier.AccessTeam and
//     verifier.AccessAUD, which the verifiers pin by value (verifier.AccessPinOK). Both public. Before then they were
//     placeholders that fail closed (an all-zero audience); --manifest refuses anything but the pinned app
//     (manifestPinsFor, the verifiers' own check).
const (
	ReleaseCloudflaredVersion = "2026.10.7-tacy2"
	ReleaseCloudflaredCommit  = "872b241f94871665c1c157adefcf90c11f0ead96"
	ReleaseCloudflaredSHA256  = "1c8c92c803f5d919c51bf01e1ce8d642d3ec05b51326c214eff756ed4221f0dd"
	releaseAccessTeam         = verifier.AccessTeam
	releaseAccessAUD          = verifier.AccessAUD
)

// tunnelSlots are the release's tunnel slots and the vault secret each one's gatewayd leases its token from
// (vault.TunnelSecrets, in that order; the verifier accepts exactly these two names).
var tunnelSlots = map[string]string{"a": "CF_TUNNEL_TOKEN_VMA", "b": "CF_TUNNEL_TOKEN_VMB"}

// tunnelSecretRE finds gatewayd's tunnel secret in a compose.
var tunnelSecretRE = regexp.MustCompile(`"-tunnel-secret", "CF_TUNNEL_TOKEN_VM([AB])"`)

// committedSlot is the slot a compose's gatewayd names (exactly one -tunnel-secret of the two).
func committedSlot(compose []byte) (string, error) {
	m := tunnelSecretRE.FindAllSubmatch(compose, -1)
	if len(m) != 1 {
		return "", fmt.Errorf("compose.yaml: %d tunnel slots named (want exactly one -tunnel-secret CF_TUNNEL_TOKEN_VMA or _VMB)", len(m))
	}
	return strings.ToLower(string(m[0][1])), nil
}

// tunnelSlot is the release's slot. Writing the release compose (and a manifest without --check) needs --tunnel-slot:
// nothing defaults to a slot, since two VMs on one slot share one tunnel and the edge splits requests between them.
// follow (--check, --dev-out) takes the committed compose.yaml's slot, which it is held to: --check refuses another
// one; a development compose (--dev-out) may take the other slot for a throwaway.
func tunnelSlot(flagSlot string, follow, check bool, committed []byte) (string, error) {
	if _, ok := tunnelSlots[flagSlot]; flagSlot != "" && !ok {
		return "", fmt.Errorf("--tunnel-slot %q: a or b", flagSlot)
	}
	if !follow {
		if flagSlot == "" {
			return "", fmt.Errorf("--tunnel-slot a|b is required: the slot (vm-a, vm-b) whose tunnel token this release's gatewayd " +
				"leases; take the one the live release isn't on (its release.json tunnel_slot)")
		}
		return flagSlot, nil
	}
	c, err := committedSlot(committed)
	if err != nil {
		if flagSlot != "" && !check {
			return flagSlot, nil
		}
		return "", err
	}
	if check && flagSlot != "" && flagSlot != c {
		return "", fmt.Errorf("--check --tunnel-slot %s: the committed compose.yaml is on slot %s", flagSlot, c)
	}
	if flagSlot != "" {
		return flagSlot, nil
	}
	return c, nil
}

// accessPinned says whether the release's Access app is the one the verifiers pin (not a placeholder, not another app).
func accessPinned() bool { return verifier.AccessPinOK(releaseAccessTeam + "," + releaseAccessAUD) }

// manifestPins refuses a release manifest (what a tag needs) unless the release's Access app is the pinned one. The
// key service's compose (--kms) has no tunnel, so it isn't held to it.
func manifestPins(manifest string, kmsMode bool) error {
	return manifestPinsFor(releaseAccessTeam+","+releaseAccessAUD, manifest, kmsMode)
}

func manifestPinsFor(access, manifest string, kmsMode bool) error {
	if manifest != "" && !kmsMode && !verifier.AccessPinOK(access) {
		return fmt.Errorf("--manifest: the release's Access app isn't the pinned one (cmd/compose/cloudflared.go releaseAccessTeam, " +
			"releaseAccessAUD must be verifier.AccessTeam, verifier.AccessAUD); a release can't be cut with placeholders or another app")
	}
	return nil
}

// setReleaseTunnel sets the release's tunnel: the pinned binary (releaseCloudflared), the config for the release's
// Access app, the slot's token (tunnelSlots), no -listen. listen (development composes only) keeps gatewayd's -listen
// :8080 and the published port for harnesses that still reach the VM through Phala's gateway.
func setReleaseTunnel(listen bool, slot string) error {
	secret, ok := tunnelSlots[slot]
	if !ok {
		return fmt.Errorf("tunnel slot %q: a or b", slot)
	}
	b, err := releaseCloudflared()
	if err != nil {
		return err
	}
	access := releaseAccessTeam + "," + releaseAccessAUD
	if _, _, err := cftunnel.ParseAccess(access); err != nil {
		return err
	}
	cfd.bin, cfd.sha, cfd.access, cfd.secret, cfd.noListen = b, ReleaseCloudflaredSHA256, access, secret, !listen
	return nil
}

// releaseCloudflared returns the pinned cloudflared binary, checked against ReleaseCloudflaredSHA256. Where from:
//   - $TACY_CLOUDFLARED_BIN: a binary;
//   - $TACY_CLOUDFLARED_SRC: a tree cloudflared/fetch.sh made (scripts/reproduce.sh fetches on the host, where git
//     is, and builds here, in the pinned Go container), built by cloudflared/build.sh;
//   - else the user's cache, unless $TACY_CLOUDFLARED_FRESH=1 (scripts/reproduce.sh: always from source);
//   - else fetched and built in a fresh directory (git and network: GitHub, the Go module proxy), then cached.
//
// Wherever it comes from, only the pinned bytes are used.
func releaseCloudflared() ([]byte, error) {
	check := func(b []byte, from string) ([]byte, error) {
		if h := sha256.Sum256(b); hex.EncodeToString(h[:]) != ReleaseCloudflaredSHA256 {
			return nil, fmt.Errorf("cloudflared from %s: sha256 %x isn't the pinned %s", from, h, ReleaseCloudflaredSHA256)
		}
		return b, nil
	}
	if p := os.Getenv("TACY_CLOUDFLARED_BIN"); p != "" {
		b, err := os.ReadFile(p)
		if err != nil {
			return nil, err
		}
		return check(b, p)
	}
	fresh := os.Getenv("TACY_CLOUDFLARED_FRESH") == "1"
	src := os.Getenv("TACY_CLOUDFLARED_SRC")
	cache := ""
	if d, err := os.UserCacheDir(); err == nil {
		cache = filepath.Join(d, "tacy", "cloudflared-"+ReleaseCloudflaredVersion+"-linux-amd64")
		if b, err := os.ReadFile(cache); err == nil && !fresh && src == "" {
			if b, err := check(b, cache); err == nil {
				return b, nil
			}
		}
	}
	dir, err := os.MkdirTemp("", "tacy-cloudflared-")
	if err != nil {
		return nil, err
	}
	scripts, err := filepath.Abs(filepath.Join("cmd", "compose", "cloudflared"))
	if err != nil {
		return nil, err
	}
	run := func(name string, args ...string) error {
		cmd := exec.Command("sh", append([]string{filepath.Join(scripts, name)}, args...)...)
		cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("cloudflared: %s: %w (or set TACY_CLOUDFLARED_BIN)", name, err)
		}
		return nil
	}
	if src == "" {
		if err := run("fetch.sh", dir); err != nil {
			return nil, err
		}
		src = filepath.Join(dir, "src")
	}
	out := filepath.Join(dir, "cloudflared-tacy-linux-amd64")
	if err := run("build.sh", src, out); err != nil {
		return nil, err
	}
	b, err := os.ReadFile(out)
	if err != nil {
		return nil, err
	}
	if b, err = check(b, out); err != nil {
		return nil, err
	}
	fmt.Fprintf(os.Stderr, "cloudflared %s (upstream %s) rebuilt from source: sha256 %s\n", ReleaseCloudflaredVersion,
		ReleaseCloudflaredCommit, ReleaseCloudflaredSHA256)
	if cache != "" && os.MkdirAll(filepath.Dir(cache), 0o755) == nil {
		if tmp, err := os.CreateTemp(filepath.Dir(cache), ".cloudflared-*"); err == nil {
			_, werr := tmp.Write(b)
			if cerr := tmp.Close(); werr == nil && cerr == nil {
				os.Rename(tmp.Name(), cache)
			}
			os.Remove(tmp.Name())
		}
	}
	return b, nil
}

// setCloudflared reads --cloudflared (the binary, checked against --cloudflared-sha256), makes the config for
// --cloudflared-access team,aud, and keeps --tunnel-secret (the vault secret name of the tunnel token).
func setCloudflared(path, sum, access, secret string, spike, confined bool) error {
	if path == "" {
		if sum != "" || access != "" || secret != "" || spike || confined {
			return fmt.Errorf("--cloudflared-* and --tunnel-* need --cloudflared")
		}
		return nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	h := sha256.Sum256(b)
	if got := hex.EncodeToString(h[:]); got != sum {
		return fmt.Errorf("--cloudflared %s: sha256 %s, --cloudflared-sha256 pins %s", path, got, sum)
	}
	team, aud, _ := strings.Cut(access, ",")
	sock := cftunnel.SocketPath
	if confined {
		sock = cftunnel.ConfinedSocket
	}
	c, err := cftunnel.ConfigFor(sock, team, aud)
	if err != nil {
		return err
	}
	if secret == "" {
		return fmt.Errorf("--cloudflared needs --tunnel-secret")
	}
	cfd.bin, cfd.sha, cfd.config, cfd.secret, cfd.spike, cfd.confined = b, sum, c, secret, spike, confined
	return nil
}

// cloudflaredLayer is the extra layer of gatewayd's image (nil: none).
func cloudflaredLayer() (*layer, error) {
	if cfd.bin == nil || cfd.confined {
		return nil, nil
	}
	return cloudflaredFiles()
}

// cloudflaredFiles is the layer with the binary and the config.
func cloudflaredFiles() (*layer, error) {
	if cfd.bin == nil {
		return nil, nil
	}
	files := []file{{path: strings.TrimPrefix(cftunnel.BinPath, "/tacy/"), data: cfd.bin}}
	what := "tacy cmd/compose: " + cftunnel.BinPath + " (cloudflared, sha256 " + cfd.sha + ")"
	if cfd.config != nil {
		files = append(files, file{path: strings.TrimPrefix(cftunnel.ConfigPath, "/tacy/"), data: cfd.config, mode: 0o444})
		what += " and " + cftunnel.ConfigPath
	}
	gz, err := filesLayer(files)
	if err != nil {
		return nil, err
	}
	return &layer{gz, what}, nil
}

// cloudflaredArgs are gatewayd's extra flags (-tunnel-uid: gatewayd's launcher starts cloudflared as its own uid) (none when no tunnel is set: unit tests' generateWith).
func cloudflaredArgs() []string {
	if cfd.bin == nil {
		return nil
	}
	if cfd.confined {
		a := []string{"-tunnel-confined", cftunnel.ConfinedDir, "-tunnel-confined-gid", itoa(cftunnel.ConfinedUID), "-tunnel-secret", cfd.secret}
		if cfd.spike {
			a = append(a, "-tunnel-spike-routes")
		}
		return a
	}
	a := []string{"-tunnel-uid", itoa(cftunnel.TunnelUID), "-cloudflared", cftunnel.BinPath, "-cloudflared-sha256", cfd.sha}
	if cfd.access != "" {
		a = append(a, "-cloudflared-access", cfd.access)
	} else {
		a = append(a, "-cloudflared-config", cftunnel.ConfigPath)
	}
	a = append(a, "-tunnel-secret", cfd.secret)
	if cfd.spike {
		a = append(a, "-tunnel-spike-routes")
	}
	return a
}

func itoa(n int) string { return fmt.Sprint(n) }

// nextService is the start of the next service (or top-level key) in a compose.
var nextService = regexp.MustCompile(`\n(  )?[a-z0-9_-]+:\n`)

// confine edits the generated compose for the confined variant: setup makes /run/tacy/cft (gatewayd's, group
// cloudflared's) in the cftsock volume; gatewayd mounts it and joins cloudflared's group; the cftunnel service (its own
// uid, no capabilities, its own network cft, only that volume) runs the pinned cloudflared image.
func confine(c, ref string) (string, error) {
	uid := itoa(cftunnel.ConfinedUID)
	section := func(name string) (int, int) {
		i := strings.Index(c, "\n  "+name+":\n")
		if i < 0 {
			return -1, -1
		}
		if m := nextService.FindStringIndex(c[i+1:]); m != nil {
			return i, i + 1 + m[0]
		}
		return i, len(c)
	}
	edit := func(name, old, new string) error {
		i, j := section(name)
		if i < 0 || strings.Count(c[i:j], old) != 1 {
			return fmt.Errorf("confine: %s: %q", name, old)
		}
		c = c[:i] + strings.Replace(c[i:j], old, new, 1) + c[j:]
		return nil
	}
	if err := edit("setup", "      - unlockgw:/run/tacy/unlockgw\n", "      - unlockgw:/run/tacy/unlockgw\n      - cftsock:"+cftunnel.ConfinedDir+"\n"); err != nil {
		return "", err
	}
	if err := edit("setup", `"-dir", "/run/tacy/unlockgw=10001:10001:0750"`, `"-dir", "/run/tacy/unlockgw=10001:10001:0750", "-dir", "`+cftunnel.ConfinedDir+`=10001:`+uid+`:0750"`); err != nil {
		return "", err
	}
	if err := edit("agentvm", "      - unlockgw:/run/tacy/unlockgw\n", "      - unlockgw:/run/tacy/unlockgw\n      - cftsock:"+cftunnel.ConfinedDir+"\n"); err != nil {
		return "", err
	}
	if err := edit("agentvm", `    user: "10001:10001"`+"\n", `    user: "10001:10001"`+"\n"+`    group_add: ["`+uid+`"]`+"\n"); err != nil {
		return "", err
	}
	svc := `  cftunnel:
    # The cloudflared spike, confined variant: Cloudflare's tunnel client in a container of its own (its own uid, its
    # own network, no capabilities), its only local peer gatewayd's ingress socket in the cftsock volume.
    image: ` + ref + `
    entrypoint: ["` + cftunnel.BinPath + `"]
    restart: unless-stopped
    logging:
      driver: none
    ulimits:
      core: 0
    depends_on:
      setup:
        condition: service_completed_successfully
    user: "` + uid + `:` + uid + `"
    read_only: true
    cap_drop: [ALL]
    security_opt: ["no-new-privileges:true"]
    networks: [cft]
    volumes:
      - cftsock:` + cftunnel.ConfinedDir + `
    command: ["tunnel", "--config", "` + cftunnel.ConfigPath + `", "--no-autoupdate", "--protocol", "http2", "--management-diagnostics=false", "--metrics", "127.0.0.1:0", "--loglevel", "info", "run", "--token-file", "` + cftunnel.ConfinedToken + `"]
`
	i := strings.Index(c, "\nvolumes:\n")
	if i < 0 {
		return "", fmt.Errorf("confine: no volumes:")
	}
	c = c[:i+1] + svc + c[i+1:]
	c += "  cftsock:\n    driver_opts:\n      type: tmpfs\n      device: tmpfs\n      o: \"size=1m,uid=10001,gid=" + uid + ",mode=0750\"\n"
	c += "networks:\n  cft: {}\n"
	return c, nil
}
