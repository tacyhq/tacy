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
)

// The tunnel (a research note; chosen 2026-11-21: Phala Fix B plus our
// patched cloudflared, in-container, as the only way in). Since vm-v1 the release has it: gatewayd's image gets one
// more layer, the pinned cloudflared binary at /tacy/cloudflared and its locally-managed config at
// /tacy/cloudflared.yml (gateway/cftunnel.Config), and gatewayd's command line names them and the tunnel token's
// secret name; there is no gatewayd -listen and no published 8080 (go-condition 3), so the tunnel is the only way
// in. The spike's flags (--cloudflared, --cloudflared-confined, --tunnel-spike-routes, --listen) are for development
// composes only (--dev-out).
var cfd struct {
	bin      []byte
	sha      string
	config   []byte
	secret   string
	spike    bool
	confined bool // the confined variant: cloudflared in its own service (cftunnel), not gatewayd's child
	noListen bool // no gatewayd -listen, no published 8080 (go-condition 3): the release's
}

// The release's tunnel pins.
//   - ReleaseCloudflaredSHA256: cloudflared 2026.10.7 with cmd/cfdlocal/cloudflared-2026.10.7-tacy1.patch (refuses
//     every config the edge pushes; no management service), built by cmd/cfdlocal/build-cloudflared.sh, byte for
//     byte the same from two source trees (2026-11-21, and again for vm-v1).
//   - releaseTunnelSecret: the vault secret (vault.TunnelSecrets, in the epoch's sealed secrets bundle) gatewayd
//     leases the tunnel token from: slot vm-a. A release on slot vm-b names CF_TUNNEL_TOKEN_VMB (blue/green by the
//     Worker's target, never DNS).
//   - releaseAccessTeam, releaseAccessAUD: the Cloudflare Access app cloudflared checks the JWT of in the TD. NOT
//     PINNED YET: the production Access app and tunnel are made at the Cloudflare setup (a live step the owner
//     approves). Until then these placeholders fail closed (no Access app has an all-zero audience, so cloudflared
//     refuses every request) and --manifest, which a release tag needs, refuses them (accessPinned).
const (
	ReleaseCloudflaredVersion = "2026.10.7-tacy1"
	ReleaseCloudflaredSHA256  = "24fdcd7ecc7b4c05a0313f498a42af254e71a2e28e50273fb2dee0834d1ec946"
	releaseTunnelSecret       = "CF_TUNNEL_TOKEN_VMA"
	releaseAccessTeam         = "unpinned"
	releaseAccessAUD          = "0000000000000000000000000000000000000000000000000000000000000000"
)

// accessPinned says whether the release's Access app is pinned (not the placeholders).
func accessPinned() bool {
	return releaseAccessTeam != "unpinned" && releaseAccessAUD != strings.Repeat("0", 64)
}

// setReleaseTunnel sets the release's tunnel: the pinned binary (releaseCloudflared), the config for the release's
// Access app, slot vm-a's token, no -listen. listen (development composes only) keeps gatewayd's -listen :8080 and
// the published port for harnesses that still reach the VM through Phala's gateway.
func setReleaseTunnel(listen bool) error {
	b, err := releaseCloudflared()
	if err != nil {
		return err
	}
	c, err := cftunnel.ConfigFor(cftunnel.SocketPath, releaseAccessTeam, releaseAccessAUD)
	if err != nil {
		return err
	}
	cfd.bin, cfd.sha, cfd.config, cfd.secret, cfd.noListen = b, ReleaseCloudflaredSHA256, c, releaseTunnelSecret, !listen
	return nil
}

// releaseCloudflared returns the pinned cloudflared binary, checked against ReleaseCloudflaredSHA256: from
// $TACY_CLOUDFLARED_BIN if set, else from the user's cache, else built by cmd/cfdlocal/build-cloudflared.sh in a fresh
// directory (git and network: GitHub and the Go toolchain; then cached). Wherever it comes from, only the pinned
// bytes are used.
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
	cache := ""
	if d, err := os.UserCacheDir(); err == nil {
		cache = filepath.Join(d, "tacy", "cloudflared-"+ReleaseCloudflaredVersion+"-linux-amd64")
		if b, err := os.ReadFile(cache); err == nil {
			if b, err := check(b, cache); err == nil {
				return b, nil
			}
		}
	}
	dir, err := os.MkdirTemp("", "tacy-cloudflared-")
	if err != nil {
		return nil, err
	}
	script, err := filepath.Abs(filepath.Join("cmd", "cfdlocal", "build-cloudflared.sh"))
	if err != nil {
		return nil, err
	}
	cmd := exec.Command("sh", script, dir)
	cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("cloudflared: build-cloudflared.sh: %w (or set TACY_CLOUDFLARED_BIN)", err)
	}
	out := filepath.Join(dir, "cloudflared-tacy-linux-amd64")
	b, err := os.ReadFile(out)
	if err != nil {
		return nil, err
	}
	if b, err = check(b, out); err != nil {
		return nil, err
	}
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
	gz, err := filesLayer([]file{{path: strings.TrimPrefix(cftunnel.BinPath, "/tacy/"), data: cfd.bin},
		{path: strings.TrimPrefix(cftunnel.ConfigPath, "/tacy/"), data: cfd.config, mode: 0o444}})
	if err != nil {
		return nil, err
	}
	return &layer{gz, "tacy cmd/compose: " + cftunnel.BinPath + " (cloudflared, sha256 " + cfd.sha + ") and " + cftunnel.ConfigPath}, nil
}

// cloudflaredArgs are gatewayd's extra flags (none when no tunnel is set: unit tests' generateWith).
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
	a := []string{"-cloudflared", cftunnel.BinPath, "-cloudflared-sha256", cfd.sha, "-cloudflared-config", cftunnel.ConfigPath,
		"-tunnel-secret", cfd.secret}
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
