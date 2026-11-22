package main

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	agentvm "github.com/tacyhq/tacy"
	"github.com/tacyhq/tacy/verifier"
)

// The confined variant's compose (cloudflared as a seventh service, cftunnel): the release verifier (the six
// services, since vm-v1's in-container decision) refuses it, and so does one that lists cftunnel too (its gatewayd
// and its network aren't the release's shape: that variant would need a client build and a holder redeploy).
func TestConfinedCompose(t *testing.T) {
	ref := "ghcr.io/tacyhq/tacy/cftunnel@sha256:" + strings.Repeat("ab", 32)
	// The confined variant has no launcher: gatewayd's container as before review H1 (user 10001, no capabilities).
	launcher := "    user: \"0:0\"\n    read_only: true\n    cap_drop: [ALL]\n    cap_add: [SETGID, SETUID]\n"
	if strings.Count(string(agentvm.Compose), launcher) != 1 {
		t.Fatal("compose.yaml: gatewayd isn't the launcher's")
	}
	base := strings.Replace(string(agentvm.Compose), launcher, "    user: \"10001:10001\"\n    read_only: true\n    cap_drop: [ALL]\n", 1)
	c, err := confine(base, ref)
	if err != nil {
		t.Fatal(err)
	}
	if len(verifier.ReleaseServices) != 6 || slices.Contains(verifier.ReleaseServices, "cftunnel") {
		t.Fatalf("release services %v", verifier.ReleaseServices)
	}
	if _, err := verifier.ComposeImages(c); err == nil || !strings.Contains(err.Error(), "cftunnel") {
		t.Fatalf("the release verifier takes the confined compose: %v", err)
	}
	// Listing cftunnel (a signed trust list's services) isn't enough since review 2's M1: the confined variant changes
	// gatewayd's container and adds a network, so a release with unlockd isn't cmd/compose's release shape; that
	// variant would need a verifier build (clients and holders first).
	if _, err := verifier.ComposeImagesFor(c, append(slices.Clone(verifier.ReleaseServices), "cftunnel")); err == nil ||
		!strings.Contains(err.Error(), "release shape") {
		t.Fatalf("with cftunnel listed: %v", err)
	}
	for _, want := range []string{"  cftunnel:\n", "    networks: [cft]\n", "      - cftsock:/run/tacy/cft\n", `    group_add: ["10006"]`, "networks:\n  cft: {}\n"} {
		if !strings.Contains(c, want) {
			t.Errorf("no %q", want)
		}
	}
	if strings.Count(c, "- /var/run/dstack.sock:") != 1 {
		t.Error("only unlockd mounts the dstack socket")
	}
}

// Review M2: the cloudflared build is pinned by upstream commit (not a tag), the patch and the version are the ones
// cmd/compose names, and the release pin is a sha256.
func TestCloudflaredBuildPins(t *testing.T) {
	fetch, err := os.ReadFile("cloudflared/fetch.sh")
	if err != nil {
		t.Fatal(err)
	}
	build, err := os.ReadFile("cloudflared/build.sh")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(fetch), "commit="+ReleaseCloudflaredCommit+" ") ||
		!strings.Contains(string(fetch), `[ "$got" = "$commit" ]`) || strings.Contains(string(fetch), "--branch") {
		t.Fatal("fetch.sh doesn't fetch and check the pinned commit")
	}
	patch := "cloudflared-" + strings.Split(ReleaseCloudflaredVersion, "-")[0] + "-" + strings.Split(ReleaseCloudflaredVersion, "-")[1] + ".patch"
	if !strings.Contains(string(fetch), "patch="+patch) {
		t.Fatalf("fetch.sh doesn't apply %s", patch)
	}
	p, err := os.ReadFile(filepath.Join("cloudflared", patch))
	if err != nil {
		t.Fatal(err)
	}
	// The patch's three refusals and their tests (run in the cloudflared tree: go test -run Tacy ...).
	for _, want := range []string{"RefuseRemoteConfig", "internalRules := []ingress.Rule{}", "return ErrWarpRoutingRefused",
		"return nil, ErrPrivateRoutingRefused", "return nil, errICMPRefused", "func TestTacyRefusesWarpTCP", "func TestTacyOriginDialerRefuses",
		"func TestTacyNoICMPRouter", "func TestTacyRefusesRemoteConfig"} {
		if !strings.Contains(string(p), want) {
			t.Errorf("the patch has no %q", want)
		}
	}
	if !strings.Contains(string(build), "-X main.Version="+ReleaseCloudflaredVersion+" ") {
		t.Fatal("build.sh stamps another version")
	}
	if len(ReleaseCloudflaredSHA256) != 64 || len(ReleaseCloudflaredCommit) != 40 {
		t.Fatal("pins")
	}
	if a := strings.Join(cloudflaredArgsFor(), " "); !strings.Contains(a, "-tunnel-uid 10006 ") {
		t.Fatalf("gatewayd's tunnel flags: %s", a)
	}
}

// cloudflaredArgsFor is cloudflaredArgs with a stand-in in-container tunnel.
func cloudflaredArgsFor() []string {
	saved := cfd
	defer func() { cfd = saved }()
	cfd.bin, cfd.sha, cfd.secret, cfd.confined, cfd.spike = []byte{1}, ReleaseCloudflaredSHA256, "CF_TUNNEL_TOKEN_VMA", false, false
	return cloudflaredArgs()
}
