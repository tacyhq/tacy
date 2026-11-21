package main

import (
	"slices"
	"strings"
	"testing"

	agentvm "github.com/tacyhq/tacy"
	"github.com/tacyhq/tacy/verifier"
)

// The confined variant's compose (cloudflared as a seventh service, cftunnel): the release verifier (the six
// services, since vm-v1's in-container decision) refuses it; a verifier that lists cftunnel too (what that variant
// would need: a signed trust list's services, or a client build and a holder redeploy) takes it.
func TestConfinedCompose(t *testing.T) {
	ref := "ghcr.io/tacyhq/tacy/cftunnel@sha256:" + strings.Repeat("ab", 32)
	c, err := confine(string(agentvm.Compose), ref)
	if err != nil {
		t.Fatal(err)
	}
	if len(verifier.ReleaseServices) != 6 || slices.Contains(verifier.ReleaseServices, "cftunnel") {
		t.Fatalf("release services %v", verifier.ReleaseServices)
	}
	if _, err := verifier.ComposeImages(c); err == nil || !strings.Contains(err.Error(), "cftunnel") {
		t.Fatalf("the release verifier takes the confined compose: %v", err)
	}
	if _, err := verifier.ComposeImagesFor(c, append(slices.Clone(verifier.ReleaseServices), "cftunnel")); err != nil {
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
