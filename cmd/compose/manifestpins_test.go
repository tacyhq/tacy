package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// mainEnv makes the test binary run main() with the arguments after "--" (TestManifestRefusesPlaceholders).
const mainEnv = "TACY_COMPOSE_TEST_MAIN"

func TestMain(m *testing.M) {
	if os.Getenv(mainEnv) == "1" {
		for i, a := range os.Args {
			if a == "--" {
				os.Args = append([]string{os.Args[0]}, os.Args[i+1:]...)
				break
			}
		}
		main()
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// Until the production Access app exists (a Cloudflare setup step), the release's team and audience are placeholders
// that fail closed, and a release manifest (what a tag needs) is refused, before anything is fetched or built. The
// key service's compose has no tunnel and isn't held to it.
func TestManifestRefusesPlaceholders(t *testing.T) {
	if releaseAccessTeam != "unpinned" || releaseAccessAUD != strings.Repeat("0", 64) {
		t.Skip("the production Access app is pinned: this test is for the placeholders")
	}
	if accessPinned() {
		t.Fatal("the placeholders count as pinned")
	}
	if err := manifestPins("release.json", false); err == nil || !strings.Contains(err.Error(), "isn't pinned yet") {
		t.Fatalf("a release manifest with the placeholders: %v", err)
	}
	if err := manifestPins("", false); err != nil {
		t.Fatalf("no manifest: %v", err)
	}
	if err := manifestPins("kms-release.json", true); err != nil {
		t.Fatalf("the key service's manifest: %v", err)
	}
	// The command itself, as a release tag runs it: refused at once (no cloudflared fetched, nothing written).
	out := filepath.Join(t.TempDir(), "release.json")
	cmd := exec.Command(os.Args[0], "-test.run=^$", "--", "--check", "--manifest", out, "--version", "v1.0.0", "--commit", strings.Repeat("a", 40))
	cmd.Env = append(os.Environ(), mainEnv+"=1", "TACY_CLOUDFLARED_BIN=/nonexistent")
	b, err := cmd.CombinedOutput()
	if err == nil || !strings.Contains(string(b), "Access app isn't pinned yet") {
		t.Fatalf("compose --manifest with the placeholders: %v\n%s", err, b)
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Fatalf("a manifest was written: %v", err)
	}
}
