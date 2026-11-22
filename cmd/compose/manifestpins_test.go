package main

import (
	"os"
	"strings"
	"testing"

	"github.com/tacyhq/tacy/verifier"
)

// mainEnv makes the test binary run main() with the arguments after "--" (tunnelslot_test.go runs the command).
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

// A release manifest (what a tag needs) names only the pinned Access app (verifier.AccessPinOK, the verifiers' own
// check): the placeholders, another app of the team, another team and malformed values are refused, before anything
// is fetched or built; the release's own constants pass. The key service's compose has no tunnel and isn't held to it.
func TestManifestAccessPin(t *testing.T) {
	zero := strings.Repeat("0", 64)
	for name, access := range map[string]string{
		"the placeholders":          "unpinned," + zero,
		"our team, the zero aud":    verifier.AccessTeam + "," + zero,
		"another app of our team":   verifier.AccessTeam + "," + strings.Repeat("ab", 32),
		"another team, our aud":     "kikosh," + verifier.AccessAUD,
		"our app, a trailing space": verifier.AccessTeam + "," + verifier.AccessAUD + " ",
		"our app in capitals":       strings.ToUpper(verifier.AccessTeam) + "," + verifier.AccessAUD,
		"no comma":                  verifier.AccessTeam + verifier.AccessAUD,
	} {
		if err := manifestPinsFor(access, "release.json", false); err == nil || !strings.Contains(err.Error(), "isn't the pinned one") {
			t.Errorf("%s: a release manifest: %v", name, err)
		}
		if err := manifestPinsFor(access, "", false); err != nil {
			t.Errorf("%s: no manifest: %v", name, err)
		}
		if err := manifestPinsFor(access, "kms-release.json", true); err != nil {
			t.Errorf("%s: the key service's manifest: %v", name, err)
		}
	}
	if err := manifestPinsFor(verifier.AccessTeam+","+verifier.AccessAUD, "release.json", false); err != nil {
		t.Fatalf("the pinned app: %v", err)
	}
	if !accessPinned() || manifestPins("release.json", false) != nil {
		t.Fatalf("the release's own constants (%s,%s) aren't the pinned app", releaseAccessTeam, releaseAccessAUD)
	}
	if !verifier.AccessPinOK(cfdAccessOf(t)) {
		t.Fatal("the release compose's -cloudflared-access isn't the pinned app")
	}
}

// cfdAccessOf is the committed compose.yaml's -cloudflared-access value.
func cfdAccessOf(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("../../compose.yaml")
	if err != nil {
		t.Fatal(err)
	}
	_, rest, ok := strings.Cut(string(b), `"-cloudflared-access", "`)
	v, _, ok2 := strings.Cut(rest, `"`)
	if !ok || !ok2 {
		t.Fatal("compose.yaml has no -cloudflared-access")
	}
	return v
}
