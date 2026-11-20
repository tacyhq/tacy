package tacy

import (
	"bytes"
	"flag"
	"os"
	"testing"

	"github.com/tacyhq/tacy/verifier"
)

var update = flag.Bool("update", false, "rewrite app-compose.json and app-compose.deploy.json from compose.yaml (what go run ./cmd/compose writes)")

// app-compose.json is the release's: compose.yaml with the settings verifier.ReleaseAppCompose writes, in the key mode
// KMSFallback names; app-compose.deploy.json what the deploy sends for it. go run ./cmd/compose writes both with
// compose.yaml; this catches an edit of either by hand without the image build (go test -run TestAppCompose -update
// rewrites them).
func TestAppCompose(t *testing.T) {
	want, err := ReleaseAppCompose(Compose)
	if err != nil {
		t.Fatal(err)
	}
	deploy, err := verifier.DeployAppCompose(want)
	if err != nil {
		t.Fatal(err)
	}
	if *update {
		if err := os.WriteFile("app-compose.json", want, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile("app-compose.deploy.json", deploy, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	if !bytes.Equal(AppCompose, want) {
		t.Fatal("app-compose.json isn't the release's for compose.yaml: run go run ./cmd/compose")
	}
	if b, _ := os.ReadFile("app-compose.deploy.json"); !bytes.Equal(b, deploy) {
		t.Fatal("app-compose.deploy.json isn't the one for app-compose.json: run go run ./cmd/compose")
	}
}
