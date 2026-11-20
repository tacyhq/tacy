package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/tacyhq/tacy/kms"
	"github.com/tacyhq/tacy/safety"
)

// A development compose (throwaway CVMs before a release exists): --dev-out DIR writes the compose, app-compose.json
// and the deploy form there, never over the repo's compose.yaml; --dev-pins FILE replaces the release's pins (the
// relay key, the key service, the state API) with a staging set, and --dev-registry names the images in a scratch
// registry they are pushed to (cmd/e2e push-images; the digests are the same, only the repository differs). The
// release itself never uses any of these: its compose is `go run ./cmd/compose` with the pins in this package, and
// its images are the release workflow's.
//
//	go run ./cmd/compose --dev-out DIR --dev-pins pins.json [--dev-registry ttl.sh/<random>] [--oci DIR/oci]
//	go run ./cmd/compose --kms --kms-staging --kms-admin-keys … --dev-out DIR [--dev-registry …] [--oci DIR/oci]
//
// pins.json: {"relay_auth_key": "ed25519:…", "kms_id": "ed25519:…", "kms_urls": ["https://…"], "state_url": "https://…"}
// (public values only; the private halves stay with whoever runs the throwaway).

// devPinsFile is --dev-pins.
type devPinsFile struct {
	RelayAuthKey string   `json:"relay_auth_key"`
	KMSID        string   `json:"kms_id"`
	KMSURLs      []string `json:"kms_urls"`
	StateURL     string   `json:"state_url"`
}

// registry is where the composes name the images: Registry, or --dev-registry.
var registry = Registry

// loadDevPins reads and checks a --dev-pins file. A staging set may not name the production relay key.
func loadDevPins(path string) (releasePins, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return releasePins{}, err
	}
	var f devPinsFile
	d := json.NewDecoder(strings.NewReader(string(b)))
	d.DisallowUnknownFields()
	if err := d.Decode(&f); err != nil {
		return releasePins{}, fmt.Errorf("%s: %w", path, err)
	}
	if _, err := safety.ParseKey(f.RelayAuthKey); err != nil {
		return releasePins{}, fmt.Errorf("%s: relay_auth_key: %w", path, err)
	}
	if relayAuthKey != "" && f.RelayAuthKey == relayAuthKey {
		return releasePins{}, fmt.Errorf("%s: relay_auth_key is the production one: a development compose pins a dev key", path)
	}
	if _, err := kms.ParseID(f.KMSID); err != nil {
		return releasePins{}, fmt.Errorf("%s: kms_id: %w", path, err)
	}
	if kmsID != "" && f.KMSID == kmsID {
		return releasePins{}, fmt.Errorf("%s: kms_id is the production key service: a development compose uses a staging one", path)
	}
	if len(f.KMSURLs) == 0 {
		return releasePins{}, fmt.Errorf("%s: kms_urls is empty", path)
	}
	for _, u := range append(append([]string(nil), f.KMSURLs...), f.StateURL) {
		if !strings.HasPrefix(u, "https://") || strings.ContainsAny(u, " \"") {
			return releasePins{}, fmt.Errorf("%s: %q isn't an https URL", path, u)
		}
	}
	return releasePins{relayAuthKey: f.RelayAuthKey, kmsID: f.KMSID, kmsURLs: f.KMSURLs, stateURL: strings.TrimSuffix(f.StateURL, "/")}, nil
}

// setDevRegistry checks and sets --dev-registry (never the release's own registry).
func setDevRegistry(r string) error {
	r = strings.TrimSuffix(r, "/")
	if r == "" {
		return nil
	}
	if r == Registry || strings.HasPrefix(r, "ghcr.io/tacyhq/") {
		return fmt.Errorf("--dev-registry %q: a development build never names the release's registry", r)
	}
	if strings.ContainsAny(r, " \"@:") {
		return fmt.Errorf("--dev-registry %q: want host/path", r)
	}
	registry = r
	return nil
}

// devPath is name in the --dev-out directory (or name itself: the repo's file, for a release).
func devPath(dir, name string) string {
	if dir == "" {
		return name
	}
	return filepath.Join(dir, name)
}
