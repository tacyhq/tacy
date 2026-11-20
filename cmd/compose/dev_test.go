package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDevPins(t *testing.T) {
	dir := t.TempDir()
	write := func(s string) string {
		p := filepath.Join(dir, "pins.json")
		os.WriteFile(p, []byte(s), 0o600)
		return p
	}
	good := `{"relay_auth_key": "ed25519:` + strings.Repeat("A", 43) + `=", "kms_id": "ed25519:` + strings.Repeat("B", 43) +
		`=", "kms_urls": ["https://kms.example"], "state_url": "https://standin.example/"}`
	p, err := loadDevPins(write(good))
	if err != nil {
		t.Fatal(err)
	}
	if p.stateURL != "https://standin.example" || len(p.kmsURLs) != 1 {
		t.Fatalf("%+v", p)
	}
	for _, bad := range []string{
		strings.Replace(good, `"kms_urls": ["https://kms.example"]`, `"kms_urls": []`, 1),
		strings.Replace(good, "https://kms.example", "http://kms.example", 1),
		strings.Replace(good, `"state_url"`, `"extra": 1, "state_url"`, 1),
		strings.Replace(good, `"ed25519:`+strings.Repeat("B", 43)+`="`, `"nope"`, 1),
	} {
		if _, err := loadDevPins(write(bad)); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
	for _, r := range []string{Registry, "ghcr.io/tacyhq/other", "ttl.sh/x@y"} {
		if setDevRegistry(r) == nil {
			t.Errorf("--dev-registry %s accepted", r)
		}
	}
	if err := setDevRegistry("ttl.sh/0123abcd"); err != nil || registry != "ttl.sh/0123abcd" {
		t.Fatalf("%v %s", err, registry)
	}
	registry = Registry
}
