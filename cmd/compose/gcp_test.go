package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tacyhq/tacy/verifier"
)

// TestGCPReleaseIsTheVerifiers: release.json's gcp section, built from dstack's tarball, names the verifier's Google
// sets for every shape, with RTMR1 and RTMR2 the image gives (skips without TACY_DSTACK_GCP_SRC).
func TestGCPReleaseIsTheVerifiers(t *testing.T) {
	src := os.Getenv("TACY_DSTACK_GCP_SRC")
	if src == "" {
		t.Skip("TACY_DSTACK_GCP_SRC unset")
	}
	r, err := gcpRelease(src, t.TempDir(), "")
	if err != nil {
		t.Fatal(err)
	}
	if len(r.BootSets) != len(gcpShapes) || r.Schema != GCPSchema {
		t.Fatalf("%d sets", len(r.BootSets))
	}
	for _, s := range r.BootSets {
		if s.RTMR1 != r.Guest.Boot.RTMR1 || s.RTMR2 != r.Guest.Boot.RTMR2 || len(s.Zones) == 0 || s.BootDiskType == "" {
			t.Errorf("%+v", s)
		}
	}
	// The release's own section passes the endorsement check's offline part; a changed set doesn't.
	dir := t.TempDir()
	write := func(r *GCPRelease) string {
		b, _ := json.Marshal(map[string]any{"gcp": r})
		p := filepath.Join(dir, "release.json")
		os.WriteFile(p, b, 0o644)
		return p
	}
	r.BootSets[0].RTMR0 = strings.Repeat("0", 96)
	if err := gcpEndorsements(write(r)); err == nil || !strings.Contains(err.Error(), "isn't the verifier's") {
		t.Fatalf("a changed RTMR0: %v", err)
	}
}

// TestGCPShapesHaveSets: every shape a release offers has exactly one verifier set (offline).
func TestGCPShapesHaveSets(t *testing.T) {
	for _, sh := range gcpShapes {
		n := 0
		for _, b := range verifier.GCPBootMeasurements {
			if strings.Contains(b.Name, " "+sh.shape+" ") {
				n++
			}
		}
		if n != 1 || len(sh.zones) == 0 {
			t.Errorf("%s: %d sets, %d zones", sh.shape, n, len(sh.zones))
		}
	}
	if err := gcpEndorsements(filepath.Join(t.TempDir(), "none.json")); err == nil {
		t.Fatal("a missing file passed")
	}
}
