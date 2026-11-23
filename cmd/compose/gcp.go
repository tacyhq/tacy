package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/tacyhq/tacy/internal/gcetcb"
	"github.com/tacyhq/tacy/internal/gcpimage"
	"github.com/tacyhq/tacy/verifier"
)

// The Google Cloud part of a release: `--gcp-out DIR` with --manifest. The same
// compose.yaml, app-compose.json and images as the Phala release, plus what a Google Cloud TDX VM boots from, all
// made here from dstack's published OS image (internal/gcpimage) and signed with the rest:
//
//	DIR/gcp-boot.tar.gz       the boot disk (dstack's disk.raw), the form Compute Engine imports
//	DIR/gcp-data.tar.gz       the data disk (one empty GPT partition; formatted in the VM under a key made there)
//	DIR/gcp-sys-config.json   dstack's system config for key provider none, the shared disk's .sys-config.json
//
// and release.json's "gcp": the dstack source (URL, sha256, os-image-hash), the files' sha256s, the boot
// measurements computed from the image (the GPT, UKI and kernel events, RTMR1, RTMR2) and the boot sets a Google VM
// of this release must match (the verifier's GCPBootMeasurements: Google's firmware MRTDs we reviewed, the minimum
// SVN, RTMR0 per shape; RTMR1 and RTMR2 must equal what the image gives, or nothing is written), with the shape's
// disk type and zones.
//
// The dstack tarball (630 MB): $TACY_DSTACK_GCP_SRC, else the user cache, else downloaded (`--gcp-fetch DIR` only
// downloads and checks it, for release.yml and scripts/reproduce.sh to share one copy). It must hash to the pinned
// gcpimage.Dstack066.SHA256.

// GCPSchema is release.json's gcp section schema. Readers (cmd/e2e create --gcp, the chat Worker's host adapter)
// must refuse another.
const GCPSchema = "tacy-gcp/v1"

// GCPRelease is release.json's "gcp" (field names are stable: readers outside this repository depend on them).
type GCPRelease struct {
	Schema   string          `json:"schema"`
	Guest    *gcpimage.Guest `json:"guest"`
	BootSets []GCPBootSet    `json:"boot_sets"`
	Platform GCPPlatform     `json:"platform"`
}

// GCPBootSet is one machine shape a release's VM may run on, and the measurements its quote must show.
type GCPBootSet struct {
	Shape          string   `json:"shape"` // Compute Engine machine type, e.g. c3-standard-4
	Name           string   `json:"name"`  // the verifier's set name
	MRTDs          []string `json:"mrtds"` // Google firmware builds we reviewed (and Google endorses)
	MinFirmwareSVN uint32   `json:"min_firmware_svn"`
	RTMR0          string   `json:"rtmr0"` // per shape: Google's firmware configuration (observed, reviewed)
	RTMR1          string   `json:"rtmr1"` // = guest.boot.rtmr1 (computed from the image)
	RTMR2          string   `json:"rtmr2"` // = guest.boot.rtmr2
	BootDiskType   string   `json:"boot_disk_type"`
	Zones          []string `json:"zones"` // where the set was observed; create refuses others
}

// GCPPlatform is how a VM of the release is created (cmd/e2e create --gcp and the adapter use exactly this).
type GCPPlatform struct {
	ConfidentialCompute string   `json:"confidential_compute"` // TDX
	MaintenancePolicy   string   `json:"maintenance_policy"`   // TERMINATE (TDX can't live-migrate)
	NIC                 string   `json:"nic"`                  // GVNIC
	BootImageFeatures   []string `json:"boot_image_features"`  // guest OS features of the imported boot image
	DiskImageFeatures   []string `json:"disk_image_features"`  // of the data and shared disk images
	BootDiskGB          int      `json:"boot_disk_gb"`
	DataDiskGB          int      `json:"data_disk_gb"`
	SharedDiskGB        int      `json:"shared_disk_gb"`
	ServiceAccount      bool     `json:"service_account"` // false: the VM gets no Google credentials
	AppID               string   `json:"app_id"`          // how the shared disk's app id is chosen
}

// gcpShapes are the machine shapes a release offers: the verifier's set for each (by name) and its boot disk type
// and the zones where that set was observed (the verifier's Source notes; docs/research 2026-11-21 G3).
var gcpShapes = []struct {
	shape, diskType string
	zones           []string
}{
	{"c3-standard-4", "pd-balanced", []string{"us-central1-a", "us-central1-b", "us-central1-c", "us-east1-c", "us-east1-d"}},
	{"c4-standard-2", "hyperdisk-balanced", []string{"us-central1-f", "us-east4-c"}},
}

func gcpPlatform() GCPPlatform {
	return GCPPlatform{ConfidentialCompute: "TDX", MaintenancePolicy: "TERMINATE", NIC: "GVNIC",
		BootImageFeatures: []string{"UEFI_COMPATIBLE", "TDX_CAPABLE", "GVNIC"}, DiskImageFeatures: []string{"GVNIC"},
		BootDiskGB: 10, DataDiskGB: 10, SharedDiskGB: 1, AppID: gcpimage.AppIDRule}
}

// gcpRelease builds the release's Google Cloud files into out and returns release.json's section. tmp: scratch for
// disk.raw (out if empty).
func gcpRelease(src, out, tmp string) (*GCPRelease, error) {
	s := gcpimage.Dstack066
	if _, ok := verifier.GCPImages[s.OSImageHash]; !ok {
		return nil, fmt.Errorf("dstack %s (os-image-hash %s) isn't a verifier GCP image", s.Dstack, s.OSImageHash)
	}
	g, err := gcpimage.BuildGuest(s, src, out, tmp)
	if err != nil {
		return nil, err
	}
	r := &GCPRelease{Schema: GCPSchema, Guest: g, Platform: gcpPlatform()}
	for _, sh := range gcpShapes {
		var set *verifier.BootMeasurement
		for i, b := range verifier.GCPBootMeasurements {
			if b.OSImage == s.OSImageHash && strings.Contains(b.Name, " "+sh.shape+" ") {
				if set != nil {
					return nil, fmt.Errorf("two verifier GCP sets for %s", sh.shape)
				}
				set = &verifier.GCPBootMeasurements[i]
			}
		}
		if set == nil {
			return nil, fmt.Errorf("no verifier GCP set for %s on dstack %s", sh.shape, s.Dstack)
		}
		// The image decides RTMR1 and RTMR2 (and the UKI): what the verifier pins must be what this image gives.
		if !strings.EqualFold(set.RTMR1, g.Boot.RTMR1) || !strings.EqualFold(set.RTMR2, g.Boot.RTMR2) || !strings.EqualFold(set.UKI, g.Boot.UKI) {
			return nil, fmt.Errorf("%s: the verifier pins RTMR1 %s, RTMR2 %s, UKI %s; the image gives %s, %s, %s", set.Name,
				short(set.RTMR1), short(set.RTMR2), short(set.UKI), short(g.Boot.RTMR1), short(g.Boot.RTMR2), short(g.Boot.UKI))
		}
		if set.MRTD != verifier.MRTDGoogleEndorsed || len(set.GoogleMRTDs) == 0 {
			return nil, fmt.Errorf("%s: no reviewed Google MRTD", set.Name)
		}
		r.BootSets = append(r.BootSets, GCPBootSet{Shape: sh.shape, Name: set.Name, MRTDs: slices.Clone(set.GoogleMRTDs),
			MinFirmwareSVN: set.MinFirmwareSVN, RTMR0: set.RTMR0, RTMR1: set.RTMR1, RTMR2: set.RTMR2, BootDiskType: sh.diskType,
			Zones: slices.Clone(sh.zones)})
	}
	return r, nil
}

func short(h string) string {
	if len(h) > 16 {
		return h[:16] + "…"
	}
	return h
}

// gcpSource is the dstack tarball's path: $TACY_DSTACK_GCP_SRC, the cache, or a fresh download into the cache (or
// into dir, for --gcp-fetch). Its sha256 is checked by gcpimage.BuildGuest (and here before a download is kept).
func gcpSource(dir string) (string, error) {
	s := gcpimage.Dstack066
	if p := os.Getenv("TACY_DSTACK_GCP_SRC"); p != "" && dir == "" {
		return p, nil
	}
	if dir == "" {
		d, err := os.UserCacheDir()
		if err != nil {
			return "", err
		}
		dir = filepath.Join(d, "tacy")
	}
	p := filepath.Join(dir, filepath.Base(s.URL))
	if sum, err := fileSHA256(p); err == nil && sum == s.SHA256 {
		return p, nil
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	fmt.Printf("downloading dstack %s's image for Google Cloud (%s)\n", s.Dstack, s.URL)
	resp, err := http.Get(s.URL)
	if err != nil {
		return "", fmt.Errorf("dstack image: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("dstack image %s: %s", s.URL, resp.Status)
	}
	tmp, err := os.CreateTemp(dir, ".dstack-*")
	if err != nil {
		return "", err
	}
	defer os.Remove(tmp.Name())
	h := sha256.New()
	if _, err := io.Copy(io.MultiWriter(tmp, h), io.LimitReader(resp.Body, 2<<30)); err != nil {
		tmp.Close()
		return "", fmt.Errorf("dstack image: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return "", err
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != s.SHA256 {
		return "", fmt.Errorf("dstack image %s: sha256 %s, pinned %s", s.URL, got, s.SHA256)
	}
	return p, os.Rename(tmp.Name(), p)
}

func fileSHA256(p string) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// gcpEndorsements is --gcp-endorsements RELEASE.json: what reproduce.sh prints for the part of a Google Cloud release
// no one but Google can rebuild. Each boot set's MRTDs must be listed in Google's signed TDX launch endorsement
// (fetched from Google's bucket, checked offline against the root compiled into the verifier, internal/gcetcb), at
// or above the set's minimum SVN; the release's sets must be the verifier's at this commit. It prints what Google
// signed about each build (SVN, date, changelist, the firmware binary's sha384). RTMR0 isn't checked here: it is a
// reviewed pin from observed boots, which only a quote from a VM of that shape shows.
func gcpEndorsements(path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var m struct {
		GCP *GCPRelease `json:"gcp"`
	}
	if err := json.Unmarshal(b, &m); err != nil || m.GCP == nil || m.GCP.Schema != GCPSchema {
		return fmt.Errorf("%s: no %s gcp section", path, GCPSchema)
	}
	seen := map[string]bool{}
	for _, s := range m.GCP.BootSets {
		var pinned *verifier.BootMeasurement
		for i, v := range verifier.GCPBootMeasurements {
			if v.Name == s.Name {
				pinned = &verifier.GCPBootMeasurements[i]
			}
		}
		if pinned == nil || pinned.RTMR0 != s.RTMR0 || pinned.RTMR1 != s.RTMR1 || pinned.RTMR2 != s.RTMR2 ||
			!slices.Equal(pinned.GoogleMRTDs, s.MRTDs) || pinned.MinFirmwareSVN != s.MinFirmwareSVN {
			return fmt.Errorf("%s: the release's boot set isn't the verifier's at this commit", s.Name)
		}
		for _, h := range s.MRTDs {
			mrtd, err := hex.DecodeString(h)
			if err != nil {
				return err
			}
			f, meas, err := gcetcb.Check(context.Background(), nil, mrtd, time.Now())
			if err != nil {
				return fmt.Errorf("%s: MRTD %s: %w", s.Shape, short(h), err)
			}
			if f.SVN < s.MinFirmwareSVN {
				return fmt.Errorf("%s: MRTD %s is firmware SVN %d, below %d", s.Shape, short(h), f.SVN, s.MinFirmwareSVN)
			}
			if !seen[h] {
				fmt.Printf("ENDORSED: MRTD %s %s\n", short(h), f.Describe(meas))
				seen[h] = true
			}
		}
		fmt.Printf("PINNED: %s RTMR0 %s (Google's firmware configuration for the shape, observed: not rebuildable)\n", s.Shape, short(s.RTMR0))
	}
	return nil
}
