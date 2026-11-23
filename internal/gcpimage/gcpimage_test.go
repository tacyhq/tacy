package gcpimage

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tacyhq/tacy/internal/tdx"
	"github.com/tacyhq/tacy/verifier"
)

// envSrc names dstack 0.6.6's release tarball (Dstack066.URL, 630 MB) for the tests that need the whole image; they
// skip without it. scripts/reproduce.sh and the release build always have it.
const envSrc = "TACY_DSTACK_GCP_SRC"

func read(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// recorded are the genuine Google Cloud attestations the verifier's sets were pinned from (6 VMs, both shapes, three
// regions).
func recorded(t *testing.T) map[string][]tdx.Event {
	t.Helper()
	out := map[string][]tdx.Event{}
	files, _ := filepath.Glob("../../testdata/gcp-066-*.json")
	if len(files) < 6 {
		t.Fatalf("recorded Google Cloud attestations: %d, want 6", len(files))
	}
	for _, f := range files {
		b, _ := os.ReadFile(f)
		var a struct {
			Quote struct {
				EventLog json.RawMessage `json:"event_log"`
			} `json:"quote"`
		}
		if err := json.Unmarshal(b, &a); err != nil {
			t.Fatal(err)
		}
		var s string
		raw := a.Quote.EventLog
		if json.Unmarshal(raw, &s) == nil {
			raw = json.RawMessage(s)
		}
		ev, err := tdx.ParseEventLog(raw)
		if err != nil {
			t.Fatal(err)
		}
		out[filepath.Base(f)] = ev
	}
	return out
}

// logged is the RTMR1 and RTMR2 events of a firmware log, in order.
func logged(ev []tdx.Event) []Event {
	var out []Event
	for _, e := range ev {
		if (e.IMR == 1 || e.IMR == 2) && e.EventType != 3 {
			out = append(out, Event{RTMR: e.IMR, Digest: strings.ToLower(e.Digest)})
		}
	}
	return out
}

// TestGPTEventFromImage: the EV_EFI_GPT_EVENT digest computed from dstack 0.6.6's partition table (its first 34
// sectors) is the one every recorded Google boot logged.
func TestGPTEventFromImage(t *testing.T) {
	ev, parts, err := readGPT(bytes.NewReader(read(t, "dstack-0.6.6-gpt.bin")))
	if err != nil {
		t.Fatal(err)
	}
	if len(parts) != 2 || parts[0].TypeGUID != espType || parts[1].Name != "dstack-rootfs" {
		t.Fatalf("partitions %+v", parts)
	}
	got := hex.EncodeToString(sum384(ev))
	for name, log := range recorded(t) {
		found := false
		for _, e := range log {
			if e.IMR == 1 && e.EventType == 0x80000006 && strings.EqualFold(e.Digest, got) {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: no EV_EFI_GPT_EVENT %s", name, got)
		}
	}
	// A changed partition table is another event.
	b := read(t, "dstack-0.6.6-gpt.bin")
	b[2*sector+56] ^= 1 // the ESP's name
	if _, _, err := readGPT(bytes.NewReader(b)); err == nil {
		t.Error("an edited partition entry passed its CRC")
	}
}

// TestFixedEventsMatchLogs: the firmware's own RTMR1 actions and separator are what every recorded boot logged.
func TestFixedEventsMatchLogs(t *testing.T) {
	want := map[int]string{
		0: hex.EncodeToString(sum384([]byte(actionBootOption))),
		1: hex.EncodeToString(sum384([]byte{0, 0, 0, 0})),
	}
	for name, log := range recorded(t) {
		l := logged(log)
		if len(l) != 19 {
			t.Fatalf("%s: %d RTMR1/RTMR2 events, want 19", name, len(l))
		}
		for i, d := range want {
			if l[i].Digest != d {
				t.Errorf("%s: event %d %s, want %s", name, i, l[i].Digest, d)
			}
		}
		if l[17].Digest != hex.EncodeToString(sum384([]byte(actionExitBS))) || l[18].Digest != hex.EncodeToString(sum384([]byte(actionExitBSOK))) {
			t.Errorf("%s: ExitBootServices actions differ", name)
		}
	}
}

// TestSysConfigIsDstackCloud's: the system config made from the image's files is, byte for byte, the one
// dstack-cloud wrote for the shared disks every Google run so far booted with.
func TestSysConfigIsDstackClouds(t *testing.T) {
	sums, cbor := read(t, "dstack-0.6.6-sha256sum.txt"), read(t, "dstack-0.6.6-measurement.gcp.cbor")
	if h := sha256.Sum256(sums); hex.EncodeToString(h[:]) != Dstack066.OSImageHash {
		t.Fatal("testdata sha256sum.txt isn't dstack 0.6.6's")
	}
	got, err := SysConfig(Dstack066.OSImageHash, sums, cbor)
	if err != nil {
		t.Fatal(err)
	}
	if want := read(t, "dstack-0.6.6-sys-config.json"); !bytes.Equal(got, want) {
		t.Fatalf("sys-config differs:\n%s\nwant\n%s", got, want)
	}
	a, err := gcpUKIAuth(cbor)
	if err != nil || !strings.HasPrefix(hex.EncodeToString(a), "19eaec30") {
		t.Fatalf("uki_auth %x %v", a, err)
	}
}

func TestDataDisk(t *testing.T) {
	d := DataDisk()
	if len(d) != DataDiskBytes {
		t.Fatal(len(d))
	}
	_, parts, err := readGPT(bytes.NewReader(d))
	if err != nil {
		t.Fatal(err)
	}
	if len(parts) != 1 || parts[0].Name != "dstack-data" || parts[0].First != 2048 || parts[0].Last != DataDiskBytes/sector-34 {
		t.Fatalf("partitions %+v", parts)
	}
	if !bytes.Equal(d, DataDisk()) {
		t.Fatal("not reproducible")
	}
	var a, b bytes.Buffer
	if err := ImageTar(&a, bytes.NewReader(d), int64(len(d))); err != nil {
		t.Fatal(err)
	}
	if err := ImageTar(&b, bytes.NewReader(d), int64(len(d))); err != nil || !bytes.Equal(a.Bytes(), b.Bytes()) {
		t.Fatal("image tarball not reproducible")
	}
}

func TestSharedDiskRoundTrip(t *testing.T) {
	ac := bytes.Repeat([]byte("x"), 13682) // the size of a real app-compose.json: several clusters
	s := SharedFiles{AppCompose: ac, SysConfig: read(t, "dstack-0.6.6-sys-config.json"), AppID: AppIDFor("p", "tacy-agent-vm-v2a"), Seed: NewSeed()}
	img, err := SharedDisk(s)
	if err != nil {
		t.Fatal(err)
	}
	label, files, err := ReadShared(img)
	if err != nil {
		t.Fatal(err)
	}
	if label != SharedLabel || len(files) != 4 || !bytes.Equal(files[SharedAppCompose], ac) || string(files[SharedUserConfig]) != "{}" ||
		!bytes.Equal(files[SharedSysConfig], s.SysConfig) {
		t.Fatalf("label %q files %d", label, len(files))
	}
	var info map[string]string
	if err := json.Unmarshal(files[SharedInstanceInf], &info); err != nil || info["app_id"] != s.AppID || info["instance_id_seed"] != s.Seed {
		t.Fatalf("instance info %s", files[SharedInstanceInf])
	}
	if AppIDFor("p", "tacy-agent-vm-v2a") == AppIDFor("p", "tacy-agent-vm-v2b") || AppIDFor("p", "a") == AppIDFor("q", "a") {
		t.Fatal("app ids collide")
	}
	if _, err := SharedDisk(SharedFiles{AppCompose: ac, SysConfig: s.SysConfig, AppID: "short", Seed: s.Seed}); err == nil {
		t.Fatal("a bad app id passed")
	}
}

// TestReadsMkfsShared: the reader takes a shared disk mkfs.fat and mtools made (FAT32), as dstack-cloud's.
func TestReadsMkfsShared(t *testing.T) {
	p := os.Getenv("TACY_GCP_MKFS_SHARED")
	if p == "" {
		t.Skip("TACY_GCP_MKFS_SHARED unset")
	}
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	label, files, err := ReadShared(b)
	if err != nil || label != SharedLabel || files[SharedAppCompose] == nil || files[SharedSysConfig] == nil {
		t.Fatalf("%q %d %v", label, len(files), err)
	}
}

// TestBuildGuestFromRelease: the whole image, from dstack's release tarball: every RTMR1 and RTMR2 event computed from
// disk.raw is, in order, the one each recorded Google boot logged, and RTMR1 and RTMR2 are exactly the verifier's
// pinned Google sets' (both shapes); the UKI is the sets' UKI and dstack's own uki_auth; the files are reproducible.
func TestBuildGuestFromRelease(t *testing.T) {
	src := os.Getenv(envSrc)
	if src == "" {
		t.Skip(envSrc + " unset (dstack 0.6.6's tarball)")
	}
	dir := t.TempDir()
	g, err := BuildGuest(Dstack066, src, filepath.Join(dir, "a"), "")
	if err != nil {
		t.Fatal(err)
	}
	for name, log := range recorded(t) {
		l := logged(log)
		if len(l) != len(g.Boot.Events) {
			t.Fatalf("%s: %d events logged, %d computed", name, len(l), len(g.Boot.Events))
		}
		for i := range l {
			if l[i].RTMR != g.Boot.Events[i].RTMR || l[i].Digest != g.Boot.Events[i].Digest {
				t.Errorf("%s: event %d (%s) RTMR%d %s, computed RTMR%d %s", name, i, g.Boot.Events[i].What, l[i].RTMR, l[i].Digest,
					g.Boot.Events[i].RTMR, g.Boot.Events[i].Digest)
			}
		}
	}
	n := 0
	for _, s := range verifier.GCPBootMeasurements {
		if s.OSImage != Dstack066.OSImageHash {
			continue
		}
		n++
		if s.RTMR1 != g.Boot.RTMR1 || s.RTMR2 != g.Boot.RTMR2 || s.UKI != g.Boot.UKI {
			t.Errorf("%s: pinned RTMR1 %s RTMR2 %s UKI %s, the image gives %s %s %s", s.Name, s.RTMR1, s.RTMR2, s.UKI, g.Boot.RTMR1, g.Boot.RTMR2, g.Boot.UKI)
		}
	}
	if n == 0 {
		t.Fatal("no pinned set for dstack 0.6.6")
	}
	if !strings.HasPrefix(g.UKIAuthSHA256, "19eaec30") {
		t.Errorf("uki_auth %s", g.UKIAuthSHA256)
	}
	g2, err := BuildGuest(Dstack066, src, filepath.Join(dir, "b"), "")
	if err != nil {
		t.Fatal(err)
	}
	for f, h := range g.Files {
		if g2.Files[f] != h {
			t.Errorf("%s: %s then %s (not reproducible)", f, h, g2.Files[f])
		}
	}
	t.Logf("files %v", g.Files)
	// A tarball that isn't the pinned one is refused before anything is used.
	bad := Dstack066
	bad.SHA256 = strings.Repeat("0", 64)
	if _, err := BuildGuest(bad, src, filepath.Join(dir, "c"), ""); err == nil || !strings.Contains(err.Error(), "sha256") {
		t.Errorf("a wrong tarball hash: %v", err)
	}
}

// Review L9: a PE whose SizeOfHeaders ends before the fields Authenticode skips is refused, not a panic.
func TestAuthenticodeShortHeaders(t *testing.T) {
	b := make([]byte, 0x400)
	copy(b, "MZ")
	b[0x3c] = 0x80
	copy(b[0x80:], "PE\x00\x00")
	coff := 0x84
	b[coff+16] = 240 // SizeOfOptionalHeader
	opt := coff + 20
	b[opt], b[opt+1] = 0x0b, 0x02 // PE32+
	b[opt+60] = 0x10              // SizeOfHeaders 16
	b[opt+108] = 16               // NumberOfRvaAndSizes
	if _, err := authenticode384(b); err == nil {
		t.Fatal("headers too short for the checksum passed")
	}
	if _, err := authenticode384(b[:0x30]); err == nil {
		t.Fatal("a truncated image passed")
	}
}
