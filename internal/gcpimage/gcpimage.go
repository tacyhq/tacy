// Package gcpimage makes the Google Cloud pieces of an agent VM release from dstack's published OS image, and checks
// them: the boot disk image Google imports, the data disk image, the shared-disk system config, and the boot
// measurements the disk puts in RTMR1 and RTMR2 (Measure), computed from the image alone.
//
// Source: dstack's OS release (Source: its tarball by URL and sha256, the os-image-hash its sha256sum.txt hashes to).
// Guest reads the tarball, checks it, measures disk.raw and writes, byte for byte the same on any machine with the
// same Go version (archive/tar and compress/gzip, fixed headers):
//
//   - BootFile: a tar.gz holding only disk.raw, the form `gcloud compute images create --source-uri` takes;
//   - DataFile: the same form, a 10 MiB disk with one GPT partition "dstack-data" (dstack formats it at each boot
//     under a key made in the VM: app-compose requirements.ephemeral_data_disk);
//   - SysConfigFile: dstack's .sys-config.json for key provider none (no key service, no gateway: placeholder URLs
//     that are never used) with the image's vm_config (its os-image-hash and GCP measurement files).
//
// What Google's firmware adds can't be computed from the image: the MRTD (Google's firmware build; pinned to builds we
// reviewed plus Google's signed endorsement, verifier.GCPBootMeasurements) and RTMR0 (its configuration volume,
// Secure Boot variables, ACPI tables per machine shape, boot variables; pinned per shape from observed boots).
//
// Integrity of what Google boots doesn't rest on these files: the quote's RTMR1 binds the disk's GPT, the UKI and
// its kernel, RTMR2 the UKI's sections (its command line carries the root file system's dm-verity hash), RTMR3 the
// app-compose on the shared disk. The files' sha256s in release.json (signed) say which bytes a release imports.
package gcpimage

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Source is the dstack OS release a Google Cloud release imports.
type Source struct {
	Dstack      string // version
	URL         string // the release tarball
	SHA256      string // its sha256 (hex)
	OSImageHash string // sha256 of its sha256sum.txt (dstack's os-image-hash; verifier.GCPImages)
	Dir         string // the tarball's top directory
}

// Dstack066 is dstack 0.6.6 (mkosi-os-v0.6.6, 2026-11-20): the image every Google Cloud boot set was observed with
// (verifier.GCPBootMeasurements), and its sha256 as GitHub reports the asset's digest.
var Dstack066 = Source{
	Dstack:      "0.6.6",
	URL:         "https://github.com/Dstack-TEE/dstack/releases/download/mkosi-os-v0.6.6/dstack-0.6.6-uki.tar.gz",
	SHA256:      "cd54e641a2dda2cda6063e947c89ce9f7e9ef3bdc23fdd669624e71f197451d1",
	OSImageHash: "5aa762ee7cddc62174c13e1081d56f7ab2a9aebc513973a1d63b3775fda250ec",
	Dir:         "dstack-0.6.6",
}

// The release asset names (release.yml publishes them; each is a signed subject).
const (
	BootFile      = "gcp-boot.tar.gz"
	DataFile      = "gcp-data.tar.gz"
	SysConfigFile = "gcp-sys-config.json"
)

// DataDiskBytes is the data disk image's size (the VM's data disk is larger; dstack uses all of it).
const DataDiskBytes = 10 << 20

// Guest describes what Guest wrote: the source, the files and the boot measurements.
type Guest struct {
	Dstack        string            `json:"dstack"`
	URL           string            `json:"url"`
	TarballSHA256 string            `json:"tarball_sha256"`
	OSImageHash   string            `json:"os_image_hash"`
	DiskSHA256    string            `json:"disk_raw_sha256"`
	UKIAuthSHA256 string            `json:"uki_auth_sha256"` // dstack's measurement.gcp.cbor uki_auth: the UKI's Authenticode SHA-256
	Files         map[string]string `json:"files"`           // BootFile, DataFile, SysConfigFile -> sha256
	Boot          *Boot             `json:"boot"`
}

// BuildGuest reads src (the Source tarball), checks it against s, and writes BootFile, DataFile and SysConfigFile
// into out (made if needed). tmp holds disk.raw while it is measured (out if empty); it is removed after.
func BuildGuest(s Source, src, out, tmp string) (*Guest, error) {
	if tmp == "" {
		tmp = out
	}
	if err := os.MkdirAll(out, 0o755); err != nil {
		return nil, err
	}
	// The tarball's sha256 first, before anything in it is parsed or written out (review L9).
	sum, err := fileSum(src)
	if err != nil {
		return nil, err
	}
	if sum != s.SHA256 {
		return nil, fmt.Errorf("%s: sha256 %s, the pinned dstack %s release is %s", src, sum, s.Dstack, s.SHA256)
	}
	f, err := os.Open(src)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	th := sha256.New()
	gz, err := gzip.NewReader(io.TeeReader(f, th))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", src, err)
	}
	disk, err := os.CreateTemp(tmp, "disk-*.raw")
	if err != nil {
		return nil, err
	}
	defer os.Remove(disk.Name())
	defer disk.Close()
	small := map[string][]byte{}
	var diskSum []byte
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("%s: %w", src, err)
		}
		if h.Typeflag != tar.TypeReg && h.Typeflag != tar.TypeGNUSparse {
			continue
		}
		name := strings.TrimPrefix(h.Name, s.Dir+"/")
		switch name {
		case "disk.raw":
			dh := sha256.New()
			if _, err := io.Copy(io.MultiWriter(disk, dh), tr); err != nil {
				return nil, err
			}
			diskSum = dh.Sum(nil)
		case "sha256sum.txt", "digest.txt", "measurement.gcp.cbor":
			if h.Size > 1<<16 {
				return nil, fmt.Errorf("%s: %s too large", src, name)
			}
			b, err := io.ReadAll(tr)
			if err != nil {
				return nil, err
			}
			small[name] = b
		}
	}
	io.Copy(io.Discard, f) // the rest of the gzip stream, for the tarball's hash
	if got := hex.EncodeToString(th.Sum(nil)); got != s.SHA256 {
		return nil, fmt.Errorf("%s: sha256 %s, the pinned dstack %s release is %s", src, got, s.Dstack, s.SHA256)
	}
	if diskSum == nil || small["sha256sum.txt"] == nil || small["measurement.gcp.cbor"] == nil {
		return nil, fmt.Errorf("%s: no disk.raw, sha256sum.txt or measurement.gcp.cbor under %s/", src, s.Dir)
	}
	sums := small["sha256sum.txt"]
	if h := sha256.Sum256(sums); hex.EncodeToString(h[:]) != s.OSImageHash {
		return nil, fmt.Errorf("sha256sum.txt hashes to %x, not the pinned os-image-hash %s", h, s.OSImageHash)
	}
	if d := strings.TrimSpace(string(small["digest.txt"])); d != "" && d != s.OSImageHash {
		return nil, fmt.Errorf("digest.txt says %s, not the os-image-hash %s", d, s.OSImageHash)
	}
	cbor := small["measurement.gcp.cbor"]
	if h := sha256.Sum256(cbor); !strings.Contains(string(sums), hex.EncodeToString(h[:])+"  measurement.gcp.cbor") {
		return nil, errors.New("measurement.gcp.cbor isn't the one sha256sum.txt lists")
	}
	ukiAuth, err := gcpUKIAuth(cbor)
	if err != nil {
		return nil, err
	}
	boot, err := Measure(disk)
	if err != nil {
		return nil, fmt.Errorf("disk.raw: %w", err)
	}
	// dstack's own GCP measurement is the UKI's Authenticode SHA-256: it must be the UKI we measured.
	fs, err := espOf(disk)
	if err != nil {
		return nil, err
	}
	uki, err := fs.readFile(UKIPath)
	if err != nil {
		return nil, err
	}
	a256, err := authenticode(uki, sha256.New())
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(a256, ukiAuth) {
		return nil, fmt.Errorf("dstack's measurement.gcp.cbor names UKI %x, the disk's UKI is %x", ukiAuth, a256)
	}
	g := &Guest{Dstack: s.Dstack, URL: s.URL, TarballSHA256: s.SHA256, OSImageHash: s.OSImageHash,
		DiskSHA256: hex.EncodeToString(diskSum), UKIAuthSHA256: hex.EncodeToString(ukiAuth), Files: map[string]string{}, Boot: boot}
	if _, err := disk.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	st, err := disk.Stat()
	if err != nil {
		return nil, err
	}
	if g.Files[BootFile], err = writeImageTar(filepath.Join(out, BootFile), disk, st.Size()); err != nil {
		return nil, err
	}
	data := DataDisk()
	if g.Files[DataFile], err = writeImageTar(filepath.Join(out, DataFile), bytes.NewReader(data), int64(len(data))); err != nil {
		return nil, err
	}
	sc, err := SysConfig(s.OSImageHash, sums, cbor)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(out, SysConfigFile), sc, 0o644); err != nil {
		return nil, err
	}
	h := sha256.Sum256(sc)
	g.Files[SysConfigFile] = hex.EncodeToString(h[:])
	return g, nil
}

func fileSum(p string) (string, error) {
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

func espOf(disk io.ReaderAt) (*fatFS, error) {
	_, parts, err := readGPT(disk)
	if err != nil {
		return nil, err
	}
	for _, p := range parts {
		if p.TypeGUID == espType {
			return openFAT(disk, int64(p.First)*sector)
		}
	}
	return nil, errors.New("no EFI System Partition")
}

// gcpUKIAuth reads uki_auth from dstack's measurement.gcp.cbor ({"version": 1, "uki_auth": bstr(32)}).
func gcpUKIAuth(b []byte) ([]byte, error) {
	key := append([]byte{0x68}, "uki_auth"...) // text(8) "uki_auth"
	i := bytes.Index(b, key)
	if i < 0 || i+len(key)+2+32 > len(b) || b[i+len(key)] != 0x58 || b[i+len(key)+1] != 0x20 {
		return nil, errors.New("measurement.gcp.cbor: no 32-byte uki_auth")
	}
	return b[i+len(key)+2 : i+len(key)+2+32], nil
}

// imageTime is every file time in the tarballs (fixed, so the same bytes give the same tarball).
var imageTime = time.Unix(0, 0).UTC()

// writeImageTar writes path: a gzip'd tar holding one file, disk.raw (size bytes from r), as Compute Engine's image
// import takes it; fixed header fields, so it's reproducible. It returns the file's sha256.
func writeImageTar(path string, r io.Reader, size int64) (string, error) {
	f, err := os.Create(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if err := ImageTar(io.MultiWriter(f, h), r, size); err != nil {
		return "", err
	}
	if err := f.Close(); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// ImageTar writes the image-import form of a raw disk (see writeImageTar) to w.
func ImageTar(w io.Writer, r io.Reader, size int64) error {
	gz, err := gzip.NewWriterLevel(w, gzip.DefaultCompression)
	if err != nil {
		return err
	}
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{Name: "disk.raw", Mode: 0o644, Size: size, ModTime: imageTime, Typeflag: tar.TypeReg,
		Format: tar.FormatGNU}); err != nil {
		return err
	}
	if n, err := io.Copy(tw, r); err != nil || n != size {
		return fmt.Errorf("disk.raw: wrote %d of %d bytes: %v", n, size, err)
	}
	if err := tw.Close(); err != nil {
		return err
	}
	return gz.Close()
}

// DataDisk is the data disk image: DataDiskBytes with one GPT partition named dstack-data (Linux file system type)
// from LBA 2048 to the last usable one, fixed GUIDs.
func DataDisk() []byte {
	d := make([]byte, DataDiskBytes)
	lbas := uint64(DataDiskBytes / sector)
	linuxFS := [16]byte{0xaf, 0x3d, 0xc6, 0x0f, 0x83, 0x84, 0x72, 0x47, 0x8e, 0x79, 0x3d, 0x69, 0xd8, 0x47, 0x7d, 0xe4}
	writeGPT(d, guidOf("tacy dstack data disk"), []gptPart{{TypeGUID: linuxFS, Name: "dstack-data", First: 2048, Last: lbas - 34}},
		[][16]byte{guidOf("tacy dstack data partition")})
	return d
}

// guidOf is a fixed version-4-shaped GUID from a label (so images are reproducible).
func guidOf(label string) [16]byte {
	h := sha256.Sum256([]byte(label))
	var g [16]byte
	copy(g[:], h[:16])
	g[7] = g[7]&0x0f | 0x40
	g[8] = g[8]&0x3f | 0x80
	return g
}

// SysConfig is dstack's .sys-config.json for a Google Cloud VM in key provider none: no key service and no gateway
// (placeholder URLs: dstack-cloud falls back to a public key service when the lists are empty, and none mode never
// calls them), no PCCS, and the image's vm_config, which names its os-image-hash and its GCP measurement files
// (sha256sum.txt and measurement.gcp.cbor, base64), as dstack-cloud writes them.
func SysConfig(osImageHash string, sums, cbor []byte) ([]byte, error) {
	vm := fmt.Sprintf(`{"spec_version": 2, "os_image_hash": %q, "gcp_measurement": {"checksum_file": %q, "measurement": %q}}`,
		osImageHash, base64.StdEncoding.EncodeToString(sums), base64.StdEncoding.EncodeToString(cbor))
	return json.MarshalIndent(struct {
		KMSURLs     []string `json:"kms_urls"`
		GatewayURLs []string `json:"gateway_urls"`
		PCCSURL     string   `json:"pccs_url"`
		VMConfig    string   `json:"vm_config"`
	}{[]string{"https://127.0.0.1:1"}, []string{"https://127.0.0.1:1"}, "", vm}, "", "  ")
}
