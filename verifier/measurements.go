package verifier

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/google/go-tdx-guest/verify/trust"

	"github.com/tacyhq/tacy/internal/gcetcb"
	"github.com/tacyhq/tacy/internal/tdx"
)

// BootMeasurement is one allowed set of TDX boot measurements: a dstack OS image on one VM shape.
//
//   - MRTD is the firmware (dstack's OVMF/TDVF), and with QEMU 8.x how its pages are added.
//   - RTMR0 is the firmware's configuration: the TD HOB (memory size), ACPI tables (vCPUs, devices, hotplug,
//     PCI layout, QEMU version) and the boot variables. It changes with the VM size, not only the image.
//   - RTMR1 is the kernel (bzImage, with the setup header the firmware patches). For an image whose metadata.json
//     says kernel_header_normalized (0.6.4 and 0.6.5) it is the same on every shape (dstack-mr; 0.6.5 also observed
//     on tdx.small, medium and large, 2026-11-23); for one without it, RTMR1 can depend on the memory size too.
//   - RTMR2 is the kernel command line (which carries the dm-verity root hash of the root filesystem) and the
//     initramfs.
//
// So a set pins the code that boots (firmware, kernel, initramfs, root filesystem) and the VM shape it boots on.
// RTMR3 (the app, measured at runtime) is checked separately against the event log.
type BootMeasurement struct {
	Name    string // the image and VM shape, e.g. "dstack-0.5.9, 1 vCPU, 2 GiB"
	OSImage string // dstack os-image-hash: sha256 of the image's sha256sum.txt (RTMR3 os-image-hash event)
	MRTD    string // hex, 48 bytes each; MRTDGoogleEndorsed for a Google Cloud set (GCPBootMeasurements)
	RTMR0   string
	RTMR1   string
	RTMR2   string
	Source  string // how the values were obtained: computed, observed, or both
	// Google Cloud sets only (MRTD MRTDGoogleEndorsed):
	UKI            string   // the dstack UKI's Authenticode SHA-384, which RTMR1's boot applications must hold
	MinFirmwareSVN uint32   // the lowest firmware SVN Google's endorsement may state
	GoogleMRTDs    []string // the Google firmware builds we reviewed (hex MRTDs); the quote's must be one AND endorsed
}

// MRTDGoogleEndorsed as a set's MRTD: the quote's MRTD is checked by gcpBoot, not matched literally. It must be
// both:
//   - one of the set's GoogleMRTDs, the Google firmware builds we reviewed (independent review H1, 2026-11-21:
//     with Google as the adversary, "any build Google signs" would trust future builds we never saw, and the
//     firmware is what measures RTMR0-2), and
//   - in Google's signed TDX launch endorsement (internal/gcetcb: fetched from Google's gce_tcb_integrity bucket,
//     checked offline against the compiled-in GCE-cc-tcb-root), listing that MRTD, with at least the set's
//     MinFirmwareSVN. The endorsement stays required evidence that the pinned value is Google's build.
//
// So a Google firmware rotation (the MRTD changed between 2026-10-13 and 2026-11-20) needs a client and holder
// release: boot a throwaway per shape on the new build, check its endorsement (build date, changelist, SVN) and
// which RTMR0 events changed, then add the new MRTD to GoogleMRTDs with the new RTMR0 as new sets (README.md,
// "Google Cloud boot sets"). RTMR0 already forces that release (the configuration volume is part of the build),
// so pinning the MRTD adds no release of its own. Until then the new build's VMs are refused.
const MRTDGoogleEndorsed = "google-endorsed"

// GCPImages are the dstack OS images accepted on Google Cloud, by os-image-hash: only with key provider none, where
// the label is the one of the GCP set the measurements match. Not in ProdImages: a Policy accepts them only through
// WithGCP.
var GCPImages = map[string]string{
	"5aa762ee7cddc62174c13e1081d56f7ab2a9aebc513973a1d63b3775fda250ec": "dstack-0.6.6 (GCP UKI)",
}

// GCPBootMeasurements are the boot sets of dstack on Google Cloud TDX (Google's firmware, dstack's UKI booted from
// the disk), one per machine shape. Off by default: a Policy accepts them only through WithGCP, so every Phala
// verifier (clients, holders, kmsd, the chat) behaves as before.
//
//   - MRTD: Google's firmware, a build we reviewed (GoogleMRTDs) that Google's signed endorsement also lists
//     (MRTDGoogleEndorsed), SVN at least MinFirmwareSVN.
//   - RTMR0: the firmware's configuration: the TD HOB (memory), the configuration firmware volume (CFV, part of the
//     firmware build: it changed with Google's 2026 firmware update), the Secure Boot variables, the ACPI tables
//     (machine shape) and the boot variables. So it is pinned per shape, and changes when Google's firmware does.
//   - RTMR1: the GPT of the boot disk and the boot applications: the dstack UKI (its Authenticode hash, UKI, which
//     covers the kernel, the initramfs and the command line with the root filesystem's dm-verity hash) and the
//     kernel it loads. The exact RTMR1 is what binds them. The verifier also replays the firmware log and requires
//     UKI among the boot applications, but the log's event types aren't measured, so that check is defense in depth
//     and a clearer error, not a binding of its own (review L1).
//   - RTMR2: the UKI's sections as its stub measures them (command line, initramfs, kernel, os-release).
//
// Every set requires key provider none (keys made in the TD) and the none-mode app-compose rules (ephemeral data
// disk and the rest, appcompose.go).
// mrtdGoogle20260731 is Google's TDX firmware of 2026-07-31 (cl 957008435, SVN 2), the MRTD of every recorded GCP
// quote (testdata/gcp-066-*.json, 2026-11-20 and -21) and listed in its endorsement
// (internal/gcetcb/testdata/f21e6b48….binarypb). Google's older build c1ee9c16… (2026-05-21) is still endorsed but not
// pinned: no set's RTMR0 is its configuration, and we never reviewed it for dstack.
const mrtdGoogle20260731 = "f21e6b48743fe14c2d090078ca1197f09ae4c99438677f2c79901ef80e2aeefe2f9a7eb6e3eb3b5047c4f1511731e5d3"

var GCPBootMeasurements = []BootMeasurement{
	{
		Name:    "dstack-0.6.6, GCP c3-standard-4 TDX (4 vCPU, 16 GB)",
		OSImage: "5aa762ee7cddc62174c13e1081d56f7ab2a9aebc513973a1d63b3775fda250ec",
		MRTD:    MRTDGoogleEndorsed,
		RTMR0:   "4b08605d192148837400c4eee71f46b65ff960eaaf63494c472c4ddc4482d7c23d8671913ebec4b85c6edb89aa232662",
		RTMR1:   "09328a31bcc05f3c0f1f40a52f822b3a19fb987f67179f569cecef0500e9444a3387518849b0e231b12173371dfdac1a",
		RTMR2:   "97c2b630118d3b027eb2ed399df39d10be6d03a502ebeaf14a40459ff0789ffa2e7ef4d657265c01ec0497df19d2fefc",
		UKI:     "440fa6cac8d3fc19d6f7dbd1340fc7fc1a847539d2c41a8da82de5d38e8ec008c27ae889df05561732043cb9f748515a",
		Source: "observed on 61 fresh throwaway VMs in sealowl (41 in us-central1-a, -b, -c, 2026-11-20 and -21; 20 in " +
			"us-east1-c and -d, 2026-11-21, G3; testdata/gcp-066-c3-*.json), dstack 0.6.6 (mkosi-os-v0.6.6, disk.raw of dstack-0.6.6-uki.tar.gz, sha256 " +
			"cd54e641…; its sha256sum.txt hashes to the os-image-hash), 10 GiB pd-balanced boot disk; MRTD f21e6b48… " +
			"(Google's firmware of 2026-07-31, cl 957008435, SVN 2, endorsed); UKI = the Authenticode SHA-384 of the " +
			"image's UKI, whose SHA-256 is the release's GCP uki_auth 19eaec30…",
		MinFirmwareSVN: 2,
		GoogleMRTDs:    []string{mrtdGoogle20260731},
	},
	{
		Name:    "dstack-0.6.6, GCP c4-standard-2 TDX (2 vCPU, 7 GB)",
		OSImage: "5aa762ee7cddc62174c13e1081d56f7ab2a9aebc513973a1d63b3775fda250ec",
		MRTD:    MRTDGoogleEndorsed,
		RTMR0:   "224971ff25a3565a3b5153517025b40a192f68e1a8d6d30e4504e339fd901acbbcfca375a81b3894e4ba8820b6c8294b",
		RTMR1:   "09328a31bcc05f3c0f1f40a52f822b3a19fb987f67179f569cecef0500e9444a3387518849b0e231b12173371dfdac1a",
		RTMR2:   "97c2b630118d3b027eb2ed399df39d10be6d03a502ebeaf14a40459ff0789ffa2e7ef4d657265c01ec0497df19d2fefc",
		UKI:     "440fa6cac8d3fc19d6f7dbd1340fc7fc1a847539d2c41a8da82de5d38e8ec008c27ae889df05561732043cb9f748515a",
		Source: "observed on all 24 c4-standard-2 throwaway VMs of G3 in sealowl (us-east4-c 10, us-central1-f 14, " +
			"2026-11-21; the only two of 14 zones tried with stock; testdata/gcp-066-c4-*.json), dstack 0.6.6 as the c3 " +
			"set, 10 GiB hyperdisk-balanced boot disk; MRTD, RTMR1 and RTMR2 equal the c3 set's (the same firmware and " +
			"UKI), RTMR0 is the shape's",
		MinFirmwareSVN: 2,
		GoogleMRTDs:    []string{mrtdGoogle20260731},
	},
	// The bigger C3 shapes (2026-11-23): only RTMR0 differs from c3-standard-4's set, in its TD HOB (memory) and ACPI
	// table events.
	{
		Name:    "dstack-0.6.6, GCP c3-standard-8 TDX (8 vCPU, 32 GB)",
		OSImage: "5aa762ee7cddc62174c13e1081d56f7ab2a9aebc513973a1d63b3775fda250ec",
		MRTD:    MRTDGoogleEndorsed,
		RTMR0:   "2074615297d6e87ec1dbbb764635ee3bb06b00b0fbc13f35bead969b811355f749156b1a88f9716300db68b1ddae1f71",
		RTMR1:   "09328a31bcc05f3c0f1f40a52f822b3a19fb987f67179f569cecef0500e9444a3387518849b0e231b12173371dfdac1a",
		RTMR2:   "97c2b630118d3b027eb2ed399df39d10be6d03a502ebeaf14a40459ff0789ffa2e7ef4d657265c01ec0497df19d2fefc",
		UKI:     "440fa6cac8d3fc19d6f7dbd1340fc7fc1a847539d2c41a8da82de5d38e8ec008c27ae889df05561732043cb9f748515a",
		Source: "observed on all 12 c3-standard-8 throwaway VMs in tacy-test (us-central1-a 4, -b 3, -c 3, us-east1-c 2; " +
			"2026-11-23; testdata/gcp-066-c3s8-*.json), each verified in full with Intel and Google live, dstack 0.6.6 as " +
			"the c3-standard-4 set, 10 GiB pd-balanced boot disk; MRTD, RTMR1 and RTMR2 equal the c3-standard-4 set's (the " +
			"same firmware and UKI), RTMR0 is the shape's (its TD HOB and ACPI table events differ)",
		MinFirmwareSVN: 2,
		GoogleMRTDs:    []string{mrtdGoogle20260731},
	},
	{
		Name:    "dstack-0.6.6, GCP c3-standard-22 TDX (22 vCPU, 88 GB)",
		OSImage: "5aa762ee7cddc62174c13e1081d56f7ab2a9aebc513973a1d63b3775fda250ec",
		MRTD:    MRTDGoogleEndorsed,
		RTMR0:   "b1a5e2e167a01af91a68edf14fe9b9845127502b1a58117f4fa13eb55883b5073d8bb36f784fa2d1e2d2e40fc7812b0a",
		RTMR1:   "09328a31bcc05f3c0f1f40a52f822b3a19fb987f67179f569cecef0500e9444a3387518849b0e231b12173371dfdac1a",
		RTMR2:   "97c2b630118d3b027eb2ed399df39d10be6d03a502ebeaf14a40459ff0789ffa2e7ef4d657265c01ec0497df19d2fefc",
		UKI:     "440fa6cac8d3fc19d6f7dbd1340fc7fc1a847539d2c41a8da82de5d38e8ec008c27ae889df05561732043cb9f748515a",
		Source: "observed on all 5 c3-standard-22 throwaway VMs in tacy-test (us-central1-a 2, -b 2, -c 1; 2026-11-23; " +
			"testdata/gcp-066-c3s22-us-central1-a.json), each verified in full with Intel and Google live, dstack 0.6.6 as " +
			"the c3-standard-4 set, 10 GiB pd-balanced boot disk; MRTD, RTMR1 and RTMR2 equal the c3-standard-4 set's, " +
			"RTMR0 is the shape's (its TD HOB and ACPI table events differ)",
		MinFirmwareSVN: 2,
		GoogleMRTDs:    []string{mrtdGoogle20260731},
	},
}

// BootMeasurements are the measurement sets a VM may boot with. Add a set when the dstack image or the VM size
// changes (README.md, "Boot measurements"); the verifier refuses any other.
var BootMeasurements = []BootMeasurement{
	{
		Name:    "dstack-0.6.5, 1 vCPU, 2 GiB (Phala tdx.small, QEMU 8.2.2)",
		OSImage: "4771a29e03e93f0e2d5e37174cd8bb1112942c9689deb36b16c5df9e183d8623",
		MRTD:    "2a674327c50218dba880066b349b8d559d749ed68dce33fd651c184a877d084b07a9e583767a7ad5da13ed91deec2b70",
		RTMR0:   "68102e7b524af310f7b7d426ce75481e36c40f5d513a9009c046e9d37e31551f0134d954b496a3357fd61d03f07ffe96",
		RTMR1:   "2f72a4db2f7de90adeabe55607b0c1cf209fc243bc773f5862d1b00d3bb198e835e99d502e90a24005f0d1368dd24f29",
		RTMR2:   "3d9910a33a26a769c5146dea31bea0d2924a7746ad09e121dabe709eddd5c647716f4d89279e0e24d8dbb93f9cdb605b",
		Source: "computed with dstack-mr (Dstack-TEE/dstack mkosi-os-v0.6.5, commit 350a0a7, built from source; it " +
			"reproduces the retired 0.6.4 set from the live CVM's vm_config) from dstack-0.6.5.tar.gz of the GitHub release " +
			"mkosi-os-v0.6.5 (sha256 f33965e0…, as the release lists; its sha256sum.txt hashes to the os-image-hash; " +
			"metadata.json: version 0.6.5, is_dev false, the same ovmf.fd as 0.6.4, cmdline with systemd.gpt_auto=0 " +
			"systemd.import_credentials=no) and the live CVM's vm_config (prod9) with the image swapped; RTMR2 also " +
			"recomputed by hand from the command line and initramfs (TestDstack065CmdlineFix). Equal to two genuine 0.6.5 " +
			"quotes of key_provider none throwaways on Phala prod2 (tdx.small), 2026-11-21, the second after a restart, " +
			"with Intel's collateral (testdata/attest-065-none.json, attest-065-none-restart.json; TestRecorded065None)",
	},
	// The bigger Phala shapes: the same image, firmware, kernel, command line and initramfs as tdx.small,
	// so MRTD, RTMR1 and RTMR2 are its; only RTMR0 (the TD HOB's memory, the ACPI tables' vCPUs) is the shape's.
	{
		Name:    "dstack-0.6.5, 2 vCPU, 4 GiB (Phala tdx.medium, QEMU 8.2.2)",
		OSImage: "4771a29e03e93f0e2d5e37174cd8bb1112942c9689deb36b16c5df9e183d8623",
		MRTD:    "2a674327c50218dba880066b349b8d559d749ed68dce33fd651c184a877d084b07a9e583767a7ad5da13ed91deec2b70",
		RTMR0:   "027b610ab0555482f8a3868524093bdf3cdbe2539f81dfeeb886864654cb2fe3422f7fc36d4bab6fa46683aad11d1ba7",
		RTMR1:   "2f72a4db2f7de90adeabe55607b0c1cf209fc243bc773f5862d1b00d3bb198e835e99d502e90a24005f0d1368dd24f29",
		RTMR2:   "3d9910a33a26a769c5146dea31bea0d2924a7746ad09e121dabe709eddd5c647716f4d89279e0e24d8dbb93f9cdb605b",
		Source: "computed with dstack-mr (the tdx.small set's build: mkosi-os-v0.6.5, commit 350a0a7; dstack-0.6.5.tar.gz, " +
			"sha256 f33965e0…) from the tdx.small set's vm_config with cpu_count 2 and memory_size 4 GiB, nothing else " +
			"changed (2026-11-23); MRTD, RTMR1 and RTMR2 equal the tdx.small set's. Equal to Phala's tcb_info of a " +
			"tdx.medium throwaway on prod5 (2026-11-23), and to genuine key_provider none quotes of the release on tdx.medium " +
			"(prod5, 2026-11-23, a boot and a restart) with Intel's collateral" +
			" (testdata/quote-shape-medium.hex, quote-shape-medium-restart.hex; TestShapeQuotes)" +
			"",
	},
	{
		Name:    "dstack-0.6.5, 4 vCPU, 8 GiB (Phala tdx.large, QEMU 8.2.2)",
		OSImage: "4771a29e03e93f0e2d5e37174cd8bb1112942c9689deb36b16c5df9e183d8623",
		MRTD:    "2a674327c50218dba880066b349b8d559d749ed68dce33fd651c184a877d084b07a9e583767a7ad5da13ed91deec2b70",
		RTMR0:   "fb14dc139f33d6fcf474bc8332cac001259fb31cfbcb6b34d4ceeb552a2c4466884a0cbde45ad98a05c5c060c23ad65a",
		RTMR1:   "2f72a4db2f7de90adeabe55607b0c1cf209fc243bc773f5862d1b00d3bb198e835e99d502e90a24005f0d1368dd24f29",
		RTMR2:   "3d9910a33a26a769c5146dea31bea0d2924a7746ad09e121dabe709eddd5c647716f4d89279e0e24d8dbb93f9cdb605b",
		Source: "computed with dstack-mr (the tdx.small set's build: mkosi-os-v0.6.5, commit 350a0a7; dstack-0.6.5.tar.gz, " +
			"sha256 f33965e0…) from the tdx.small set's vm_config with cpu_count 4 and memory_size 8 GiB, nothing else " +
			"changed (2026-11-23); MRTD, RTMR1 and RTMR2 equal the tdx.small set's. Equal to Phala's tcb_info of a " +
			"tdx.large throwaway on prod5 (2026-11-23), and to genuine key_provider none quotes of the release on tdx.large " +
			"(prod5, 2026-11-23, two CVMs, the second after a restart) with Intel's collateral" +
			" (testdata/quote-shape-large.hex, quote-shape-large-restart.hex; TestShapeQuotes)" +
			"",
	},
}

// RetiredBootMeasurements are sets the verifier no longer accepts (since 2026-10-17: only 0.6.1 once the live
// CVM moved to it, with the gateway/vault release; 2026-11-15: only 0.6.4 once it moved off 0.6.1; 2026-11-20: only
// 0.6.5, once Phala moved the live CVM there with its KMS's new root). Kept for the record and for tests on older
// recordings: 0.5.9 (computed and observed: the live CVM until 2026-10-17), 0.5.8 and 0.6.0 (computed only, never
// booted by us), 0.6.1 (computed and observed: the live CVM until 2026-11-15; refused for GHSA-c79w-3x5w-gmm5, its
// guest acts on partitions the host appends to its disk), 0.6.4 (computed and observed: the live CVM until
// 2026-11-20; a VM whose disk moved to the KMS's new root can't boot it again: only a 0.6.5 guest migrates to a new
// root epoch, and a 0.6.4 guest on the old root would get keys an exposed root derives).
var RetiredBootMeasurements = []BootMeasurement{
	{
		Name:    "dstack-0.5.9, 1 vCPU, 2 GiB (Phala tdx.small, QEMU 8.2.2)",
		OSImage: "bd369a8c2f9edb2b52dad48ac8e0b32dde5f1337c423a506b48d07403a7d8033",
		MRTD:    "f06dfda6dce1cf904d4e2bab1dc370634cf95cefa2ceb2de2eee127c9382698090d7a4a13e14c536ec6c9c3c8fa87077",
		RTMR0:   "68102e7b524af310f7b7d426ce75481e36c40f5d513a9009c046e9d37e31551f0134d954b496a3357fd61d03f07ffe96",
		RTMR1:   "07e6f51aa763abfe75c3ddfbf4f425fe3f0ceff66d807a75e049303dce9addf68e7218729bd419638af63a370f65878c",
		RTMR2:   "df67e467e60edc1737bcf8e682d48131bfb427f523226aa7f197a7608e9b3784783fa759ef5b28191fa12f9ddb36b858",
		Source: "computed with dstack-mr (Dstack-TEE/dstack v0.6.1) from mr_bd369a8c….tar.gz on download.dstack.org " +
			"(its sha256sum.txt hashes to the os-image-hash; metadata.json: version 0.5.9, is_dev false) and the VM's " +
			"vm_config; equal to the quote of a VM recorded 2026-10-13",
	},
	{
		Name:    "dstack-0.5.8, 1 vCPU, 2 GiB (Phala tdx.small, QEMU 8.2.2)",
		OSImage: "6427f4f5ded88b72d326bd973e581c1689c5080c6444a0cf90fec7d9e4c8b92a",
		MRTD:    "f06dfda6dce1cf904d4e2bab1dc370634cf95cefa2ceb2de2eee127c9382698090d7a4a13e14c536ec6c9c3c8fa87077",
		RTMR0:   "68102e7b524af310f7b7d426ce75481e36c40f5d513a9009c046e9d37e31551f0134d954b496a3357fd61d03f07ffe96",
		RTMR1:   "b598fde9491427341bc4683b75d10d3e36770af3a36a6954d8b6b7b22aa66358f13e1f172e51b7d6e6710d99a8d8532f",
		RTMR2:   "9284cde236231d5ddace01104a440fd504df5182a2ad1ac3d2138b80c6a7864bd2c30f69041d8264217f3d24541580cf",
		Source: "computed only (2026-10-17), dstack-mr v0.6.1 from mr_6427f4f5….tar.gz on download.dstack.org (its " +
			"sha256sum.txt hashes to the os-image-hash; metadata.json: version 0.5.8, is_dev false) and the 0.5.9 VM's " +
			"vm_config with the image swapped; not observed",
	},
	{
		Name:    "dstack-0.6.0, 1 vCPU, 2 GiB (Phala tdx.small, QEMU 8.2.2)",
		OSImage: "8409e2a24ea8325f3ea45d7c50622c952a8a4a961ffc139f5d9a81c4e47bd744",
		MRTD:    "2a674327c50218dba880066b349b8d559d749ed68dce33fd651c184a877d084b07a9e583767a7ad5da13ed91deec2b70",
		RTMR0:   "68102e7b524af310f7b7d426ce75481e36c40f5d513a9009c046e9d37e31551f0134d954b496a3357fd61d03f07ffe96",
		RTMR1:   "3484cd07ba093cede0938303617d6da58f3c6a895ddd5461b3bdd0b29f40e869d4c92642867b44bd3619451bd78ff2d0",
		RTMR2:   "83b7a9a35ed613c17a8b9d36a49f28b095f54daa78b328c93eef10ae3e21094c1411467e3371157c4cde5e0beb72dcb8",
		Source: "computed only (2026-10-17), dstack-mr v0.6.1 from dstack-0.6.0.tar.gz of the GitHub release " +
			"mkosi-os-v0.6.0 (sha256 73f9950f…, as listed; sha256sum.txt hashes to the os-image-hash; is_dev false) " +
			"and the 0.6.1 VM's vm_config with the image swapped; not observed",
	},
	{
		Name:    "dstack-0.6.1, 1 vCPU, 2 GiB (Phala tdx.small, QEMU 8.2.2)",
		OSImage: "ec43cb8c5e04b6bb6c53b33b16076a01d83d01f7f4b703f2f78a0d947d6247e6",
		MRTD:    "2a674327c50218dba880066b349b8d559d749ed68dce33fd651c184a877d084b07a9e583767a7ad5da13ed91deec2b70",
		RTMR0:   "68102e7b524af310f7b7d426ce75481e36c40f5d513a9009c046e9d37e31551f0134d954b496a3357fd61d03f07ffe96",
		RTMR1:   "89ef86c5125b986c325f0a94acfa87718a4ef3a4d4f237dbb72dda3cf777fd2c054555fb4407eb53338d7d67329a7333",
		RTMR2:   "e9000e338f33233e8f51b7fd031e1c158bdcf8572eab041c0bc8eb7fef48b23259a6a556e6c8e2af99999fc39c793179",
		Source: "computed with dstack-mr (Dstack-TEE/dstack v0.6.1, commit 7f14314, built from source) from " +
			"dstack-0.6.1.tar.gz of the GitHub release mkosi-os-v0.6.1 (sha256 7583f51c…, as the release lists; its " +
			"sha256sum.txt hashes to the os-image-hash; metadata.json: version 0.6.1, is_dev false; MRTD is the " +
			"image's two-pass value in measurement.tdx.cbor, QEMU 8.2.2) and the VM's vm_config; equal to the quote " +
			"of a throwaway CVM on Phala prod5 recorded 2026-10-17 (testdata/attest-061.json), and to the live CVM's on " +
			"prod9 after it moved to 0.6.1 the same day (the chat's test/fixtures/agent/attest-v8.json)",
	},
	{
		Name:    "dstack-0.6.4, 1 vCPU, 2 GiB (Phala tdx.small, QEMU 8.2.2)",
		OSImage: "feff3645893ad910d4f0e06d8f553cf80a7c9fede2ce0698fa63116283260366",
		MRTD:    "2a674327c50218dba880066b349b8d559d749ed68dce33fd651c184a877d084b07a9e583767a7ad5da13ed91deec2b70",
		RTMR0:   "68102e7b524af310f7b7d426ce75481e36c40f5d513a9009c046e9d37e31551f0134d954b496a3357fd61d03f07ffe96",
		RTMR1:   "0d390cdff163d981adbe90bb1d3666463be9de93a83de9b09ad0fe233974fdddc475731ba40d0bdc523efe8887cf82b8",
		RTMR2:   "df939336955fec7a8d316b4ee4fe7b7e0810194c6911aa61c559882ad17984bfb4a7fc7c3112d25a4968f23bd6b907be",
		Source: "computed with dstack-mr (Dstack-TEE/dstack mkosi-os-v0.6.4, commit bb80091, built from source; it " +
			"reproduces the retired 0.6.1 set from the live CVM's vm_config) from dstack-0.6.4.tar.gz of the GitHub release " +
			"mkosi-os-v0.6.4 (sha256 72102489…, as the release lists; its sha256sum.txt hashes to the os-image-hash; " +
			"metadata.json: version 0.6.4, is_dev false, cmdline with systemd.gpt_auto=0 systemd.import_credentials=no, " +
			"the GHSA-c79w-3x5w-gmm5 fix) and the live CVM's vm_config (prod9) with the image swapped; equal to the quote " +
			"of a throwaway CVM moved in place from 0.6.1 to 0.6.4 on Phala prod5, 2026-11-15 (testdata/attest-064.json)",
	},
}

// keysMadeInVM: the attested key-provider event (its payload, decoded) is exactly {"name":"none","id":""}, keys
// from a seed made inside the TD at boot.
func keysMadeInVM(payload []byte) bool {
	var kp struct {
		Name *string `json:"name"`
		ID   *string `json:"id"`
	}
	if json.Unmarshal(payload, &kp) != nil || kp.Name == nil || kp.ID == nil {
		return false
	}
	return *kp.Name == KeyProviderNone && *kp.ID == ""
}

// osImageFromBoot is the OS image of the one pinned set q's MRTD and RTMR0-2 all match (key provider none, where
// dstack measures no os-image-hash). No match: matchBoot's error, which names the registers that differ.
func osImageFromBoot(q *tdx.Quote, sets []BootMeasurement) (string, error) {
	got := [4]string{hex.EncodeToString(q.MrTd), hex.EncodeToString(q.Rtmrs[0]), hex.EncodeToString(q.Rtmrs[1]),
		hex.EncodeToString(q.Rtmrs[2])}
	for _, s := range sets {
		if strings.EqualFold(s.MRTD, got[0]) && strings.EqualFold(s.RTMR0, got[1]) && strings.EqualFold(s.RTMR1, got[2]) &&
			strings.EqualFold(s.RTMR2, got[3]) {
			return s.OSImage, nil
		}
	}
	_, err := matchBoot(q, "", sets)
	return "", fmt.Errorf("no os-image-hash event (key provider none) and %w", err)
}

// matchBoot returns the set q's MRTD and RTMR0-2 match, which must also be for osImage (the os-image-hash the
// event log reports). On a mismatch the error says which registers differ from the closest set.
func matchBoot(q *tdx.Quote, osImage string, sets []BootMeasurement) (*BootMeasurement, error) {
	got := [4]string{hex.EncodeToString(q.MrTd), hex.EncodeToString(q.Rtmrs[0]), hex.EncodeToString(q.Rtmrs[1]),
		hex.EncodeToString(q.Rtmrs[2])}
	names := [4]string{"MRTD", "RTMR0", "RTMR1", "RTMR2"}
	var closest *BootMeasurement
	var closestDiff []string
	for i := range sets {
		s := &sets[i]
		var diff []string
		for j, want := range [4]string{s.MRTD, s.RTMR0, s.RTMR1, s.RTMR2} {
			// A Google Cloud set's MRTD is checked by gcpBoot (which then sets it to the quote's), so an unresolved
			// MRTDGoogleEndorsed isn't named as a difference, but it never matches either (below).
			if !strings.EqualFold(want, got[j]) && !(j == 0 && want == MRTDGoogleEndorsed) {
				diff = append(diff, names[j])
			}
		}
		if len(diff) == 0 && s.MRTD == MRTDGoogleEndorsed {
			diff = []string{"MRTD (no Google endorsement checked)"}
		}
		if len(diff) == 0 {
			if s.OSImage != osImage {
				return nil, fmt.Errorf("measurements are %s's, but the event log reports OS image %s", s.Name, short(osImage))
			}
			return s, nil
		}
		if closest == nil || len(diff) < len(closestDiff) || (len(diff) == len(closestDiff) && s.OSImage == osImage) {
			closest, closestDiff = s, diff
		}
	}
	if closest == nil {
		return nil, fmt.Errorf("no pinned boot measurements (MRTD %s)", short(got[0]))
	}
	// RTMR0 and RTMR1 are the ones that also depend on the VM shape.
	hint := " (another OS image?)"
	if !slices.Contains(closestDiff, "MRTD") && !slices.Contains(closestDiff, "RTMR2") {
		hint = " (another VM size or VM configuration?)"
	}
	// On Google Cloud RTMR1 is the UKI (the same on every shape), and RTMR0 changes with the shape and with Google's
	// firmware (its configuration volume).
	if closest.MRTD == MRTDGoogleEndorsed {
		hint = " (another OS image?)"
		if slices.Equal(closestDiff, []string{"RTMR0"}) {
			hint = " (another machine shape, or a Google firmware update?)"
		}
	}
	return nil, fmt.Errorf("MRTD/RTMR0-2 (MRTD %s, RTMR0 %s, RTMR1 %s, RTMR2 %s) match no pinned set; closest is %s, "+
		"which differs in %s%s", short(got[0]), short(got[1]), short(got[2]), short(got[3]), closest.Name,
		strings.Join(closestDiff, ", "), hint)
}

// GCPBootCheck is the check a quote gets when its RTMR0-2 match a Google Cloud set (GCPBootMeasurements); a Phala
// quote never gets it, so Phala's checks are as before.
const GCPBootCheck = "Google Cloud boot chain: firmware (MRTD) a reviewed build that Google's signed launch endorsement lists, the pinned dstack UKI in RTMR1, keys made in the VM"

// PlatformDstackGCP is the platform name that turns the Google Cloud sets on from a signed document, with no app or
// holder release: a client's trust list (safety.TrustList.Platforms, WithTrustList) or the holders' unlock policy
// (split.UnlockPolicy.Platforms, as an extra name beside "dstack": the VM's attestation still says "dstack"). Off
// unless one names it (since 2026-11-21: the Google host fallback ready to run, not running).
const PlatformDstackGCP = "dstack-gcp"

// FactPlatformSet is the fact a verification sets to PlatformDstackGCP when the quote matched a Google Cloud set (so
// a holder can require the policy's platform item for it, pin delay included); unset for every Phala quote.
const FactPlatformSet = "platform set"

// GCPShaped says why b looks like a Google Cloud set ("" if it doesn't): Google's firmware (MRTDGoogleEndorsed, or
// an MRTD in any GCP set's GoogleMRTDs), a GCP set's RTMR1 (the dstack UKI as Google's firmware boots it), or a GCP
// image (review L2, 2026-11-21). Such a set matched literally would skip gcpBoot (the endorsement, the UKI check,
// FactPlatformSet), so a signed trust list or unlock policy can't add one as an ordinary set: Google is on only
// through PlatformDstackGCP (WithGCP), with Google's checks.
func GCPShaped(b BootMeasurement) string {
	if strings.EqualFold(b.MRTD, MRTDGoogleEndorsed) {
		return "MRTD " + MRTDGoogleEndorsed
	}
	if _, ok := GCPImages[b.OSImage]; ok {
		return "a Google Cloud OS image " + short(b.OSImage)
	}
	for _, g := range GCPBootMeasurements {
		for _, m := range g.GoogleMRTDs {
			if strings.EqualFold(b.MRTD, m) {
				return "Google's firmware MRTD " + short(m)
			}
		}
		if strings.EqualFold(b.RTMR1, g.RTMR1) {
			return "the RTMR1 of " + g.Name
		}
	}
	return ""
}

// WithGCP returns p accepting dstack on Google Cloud too: GCPBootMeasurements and GCPImages are added to what p uses
// (its own, or the built-in ones). Nothing Phala's quotes are checked against changes.
func (p Policy) WithGCP() Policy {
	images := maps.Clone(cmpOr(p.ProdImages, ProdImages))
	maps.Copy(images, GCPImages)
	boot := slices.Clone(p.Boot)
	if boot == nil {
		boot = slices.Clone(BootMeasurements)
	}
	p.ProdImages, p.Boot = images, append(boot, GCPBootMeasurements...)
	return p
}

// gcpBoot checks a quote against the Google Cloud set (MRTD MRTDGoogleEndorsed) whose RTMR0, RTMR1 and RTMR2 it
// matches, if any: keys made in the VM (key provider none, no os-image-hash event), the firmware log replays to
// RTMR0-2 and RTMR1's boot applications hold the set's UKI, the quote's MRTD is one of the set's GoogleMRTDs (checked
// before anything is fetched), and Google's signed endorsement lists it with at least the set's firmware SVN. On success it returns sets with that set's MRTD set to the quote's, so
// osImageFromBoot and matchBoot then treat it like a pinned one. With no GCP set matching (every Phala quote) it
// returns sets unchanged, nil and no error, and fetches nothing.
func gcpBoot(ctx context.Context, q *tdx.Quote, ev []tdx.Event, sets []BootMeasurement, keyProvider []byte,
	hasOSEvent bool, getter trust.HTTPSGetter, now time.Time) ([]BootMeasurement, *BootMeasurement, string, error) {
	got := [3]string{hex.EncodeToString(q.Rtmrs[0]), hex.EncodeToString(q.Rtmrs[1]), hex.EncodeToString(q.Rtmrs[2])}
	for i := range sets {
		s := &sets[i]
		if s.MRTD != MRTDGoogleEndorsed || !strings.EqualFold(s.RTMR0, got[0]) || !strings.EqualFold(s.RTMR1, got[1]) ||
			!strings.EqualFold(s.RTMR2, got[2]) {
			continue
		}
		if hasOSEvent || !keysMadeInVM(keyProvider) {
			return sets, s, "", fmt.Errorf("%s needs key provider none (keys made in the VM, no os-image-hash event); key provider %q",
				s.Name, keyProvider)
		}
		apps, err := tdx.ReplayFirmware(q, ev)
		if err != nil {
			return sets, s, "", fmt.Errorf("firmware event log: %w", err)
		}
		if s.UKI == "" || !slices.ContainsFunc(apps, func(a string) bool { return strings.EqualFold(a, s.UKI) }) {
			return sets, s, "", fmt.Errorf("RTMR1's boot applications don't include %s's UKI %s", s.Name, short(s.UKI))
		}
		mrtd := hex.EncodeToString(q.MrTd)
		if !slices.ContainsFunc(s.GoogleMRTDs, func(m string) bool { return strings.EqualFold(m, mrtd) }) {
			pinned := make([]string, len(s.GoogleMRTDs))
			for j, m := range s.GoogleMRTDs {
				pinned[j] = short(m)
			}
			return sets, s, "", fmt.Errorf("MRTD %s isn't a Google firmware build we reviewed for %s (pinned: %s); "+
				"Google's endorsement alone isn't enough: a new build needs a reviewed set and a client release",
				short(mrtd), s.Name, strings.Join(pinned, ", "))
		}
		fw, m, err := gcetcb.Check(ctx, getter, q.MrTd, now)
		if err != nil {
			return sets, s, "", err
		}
		if fw.SVN < s.MinFirmwareSVN {
			return sets, s, "", fmt.Errorf("Google's firmware for MRTD %s has SVN %d, %s needs at least %d",
				short(mrtd), fw.SVN, s.Name, s.MinFirmwareSVN)
		}
		out := slices.Clone(sets)
		out[i].MRTD = mrtd
		return out, &out[i], fw.Describe(m) + "; UKI " + short(s.UKI) + " in RTMR1", nil
	}
	return sets, nil, "", nil
}
