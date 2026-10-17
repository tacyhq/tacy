package verifier

import (
	"encoding/hex"
	"fmt"
	"slices"
	"strings"

	"github.com/tacyhq/tacy/internal/tdx"
)

// BootMeasurement is one allowed set of TDX boot measurements: a dstack OS image on one VM shape.
//
//   - MRTD is the firmware (dstack's OVMF/TDVF), and with QEMU 8.x how its pages are added.
//   - RTMR0 is the firmware's configuration: the TD HOB (memory size), ACPI tables (vCPUs, devices, hotplug,
//     PCI layout, QEMU version) and the boot variables. It changes with the VM size, not only the image.
//   - RTMR1 is the kernel (bzImage, with the setup header the firmware patches; it depends on memory size too).
//   - RTMR2 is the kernel command line (which carries the dm-verity root hash of the root filesystem) and the
//     initramfs.
//
// So a set pins the code that boots (firmware, kernel, initramfs, root filesystem) and the VM shape it boots on.
// RTMR3 (the app, measured at runtime) is checked separately against the event log.
type BootMeasurement struct {
	Name    string // the image and VM shape, e.g. "dstack-0.5.9, 1 vCPU, 2 GiB"
	OSImage string // dstack os-image-hash: sha256 of the image's sha256sum.txt (RTMR3 os-image-hash event)
	MRTD    string // hex, 48 bytes each
	RTMR0   string
	RTMR1   string
	RTMR2   string
	Source  string // how the values were obtained: computed, observed, or both
}

// BootMeasurements are the measurement sets a VM may boot with. Add a set when the dstack image or the VM size
// changes (README.md, "Boot measurements"); the verifier refuses any other.
var BootMeasurements = []BootMeasurement{
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
}

// RetiredBootMeasurements are sets the verifier no longer accepts (since 2026-10-17: only 0.6.1 once the live
// CVM moved to it, with the gateway/vault release). Kept for the record and for tests on older recordings: 0.5.9
// (computed and observed: the live CVM until 2026-10-17), 0.5.8 and 0.6.0 (computed only, never booted by us).
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
			if !strings.EqualFold(want, got[j]) {
				diff = append(diff, names[j])
			}
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
	return nil, fmt.Errorf("MRTD/RTMR0-2 (MRTD %s, RTMR0 %s, RTMR1 %s, RTMR2 %s) match no pinned set; closest is %s, "+
		"which differs in %s%s", short(got[0]), short(got[1]), short(got[2]), short(got[3]), closest.Name,
		strings.Join(closestDiff, ", "), hint)
}
