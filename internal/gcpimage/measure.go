package gcpimage

import (
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
)

// UKIPath is where dstack's image keeps its unified kernel image (the ESP's only file).
const UKIPath = "EFI/BOOT/BOOTX64.EFI"

// Event is one measured event: its RTMR, what it is and its SHA-384 digest (hex).
type Event struct {
	RTMR   int    `json:"rtmr"`
	What   string `json:"what"`
	Digest string `json:"digest"`
}

// Boot is what dstack's boot disk puts in RTMR1 and RTMR2 on Google Cloud's TDX firmware, computed from the disk
// image alone. Google's firmware (MRTD) and its configuration (RTMR0: the configuration volume, Secure Boot
// variables, ACPI tables, boot variables) aren't in the image and can't be computed from it.
type Boot struct {
	GPT    string  `json:"gpt_event_sha384"`           // EV_EFI_GPT_EVENT
	UKI    string  `json:"uki_authenticode_sha384"`    // the UKI, an EV_EFI_BOOT_SERVICES_APPLICATION
	Kernel string  `json:"kernel_authenticode_sha384"` // the UKI's .linux, loaded by its stub, another one
	RTMR1  string  `json:"rtmr1"`
	RTMR2  string  `json:"rtmr2"`
	Events []Event `json:"events"` // RTMR1 and RTMR2's events, in the order the firmware log has them
}

// The fixed RTMR1 events of a UEFI boot (TCG PC Client Platform Firmware Profile; edk2 Tcg2Dxe, as Google's TDX
// firmware logs them): an EV_EFI_ACTION before the boot option's application, the separator, and the two
// ExitBootServices actions after it.
const (
	actionBootOption = "Calling EFI Application from Boot Option"
	actionExitBS     = "Exit Boot Services Invocation"
	actionExitBSOK   = "Exit Boot Services Returned with Success"
)

// stubSections are the UKI sections systemd-stub measures into PCR 11 (RTMR2 on TDX), in its order (systemd's
// UnifiedSection enum; .pcrsig is never measured): the name with its NUL, then the contents as loaded.
var stubSections = []string{".linux", ".osrel", ".cmdline", ".initrd", ".ucode", ".splash", ".dtb", ".uname", ".sbat",
	".pcrpkey", ".profile", ".dtbauto", ".hwids", ".efifw"}

func sum384(b []byte) []byte { s := sha512.Sum384(b); return s[:] }

func extend(mr, d []byte) []byte {
	h := sha512.New384()
	h.Write(mr)
	h.Write(d)
	return h.Sum(nil)
}

// Measure computes Boot from a dstack boot disk image (disk.raw).
func Measure(disk io.ReaderAt) (*Boot, error) {
	gptEv, parts, err := readGPT(disk)
	if err != nil {
		return nil, err
	}
	var esp *gptPart
	for i := range parts {
		if parts[i].TypeGUID == espType {
			if esp != nil {
				return nil, errors.New("two EFI System Partitions")
			}
			esp = &parts[i]
		}
	}
	if esp == nil {
		return nil, errors.New("no EFI System Partition")
	}
	fs, err := openFAT(disk, int64(esp.First)*sector)
	if err != nil {
		return nil, fmt.Errorf("EFI System Partition: %w", err)
	}
	uki, err := fs.readFile(UKIPath)
	if err != nil {
		return nil, err
	}
	return measureUKI(gptEv, uki)
}

func measureUKI(gptEv, uki []byte) (*Boot, error) {
	ukiHash, err := authenticode384(uki)
	if err != nil {
		return nil, fmt.Errorf("UKI: %w", err)
	}
	img, err := parsePE(uki)
	if err != nil {
		return nil, err
	}
	secs := map[string]peSection{}
	for _, s := range img.sections {
		if _, dup := secs[s.Name]; dup {
			return nil, fmt.Errorf("UKI: two %s sections", s.Name)
		}
		secs[s.Name] = s
	}
	linux, ok := secs[".linux"]
	if !ok {
		return nil, errors.New("UKI: no .linux section")
	}
	kernel, err := img.sectionData(uki, linux)
	if err != nil {
		return nil, err
	}
	kernelHash, err := authenticode384(kernel)
	if err != nil {
		return nil, fmt.Errorf("UKI .linux: %w", err)
	}
	b := &Boot{GPT: hex.EncodeToString(sum384(gptEv)), UKI: hex.EncodeToString(ukiHash), Kernel: hex.EncodeToString(kernelHash)}
	add := func(rtmr int, what string, d []byte) {
		b.Events = append(b.Events, Event{rtmr, what, hex.EncodeToString(d)})
	}
	add(1, "EV_EFI_ACTION "+actionBootOption, sum384([]byte(actionBootOption)))
	add(1, "EV_SEPARATOR", sum384([]byte{0, 0, 0, 0}))
	add(1, "EV_EFI_GPT_EVENT", sum384(gptEv))
	add(1, "EV_EFI_BOOT_SERVICES_APPLICATION UKI", ukiHash)
	for _, name := range stubSections {
		s, ok := secs[name]
		if !ok || s.VirtualSize == 0 {
			continue
		}
		data, err := img.sectionData(uki, s)
		if err != nil {
			return nil, err
		}
		add(2, "EV_IPL "+name+" (name)", sum384(append([]byte(name), 0)))
		add(2, "EV_IPL "+name, sum384(data))
	}
	add(1, "EV_EFI_BOOT_SERVICES_APPLICATION .linux", kernelHash)
	add(1, "EV_EFI_ACTION "+actionExitBS, sum384([]byte(actionExitBS)))
	add(1, "EV_EFI_ACTION "+actionExitBSOK, sum384([]byte(actionExitBSOK)))
	r1, r2 := make([]byte, 48), make([]byte, 48)
	for _, e := range b.Events {
		d, _ := hex.DecodeString(e.Digest)
		if e.RTMR == 1 {
			r1 = extend(r1, d)
		} else {
			r2 = extend(r2, d)
		}
	}
	b.RTMR1, b.RTMR2 = hex.EncodeToString(r1), hex.EncodeToString(r2)
	return b, nil
}
