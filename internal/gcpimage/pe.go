package gcpimage

import (
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"sort"
)

// peSection is one section header of a PE image.
type peSection struct {
	Name           string
	VirtualSize    uint32
	VirtualAddress uint32
	SizeOfRawData  uint32
	PointerToRaw   uint32
}

// peImage is what Authenticode and the UKI's measurements need from a PE file.
type peImage struct {
	checksumOff  int // offset of the optional header's CheckSum
	certDirOff   int // offset of the Certificate Table data directory entry (8 bytes)
	certSize     uint32
	sizeOfHeader uint32
	sections     []peSection
}

func parsePE(b []byte) (*peImage, error) {
	if len(b) < 0x40 || b[0] != 'M' || b[1] != 'Z' {
		return nil, errors.New("not a PE image (no MZ header)")
	}
	pe := int(binary.LittleEndian.Uint32(b[0x3c:]))
	if pe < 0 || pe+24 > len(b) || string(b[pe:pe+4]) != "PE\x00\x00" {
		return nil, errors.New("not a PE image (no PE signature)")
	}
	coff := pe + 4
	nsec := int(binary.LittleEndian.Uint16(b[coff+2:]))
	optSize := int(binary.LittleEndian.Uint16(b[coff+16:]))
	opt := coff + 20
	if opt+optSize > len(b) || optSize < 96 {
		return nil, errors.New("PE optional header truncated")
	}
	var dirs int
	switch binary.LittleEndian.Uint16(b[opt:]) {
	case 0x10b: // PE32
		dirs = opt + 96
	case 0x20b: // PE32+
		dirs = opt + 112
	default:
		return nil, errors.New("PE optional header: unknown magic")
	}
	nDirs := int(binary.LittleEndian.Uint32(b[dirs-4:]))
	img := &peImage{checksumOff: opt + 64, certDirOff: dirs + 4*8, sizeOfHeader: binary.LittleEndian.Uint32(b[opt+60:])}
	if nDirs > 4 {
		if img.certDirOff+8 > opt+optSize {
			return nil, errors.New("PE data directories truncated")
		}
		img.certSize = binary.LittleEndian.Uint32(b[img.certDirOff+4:])
	} else {
		img.certDirOff = -1
	}
	sh := opt + optSize
	if sh+40*nsec > len(b) {
		return nil, errors.New("PE section table truncated")
	}
	for i := 0; i < nsec; i++ {
		s := b[sh+40*i : sh+40*i+40]
		name := string(s[:8])
		for j := 0; j < len(name); j++ {
			if name[j] == 0 {
				name = name[:j]
				break
			}
		}
		img.sections = append(img.sections, peSection{Name: name, VirtualSize: binary.LittleEndian.Uint32(s[8:]),
			VirtualAddress: binary.LittleEndian.Uint32(s[12:]), SizeOfRawData: binary.LittleEndian.Uint32(s[16:]),
			PointerToRaw: binary.LittleEndian.Uint32(s[20:])})
	}
	return img, nil
}

// authenticode384 is the PE image's Authenticode digest with SHA-384, as UEFI firmware measures a boot application
// (EV_EFI_BOOT_SERVICES_APPLICATION, edk2 HashPeImage): the headers without the checksum and the certificate table
// entry, then each section's raw data in file order, then any data after the sections but the certificate table.
func authenticode384(b []byte) ([]byte, error) { return authenticode(b, sha512.New384()) }

// authenticode is the Authenticode digest of a PE image with h.
func authenticode(b []byte, h hash.Hash) ([]byte, error) {
	img, err := parsePE(b)
	if err != nil {
		return nil, err
	}
	if int(img.sizeOfHeader) > len(b) {
		return nil, errors.New("PE SizeOfHeaders past the end of the file")
	}
	// The fields Authenticode skips lie inside the headers it hashes (review L9: else a crafted image panics here).
	if end := img.checksumOff + 4; img.certDirOff >= 0 {
		end = img.certDirOff + 8
		if img.certDirOff < img.checksumOff+4 || end > int(img.sizeOfHeader) {
			return nil, errors.New("PE certificate table entry outside the headers")
		}
	} else if end > int(img.sizeOfHeader) {
		return nil, errors.New("PE checksum outside the headers")
	}
	if img.certDirOff < 0 {
		h.Write(b[:img.checksumOff])
		h.Write(b[img.checksumOff+4 : img.sizeOfHeader])
	} else {
		h.Write(b[:img.checksumOff])
		h.Write(b[img.checksumOff+4 : img.certDirOff])
		h.Write(b[img.certDirOff+8 : img.sizeOfHeader])
	}
	secs := append([]peSection(nil), img.sections...)
	sort.SliceStable(secs, func(i, j int) bool { return secs[i].PointerToRaw < secs[j].PointerToRaw })
	sum := uint64(img.sizeOfHeader)
	for _, s := range secs {
		if s.SizeOfRawData == 0 {
			continue
		}
		end := uint64(s.PointerToRaw) + uint64(s.SizeOfRawData)
		if end > uint64(len(b)) {
			return nil, fmt.Errorf("PE section %s past the end of the file", s.Name)
		}
		h.Write(b[s.PointerToRaw:end])
		sum += uint64(s.SizeOfRawData)
	}
	if uint64(len(b)) > sum+uint64(img.certSize) {
		h.Write(b[sum : uint64(len(b))-uint64(img.certSize)])
	}
	return h.Sum(nil), nil
}

// sectionData is a section's contents as the image has them loaded in memory: VirtualSize bytes, the raw data
// followed by zeros (what systemd-stub measures and hands on).
func (img *peImage) sectionData(b []byte, s peSection) ([]byte, error) {
	out := make([]byte, s.VirtualSize)
	n := min(s.VirtualSize, s.SizeOfRawData)
	if uint64(s.PointerToRaw)+uint64(n) > uint64(len(b)) {
		return nil, fmt.Errorf("PE section %s past the end of the file", s.Name)
	}
	copy(out, b[s.PointerToRaw:s.PointerToRaw+n])
	return out, nil
}
