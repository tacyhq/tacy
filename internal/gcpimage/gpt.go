package gcpimage

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"unicode/utf16"
)

const sector = 512

// gptPart is one used GPT partition entry.
type gptPart struct {
	TypeGUID [16]byte
	Name     string
	First    uint64 // first LBA
	Last     uint64 // last LBA (inclusive)
}

// espType is the EFI System Partition's type GUID (C12A7328-F81F-11D2-BA4B-00A0C93EC93B), as stored on disk.
var espType = [16]byte{0x28, 0x73, 0x2a, 0xc1, 0x1f, 0xf8, 0xd2, 0x11, 0xba, 0x4b, 0x00, 0xa0, 0xc9, 0x3e, 0xc9, 0x3b}

// readGPT reads the primary GPT of a disk image and returns the UEFI_GPT_DATA the firmware measures as
// EV_EFI_GPT_EVENT (edk2 Tcg2MeasureGptTable: the 92-byte header, the number of used entries as a UINT64, then each
// used entry, SizeOfPartitionEntry bytes, in table order) and the used partitions. Header and entry CRCs must hold.
func readGPT(r io.ReaderAt) (event []byte, parts []gptPart, err error) {
	hdr := make([]byte, sector)
	if _, err := r.ReadAt(hdr, sector); err != nil {
		return nil, nil, fmt.Errorf("GPT header: %w", err)
	}
	if string(hdr[:8]) != "EFI PART" {
		return nil, nil, errors.New("no GPT (LBA 1 isn't an EFI PART header)")
	}
	hsize := binary.LittleEndian.Uint32(hdr[12:])
	if hsize < 92 || hsize > sector {
		return nil, nil, fmt.Errorf("GPT header size %d", hsize)
	}
	h := append([]byte(nil), hdr[:hsize]...)
	want := binary.LittleEndian.Uint32(h[16:])
	binary.LittleEndian.PutUint32(h[16:], 0)
	if crc32.ChecksumIEEE(h) != want {
		return nil, nil, errors.New("GPT header CRC doesn't match")
	}
	entLBA := binary.LittleEndian.Uint64(hdr[72:])
	n := binary.LittleEndian.Uint32(hdr[80:])
	esize := binary.LittleEndian.Uint32(hdr[84:])
	if esize < 128 || esize > 4096 || n == 0 || n > 1024 {
		return nil, nil, fmt.Errorf("GPT entries: %d of %d bytes", n, esize)
	}
	ents := make([]byte, int(n)*int(esize))
	if _, err := r.ReadAt(ents, int64(entLBA)*sector); err != nil {
		return nil, nil, fmt.Errorf("GPT entries: %w", err)
	}
	if crc32.ChecksumIEEE(ents) != binary.LittleEndian.Uint32(hdr[88:]) {
		return nil, nil, errors.New("GPT entries CRC doesn't match")
	}
	var used [][]byte
	for i := 0; i < int(n); i++ {
		e := ents[i*int(esize) : (i+1)*int(esize)]
		if bytes.Equal(e[:16], make([]byte, 16)) {
			continue
		}
		used = append(used, e)
		var p gptPart
		copy(p.TypeGUID[:], e[:16])
		p.First, p.Last = binary.LittleEndian.Uint64(e[32:]), binary.LittleEndian.Uint64(e[40:])
		u := make([]uint16, 36)
		for j := range u {
			u[j] = binary.LittleEndian.Uint16(e[56+2*j:])
		}
		for j, c := range u {
			if c == 0 {
				u = u[:j]
				break
			}
		}
		p.Name = string(utf16.Decode(u))
		parts = append(parts, p)
	}
	ev := append([]byte(nil), hdr[:92]...)
	ev = binary.LittleEndian.AppendUint64(ev, uint64(len(used)))
	for _, e := range used {
		ev = append(ev, e...)
	}
	return ev, parts, nil
}

// writeGPT lays out a disk of size bytes (a multiple of 512) with a protective MBR, a primary and a backup GPT, and
// partitions (First/Last set by the caller), with fixed disk and partition GUIDs, so the same input gives the same
// bytes. Each partition entry's unique GUID is guids[i].
func writeGPT(disk []byte, diskGUID [16]byte, parts []gptPart, guids [][16]byte) {
	lbas := uint64(len(disk) / sector)
	// Protective MBR.
	mbr := disk[:sector]
	mbr[446+4] = 0xee
	mbr[446+1], mbr[446+2], mbr[446+3] = 0x00, 0x02, 0x00
	mbr[446+5], mbr[446+6], mbr[446+7] = 0xff, 0xff, 0xff
	binary.LittleEndian.PutUint32(mbr[446+8:], 1)
	binary.LittleEndian.PutUint32(mbr[446+12:], uint32(min(lbas-1, 0xffffffff)))
	mbr[510], mbr[511] = 0x55, 0xaa
	const n, esize = 128, 128
	ents := make([]byte, n*esize)
	for i, p := range parts {
		e := ents[i*esize:]
		copy(e[:16], p.TypeGUID[:])
		copy(e[16:32], guids[i][:])
		binary.LittleEndian.PutUint64(e[32:], p.First)
		binary.LittleEndian.PutUint64(e[40:], p.Last)
		for j, c := range utf16.Encode([]rune(p.Name)) {
			binary.LittleEndian.PutUint16(e[56+2*j:], c)
		}
	}
	entSectors := uint64(n * esize / sector)
	hdr := func(my, alt, entries uint64) []byte {
		h := make([]byte, 92)
		copy(h, "EFI PART")
		binary.LittleEndian.PutUint32(h[8:], 0x00010000)
		binary.LittleEndian.PutUint32(h[12:], 92)
		binary.LittleEndian.PutUint64(h[24:], my)
		binary.LittleEndian.PutUint64(h[32:], alt)
		binary.LittleEndian.PutUint64(h[40:], 2+entSectors)
		binary.LittleEndian.PutUint64(h[48:], lbas-2-entSectors)
		copy(h[56:72], diskGUID[:])
		binary.LittleEndian.PutUint64(h[72:], entries)
		binary.LittleEndian.PutUint32(h[80:], n)
		binary.LittleEndian.PutUint32(h[84:], esize)
		binary.LittleEndian.PutUint32(h[88:], crc32.ChecksumIEEE(ents))
		binary.LittleEndian.PutUint32(h[16:], crc32.ChecksumIEEE(h))
		return h
	}
	copy(disk[sector:], hdr(1, lbas-1, 2))
	copy(disk[2*sector:], ents)
	copy(disk[(lbas-1-entSectors)*sector:], ents)
	copy(disk[(lbas-1)*sector:], hdr(lbas-1, 1, lbas-1-entSectors))
}
