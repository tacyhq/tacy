package gcpimage

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode/utf16"
)

// fatFS is a read-only FAT12/16/32 file system (enough to read the dstack UKI from the EFI System Partition and to
// read back the shared disks we write).
type fatFS struct {
	r          io.ReaderAt
	base       int64 // byte offset of the volume
	bps        int64 // bytes per sector
	spc        int64 // sectors per cluster
	fatStart   int64 // byte offset of the first FAT
	rootStart  int64 // FAT12/16: byte offset of the root directory
	rootSize   int64 // FAT12/16: its size in bytes
	dataStart  int64 // byte offset of cluster 2
	rootClus   uint32
	bits       int // 12, 16 or 32
	clusters   uint32
	VolumeName string
}

func openFAT(r io.ReaderAt, base int64) (*fatFS, error) {
	b := make([]byte, 512)
	if _, err := r.ReadAt(b, base); err != nil {
		return nil, err
	}
	if b[510] != 0x55 || b[511] != 0xaa {
		return nil, errors.New("FAT: no boot sector signature")
	}
	f := &fatFS{r: r, base: base, bps: int64(binary.LittleEndian.Uint16(b[11:])), spc: int64(b[13])}
	if f.bps != 512 && f.bps != 1024 && f.bps != 2048 && f.bps != 4096 || f.spc == 0 {
		return nil, errors.New("FAT: bad geometry")
	}
	reserved := int64(binary.LittleEndian.Uint16(b[14:]))
	nfats := int64(b[16])
	rootEnts := int64(binary.LittleEndian.Uint16(b[17:]))
	total := int64(binary.LittleEndian.Uint16(b[19:]))
	if total == 0 {
		total = int64(binary.LittleEndian.Uint32(b[32:]))
	}
	fatSz := int64(binary.LittleEndian.Uint16(b[22:]))
	label := b[43:54]
	fat32 := fatSz == 0 // as Linux tells FAT32: no 16-bit FAT size (mkfs.fat -F 32 makes small FAT32 volumes too)
	if fat32 {
		fatSz = int64(binary.LittleEndian.Uint32(b[36:]))
		f.rootClus = binary.LittleEndian.Uint32(b[44:])
		label = b[71:82]
	}
	f.VolumeName = strings.TrimRight(string(label), " ")
	rootSecs := (rootEnts*32 + f.bps - 1) / f.bps
	f.fatStart = base + reserved*f.bps
	f.rootStart = f.fatStart + nfats*fatSz*f.bps
	f.rootSize = rootEnts * 32
	f.dataStart = f.rootStart + rootSecs*f.bps
	dataSecs := total - reserved - nfats*fatSz - rootSecs
	if dataSecs <= 0 {
		return nil, errors.New("FAT: no data region")
	}
	f.clusters = uint32(dataSecs / f.spc)
	switch {
	case fat32:
		f.bits = 32
	case f.clusters < 4085:
		f.bits = 12
	default:
		f.bits = 16
	}
	if (f.bits == 32) != (rootEnts == 0) {
		return nil, errors.New("FAT: root directory doesn't fit the FAT type")
	}
	return f, nil
}

func (f *fatFS) next(c uint32) (uint32, error) {
	var off int64
	switch f.bits {
	case 12:
		off = int64(c) + int64(c)/2
	case 16:
		off = int64(c) * 2
	default:
		off = int64(c) * 4
	}
	b := make([]byte, 4)
	if _, err := f.r.ReadAt(b[:min(4, 2+f.bits/16*2)], f.fatStart+off); err != nil && err != io.EOF {
		return 0, err
	}
	switch f.bits {
	case 12:
		v := uint32(binary.LittleEndian.Uint16(b))
		if c&1 == 1 {
			v >>= 4
		}
		v &= 0xfff
		if v >= 0xff8 {
			return 0, io.EOF
		}
		return v, nil
	case 16:
		v := uint32(binary.LittleEndian.Uint16(b))
		if v >= 0xfff8 {
			return 0, io.EOF
		}
		return v, nil
	default:
		v := binary.LittleEndian.Uint32(b) & 0x0fffffff
		if v >= 0x0ffffff8 {
			return 0, io.EOF
		}
		return v, nil
	}
}

// chain reads a cluster chain (at most limit bytes; limit < 0: all of it).
func (f *fatFS) chain(c uint32, limit int64) ([]byte, error) {
	cs := f.spc * f.bps
	var out []byte
	for seen := 0; c >= 2; seen++ {
		if c-2 >= f.clusters || seen > int(f.clusters) {
			return nil, errors.New("FAT: bad cluster chain")
		}
		buf := make([]byte, cs)
		if _, err := f.r.ReadAt(buf, f.dataStart+int64(c-2)*cs); err != nil && err != io.EOF {
			return nil, err
		}
		out = append(out, buf...)
		if limit >= 0 && int64(len(out)) >= limit {
			return out[:limit], nil
		}
		n, err := f.next(c)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		c = n
	}
	if limit >= 0 && int64(len(out)) < limit {
		return nil, errors.New("FAT: file shorter than its size")
	}
	return out, nil
}

// fatEntry is a directory entry: its long name if it has one, else the 8.3 name.
type fatEntry struct {
	Name  string
	Dir   bool
	Clus  uint32
	Size  uint32
	Label bool
}

func (f *fatFS) readDir(clus uint32, root bool) ([]fatEntry, error) {
	var b []byte
	var err error
	if root && f.bits != 32 {
		b = make([]byte, f.rootSize)
		_, err = f.r.ReadAt(b, f.rootStart)
	} else {
		if root {
			clus = f.rootClus
		}
		b, err = f.chain(clus, -1)
	}
	if err != nil {
		return nil, err
	}
	var out []fatEntry
	var lfn []uint16
	for i := 0; i+32 <= len(b); i += 32 {
		e := b[i : i+32]
		if e[0] == 0 {
			break
		}
		if e[0] == 0xe5 {
			lfn = nil
			continue
		}
		if e[11] == 0x0f { // long name part: 13 UCS-2 characters, last part first
			var part []uint16
			for _, o := range []int{1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30} {
				part = append(part, binary.LittleEndian.Uint16(e[o:]))
			}
			lfn = append(part, lfn...)
			continue
		}
		name := strings.TrimRight(string(e[:8]), " ")
		if ext := strings.TrimRight(string(e[8:11]), " "); ext != "" {
			name += "." + ext
		}
		if lfn != nil {
			for j, c := range lfn {
				if c == 0 || c == 0xffff {
					lfn = lfn[:j]
					break
				}
			}
			name = string(utf16.Decode(lfn))
			lfn = nil
		}
		clus := uint32(binary.LittleEndian.Uint16(e[26:])) | uint32(binary.LittleEndian.Uint16(e[20:]))<<16
		out = append(out, fatEntry{Name: name, Dir: e[11]&0x10 != 0, Clus: clus, Size: binary.LittleEndian.Uint32(e[28:]),
			Label: e[11]&0x08 != 0 && e[11] != 0x0f})
	}
	return out, nil
}

// readFile reads the file at path (components separated by "/", matched without regard to case, as FAT does).
func (f *fatFS) readFile(path string) ([]byte, error) {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	clus, root := uint32(0), true
	for i, p := range parts {
		ents, err := f.readDir(clus, root)
		if err != nil {
			return nil, err
		}
		found := false
		for _, e := range ents {
			if e.Label || !strings.EqualFold(e.Name, p) {
				continue
			}
			if i == len(parts)-1 {
				if e.Dir {
					return nil, fmt.Errorf("FAT: %s is a directory", path)
				}
				return f.chain(e.Clus, int64(e.Size))
			}
			if !e.Dir {
				return nil, fmt.Errorf("FAT: %s isn't a directory", p)
			}
			clus, root, found = e.Clus, false, true
			break
		}
		if !found {
			return nil, fmt.Errorf("FAT: no %s", path)
		}
	}
	return nil, fmt.Errorf("FAT: no %s", path)
}

// rootFiles lists the root directory's files (not directories or the volume label) by name.
func (f *fatFS) rootFiles() (map[string][]byte, error) {
	ents, err := f.readDir(0, true)
	if err != nil {
		return nil, err
	}
	out := map[string][]byte{}
	for _, e := range ents {
		if e.Dir || e.Label {
			continue
		}
		b, err := f.chain(e.Clus, int64(e.Size))
		if e.Size == 0 {
			b, err = nil, nil
		}
		if err != nil {
			return nil, err
		}
		out[e.Name] = b
	}
	return out, nil
}
