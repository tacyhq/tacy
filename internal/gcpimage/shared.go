package gcpimage

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"unicode/utf16"
)

// The shared disk dstack's guest reads its configuration from on Google Cloud: a FAT volume labelled DSTACKSHR
// holding app-compose.json (whose sha256 is the attested compose-hash, RTMR3), .sys-config.json, .instance_info and
// .user-config. Only app-compose.json is measured; the rest is configuration a wrong value of can only stop the boot
// (none mode: no key service, no gateway).
const (
	SharedLabel       = "DSTACKSHR"
	SharedBytes       = 8 << 20
	SharedAppCompose  = "app-compose.json"
	SharedSysConfig   = ".sys-config.json"
	SharedInstanceInf = ".instance_info"
	SharedUserConfig  = ".user-config"
)

// SharedFiles are the files a shared disk holds.
type SharedFiles struct {
	AppCompose []byte // the release's app-compose.json, byte for byte
	SysConfig  []byte // the release's gcp-sys-config.json
	AppID      string // 40 hex: the app id dstack measures (RTMR3 app-id)
	Seed       string // 40 hex: the instance id seed (fresh per VM; NewSeed)
}

// AppIDFor is the app id dstack measures (RTMR3 app-id) for the VM named name in project: fixed per VM, as Phala
// gives a CVM one id for its life, so a restart (on Google a delete and a create of the same name) and an update in
// place keep it (the chat's schedule owner rows name it: <app id>/<instance id>), and another VM gets another.
func AppIDFor(project, name string) string {
	// AppIDRule says this in release.json.
	h := sha256.Sum256([]byte("tacy gcp app id\x00" + project + "\x00" + name))
	return hex.EncodeToString(h[:20])
}

// AppIDRule is AppIDFor in words, for release.json's gcp.platform.app_id.
const AppIDRule = "hex(sha256(\"tacy gcp app id\" NUL project NUL instance name)[:20])"

// NewSeed is a fresh instance id seed.
func NewSeed() string {
	b := make([]byte, 20)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func (s SharedFiles) files() (map[string][]byte, error) {
	for _, h := range []string{s.AppID, s.Seed} {
		if b, err := hex.DecodeString(h); err != nil || len(b) != 20 {
			return nil, fmt.Errorf("shared disk: app id and seed must be 40 hex, got %q", h)
		}
	}
	if len(s.AppCompose) == 0 || len(s.SysConfig) == 0 {
		return nil, errors.New("shared disk: app-compose.json and the system config are required")
	}
	info, _ := json.MarshalIndent(map[string]string{"instance_id_seed": s.Seed, "app_id": s.AppID}, "", "  ")
	return map[string][]byte{SharedAppCompose: s.AppCompose, SharedSysConfig: s.SysConfig, SharedInstanceInf: info,
		SharedUserConfig: []byte("{}")}, nil
}

// SharedDisk is the shared disk image (raw, SharedBytes): a FAT16 volume labelled DSTACKSHR with the four files in
// its root directory under their long names, fixed volume id and times.
func SharedDisk(s SharedFiles) ([]byte, error) {
	files, err := s.files()
	if err != nil {
		return nil, err
	}
	return writeFAT16(SharedBytes, SharedLabel, files)
}

// ReadShared reads a shared disk image back: its volume label and root files.
func ReadShared(img []byte) (label string, files map[string][]byte, err error) {
	fs, err := openFAT(bytes.NewReader(img), 0)
	if err != nil {
		return "", nil, err
	}
	files, err = fs.rootFiles()
	return fs.VolumeName, files, err
}

// writeFAT16 makes a FAT16 volume of size bytes (512-byte sectors, 2 per cluster, 2 FATs, 512 root entries) holding
// files in its root directory, each under a long name (VFAT) with a short alias TACY000n.
func writeFAT16(size int, label string, files map[string][]byte) ([]byte, error) {
	const bps, spc, reserved, nfats, rootEnts = 512, 2, 1, 2, 512
	total := size / bps
	rootSecs := rootEnts * 32 / bps
	fatSecs := 1
	for {
		clusters := (total - reserved - nfats*fatSecs - rootSecs) / spc
		if (clusters+2)*2 <= fatSecs*bps {
			if clusters < 4085 || clusters >= 65525 {
				return nil, fmt.Errorf("FAT16: %d clusters don't make a FAT16 volume", clusters)
			}
			break
		}
		fatSecs++
	}
	img := make([]byte, size)
	b := img[:bps]
	copy(b, []byte{0xeb, 0x3c, 0x90})
	copy(b[3:11], "TACY    ")
	binary.LittleEndian.PutUint16(b[11:], bps)
	b[13] = spc
	binary.LittleEndian.PutUint16(b[14:], reserved)
	b[16] = nfats
	binary.LittleEndian.PutUint16(b[17:], rootEnts)
	if total < 65536 {
		binary.LittleEndian.PutUint16(b[19:], uint16(total))
	} else {
		binary.LittleEndian.PutUint32(b[32:], uint32(total))
	}
	b[21] = 0xf8
	binary.LittleEndian.PutUint16(b[22:], uint16(fatSecs))
	binary.LittleEndian.PutUint16(b[24:], 32)
	binary.LittleEndian.PutUint16(b[26:], 64)
	b[36] = 0x80
	b[38] = 0x29
	binary.LittleEndian.PutUint32(b[39:], 0x54414359) // volume id "TACY"
	copy(b[43:54], fmt.Sprintf("%-11s", label))
	copy(b[54:62], "FAT16   ")
	b[510], b[511] = 0x55, 0xaa
	fat := make([]byte, fatSecs*bps)
	binary.LittleEndian.PutUint16(fat[0:], 0xfff8)
	binary.LittleEndian.PutUint16(fat[2:], 0xffff)
	root := make([]byte, rootEnts*32)
	dataStart := (reserved + nfats*fatSecs + rootSecs) * bps
	cs := spc * bps
	// The volume label entry first, as mkfs.fat writes it.
	copy(root[0:11], fmt.Sprintf("%-11s", label))
	root[11] = 0x08
	setTimes(root[0:32])
	ent := 32
	next := uint32(2)
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	slices.Sort(names)
	for i, n := range names {
		data := files[n]
		short := []byte(fmt.Sprintf("TACY%04d   ", i+1))
		u := utf16.Encode([]rune(n))
		parts := (len(u) + 12) / 13
		if ent+32*(parts+1) > len(root) {
			return nil, errors.New("FAT16: root directory full")
		}
		var sum byte
		for _, c := range short {
			sum = (sum>>1 | sum<<7) + c
		}
		for p := parts; p >= 1; p-- {
			e := root[ent : ent+32]
			e[0] = byte(p)
			if p == parts {
				e[0] |= 0x40
			}
			e[11], e[13] = 0x0f, sum
			for k, o := range []int{1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30} {
				j := (p-1)*13 + k
				var c uint16 = 0xffff
				switch {
				case j < len(u):
					c = u[j]
				case j == len(u):
					c = 0
				}
				binary.LittleEndian.PutUint16(e[o:], c)
			}
			ent += 32
		}
		e := root[ent : ent+32]
		copy(e[0:11], short)
		e[11] = 0x20 // archive
		setTimes(e)
		binary.LittleEndian.PutUint32(e[28:], uint32(len(data)))
		if len(data) > 0 {
			n := uint32((len(data) + cs - 1) / cs)
			binary.LittleEndian.PutUint16(e[26:], uint16(next))
			for k := uint32(0); k < n; k++ {
				v := uint16(next + k + 1)
				if k == n-1 {
					v = 0xffff
				}
				if int(next+k)*2+2 > len(fat) {
					return nil, errors.New("FAT16: volume full")
				}
				binary.LittleEndian.PutUint16(fat[(next+k)*2:], v)
			}
			off := dataStart + int(next-2)*cs
			if off+len(data) > size {
				return nil, errors.New("FAT16: volume full")
			}
			copy(img[off:], data)
			next += n
		}
		ent += 32
	}
	for i := 0; i < nfats; i++ {
		copy(img[(reserved+i*fatSecs)*bps:], fat)
	}
	copy(img[(reserved+nfats*fatSecs)*bps:], root)
	return img, nil
}

// setTimes sets a directory entry's creation, access and write dates to 1980-01-01 00:00.
func setTimes(e []byte) {
	for _, o := range []int{16, 18, 24} {
		binary.LittleEndian.PutUint16(e[o:], 0x0021)
	}
}
