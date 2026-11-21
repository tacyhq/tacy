// Package fixbrb is the shared part of the Fix B throwaway's disk-rollback check (test only: cmd/e2epush runs it in
// the VM, cmd/e2e fixb rollback judges what it pushed; never in a release).
//
// The threat (Fix B review, "missing test 3"): the data disk is LUKS2 aes-xts-plain64 with no integrity, under a key
// made in the TD. The host can't choose plaintext, but it can save a sector's ciphertext and write it back later in
// the same boot. XTS tweaks by sector number only, so the sector then decrypts to its OLD plaintext, not to garbage.
// The claim under test: ZFS refuses it, because every block's checksum sits in its parent block pointer, up to the
// uberblock that the running pool keeps in memory; the TD gets a read error, never the old data.
//
// ZFS is copy-on-write: a new version of a file goes to new sectors, so writing the old ciphertext back where the
// old version was touches nothing live. A rollback reaches a live block only once ZFS has reused a sector: the
// attacker restores what the sector held before that reuse. The check therefore makes ZFS reuse the old version's
// sectors (frees, then writes, then filler), restores the saved ciphertext of every reused sector, and reads.
package fixbrb

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// BlockSize is a test block: the pool's ashift (4 KiB) and the unit the check saves, restores and reads.
const BlockSize = 4096

// The markers: the first 8 bytes of each test block. A is the version the host saves, B the version written after
// it, Filler what is written to make ZFS reuse A's sectors.
var (
	SmallA = []byte("TACYRBSA")
	SmallB = []byte("TACYRBSB")
	LargeA = []byte("TACYRBLA")
	LargeB = []byte("TACYRBLB")
	Filler = []byte("TACYRBFC")
)

// Markers are all of them, in the order Kind names them.
var Markers = [][]byte{SmallA, SmallB, LargeA, LargeB, Filler}

// Gen makes the test blocks: marker (8 bytes), the block's index in its file (8), the file's number (8), then
// AES-CTR keystream under the run's key (made in the TD, never sent) with an IV of those three. Every block can be
// made again to compare with what a read returns, so nothing has to be kept in memory.
type Gen struct{ block cipher.Block }

// NewGen takes a 32-byte key.
func NewGen(key []byte) (*Gen, error) {
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return &Gen{block: b}, nil
}

// Block is block idx of file number file with marker m.
func (g *Gen) Block(m []byte, file, idx uint64) []byte {
	b := make([]byte, BlockSize)
	g.fill(b, m, file, idx)
	return b
}

func (g *Gen) fill(b, m []byte, file, idx uint64) {
	copy(b[:8], m)
	binary.BigEndian.PutUint64(b[8:16], idx)
	binary.BigEndian.PutUint64(b[16:24], file)
	// The IV names the block in its first 12 bytes and leaves the last 4 to CTR's counter: blocks' keystreams never
	// overlap (with the index in the counter's bytes, block i+1's stream was block i's shifted by 16 bytes, and ZFS's
	// lz4 compressed the file 20 times, so the markers never reached the disk as they were).
	iv := make([]byte, aes.BlockSize)
	iv[0], iv[1] = m[6], m[7]
	binary.BigEndian.PutUint32(iv[2:6], uint32(file))
	var ib [8]byte
	binary.BigEndian.PutUint64(ib[:], idx)
	copy(iv[6:12], ib[2:]) // the index's low 48 bits
	for i := range b[24:] {
		b[24+i] = 0
	}
	cipher.NewCTR(g.block, iv).XORKeyStream(b[24:], b[24:])
}

// File is n blocks of file number file with marker m, indexes from 0.
func (g *Gen) File(m []byte, file uint64, n int) []byte {
	b := make([]byte, n*BlockSize)
	for i := 0; i < n; i++ {
		g.fill(b[i*BlockSize:(i+1)*BlockSize], m, file, uint64(i))
	}
	return b
}

// Kind names a block by its marker: "small-A", "large-B", "filler", or "" (none of ours).
func Kind(b []byte) string {
	if len(b) < 8 {
		return ""
	}
	for i, m := range Markers {
		if bytes.Equal(b[:8], m) {
			return []string{"small-A", "small-B", "large-A", "large-B", "filler"}[i]
		}
	}
	return ""
}

// Ident is a block's marker kind, file and index as its header says (ok false if it isn't one of ours).
func Ident(b []byte) (kind string, file, idx uint64, ok bool) {
	kind = Kind(b)
	if kind == "" || len(b) < 24 {
		return "", 0, 0, false
	}
	return kind, binary.BigEndian.Uint64(b[16:24]), binary.BigEndian.Uint64(b[8:16]), true
}

// Genuine reports whether b is exactly the block its header names (a stale or edited block isn't).
func (g *Gen) Genuine(b []byte) bool {
	kind, file, idx, ok := Ident(b)
	if !ok || len(b) != BlockSize {
		return false
	}
	return bytes.Equal(b, g.Block(Markers[kindIndex(kind)], file, idx))
}

func kindIndex(kind string) int {
	for i, k := range []string{"small-A", "small-B", "large-A", "large-B", "filler"} {
		if k == kind {
			return i
		}
	}
	return -1
}

// Hit is a test block found on the device's plaintext view.
type Hit struct {
	Off  int64
	Kind string
	File uint64
	Idx  uint64
}

// ScanChunk finds our blocks in buf, read from the device at base. ZFS places blocks on 512-byte boundaries at
// least, so it looks there only. Only the A versions are wanted (the sectors to save): want filters by kind.
func ScanChunk(buf []byte, base int64, want func(kind string) bool) []Hit {
	var out []Hit
	for i := 0; i+24 <= len(buf); i += 512 {
		if !bytes.Equal(buf[i:i+5], []byte("TACYR")) {
			continue
		}
		kind, file, idx, ok := Ident(buf[i : i+24])
		if ok && (want == nil || want(kind)) {
			out = append(out, Hit{Off: base + int64(i), Kind: kind, File: file, Idx: idx})
		}
	}
	return out
}

// Read is what reading one file through ZFS gave, block by block (after the restore, the caches dropped).
type Read struct {
	File   string `json:"file"`
	Blocks int    `json:"blocks"`
	OK     int    `json:"ok"`      // the block the file should hold (its B or filler content)
	StaleA int    `json:"stale_a"` // an A block, intact: the old data read back without an error (the finding)
	Errors int    `json:"errors"`  // the read failed (ZFS: checksum, EIO)
	Other  int    `json:"other"`   // anything else (neither the right block nor an A one)
	// The blocks whose sector the host rolled back, by what reading them gave.
	Restored       int    `json:"restored"`
	RestoredErrors int    `json:"restored_errors"`
	RestoredOK     int    `json:"restored_ok"` // the right content: served from a cache, not the disk
	RestoredStale  int    `json:"restored_stale"`
	FirstErr       string `json:"first_err,omitempty"`
}

// Location is a saved A sector, what was there just before the restore and what the plaintext view read after it.
type Location struct {
	Plain    int64  `json:"plain"` // offset on the dm-crypt device (the vdev); the raw offset adds the LUKS data offset
	Was      string `json:"was"`   // the A block saved: "large-A 0/17"
	Now      string `json:"now"`   // before the restore: "free (A still there)", "large-B 0/5", "filler 3/77", "other"
	Restored bool   `json:"restored"`
	// After the restore the plaintext view reads A's block exactly: XTS gave the old plaintext back, not garbage.
	OldPlaintextBack bool `json:"old_plaintext_back"`
}

// MetaBlock is a live ZFS metadata block (zdb) whose sector the check had saved earlier, rolled back.
type MetaBlock struct {
	Object   string `json:"object"` // zdb's object number ("0": the dnode blocks)
	Level    int    `json:"level"`
	Copy     int    `json:"copy"` // which DVA
	Plain    int64  `json:"plain"`
	Size     int64  `json:"size"`
	Restored bool   `json:"restored"`
	What     string `json:"what"` // "old metadata" (an earlier version of a metadata block) or "A data over metadata"
}

// Result is the "rollback" message's body.
type Result struct {
	Pool          string      `json:"pool"`
	Dataset       string      `json:"dataset"`
	DatasetProps  string      `json:"dataset_props"`
	Crypt         string      `json:"crypt"`
	DataOffset    int64       `json:"data_offset_bytes"`
	Zdb           string      `json:"zdb"` // "yes" or why not
	Tunables      string      `json:"tunables"`
	SavedSmall    int         `json:"saved_small"`
	SavedLarge    int         `json:"saved_large"`
	ZdbMatch      string      `json:"zdb_match,omitempty"` // zdb's DVAs against the marker scan
	FillerMiB     int         `json:"filler_mib"`
	Rounds        int         `json:"rounds"`
	Reused        int         `json:"reused"` // saved sectors that now hold one of our live blocks
	ReusedOther   int         `json:"reused_other"`
	Restored      int         `json:"restored"`
	OldPlainBack  int         `json:"old_plaintext_back"`
	Locations     []Location  `json:"locations"` // the reused ones (and a few still-free ones)
	Meta          []MetaBlock `json:"meta,omitempty"`
	SmallRewrites int         `json:"small_rewrites"` // times small.bin was written again for ZFS to reuse A's sector
	WalkFiles     int         `json:"walk_files"`     // every file of the dataset read after the restore
	WalkErrors    []string    `json:"walk_errors,omitempty"`
	Reads         []Read      `json:"reads"`
	Scrub         string      `json:"scrub"`
	ScrubCksum    int64       `json:"scrub_cksum"`
	ErrorFiles    []string    `json:"error_files"`
	ReadsAfter    []Read      `json:"reads_after_scrub"`
	Steps         []string    `json:"steps"`
	Error         string      `json:"error,omitempty"`
}

// Verdict judges a rollback result.
//   - FINDING: a read through ZFS returned an A block (old data) without an error.
//   - INCONCLUSIVE: no live block was rolled back (ZFS reused none of the saved sectors), or the restore didn't put
//     the old plaintext back, so nothing was tested.
//   - FAIL: a rolled-back block read back as the right data (a cache answered, so the disk wasn't tested), or the
//     scrub didn't see it.
//   - PASS: every rolled-back live block failed its read, none returned old data, and the scrub counted checksum
//     errors.
func Verdict(r *Result) (string, string) {
	stale, restored, rerr, rok := 0, 0, 0, 0
	for _, rd := range append(append([]Read{}, r.Reads...), r.ReadsAfter...) {
		stale += rd.StaleA
	}
	for _, rd := range r.Reads {
		restored += rd.Restored
		rerr += rd.RestoredErrors
		rok += rd.RestoredOK
	}
	switch {
	case stale > 0:
		return "FINDING", fmt.Sprintf("SILENT ROLLBACK: %d block(s) read back as the old version A with no error", stale)
	case r.Error != "" && r.Restored == 0:
		return "INCONCLUSIVE", "error before any rollback: " + r.Error
	case r.Restored == 0 || restored == 0:
		return "INCONCLUSIVE", fmt.Sprintf("no live block was rolled back (%d saved sectors reused by our data, %d by others)", r.Reused, r.ReusedOther)
	case r.OldPlainBack < r.Restored:
		return "INCONCLUSIVE", fmt.Sprintf("only %d of %d restored sectors decrypt to the old plaintext", r.OldPlainBack, r.Restored)
	case rok > 0:
		return "FAIL", fmt.Sprintf("%d rolled-back block(s) read as the right data: a cache answered, the disk wasn't read", rok)
	case rerr < restored:
		return "FAIL", fmt.Sprintf("only %d of %d rolled-back blocks failed their read", rerr, restored)
	case r.ScrubCksum == 0:
		return "FAIL", "the scrub counted no checksum error"
	}
	return "PASS", fmt.Sprintf("%d live blocks rolled back (old plaintext under them: %d of %d); every read of them failed (%d of %d), 0 returned old data; scrub CKSUM %d, %d file(s) with permanent errors",
		restored, r.OldPlainBack, r.Restored, rerr, restored, r.ScrubCksum, len(r.ErrorFiles))
}

// DVA is one copy of a block as zdb prints it: vdev, offset in the vdev's allocatable space, allocated size.
type DVA struct {
	Vdev  int
	Off   int64
	ASize int64
}

// ZBlock is a line of zdb's "Indirect blocks" listing.
type ZBlock struct {
	FileOff int64
	Level   int
	DVAs    []DVA
	LSize   int64 // logical size (the file range an L0 block covers)
}

// ObjBlock is a ZBlock of one object of a whole-dataset listing.
type ObjBlock struct {
	Object string
	ZBlock
}

var (
	reZLine = regexp.MustCompile(`^\s*([0-9a-f]+)\s+L(\d+)\s+((?:\d+:[0-9a-f]+:[0-9a-f]+\s+)+)`)
	reDVA   = regexp.MustCompile(`(\d+):([0-9a-f]+):([0-9a-f]+)`)
	reLSize = regexp.MustCompile(`\s([0-9a-f]+)L/([0-9a-f]+)P\s`)
	reObj   = regexp.MustCompile(`^\s+(\d+)\s+(\d+)\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+[\d.]+\s+\S`)
)

// ParseZdbAll reads `zdb -ddddd <dataset>` (every object): each block line with the object it belongs to (the
// last object row above it).
func ParseZdbAll(out string) []ObjBlock {
	var bl []ObjBlock
	obj := ""
	for _, ln := range strings.Split(out, "\n") {
		if m := reObj.FindStringSubmatch(ln); m != nil && !reZLine.MatchString(ln) {
			obj = m[1]
			continue
		}
		if obj == "" {
			continue
		}
		for _, b := range ParseZdb(ln) {
			bl = append(bl, ObjBlock{Object: obj, ZBlock: b})
		}
	}
	return bl
}

// Covers reports whether one of b's copies covers [off, off+n) on the device, and which.
func (b ZBlock) Covers(off, n int64) (int, bool) {
	for i, v := range b.DVAs {
		start := v.Off + LabelStart
		if off < start+v.ASize && start < off+n {
			return i, true
		}
	}
	return 0, false
}

// ParseZdb reads the block lines of `zdb -ddddd <dataset> <object>`:
//
//	0 L1  0:1c9a000:2000 0:5c9a000:2000 20000L/2000P F=64 B=91/91 cksum=…
//	0  L0 0:1a00000:20000 20000L/20000P F=1 B=91/91 cksum=…
func ParseZdb(out string) []ZBlock {
	var bl []ZBlock
	for _, ln := range strings.Split(out, "\n") {
		m := reZLine.FindStringSubmatch(ln)
		if m == nil {
			continue
		}
		off, err1 := strconv.ParseInt(m[1], 16, 64)
		lvl, err2 := strconv.Atoi(m[2])
		if err1 != nil || err2 != nil {
			continue
		}
		b := ZBlock{FileOff: off, Level: lvl}
		for _, d := range reDVA.FindAllStringSubmatch(m[3], -1) {
			v, _ := strconv.Atoi(d[1])
			o, err1 := strconv.ParseInt(d[2], 16, 64)
			a, err2 := strconv.ParseInt(d[3], 16, 64)
			if err1 == nil && err2 == nil {
				b.DVAs = append(b.DVAs, DVA{Vdev: v, Off: o, ASize: a})
			}
		}
		if l := reLSize.FindStringSubmatch(ln); l != nil {
			b.LSize, _ = strconv.ParseInt(l[1], 16, 64)
		}
		bl = append(bl, b)
	}
	return bl
}

// LabelStart is where a vdev's allocatable space begins: two 256 KiB labels and the 3.5 MiB boot area. A DVA's
// offset plus this is the offset on the vdev's device.
const LabelStart = 4 << 20

var reCksumRow = regexp.MustCompile(`(?m)^\s+(\S+)\s+(ONLINE|DEGRADED|FAULTED|UNAVAIL)\s+(\d+)\s+(\d+)\s+(\d+)`)

// ParseStatus reads `zpool status -vp`: the largest CKSUM count of a vdev row and the files listed under the
// permanent errors (every indented line after that heading).
func ParseStatus(out string) (cksum int64, files []string) {
	for _, m := range reCksumRow.FindAllStringSubmatch(out, -1) {
		if n, err := strconv.ParseInt(m[5], 10, 64); err == nil && n > cksum {
			cksum = n
		}
	}
	if i := strings.Index(out, "Permanent errors"); i >= 0 {
		rest := out[i:]
		if j := strings.IndexByte(rest, '\n'); j >= 0 {
			for _, ln := range strings.Split(rest[j+1:], "\n") {
				if t := strings.TrimSpace(ln); t != "" && ln != t {
					files = append(files, t)
				} else if t != "" {
					break
				}
			}
		}
	}
	return
}
