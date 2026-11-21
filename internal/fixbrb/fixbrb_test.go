package fixbrb

import (
	"bytes"
	"compress/flate"
	"strings"
	"testing"
)

func testGen(t *testing.T) *Gen {
	t.Helper()
	g, err := NewGen(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return g
}

// The blocks are made again for every comparison, so they must be the same each time, distinct per marker, file and
// index, and an A block must never pass as its B (the check would miss a silent rollback).
func TestGenBlocks(t *testing.T) {
	g := testGen(t)
	a := g.Block(LargeA, 1, 5)
	if !bytes.Equal(a, g.Block(LargeA, 1, 5)) || !bytes.Equal(a, g.File(LargeA, 1, 8)[5*BlockSize:6*BlockSize]) {
		t.Fatal("not deterministic")
	}
	seen := map[string]bool{}
	for _, m := range Markers {
		for f := uint64(0); f < 3; f++ {
			for i := uint64(0); i < 3; i++ {
				b := g.Block(m, f, i)
				if seen[string(b[24:])] {
					t.Fatalf("keystream repeats for %s %d %d", m, f, i)
				}
				seen[string(b[24:])] = true
				k, bf, bi, ok := Ident(b)
				if !ok || bf != f || bi != i || Markers[kindIndex(k)] == nil || !bytes.Equal(Markers[kindIndex(k)], m) || !g.Genuine(b) {
					t.Fatalf("ident %s %d %d: %s %d %d %v", m, f, i, k, bf, bi, ok)
				}
			}
		}
	}
	// One byte changed, or the right header over another block's body: not genuine.
	b := g.Block(LargeB, 1, 5)
	b[100] ^= 1
	if g.Genuine(b) {
		t.Fatal("an edited block passed")
	}
	mixed := append(append([]byte{}, g.Block(LargeB, 1, 5)[:24]...), a[24:]...)
	if g.Genuine(mixed) {
		t.Fatal("B's header over A's body passed")
	}
	other, _ := NewGen(bytes.Repeat([]byte{8}, 32))
	if other.Genuine(a) {
		t.Fatal("another run's key accepted the block")
	}
	if Kind([]byte("short")) != "" || Kind(make([]byte, BlockSize)) != "" {
		t.Fatal("kind of a non-block")
	}
}

func TestScanChunk(t *testing.T) {
	g := testGen(t)
	buf := make([]byte, 64<<10)
	copy(buf[4096:], g.Block(SmallA, 0, 0))
	copy(buf[8192+512:], g.Block(LargeA, 1, 9)) // 512-aligned, not 4K
	copy(buf[16384:], g.Block(LargeB, 1, 2))
	copy(buf[20000:], g.Block(LargeA, 1, 3)) // not on a sector boundary: ZFS never puts a block there
	hits := ScanChunk(buf, 1<<30, func(k string) bool { return strings.HasSuffix(k, "-A") })
	if len(hits) != 2 || hits[0] != (Hit{Off: 1<<30 + 4096, Kind: "small-A", File: 0, Idx: 0}) ||
		hits[1] != (Hit{Off: 1<<30 + 8704, Kind: "large-A", File: 1, Idx: 9}) {
		t.Fatalf("%+v", hits)
	}
	if all := ScanChunk(buf, 0, nil); len(all) != 3 {
		t.Fatalf("all: %+v", all)
	}
}

func TestParseZdb(t *testing.T) {
	out := `Indirect blocks:
               0 L1  0:1c9a000:2000 0:5c9a000:2000 20000L/2000P F=64 B=91/91 cksum=0123
               0  L0 0:1a00000:20000 20000L/20000P F=1 B=91/91 cksum=4567
           20000  L0 0:1a20000:20000 20000L/20000P F=1 B=91/91 cksum=89ab
		segment [0000000000000000, 0000000000800000) size 8M`
	bl := ParseZdb(out)
	if len(bl) != 3 || bl[0].Level != 1 || len(bl[0].DVAs) != 2 || bl[0].DVAs[1] != (DVA{0, 0x5c9a000, 0x2000}) ||
		bl[2].FileOff != 0x20000 || bl[2].Level != 0 || bl[2].DVAs[0] != (DVA{0, 0x1a20000, 0x20000}) {
		t.Fatalf("%+v", bl)
	}
}

func TestParseStatus(t *testing.T) {
	out := `  pool: dstack
 state: ONLINE
status: One or more devices has experienced an error resulting in data
	corruption.  Applications may be affected.
  scan: scrub repaired 0B in 00:00:03 with 3 errors on Fri Nov 21 03:10:00 2026
config:
	NAME                          STATE     READ WRITE CKSUM
	dstack                        ONLINE       0     0     0
	  dm-uuid-CRYPT-LUKS2-abc     ONLINE       0     0    12
errors: Permanent errors have been detected in the following files:
        /run/tacy-e2e/rb/large.bin
        dstack/tacy-rb:/filler-3.bin
        <metadata>:<0x83>`
	ck, files := ParseStatus(out)
	if ck != 12 || len(files) != 3 || files[0] != "/run/tacy-e2e/rb/large.bin" || files[2] != "<metadata>:<0x83>" {
		t.Fatalf("%d %q", ck, files)
	}
	if ck, files := ParseStatus("errors: No known data errors\n\tdstack ONLINE 0 0 0\n"); ck != 0 || files != nil {
		t.Fatalf("clean: %d %q", ck, files)
	}
}

func TestVerdict(t *testing.T) {
	pass := func() *Result {
		return &Result{Reused: 40, Restored: 40, OldPlainBack: 40, ScrubCksum: 3, ErrorFiles: []string{"/x/large.bin"},
			Reads:      []Read{{File: "large.bin", Blocks: 2048, OK: 2000, Errors: 48, Restored: 40, RestoredErrors: 40}},
			ReadsAfter: []Read{{File: "large.bin", Blocks: 2048, OK: 2000, Errors: 48}}}
	}
	for _, c := range []struct {
		name string
		edit func(*Result)
		want string
	}{
		{"every rolled-back block errors", func(*Result) {}, "PASS"},
		{"old data read back", func(r *Result) { r.Reads[0].StaleA, r.Reads[0].RestoredStale, r.Reads[0].RestoredErrors = 1, 1, 39 }, "FINDING"},
		{"old data after the scrub", func(r *Result) { r.ReadsAfter[0].StaleA = 2 }, "FINDING"},
		{"no reuse", func(r *Result) { r.Reused, r.Restored, r.Reads[0].Restored, r.Reads[0].RestoredErrors = 0, 0, 0, 0 }, "INCONCLUSIVE"},
		{"old plaintext not back", func(r *Result) { r.OldPlainBack = 10 }, "INCONCLUSIVE"},
		{"a cache answered", func(r *Result) { r.Reads[0].RestoredOK, r.Reads[0].RestoredErrors = 1, 39 }, "FAIL"},
		{"a block read as something else", func(r *Result) { r.Reads[0].RestoredErrors = 39 }, "FAIL"},
		{"scrub saw nothing", func(r *Result) { r.ScrubCksum = 0 }, "FAIL"},
		{"error before the rollback", func(r *Result) { *r = Result{Error: "no ZFS pool"} }, "INCONCLUSIVE"},
	} {
		r := pass()
		c.edit(r)
		if got, detail := Verdict(r); got != c.want {
			t.Errorf("%s: %s (%s), want %s", c.name, got, detail, c.want)
		}
	}
}

// The blocks must be incompressible as a record: ZFS compresses what it can (lz4 on the box), and a compressed
// record holds no marker on the disk to find.
func TestGenIncompressible(t *testing.T) {
	g := testGen(t)
	for _, m := range Markers {
		b := g.File(m, 1, 32) // one 128 KiB record
		var o bytes.Buffer
		w, _ := flate.NewWriter(&o, flate.BestCompression)
		w.Write(b)
		w.Close()
		if o.Len() < len(b)*99/100 {
			t.Fatalf("%s: a record compresses to %d of %d bytes", m, o.Len(), len(b))
		}
	}
}

// A whole-dataset listing: each block line under the object row above it; Covers finds the copy over a sector.
func TestParseZdbAll(t *testing.T) {
	out := `Dataset dstack/tacy-rb [ZPL], ID 110, cr_txg 66, 8.04M, 8 objects

    Object  lvl   iblk   dblk  dsize  dnsize  lsize   %full  type
         0    6   128K    16K    13K     512    32K    9.38  DMU dnode
Indirect blocks:
               0 L5  0:a5b5c200:200 0:20183000:200 20000L/200P F=8 B=91/91 cksum=1
               0  L0 0:a5b40000:1000 0:2014a000:1000 4000L/1000P F=8 B=91/91 cksum=2

    Object  lvl   iblk   dblk  dsize  dnsize  lsize   %full  type
         3    2   128K   128K  8.01M     512     8M  100.00  ZFS plain file
                                               176   bonus  System attributes
Indirect blocks:
               0 L1  0:1c9a000:2000 0:5c9a000:2000 20000L/2000P F=64 B=91/91 cksum=3
           20000  L0 0:1a20000:20000 20000L/20000P F=1 B=91/91 cksum=4`
	bl := ParseZdbAll(out)
	if len(bl) != 4 || bl[0].Object != "0" || bl[1].Object != "0" || bl[1].LSize != 0x4000 || bl[2].Object != "3" || bl[2].Level != 1 ||
		bl[3].Object != "3" || bl[3].FileOff != 0x20000 || bl[3].LSize != 0x20000 {
		t.Fatalf("%+v", bl)
	}
	// The L0 record spans 0x1a20000+4 MiB .. +128 KiB on the device: a sector 512 bytes into it, or straddling its
	// start, is covered; one just past its end isn't.
	base := int64(0x1a20000 + LabelStart)
	for _, c := range []struct {
		off  int64
		want bool
	}{{base + 512, true}, {base - 2048, true}, {base + 0x20000, false}, {base - 4096, false}} {
		if _, ok := bl[3].Covers(c.off, BlockSize); ok != c.want {
			t.Errorf("covers %x: %v", c.off, ok)
		}
	}
	if c, ok := bl[2].Covers(0x5c9a000+LabelStart, BlockSize); !ok || c != 1 {
		t.Fatalf("second copy: %d %v", c, ok)
	}
}
