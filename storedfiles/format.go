// Package storedfiles reads the person's encrypted stored files inside the VM: the objects a run (or a
// schedule's runs) was given, each with its own key, fetched as ciphertext from R2 and checked chunk by chunk exactly
// as the browser checks them (the chat's src/client/storage/crypto.ts decryptRange; the layout is
// src/shared/file-format.ts; both replay test/golden/v2-files.json, of which testdata/v2-files.json is a copy the
// chat's tests require to be identical). Shipped in v0.17.0.
//
// A stored object is one version of one file, or the text the browser extracted from a PDF or Office file at upload:
//
//	object    = chunk 0 ‖ chunk 1 ‖ … ‖ chunk n-1
//	chunk i   = IV (12) ‖ AES-256-GCM(object key, IV, AAD) of plaintext[i·1 MiB, (i+1)·1 MiB) ‖ tag (16)
//	AAD       = "tacy/v2/file-chunk" ‖ 0 ‖ file ‖ 0 ‖ object ‖ 0 ‖ 2 ‖ 0 ‖ 1 ‖ 0 ‖ epoch ‖ 0 ‖ i ‖ 0 ‖ last (1 | 0)
//	plaintext = u64 BE length of the file ‖ its bytes ‖ zeros up to the padded size
//
// So a chunk can't move to another position, object or file; a dropped tail leaves a final chunk marked not last; the
// length prefix is checked against the size the browser named (from the file's node record), and the padding must be
// zeros. Nothing here keeps plaintext anywhere but the slices it returns: the guard holds them in memory for the task
// and drops them when it ends.
package storedfiles

import (
	"errors"
	"strconv"
	"strings"
)

// The layout's constants (file-format.ts).
const (
	ChunkBytes        = 1 << 20
	IVBytes           = 12
	TagBytes          = 16
	ChunkOverhead     = IVBytes + TagBytes
	SealedChunkBytes  = ChunkBytes + ChunkOverhead
	LengthPrefixBytes = 8
	MinPaddedBytes    = 64 * 1024
	// PartChunks: a read fetches at most this many chunks at once (8 MiB and a little), as the browser reads.
	PartChunks = 8
	// MaxFileBytes is the most one stored file may have (a placeholder).
	MaxFileBytes = 100 * 1024 * 1024
	// ChunkLabel starts every chunk's AAD.
	ChunkLabel = "tacy/v2/file-chunk"
	// MaxEpoch is the largest key epoch (envelope.ts MAX_EPOCH).
	MaxEpoch = 0xffffffff

	formatV2   = 2
	algAESGCM  = 1
	maxPadding = MaxFileBytes + LengthPrefixBytes
)

// The limits on what one run may read (by design: an agent run 200 files / 200 MB), counted on stored (ciphertext) bytes,
// the same numbers the Worker checks before it mints read URLs (FILE_LIMITS.agentRunFiles, agentRunBytes).
const (
	MaxRunFiles = 200
	MaxRunBytes = 200 * 1024 * 1024
)

// ErrBadSize: a size or range that doesn't fit the layout.
var ErrBadSize = errors.New("storedfiles: bad size or range")

// PaddedSize is the padded plaintext size for n bytes (the length prefix included): 64 KiB, 128 KiB, … 1 MiB, then
// whole MiB.
func PaddedSize(n int64) (int64, error) {
	if n < 0 || n > maxPadding {
		return 0, ErrBadSize
	}
	if n <= MinPaddedBytes {
		return MinPaddedBytes, nil
	}
	if n <= ChunkBytes {
		s := int64(MinPaddedBytes)
		for s < n {
			s *= 2
		}
		return s, nil
	}
	return (n + ChunkBytes - 1) / ChunkBytes * ChunkBytes, nil
}

// PaddedFor is the padded size of a file of size bytes.
func PaddedFor(size int64) (int64, error) {
	if size < 0 || size > MaxFileBytes {
		return 0, ErrBadSize
	}
	return PaddedSize(size + LengthPrefixBytes)
}

// ChunksOf is how many chunks an object of padded size padded has.
func ChunksOf(padded int64) int64 { return (padded + ChunkBytes - 1) / ChunkBytes }

// ObjectBytes is the stored (ciphertext) size of an object of padded size padded: what is metered and fetched.
func ObjectBytes(padded int64) int64 { return padded + ChunksOf(padded)*ChunkOverhead }

// ChunkPlainBytes is the plaintext bytes in chunk i.
func ChunkPlainBytes(padded, i int64) int64 {
	if i < ChunksOf(padded)-1 {
		return ChunkBytes
	}
	return padded - (ChunksOf(padded)-1)*ChunkBytes
}

// ChunkAAD is chunk index's AAD (see the package doc).
func ChunkAAD(file, object string, epoch int, index int64, last bool) []byte {
	l := "0"
	if last {
		l = "1"
	}
	return []byte(strings.Join([]string{ChunkLabel, file, object, strconv.Itoa(formatV2), strconv.Itoa(algAESGCM),
		strconv.Itoa(epoch), strconv.FormatInt(index, 10), l}, "\x00"))
}

// ObjectKey is an object's key in the bucket: f/<owner>/<object>.
func ObjectKey(owner, object string) string { return "f/" + owner + "/" + object }
