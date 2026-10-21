package storedfiles

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	"unicode/utf8"

	"github.com/tacyhq/tacy/proto"
)

// ReadFunc reads stored bytes [from, to) of an object (a ranged GET; the whole object is [0, ObjectBytes)).
type ReadFunc func(ctx context.Context, from, to int64) ([]byte, error)

// ErrChunk: a chunk didn't open (tampered, moved, from another object or file, or a wrong key). The message never
// names more than the chunk's number.
var ErrChunk = errors.New("storedfiles: a chunk didn't decrypt (tampered, moved, from another file, or a wrong key)")

// Errors of the plaintext's frame.
var (
	ErrLength  = errors.New("storedfiles: the object's length doesn't match its file")
	ErrPadding = errors.New("storedfiles: bad padding")
	ErrShort   = errors.New("storedfiles: the store returned the wrong number of bytes")
)

func aeadOf(key []byte) (cipher.AEAD, error) {
	if len(key) != keyBytes {
		return nil, errors.New("storedfiles: bad key")
	}
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(b)
}

// OpenChunk opens chunk index of f's object (sealed: IV ‖ ciphertext ‖ tag, exactly its length).
func OpenChunk(aead cipher.AEAD, f *proto.StoredFile, index int64, sealed []byte) ([]byte, error) {
	n := ChunksOf(f.Padded)
	if index < 0 || index >= n {
		return nil, ErrBadSize
	}
	if int64(len(sealed)) != ChunkPlainBytes(f.Padded, index)+ChunkOverhead {
		return nil, ErrShort
	}
	pt, err := aead.Open(nil, sealed[:IVBytes], sealed[IVBytes:], ChunkAAD(f.File, f.Object, f.Epoch, index, index == n-1))
	if err != nil {
		return nil, fmt.Errorf("%w (chunk %d)", ErrChunk, index)
	}
	return pt, nil
}

// Decrypt reads file bytes [start, end) of f's object through read, chunk by chunk, checking every chunk's binding,
// the length prefix against f.Size whenever chunk 0 is read, and that the padding is zeros: the browser's
// decryptRange (crypto.ts). A whole-file read (0, f.Size) reads every chunk, the final one included, so a dropped or
// added tail is caught; a range reads only the chunks that hold it (each is authenticated on its own). f must have
// passed Check.
func Decrypt(ctx context.Context, f *proto.StoredFile, read ReadFunc, start, end int64) ([]byte, error) {
	if p, err := PaddedFor(f.Size); err != nil || p != f.Padded {
		return nil, ErrBadSize
	}
	if start < 0 || end < start || end > f.Size {
		return nil, ErrBadSize
	}
	if end == start {
		return []byte{}, nil
	}
	aead, err := aeadOf(f.Key)
	if err != nil {
		return nil, err
	}
	a, b := start+LengthPrefixBytes, end+LengthPrefixBytes
	fileEnd := f.Size + LengthPrefixBytes
	first, last := a/ChunkBytes, (b-1)/ChunkBytes
	if start == 0 && end == f.Size {
		last = ChunksOf(f.Padded) - 1
	}
	out := make([]byte, 0, end-start)
	for i := first; i <= last; i += PartChunks {
		j := min(last, i+PartChunks-1)
		from := i * SealedChunkBytes
		to := j*SealedChunkBytes + ChunkPlainBytes(f.Padded, j) + ChunkOverhead
		got, err := read(ctx, from, to)
		if err != nil {
			return nil, err
		}
		if int64(len(got)) != to-from {
			return nil, ErrShort
		}
		for k := i; k <= j; k++ {
			off := (k - i) * SealedChunkBytes
			plain, err := OpenChunk(aead, f, k, got[off:off+ChunkPlainBytes(f.Padded, k)+ChunkOverhead])
			if err != nil {
				return nil, err
			}
			base := k * ChunkBytes
			if k == 0 && binary.BigEndian.Uint64(plain[:LengthPrefixBytes]) != uint64(f.Size) {
				return nil, ErrLength
			}
			for x := max(fileEnd, base); x < base+int64(len(plain)); x++ {
				if plain[x-base] != 0 {
					return nil, ErrPadding
				}
			}
			s, e := max(a, base)-base, min(b, base+int64(len(plain)))-base
			if e > s {
				out = append(out, plain[s:e]...)
			}
			clear(plain)
		}
		clear(got)
	}
	return out, nil
}

// ErrNotText: the file's bytes aren't UTF-8 text (an image, an archive, a binary): the agent can't read it.
var ErrNotText = errors.New("storedfiles: not a text file")

// ErrEmpty: the file has no bytes.
var ErrEmpty = errors.New("storedfiles: the file is empty")

// OpenText reads f's text from its start, at most maxBytes of it (a range read of the chunks that hold them), and
// checks it is UTF-8 text without NUL bytes. truncated: the file is longer; the text then ends at the last whole
// character before maxBytes.
func OpenText(ctx context.Context, f *proto.StoredFile, read ReadFunc, maxBytes int64) (text string, truncated bool, err error) {
	if f.Size == 0 {
		return "", false, ErrEmpty
	}
	end := min(f.Size, maxBytes)
	if end <= 0 {
		return "", false, ErrBadSize
	}
	b, err := Decrypt(ctx, f, read, 0, end)
	if err != nil {
		return "", false, err
	}
	truncated = end < f.Size
	if truncated { // cut a character the limit split
		for k := 0; k < utf8.UTFMax && len(b) > 0 && !utf8.Valid(b); k++ {
			r, _ := utf8.DecodeLastRune(b)
			if r != utf8.RuneError {
				break
			}
			b = b[:len(b)-1]
		}
	}
	if !utf8.Valid(b) || containsNUL(b) {
		clear(b)
		return "", false, ErrNotText
	}
	return string(b), truncated, nil
}

func containsNUL(b []byte) bool {
	for _, c := range b {
		if c == 0 {
			return true
		}
	}
	return false
}
