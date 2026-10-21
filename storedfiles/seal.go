package storedfiles

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
)

// Encrypt makes a stored object the way the browser does (crypto.ts encryptParts): data padded and cut into chunks,
// each sealed under key with its AAD. iv gives chunk i's IV (nil: random). For tests, labs and cmd/e2e's stand-in
// store only: the VM never writes stored files.
func Encrypt(key []byte, file, object string, epoch int, data []byte, iv func(i int64) []byte) (sealed []byte, padded int64, err error) {
	padded, err = PaddedFor(int64(len(data)))
	if err != nil {
		return nil, 0, err
	}
	aead, err := aeadOf(key)
	if err != nil {
		return nil, 0, err
	}
	plain := make([]byte, padded)
	binary.BigEndian.PutUint64(plain, uint64(len(data)))
	copy(plain[LengthPrefixBytes:], data)
	n := ChunksOf(padded)
	out := make([]byte, 0, ObjectBytes(padded))
	for i := range n {
		nonce := make([]byte, IVBytes)
		if iv != nil {
			nonce = iv(i)
			if len(nonce) != IVBytes {
				return nil, 0, errors.New("storedfiles: bad IV")
			}
		} else if _, err := rand.Read(nonce); err != nil {
			return nil, 0, err
		}
		chunk := plain[i*ChunkBytes : i*ChunkBytes+ChunkPlainBytes(padded, i)]
		out = append(out, nonce...)
		out = aead.Seal(out, nonce, chunk, ChunkAAD(file, object, epoch, i, i == n-1))
	}
	return out, padded, nil
}
