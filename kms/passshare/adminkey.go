package passshare

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strings"
)

// An admin key file (kmsctl keygen-admin): the Ed25519 seed wrapped under a passphrase like a share, so no admin key
// is ever written in the clear (one stolen laptop file is not a signature). Version 1:
//
//	"TKA1" ‖ argon2id time (1) ‖ log2 memory KiB (1) ‖ threads (1) ‖ salt (16) ‖ public key (32) ‖ nonce (12)
//	‖ AES-256-GCM(Argon2id(passphrase, salt, ...), nonce, seed, aad = the bytes before the nonce)
//
// armored as base64 between the AdminKeyBegin and AdminKeyEnd lines. The public key is in the clear (and in the AAD),
// so kmsctl can say which key a file is before asking for its passphrase.

const adminMagic = "TKA1"

// Armor lines of an admin key file.
const (
	AdminKeyBegin = "-----BEGIN TACY KMS ADMIN KEY-----"
	AdminKeyEnd   = "-----END TACY KMS ADMIN KEY-----"
)

// ErrNotAdminKey: the text isn't a wrapped admin key.
var ErrNotAdminKey = errors.New("passshare: not a wrapped admin key")

// WrapAdminKey wraps key's seed under pass: the file's text.
func WrapAdminKey(pass []byte, key ed25519.PrivateKey, p Params) (string, error) {
	if err := p.check(); err != nil {
		return "", err
	}
	if len([]rune(string(pass))) < MinPassphrase {
		return "", errors.New("passshare: the passphrase is too short")
	}
	var salt [16]byte
	var nonce [12]byte
	rand.Read(salt[:])
	rand.Read(nonce[:])
	head := append([]byte(adminMagic), p.Time, p.MemLog2, p.Threads)
	head = append(head, salt[:]...)
	head = append(head, key.Public().(ed25519.PublicKey)...)
	k := p.key(pass, salt[:])
	defer clear(k)
	g, err := gcm(k)
	if err != nil {
		return "", err
	}
	seed := key.Seed()
	defer clear(seed)
	blob := append(append(bytes.Clone(head), nonce[:]...), g.Seal(nil, nonce[:], seed, head)...)
	return AdminKeyBegin + "\n" + base64.StdEncoding.EncodeToString(blob) + "\n" + AdminKeyEnd + "\n", nil
}

// AdminKeyPublic reads a wrapped admin key file's public key without its passphrase.
func AdminKeyPublic(text string) (ed25519.PublicKey, error) {
	b, err := adminBlob(text)
	if err != nil {
		return nil, err
	}
	return ed25519.PublicKey(bytes.Clone(b[len(adminMagic)+3+16 : len(adminMagic)+3+16+32])), nil
}

// IsAdminKey says whether text is a wrapped admin key file.
func IsAdminKey(text string) bool { _, err := adminBlob(text); return err == nil }

func adminBlob(text string) ([]byte, error) {
	t := strings.TrimSpace(text)
	body, ok := strings.CutPrefix(t, AdminKeyBegin)
	if !ok {
		return nil, ErrNotAdminKey
	}
	body, ok = strings.CutSuffix(strings.TrimSpace(body), AdminKeyEnd)
	if !ok {
		return nil, ErrNotAdminKey
	}
	b, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(body), ""))
	h := len(adminMagic) + 3 + 16 + 32
	if err != nil || len(b) != h+12+32+16 || string(b[:len(adminMagic)]) != adminMagic {
		return nil, ErrNotAdminKey
	}
	return b, nil
}

// OpenAdminKey unwraps a wrapped admin key file with its passphrase.
func OpenAdminKey(text string, pass []byte) (ed25519.PrivateKey, error) {
	b, err := adminBlob(text)
	if err != nil {
		return nil, err
	}
	p := Params{Time: b[4], MemLog2: b[5], Threads: b[6]}
	if err := p.check(); err != nil {
		return nil, err
	}
	h := len(adminMagic) + 3 + 16 + 32
	k := p.key(pass, b[7:7+16])
	defer clear(k)
	g, err := gcm(k)
	if err != nil {
		return nil, err
	}
	seed, err := g.Open(nil, b[h:h+12], b[h+12:], b[:h])
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, ErrPassphrase
	}
	defer clear(seed)
	key := ed25519.NewKeyFromSeed(seed)
	if !bytes.Equal(key.Public().(ed25519.PublicKey), b[h-32:h]) {
		return nil, ErrPassphrase
	}
	return key, nil
}
