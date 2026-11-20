// Package passshare is a passphrase-protected key service share (kmsctl's "pass:" recipients;
// no hardware keys for now). Genesis seals each share in the key service's TD to a P-256 recipient (kms.SealedShare,
// unchanged); for a pass recipient kmsctl makes that P-256 key in memory just before the genesis and keeps it only
// wrapped under a key derived from the share holder's passphrase (Argon2id, high cost). The result is one short
// binary blob per share, printed as text: armored base64 (a password manager, a file on a USB drive) or a paper
// encoding of base32 lines, each with its own checksum. Neither the passphrase nor the share, nor the P-256 key in
// the clear, is ever written anywhere. Unlocking needs the blob and its passphrase; a wrong passphrase (or a damaged
// blob) fails before anything is sent. Hardware keys can come later by re-issuing shares to P-256 recipients.
//
// Blob, version 1 (integers big-endian):
//
//	"TKS1" ‖ index (1) ‖ epoch (4) ‖ KMS id (32) ‖ argon2id time (1) ‖ log2 memory KiB (1) ‖ threads (1) ‖ salt (16)
//	‖ nonce (12) ‖ wrapped P-256 scalar (32 + 16) ‖ len(enc) (1) ‖ enc ‖ len(ct) (2) ‖ ct ‖ sha256(all before)[:4]
//
// wrapped = AES-256-GCM(Argon2id(passphrase, salt, time, memory, threads, 32), nonce, scalar, aad = the bytes before
// the nonce); enc and ct are the share's HPKE ciphertext to that P-256 key (kms.SealedShare).
package passshare

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"

	"github.com/tacyhq/tacy/kms"
)

// Params are Argon2id's costs.
type Params struct {
	Time    uint8
	MemLog2 uint8 // memory = 1 << MemLog2 KiB
	Threads uint8
}

// Default is the cost kmsctl uses: 1 GiB, 4 passes, 4 lanes (a few seconds on a laptop, per share, at genesis and
// at each unlock).
var Default = Params{Time: 4, MemLog2: 20, Threads: 4}

// MinPassphrase is the shortest passphrase kmsctl takes.
const MinPassphrase = 20

const magic = "TKS1"

// Errors.
var (
	ErrPassphrase = errors.New("passshare: wrong passphrase (or the share's text was changed)")
	ErrFormat     = errors.New("passshare: not a passphrase share")
	ErrChecksum   = errors.New("passshare: the share's checksum doesn't match (a mistyped or damaged copy)")
)

// Share is one passphrase-protected share.
type Share struct {
	Index   byte
	Epoch   uint32
	KMSID   ed25519.PublicKey
	Params  Params
	Salt    [16]byte
	Nonce   [12]byte
	Wrapped []byte // the P-256 scalar under the passphrase key (48 bytes)
	Sealed  kms.Sealed
}

func (p Params) check() error {
	if p.Time < 1 || p.Threads < 1 || p.MemLog2 < 3 || p.MemLog2 > 22 {
		return fmt.Errorf("passshare: bad argon2id parameters %+v", p)
	}
	return nil
}

func (p Params) key(pass []byte, salt []byte) []byte {
	return argon2.IDKey(pass, salt, uint32(p.Time), uint32(1)<<p.MemLog2, p.Threads, 32)
}

// header is the blob's bytes before the nonce (the wrap's AAD).
func (s *Share) header() []byte {
	b := []byte(magic)
	b = append(b, s.Index)
	b = binary.BigEndian.AppendUint32(b, s.Epoch)
	b = append(b, s.KMSID...)
	b = append(b, s.Params.Time, s.Params.MemLog2, s.Params.Threads)
	return append(b, s.Salt[:]...)
}

// New wraps recipient's private key under passphrase for the share sh (sealed to that key at genesis).
func New(pass []byte, recipient *ecdh.PrivateKey, sh kms.SealedShare, p Params) (*Share, error) {
	if err := p.check(); err != nil {
		return nil, err
	}
	id, err := kms.ParseID(sh.KMSID)
	if err != nil {
		return nil, err
	}
	if kms.RecipientString(recipient.PublicKey()) != sh.Recipient {
		return nil, errors.New("passshare: the key isn't the share's recipient")
	}
	if len(sh.Enc) > 255 || len(sh.CT) > 65535 {
		return nil, errors.New("passshare: share too large")
	}
	s := &Share{Index: sh.Index, Epoch: sh.Epoch, KMSID: id, Params: p, Sealed: sh.Sealed}
	rand.Read(s.Salt[:])
	rand.Read(s.Nonce[:])
	k := p.key(pass, s.Salt[:])
	defer clear(k)
	g, err := gcm(k)
	if err != nil {
		return nil, err
	}
	scalar := recipient.Bytes()
	defer clear(scalar)
	s.Wrapped = g.Seal(nil, s.Nonce[:], scalar, s.header())
	return s, nil
}

func gcm(k []byte) (cipher.AEAD, error) {
	b, err := aes.NewCipher(k)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(b)
}

// Open unwraps the recipient key with pass and returns it with the share as kmsctl unlock takes it.
func (s *Share) Open(pass []byte) (*ecdh.PrivateKey, kms.SealedShare, error) {
	if err := s.Params.check(); err != nil {
		return nil, kms.SealedShare{}, err
	}
	k := s.Params.key(pass, s.Salt[:])
	defer clear(k)
	g, err := gcm(k)
	if err != nil {
		return nil, kms.SealedShare{}, err
	}
	scalar, err := g.Open(nil, s.Nonce[:], s.Wrapped, s.header())
	if err != nil {
		return nil, kms.SealedShare{}, ErrPassphrase
	}
	defer clear(scalar)
	priv, err := ecdh.P256().NewPrivateKey(scalar)
	if err != nil {
		return nil, kms.SealedShare{}, ErrPassphrase
	}
	return priv, kms.SealedShare{Recipient: kms.RecipientString(priv.PublicKey()), Index: s.Index, Epoch: s.Epoch,
		KMSID: kms.IDString(s.KMSID), Sealed: s.Sealed}, nil
}

// Marshal is the blob.
func (s *Share) Marshal() []byte {
	b := s.header()
	b = append(b, s.Nonce[:]...)
	b = append(b, s.Wrapped...)
	b = append(b, byte(len(s.Sealed.Enc)))
	b = append(b, s.Sealed.Enc...)
	b = binary.BigEndian.AppendUint16(b, uint16(len(s.Sealed.CT)))
	b = append(b, s.Sealed.CT...)
	h := sha256.Sum256(b)
	return append(b, h[:4]...)
}

// Parse reads a blob.
func Parse(b []byte) (*Share, error) {
	const fixed = 4 + 1 + 4 + 32 + 3 + 16 + 12 + 48
	if len(b) < fixed+1+2+4 || string(b[:4]) != magic {
		return nil, ErrFormat
	}
	body, sum := b[:len(b)-4], b[len(b)-4:]
	if h := sha256.Sum256(body); !bytes.Equal(h[:4], sum) {
		return nil, ErrChecksum
	}
	s := &Share{Index: body[4], Epoch: binary.BigEndian.Uint32(body[5:9]), KMSID: ed25519.PublicKey(bytes.Clone(body[9:41])),
		Params: Params{Time: body[41], MemLog2: body[42], Threads: body[43]}}
	copy(s.Salt[:], body[44:60])
	copy(s.Nonce[:], body[60:72])
	s.Wrapped = bytes.Clone(body[72:120])
	rest := body[120:]
	n := int(rest[0])
	if len(rest) < 1+n+2 {
		return nil, ErrFormat
	}
	s.Sealed.Enc = bytes.Clone(rest[1 : 1+n])
	rest = rest[1+n:]
	m := int(binary.BigEndian.Uint16(rest))
	if len(rest) != 2+m {
		return nil, ErrFormat
	}
	s.Sealed.CT = bytes.Clone(rest[2:])
	return s, nil
}

// ---- text encodings ------------------------------------------------------------------------------------------

const (
	armorBegin = "-----BEGIN TACY KMS SHARE-----"
	armorEnd   = "-----END TACY KMS SHARE-----"
	paperTitle = "TACY KMS SHARE"
)

// Armor is the blob as base64 lines between markers, with a comment line naming the share (not secret).
func Armor(s *Share) string {
	enc := base64.StdEncoding.EncodeToString(s.Marshal())
	var b strings.Builder
	b.WriteString(armorBegin + "\n")
	fmt.Fprintf(&b, "Share: %d, epoch %d, KMS %s\n\n", s.Index, s.Epoch, kms.IDString(s.KMSID))
	for len(enc) > 64 {
		b.WriteString(enc[:64] + "\n")
		enc = enc[64:]
	}
	b.WriteString(enc + "\n" + armorEnd + "\n")
	return b.String()
}

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// lineSum is a paper line's checksum: 2 base32 characters of sha256(line number ‖ its characters).
func lineSum(n int, chars string) string {
	h := sha256.Sum256([]byte(strconv.Itoa(n) + ":" + chars))
	return b32.EncodeToString(h[:2])[:2]
}

// Paper is the blob for writing down or printing: numbered lines of base32 (A-Z, 2-7) in groups of four, each line
// ending in a two-character checksum of that line, and a last line with the whole blob's length and checksum. A
// mistyped character is found and its line named before anything is decrypted.
func Paper(s *Share) string {
	raw := s.Marshal()
	enc := b32.EncodeToString(raw)
	var b strings.Builder
	fmt.Fprintf(&b, "%s %d (epoch %d, KMS %s)\n", paperTitle, s.Index, s.Epoch, kms.IDString(s.KMSID))
	for n := 1; len(enc) > 0; n++ {
		w := min(32, len(enc))
		chunk := enc[:w]
		enc = enc[w:]
		var groups []string
		for i := 0; i < len(chunk); i += 4 {
			groups = append(groups, chunk[i:min(i+4, len(chunk))])
		}
		fmt.Fprintf(&b, "%02d  %s  %s\n", n, strings.Join(groups, " "), lineSum(n, chunk))
	}
	h := sha256.Sum256(raw)
	fmt.Fprintf(&b, "END %d %s\n", len(raw), strings.ToUpper(hex.EncodeToString(h[:4])))
	return b.String()
}

// Decode reads a share from Armor's or Paper's text (whitespace and case don't matter on paper; 0, 1 and 8 read as
// O, I and B).
func Decode(text string) (*Share, error) {
	t := strings.TrimSpace(text)
	if strings.HasPrefix(t, armorBegin) {
		end := strings.Index(t, armorEnd)
		if end < 0 {
			return nil, ErrFormat
		}
		var body strings.Builder
		for _, ln := range strings.Split(t[len(armorBegin):end], "\n") {
			ln = strings.TrimSpace(ln)
			if ln == "" || strings.Contains(ln, ":") {
				continue
			}
			body.WriteString(ln)
		}
		raw, err := base64.StdEncoding.DecodeString(body.String())
		if err != nil {
			return nil, ErrFormat
		}
		return Parse(raw)
	}
	if strings.HasPrefix(strings.ToUpper(t), paperTitle) {
		return decodePaper(t)
	}
	return nil, ErrFormat
}

func decodePaper(t string) (*Share, error) {
	fix := strings.NewReplacer("0", "O", "1", "I", "8", "B")
	var enc strings.Builder
	wantLen, wantSum := -1, ""
	n := 0
	for _, ln := range strings.Split(t, "\n")[1:] {
		f := strings.Fields(strings.ToUpper(ln))
		if len(f) == 0 {
			continue
		}
		if f[0] == "END" {
			if len(f) != 3 {
				return nil, ErrFormat
			}
			l, err := strconv.Atoi(f[1])
			if err != nil {
				return nil, ErrFormat
			}
			wantLen, wantSum = l, f[2]
			break
		}
		num, err := strconv.Atoi(f[0])
		if err != nil || len(f) < 3 {
			return nil, ErrFormat
		}
		n++
		if num != n {
			return nil, fmt.Errorf("%w: line %d is missing or out of order", ErrChecksum, n)
		}
		chunk := fix.Replace(strings.Join(f[1:len(f)-1], ""))
		if lineSum(num, chunk) != fix.Replace(f[len(f)-1]) {
			return nil, fmt.Errorf("%w: line %d", ErrChecksum, num)
		}
		enc.WriteString(chunk)
	}
	raw, err := b32.DecodeString(enc.String())
	if err != nil || wantLen < 0 {
		return nil, ErrFormat
	}
	h := sha256.Sum256(raw)
	if len(raw) != wantLen || strings.ToUpper(hex.EncodeToString(h[:4])) != wantSum {
		return nil, ErrChecksum
	}
	return Parse(raw)
}
