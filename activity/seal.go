package activity

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/hpke"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

var b64 = base64.StdEncoding

// MaxRecord bounds one sealed record's JSON (a run with many calls stays far below).
const MaxRecord = 256 << 10

// Signer is the VM's activity signing key.
type Signer struct {
	priv ed25519.PrivateKey
	pub  string
}

// NewSigner makes a signer from a 32-byte Ed25519 seed.
func NewSigner(seed []byte) (*Signer, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, errors.New("activity: signing seed must be 32 bytes")
	}
	priv := ed25519.NewKeyFromSeed(seed)
	return &Signer{priv: priv, pub: KeyString(priv.Public().(ed25519.PublicKey))}, nil
}

// DeriveSigner derives the signing key from key material only the attested VM gets (dstack's GetKey for this
// app), for one firm: HKDF-SHA256(ikm, info "tacy-activity/v1/signing-key\x00" || firm).
func DeriveSigner(ikm []byte, firm string) (*Signer, error) {
	if len(ikm) < 32 {
		return nil, errors.New("activity: key material too short")
	}
	seed, err := hkdf.Key(sha256.New, ikm, nil, Label+"/signing-key\x00"+firm, ed25519.SeedSize)
	if err != nil {
		return nil, err
	}
	return NewSigner(seed)
}

// Public is the signer's key as records name it: "ed25519:<base64>".
func (s *Signer) Public() string { return s.pub }

// KeyString is an Ed25519 public key as records name it.
func KeyString(pub ed25519.PublicKey) string { return "ed25519:" + b64.EncodeToString(pub) }

// ParseKey reads "ed25519:<base64>".
func ParseKey(s string) (ed25519.PublicKey, error) {
	raw, ok := strings.CutPrefix(s, "ed25519:")
	b, err := b64.Strict().DecodeString(raw)
	if !ok || err != nil || len(b) != ed25519.PublicKeySize {
		return nil, errors.New("activity: bad signing key")
	}
	return ed25519.PublicKey(b), nil
}

// RecipientString is an X25519 public key as records name it: "x25519:<base64>".
func RecipientString(pub *ecdh.PublicKey) string { return "x25519:" + b64.EncodeToString(pub.Bytes()) }

// ParseRecipient reads "x25519:<base64>" (32 bytes). It refuses the all-zero and other low-order keys ecdh
// refuses.
func ParseRecipient(s string) (*ecdh.PublicKey, error) {
	raw, ok := strings.CutPrefix(s, "x25519:")
	b, err := b64.Strict().DecodeString(raw)
	if !ok || err != nil || len(b) != 32 {
		return nil, errors.New("activity: bad recipient key")
	}
	pub, err := ecdh.X25519().NewPublicKey(b)
	if err != nil || bytes.Equal(b, make([]byte, 32)) {
		return nil, errors.New("activity: bad recipient key")
	}
	return pub, nil
}

// ChainID names the chain of one recipient in one space: the first 16 bytes of
// SHA-256("tacy-activity/v1/chain\x00" || space || "\x00" || recipient), hex. It says nothing about either.
func ChainID(space, to string) string {
	h := sha256.Sum256([]byte(Label + "/chain\x00" + space + "\x00" + to))
	return hex.EncodeToString(h[:16])
}

func signedBytes(header []byte) []byte {
	return append([]byte(Label+"\x00"), header...)
}

// HashHeader is a record's hash (what the next record's prev names).
func HashHeader(header []byte) string {
	h := sha256.Sum256(signedBytes(header))
	return hex.EncodeToString(h[:])
}

func aad(chain string, seq uint64) []byte {
	return []byte(Label + "\x00" + chain + "\x00" + strconv.FormatUint(seq, 10))
}

var suite = struct {
	kem  hpke.KEM
	kdf  hpke.KDF
	aead hpke.AEAD
}{hpke.DHKEM(ecdh.X25519()), hpke.HKDFSHA256(), hpke.AES256GCM()}

// seal makes record seq of chain: body sealed to `to`, header signed. It returns the record and its hash.
func (s *Signer) seal(chain string, seq uint64, prev string, unix int64, to string, body []byte) (Sealed, string, error) {
	pub, err := ParseRecipient(to)
	if err != nil {
		return Sealed{}, "", err
	}
	hp, err := hpke.NewDHKEMPublicKey(pub)
	if err != nil {
		return Sealed{}, "", err
	}
	enc, sender, err := hpke.NewSender(hp, suite.kdf, suite.aead, []byte(Label))
	if err != nil {
		return Sealed{}, "", err
	}
	ct, err := sender.Seal(aad(chain, seq), body)
	if err != nil {
		return Sealed{}, "", err
	}
	sum := sha256.Sum256(ct)
	h := Header{V: Version, Chain: chain, Seq: seq, Prev: prev, Time: unix, Key: s.pub, To: to,
		Enc: b64.EncodeToString(enc), CTHash: hex.EncodeToString(sum[:]), CTLen: len(ct)}
	hb, err := json.Marshal(&h)
	if err != nil {
		return Sealed{}, "", err
	}
	sig := ed25519.Sign(s.priv, signedBytes(hb))
	return Sealed{Header: b64.EncodeToString(hb), Sig: b64.EncodeToString(sig), CT: b64.EncodeToString(ct)}, HashHeader(hb), nil
}

// Errors a check reports.
var (
	ErrFormat    = errors.New("activity: malformed record")
	ErrSignature = errors.New("activity: bad signature")
	ErrUntrusted = errors.New("activity: signed by a key that isn't trusted")
	ErrCipher    = errors.New("activity: ciphertext doesn't match its header")
	ErrChain     = errors.New("activity: broken chain")
)

// Check verifies one record on its own: the header's form, the signature by the key it names (which trusted must
// accept; nil accepts any), and the ciphertext against its hash and length. It returns the header and its hash.
func Check(r Sealed, trusted func(key string) bool) (*Header, string, error) {
	hb, err := b64.Strict().DecodeString(r.Header)
	if err != nil || len(hb) == 0 || len(hb) > 4096 {
		return nil, "", ErrFormat
	}
	var h Header
	if err := json.Unmarshal(hb, &h, json.RejectUnknownMembers(true)); err != nil {
		return nil, "", ErrFormat
	}
	if h.V != Version || len(h.Chain) != 32 || !isHex(h.Chain) || h.Seq == 0 || (h.Seq == 1) != (h.Prev == "") ||
		(h.Prev != "" && (len(h.Prev) != 64 || !isHex(h.Prev))) || len(h.CTHash) != 64 || !isHex(h.CTHash) || h.CTLen <= 0 {
		return nil, "", ErrFormat
	}
	if _, err := ParseRecipient(h.To); err != nil {
		return nil, "", ErrFormat
	}
	pub, err := ParseKey(h.Key)
	if err != nil {
		return nil, "", ErrFormat
	}
	sig, err := b64.Strict().DecodeString(r.Sig)
	if err != nil || len(sig) != ed25519.SignatureSize || !ed25519.Verify(pub, signedBytes(hb), sig) {
		return nil, "", ErrSignature
	}
	if trusted != nil && !trusted(h.Key) {
		return nil, "", ErrUntrusted
	}
	ct, err := b64.Strict().DecodeString(r.CT)
	sum := sha256.Sum256(ct)
	if err != nil || len(ct) != h.CTLen || hex.EncodeToString(sum[:]) != h.CTHash {
		return nil, "", ErrCipher
	}
	return &h, HashHeader(hb), nil
}

// Link is where a verified chain ends: its last sequence number and that record's hash.
type Link struct {
	Seq  uint64 `json:"seq"`
	Hash string `json:"hash"`
}

// VerifyChain checks records of one chain in order: each passes Check, all name the same chain, sequence numbers
// go up by one without gaps, and each names the previous record's hash. from is where the caller's verified copy
// of the chain ends (nil: the records must start at seq 1). It returns the new end.
func VerifyChain(recs []Sealed, trusted func(key string) bool, from *Link) (Link, error) {
	var last Link
	chain := ""
	if from != nil {
		last = *from
	}
	for i, r := range recs {
		h, hash, err := Check(r, trusted)
		if err != nil {
			return last, fmt.Errorf("record %d: %w", i, err)
		}
		switch {
		case chain != "" && h.Chain != chain:
			return last, fmt.Errorf("record %d: %w: another chain", i, ErrChain)
		case h.Seq != last.Seq+1:
			return last, fmt.Errorf("record %d: %w: seq %d after %d", i, ErrChain, h.Seq, last.Seq)
		case h.Prev != last.Hash:
			return last, fmt.Errorf("record %d: %w: prev doesn't name the record before", i, ErrChain)
		}
		chain = h.Chain
		last = Link{Seq: h.Seq, Hash: hash}
	}
	return last, nil
}

// Open checks a record (Check) and decrypts its body with the recipient's private key. The body must name the
// header's chain and sequence number.
func Open(r Sealed, priv *ecdh.PrivateKey, trusted func(key string) bool) (*Header, *Run, error) {
	h, _, err := Check(r, trusted)
	if err != nil {
		return nil, nil, err
	}
	if RecipientString(priv.PublicKey()) != h.To {
		return nil, nil, errors.New("activity: sealed to another key")
	}
	hk, err := hpke.NewDHKEMPrivateKey(priv)
	if err != nil {
		return nil, nil, err
	}
	enc, _ := b64.DecodeString(h.Enc)
	ct, _ := b64.DecodeString(r.CT)
	rc, err := hpke.NewRecipient(enc, hk, suite.kdf, suite.aead, []byte(Label))
	if err != nil {
		return nil, nil, ErrCipher
	}
	pt, err := rc.Open(aad(h.Chain, h.Seq), ct)
	if err != nil {
		return nil, nil, ErrCipher
	}
	var run Run
	if err := json.Unmarshal(pt, &run, json.RejectUnknownMembers(true)); err != nil {
		return nil, nil, ErrFormat
	}
	if run.Type != BodyType || run.Chain != h.Chain || run.Seq != h.Seq {
		return nil, nil, ErrFormat
	}
	return h, &run, nil
}

func isHex(s string) bool {
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// SealTo seals body to the recipient key to ("x25519:<base64>") with the records' HPKE suite (RFC 9180 base mode,
// DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-256-GCM) under info and aad, padded to a size bucket first (trailing
// spaces: the same JSON). A scheduled run's result uses it (agentd, v0.12.0).
func SealTo(to string, info, aad, body []byte) (enc, ct []byte, err error) {
	pub, err := ParseRecipient(to)
	if err != nil {
		return nil, nil, err
	}
	hp, err := hpke.NewDHKEMPublicKey(pub)
	if err != nil {
		return nil, nil, err
	}
	enc, sender, err := hpke.NewSender(hp, suite.kdf, suite.aead, info)
	if err != nil {
		return nil, nil, err
	}
	pt := pad(bytes.Clone(body))
	ct, err = sender.Seal(aad, pt)
	clear(pt)
	return enc, ct, err
}

// OpenFrom opens what SealTo sealed, with the recipient's private key (tests; the browser does the same).
func OpenFrom(priv *ecdh.PrivateKey, info, aad, enc, ct []byte) ([]byte, error) {
	hk, err := hpke.NewDHKEMPrivateKey(priv)
	if err != nil {
		return nil, err
	}
	rc, err := hpke.NewRecipient(enc, hk, suite.kdf, suite.aead, info)
	if err != nil {
		return nil, ErrCipher
	}
	pt, err := rc.Open(aad, ct)
	if err != nil {
		return nil, ErrCipher
	}
	return pt, nil
}
