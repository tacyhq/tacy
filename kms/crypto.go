package kms

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/hpke"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
)

// MasterSize is M's size.
const MasterSize = 32

// DeriveID is the KMS id: the Ed25519 key whose seed is HKDF-SHA256(M, info LabelID).
func DeriveID(master []byte) (ed25519.PrivateKey, error) {
	if len(master) != MasterSize {
		return nil, errors.New("kms: master key must be 32 bytes")
	}
	seed, err := hkdf.Key(sha256.New, master, nil, LabelID, ed25519.SeedSize)
	if err != nil {
		return nil, err
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// DeriveKey is a purpose key: HKDF-SHA256(M_e, salt "tacy-kms/v1", info app‖0‖firm‖0‖purpose‖0‖e), 32 bytes.
func DeriveKey(master []byte, app, firm, purpose string, epoch uint32) ([]byte, error) {
	if len(master) != MasterSize {
		return nil, errors.New("kms: master key must be 32 bytes")
	}
	info := app + "\x00" + firm + "\x00" + purpose + "\x00" + strconv.FormatUint(uint64(epoch), 10)
	return hkdf.Key(sha256.New, master, []byte(LabelPurpose), info, 32)
}

// SecretsKey is the secrets bundle's AES-256-GCM key: HKDF-SHA256(M, info "secrets/v1").
func SecretsKey(master []byte) ([]byte, error) {
	if len(master) != MasterSize {
		return nil, errors.New("kms: master key must be 32 bytes")
	}
	return hkdf.Key(sha256.New, master, nil, LabelSecrets, 32)
}

// IDString is a KMS id as composes, clients and the trust list name it: "ed25519:<base64>".
func IDString(pub ed25519.PublicKey) string {
	return "ed25519:" + base64.StdEncoding.EncodeToString(pub)
}

// ParseID reads "ed25519:<base64>".
func ParseID(s string) (ed25519.PublicKey, error) {
	b64, ok := strings.CutPrefix(strings.TrimSpace(s), "ed25519:")
	b, err := base64.StdEncoding.DecodeString(b64)
	if !ok || err != nil || len(b) != ed25519.PublicKeySize {
		return nil, errors.New("kms: key must be ed25519:<base64 of 32 bytes>")
	}
	return ed25519.PublicKey(b), nil
}

// RecipientString is a share recipient: "p256:<base64 SEC1 uncompressed point>".
func RecipientString(pub *ecdh.PublicKey) string {
	return "p256:" + base64.StdEncoding.EncodeToString(pub.Bytes())
}

// ParseRecipient reads "p256:<base64>".
func ParseRecipient(s string) (*ecdh.PublicKey, error) {
	b64, ok := strings.CutPrefix(strings.TrimSpace(s), "p256:")
	b, err := base64.StdEncoding.DecodeString(b64)
	if !ok || err != nil {
		return nil, errors.New("kms: recipient must be p256:<base64>")
	}
	pk, err := ecdh.P256().NewPublicKey(b)
	if err != nil {
		return nil, errors.New("kms: recipient isn't a P-256 point")
	}
	return pk, nil
}

// ShareAAD binds a share to its KMS id, index and epoch.
func ShareAAD(kmsID string, index byte, epoch uint32) []byte {
	b := append([]byte(kmsID), 0, index)
	return binary.BigEndian.AppendUint32(b, epoch)
}

// Seal is HPKE base mode (KDF HKDF-SHA256, AEAD AES-256-GCM) to pub (X25519 or P-256) with info and aad.
func Seal(pub *ecdh.PublicKey, info string, aad, plaintext []byte) (Sealed, error) {
	pk, err := hpke.NewDHKEMPublicKey(pub)
	if err != nil {
		return Sealed{}, err
	}
	enc, s, err := hpke.NewSender(pk, hpke.HKDFSHA256(), hpke.AES256GCM(), []byte(info))
	if err != nil {
		return Sealed{}, err
	}
	ct, err := s.Seal(aad, plaintext)
	return Sealed{Enc: enc, CT: ct}, err
}

// Open opens Seal's output with priv.
func Open(priv ecdh.KeyExchanger, info string, aad []byte, box Sealed) ([]byte, error) {
	k, err := hpke.NewDHKEMPrivateKey(priv)
	if err != nil {
		return nil, err
	}
	r, err := hpke.NewRecipient(box.Enc, k, hpke.HKDFSHA256(), hpke.AES256GCM(), []byte(info))
	if err != nil {
		return nil, err
	}
	return r.Open(aad, box.CT)
}

// Hash is sha256(enc‖ct).
func (s Sealed) Hash() []byte {
	h := sha256.New()
	h.Write(s.Enc)
	h.Write(s.CT)
	return h.Sum(nil)
}

func label(l string) []byte { return append([]byte(l), 0) }

func appendStr(b []byte, s string) []byte {
	b = binary.BigEndian.AppendUint32(b, uint32(len(s)))
	return append(b, s...)
}

// LeaseBytes is a lease's signed encoding.
func LeaseBytes(l Lease) []byte {
	var b []byte
	b = appendStr(b, l.ID)
	b = appendStr(b, l.App)
	b = appendStr(b, l.Holder)
	b = appendStr(b, l.Instance)
	b = appendStr(b, l.Key)
	b = binary.BigEndian.AppendUint64(b, l.Seq)
	return binary.BigEndian.AppendUint64(b, uint64(l.Expires))
}

// ReleaseSigMessage is what the KMS id signs on a release reply: label, the nonce, sha256 of the attestation bytes
// the VM sent, sha256(enc‖ct), the lease and the audit sequence number.
func ReleaseSigMessage(nonce, attHash, sealedHash []byte, l Lease, logSeq uint64) []byte {
	b := label(sigRelease)
	b = appendStr(b, string(nonce))
	b = appendStr(b, string(attHash))
	b = appendStr(b, string(sealedHash))
	b = appendStr(b, string(LeaseBytes(l)))
	return binary.BigEndian.AppendUint64(b, logSeq)
}

// StoreAuthKey is a store-auth key: the Ed25519 key whose seed is HKDF-SHA256(purposeKey, info LabelStoreAuth).
func StoreAuthKey(purposeKey []byte) (ed25519.PrivateKey, error) {
	if len(purposeKey) != 32 {
		return nil, errors.New("kms: a store-auth key needs a 32-byte purpose key")
	}
	seed, err := hkdf.Key(sha256.New, purposeKey, nil, LabelStoreAuth, ed25519.SeedSize)
	if err != nil {
		return nil, err
	}
	defer clear(seed)
	return ed25519.NewKeyFromSeed(seed), nil
}

// StoreCertMessage is what the KMS id signs on a StoreCert: the label and a NUL, then app, firm, the epoch (u32
// big-endian), purpose and key, each string length-prefixed (u32 big-endian). The chat Worker checks it
// (the chat's src/worker/vm-state.ts).
func StoreCertMessage(c StoreCert) []byte {
	b := label(sigStoreCert)
	b = appendStr(b, c.App)
	b = appendStr(b, c.Firm)
	b = binary.BigEndian.AppendUint32(b, c.Epoch)
	b = appendStr(b, c.Purpose)
	return appendStr(b, c.Key)
}

// LeaseSigMessage is what the KMS id signs on a lease.
func LeaseSigMessage(l Lease) []byte { return append(label(sigLease), LeaseBytes(l)...) }

func appendGen(b []byte, g Gen) []byte {
	b = appendStr(b, g.App)
	b = appendStr(b, g.Name)
	b = binary.BigEndian.AppendUint64(b, g.Gen)
	return appendStr(b, g.Hash)
}

func appendBool(b []byte, v bool) []byte {
	if v {
		return append(b, 1)
	}
	return append(b, 0)
}

// GenSigMessage is what the KMS id signs on a register answer: the entry, the previous generation's hash, whether
// it is stored, and the caller's nonce (so an old answer doesn't pass as a fresh one).
func GenSigMessage(sg SignedGen) []byte {
	b := appendGen(label(sigGen), sg.Gen)
	b = appendStr(b, sg.Prev)
	b = appendBool(b, sg.Stored)
	return appendStr(b, sg.Nonce)
}

// SnapshotSigMessage is what the KMS id signs on a register snapshot.
func SnapshotSigMessage(s Snapshot) []byte {
	b := appendStr(label(sigSnapshot), s.KMSID)
	b = binary.BigEndian.AppendUint32(b, s.Epoch)
	b = binary.BigEndian.AppendUint64(b, uint64(s.Time))
	b = binary.BigEndian.AppendUint64(b, s.LogSeq)
	b = appendStr(b, s.Nonce)
	b = binary.BigEndian.AppendUint32(b, uint32(len(s.Entries)))
	for _, e := range s.Entries {
		b = appendGen(b, e.Gen)
		b = appendStr(b, e.Prev)
		b = appendBool(b, e.Stored)
	}
	return b
}

// JoinSigMessage is what the KMS id signs on a join reply.
func JoinSigMessage(peerNonce, attHash, sealedHash []byte) []byte {
	b := label(sigJoin)
	b = appendStr(b, string(peerNonce))
	b = appendStr(b, string(attHash))
	return appendStr(b, string(sealedHash))
}

// GenesisSigMessage is what the new KMS id signs on the genesis reply: the genesis document's hash and every share.
func GenesisSigMessage(genesisHash string, shares []SealedShare) []byte {
	b := appendStr(label(sigGenesis), genesisHash)
	for _, s := range shares {
		b = appendStr(b, s.Recipient)
		b = append(b, s.Index)
		b = appendStr(b, string(s.Hash()))
	}
	return b
}

// ShareCommitment is sha256(label ‖ kms id ‖ index ‖ epoch ‖ share), hex: what a share must hash to.
func ShareCommitment(kmsID string, index byte, epoch uint32, share []byte) string {
	b := appendStr(label(sigCommit), kmsID)
	b = append(b, index)
	b = binary.BigEndian.AppendUint32(b, epoch)
	h := sha256.Sum256(append(b, share...))
	return hex.EncodeToString(h[:])
}

// CommitmentsSigMessage is what the KMS id signs on the share commitments.
func CommitmentsSigMessage(kmsID string, epoch uint32, commitments []string) []byte {
	b := appendStr(label(sigCommit), kmsID)
	b = binary.BigEndian.AppendUint32(b, epoch)
	for _, c := range commitments {
		b = appendStr(b, c)
	}
	return b
}

// LeaseMAC is the HMAC-SHA256 a lease holder proves itself with: op ("renew", "drop" or "commit") and its fields.
func LeaseMAC(secret []byte, op string, fields ...string) []byte {
	m := hmac.New(sha256.New, secret)
	m.Write(label(LabelLeaseMAC))
	m.Write(appendStr(nil, op))
	for _, f := range fields {
		m.Write(appendStr(nil, f))
	}
	return m.Sum(nil)
}

// RenewMAC is LeaseRenew's MAC.
func RenewMAC(secret []byte, app, holder, lease string, at int64) []byte {
	return LeaseMAC(secret, "renew", app, holder, lease, strconv.FormatInt(at, 10))
}

// DropMAC is a lease drop's MAC (POST /v1/lease/drop takes a LeaseRenew with it).
func DropMAC(secret []byte, app, holder, lease string, at int64) []byte {
	return LeaseMAC(secret, "drop", app, holder, lease, strconv.FormatInt(at, 10))
}

// CommitMAC is GenCommit's MAC: every field but the MAC.
func CommitMAC(secret []byte, c GenCommit) []byte {
	stored := "reserve"
	if c.Stored {
		stored = "stored"
	}
	return LeaseMAC(secret, "commit", c.App, c.Holder, c.Name, strconv.FormatUint(c.Gen.Gen, 10), c.Hash, stored, c.Nonce, c.Lease,
		strconv.FormatInt(c.At, 10))
}

// AuditHash is an entry's hash: sha256 of the label, the previous hash and every field.
func AuditHash(e AuditEntry) string {
	b := label(sigAudit)
	b = appendStr(b, e.Prev)
	b = binary.BigEndian.AppendUint64(b, e.Seq)
	b = binary.BigEndian.AppendUint64(b, uint64(e.Time))
	b = appendStr(b, e.Kind)
	b = appendBool(b, e.OK)
	b = appendStr(b, e.App)
	b = appendStr(b, e.Instance)
	b = appendStr(b, e.Detail)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// AuditSigMessage is what the KMS id signs on an audit entry: a label and its hash.
func AuditSigMessage(hash string) []byte { return append(label(sigAuditEntry), hash...) }

// VerifyLog checks a run of entries: each hash, each link to the one before (prev is the hash before entries[0],
// "" from the start) and each signature by the KMS id. It returns the last hash.
func VerifyLog(entries []AuditEntry, prev string, id ed25519.PublicKey) (string, error) {
	for _, e := range entries {
		if e.Prev != prev {
			return "", errors.New("kms: audit entry " + strconv.FormatUint(e.Seq, 10) + " doesn't link to the one before")
		}
		if AuditHash(e) != e.Hash {
			return "", errors.New("kms: audit entry " + strconv.FormatUint(e.Seq, 10) + " has a wrong hash")
		}
		if !ed25519.Verify(id, AuditSigMessage(e.Hash), e.Sig) {
			return "", errors.New("kms: audit entry " + strconv.FormatUint(e.Seq, 10) + " isn't signed by the KMS id")
		}
		prev = e.Hash
	}
	return prev, nil
}
