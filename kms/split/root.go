package split

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"time"

	"github.com/tacyhq/tacy/kms"
)

// Labels of the epoch root and what derives from it.
const (
	LabelVMRoot   = "tacy-split/vm-root/v1"    // HKDF info prefix: R_e from M
	LabelRootID   = "tacy-split/vm-root-id/v1" // HKDF info: R_e's root id (an Ed25519 seed; only its public half is used)
	LabelSecrets  = "tacy-split/secrets/v1"    // HKDF info prefix: the secrets bundle's key from R_e
	sigEpochCert  = "tacy-split/epoch-cert/v1" // Ed25519 label (KMS id): an epoch certificate
	secretsMagic  = "TACYSECRETS1"
	rootInfoEpoch = "\x00" // label ‖ 0 ‖ epoch (u32 big-endian)
)

// EpochRoot is the VM root of epoch e: HKDF-SHA256(M, info LabelVMRoot ‖ 0 ‖ e), 32 bytes. Holders hold shares of
// it, never of M; a leaked R_e is answered by moving to e+1 (an offline re-split), with the same KMS id.
func EpochRoot(master []byte, epoch uint32) ([]byte, error) {
	if len(master) != kms.MasterSize || epoch == 0 {
		return nil, errors.New("split: an epoch root needs the 32-byte M and an epoch > 0")
	}
	return hkdf.Key(sha256.New, master, nil, epochInfo(LabelVMRoot, epoch), kms.MasterSize)
}

func epochInfo(label string, epoch uint32) string {
	return label + rootInfoEpoch + string(binary.BigEndian.AppendUint32(nil, epoch))
}

// RootID names R_e publicly ("ed25519:<base64>"): the Ed25519 public key whose seed is HKDF(R_e, LabelRootID). The
// share set and the epoch certificate carry it, so the VM can tell the right R_e from any other 32 bytes.
func RootID(root []byte) (string, error) {
	if len(root) != kms.MasterSize {
		return "", errors.New("split: a root is 32 bytes")
	}
	seed, err := hkdf.Key(sha256.New, root, nil, LabelRootID, ed25519.SeedSize)
	if err != nil {
		return "", err
	}
	k := ed25519.NewKeyFromSeed(seed)
	clear(seed)
	pub := k.Public().(ed25519.PublicKey)
	clear(k)
	return kms.IDString(pub), nil
}

// RootKey is a per-purpose key from R_e: kms.DeriveKey with R_e in place of M (HKDF-SHA256, salt "tacy-kms/v1",
// info app‖0‖firm‖0‖purpose‖0‖e).
func RootKey(root []byte, app, firm, purpose string, epoch uint32) ([]byte, error) {
	return kms.DeriveKey(root, app, firm, purpose, epoch)
}

// EpochCert is the KMS id's certificate of one epoch: R_e's root id and the public keys derived from R_e that others
// check (the chat Worker the store certificates, the clients the activity signer). Signed offline, once per epoch,
// at the ceremony: the VM never holds the KMS id's private key.
type EpochCert struct {
	KMSID string `json:"kms_id"`
	Epoch uint32 `json:"epoch"`
	Root  string `json:"root"` // RootID(R_e)
	App   string `json:"app"`
	Firm  string `json:"firm"`
	// StoreCerts: for each of kms.StorePurposes, the KMS id's kms.StoreCert for the store-auth key of that
	// purpose's key from R_e (the Worker's /api/vm/state checks these as before).
	StoreCerts map[string]kms.StoreCert `json:"store_certs"`
	// Signers: other public keys derived from R_e, by purpose ("activity-sign/v1": the activity signer).
	Signers  map[string]string `json:"signers,omitempty"`
	IssuedAt time.Time         `json:"issued_at"`
}

// SignedEpochCert is an EpochCert's exact JSON and the KMS id's signature over label ‖ 0 ‖ doc.
type SignedEpochCert struct {
	Doc []byte `json:"doc"`
	Sig []byte `json:"sig"`
}

// Open checks the KMS id signed c and returns the certificate, each store certificate checked too.
func (c SignedEpochCert) Open(kmsID ed25519.PublicKey) (*EpochCert, error) {
	if len(c.Sig) != ed25519.SignatureSize || !ed25519.Verify(kmsID, signMessage(sigEpochCert, c.Doc), c.Sig) {
		return nil, errors.New("split: epoch certificate isn't signed by the KMS id")
	}
	var ec EpochCert
	if err := kms.Strict(c.Doc, &ec); err != nil {
		return nil, fmt.Errorf("split: epoch certificate: %w", err)
	}
	if ec.KMSID != kms.IDString(kmsID) || ec.Epoch == 0 {
		return nil, errors.New("split: epoch certificate is for another KMS id")
	}
	if _, err := kms.ParseID(ec.Root); err != nil {
		return nil, fmt.Errorf("split: epoch certificate root: %w", err)
	}
	for pu, sc := range ec.StoreCerts {
		if sc.Purpose != pu || sc.Epoch != ec.Epoch || sc.App != ec.App || sc.Firm != ec.Firm || len(sc.Sig) != ed25519.SignatureSize ||
			!ed25519.Verify(kmsID, kms.StoreCertMessage(sc), sc.Sig) {
			return nil, fmt.Errorf("split: epoch certificate: the %s store certificate doesn't check", pu)
		}
	}
	return &ec, nil
}

// NewEpochCert makes and signs (with the KMS id M derives) epoch's certificate for app and firm: R_e's root id, the
// store certificates, and signers (public keys the caller derived from R_e, by purpose).
func NewEpochCert(master []byte, kmsID string, epoch uint32, app, firm string, signers map[string]string, issuedAt time.Time) (*SignedEpochCert, error) {
	id, err := checkMaster(master, kmsID)
	if err != nil {
		return nil, err
	}
	defer clear(id)
	root, err := EpochRoot(master, epoch)
	if err != nil {
		return nil, err
	}
	defer clear(root)
	rid, err := RootID(root)
	if err != nil {
		return nil, err
	}
	ec := EpochCert{KMSID: kmsID, Epoch: epoch, Root: rid, App: app, Firm: firm, StoreCerts: map[string]kms.StoreCert{},
		Signers: signers, IssuedAt: issuedAt.UTC()}
	for _, pu := range kms.StorePurposes {
		k, err := RootKey(root, app, firm, pu, epoch)
		if err != nil {
			return nil, err
		}
		sk, err := kms.StoreAuthKey(k)
		clear(k)
		if err != nil {
			return nil, err
		}
		sc := kms.StoreCert{App: app, Firm: firm, Epoch: epoch, Purpose: pu, Key: kms.IDString(sk.Public().(ed25519.PublicKey))}
		clear(sk)
		sc.Sig = ed25519.Sign(id, kms.StoreCertMessage(sc))
		ec.StoreCerts[pu] = sc
	}
	doc, err := json.Marshal(ec)
	if err != nil {
		return nil, err
	}
	return &SignedEpochCert{Doc: doc, Sig: ed25519.Sign(id, signMessage(sigEpochCert, doc))}, nil
}

// SecretsBundle is our third-party API keys (Tinfoil, Exa, Tavily) for one epoch. Seq orders bundles (the policy's
// secrets_floor refuses older ones).
type SecretsBundle struct {
	KMSID  string            `json:"kms_id"`
	Epoch  uint32            `json:"epoch"`
	Seq    uint64            `json:"seq"`
	Values map[string]string `json:"values"`
}

// SecretsKey is the secrets bundle's AES-256-GCM key from R_e: HKDF-SHA256(R_e, info LabelSecrets ‖ 0 ‖ e).
func SecretsKey(root []byte, epoch uint32) ([]byte, error) {
	if len(root) != kms.MasterSize {
		return nil, errors.New("split: a root is 32 bytes")
	}
	return hkdf.Key(sha256.New, root, nil, epochInfo(LabelSecrets, epoch), 32)
}

func secretsAAD(kmsID string, epoch uint32, seq uint64) []byte {
	return append(lp([]byte(secretsMagic), kmsID+"\x00"+strconv.FormatUint(uint64(epoch), 10)), binary.BigEndian.AppendUint64(nil, seq)...)
}

// SealSecrets seals b under R_e (ciphertext; store it anywhere, the Worker serves it to the VM): magic ‖ seq (u64) ‖
// nonce ‖ AES-256-GCM(JSON, aad magic, KMS id, epoch, seq).
func SealSecrets(root []byte, b SecretsBundle) ([]byte, error) {
	if b.Seq == 0 || len(b.Values) == 0 {
		return nil, errors.New("split: a secrets bundle needs a seq and values")
	}
	k, err := SecretsKey(root, b.Epoch)
	if err != nil {
		return nil, err
	}
	defer clear(k)
	g, err := gcmOf(k)
	if err != nil {
		return nil, err
	}
	pt, err := json.Marshal(b)
	if err != nil {
		return nil, err
	}
	defer clear(pt)
	out := append([]byte(secretsMagic), binary.BigEndian.AppendUint64(nil, b.Seq)...)
	nonce := make([]byte, g.NonceSize())
	rand.Read(nonce)
	out = append(out, nonce...)
	return g.Seal(out, nonce, pt, secretsAAD(b.KMSID, b.Epoch, b.Seq)), nil
}

// OpenSecrets opens a sealed bundle with R_e of kmsID's epoch.
func OpenSecrets(root []byte, kmsID string, epoch uint32, sealed []byte) (*SecretsBundle, error) {
	k, err := SecretsKey(root, epoch)
	if err != nil {
		return nil, err
	}
	defer clear(k)
	g, err := gcmOf(k)
	if err != nil {
		return nil, err
	}
	head := len(secretsMagic) + 8
	if len(sealed) < head+g.NonceSize()+g.Overhead() || string(sealed[:len(secretsMagic)]) != secretsMagic {
		return nil, errors.New("split: not a sealed secrets bundle")
	}
	seq := binary.BigEndian.Uint64(sealed[len(secretsMagic):head])
	nonce := sealed[head : head+g.NonceSize()]
	pt, err := g.Open(nil, nonce, sealed[head+g.NonceSize():], secretsAAD(kmsID, epoch, seq))
	if err != nil {
		return nil, errors.New("split: the secrets bundle doesn't open with this epoch's root")
	}
	defer clear(pt)
	var b SecretsBundle
	if err := kms.Strict(pt, &b); err != nil || b.Seq != seq || b.KMSID != kmsID || b.Epoch != epoch {
		return nil, errors.New("split: the secrets bundle names another seq, KMS id or epoch")
	}
	return &b, nil
}

func gcmOf(k []byte) (cipher.AEAD, error) {
	c, err := aes.NewCipher(k)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(c)
}

// Purposes lists the purposes an epoch certificate's signers may name (for kmsctl).
var signerPurposes = []string{"activity-sign/v1"}

// SignerPurpose reports whether purpose may name a signer in an epoch certificate.
func SignerPurpose(purpose string) bool { return slices.Contains(signerPurposes, purpose) }
