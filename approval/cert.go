package approval

import (
	"crypto"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"time"

	"github.com/tacyhq/tacy/identity"
)

// Passkey certificates (docs/27 section 4). The VM can't trust a passkey public key the Worker stores (we could
// swap it), so each person's identity signs a small certificate naming the passkey: at registration from the key
// the authenticator returned, for an existing passkey after the browser checked a fresh assertion against the
// stored one. Firm members publish it as a passkey.add entry in the firm key log (keys v2); until then it travels
// with each approval, and the VM checks the identity's signature with the identity's key from the Directory.

// CertType names a passkey certificate's payload.
const CertType = "tacy.passkey/v1"

// CertLabel prefixes what a certificate's signature covers.
const CertLabel = "tacy-passkey/v1"

// Cert is a passkey certificate's payload.
type Cert struct {
	Type       string    `json:"type"`
	Firm       string    `json:"firm"`
	Identity   string    `json:"identity"`   // i_: whose passkey
	Credential string    `json:"credential"` // the credential id, base64url without padding
	Key        []byte    `json:"key"`        // the passkey's public key, SubjectPublicKeyInfo DER (ParsePasskeyKey)
	IssuedAt   time.Time `json:"issued_at"`
}

// SignedCert is a certificate as it travels: the payload exactly as signed and the identity's Ed25519 signature
// over CertLabel ‖ NUL ‖ payload.
type SignedCert struct {
	Payload []byte `json:"payload"`
	Sig     []byte `json:"sig"`
}

// SignCert makes a signed certificate (tests, and what the browser does).
func SignCert(c Cert, key ed25519.PrivateKey) (SignedCert, error) {
	c.Type = CertType
	b, err := json.Marshal(c)
	if err != nil {
		return SignedCert{}, err
	}
	return SignedCert{Payload: b, Sig: ed25519.Sign(key, certSigned(b))}, nil
}

func certSigned(payload []byte) []byte {
	return append([]byte(CertLabel+"\x00"), payload...)
}

// Verify checks the certificate for firm and space: strict payload, the identity current in the firm and holding
// the space (dir), its signature with that identity's key, and the passkey's key. It returns the certificate and
// the passkey's public key.
func (sc *SignedCert) Verify(dir identity.Directory, firm, space string) (*Cert, crypto.PublicKey, error) {
	if dir == nil {
		return nil, nil, errors.New("approval: no identity directory on this VM")
	}
	if len(sc.Payload) == 0 || len(sc.Payload) > 4<<10 || len(sc.Sig) != ed25519.SignatureSize {
		return nil, nil, errors.New("approval: bad certificate")
	}
	var c Cert
	if err := json.Unmarshal(sc.Payload, &c, json.RejectUnknownMembers(true)); err != nil {
		return nil, nil, errors.New("approval: bad certificate payload")
	}
	if c.Type != CertType || c.Firm != firm || !identity.ValidID("i", c.Identity) || c.IssuedAt.IsZero() {
		return nil, nil, errors.New("approval: certificate isn't for this firm")
	}
	if b, err := base64.RawURLEncoding.DecodeString(c.Credential); err != nil || len(b) == 0 || len(b) > 1023 {
		return nil, nil, errors.New("approval: bad credential id")
	}
	ik, err := dir.Key(firm, space, c.Identity)
	if err != nil {
		return nil, nil, err
	}
	if !ed25519.Verify(ik, certSigned(sc.Payload), sc.Sig) {
		return nil, nil, errors.New("approval: certificate not signed by its identity")
	}
	pk, err := ParsePasskeyKey(c.Key)
	if err != nil {
		return nil, nil, err
	}
	return &c, pk, nil
}
