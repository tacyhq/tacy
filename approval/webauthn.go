package approval

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"fmt"
	"slices"
)

// Assertion is a WebAuthn assertion as the browser's navigator.credentials.get returns it, its buffers base64
// (standard, padded) in JSON. The VM checks it itself (docs/27 section 4): no library, Go's standard library.
type Assertion struct {
	CredentialID      string `json:"credential_id"` // base64url without padding, as the passkey certificate names it
	AuthenticatorData []byte `json:"authenticator_data"`
	ClientDataJSON    []byte `json:"client_data_json"`
	Signature         []byte `json:"signature"`
}

// RP is who the assertion must be for: the relying party id (its SHA-256 is in the authenticator data) and the
// origins the release pins (the page the person approved on).
type RP struct {
	ID      string   // "tacy.io"
	Origins []string // "https://chat.tacy.io"
}

// Authenticator data flags (WebAuthn Level 2, section 6.1).
const (
	flagUP = 0x01 // user present
	flagUV = 0x04 // user verified (PIN, face, fingerprint)
)

// clientData is the part of the client data JSON the VM reads. Other members (crossOrigin false, browser extras)
// are allowed; a duplicate member name isn't (encoding/json/v2 refuses them).
type clientData struct {
	Type        string `json:"type"`
	Challenge   string `json:"challenge"`
	Origin      string `json:"origin"`
	CrossOrigin bool   `json:"crossOrigin"`
	TopOrigin   string `json:"topOrigin"`
}

// MaxAssertion bounds each part of an assertion.
const MaxAssertion = 4 << 10

// Verify checks the assertion with pub (the passkey's public key: ECDSA P-256, Ed25519, or RSA of at least 2048
// bits) for challenge and rp: type webauthn.get, the challenge, an origin rp pins, not cross-origin, the rpId's
// hash, user present and user verified, and the signature over authenticator data ‖ SHA-256(client data JSON).
// The signature counter isn't checked (synced passkeys report 0; clone detection needs state the VM doesn't keep).
func (a *Assertion) Verify(pub crypto.PublicKey, challenge []byte, rp RP) error {
	if len(a.AuthenticatorData) < 37 || len(a.AuthenticatorData) > MaxAssertion || len(a.ClientDataJSON) > MaxAssertion ||
		len(a.Signature) == 0 || len(a.Signature) > MaxAssertion {
		return errors.New("webauthn: assertion parts missing or too large")
	}
	var cd clientData
	if err := json.Unmarshal(a.ClientDataJSON, &cd); err != nil {
		return fmt.Errorf("webauthn: client data: %v", err)
	}
	switch {
	case cd.Type != "webauthn.get":
		return errors.New("webauthn: client data type isn't webauthn.get")
	case cd.Challenge != base64.RawURLEncoding.EncodeToString(challenge):
		return errors.New("webauthn: challenge doesn't match the payload")
	case !slices.Contains(rp.Origins, cd.Origin):
		return errors.New("webauthn: origin not pinned by the release")
	case cd.CrossOrigin || cd.TopOrigin != "":
		return errors.New("webauthn: cross-origin assertion")
	}
	ad := a.AuthenticatorData
	rpHash := sha256.Sum256([]byte(rp.ID))
	switch {
	case rp.ID == "" || !bytes.Equal(ad[:32], rpHash[:]):
		return errors.New("webauthn: rpId hash doesn't match")
	case ad[32]&flagUP == 0:
		return errors.New("webauthn: user not present")
	case ad[32]&flagUV == 0:
		return errors.New("webauthn: user not verified")
	}
	cdHash := sha256.Sum256(a.ClientDataJSON)
	signed := append(append([]byte(nil), ad...), cdHash[:]...)
	digest := sha256.Sum256(signed)
	ok := false
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		ok = k.Curve == elliptic.P256() && ecdsa.VerifyASN1(k, digest[:], a.Signature)
	case ed25519.PublicKey:
		ok = ed25519.Verify(k, signed, a.Signature)
	case *rsa.PublicKey:
		ok = k.N.BitLen() >= 2048 && rsa.VerifyPKCS1v15(k, crypto.SHA256, digest[:], a.Signature) == nil
	default:
		return errors.New("webauthn: unsupported key type")
	}
	if !ok {
		return errors.New("webauthn: bad signature")
	}
	return nil
}

// ParsePasskeyKey reads a passkey's public key as SubjectPublicKeyInfo DER (what the browser's
// AuthenticatorAttestationResponse.getPublicKey() returns at registration): ES256 (P-256), EdDSA (Ed25519) or RS256
// (RSA of at least 2048 bits). SPKI instead of COSE keeps a CBOR parser out of the VM.
func ParsePasskeyKey(spki []byte) (crypto.PublicKey, error) {
	if len(spki) == 0 || len(spki) > 1024 {
		return nil, errors.New("webauthn: key missing or too large")
	}
	k, err := x509.ParsePKIXPublicKey(spki)
	if err != nil {
		return nil, fmt.Errorf("webauthn: key: %v", err)
	}
	switch k := k.(type) {
	case *ecdsa.PublicKey:
		if k.Curve != elliptic.P256() {
			return nil, errors.New("webauthn: only P-256 ECDSA keys")
		}
	case ed25519.PublicKey:
	case *rsa.PublicKey:
		if k.N.BitLen() < 2048 {
			return nil, errors.New("webauthn: RSA key under 2048 bits")
		}
	default:
		return nil, errors.New("webauthn: unsupported key type")
	}
	return k, nil
}
