package split

import (
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	"encoding/json"

	"github.com/tacyhq/tacy/kms"
)

// The rollback witness (privacy review 2026-11-20: Cloudflare rolling back the sealed state would revive deleted
// schedules and disconnected mail logins). The VM signs a head of its sealed state (every name's generation and
// hash, a counter that only grows) with a witness key derived from R_e, certified in the epoch certificate
// (Signers[WitnessPurpose]). It pushes each new head to the policy's witnesses (POST /v1/witness), which keep the
// highest counter; at every unlock a witness returns its head inside the reply (bound into the reply's AAD, so it
// can't be stripped), and the VM refuses Worker state older than the head.

// WitnessPurpose is the purpose the witness key derives from (and its name in the epoch certificate's signers).
const WitnessPurpose = "witness/v1"

const (
	labelWitnessKey = "tacy-split/witness-key/v1"
	sigHead         = "tacy-split/state-head/v1"
)

// HeadEntry is one sealed state name's generation and blob hash.
type HeadEntry struct {
	Gen  uint64 `json:"gen"`
	Hash string `json:"hash"`
}

// StateHead is the VM's signed view of its sealed state.
type StateHead struct {
	KMSID   string               `json:"kms_id"`
	App     string               `json:"app"`
	Epoch   uint32               `json:"epoch"`
	Counter uint64               `json:"counter"` // grows with each new head
	Names   map[string]HeadEntry `json:"names"`
	At      time.Time            `json:"at"`
}

// SignedHead is a StateHead's exact JSON and the witness key's signature over label ‖ 0 ‖ doc.
type SignedHead struct {
	Doc []byte `json:"doc"`
	Sig []byte `json:"sig"`
}

// WitnessKey is the witness signing key from R_e (app, firm, epoch).
func WitnessKey(root []byte, app, firm string, epoch uint32) (ed25519.PrivateKey, error) {
	k, err := RootKey(root, app, firm, WitnessPurpose, epoch)
	if err != nil {
		return nil, err
	}
	defer clear(k)
	seed, err := hkdf.Key(sha256.New, k, nil, labelWitnessKey, ed25519.SeedSize)
	if err != nil {
		return nil, err
	}
	defer clear(seed)
	return ed25519.NewKeyFromSeed(seed), nil
}

// WitnessPublic is the witness key's public half, as the epoch certificate names it.
func WitnessPublic(root []byte, app, firm string, epoch uint32) (string, error) {
	k, err := WitnessKey(root, app, firm, epoch)
	if err != nil {
		return "", err
	}
	defer clear(k)
	return kms.IDString(k.Public().(ed25519.PublicKey)), nil
}

// SignHead signs h with the witness key.
func SignHead(key ed25519.PrivateKey, h StateHead) (*SignedHead, error) {
	if h.Counter == 0 || len(h.Names) > 1024 {
		return nil, errors.New("split: a head needs a counter and at most 1024 names")
	}
	doc, err := json.Marshal(h)
	if err != nil {
		return nil, err
	}
	return &SignedHead{Doc: doc, Sig: ed25519.Sign(key, signMessage(sigHead, doc))}, nil
}

// Open checks the head is signed by cert's witness key, for cert's KMS id, app and epoch.
func (s SignedHead) Open(cert *EpochCert) (*StateHead, error) {
	pub, err := kms.ParseID(cert.Signers[WitnessPurpose])
	if err != nil {
		return nil, errors.New("split: the epoch certificate names no witness key")
	}
	if len(s.Sig) != ed25519.SignatureSize || !ed25519.Verify(pub, signMessage(sigHead, s.Doc), s.Sig) {
		return nil, errors.New("split: the state head isn't signed by the epoch's witness key")
	}
	var h StateHead
	if err := kms.Strict(s.Doc, &h); err != nil {
		return nil, fmt.Errorf("split: state head: %w", err)
	}
	if h.KMSID != cert.KMSID || h.App != cert.App || h.Epoch != cert.Epoch || h.Counter == 0 {
		return nil, errors.New("split: the state head is for another KMS id, app or epoch")
	}
	return &h, nil
}

// WitnessPush is POST /v1/witness: a new head and the epoch certificate whose witness key signed it.
type WitnessPush struct {
	Cert SignedEpochCert `json:"cert"`
	Head SignedHead      `json:"head"`
}

// WitnessReply is POST /v1/witness's answer: the counter the witness now holds.
type WitnessReply struct {
	Counter uint64 `json:"counter"`
}

// headHash is the hash of a reply's witness head bytes ("" when none) for the reply's AAD.
func headHash(head []byte) string {
	h := sha256.Sum256(head)
	return string(h[:])
}
