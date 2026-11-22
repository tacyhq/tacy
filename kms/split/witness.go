package split

import (
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/sha256"

	"github.com/tacyhq/tacy/kms"
)

// The witness key: an Ed25519 key derived from R_e per app, firm and epoch, named in the epoch certificate
// (Signers[WitnessPurpose]). The freshness record (V1-DESIGN §4) has the VM sign its record ops with it, and
// holderinit checks those ops (services/key-holders holderinit/seed.go). The legacy rollback witness that used it
// for signed state heads (POST /v1/witness, the head in the unlock reply) is removed (V1-DESIGN §2.5 step 1).

// WitnessPurpose is the purpose the witness key derives from (and its name in the epoch certificate's signers).
const WitnessPurpose = "witness/v1"

const labelWitnessKey = "tacy-split/witness-key/v1"

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
