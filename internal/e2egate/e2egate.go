// Package e2egate is the release gate's staging holder config (the release gate's notes): what cmd/e2e sends
// the stand-in (cmd/statestandin -holder) so it can serve as a 1-of-1 staging holder without its keys ever being in
// the compose the host stores. Test tooling only: never in a release.
package e2egate

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hpke"
	"encoding/json"
	"errors"

	"github.com/tacyhq/tacy/kms"
	"github.com/tacyhq/tacy/kms/split"
	"github.com/tacyhq/tacy/safety"
)

// KindHolderConfig is the envelope kind of the holder's config (the dev admin key signs it).
const KindHolderConfig = "e2e-standin-holder-config"

// info is the HPKE info of the sealed holder keys.
const info = "tacy e2e stand-in holder keys v1"

// HolderConfig is the envelope's payload.
type HolderConfig struct {
	Holder string            `json:"holder"`
	Share  split.HolderShare `json:"share"`
	Sealed []byte            `json:"sealed"` // HPKE to the stand-in's boot key: HolderKeys
}

// HolderKeys are the holder's private keys (sealed in HolderConfig).
type HolderKeys struct {
	Key   []byte `json:"key"`   // X25519 private key (the share's recipient)
	Nonce []byte `json:"nonce"` // the holder's 32-byte nonce key
}

// Seal makes the signed config: the keys sealed to boot (the stand-in's X25519 boot key), signed by admin.
func Seal(boot []byte, holder string, share split.HolderShare, key *ecdh.PrivateKey, nonce []byte, admin ed25519.PrivateKey) ([]byte, error) {
	pk, err := hpke.DHKEM(ecdh.X25519()).NewPublicKey(boot)
	if err != nil {
		return nil, err
	}
	pt, _ := json.Marshal(HolderKeys{Key: key.Bytes(), Nonce: nonce})
	defer clear(pt)
	ct, err := hpke.Seal(pk, hpke.HKDFSHA256(), hpke.AES256GCM(), []byte(info), pt)
	if err != nil {
		return nil, err
	}
	b, _ := json.Marshal(HolderConfig{Holder: holder, Share: share, Sealed: ct})
	return json.Marshal(safety.Sign(KindHolderConfig, b, admin))
}

// Open checks the admin signatures and opens the keys with the boot key.
func Open(b []byte, admin kms.AdminKeys, boot hpke.PrivateKey) (*HolderConfig, *HolderKeys, error) {
	var env safety.Envelope
	if err := json.Unmarshal(b, &env); err != nil {
		return nil, nil, errors.New("not an envelope")
	}
	var c HolderConfig
	if err := admin.Open(&env, KindHolderConfig, &c); err != nil {
		return nil, nil, err
	}
	pt, err := hpke.Open(boot, hpke.HKDFSHA256(), hpke.AES256GCM(), []byte(info), c.Sealed)
	if err != nil {
		return nil, nil, errors.New("the keys aren't sealed to this boot's key")
	}
	defer clear(pt)
	var k HolderKeys
	if err := json.Unmarshal(pt, &k); err != nil {
		return nil, nil, errors.New("sealed keys: not JSON")
	}
	return &c, &k, nil
}
