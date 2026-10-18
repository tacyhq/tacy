package activity

import (
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
)

// RecordProof is how a run request shows that whoever asks for records sealed to `to` holds its private key
// (else anyone who saw someone's public key, our relay included, could make the VM write into their chain and
// learn its length from meta.activity). Both sides compute it from one X25519 agreement between the recipient key
// and the VM's attested EHBP key for this boot:
//
//	k     = HKDF-SHA256(X25519(recipient, vm), salt empty, info "tacy-activity/v1/record-to", 32 bytes)
//	proof = HMAC-SHA256(k, "tacy-activity/v1/record-to\0" || to || "\0" || hex(vm public key))
//
// The browser computes it with its activity key and the VM key it verified; the VM with its EHBP private key and
// `to`. It travels inside the EHBP-encrypted body, so the relay never sees it, and it's bound to this boot's key.
func RecordProof(priv *ecdh.PrivateKey, peer *ecdh.PublicKey, to string, vmPub []byte) ([]byte, error) {
	shared, err := priv.ECDH(peer)
	if err != nil {
		return nil, err
	}
	k, err := hkdf.Key(sha256.New, shared, nil, Label+"/record-to", 32)
	clear(shared)
	if err != nil {
		return nil, err
	}
	m := hmac.New(sha256.New, k)
	m.Write([]byte(Label + "/record-to\x00" + to + "\x00" + hex.EncodeToString(vmPub)))
	return m.Sum(nil), nil
}

// ErrRecordProof: the run asked for records sealed to a key it didn't prove it holds.
var ErrRecordProof = errors.New("activity: record_to without a valid proof")

// CheckRecordProof is the VM's side: vm is its EHBP private key.
func CheckRecordProof(vm *ecdh.PrivateKey, to string, proof []byte) error {
	pub, err := ParseRecipient(to)
	if err != nil {
		return err
	}
	want, err := RecordProof(vm, pub, to, vm.PublicKey().Bytes())
	if err != nil || len(proof) != len(want) || !hmac.Equal(want, proof) {
		return ErrRecordProof
	}
	return nil
}
