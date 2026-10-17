// Package safety is foundation step 6 (docs/23-safety-controls.md): signed policy, the kill switch, budgets and
// rate limits, checked inside the VM by agentd, gatewayd and vaultd, each on its own.
//
// Every control document is a signed envelope: the exact payload bytes and Ed25519 signatures over them, with
// the document kind bound into what is signed. Policies and a firm's own stop list are signed by the firm's
// admin keys; the operator's stop list (global stop, availability only) by the operator key. Both trust roots are
// pinned in the attested compose. Standard library only.
package safety

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"strings"
)

// Document kinds.
const (
	KindPolicy = "policy"
	KindStop   = "stop"
)

// MaxEnvelope bounds one signed document on the wire.
const MaxEnvelope = 32 << 10

// Envelope is one signed document: Payload is the JSON document exactly as signed (base64 in JSON).
type Envelope struct {
	Kind    string `json:"kind"`
	Payload []byte `json:"payload"`
	Sigs    []Sig  `json:"sigs"`
}

// Sig is one signature: Key is the signer's public key ("ed25519:<base64 raw 32 bytes>").
type Sig struct {
	Key string `json:"key"`
	Sig []byte `json:"sig"`
}

// signed is what a signature covers: a fixed label, the kind and the payload, so a signature on one kind of
// document can't be presented as another.
func signed(kind string, payload []byte) []byte {
	b := make([]byte, 0, 32+len(payload))
	b = append(b, "tacy-safety/v1\x00"...)
	b = append(b, kind...)
	b = append(b, 0)
	return append(b, payload...)
}

// Hash is the document's id as records and the browser show it: sha256 of kind and payload, hex.
func (e *Envelope) Hash() string {
	h := sha256.Sum256(signed(e.Kind, e.Payload))
	return hex.EncodeToString(h[:])
}

// Sign makes an envelope of kind for payload signed by each key.
func Sign(kind string, payload []byte, keys ...ed25519.PrivateKey) Envelope {
	e := Envelope{Kind: kind, Payload: bytes.Clone(payload)}
	for _, k := range keys {
		e.Sigs = append(e.Sigs, Sig{Key: KeyString(k.Public().(ed25519.PublicKey)), Sig: ed25519.Sign(k, signed(kind, payload))})
	}
	return e
}

// KeyString is a public key as policies, flags and the compose name it.
func KeyString(pub ed25519.PublicKey) string {
	return "ed25519:" + base64.StdEncoding.EncodeToString(pub)
}

// ParseKey reads "ed25519:<base64>".
func ParseKey(s string) (ed25519.PublicKey, error) {
	b64, ok := strings.CutPrefix(strings.TrimSpace(s), "ed25519:")
	if !ok {
		return nil, errors.New("safety: key must be ed25519:<base64>")
	}
	b, err := base64.StdEncoding.DecodeString(b64)
	if err != nil || len(b) != ed25519.PublicKeySize {
		return nil, errors.New("safety: bad ed25519 public key")
	}
	return ed25519.PublicKey(b), nil
}

// ParseKeys reads a comma-separated list of keys ("" is none).
func ParseKeys(s string) ([]ed25519.PublicKey, error) {
	var out []ed25519.PublicKey
	for _, f := range strings.Split(s, ",") {
		if strings.TrimSpace(f) == "" {
			continue
		}
		k, err := ParseKey(f)
		if err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, nil
}

// signers returns how many distinct keys of trusted made a valid signature on e. Signatures by other keys are
// ignored (they add nothing), never an error.
func (e *Envelope) signers(trusted []ed25519.PublicKey) int {
	msg := signed(e.Kind, e.Payload)
	seen := map[string]bool{}
	for _, s := range e.Sigs {
		k, err := ParseKey(s.Key)
		if err != nil || seen[string(k)] || len(s.Sig) != ed25519.SignatureSize {
			continue
		}
		for _, t := range trusted {
			if bytes.Equal(t, k) && ed25519.Verify(t, msg, s.Sig) {
				seen[string(k)] = true
				break
			}
		}
	}
	return len(seen)
}

// DecodeEnvelopes reads one envelope or a JSON array of them, strictly (unknown members, duplicate names and
// trailing data are refused).
func DecodeEnvelopes(b []byte) ([]Envelope, error) {
	b = bytes.TrimSpace(b)
	if len(b) == 0 || len(b) > 8*MaxEnvelope {
		return nil, errors.New("safety: empty or oversize body")
	}
	var out []Envelope
	var err error
	if b[0] == '[' {
		err = json.Unmarshal(b, &out, json.RejectUnknownMembers(true))
	} else {
		var e Envelope
		err = json.Unmarshal(b, &e, json.RejectUnknownMembers(true))
		out = []Envelope{e}
	}
	if err != nil {
		return nil, fmt.Errorf("safety: bad envelope: %w", err)
	}
	if len(out) > 8 {
		return nil, errors.New("safety: at most 8 documents at once")
	}
	for _, e := range out {
		if len(e.Payload) == 0 || len(e.Payload) > MaxEnvelope || len(e.Sigs) == 0 || len(e.Sigs) > 8 {
			return nil, errors.New("safety: bad envelope size")
		}
	}
	return out, nil
}

// strict decodes a payload: unknown members, duplicate names and invalid UTF-8 are refused.
func strict(b []byte, v any) error {
	return json.Unmarshal(b, v, json.RejectUnknownMembers(true))
}
