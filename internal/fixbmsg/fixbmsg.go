// Package fixbmsg is the Fix B throwaway's results channel (test only: cmd/e2epush in the VM, cmd/e2e fixb on the
// tester's machine; never in a release). Review M1 (2026-11-21): sealing to the tester's HPKE key only proves the
// sender knew that public key, which is in the compose Phala stores and shows, so the host under test could forge
// any result. Now each container start of e2epush makes an Ed25519 key in TD memory and first sends a key message
// whose dstack quote binds the key (report_data, through KeyNonce, with the run, boot and start); every message,
// the key message too, is signed by it and carries the run id, the boot, the start and a sequence number. The tester
// takes a key only after the full verifier accepts its quote, then each message only if its signature verifies under
// an accepted key, it is of the same run, boot and start, and its seq is exactly the next one: a replay or an
// earlier message presented later is refused, a later one waits for the ones before it. The channel stays sealed to
// the tester's key (HPKE) as before: the relay sees ciphertext.
package fixbmsg

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/tacyhq/tacy/proto"
)

// Info is the HPKE info string both ends use (unchanged from the unsigned channel's).
const Info = "tacy-fixb-push/v1"

// KeyTitle is the title of a start's first message (seq 0): its signing key and the quote binding it.
const KeyTitle = "key"

const (
	signDomain  = "tacy-fixb-msg/v1\x00"
	nonceDomain = "tacy-fixb-key/v1\x00"
)

// Payload is what a message signs.
type Payload struct {
	Run   string          `json:"run"`   // the run's id (cmd/e2e fixb prepare; -run)
	Boot  string          `json:"boot"`  // the TD's boot id (/proc/sys/kernel/random/boot_id)
	Start int             `json:"start"` // e2epush's container start in this boot (1, 2, ...)
	Seq   int             `json:"seq"`   // 0: the key message; then 1, 2, ... per start
	Title string          `json:"title"` // attest-1, scan-1, ...
	At    string          `json:"at"`
	Body  json.RawMessage `json:"body"`
}

// Signed is a message as sealed: the signer's public key, the payload's bytes and the signature over them.
type Signed struct {
	Key     string `json:"key"` // Ed25519 public key, hex
	Payload []byte `json:"payload"`
	Sig     []byte `json:"sig"`
}

// KeyBody is the key message's body: a dstack quote under agentd's label (proto.VersionAgent, so it can never ask a
// holder for a share) whose nonce is KeyNonce of the key message's run, boot, start and key.
type KeyBody struct {
	Attestation *proto.Attestation `json:"attestation,omitempty"`
	QuoteErr    string             `json:"quote_err,omitempty"`
}

// KeyNonce is the nonce a start's quote binds: sha256 over the domain, the run, the boot, the start and the key.
func KeyNonce(run, boot string, start int, pub ed25519.PublicKey) []byte {
	h := sha256.New()
	h.Write([]byte(nonceDomain))
	for _, s := range []string{run, boot} {
		binary.Write(h, binary.BigEndian, uint32(len(s)))
		h.Write([]byte(s))
	}
	binary.Write(h, binary.BigEndian, uint64(start))
	h.Write(pub)
	return h.Sum(nil)
}

func signed(payload []byte) []byte { return append([]byte(signDomain), payload...) }

// Sign makes a message of p signed by priv (JSON, to seal).
func Sign(priv ed25519.PrivateKey, p Payload) ([]byte, error) {
	b, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}
	pub := priv.Public().(ed25519.PublicKey)
	return json.Marshal(Signed{Key: hex.EncodeToString(pub), Payload: b, Sig: ed25519.Sign(priv, signed(b))})
}

// Open parses an opened (unsealed) message and checks its signature under the key it names. That only shows the
// holder of that key signed it: Chain.Accept decides whether the key is one the tester accepted.
func Open(b []byte) (*Signed, *Payload, error) {
	var s Signed
	if err := json.Unmarshal(b, &s); err != nil || s.Key == "" || len(s.Payload) == 0 {
		return nil, nil, errors.New("not a signed message")
	}
	pub, err := hex.DecodeString(s.Key)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return nil, nil, errors.New("the signer's key isn't an Ed25519 key")
	}
	if !ed25519.Verify(pub, signed(s.Payload), s.Sig) {
		return nil, nil, errors.New("the signature doesn't verify")
	}
	var p Payload
	d := json.NewDecoder(strings.NewReader(string(s.Payload)))
	d.DisallowUnknownFields()
	if err := d.Decode(&p); err != nil {
		return nil, nil, fmt.Errorf("payload: %w", err)
	}
	return &s, &p, nil
}

// KeyState is an accepted key: the boot and start its quote bound, and the last seq taken from it.
type KeyState struct {
	Boot  string `json:"boot"`
	Start int    `json:"start"`
	Last  int    `json:"last"`
}

// Chain is what the tester has accepted for one run (cmd/e2e keeps it in DIR/chain.json).
type Chain struct {
	Run  string               `json:"run"`
	Keys map[string]*KeyState `json:"keys"` // by public key, hex
}

// ErrPending: the message is later than the next one expected from its key, or its key isn't accepted yet. Keep it
// and try again once the messages before it have come.
var ErrPending = errors.New("pending")

// VerifyKey checks a key message's quote: that the full verifier accepts it with nonce as its nonce. It is
// cmd/e2e's (Intel's PCS live and the overlay's policy); tests pass their own.
type VerifyKey func(a *proto.Attestation, nonce []byte) error

// Accept checks one opened message against the chain and, if it is the next one, takes it.
func (c *Chain) Accept(s *Signed, p *Payload, verify VerifyKey) error {
	if c.Keys == nil {
		c.Keys = map[string]*KeyState{}
	}
	if c.Run == "" || p.Run != c.Run {
		return fmt.Errorf("run %q, this run is %q", p.Run, c.Run)
	}
	k, known := c.Keys[s.Key]
	if p.Seq == 0 {
		if p.Title != KeyTitle {
			return fmt.Errorf("seq 0 is %q, want the key message", p.Title)
		}
		if known {
			return fmt.Errorf("REPLAY: key %s is already accepted", short(s.Key))
		}
		var kb KeyBody
		if err := json.Unmarshal(p.Body, &kb); err != nil || kb.Attestation == nil {
			return fmt.Errorf("the key message has no quote (%s)", kb.QuoteErr)
		}
		pub, _ := hex.DecodeString(s.Key)
		nonce := KeyNonce(p.Run, p.Boot, p.Start, pub)
		if kb.Attestation.Version != proto.VersionAgent || kb.Attestation.Nonce != hex.EncodeToString(nonce) {
			return errors.New("the key message's quote isn't for this key, run, boot and start")
		}
		if err := verify(kb.Attestation, nonce); err != nil {
			return fmt.Errorf("the key message's quote: %w", err)
		}
		for _, o := range c.Keys {
			if o.Boot == p.Boot && o.Start == p.Start {
				return fmt.Errorf("REPLAY: boot %s start %d already has a key", short(p.Boot), p.Start)
			}
		}
		c.Keys[s.Key] = &KeyState{Boot: p.Boot, Start: p.Start}
		return nil
	}
	if p.Title == KeyTitle || p.Seq < 0 {
		return fmt.Errorf("seq %d is %q", p.Seq, p.Title)
	}
	if !known {
		return fmt.Errorf("%w: key %s isn't accepted (yet)", ErrPending, short(s.Key))
	}
	if p.Boot != k.Boot || p.Start != k.Start {
		return fmt.Errorf("boot %s start %d, the key's quote bound boot %s start %d", short(p.Boot), p.Start, short(k.Boot), k.Start)
	}
	switch {
	case p.Seq <= k.Last:
		return fmt.Errorf("REPLAY or reordered: seq %d, already took up to %d from this key", p.Seq, k.Last)
	case p.Seq > k.Last+1:
		return fmt.Errorf("%w: seq %d, waiting for %d", ErrPending, p.Seq, k.Last+1)
	}
	k.Last = p.Seq
	return nil
}

// Verified checks that a message the chain took earlier (as cmd/e2e stored it) is signed by an accepted key, of
// this run, the key's boot and start, and not later than what the chain took from it.
func (c *Chain) Verified(b []byte) (*Payload, error) {
	s, p, err := Open(b)
	if err != nil {
		return nil, err
	}
	k, ok := c.Keys[s.Key]
	switch {
	case !ok:
		return nil, fmt.Errorf("key %s isn't an accepted one", short(s.Key))
	case p.Run != c.Run || p.Boot != k.Boot || p.Start != k.Start:
		return nil, errors.New("not of this run, or not of its key's boot and start")
	case p.Seq < 1 || p.Seq > k.Last:
		return nil, fmt.Errorf("seq %d wasn't taken from this key", p.Seq)
	}
	return p, nil
}

func short(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}
