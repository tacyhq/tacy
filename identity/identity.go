// Package identity is what the VM knows about people for signed definitions and approvals (docs/27 sections 3 and 4): ids in
// the id format, Ed25519 identity keys as the key log names them ("ed25519:<base64>"), and the Directory that says
// whether an identity is current and holds a space.
//
// The real Directory is the firm key log and the space log (keys v2's key log and spaces; the keylog package on
// their branch). Until that merges, nothing in the VM's mains sets one, so every check that needs a person's
// signature (a sponsor, an approver) fails closed. Static is the in-memory one tests and local development use.
// Standard library only.
package identity

import (
	"crypto/ed25519"
	"encoding/base32"
	"encoding/base64"
	"errors"
	"strings"
	"sync"
)

var idEncoding = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)

// ValidID reports whether s is "<prefix>_" plus 26 lowercase base32 characters encoding 128 bits canonically
// (ids: i_ identity, s_ space, f_ firm, a_ agent, tr_ trigger, ap_ approval).
func ValidID(prefix, s string) bool {
	rest, ok := strings.CutPrefix(s, prefix+"_")
	if !ok || len(rest) != 26 {
		return false
	}
	b, err := idEncoding.DecodeString(rest)
	return err == nil && len(b) == 16 && idEncoding.EncodeToString(b) == rest
}

// IDFrom makes "<prefix>_" + the base32 of the first 16 bytes of b (b must have at least 16).
func IDFrom(prefix string, b []byte) string { return prefix + "_" + idEncoding.EncodeToString(b[:16]) }

// KeyString is an Ed25519 public key as the key log and signed documents name it.
func KeyString(pub ed25519.PublicKey) string {
	return "ed25519:" + base64.StdEncoding.EncodeToString(pub)
}

// ParseKey reads "ed25519:<base64 of 32 bytes>".
func ParseKey(s string) (ed25519.PublicKey, error) {
	b64, ok := strings.CutPrefix(s, "ed25519:")
	if !ok {
		return nil, errors.New("identity: key must be ed25519:<base64>")
	}
	b, err := base64.StdEncoding.DecodeString(b64)
	if err != nil || len(b) != ed25519.PublicKeySize || base64.StdEncoding.EncodeToString(b) != b64 {
		return nil, errors.New("identity: bad ed25519 key")
	}
	return ed25519.PublicKey(b), nil
}

// Errors a Directory returns. Callers treat every error the same (refuse); the kinds are for logs and tests.
var (
	ErrUnknown   = errors.New("identity: not in the firm's key log")
	ErrRevoked   = errors.New("identity: revoked")
	ErrNotHolder = errors.New("identity: doesn't hold the space")
)

// Directory says who is current: an identity in the firm's key log, not revoked, holding the space now.
type Directory interface {
	// Key returns identity id's Ed25519 key if it is current in firm and holds space; an error otherwise.
	Key(firm, space, id string) (ed25519.PublicKey, error)
}

// Static is an in-memory Directory: tests and local development. Safe for concurrent use.
type Static struct {
	mu      sync.Mutex
	keys    map[string]ed25519.PublicKey // firm\x00id
	holds   map[string]bool              // firm\x00space\x00id
	revoked map[string]bool              // firm\x00id
}

func (s *Static) init() {
	if s.keys == nil {
		s.keys, s.holds, s.revoked = map[string]ed25519.PublicKey{}, map[string]bool{}, map[string]bool{}
	}
}

// Add makes id current in firm with pub, holding each of spaces.
func (s *Static) Add(firm, id string, pub ed25519.PublicKey, spaces ...string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.init()
	s.keys[firm+"\x00"+id] = pub
	delete(s.revoked, firm+"\x00"+id)
	for _, sp := range spaces {
		s.holds[firm+"\x00"+sp+"\x00"+id] = true
	}
}

// Revoke revokes id in firm (a key log identity.revoke).
func (s *Static) Revoke(firm, id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.init()
	s.revoked[firm+"\x00"+id] = true
}

// Leave removes id from space (a space log remove).
func (s *Static) Leave(firm, space, id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.init()
	delete(s.holds, firm+"\x00"+space+"\x00"+id)
}

// Key is Directory.Key.
func (s *Static) Key(firm, space, id string) (ed25519.PublicKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.init()
	k := s.keys[firm+"\x00"+id]
	switch {
	case k == nil:
		return nil, ErrUnknown
	case s.revoked[firm+"\x00"+id]:
		return nil, ErrRevoked
	case !s.holds[firm+"\x00"+space+"\x00"+id]:
		return nil, ErrNotHolder
	}
	return k, nil
}
