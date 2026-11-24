// Package sealstate is the only code in the agent VM allowed to write lasting state (the keys plan §3.2;
// internal/nowrite_test.go enforces it). Nothing the VM keeps may sit under a provider's key ("Keys: never
// a provider's"): every blob is sealed here under a key from the Tacy key service before it leaves the process, and
// it is stored outside the VM (the relay backend: the chat Worker's R2), so a fresh CVM, a new app id or a standby
// finds it again and Phala's disk never holds it.
//
// A blob is
//
//	"TACYSEAL1" ‖ u16 len(name) ‖ name ‖ u64 gen ‖ nonce (12) ‖ AES-256-GCM(k, nonce, plaintext, aad)
//	k   = HKDF-SHA256(state key, salt "", info "tacy/sealstate/v1" ‖ 0 ‖ name), 32 bytes
//	aad = "TACYSEAL1" ‖ 0 ‖ name ‖ 0 ‖ decimal(gen) ‖ 0 ‖ binding
//
// (integers big-endian). The state key is the key service's purpose state/v1 (conn/v1 for vaultd's connections),
// the binding the key service's app name (the same on every instance, release and boot of the app, so a new boot
// opens what the last one sealed; it is not the lease id): a blob opens only under the key and binding it was sealed
// with, under its own name and generation. Each save raises the generation by one; a load refuses a generation below
// the highest this Store saw or was told (Floor), and a backend refuses a put whose previous generation isn't the
// one it holds.
//
// With the key service's generation register (Register, the keys plan §2.4) a save reserves its generation there first
// and stores the blob only then, so a blob nobody reserved (a stale instance's) never counts; a load accepts only the
// register's generation with its hash (or the one before, with its hash, when the last reservation was never
// stored). A refusal from the register or a conflict at the backend means another instance holds the state: the
// Store stops (ErrFailed) and its process must stop serving.
package sealstate

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"sync"
)

// Magic starts every sealed blob (and so every file the VM's state may leave).
const Magic = "TACYSEAL1"

const (
	keyInfo  = "tacy/sealstate/v1"
	nonceLen = 12
	// MaxBlob bounds a blob (a side.db snapshot with a month of schedules' results). The relay backend carries it
	// as one gatewayd fixed call (gateway.MaxFixedBody) and the Worker takes at most this much (vm-state.ts).
	MaxBlob = 10 << 20
)

// Errors.
var (
	ErrNotFound = errors.New("sealstate: no such state")
	ErrConflict = errors.New("sealstate: the stored generation isn't the one this save follows")
	ErrSealed   = errors.New("sealstate: the blob didn't open (another key, lease, name or generation, or tampered)")
	ErrRollback = errors.New("sealstate: the blob is older than a generation already seen")
	ErrName     = errors.New("sealstate: bad state name")
	// ErrRefused: the register refused a reservation (another lease, or another generation): wrap it in a Register.
	ErrRefused = errors.New("sealstate: the register refused")
	// ErrFailed: the Store stopped after a refused reservation or a conflict; nothing more is saved.
	ErrFailed = errors.New("sealstate: stopped: another instance holds this state, or its lease is gone")
)

// nameRe: state names are short and plain (they are paths at the relay).
var nameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)

// ValidName reports whether name may name a state.
func ValidName(name string) bool { return nameRe.MatchString(name) }

func subkey(stateKey []byte, name string) ([]byte, error) {
	if len(stateKey) < 32 {
		return nil, errors.New("sealstate: the state key must be at least 32 bytes")
	}
	return hkdf.Key(sha256.New, stateKey, nil, keyInfo+"\x00"+name, 32)
}

func aad(name string, gen uint64, lease string) []byte {
	return []byte(Magic + "\x00" + name + "\x00" + strconv.FormatUint(gen, 10) + "\x00" + lease)
}

// Seal seals plaintext as generation gen of state name.
func Seal(stateKey []byte, lease, name string, gen uint64, plaintext []byte) ([]byte, error) {
	if !ValidName(name) {
		return nil, ErrName
	}
	k, err := subkey(stateKey, name)
	if err != nil {
		return nil, err
	}
	defer clear(k)
	block, err := aes.NewCipher(k)
	if err != nil {
		return nil, err
	}
	g, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	head := make([]byte, 0, len(Magic)+2+len(name)+8+nonceLen)
	head = append(head, Magic...)
	head = binary.BigEndian.AppendUint16(head, uint16(len(name)))
	head = append(head, name...)
	head = binary.BigEndian.AppendUint64(head, gen)
	nonce := make([]byte, nonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	head = append(head, nonce...)
	out := g.Seal(head, nonce, plaintext, aad(name, gen, lease))
	if len(out) > MaxBlob {
		return nil, fmt.Errorf("sealstate: %s would be %d bytes (at most %d)", name, len(out), MaxBlob)
	}
	return out, nil
}

// Header reads a blob's name and generation without opening it (what the relay may check).
func Header(blob []byte) (name string, gen uint64, err error) {
	if len(blob) < len(Magic)+2 || string(blob[:len(Magic)]) != Magic {
		return "", 0, ErrSealed
	}
	n := int(binary.BigEndian.Uint16(blob[len(Magic):]))
	off := len(Magic) + 2
	if len(blob) < off+n+8+nonceLen+16 {
		return "", 0, ErrSealed
	}
	name = string(blob[off : off+n])
	if !ValidName(name) {
		return "", 0, ErrSealed
	}
	return name, binary.BigEndian.Uint64(blob[off+n:]), nil
}

// Open opens a blob of state name and returns its generation and plaintext.
func Open(stateKey []byte, lease, name string, blob []byte) (uint64, []byte, error) {
	got, gen, err := Header(blob)
	if err != nil || got != name {
		return 0, nil, ErrSealed
	}
	k, err := subkey(stateKey, name)
	if err != nil {
		return 0, nil, err
	}
	defer clear(k)
	block, err := aes.NewCipher(k)
	if err != nil {
		return 0, nil, err
	}
	g, err := cipher.NewGCM(block)
	if err != nil {
		return 0, nil, err
	}
	off := len(Magic) + 2 + len(name) + 8
	pt, err := g.Open(nil, blob[off:off+nonceLen], blob[off+nonceLen:], aad(name, gen, lease))
	if err != nil {
		return 0, nil, ErrSealed
	}
	return gen, pt, nil
}

// Backend stores blobs by name. It sees only ciphertext.
type Backend interface {
	// Get returns the blob stored as name (ErrNotFound when there is none).
	Get(ctx context.Context, name string) ([]byte, error)
	// Put stores blob as name if the generation it holds now is prev (0: none yet), else ErrConflict.
	Put(ctx context.Context, name string, blob []byte, prev uint64) error
}

// Entry is a register entry: the generation last reserved, its blob's hash, whether it is stored, and the hash of
// the generation before it.
type Entry struct {
	Gen    uint64
	Hash   string
	Prev   string
	Stored bool
}

// Register is the key service's generation register (the keys plan §2.4, PX-11): name -> the generation last reserved
// and its blob's sha256, signed by the KMS id over the caller's nonce (the client checks it). With one, a Store
// reserves each generation before it stores the blob and marks it stored after, and refuses a blob that isn't the
// register's, so the Backend's operator can't hand back an old state and a stale instance can't add one.
// Reserve and Stored wrap ErrRefused when the register said no (as opposed to not answering).
type Register interface {
	Generation(ctx context.Context, name string) (Entry, error)
	Reserve(ctx context.Context, name string, gen uint64, hash string) error
	Stored(ctx context.Context, name string, gen uint64, hash string) error
}

// Store seals and opens named states on a Backend, keeping each name's generation.
type Store struct {
	b       Backend
	key     []byte
	binding string
	reg     Register // nil: no register (tests, local runs)

	saveMu  sync.Mutex // one save at a time (each follows the generation the last one stored)
	mu      sync.Mutex
	gens    map[string]uint64 // the generation stored last (loaded or saved)
	pending map[string]commit // stored at the Backend but not yet marked stored at the register
	failed  error
}

type commit struct {
	gen  uint64
	hash string
}

// BlobHash is a blob's sha256, hex: what the register keeps.
func BlobHash(blob []byte) string {
	h := sha256.Sum256(blob)
	return hex.EncodeToString(h[:])
}

// WithRegister makes s check every load against r and reserve every save there.
func (s *Store) WithRegister(r Register) *Store {
	s.reg = r
	return s
}

// New makes a Store sealing under stateKey (copied) and binding (the key service's app name).
func New(b Backend, stateKey []byte, binding string) (*Store, error) {
	if len(stateKey) < 32 {
		return nil, errors.New("sealstate: the state key must be at least 32 bytes")
	}
	return &Store{b: b, key: append([]byte(nil), stateKey...), binding: binding, gens: map[string]uint64{}, pending: map[string]commit{}}, nil
}

// Floor raises name's lowest acceptable generation: a blob below it is refused.
func (s *Store) Floor(name string, gen uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if gen > s.gens[name] {
		s.gens[name] = gen
	}
}

// Gen is the generation of name this Store loaded or saved last.
func (s *Store) Gen(name string) uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.gens[name]
}

// Failed is why the Store stopped (wrapping ErrFailed), or nil.
func (s *Store) Failed() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.failed
}

func (s *Store) fail(err error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failed == nil {
		s.failed = fmt.Errorf("%w: %w", ErrFailed, err)
	}
	return s.failed
}

// Load opens the stored state name: nil and no error when there is none yet.
func (s *Store) Load(ctx context.Context, name string) ([]byte, error) {
	if !ValidName(name) {
		return nil, ErrName
	}
	var e Entry
	if s.reg != nil {
		var err error
		if e, err = s.reg.Generation(ctx, name); err != nil {
			return nil, fmt.Errorf("sealstate: register %s: %w", name, err)
		}
	}
	blob, err := s.b.Get(ctx, name)
	if errors.Is(err, ErrNotFound) {
		// The register says it was stored: a backend that lost or withheld it is a rollback. A first reservation
		// that never got stored is no state yet.
		if s.reg != nil && e.Gen > 0 && !(e.Gen == 1 && !e.Stored) {
			return nil, fmt.Errorf("%w: %s generation %d is in the register but the backend has none", ErrRollback, name, e.Gen)
		}
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	gen, pt, err := Open(s.key, s.binding, name, blob)
	if err != nil {
		return nil, err
	}
	if s.reg != nil {
		h := BlobHash(blob)
		switch {
		case gen == e.Gen && h == e.Hash:
			if !e.Stored { // stored before the last process could say so
				if err := s.reg.Stored(ctx, name, gen, h); err != nil {
					clear(pt)
					return nil, fmt.Errorf("sealstate: register %s: %w", name, err)
				}
			}
		case !e.Stored && gen+1 == e.Gen && h == e.Prev && e.Prev != "":
			// The last save reserved e.Gen and stopped before storing it: this is the generation before, by its hash.
			// The next save reserves e.Gen again.
		default:
			clear(pt)
			return nil, fmt.Errorf("%w: %s is generation %d, the register %d", ErrRollback, name, gen, e.Gen)
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if gen < s.gens[name] {
		clear(pt)
		return nil, ErrRollback
	}
	s.gens[name] = gen
	return pt, nil
}

// Save seals plaintext as name's next generation and stores it: with a register, reserved there first, and marked
// stored after. A refused reservation or a conflict at the backend stops the Store (ErrFailed): another instance
// has the state now, and this one must not go on as if it had saved.
func (s *Store) Save(ctx context.Context, name string, plaintext []byte) error {
	s.saveMu.Lock()
	defer s.saveMu.Unlock()
	if err := s.Failed(); err != nil {
		return err
	}
	s.mu.Lock()
	prev := s.gens[name]
	pend, hasPend := s.pending[name]
	s.mu.Unlock()
	if hasPend { // the last save's "stored" mark didn't get through: it goes first (the register wants it)
		if err := s.reg.Stored(ctx, name, pend.gen, pend.hash); err != nil {
			if errors.Is(err, ErrRefused) {
				return s.fail(err)
			}
			return fmt.Errorf("sealstate: register %s: %w", name, err)
		}
		s.mu.Lock()
		delete(s.pending, name)
		s.mu.Unlock()
	}
	blob, err := Seal(s.key, s.binding, name, prev+1, plaintext)
	if err != nil {
		return err
	}
	h := BlobHash(blob)
	if s.reg != nil {
		if err := s.reg.Reserve(ctx, name, prev+1, h); err != nil {
			if errors.Is(err, ErrRefused) {
				return s.fail(err)
			}
			return fmt.Errorf("sealstate: register %s: %w", name, err) // not answered: nothing stored, try again
		}
	}
	if err := s.b.Put(ctx, name, blob, prev); err != nil {
		if errors.Is(err, ErrConflict) {
			return s.fail(err)
		}
		return err // the reservation stands; the next save reserves the same generation again
	}
	s.mu.Lock()
	if s.gens[name] == prev {
		s.gens[name] = prev + 1
	}
	s.mu.Unlock()
	if s.reg != nil {
		if err := s.reg.Stored(ctx, name, prev+1, h); err != nil {
			if errors.Is(err, ErrRefused) {
				return s.fail(err)
			}
			// Stored, not marked: the next save (or the next boot's load) marks it first.
			s.mu.Lock()
			s.pending[name] = commit{gen: prev + 1, hash: h}
			s.mu.Unlock()
		}
	}
	return nil
}

// Stale says whether any of names is stored at the backend at another generation than the one this Store loaded or
// saved last: another instance saved it since (a standby VM taking the writer lease must load again first,
// app/lease.go). An error (the backend didn't answer, a blob out of form): unknown, don't take over.
func (s *Store) Stale(ctx context.Context, names []string) (bool, error) {
	for _, name := range names {
		blob, err := s.b.Get(ctx, name)
		var gen uint64
		switch {
		case errors.Is(err, ErrNotFound):
		case err != nil:
			return false, fmt.Errorf("sealstate: %s: %w", name, err)
		default:
			n, g, err := Header(blob)
			if err != nil || n != name {
				return false, fmt.Errorf("sealstate: %s: a blob out of form", name)
			}
			gen = g
		}
		if gen != s.Gen(name) {
			return true, nil
		}
	}
	return false, nil
}

// Pending is how many saves are stored but not yet marked stored at the register.
func (s *Store) Pending() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.pending)
}

// Backend is where s keeps its blobs (tests: a second Store on the same backend).
func (s *Store) Backend() Backend { return s.b }
