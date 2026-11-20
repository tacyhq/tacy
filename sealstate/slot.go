package sealstate

import (
	"bytes"
	"sync"
)

// Slot is one document kept in memory and saved by a Keeper: what a store that writes its whole state at once (the
// safety floors, the budgets' day counters, the notification switches, vaultd's connections) saves into instead of
// a file. Save never blocks on the backend; the Keeper saves within a second, and on SIGTERM.
type Slot struct {
	mu sync.Mutex
	b  []byte
	v  uint64
}

// NewSlot is a Slot holding what was loaded (nil: nothing yet).
func NewSlot(loaded []byte) *Slot { return &Slot{b: bytes.Clone(loaded)} }

// Load is the document (nil: nothing yet).
func (s *Slot) Load() ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return bytes.Clone(s.b), nil
}

// Save replaces the document.
func (s *Slot) Save(b []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	clear(s.b)
	s.b = bytes.Clone(b)
	s.v++
	return nil
}

func (s *Slot) Version() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.v
}

func (s *Slot) Snapshot() ([]byte, error) { return s.Load() }
