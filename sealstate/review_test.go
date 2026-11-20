package sealstate

// Regression tests for the security review's M4 (2026-11-20): a stale instance's blob never counts, a refused
// reservation or a conflict stops the Store, and a save that stopped between its reservation and its put recovers.

import (
	"context"
	"errors"
	"fmt"
	"testing"
)

// fakeReg is the key service's register as kmsd keeps it: one lease may reserve; reservations before stores.
type fakeReg struct {
	e      map[string]Entry
	holder string // the lease allowed to reserve
	down   bool   // not answering
}

func newFakeReg(holder string) *fakeReg { return &fakeReg{e: map[string]Entry{}, holder: holder} }

func (r *fakeReg) as(lease string) Register { return regAs{r, lease} }

type regAs struct {
	r     *fakeReg
	lease string
}

func (a regAs) Generation(_ context.Context, name string) (Entry, error) {
	if a.r.down {
		return Entry{}, errors.New("unreachable")
	}
	e, ok := a.r.e[name]
	if !ok {
		e.Stored = true
	}
	return e, nil
}

func (a regAs) Reserve(_ context.Context, name string, gen uint64, hash string) error {
	if a.r.down {
		return errors.New("unreachable")
	}
	if a.lease != a.r.holder {
		return fmt.Errorf("%w: commit needs the holder's live lease", ErrRefused)
	}
	cur, ok := a.r.e[name]
	if !ok {
		cur.Stored = true
	}
	switch {
	case cur.Stored && gen == cur.Gen+1:
		a.r.e[name] = Entry{Gen: gen, Hash: hash, Prev: cur.Hash}
	case !cur.Stored && gen == cur.Gen:
		a.r.e[name] = Entry{Gen: gen, Hash: hash, Prev: cur.Prev}
	default:
		return fmt.Errorf("%w: generation %d", ErrRefused, gen)
	}
	return nil
}

func (a regAs) Stored(_ context.Context, name string, gen uint64, hash string) error {
	if a.r.down {
		return errors.New("unreachable")
	}
	if a.lease != a.r.holder {
		return fmt.Errorf("%w: lease", ErrRefused)
	}
	cur := a.r.e[name]
	if cur.Gen != gen || cur.Hash != hash {
		return fmt.Errorf("%w: not the reserved one", ErrRefused)
	}
	cur.Stored = true
	a.r.e[name] = cur
	return nil
}

// The review's scenario: A loses the lease (its renewals blocked) and keeps going; B gets the lease. A's saves are
// refused at the register before anything is stored, so A stops, B's saves land, and B's next boot loads B's state.
func TestReviewM4StaleInstanceStops(t *testing.T) {
	ctx := context.Background()
	be, reg := &Mem{}, newFakeReg("A")
	a, _ := New(be, key, "agent-vm")
	a.WithRegister(reg.as("A"))
	if err := a.Save(ctx, "safety", []byte("v1 by A")); err != nil {
		t.Fatal(err)
	}
	reg.holder = "B" // A's lease lapsed; B holds it
	b, _ := New(be, key, "agent-vm")
	b.WithRegister(reg.as("B"))
	if pt, err := b.Load(ctx, "safety"); err != nil || string(pt) != "v1 by A" {
		t.Fatalf("B's load: %q %v", pt, err)
	}
	err := a.Save(ctx, "safety", []byte("v2 by stale A"))
	if !errors.Is(err, ErrFailed) || !errors.Is(err, ErrRefused) {
		t.Fatalf("stale A's save: %v", err)
	}
	if b2, _ := be.Get(ctx, "safety"); string(mustOpen(t, b2)) != "v1 by A" {
		t.Fatal("a refused reservation still stored a blob")
	}
	if err := a.Save(ctx, "safety", []byte("v3")); !errors.Is(err, ErrFailed) {
		t.Fatalf("a stopped store saved again: %v", err)
	}
	if err := b.Save(ctx, "safety", []byte("v2 by B")); err != nil {
		t.Fatal(err)
	}
	c, _ := New(be, key, "agent-vm")
	c.WithRegister(reg.as("B"))
	if pt, err := c.Load(ctx, "safety"); err != nil || string(pt) != "v2 by B" {
		t.Fatalf("the next boot: %q %v", pt, err)
	}
}

// A conflict at the backend (someone else stored this generation) stops the Store too.
func TestReviewM4ConflictStops(t *testing.T) {
	ctx := context.Background()
	be := &Mem{}
	a, _ := New(be, key, "agent-vm")
	b, _ := New(be, key, "agent-vm")
	a.Save(ctx, "side", []byte("1"))
	b.Load(ctx, "side")
	b.Save(ctx, "side", []byte("2 by b"))
	if err := a.Save(ctx, "side", []byte("2 by a")); !errors.Is(err, ErrFailed) || !errors.Is(err, ErrConflict) {
		t.Fatalf("a conflict: %v", err)
	}
	if a.Failed() == nil {
		t.Fatal("the store goes on after a conflict")
	}
}

// A save that reserved and then didn't store (its put failed, or the process stopped) is recovered: the next boot
// loads the generation before by its hash and reserves the same generation again. A register that doesn't answer
// stores nothing and stops nothing.
func TestReviewM4ReserveThenCrash(t *testing.T) {
	ctx := context.Background()
	be, reg := &Mem{}, newFakeReg("A")
	a, _ := New(be, key, "agent-vm")
	a.WithRegister(reg.as("A"))
	a.Save(ctx, "side", []byte("one"))
	// The process stops after reserving generation 2: it never reached the backend.
	blob, _ := Seal(key, "agent-vm", "side", 2, []byte("two, lost"))
	reg.as("A").Reserve(ctx, "side", 2, BlobHash(blob))
	b, _ := New(be, key, "agent-vm")
	b.WithRegister(reg.as("A"))
	if pt, err := b.Load(ctx, "side"); err != nil || string(pt) != "one" {
		t.Fatalf("after a reserved, unstored generation: %q %v", pt, err)
	}
	if err := b.Save(ctx, "side", []byte("two")); err != nil {
		t.Fatalf("reserving 2 again: %v", err)
	}
	if e := reg.e["side"]; e.Gen != 2 || !e.Stored {
		t.Fatalf("register %+v", e)
	}
	// But the generation before, served when the register says 2 is stored, is a rollback.
	old := &Mem{}
	ob, _ := Seal(key, "agent-vm", "side", 1, []byte("one"))
	old.Put(ctx, "side", ob, 0)
	c, _ := New(old, key, "agent-vm")
	c.WithRegister(reg.as("A"))
	if _, err := c.Load(ctx, "side"); !errors.Is(err, ErrRollback) {
		t.Fatalf("generation 1 under a stored 2: %v", err)
	}
	// The register is down: nothing is stored, the store goes on, and the next try works.
	reg.down = true
	if err := b.Save(ctx, "side", []byte("three")); err == nil || errors.Is(err, ErrFailed) {
		t.Fatalf("a save with the register down: %v", err)
	}
	if _, g, _ := Header(be.blobs["side"]); g != 2 {
		t.Fatalf("stored generation %d without a reservation", g)
	}
	reg.down = false
	if err := b.Save(ctx, "side", []byte("three")); err != nil {
		t.Fatal(err)
	}
}

func mustOpen(t *testing.T, blob []byte) []byte {
	t.Helper()
	_, pt, err := Open(key, "agent-vm", "safety", blob)
	if err != nil {
		t.Fatal(err)
	}
	return pt
}
