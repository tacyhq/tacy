package queue

import (
	"bytes"
	"testing"
	"time"

	"github.com/tacyhq/tacy/approval"
	"github.com/tacyhq/tacy/approval/approvaltest"
	"github.com/tacyhq/tacy/trigger"
)

func memSide(t *testing.T, snap []byte) *Side {
	t.Helper()
	s, err := OpenSideMemory(snap)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// The memory side store passes the same store tests as the file one.
func TestSideMemoryStores(t *testing.T) {
	approvaltest.RunStore(t, func(t *testing.T) approval.Store { return memSide(t, nil) })
	trigger.RunCollectStoreTests(t, memSide(t, nil))
	trigger.RunHandoffStoreTests(t, memSide(t, nil))
}

// A snapshot carries holders and memory to a new store; Version moves with each write and not with reads.
func TestSideMemorySnapshot(t *testing.T) {
	s := memSide(t, nil)
	v0 := s.Version()
	at := time.Now().UTC().Truncate(time.Millisecond)
	if err := s.PutHolder(trigger.Holder{Space: "s_one", Identity: "i_one", Key: "ed25519:k", Seal: "x25519:s", At: at}); err != nil {
		t.Fatal(err)
	}
	if err := s.PutMemory(trigger.Remembered{Space: "s_one", Agent: "a1", Task: "t1", Day: "2026-11-20", EndedAt: at, Text: "canary-memory"}); err != nil {
		t.Fatal(err)
	}
	v1 := s.Version()
	if v1 == v0 {
		t.Fatal("writes didn't move the version")
	}
	if _, err := s.Holder("s_one", "i_one"); err != nil || s.Version() != v1 {
		t.Fatalf("a read moved the version (%v)", err)
	}
	snap, err := s.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(snap, []byte("canary-memory")) {
		t.Fatal("the snapshot is the plaintext database (sealstate seals it)")
	}
	s2 := memSide(t, snap)
	h, err := s2.Holder("s_one", "i_one")
	if err != nil || h == nil || h.Seal != "x25519:s" {
		t.Fatalf("holder after the snapshot: %+v %v", h, err)
	}
	m, err := s2.Memories("s_one", "a1", at.Add(-time.Hour))
	if err != nil || len(m) != 1 || m[0].Text != "canary-memory" {
		t.Fatalf("memory after the snapshot: %+v %v", m, err)
	}
	if _, err := (&Side{db: s.db}).Snapshot(); err == nil {
		t.Fatal("a file store snapshotted")
	}
}
