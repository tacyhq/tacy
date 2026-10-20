package queue

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/tacyhq/tacy/approval"
	"github.com/tacyhq/tacy/approval/approvaltest"
	"github.com/tacyhq/tacy/trigger"
)

func openSide(t *testing.T, path string) *Side {
	s, err := OpenSide(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestSideApprovals(t *testing.T) {
	approvaltest.RunStore(t, func(t *testing.T) approval.Store { return openSide(t, filepath.Join(t.TempDir(), "side.db")) })
}

func TestSideTriggers(t *testing.T) {
	trigger.RunStoreTests(t, openSide(t, filepath.Join(t.TempDir(), "side.db")))
}

// What the side file holds survives a restart (closing and opening it again), and the queue's own file stays at the
// schema version an older release knows (a rollback opens it; it never opens the side file).
func TestSideSurvivesRestartAndLeavesTheQueueAlone(t *testing.T) {
	dir := t.TempDir()
	q, err := Open(filepath.Join(dir, "queue.db"))
	if err != nil {
		t.Fatal(err)
	}
	var v int
	q.db.QueryRow(`PRAGMA user_version`).Scan(&v)
	q.Close()
	if v != 3 {
		t.Fatalf("queue schema %d: the side file must not migrate the queue file (v0.8.x refuses a newer one)", v)
	}
	path := filepath.Join(dir, "side.db")
	s, err := OpenSide(path)
	if err != nil {
		t.Fatal(err)
	}
	exp := time.Now().Add(time.Hour).UTC().Truncate(time.Millisecond)
	s.PutApproval(approval.Record{ID: "ap_x", Task: "tk_x", Request: "r", Action: "sink.post", Effect: []byte(`{}`), EffectHash: "h",
		Approvers: []string{"i_a", "i_b"}, ExpiresAt: exp})
	s.MoveApproval("ap_x", approval.StateHeld, approval.StateApproved, []byte(`{"p":1}`))
	s.MoveApproval("ap_x", approval.StateApproved, approval.StateSending, nil)
	s.SetFired("tr_1", 7)
	s.SetHighWater(exp)
	s.Close()
	s2 := openSide(t, path)
	r, err := s2.Approval("ap_x")
	if err != nil || r == nil || r.State != approval.StateSending || !r.ExpiresAt.Equal(exp) || len(r.Approvers) != 2 || string(r.Decision) != `{"p":1}` {
		t.Fatalf("after restart: %+v %v", r, err)
	}
	if rs, _ := s2.Approvals(approval.StateSending); len(rs) != 1 {
		t.Fatalf("sending: %+v", rs)
	}
	if slot, ok, _ := s2.LastFired("tr_1"); !ok || slot != 7 {
		t.Fatal("fired lost")
	}
	if hw, _ := s2.HighWater(); !hw.Equal(exp) {
		t.Fatalf("high water %v", hw)
	}
}

func TestSidePersonal(t *testing.T) {
	s := openSide(t, filepath.Join(t.TempDir(), "side.db"))
	trigger.RunPersonalStoreTests(t, s, s)
}
