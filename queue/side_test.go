package queue

import (
	"database/sql"
	"fmt"
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

func TestSideMemory(t *testing.T) {
	trigger.RunMemoryStoreTests(t, openSide(t, filepath.Join(t.TempDir(), "side.db")))
}

// A side file a v0.12.0-v0.14.0 VM wrote (schema 2: a person's daily schedule, its fired slot, a result waiting)
// opens on this release as it was: the definition, its state, the slot and the result read back unchanged, the result
// as not quiet; the memory table starts empty. Its schema version stays 2, so v0.14.0 still opens it after a
// rollback (TestSideRollbackOpens).
func TestSideMigratesV2Untouched(t *testing.T) {
	path := filepath.Join(t.TempDir(), "side.db")
	old, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	for v, m := range sideMigrations[:2] {
		if _, err := old.Exec(m); err != nil {
			t.Fatal(err)
		}
		old.Exec(fmt.Sprintf(`PRAGMA user_version = %d`, v+1))
	}
	env := []byte(`{"kind":"agent","payload":"e30=","sigs":[]}`)
	old.Exec(`INSERT INTO definitions (agent, version, env, state) VALUES ('a_daily', 3, ?, 'active')`, env)
	old.Exec(`INSERT INTO fired (trigger, slot) VALUES ('tr_daily', 20747)`)
	if _, err := old.Exec(`INSERT INTO results (task, space, seal, agent, version, trigger, day, scheduled_at, started_at, ended_at, state, code, enc, ct)
		VALUES ('tk_1', 's_1', 'x25519:a', 'a_daily', 3, 'tr_daily', '2026-10-21', 1, 2, 3, 'succeeded', '', x'01', x'0203')`); err != nil {
		t.Fatal(err)
	}
	old.Close()

	s := openSide(t, path)
	var v int
	s.db.QueryRow(`PRAGMA user_version`).Scan(&v)
	if v != len(sideMigrations) || v != 2 {
		t.Fatalf("schema %d", v)
	}
	defs, err := s.Definitions()
	if err != nil || len(defs) != 1 || string(defs[0].Env) != string(env) || defs[0].State != "active" {
		t.Fatalf("definitions after the migration: %+v %v", defs, err)
	}
	if slot, ok, _ := s.LastFired("tr_daily"); !ok || slot != 20747 {
		t.Fatal("the fired slot was lost")
	}
	r, err := s.GetResult("s_1", "x25519:a", "tk_1")
	if err != nil || r == nil || r.Quiet || r.State != "succeeded" || string(r.CT) != "\x02\x03" {
		t.Fatalf("result after the migration: %+v %v", r, err)
	}
	if m, _ := s.Memories("s_1", "a_daily", time.Time{}); len(m) != 0 {
		t.Fatal("memory before any run")
	}
	// A quiet result reads back quiet.
	s.PutResult(trigger.Result{Task: "tk_2", Space: "s_1", Seal: "x25519:a", Agent: "a_daily", State: "succeeded", Quiet: true, Enc: []byte{1}, CT: []byte{2}})
	if l, _ := s.Results("s_1", "x25519:a", 0, 10); len(l) != 2 || l[0].Quiet || !l[1].Quiet {
		t.Fatalf("quiet listing: %+v", l)
	}
}

// After this release opened (and wrote) the side file, the release before it can still use it: the schema version is
// still 2 (v0.14.0's OpenSide refuses a newer one, which would stop agentd after a rollback), v0.14.0's own insert
// and select of a result (its columns, without quiet) work, and opening it here again changes nothing.
func TestSideRollbackOpens(t *testing.T) {
	path := filepath.Join(t.TempDir(), "side.db")
	s := openSide(t, path)
	s.PutResult(trigger.Result{Task: "tk_q", Space: "s_1", Seal: "x25519:a", Agent: "a_daily", State: "succeeded", Quiet: true, Enc: []byte{1}, CT: []byte{2}})
	s.PutMemory(trigger.Remembered{Space: "s_1", Agent: "a_daily", Task: "tk_q", Day: "2026-10-21", EndedAt: time.Now(), Quiet: true, Text: "same"})
	s.Close()

	old, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	var v int
	old.QueryRow(`PRAGMA user_version`).Scan(&v)
	if v != 2 {
		t.Fatalf("schema %d after this release: v0.14.0 (which knows 2) would refuse the file", v)
	}
	// v0.14.0's PutResult and its result columns, word for word.
	if _, err := old.Exec(`INSERT INTO results (task, space, seal, agent, version, trigger, day, scheduled_at, started_at,
		ended_at, state, code, enc, ct) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT (task) DO NOTHING`,
		"tk_old", "s_1", "x25519:a", "a_daily", 3, "tr_daily", "2026-10-22", 1, 2, 3, "succeeded", "", []byte{1}, []byte{2}); err != nil {
		t.Fatalf("v0.14.0's insert: %v", err)
	}
	var n int
	if err := old.QueryRow(`SELECT count(*) FROM (SELECT seq, task, space, seal, agent, version, trigger, day, scheduled_at, started_at,
		ended_at, state, code, length(ct) FROM results WHERE space = ? AND seal = ?)`, "s_1", "x25519:a").Scan(&n); err != nil || n != 2 {
		t.Fatalf("v0.14.0's listing: %d %v", n, err)
	}
	old.Close()

	s = openSide(t, path)
	if l, _ := s.Results("s_1", "x25519:a", 0, 10); len(l) != 2 || !l[0].Quiet || l[1].Quiet {
		t.Fatalf("after the rollback and back: %+v", l)
	}
	if m, _ := s.Memories("s_1", "a_daily", time.Time{}); len(m) != 1 || m[0].Text != "same" {
		t.Fatalf("memory after the rollback and back: %+v", m)
	}
}
