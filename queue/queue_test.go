package queue

import (
	"database/sql"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/tacyhq/tacy/harness"
	"github.com/tacyhq/tacy/harness/conformance"
	"github.com/tacyhq/tacy/harness/storetest"
)

func open(t *testing.T) harness.Store {
	s, err := Open(filepath.Join(t.TempDir(), "q", "space.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// The Store contract, and that everything survives closing and opening the file again (a runtime restart).
func TestStore(t *testing.T) {
	storetest.Run(t, open, func(t *testing.T, s harness.Store) harness.Store {
		q := s.(*Store)
		var path string
		q.db.QueryRow(`SELECT file FROM pragma_database_list WHERE name = 'main'`).Scan(&path)
		q.Close()
		again, err := Open(path)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { again.Close() })
		return again
	})
}

func TestFileModes(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	s, err := Open(filepath.Join(dir, "space.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	for p, want := range map[string]os.FileMode{dir: 0o700 | os.ModeDir, filepath.Join(dir, "space.db"): 0o600} {
		if fi, err := os.Stat(p); err != nil || fi.Mode() != want {
			t.Errorf("%s: %v %v, want %v", p, fi.Mode(), err, want)
		}
	}
}

// The runtime engine on this store passes the hostile-brain suite.
func TestRuntimeOnSQLite(t *testing.T) {
	conformance.RunRuntime(t, func(tb testing.TB) conformance.Target {
		s, err := Open(filepath.Join(tb.TempDir(), "space.db"))
		if err != nil {
			tb.Fatal(err)
		}
		tb.Cleanup(func() { s.Close() })
		return conformance.FakeTargetOn(tb, s)
	})
}

// A queue written by the first release (schema version 1, user_version never set) is migrated in place: its open
// task and journal are still there, with the new columns' defaults; a database newer than this code is refused.
func TestMigrateFromFirstRelease(t *testing.T) {
	path := filepath.Join(t.TempDir(), "space.db")
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{migrations[0],
		`INSERT INTO tasks (id, start, options, attempt) VALUES ('t_old', '{"space":"s_chat"}', NULL, 2)`,
		`INSERT INTO journal (task, id, kind, hash, req) VALUES ('t_old', 'a1', 'action', zeroblob(32), '{}')`} {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	db.Close()
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	var v int
	s.db.QueryRow(`PRAGMA user_version`).Scan(&v)
	if v != SchemaVersion || SchemaVersion != 3 {
		t.Fatalf("user_version %d, want %d", v, SchemaVersion)
	}
	open, err := s.OpenTasks()
	if err != nil || len(open) != 1 || open[0].ID != "t_old" || open[0].Attempt != 2 || open[0].Failures != 0 ||
		open[0].State != harness.StateQueued || open[0].Taint != "" {
		t.Fatalf("open tasks after the migration: %+v %v", open, err)
	}
	recs, err := s.Journal("t_old")
	if err != nil || len(recs) != 1 || recs[0].Held != "" || recs[0].Done {
		t.Fatalf("journal after the migration: %+v %v", recs, err)
	}
	if err := s.AddEvents("t_old", []harness.StoredEvent{{Seq: 1, Data: []byte(`{}`)}}); err != nil {
		t.Fatal(err)
	}
	if err := s.SetTaint("t_old", "a1"); err != nil {
		t.Fatal(err)
	}
	s.db.Exec(`PRAGMA user_version = 99`)
	s.Close()
	if _, err := Open(path); err == nil || !strings.Contains(err.Error(), "newer") {
		t.Fatalf("a newer schema was opened: %v", err)
	}
}

// The rollback to v0.6.0 (the chat's minimum release; before the versioned schema): it never reads user_version and
// uses only the version 1 columns, which a migrated file keeps (the new ones have defaults), so it runs on the file
// as is. Checked once by hand with v0.6.0's own code (open, restore and abandon, a /run task's life); here its exact
// statements run on a file this release migrated. A task this release left open is cancelled and deleted by
// v0.6.0 at boot (in-flight tasks are lost, as after any restart of it); back on this release, Open gives the tasks
// v0.6.0 ended their state and end time and drops the events of tasks it deleted.
func TestOlderReleaseOnMigratedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "space.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"tk_open", "tk_gone"} {
		if err := s.AddTask(id, []byte(`{"space":"s_chat"}`), nil); err != nil {
			t.Fatal(err)
		}
		s.SetState(id, harness.StateRunning, "")
		s.SetTaint(id, "s1.a0")
		s.AddEvents(id, []harness.StoredEvent{{Seq: 1, Data: []byte(`{}`)}})
	}
	s.Close()
	// v0.6.0's queue.go, statement for statement (its schema, AddTask, SetAttempt, Begin, Finish, EndTask, OpenTasks,
	// DeleteTask).
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{migrations[0],
		`UPDATE tasks SET ended = 1, outcome = 'cancelled' WHERE id = 'tk_gone'`,
		`DELETE FROM tasks WHERE id = 'tk_gone'`, `DELETE FROM steers WHERE task = 'tk_gone'`,
		`DELETE FROM journal WHERE task = 'tk_gone'`, `DELETE FROM checkpoints WHERE task = 'tk_gone'`,
		`INSERT INTO tasks (id, start, options) VALUES ('t_old', '{"x":1}', NULL)`,
		`UPDATE tasks SET attempt = 1 WHERE id = 't_old'`,
		`INSERT INTO journal (task, id, kind, hash, req) VALUES ('t_old', 's1.m', 'model', zeroblob(32), '{}')`,
		`UPDATE journal SET done = 1, body = '{}', err = NULL WHERE task = 't_old' AND id = 's1.m'`,
		`UPDATE tasks SET ended = 1, outcome = 'succeeded' WHERE id = 't_old'`} {
		if _, err := db.Exec(q); err != nil {
			t.Fatalf("v0.6.0's %q on a migrated file: %v", q, err)
		}
	}
	rows, err := db.Query(`SELECT id, start, options, attempt FROM tasks WHERE ended = 0 ORDER BY seq`)
	if err != nil {
		t.Fatal(err)
	}
	rows.Close()
	db.Close()
	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	old, err := s.Task("t_old")
	if err != nil || old == nil || old.State != harness.StateDone || old.Ended.IsZero() {
		t.Fatalf("a task v0.6.0 ended: %+v %v", old, err)
	}
	if before, _ := s.EndedBefore(old.Ended.Add(time.Millisecond)); !slices.Contains(before, "t_old") {
		t.Fatalf("not pruned by retention: %v", before)
	}
	var orphans int
	s.db.QueryRow(`SELECT COUNT(*) FROM events WHERE task NOT IN (SELECT id FROM tasks)`).Scan(&orphans)
	if orphans != 0 {
		t.Fatalf("%d orphaned events", orphans)
	}
	if evs, _ := s.Events("tk_open", 0, 10); len(evs) != 1 {
		t.Fatalf("a kept task's events: %v", evs)
	}
}
