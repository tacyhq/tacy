package queue

import (
	"os"
	"path/filepath"
	"testing"

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
