package queue

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Review 2, M3: the marker's heartbeat. A queue whose last heartbeat is within StaleAfter of this process's start
// (a container restart) is taken up with its boot; one left longer (another release held the VM in between, then a
// roll forward in the same kernel boot), or with no heartbeat at all, is wiped and gets a new boot, so its tasks
// answer task_unknown_after_restart and none resumes. Beat keeps a long-running process's queue fresh.
func TestTmpfsHeartbeat(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "tasks")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	t0 := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)
	at := func(now time.Time) Tmpfs {
		return Tmpfs{Dir: dir, IsMemory: func(string) (bool, error) { return true, nil }, BootID: func() (string, error) { return "k1", nil },
			Started: now, Now: func() time.Time { return now }}
	}
	open := func(now time.Time) (*Store, string) {
		t.Helper()
		s, boot, err := OpenTmpfs(at(now))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { s.Close() })
		return s, boot
	}
	q1, boot1 := open(t0)
	if err := q1.AddTask("tk_aaaaaaaaaaaaaaaaaaaaaaaaaa", []byte(`{}`), []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	q1.Close()
	// A container restart a minute later: the same queue, its task still there.
	q2, boot2 := open(t0.Add(time.Minute))
	if boot2 != boot1 {
		t.Fatalf("a restart after a minute: boot %q, want %q", boot2, boot1)
	}
	if open, _ := q2.OpenTasks(); len(open) != 1 {
		t.Fatalf("a restart after a minute: %d open tasks, want 1", len(open))
	}
	q2.Close()
	// The second process runs on and beats; it stops at +9 min; the next opens at +10 min: fresh.
	if err := at(t0.Add(9 * time.Minute)).Beat(boot1); err != nil {
		t.Fatal(err)
	}
	q3, boot3 := open(t0.Add(10 * time.Minute))
	if boot3 != boot1 {
		t.Fatalf("a restart a minute after the last heartbeat: boot %q, want %q", boot3, boot1)
	}
	q3.Close()
	// Nothing beats for an hour (a rollback to a release without -tasks-dir), then a roll forward: wiped.
	q4, boot4 := open(t0.Add(70 * time.Minute))
	if boot4 == boot1 || boot4 == "" {
		t.Fatalf("after an hour without a heartbeat: boot %q (was %q)", boot4, boot1)
	}
	if open, _ := q4.OpenTasks(); len(open) != 0 {
		t.Fatalf("after an hour without a heartbeat: %d open tasks, want 0 (never resumed)", len(open))
	}
	q4.Close()
	// A marker with no heartbeat (written before it): stale.
	if err := os.WriteFile(filepath.Join(dir, tmpfsMarker), []byte("kernel=k1 queue="+boot4+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, boot5 := open(t0.Add(71 * time.Minute)); boot5 == boot4 {
		t.Fatal("a marker without a heartbeat was taken up")
	}
}
