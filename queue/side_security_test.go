package queue

import (
	"bytes"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/tacyhq/tacy/runauth"
	"github.com/tacyhq/tacy/trigger"
)

// inFiles: marker is somewhere in the side file or its write-ahead log, as bytes.
func inFiles(t *testing.T, path, marker string) bool {
	t.Helper()
	for _, f := range []string{path, path + "-wal"} {
		b, err := os.ReadFile(f)
		if err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
		if bytes.Contains(b, []byte(marker)) {
			return true
		}
	}
	return false
}

// oldSide writes a side file as v0.12.0-v0.15.0 left it (schema 2, no extras), with stmts run on it.
func oldSide(t *testing.T, path string, stmts ...string) {
	t.Helper()
	old, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	defer old.Close()
	for v, m := range sideMigrations[:2] {
		if _, err := old.Exec(m); err != nil {
			t.Fatal(err)
		}
		old.Exec(fmt.Sprintf(`PRAGMA user_version = %d`, v+1))
	}
	for _, s := range stmts {
		if _, err := old.Exec(s); err != nil {
			t.Fatal(err)
		}
	}
}

// A removed schedule keeps its agent id, version and state (the floor that refuses a replay) and nothing else: its
// instructions are gone from the file, also ones a release before this one removed (purged at open). The release
// before (v0.15.0, which knows schema 2) still opens the file and refuses the removed version, word for word.
func TestSideRemovedDefinitionKeepsNoInstructions(t *testing.T) {
	const instr = "INSTRUCTIONS-MARKER read my mail every morning"
	path := filepath.Join(t.TempDir(), "side.db")
	// Removed while v0.15.0 ran: its envelope stayed.
	oldSide(t, path, `INSERT INTO definitions (agent, version, env, state) VALUES ('a_old', 4, '{"i":"`+instr+` old"}', 'removed')`,
		`INSERT INTO definitions (agent, version, env, state) VALUES ('a_daily', 3, '{"i":"daily"}', 'active')`)
	if !inFiles(t, path, instr+" old") {
		t.Fatal("the test's old row isn't in the file")
	}
	s := openSide(t, path)
	if inFiles(t, path, instr+" old") {
		t.Fatal("a definition removed before this release kept its instructions after the open")
	}
	if err := s.SaveDefinition("a_old", 4, []byte(`{"i":"`+instr+` old"}`)); !errors.Is(err, trigger.ErrStale) {
		t.Fatalf("the purged removed version installed again: %v", err)
	}
	// Removed now.
	if err := s.SaveDefinition("a_new", 1, []byte(`{"i":"`+instr+` new"}`)); err != nil {
		t.Fatal(err)
	}
	if err := s.SetState("a_new", 1, trigger.StateStopped); err != nil {
		t.Fatal(err)
	}
	if !inFiles(t, path, instr+" new") {
		t.Fatal("a stopped definition (still listed) lost its envelope")
	}
	if err := s.SetState("a_new", 1, trigger.StateRemoved); err != nil {
		t.Fatal(err)
	}
	if inFiles(t, path, instr+" new") {
		t.Fatal("a removed definition kept its instructions")
	}
	if err := s.SaveDefinition("a_new", 1, []byte(`{"i":"`+instr+` new"}`)); !errors.Is(err, trigger.ErrStale) {
		t.Fatalf("the removed version installed again: %v", err)
	}
	if defs, _ := s.Definitions(); len(defs) != 1 || string(defs[0].Env) != `{"i":"daily"}` {
		t.Fatalf("definitions: %+v", defs)
	}
	s.Close()

	// v0.15.0 after a rollback: schema 2, its own floor check and listing, word for word.
	old, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	defer old.Close()
	var v int
	old.QueryRow(`PRAGMA user_version`).Scan(&v)
	if v != 2 {
		t.Fatalf("schema %d: v0.14.0/v0.15.0 would refuse the file", v)
	}
	var ver int64
	var env []byte
	var state string
	if err := old.QueryRow(`SELECT version, env, state FROM definitions WHERE agent = ?`, "a_new").Scan(&ver, &env, &state); err != nil ||
		ver != 1 || state != trigger.StateRemoved || len(env) != 0 {
		t.Fatalf("v0.15.0's floor check reads %d %q %q %v", ver, env, state, err)
	}
	rows, err := old.Query(`SELECT env, state FROM definitions WHERE state != ? ORDER BY agent`, trigger.StateRemoved)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for rows.Next() {
		n++
	}
	rows.Close()
	if n != 1 {
		t.Fatalf("v0.15.0's listing: %d", n)
	}
}

// Each personal space's seal key pin (runauth.PinStore): the first wins, it survives a restart, a reseal moves it only
// from the pinned key, and a side file from before pins (holders recorded by schedule installs) is seeded with each
// space's earliest holder's key. The schema version stays 2 (a rollback to v0.15.0 still opens the file).
func TestSideSealPins(t *testing.T) {
	path := filepath.Join(t.TempDir(), "side.db")
	// A person's space from v0.12.0-v0.15.0: the holder's install first, then a later one with another key.
	oldSide(t, path,
		`INSERT INTO holders (space, identity, key, seal, at) VALUES ('s_mine', 'i_me', 'ed25519:a', 'x25519:mine', 1000)`,
		`INSERT INTO holders (space, identity, key, seal, at) VALUES ('s_mine', 'i_them', 'ed25519:b', 'x25519:theirs', 2000)`)
	s := openSide(t, path)
	now := time.Now()
	if p, err := s.PinSeal("s_mine", "x25519:theirs", now); err != nil || p != "x25519:mine" {
		t.Fatalf("seeded pin: %q %v", p, err)
	}
	if p, _ := s.PinSeal("s_new", "x25519:first", now); p != "x25519:first" {
		t.Fatalf("first use: %q", p)
	}
	if p, _ := s.PinSeal("s_new", "x25519:second", now); p != "x25519:first" {
		t.Fatalf("second key: %q", p)
	}
	if err := s.RepinSeal("s_new", "x25519:second", "x25519:third", now); !errors.Is(err, runauth.ErrSealPinned) {
		t.Fatalf("a reseal from a key that isn't pinned: %v", err)
	}
	if err := s.RepinSeal("s_new", "x25519:first", "x25519:next", now); err != nil {
		t.Fatal(err)
	}
	if err := s.RepinSeal("s_none", "x25519:a", "x25519:b", now); err != nil { // no pin yet: the new key
		t.Fatal(err)
	}
	s.Close()
	s = openSide(t, path)
	for space, want := range map[string]string{"s_mine": "x25519:mine", "s_new": "x25519:next", "s_none": "x25519:b"} {
		if p, _ := s.PinSeal(space, "x25519:other", now); p != want {
			t.Fatalf("%s after a restart: %q, want %q", space, p, want)
		}
	}
	var v int
	s.db.QueryRow(`PRAGMA user_version`).Scan(&v)
	if v != 2 {
		t.Fatalf("schema %d", v)
	}
}
