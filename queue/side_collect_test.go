package queue

import (
	"bytes"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"

	"github.com/tacyhq/tacy/trigger"
)

func TestSideCollect(t *testing.T) {
	trigger.RunCollectStoreTests(t, openSide(t, filepath.Join(t.TempDir(), "side.db")))
}

func TestSideHandoff(t *testing.T) {
	trigger.RunHandoffStoreTests(t, openSide(t, filepath.Join(t.TempDir(), "side.db")))
}

// The collect table (v0.17.0) is an extra: the schema stays 2, opening again changes nothing, and a count survives.
func TestSideCollectExtraKeepsSchema(t *testing.T) {
	path := filepath.Join(t.TempDir(), "side.db")
	s := openSide(t, path)
	s.PutResult(trigger.Result{Task: "tk_1", Space: "s_1", Seal: "x25519:a", Agent: "a_daily", State: "succeeded", Enc: []byte{1}, CT: []byte{2}})
	s.SetStoppedUncollected("a_daily", 3)
	s.Close()
	s = openSide(t, path)
	var v int
	s.db.QueryRow(`PRAGMA user_version`).Scan(&v)
	if v != 2 {
		t.Fatalf("schema %d", v)
	}
	if n, _ := s.Uncollected("a_daily"); n != 1 {
		t.Fatalf("count after reopening: %d", n)
	}
	if ok, _ := s.StoppedUncollected("a_daily", 3); !ok {
		t.Fatal("stop reason after reopening")
	}
}

// An expired definition's envelope is replaced in the file: the old one's key bytes are nowhere in the database or its
// log afterwards (secure_delete and a WAL checkpoint).
func TestSideExpireDefinitionLeavesNoKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "side.db")
	s := openSide(t, path)
	secret := bytes.Repeat([]byte("K3yB"), 8)
	b64 := base64.StdEncoding.EncodeToString(secret)
	if err := s.SaveDefinition("a_f", 1, []byte(`{"key":"`+b64+`","raw":"`+string(secret)+`"}`)); err != nil {
		t.Fatal(err)
	}
	if err := s.ExpireDefinition("a_f", 2, []byte(`{}`)); err != trigger.ErrStale {
		t.Fatalf("another version: %v", err)
	}
	if err := s.ExpireDefinition("a_f", 1, []byte(`{"redacted":true}`)); err != nil {
		t.Fatal(err)
	}
	defs, _ := s.Definitions()
	if len(defs) != 1 || defs[0].State != trigger.StateExpired || string(defs[0].Env) != `{"redacted":true}` {
		t.Fatalf("stored: %+v", defs)
	}
	if err := s.SaveDefinition("a_f", 1, []byte(`{"redacted":true}`)); err != trigger.ErrStale {
		t.Fatalf("expired version saved again: %v", err)
	}
	files, _ := filepath.Glob(path + "*")
	if len(files) == 0 {
		t.Fatal("no files (test broken)")
	}
	for _, f := range files {
		b, _ := os.ReadFile(f)
		if bytes.Contains(b, secret) || bytes.Contains(b, []byte(b64)) {
			t.Fatalf("%s still holds the key", filepath.Base(f))
		}
	}
	if err := s.SaveDefinition("a_f", 2, []byte(`{"v":2}`)); err != nil {
		t.Fatalf("next version: %v", err)
	}
	s.SetState("a_f", 2, trigger.StateRemoved)
	if err := s.ExpireDefinition("a_f", 2, []byte(`{}`)); err != trigger.ErrStale {
		t.Fatalf("a removed one expired: %v", err)
	}
}
