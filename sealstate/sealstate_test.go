package sealstate

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

var key = bytes.Repeat([]byte{7}, 32)

func TestSealOpen(t *testing.T) {
	pt := []byte("canary: a schedule's instructions")
	blob, err := Seal(key, "lease-1", "side", 3, pt)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(blob, []byte(Magic)) || bytes.Contains(blob, pt) {
		t.Fatal("not sealed")
	}
	if n, g, err := Header(blob); err != nil || n != "side" || g != 3 {
		t.Fatalf("header %q %d %v", n, g, err)
	}
	gen, got, err := Open(key, "lease-1", "side", blob)
	if err != nil || gen != 3 || !bytes.Equal(got, pt) {
		t.Fatalf("open %d %q %v", gen, got, err)
	}
	other := bytes.Repeat([]byte{8}, 32)
	for name, f := range map[string]func() error{
		"another key":   func() error { _, _, err := Open(other, "lease-1", "side", blob); return err },
		"another lease": func() error { _, _, err := Open(key, "lease-2", "side", blob); return err },
		"another name":  func() error { _, _, err := Open(key, "lease-1", "notify", blob); return err },
		"another gen": func() error {
			b := bytes.Clone(blob)
			b[len(Magic)+2+4+7]++ // the generation's low byte
			_, _, err := Open(key, "lease-1", "side", b)
			return err
		},
		"tampered": func() error {
			b := bytes.Clone(blob)
			b[len(b)-1] ^= 1
			_, _, err := Open(key, "lease-1", "side", b)
			return err
		},
	} {
		if err := f(); !errors.Is(err, ErrSealed) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := Seal(key, "", "Bad/Name", 1, nil); err != ErrName {
		t.Fatalf("bad name: %v", err)
	}
}

// Generations: each save is the next; a stale writer conflicts; an older blob put back by the host is refused.
func TestStoreGenerations(t *testing.T) {
	ctx := context.Background()
	b := &Mem{}
	s, _ := New(b, key, "l")
	if pt, err := s.Load(ctx, "side"); pt != nil || err != nil {
		t.Fatalf("empty: %q %v", pt, err)
	}
	for i := 1; i <= 3; i++ {
		if err := s.Save(ctx, "side", []byte("v"+strconv.Itoa(i))); err != nil {
			t.Fatal(err)
		}
	}
	old, _ := b.Get(ctx, "side")
	s2, _ := New(b, key, "l")
	if pt, err := s2.Load(ctx, "side"); string(pt) != "v3" || err != nil || s2.Gen("side") != 3 {
		t.Fatalf("reload %q %v %d", pt, err, s2.Gen("side"))
	}
	// A second instance saves; the first, still at 3, conflicts instead of forking.
	if err := s2.Save(ctx, "side", []byte("v4")); err != nil {
		t.Fatal(err)
	}
	if err := s.Save(ctx, "side", []byte("fork")); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale save: %v", err)
	}
	// The host replays generation 3 (put back under the backend's feet): a Store that saw 4 refuses it.
	b.blobs["side"] = old
	if _, err := s2.Load(ctx, "side"); !errors.Is(err, ErrRollback) {
		t.Fatalf("rollback: %v", err)
	}
	// The key service's floor does the same for a Store that saw nothing yet.
	s3, _ := New(b, key, "l")
	s3.Floor("side", 4)
	if _, err := s3.Load(ctx, "side"); !errors.Is(err, ErrRollback) {
		t.Fatalf("floor: %v", err)
	}
	// A backend refuses what isn't the next sealed generation.
	if err := b.Put(ctx, "side", []byte("plaintext"), 3); err == nil {
		t.Fatal("put plaintext")
	}
}

func TestFileBackend(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	s, _ := New(&File{Dir: dir}, key, "l")
	if err := s.Save(ctx, "notify", []byte("canary-notify")); err != nil {
		t.Fatal(err)
	}
	if err := s.Save(ctx, "notify", []byte("canary-notify-2")); err != nil {
		t.Fatal(err)
	}
	es, _ := os.ReadDir(dir)
	if len(es) != 1 || es[0].Name() != "notify.sealed" {
		t.Fatalf("files %v", es)
	}
	raw, _ := os.ReadFile(filepath.Join(dir, "notify.sealed"))
	if !bytes.HasPrefix(raw, []byte(Magic)) || bytes.Contains(raw, []byte("canary")) {
		t.Fatal("file not sealed")
	}
	s2, _ := New(&File{Dir: dir}, key, "l")
	if pt, err := s2.Load(ctx, "notify"); string(pt) != "canary-notify-2" || err != nil {
		t.Fatalf("%q %v", pt, err)
	}
}

// fakeWorker is the relay API as Relay's doc comment defines it (what the chat Worker must build).
type fakeWorker struct {
	mu    sync.Mutex
	blobs map[string][]byte
	auth  string
}

func (w *fakeWorker) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != w.auth {
		rw.WriteHeader(401)
		return
	}
	name, ok := strings.CutPrefix(r.URL.Path, "/api/vm/state/")
	if !ok || !ValidName(name) {
		rw.WriteHeader(404)
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	switch r.Method {
	case "GET":
		b, ok := w.blobs[name]
		if !ok {
			rw.WriteHeader(404)
			return
		}
		_, gen, _ := Header(b)
		rw.Header().Set("X-Tacy-Gen", strconv.FormatUint(gen, 10))
		rw.Write(b)
	case "PUT":
		b, _ := io.ReadAll(io.LimitReader(r.Body, MaxBlob+1))
		n, gen, err := Header(b)
		prev, _ := strconv.ParseUint(r.Header.Get("X-Tacy-Prev-Gen"), 10, 64)
		if err != nil || n != name || r.Header.Get("X-Tacy-Gen") != strconv.FormatUint(gen, 10) || gen != prev+1 {
			rw.WriteHeader(400)
			return
		}
		var cur uint64
		if held, ok := w.blobs[name]; ok {
			_, cur, _ = Header(held)
		}
		if cur != prev {
			rw.WriteHeader(409)
			return
		}
		if w.blobs == nil {
			w.blobs = map[string][]byte{}
		}
		w.blobs[name] = b
		rw.WriteHeader(204)
	default:
		rw.WriteHeader(405)
	}
}

func TestRelayBackend(t *testing.T) {
	ctx := context.Background()
	w := &fakeWorker{auth: "Bearer vm"}
	srv := httptest.NewServer(w)
	defer srv.Close()
	relay := func() *Relay {
		return &Relay{Base: srv.URL, Client: srv.Client(), Auth: func(r *http.Request) { r.Header.Set("Authorization", "Bearer vm") }}
	}
	s, _ := New(relay(), key, "l")
	if pt, err := s.Load(ctx, "side"); pt != nil || err != nil {
		t.Fatalf("empty: %v", err)
	}
	if err := s.Save(ctx, "side", []byte("canary-side")); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(w.blobs["side"], []byte("canary")) {
		t.Fatal("the Worker holds plaintext")
	}
	s2, _ := New(relay(), key, "l")
	if pt, err := s2.Load(ctx, "side"); string(pt) != "canary-side" || err != nil {
		t.Fatalf("%q %v", pt, err)
	}
	s2.Save(ctx, "side", []byte("2"))
	if err := s.Save(ctx, "side", []byte("fork")); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale save over the relay: %v", err)
	}
	unauth := &Relay{Base: srv.URL, Client: srv.Client()}
	if _, err := unauth.Get(ctx, "side"); err == nil {
		t.Fatal("no auth")
	}
}

type counter struct {
	mu sync.Mutex
	v  uint64
	b  []byte
}

func (c *counter) Version() uint64 { c.mu.Lock(); defer c.mu.Unlock(); return c.v }
func (c *counter) Snapshot() ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return bytes.Clone(c.b), nil
}
func (c *counter) set(b string) { c.mu.Lock(); c.v++; c.b = []byte(b); c.mu.Unlock() }

// The keeper saves a changed source once per tick (a burst is one save) and on stop.
func TestKeeper(t *testing.T) {
	b := &Mem{}
	s, _ := New(b, key, "l")
	k := &Keeper{Store: s, Every: 20 * time.Millisecond}
	c := &counter{}
	k.Add("budget", c)
	for i := 0; i < 50; i++ {
		c.set("b" + strconv.Itoa(i))
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { k.Run(ctx); close(done) }()
	for end := time.Now().Add(2 * time.Second); s.Gen("budget") == 0 && time.Now().Before(end); time.Sleep(5 * time.Millisecond) {
	}
	if g := s.Gen("budget"); g != 1 {
		t.Fatalf("a burst made %d saves", g)
	}
	c.set("last")
	cancel()
	<-done
	s2, _ := New(b, key, "l")
	if pt, _ := s2.Load(context.Background(), "budget"); string(pt) != "last" {
		t.Fatalf("after stop: %q", pt)
	}
}

func TestMemoryDB(t *testing.T) {
	db, err := OpenMemoryDB(nil)
	if err != nil {
		t.Fatal(err)
	}
	db.Exec(`CREATE TABLE t (v TEXT)`)
	db.Exec(`INSERT INTO t VALUES ('canary-row'), ('gone')`)
	db.Exec(`DELETE FROM t WHERE v = 'gone'`)
	v := DBVersion(db)
	if v == 0 {
		t.Fatal("no changes counted")
	}
	snap, err := SnapshotDB(db)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(snap, []byte("gone")) {
		t.Fatal("a deleted row is in the snapshot (secure_delete)")
	}
	db2, err := OpenMemoryDB(snap)
	if err != nil {
		t.Fatal(err)
	}
	var got string
	if err := db2.QueryRow(`SELECT v FROM t`).Scan(&got); err != nil || got != "canary-row" {
		t.Fatalf("%q %v", got, err)
	}
	if DBVersion(db) != v {
		t.Fatal("a read changed the version")
	}
}
