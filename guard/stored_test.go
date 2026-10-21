package guard

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/tacyhq/tacy/harness"
	"github.com/tacyhq/tacy/proto"
	"github.com/tacyhq/tacy/storedfiles"
	"github.com/tacyhq/tacy/storedfiles/storedfilestest"
)

// storedTask is a research task over stored files on a stand-in bucket, opened in a guard without the rest.
func storedTask(t *testing.T, files ...proto.StoredFile) (*Guard, *task) {
	t.Helper()
	return storedTaskOn(t, nil, files...)
}

func storedTaskOn(t *testing.T, st *storedfilestest.Store, files ...proto.StoredFile) (*Guard, *task) {
	t.Helper()
	cfg := Config{Up: NewPlainUpstream("http://127.0.0.1:1", nil)}
	if st != nil {
		f, u := st.Config()
		cfg.Stored = &StoredConfig{Fetcher: f, URLs: u}
	}
	g := New(cfg)
	tk := g.open("t_stored", TaskOptions{Agent: AgentResearch, Question: "What does the lease say about pets?", Stored: files}, nil)
	tk.files.init(tk.opts, tk.def)
	return g, tk
}

// Keys and URLs never reach the queue; an ended task keeps no stored file at all.
func TestStoredKeysOff(t *testing.T) {
	opts := TaskOptions{Agent: AgentResearch, FilesGrant: "g1.abc.0123456789abcdef", Stored: []proto.StoredFile{
		{Object: "ob_x", Name: "lease.md", Size: 10, Key: make([]byte, 32), URL: "https://r2/x?X-Amz-Signature=1"}}}
	off := StoredKeysOff(opts)
	b, _ := json.Marshal(off)
	if strings.Contains(string(b), `"key"`) || strings.Contains(string(b), "X-Amz") || strings.Contains(string(b), "g1.") ||
		!strings.Contains(string(b), `"name":"lease.md"`) {
		t.Fatalf("queued %s", b)
	}
	if opts.Stored[0].Key == nil || opts.Stored[0].URL == "" || opts.FilesGrant == "" {
		t.Fatal("StoredKeysOff changed the task's own options")
	}
	full, _ := json.Marshal(opts)
	ended := EndedOptions(full)
	if strings.Contains(string(ended), "stored") || strings.Contains(string(ended), "lease.md") || strings.Contains(string(ended), "files_grant") {
		t.Fatalf("ended %s", ended)
	}
}

// A stored file's passages join the outbound check when it opens, not before (the model can't have them before), and
// the brief's own words never count.
func TestStoredPassagesOnOpen(t *testing.T) {
	st := storedfilestest.NewStore()
	defer st.Close()
	a := st.Put("a.md", "text/markdown", []byte("The tenant may keep one small dog or two cats with written consent of the landlord."))
	b := st.Put("b.md", "text/markdown", []byte("Rent is due on the first business day of every calendar month by bank transfer."))
	g, tk := storedTaskOn(t, st, a, b)
	if tk.fileTextInArgs([]byte(`{"query":"may keep one small dog or two cats"}`)) {
		t.Fatal("a passage of a file not open yet counted (built before any open)")
	}
	g.openStored(context.Background(), tk, 0)
	if !tk.fileTextInArgs([]byte(`{"query":"may keep one small dog or two cats"}`)) {
		t.Fatal("a passage of an opened file passed")
	}
	if tk.fileTextInArgs([]byte(`{"query":"due on the first business day of every"}`)) {
		t.Fatal("file 2 isn't open: its words can't be the model's")
	}
	g.openStored(context.Background(), tk, 1)
	if !tk.fileTextInArgs([]byte(`{"query":"due on the first business day of every"}`)) {
		t.Fatal("a passage of file 2 passed after it opened")
	}
	if tk.fileTextInArgs([]byte(`{"query":"What does the lease say about pets"}`)) {
		t.Fatal("the brief's words counted")
	}
}

// A task holds at most maxStoredText of stored files' text: a larger file is read from its start to what fits (and
// says so); once full, no more files open.
func TestStoredTextCap(t *testing.T) {
	st := storedfilestest.NewStore()
	defer st.Close()
	big := st.Put("big.txt", "text/plain", []byte(strings.Repeat("Clause text, about a page of it. ", 200_000))) // ~6.6 MB
	small := st.Put("small.txt", "text/plain", []byte("short"))
	g, tk := storedTaskOn(t, st, big, small)
	g.openFor(context.Background(), tk, 0, maxSectionsPerRead)
	f := &tk.files.files[0]
	if !f.opened || !f.truncated || len(f.text) > maxStoredText || len(f.text) < maxStoredText-8 {
		t.Fatalf("big: opened %v truncated %v %d bytes", f.opened, f.truncated, len(f.text))
	}
	// A range read: the five chunks that hold its first 4 MiB (and the length prefix), not the seven it has.
	if st.Bytes != 5*storedfiles.SealedChunkBytes {
		t.Fatalf("fetched %d bytes for 4 MB of text", st.Bytes)
	}
	g.openStored(context.Background(), tk, 1)
	if s := &tk.files.files[1]; s.opened || !strings.Contains(s.openErr, "already holds") {
		t.Fatalf("small: %+v", s.openErr)
	}
	if l := tk.files.list(); !strings.Contains(l, "only its first") || !strings.Contains(l, "couldn't be opened") {
		t.Fatalf("list %s", l)
	}
}

// files.read's default order opens the next stored file only when the open ones have fewer unread parts than the read
// can take; a file named is opened alone.
func TestStoredOpensLazily(t *testing.T) {
	st := storedfilestest.NewStore()
	defer st.Close()
	long := strings.Repeat("A paragraph about the lease that goes on for a while, one of many in this file.\n\n", 900) // ~70k: about 20 parts
	a := st.Put("a.md", "text/markdown", []byte(long))
	b := st.Put("b.md", "text/markdown", []byte("second"))
	c := st.Put("c.md", "text/markdown", []byte("third"))
	g, tk := storedTaskOn(t, st, a, b, c)
	g.openFor(context.Background(), tk, 0, maxSectionsPerRead)
	if st.Gets[a.Object] != 1 || st.Gets[b.Object] != 0 || st.Gets[c.Object] != 0 {
		t.Fatalf("default read opened %v", st.Gets)
	}
	g.openFor(context.Background(), tk, 3, maxSectionsPerRead)
	if st.Gets[b.Object] != 0 || st.Gets[c.Object] != 1 || tk.files.unopened() != 1 {
		t.Fatalf("named read opened %v", st.Gets)
	}
}

// After a restart, a journaled files.read of a stored file not open again applies when it opens: its parts stay read.
func TestStoredRestore(t *testing.T) {
	st := storedfilestest.NewStore()
	defer st.Close()
	a := st.Put("a.md", "text/markdown", []byte("One short part."))
	g, tk := storedTaskOn(t, st, a)
	out, _ := json.Marshal(filesReadOut{Parts: []fileSectionOut{{File: 1, Part: 1, Of: 1, Read: &readView{Quotes: []quoteRef{{ID: 7}}}}}})
	if most := tk.files.restore(tk, out); most != 7 {
		t.Fatalf("quote numbers %d", most)
	}
	g.openStored(context.Background(), tk, 0)
	if !tk.files.files[0].state[0].ok || tk.files.unread() != 0 {
		t.Fatal("the restored read was lost")
	}
}

// files.fetch is checked as a read: it goes on while the stop list is stale, as the files.read that needs it does (the
// first lab round, without an operator heartbeat, found every stored file refused as an effect).
func TestStoredFetchIsRead(t *testing.T) {
	if !ReplaySafe(&harness.Action{Name: storedFetchAction}) || Effect(&harness.Action{Name: storedFetchAction}) {
		t.Fatal("files.fetch counts as an effect")
	}
}

// Without a stored-files config (a VM that can't read them), the file says so and nothing else happens.
func TestStoredWithoutConfig(t *testing.T) {
	g, tk := storedTask(t, proto.StoredFile{Object: "ob_x", Name: "a.md", Size: 3, Key: make([]byte, 32), URL: "https://x"})
	g.openStored(context.Background(), tk, 0)
	if !strings.Contains(tk.files.files[0].openErr, "can't read stored files") {
		t.Fatalf("%q", tk.files.files[0].openErr)
	}
}
