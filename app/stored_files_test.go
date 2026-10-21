package main

import (
	"context"
	"encoding/base64"
	"slices"
	"strings"
	"testing"

	"github.com/tacyhq/tacy/activity"
	"github.com/tacyhq/tacy/guard"
	"github.com/tacyhq/tacy/harness"
	"github.com/tacyhq/tacy/proto"
	"github.com/tacyhq/tacy/safety"
	"github.com/tacyhq/tacy/storedfiles"
	"github.com/tacyhq/tacy/storedfiles/storedfilestest"
	"github.com/tacyhq/tacy/trigger"
)

// The person's stored files in a research task (branch files-vm-read), with the full stack: the signed request with
// stored_files, the policy (files.fetch), the guard fetching ciphertext from a stand-in bucket (TLS, the production
// host names), checking and decrypting it, the quarantined reader, the outbound passage check, the activity record.

func storedEnv(t *testing.T, edit func(p *safety.Policy), replies ...string) (*agentEnv, *storedfilestest.Store) {
	t.Helper()
	st := storedfilestest.NewStore()
	t.Cleanup(st.Close)
	f, u := st.Config()
	return newAgentEnvWith(t, &guard.StoredConfig{Fetcher: f, URLs: u}, edit, replies...), st
}

func researchStored(files ...proto.StoredFile) proto.RunRequest {
	r := research("")
	r.Messages = []proto.Message{{Role: "system", Content: "Today is Tuesday, October 20, 2026."},
		{Role: "user", Content: "Task: NDA terms today\n\nAre five-year NDA terms still usual?"}}
	r.StoredFiles = files
	return r
}

func TestResearchWithStoredFiles(t *testing.T) {
	ae, st := storedEnv(t, nil,
		pCalls([3]string{"c1", "files_read", `{"file":1}`}),
		pCalls([3]string{"c2", "web_search", `{"query":"This Agreement lasts five (5) years from the Effective Date"}`},
			[3]string{"c3", "web_search", `{"query":"typical NDA term length"}`}),
		pText(researchAnswer))
	nda := st.Put("nda.md", "text/markdown", []byte(reviewNDA))
	other := st.Put("unrelated.csv", "text/csv", []byte("region,revenue\nnorth,10\n"))
	// While the file is being fetched, the queue (agentd's disk) has the task's options without any key or URL.
	var queued []string
	st.OnGet = func() {
		ts, _ := ae.s.rt.Store.OpenTasks()
		for _, x := range ts {
			queued = append(queued, string(x.Options))
		}
	}
	_, evs := runAgentTask(t, ae.conn(t, tasksUser), researchStored(nda, other))
	if len(queued) != 1 || !strings.Contains(queued[0], `"name":"nda.md"`) || strings.Contains(queued[0], base64Key(nda)) ||
		strings.Contains(queued[0], `"key"`) || strings.Contains(queued[0], "X-Amz") {
		t.Fatalf("queued options while the task ran: %q", queued)
	}
	if evs[len(evs)-1].Type != "done" {
		t.Fatalf("run %s: %+v", types(evs), evs[len(evs)-1])
	}
	var quotes []proto.Quote
	for _, e := range evs {
		if e.Type == "tool_result" && e.Name == "files_read" {
			quotes = append(quotes, e.Quotes...)
		}
	}
	if len(quotes) != 1 || quotes[0].File != "nda.md" {
		t.Fatalf("quotes %+v", quotes)
	}
	// Only what the run read was fetched: the first file (one chunk, one range), never the second.
	if st.Gets[nda.Object] != 1 || st.Gets[other.Object] != 0 || st.Bytes != storedfiles.ObjectBytes(nda.Padded) {
		t.Fatalf("fetched %v, %d bytes", st.Gets, st.Bytes)
	}
	// The passage search was refused in gatewayd; the model never got the file's text.
	if ae.search.count() != 1 || !strings.Contains(resultOf(evs, "c2"), guard.FileTextDenied) {
		t.Fatalf("%d searches; c2 %s", ae.search.count(), resultOf(evs, "c2"))
	}
	for i, body := range ae.model.bodies {
		if strings.Contains(body, "KESTREL-CANARY-9") {
			t.Fatalf("model call %d has the file's text", i+1)
		}
		if strings.Contains(body, base64Key(nda)) || strings.Contains(body, "X-Amz-Signature") {
			t.Fatalf("model call %d has a key or a read URL", i+1)
		}
	}
	// The brief lists both; the coverage says the second was never opened.
	text := answerText(evs)
	if !strings.Contains(text, "- unrelated.csv: not opened (the task ended first)") {
		t.Fatalf("coverage %q", text[strings.LastIndex(text, "##"):])
	}
	// The fetch is on the activity record like any fetch: the bucket's host and its bytes; nothing else new.
	runs := openedActivity(t, evs, ae.seal, ae.rec.Signer.Public())
	end := runs[len(runs)-1]
	if end.Status.State != "succeeded" {
		t.Fatalf("end %+v", end.Status)
	}
	hosts := activityHosts(end)
	if !slices.Contains(hosts, storedfiles.R2Host) {
		t.Fatalf("hosts on the record %v", hosts)
	}
}

// Under a policy without files.fetch (chat-v4 and before), a task with stored files doesn't start: nothing fetched.
func TestStoredFilesNeedPolicy(t *testing.T) {
	ae, st := storedEnv(t, func(p *safety.Policy) {
		c := p.Connectors["files"]
		c.Tools, c.Fetch = []string{"files.list", "files.read"}, nil
		p.Connectors["files"] = c
	}, pText(researchAnswer))
	nda := st.Put("nda.md", "text/markdown", []byte(reviewNDA))
	_, err := ae.conn(t, tasksUser).StartTask(context.Background(), researchStored(nda), "")
	if err == nil || !strings.Contains(err.Error(), "files.fetch") {
		t.Fatalf("start under chat-v4: %v", err)
	}
	if st.Bytes != 0 {
		t.Fatal("fetched under a policy without files.fetch")
	}
}

// A tampered object, an object read with another file's key, and a URL for another object: each refused with its
// reason, nothing of it given to the reader or the model; the run goes on and says what wasn't read.
func TestStoredFilesRefused(t *testing.T) {
	ae, st := storedEnv(t, nil,
		pCalls([3]string{"c1", "files_read", `{"file":1}`}, [3]string{"c2", "files_read", `{"file":2}`}, [3]string{"c3", "files_read", `{"file":3}`}),
		pText(researchAnswer))
	tampered := st.Put("tampered.md", "text/markdown", []byte(reviewNDA))
	sealed, _, _ := storedfiles.Encrypt(tampered.Key, tampered.File, tampered.Object, 1, []byte(reviewNDA), nil)
	sealed[storedfiles.IVBytes+3] ^= 1
	st.PutSealed(tampered, sealed)
	wrongKey := st.Put("wrong-key.md", "text/markdown", []byte(reviewNDA))
	wrongKey.Key = tampered.Key
	victim := st.Put("someone-elses.md", "text/markdown", []byte("KESTREL-CANARY-9"))
	scoped := st.Put("scoped.md", "text/markdown", []byte(reviewNDA))
	scoped.URL = victim.URL // another object's presigned URL under this file's ref
	_, evs := runAgentTask(t, ae.conn(t, tasksUser), researchStored(tampered, wrongKey, scoped))
	if evs[len(evs)-1].Type != "done" {
		t.Fatalf("run %s: %+v", types(evs), evs[len(evs)-1])
	}
	for call, want := range map[string]string{"c1": "integrity check", "c2": "integrity check", "c3": "read address isn't this file's"} {
		if r := resultOf(evs, call); !strings.Contains(r, want) {
			t.Errorf("%s: %s", call, r)
		}
	}
	if st.Gets[victim.Object] != 0 || st.Gets[scoped.Object] != 0 {
		t.Fatal("an out-of-scope URL was fetched")
	}
	for _, body := range ae.model.bodies {
		if strings.Contains(body, "KESTREL-CANARY-9") || strings.Contains(body, "Recipient pays") {
			t.Fatal("a refused file's text reached the model")
		}
	}
	if text := answerText(evs); !strings.Contains(text, "- tampered.md: not read (the stored file failed its integrity check") {
		t.Fatalf("coverage %q", text)
	}
}

// A schedule with stored files: the definition carries the keys (no URLs) and the Worker's read grant; its run asks
// the (stand-in) Worker for read URLs once, reads the file through the reader, and its result cites it. A definition
// whose grant is missing, or whose files carry URLs, is refused at install.
func TestScheduledStoredFiles(t *testing.T) {
	st := storedfilestest.NewStore()
	t.Cleanup(st.Close)
	f, u := st.Config()
	e := newSchedEnvWith(t, safeOpts{reader: reviewReader, stored: &guard.StoredConfig{Fetcher: f, URLs: u}},
		pCalls([3]string{"c1", "files_read", `{}`}), pText("Your NDA's term is five years [file quote 1]."))
	e.wireApprovals()
	nda := st.Put("nda.md", "text/markdown", []byte(reviewNDA))
	nda.URL = ""
	grant := st.Grant(nda.Object)
	d := e.daily(e.me, func(d *trigger.Definition) {
		d.Instructions = "Every morning, tell me the term of my NDA."
		d.Tools = []string{}
		d.Files, d.FilesGrant = []proto.StoredFile{nda}, grant
	})
	bad := d
	bad.FilesGrant = ""
	if code, out := e.install(e.me, e.sign(bad, e.me.Key)); code == 200 {
		t.Fatalf("install without a grant: %d %v", code, out)
	}
	bad = d
	bad.Files = []proto.StoredFile{nda}
	bad.Files[0].URL = st.URL(nda)
	if code, out := e.install(e.me, e.sign(bad, e.me.Key)); code == 200 {
		t.Fatalf("install with a URL in the definition: %d %v", code, out)
	}
	if code, out := e.install(e.me, e.sign(d, e.me.Key)); code != 200 {
		t.Fatalf("install %d %v", code, out)
	}
	e.s.triggerTick(context.Background())
	var task string
	for id := range e.s.tasks().Triggered() {
		task = id
	}
	r := e.waitResult(task)
	if r.State != harness.OutcomeSucceeded {
		t.Fatalf("result %+v", r)
	}
	_, body := e.openResult(e.me, task)
	var read string
	for _, ev := range body.Events {
		if ev.Type == "tool_result" && ev.Name == "files_read" {
			read = string(ev.Result)
		}
	}
	if !strings.Contains(read, "[file quote 1]") || st.URLAsks != 1 || st.Gets[nda.Object] != 1 {
		t.Fatalf("files_read %s; url asks %d, gets %v", read, st.URLAsks, st.Gets)
	}
	for _, b := range e.model.bodies {
		if strings.Contains(b, "KESTREL-CANARY-9") {
			t.Fatal("the model got the file's text")
		}
	}
}

// activityHosts is every host a run's end record names, over its calls.
func activityHosts(end *activity.Run) []string {
	var hs []string
	for _, c := range end.Calls {
		for _, h := range c.Hosts {
			hs = append(hs, h.Host)
		}
	}
	return hs
}

func base64Key(f proto.StoredFile) string { return base64.StdEncoding.EncodeToString(f.Key) }

// The chat agent takes no stored files, and a review takes at most 5 files in all.
func TestStoredFilesWhere(t *testing.T) {
	ae, st := storedEnv(t, nil)
	f := st.Put("a.md", "text/markdown", []byte("alpha"))
	chat := proto.RunRequest{Model: proto.DefaultModel, RunSecret: permSecret, Messages: user1("hi"), StoredFiles: []proto.StoredFile{f}}
	if _, err := ae.conn(t, tasksUser).StartTask(context.Background(), chat, ""); err == nil || !strings.Contains(err.Error(), "stored files go only") {
		t.Fatalf("chat with stored files: %v", err)
	}
	rv := review()
	for i := range 5 {
		rv.StoredFiles = append(rv.StoredFiles, st.Put("f"+string(rune('a'+i))+".md", "text/markdown", []byte("x")))
	}
	if _, err := ae.conn(t, tasksUser).StartTask(context.Background(), rv, ""); err == nil || !strings.Contains(err.Error(), "at most 5 files") {
		t.Fatalf("review with 6 files: %v", err)
	}
}
