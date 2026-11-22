package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tacyhq/tacy/agentclient"
	"github.com/tacyhq/tacy/guard"
	"github.com/tacyhq/tacy/imapro/imaptest"
	"github.com/tacyhq/tacy/leakscan"
	"github.com/tacyhq/tacy/proto"
	"github.com/tacyhq/tacy/queue"
	"github.com/tacyhq/tacy/vault"
)

// Per-task mail logins through agentd (v1, the v1 design §5.4, §5.8): the app sends the login sealed with the task;
// agentd passes it on unopened and keeps none of it; a vaultd restart makes the next mail call wait for the app to
// send it again.

// credCanary is the IMAP password of these tests: it must never be in the task queue, a record or an answer.
const credCanary = "canary-imap-1f7d3e9a5b"

const credUser = "c0ffee0000c0ffee" // the relay's user tag

// swapVault is the guard's vault, which a test can restart (a fresh vaultd: a new seal key, no logins).
type swapVault struct {
	mu        sync.Mutex
	v         *vault.Vault
	restartAt int // restart just before the n-th RunInfo (0: never)
	infos     int
	beforePut func() // called before each RunPut reaches the vault (nil: none)
}

func newVault(t *testing.T) *vault.Vault {
	t.Helper()
	v, err := vault.New(nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := v.EnableConns(nil); err != nil {
		t.Fatal(err)
	}
	return v
}

func (s *swapVault) cur() vault.Local                            { s.mu.Lock(); defer s.mu.Unlock(); return vault.Local{V: s.v} }
func (s *swapVault) SealKey(ctx context.Context) (string, error) { return s.cur().SealKey(ctx) }
func (s *swapVault) ConnPut(ctx context.Context, space, id string, b vault.Sealed) (string, vault.ConnInfo, error) {
	return s.cur().ConnPut(ctx, space, id, b)
}
func (s *swapVault) ConnDiscard(ctx context.Context, p string) error {
	return s.cur().ConnDiscard(ctx, p)
}
func (s *swapVault) ConnList(ctx context.Context, space string) ([]vault.ConnInfo, string, error) {
	return s.cur().ConnList(ctx, space)
}
func (s *swapVault) ConnRemove(ctx context.Context, space, id string) error {
	return s.cur().ConnRemove(ctx, space, id)
}
func (s *swapVault) RunPut(ctx context.Context, g vault.RunGrant) (vault.ConnInfo, error) {
	s.mu.Lock()
	f := s.beforePut
	s.mu.Unlock()
	if f != nil {
		f()
	}
	return s.cur().RunPut(ctx, g)
}
func (s *swapVault) RunInfo(ctx context.Context, task, space string) (vault.ConnInfo, error) {
	s.mu.Lock()
	s.infos++
	if s.infos == s.restartAt { // vaultd restarted: its memory (and every login in it) is gone
		nv, _ := vault.New(nil, nil, nil)
		nv.EnableConns(nil)
		s.v = nv
	}
	s.mu.Unlock()
	return s.cur().RunInfo(ctx, task, space)
}
func (s *swapVault) RunEnd(ctx context.Context, task string) error { return s.cur().RunEnd(ctx, task) }
func (s *swapVault) Lease(ctx context.Context, r vault.Request) (*vault.Secret, error) {
	return s.cur().Lease(ctx, r)
}

type credEnv struct {
	*schedEnv
	srv   *imaptest.Server
	sv    *swapVault
	c     *agentclient.Conn
	qdir  string
	waits *guard.CredWaits
}

// newCredEnv is agentd with the guard's mail on a stand-in IMAP server (the canary password), its task queue in a
// directory as OpenTmpfs opens /run/tacy-tasks on the VM, and a task client.
func newCredEnv(t *testing.T, replies ...string) *credEnv {
	t.Helper()
	srv := imaptest.New()
	srv.Users[connUser] = credCanary
	srv.Add("INBOX", []byte("Date: Tue, 27 Oct 2026 09:00:00 +0000\r\nFrom: Alice <alice@client.example>\r\nSubject: Invoice 4471\r\n\r\n"+
		"The invoice 4471 is 1,240 EUR, due 5 November.\r\n"), time.Now().Add(-time.Hour))
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(srv.Close)
	qdir := filepath.Join(t.TempDir(), "tacy-tasks")
	if err := os.Mkdir(qdir, 0o700); err != nil {
		t.Fatal(err)
	}
	q, _, err := queue.OpenTmpfs(queue.Tmpfs{Dir: qdir, IsMemory: func(string) (bool, error) { return true, nil },
		BootID: func() (string, error) { return "kernel-boot-1", nil }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { q.Close() })
	sv := &swapVault{v: newVault(t)}
	e := &credEnv{srv: srv, sv: sv, qdir: qdir}
	e.schedEnv = newSchedEnvWith(t, safeOpts{reader: mailReader, queue: q, idKey: []byte("the task-id key"),
		mail: &guard.MailConfig{Vault: sv, Dial: srv.Dial, TLS: srv.TLSConfig()}}, replies...)
	e.waits = e.s.credWaits()
	e.waits.Timeout = 5 * time.Second
	e.c = connTo(t, e.s, credUser)
	return e
}

// seal is the app's box for a task: the login sealed to the vault key for space and the task's start key.
func (e *credEnv) seal(sealKey, space, startKey, password string) []TaskCredential {
	e.t.Helper()
	pt, _ := json.Marshal(map[string]any{"type": vault.MailLoginType, "provider": "other", "host": imaptest.Host, "port": 993,
		"security": "tls", "address": connUser, "username": connUser, "password": password, "added_at": "2026-11-21T09:00:00Z"})
	exp := time.Now().Add(2 * time.Hour).UnixMilli()
	box, err := vault.SealRunCredFor(sealKey, space, testAsker.Identity, vault.ConnEmail, vault.KeyHash(startKey), exp, pt)
	if err != nil {
		e.t.Fatal(err)
	}
	return []TaskCredential{{Connection: vault.ConnEmail, Expires: exp, Sealed: box}}
}

func (e *credEnv) sealKey() string {
	k, err := e.sv.SealKey(context.Background())
	if err != nil {
		e.t.Fatal(err)
	}
	return k
}

func mailRequest() proto.RunRequest {
	return proto.RunRequest{Messages: user1("What do I owe Alice?"), Tools: []string{"mail_search"}, Permissions: guard.AllowAll()}
}

// follow follows a task to its end, answering need_credential with on (nil: never).
func (e *credEnv) follow(id string, on func(need *proto.CredentialNeed)) []proto.Event {
	e.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var evs []proto.Event
	err := e.c.FollowTask(ctx, id, 0, func(_ int, ev proto.Event) {
		evs = append(evs, ev)
		if ev.Type == "need_credential" && ev.Credential != nil && ev.Credential.Decision == "" && on != nil {
			go on(ev.Credential)
		}
	})
	if err != nil {
		e.t.Fatal(err)
	}
	return evs
}

func toolResultOf(evs []proto.Event, name string) string {
	for _, ev := range evs {
		if ev.Type == "tool_result" && ev.Name == name {
			return string(ev.Result)
		}
	}
	return ""
}

func needs(evs []proto.Event) (asked, settled []proto.CredentialNeed) {
	for _, ev := range evs {
		if ev.Type == "need_credential" && ev.Credential != nil {
			if ev.Credential.Decision == "" {
				asked = append(asked, *ev.Credential)
			} else {
				settled = append(settled, *ev.Credential)
			}
		}
	}
	return
}

// scanQueue fails the test if any file of the task queue holds one of needles (or the password in any encoding).
func (e *credEnv) scanQueue(when string, needles [][]byte) {
	e.t.Helper()
	n := 0
	filepath.WalkDir(e.qdir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		n++
		b, _ := os.ReadFile(p)
		for _, nd := range needles {
			if bytes.Contains(b, nd) {
				e.t.Errorf("%s: %s holds the login or its box (%q…)", when, filepath.Base(p), nd[:min(8, len(nd))])
			}
		}
		for _, f := range leakscan.ScanWith(b, [][]byte{[]byte(credCanary)}) {
			if f.Pattern == leakscan.ExactSecret {
				e.t.Errorf("%s: %s holds the password (via %q)", when, filepath.Base(p), f.Via)
			}
		}
		return nil
	})
	if n == 0 {
		e.t.Fatalf("%s: the queue wrote nothing (the scan would prove nothing)", when)
	}
}

func boxNeedles(creds []TaskCredential) [][]byte {
	var out [][]byte
	for _, c := range creds {
		out = append(out, c.Sealed.CT, c.Sealed.Enc, []byte(base64.StdEncoding.EncodeToString(c.Sealed.CT)),
			[]byte(base64.StdEncoding.EncodeToString(c.Sealed.Enc)))
	}
	return out
}

// TestNoMailLoginInTaskQueue: the task queue (the files OpenTmpfs keeps in /run/tacy-tasks on the VM) never holds a
// mail login or its sealed box: not while the task runs (scanned while its mail call waits for the login sent again,
// after a vaultd restart, so its start and journal are in the queue), not after it ended; nor do its events. The
// task's own search ran with the login, and once the task ended the vault holds none.
func TestNoMailLoginInTaskQueue(t *testing.T) {
	e := newCredEnv(t, pCalls([3]string{"c1", "mail_search", `{"words":"invoice"}`}), pText("Alice's invoice 4471 is 1,240 EUR [m1]."))
	e.sv.restartAt = 1
	creds := e.seal(e.sealKey(), testAsker.Space, "start-q1", credCanary)
	task, err := e.c.StartTaskCredentials(context.Background(), mailRequest(), "start-q1", creds)
	if err != nil || task.Task == "" {
		t.Fatalf("start: %+v %v", task, err)
	}
	needles := append(boxNeedles(creds), []byte(credCanary), []byte(connUser))
	var again []TaskCredential
	evs := e.follow(task.Task, func(need *proto.CredentialNeed) {
		e.scanQueue("while the task runs", needles)
		again = e.seal(e.sealKey(), testAsker.Space, "start-q1", credCanary)
		if code, ec, _ := e.c.SendCredential(context.Background(), need.Task, "start-q1", again); code != 200 {
			t.Errorf("resend: %d %s", code, ec)
		}
	})
	if r := toolResultOf(evs, "mail_search"); !strings.Contains(r, `"m1"`) {
		t.Fatalf("the search didn't run with the task's login: %s (%s)", r, evTypesOf(evs))
	}
	if e.srv.Logins() != 1 {
		t.Fatalf("logins %d", e.srv.Logins())
	}
	waitFor(t, func() bool { return e.sv.cur().V.RunCreds() == 0 }, "the ended task's login forgotten")
	needles = append(needles, boxNeedles(again)...)
	e.scanQueue("after the end", needles)
	b, _ := json.Marshal(evs)
	for _, nd := range append(append(boxNeedles(creds), boxNeedles(again)...), []byte(credCanary)) {
		if bytes.Contains(b, nd) {
			t.Fatal("an event carries the login or its box")
		}
	}
}

// TestMailLoginNeededAfterVaultRestart: vaultd restarted after the start (its memory gone): the mail call doesn't
// reach the server; agentd holds it and asks (need_credential); with no app answering, it is denied when the wait
// ends and the model is told so; nothing went to the mail server.
func TestMailLoginNeededAfterVaultRestart(t *testing.T) {
	e := newCredEnv(t, pCalls([3]string{"c1", "mail_search", `{}`}), pText("I couldn't read your mail."))
	e.waits.Timeout = 1200 * time.Millisecond
	e.sv.restartAt = 1
	task, err := e.c.StartTaskCredentials(context.Background(), mailRequest(), "start-r1", e.seal(e.sealKey(), testAsker.Space, "start-r1", credCanary))
	if err != nil || task.Task == "" {
		t.Fatalf("start: %+v %v", task, err)
	}
	evs := e.follow(task.Task, nil)
	asked, settled := needs(evs)
	if len(asked) != 1 || asked[0].Task != task.Task || asked[0].Connection != "email" || asked[0].TimeoutS == 0 {
		t.Fatalf("asked %+v (%s)", asked, evTypesOf(evs))
	}
	if len(settled) != 1 || settled[0].Decision != guard.CredTimedOut {
		t.Fatalf("settled %+v", settled)
	}
	if r := toolResultOf(evs, "mail_search"); !strings.Contains(r, guard.MailLoginNeeded) {
		t.Fatalf("the model wasn't told: %s", r)
	}
	if len(e.srv.Commands()) != 0 {
		t.Fatalf("the mail server was reached: %v", e.srv.Commands())
	}
	if e.waits.Waiting(task.Task) != 0 {
		t.Fatal("a wait left open")
	}
}

// TestTaskCredentialResend: after a vaultd restart the app answers need_credential with the login sealed again:
// to the old boot's key it is refused (409 stale_key), with another start key (400 bad_credential) or without the
// run's MAC (404); sealed to the new key with the task's start key it is taken, and the held call runs (one login
// at the server) and the task's answer comes. A resend for a task that ended is refused.
func TestTaskCredentialResend(t *testing.T) {
	e := newCredEnv(t, pCalls([3]string{"c1", "mail_search", `{"words":"invoice"}`}), pText("Alice's invoice is 1,240 EUR [m1]."))
	e.sv.restartAt = 1
	oldKey := e.sealKey()
	task, err := e.c.StartTaskCredentials(context.Background(), mailRequest(), "start-r2", e.seal(oldKey, testAsker.Space, "start-r2", credCanary))
	if err != nil || task.Task == "" {
		t.Fatalf("start: %+v %v", task, err)
	}
	type try struct {
		code int
		err  string
	}
	var tries []try
	evs := e.follow(task.Task, func(need *proto.CredentialNeed) {
		ctx := context.Background()
		code, ec, _ := e.c.SendCredential(ctx, need.Task, "start-r2", e.seal(oldKey, testAsker.Space, "start-r2", credCanary))
		tries = append(tries, try{code, ec})
		newKey := e.sealKey()
		code, ec, _ = e.c.SendCredential(ctx, need.Task, "start-other", e.seal(newKey, testAsker.Space, "start-other", credCanary))
		tries = append(tries, try{code, ec})
		other := connTo(t, e.s, credUser) // the same user, but without the run's secret: no MAC
		code, ec, _ = other.SendCredential(ctx, need.Task, "start-r2", e.seal(newKey, testAsker.Space, "start-r2", credCanary))
		tries = append(tries, try{code, ec})
		code, ec, _ = e.c.SendCredential(ctx, need.Task, "start-r2", e.seal(newKey, testAsker.Space, "start-r2", credCanary))
		tries = append(tries, try{code, ec})
	})
	want := []try{{409, "stale_key"}, {400, "bad_credential"}, {404, "no_such_task"}, {200, ""}}
	if len(tries) != len(want) {
		t.Fatalf("tries %+v (%s)", tries, evTypesOf(evs))
	}
	for i := range want {
		if tries[i] != want[i] {
			t.Errorf("try %d: %+v, want %+v", i, tries[i], want[i])
		}
	}
	_, settled := needs(evs)
	if len(settled) != 1 || settled[0].Decision != guard.CredProvided {
		t.Fatalf("settled %+v", settled)
	}
	if r := toolResultOf(evs, "mail_search"); !strings.Contains(r, `"m1"`) {
		t.Fatalf("the held call didn't run: %s", r)
	}
	if e.srv.Logins() != 1 {
		t.Fatalf("logins %d", e.srv.Logins())
	}
	if code, ec, _ := e.c.SendCredential(context.Background(), task.Task, "start-r2", e.seal(e.sealKey(), testAsker.Space, "start-r2", credCanary)); code != 409 || ec != "task_ended" {
		t.Fatalf("after the end: %d %s", code, ec)
	}
}

// A start's credential is checked before anything runs: a key is required, at most one, for email, with mail tools,
// for this space and start key, sealed to this boot's key; nothing starts when it is refused.
func TestTaskStartCredentialRefusals(t *testing.T) {
	e := newCredEnv(t, pText("ok"))
	ctx := context.Background()
	key := e.sealKey()
	start := func(req proto.RunRequest, startKey string, creds []TaskCredential) *agentclient.Task {
		task, err := e.c.StartTaskCredentials(ctx, req, startKey, creds)
		if err != nil { // refused (an HTTP error): nothing started
			t.Logf("refused: %v", err)
			return &agentclient.Task{}
		}
		return task
	}
	two := append(e.seal(key, testAsker.Space, "k1", credCanary), e.seal(key, testAsker.Space, "k1", credCanary)...)
	noMail := mailRequest()
	noMail.Tools = []string{"web_search"}
	stale := e.seal(key, testAsker.Space, "k1", credCanary)
	stale[0].Sealed.Key = "x25519:" + base64.StdEncoding.EncodeToString(make([]byte, 32))
	for name, c := range map[string]struct {
		req   proto.RunRequest
		key   string
		creds []TaskCredential
	}{
		"no start key":     {mailRequest(), "", e.seal(key, testAsker.Space, "", credCanary)},
		"two":              {mailRequest(), "k1", two},
		"no mail tool":     {noMail, "k1", e.seal(key, testAsker.Space, "k1", credCanary)},
		"another key":      {mailRequest(), "k1", e.seal(key, testAsker.Space, "k2", credCanary)},
		"another space":    {mailRequest(), "k1", e.seal(key, "s_another", "k1", credCanary)},
		"another boot key": {mailRequest(), "k1", stale},
	} {
		if task := start(c.req, c.key, c.creds); task.Task != "" {
			t.Errorf("%s: started %s", name, task.Task)
		}
	}
	if n := e.sv.cur().V.RunCreds(); n != 0 {
		t.Fatalf("%d logins held after refusals", n)
	}
}

func evTypesOf(evs []proto.Event) string {
	var out []string
	for _, ev := range evs {
		out = append(out, ev.Type)
	}
	return strings.Join(out, ",")
}

func waitFor(t *testing.T, ok func() bool, what string) {
	t.Helper()
	for range 200 {
		if ok() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting: %s", what)
}

// Review 2, L6: a login sent again (POST /tasks/credential) while its task ends. The task's end (here a cancel, whose
// run_end reaches vaultd first) races the put; after the put agentd reads the task's state again, sees it ended,
// tells vaultd to forget the login and answers task_ended. No login is left in vaultd for the ended task.
func TestTaskCredentialRacingTaskEnd(t *testing.T) {
	e := newCredEnv(t, pCalls([3]string{"c1", "mail_search", `{"words":"invoice"}`}), pText("Alice's invoice is 1,240 EUR [m1]."))
	e.sv.restartAt = 1 // the mail call finds no login and waits for one sent again
	task, err := e.c.StartTaskCredentials(context.Background(), mailRequest(), "start-l6", e.seal(e.sealKey(), testAsker.Space, "start-l6", credCanary))
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	type answer struct {
		code int
		err  string
	}
	got := make(chan answer, 1)
	e.follow(task.Task, func(need *proto.CredentialNeed) {
		ctx := context.Background()
		e.sv.mu.Lock()
		e.sv.beforePut = func() { // the task ends between agentd's check and the put
			e.sv.mu.Lock()
			e.sv.beforePut = nil
			e.sv.mu.Unlock()
			if _, err := e.c.CancelTask(ctx, need.Task); err != nil {
				t.Errorf("cancel: %v", err)
			}
			for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
				if st, err := e.s.rt.Status(need.Task); err == nil && st.Outcome != nil {
					return
				}
			}
			t.Error("the task didn't end")
		}
		e.sv.mu.Unlock()
		code, ec, _ := e.c.SendCredential(ctx, need.Task, "start-l6", e.seal(e.sealKey(), testAsker.Space, "start-l6", credCanary))
		got <- answer{code, ec}
	})
	a := <-got
	if a.code != 409 || a.err != "task_ended" {
		t.Errorf("a login put as its task ended: %d %s, want 409 task_ended", a.code, a.err)
	}
	if _, err := e.sv.cur().V.RunCredInfo(task.Task, testAsker.Space); err == nil {
		t.Fatal("the ended task's login is still in vaultd")
	}
}
