package vault

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json/v2"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/tacyhq/tacy/leakscan"
	"github.com/tacyhq/tacy/sealstate"
)

// The per-task mail login (v1, the v1 design §5.4, §5.8). canaryPassword is planted in every box: it must never
// be anywhere but the vault's memory while its task runs.
const canaryPassword = "canary-pw-6b1f0e7c2a9d4e58"

func loginJSON(password string, edit func(m map[string]any)) []byte {
	m := map[string]any{"type": MailLoginType, "provider": "gmail", "host": "imap.gmail.com", "port": 993, "security": "tls",
		"address": "me@gmail.com", "username": "me@gmail.com", "password": password, "added_at": "2026-11-21T09:00:00Z"}
	if edit != nil {
		edit(m)
	}
	b, _ := json.Marshal(m)
	return b
}

// clock is a settable now for the rig's vault.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func (r *connRig) withClock() *clock {
	c := &clock{t: time.Now()}
	r.v.mu.Lock()
	r.v.now = c.now
	r.v.mu.Unlock()
	return c
}

// grant seals password for task in space under the start key, expiring in 2 h of the vault's now.
func (r *connRig) grant(t *testing.T, task, space, startKey, password string) RunGrant {
	t.Helper()
	key, err := r.c.SealKey(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	exp := r.v.now().Add(RunCredMaxAhead).UnixMilli()
	box, err := SealRunCred(key, space, ConnEmail, KeyHash(startKey), exp, loginJSON(password, nil))
	if err != nil {
		t.Fatal(err)
	}
	return RunGrant{Task: task, Space: space, Connection: ConnEmail, KeyHash: KeyHash(startKey), Expires: exp, Sealed: box}
}

func (r *connRig) putRun(t *testing.T, task, space, startKey, password string) {
	t.Helper()
	if _, err := r.c.RunPut(context.Background(), r.grant(t, task, space, startKey, password)); err != nil {
		t.Fatalf("run put: %v", err)
	}
}

func (r *connRig) leaseTask(task, space, host string) (*Secret, error) {
	return r.c.Lease(context.Background(), Request{Secret: ConnSecret, Connector: MailConnector, Host: host, Task: task,
		Action: "s1.a0", Space: space, Conn: ConnEmail})
}

// passwordOf is the task's login's password slice as the vault holds it (to see it zeroed later).
func (r *connRig) passwordOf(task string) []byte {
	cs := r.v.connState()
	cs.mu.Lock()
	defer cs.mu.Unlock()
	if rc := cs.runs[task]; rc != nil {
		return rc.password
	}
	return nil
}

func allZero(b []byte) bool { return len(bytes.Trim(b, "\x00")) == 0 }

// The rig's sealed connections state, opened with its key: the plaintext document the Keeper saved.
func openedState(t *testing.T, dir string) []byte {
	t.Helper()
	st, err := sealstate.New(&sealstate.File{Dir: dir}, testConnKey, "lease")
	if err != nil {
		t.Fatal(err)
	}
	b, err := st.Load(context.Background(), ConnState)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func holdsCanary(b []byte, canary string) bool {
	if bytes.Contains(b, []byte(canary)) {
		return true
	}
	for _, f := range leakscan.ScanWith(b, [][]byte{[]byte(canary)}) {
		if f.Pattern == leakscan.ExactSecret {
			return true
		}
	}
	return false
}

// TestRunCredentialNeverInSealedState: a task's login (and Settings' test box) goes through the whole v1 flow (test,
// per-task put, leases, end) and never reaches the Persister: the slot isn't written, its snapshot, the state the
// Keeper saved (opened with its key) and every blob it wrote hold no trace of the canary, nor do the records.
func TestRunCredentialNeverInSealedState(t *testing.T) {
	dir := t.TempDir()
	r := newConnRig(t, dir)
	ctx := context.Background()
	slot := r.slot
	v0 := slot.Version()
	// Settings' test of the account.
	key, _ := r.c.SealKey(ctx)
	box, _ := SealConn(key, "s_me", ConnEmail, emailJSON(func(m map[string]any) { m["password"] = canaryPassword }))
	pid, _, err := r.c.ConnPut(ctx, "s_me", ConnEmail, box)
	if err != nil {
		t.Fatal(err)
	}
	if s, err := r.leaseFor("s_me", "imap.gmail.com", pid); err != nil {
		t.Fatal(err)
	} else {
		s.Wipe()
	}
	r.c.ConnDiscard(ctx, pid)
	// Two tasks with the login: one ends, one is still running when the state is saved.
	r.putRun(t, "t_ended", "s_me", "start-ended", canaryPassword)
	r.putRun(t, "t_live", "s_me", "start-live", canaryPassword)
	for _, task := range []string{"t_ended", "t_live"} {
		s, err := r.leaseTask(task, "s_me", "imap.gmail.com")
		if err != nil || string(s.Bytes()) != canaryPassword {
			t.Fatalf("lease %s: %v", task, err)
		}
		s.Wipe()
	}
	if err := r.c.RunEnd(ctx, "t_ended"); err != nil {
		t.Fatal(err)
	}
	if err := r.keep.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	if v := slot.Version(); v != v0 {
		t.Errorf("the connections state was written %d times by the v1 flow", v-v0)
	}
	snap, _ := slot.Snapshot()
	if holdsCanary(snap, canaryPassword) {
		t.Errorf("the slot's snapshot holds the login: %s", snap)
	}
	if doc := openedState(t, dir); holdsCanary(doc, canaryPassword) || bytes.Contains(doc, []byte("me@gmail.com")) {
		t.Errorf("the saved state holds the login: %s", doc)
	}
	es, _ := os.ReadDir(dir)
	for _, e := range es {
		b, _ := os.ReadFile(filepath.Join(dir, e.Name()))
		if holdsCanary(b, canaryPassword) {
			t.Errorf("%s holds the login", e.Name())
		}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, rec := range r.recs {
		b, _ := json.Marshal(rec)
		if holdsCanary(b, canaryPassword) || bytes.Contains(b, []byte("me@gmail.com")) {
			t.Errorf("a record holds the login: %s", b)
		}
	}
}

// TestRunCredentialForgottenAtTaskEnd: the task's end forgets its login at once, zeroed in memory; another task's
// stays.
func TestRunCredentialForgottenAtTaskEnd(t *testing.T) {
	r := newConnRig(t, t.TempDir())
	ctx := context.Background()
	r.putRun(t, "t_a", "s_me", "start-a", canaryPassword)
	r.putRun(t, "t_b", "s_me", "start-b", canaryPassword)
	held := r.passwordOf("t_a")
	if string(held) != canaryPassword {
		t.Fatal("not held")
	}
	if n := r.v.RunCreds(); n != 2 {
		t.Fatalf("%d logins held", n)
	}
	if err := r.c.RunEnd(ctx, "t_a"); err != nil {
		t.Fatal(err)
	}
	if !allZero(held) {
		t.Error("the ended task's password wasn't zeroed")
	}
	if _, err := r.leaseTask("t_a", "s_me", "imap.gmail.com"); !errors.Is(err, ErrLoginNeeded) {
		t.Errorf("lease after the end: %v", err)
	}
	if _, err := r.c.RunInfo(ctx, "t_a", "s_me"); !errors.Is(err, ErrLoginNeeded) {
		t.Errorf("info after the end: %v", err)
	}
	if s, err := r.leaseTask("t_b", "s_me", "imap.gmail.com"); err != nil {
		t.Errorf("the other task's login: %v", err)
	} else {
		s.Wipe()
	}
	if err := r.c.RunEnd(ctx, "t_a"); err != nil {
		t.Errorf("ending twice: %v", err)
	}
	// A vaultd restart is a new process: nothing of the logins survives it.
	r2 := newConnRig(t, t.TempDir())
	if _, err := r2.leaseTask("t_b", "s_me", "imap.gmail.com"); !errors.Is(err, ErrLoginNeeded) {
		t.Errorf("after a restart: %v", err)
	}
}

// TestRunCredentialIdleTimeout: 15 minutes without a mail call forgets the login (zeroed); each call starts the
// time again; the box's expiry ends it whatever the use.
func TestRunCredentialIdleTimeout(t *testing.T) {
	r := newConnRig(t, t.TempDir())
	c := r.withClock()
	r.putRun(t, "t_a", "s_me", "start-a", canaryPassword)
	for range 3 { // used every 14 minutes: kept
		c.add(14 * time.Minute)
		s, err := r.leaseTask("t_a", "s_me", "imap.gmail.com")
		if err != nil {
			t.Fatalf("lease within the idle time: %v", err)
		}
		s.Wipe()
	}
	held := r.passwordOf("t_a")
	c.add(RunCredIdle)
	if _, err := r.leaseTask("t_a", "s_me", "imap.gmail.com"); !errors.Is(err, ErrLoginNeeded) {
		t.Fatalf("lease after 15 idle minutes: %v", err)
	}
	if !allZero(held) {
		t.Error("the idle login wasn't zeroed")
	}
	// The expiry: a box for 20 minutes, used every 10, is gone at 20.
	key, _ := r.c.SealKey(context.Background())
	exp := c.now().Add(20 * time.Minute).UnixMilli()
	box, _ := SealRunCred(key, "s_me", ConnEmail, KeyHash("start-b"), exp, loginJSON(canaryPassword, nil))
	if _, err := r.c.RunPut(context.Background(), RunGrant{Task: "t_b", Space: "s_me", Connection: ConnEmail,
		KeyHash: KeyHash("start-b"), Expires: exp, Sealed: box}); err != nil {
		t.Fatal(err)
	}
	c.add(10 * time.Minute)
	if s, err := r.leaseTask("t_b", "s_me", "imap.gmail.com"); err != nil {
		t.Fatalf("before the expiry: %v", err)
	} else {
		s.Wipe()
	}
	c.add(10 * time.Minute)
	if _, err := r.leaseTask("t_b", "s_me", "imap.gmail.com"); !errors.Is(err, ErrLoginNeeded) {
		t.Fatalf("at the expiry: %v", err)
	}
	if n := r.v.RunCreds(); n != 0 {
		t.Errorf("%d logins still held", n)
	}
}

// TestRunCredentialWrongTaskLease: a lease names its task, and gets only that task's login: never another task's,
// nor for another space or host; a lease without a task login finds none.
func TestRunCredentialWrongTaskLease(t *testing.T) {
	r := newConnRig(t, t.TempDir())
	ctx := context.Background()
	r.putRun(t, "t_a", "s_me", "start-a", canaryPassword)
	cases := []struct {
		task, space, host string
		want              error
	}{
		{"t_b", "s_me", "imap.gmail.com", ErrLoginNeeded},  // another task of the same space
		{"t_a", "s_other", "imap.gmail.com", ErrNotSet},    // the task, but another space
		{"t_a", "s_me", "imap.evil.example", ErrHost},      // the task, but another host
		{"none", "s_me", "imap.gmail.com", ErrLoginNeeded}, // the gateway's id for no task
	}
	for _, c := range cases {
		if s, err := r.leaseTask(c.task, c.space, c.host); !errors.Is(err, c.want) {
			if s != nil {
				s.Wipe()
			}
			t.Errorf("%s/%s/%s: %v, want %v", c.task, c.space, c.host, err, c.want)
		}
	}
	if _, err := r.c.RunInfo(ctx, "t_b", "s_me"); !errors.Is(err, ErrLoginNeeded) {
		t.Errorf("another task's info: %v", err)
	}
	if _, err := r.c.RunInfo(ctx, "t_a", "s_other"); !errors.Is(err, ErrNotSet) {
		t.Errorf("another space's info: %v", err)
	}
	// The pending path never reaches a task's login.
	if _, err := r.leaseFor("s_me", "imap.gmail.com", "p_000000000000000000000000"); !errors.Is(err, ErrNotSet) {
		t.Errorf("a made-up pending id: %v", err)
	}
	// Every refusal is recorded, released only for t_a.
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, rec := range r.recs {
		if rec.Decision == "released" && rec.Task != "t_a" {
			t.Errorf("released for %s", rec.Task)
		}
	}
}

// TestRunCredentialAADBindsTaskKey: the box opens only for the space, connection, task start key and expiry it was
// sealed for, under this boot's key, with an expiry ahead and at most 2 h away (plus skew), and only the login's type.
func TestRunCredentialAADBindsTaskKey(t *testing.T) {
	r := newConnRig(t, t.TempDir())
	ctx := context.Background()
	good := r.grant(t, "t_a", "s_me", "start-a", canaryPassword)
	bad := map[string]func(g *RunGrant){
		"another task's start key": func(g *RunGrant) { g.KeyHash = KeyHash("start-b") },
		"another space":            func(g *RunGrant) { g.Space = "s_other" },
		"another expiry":           func(g *RunGrant) { g.Expires++ },
		"tampered":                 func(g *RunGrant) { g.Sealed.CT = bytes.Clone(g.Sealed.CT); g.Sealed.CT[0] ^= 1 },
	}
	for name, edit := range bad {
		g := good
		edit(&g)
		if _, err := r.c.RunPut(ctx, g); !errors.Is(err, ErrBadSealed) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// Replayed into another task: agentd names that task's own start key, so it doesn't open.
	g := good
	g.Task, g.KeyHash = "t_b", KeyHash("start-b")
	if _, err := r.c.RunPut(ctx, g); !errors.Is(err, ErrBadSealed) {
		t.Errorf("replayed into another task: %v", err)
	}
	if n := r.v.RunCreds(); n != 0 {
		t.Fatalf("%d logins held after refusals", n)
	}
	key, _ := r.c.SealKey(ctx)
	seal := func(exp int64, pt []byte) RunGrant {
		box, err := SealRunCred(key, "s_me", ConnEmail, KeyHash("start-a"), exp, pt)
		if err != nil {
			t.Fatal(err)
		}
		return RunGrant{Task: "t_a", Space: "s_me", Connection: ConnEmail, KeyHash: KeyHash("start-a"), Expires: exp, Sealed: box}
	}
	now := time.Now()
	for name, g := range map[string]RunGrant{
		"expired":         seal(now.Add(-time.Second).UnixMilli(), loginJSON(canaryPassword, nil)),
		"too far ahead":   seal(now.Add(RunCredMaxAhead+RunCredSkew+time.Minute).UnixMilli(), loginJSON(canaryPassword, nil)),
		"the test's type": seal(now.Add(time.Hour).UnixMilli(), emailJSON(func(m map[string]any) { m["password"] = canaryPassword })),
		"unknown member":  seal(now.Add(time.Hour).UnixMilli(), loginJSON(canaryPassword, func(m map[string]any) { m["extra"] = 1 })),
		"smtp port":       seal(now.Add(time.Hour).UnixMilli(), loginJSON(canaryPassword, func(m map[string]any) { m["port"] = 587 })),
	} {
		if _, err := r.c.RunPut(ctx, g); !errors.Is(err, ErrBadSealed) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// Sealed to another boot's key (a box replayed after a reboot): stale.
	r2 := newConnRig(t, t.TempDir())
	if _, err := r2.c.RunPut(ctx, good); !errors.Is(err, ErrStaleKey) {
		t.Errorf("another boot's box: %v", err)
	}
	// Malformed grants are refused before anything opens.
	for name, edit := range map[string]func(g *RunGrant){
		"key hash": func(g *RunGrant) { g.KeyHash = "start-a" },
		"conn":     func(g *RunGrant) { g.Connection = "calendar" },
		"task":     func(g *RunGrant) { g.Task = "" },
	} {
		g := good
		edit(&g)
		if _, err := r.c.RunPut(ctx, g); !errors.Is(err, ErrBadRequest) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if info, err := r.c.RunPut(ctx, good); err != nil || info.Host != "imap.gmail.com" || info.Username != "me@gmail.com" {
		t.Fatalf("the good box: %+v %v", info, err)
	}
}

// TestConnectionsPutNoLongerKeeps: v1 keeps no account. Over the wire a pending box can't be committed (the op is
// gone), nothing is listed, and an account an older release kept in the sealed state is wiped at the first load.
func TestConnectionsPutNoLongerKeeps(t *testing.T) {
	dir := t.TempDir()
	// An older release's state: one kept account.
	{
		p, k, err := SealedConns(context.Background(), &sealstate.File{Dir: dir}, testConnKey, "lease", nil)
		if err != nil {
			t.Fatal(err)
		}
		old, _ := json.Marshal(map[string]any{"version": 1, "connections": []map[string]any{{"space": "s_me", "connection": "email",
			"kind": "email", "provider": "gmail", "address": "me@gmail.com", "username": "me@gmail.com", "host": "imap.gmail.com",
			"port": 993, "security": "tls", "password": []byte(canaryPassword)}}})
		if err := p.Save(old); err != nil {
			t.Fatal(err)
		}
		if err := k.Flush(context.Background()); err != nil {
			t.Fatal(err)
		}
		if !holdsCanary(openedState(t, dir), canaryPassword) {
			t.Fatal("the old state wasn't written")
		}
	}
	r := newConnRig(t, dir)
	ctx := context.Background()
	if r.v.Wiped() != 1 {
		t.Errorf("wiped %d", r.v.Wiped())
	}
	if err := r.keep.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	if doc := openedState(t, dir); holdsCanary(doc, canaryPassword) || bytes.Contains(doc, []byte("me@gmail.com")) {
		t.Errorf("the old account is still in the state: %s", doc)
	}
	if _, err := r.leaseFor("s_me", "imap.gmail.com", ""); !errors.Is(err, ErrLoginNeeded) {
		t.Errorf("the old account is still leased: %v", err)
	}
	// A put, then the old commit op by hand: refused (the connection closes, no reply), nothing kept.
	key, _ := r.c.SealKey(ctx)
	box, _ := SealConn(key, "s_me", ConnEmail, emailJSON(nil))
	pid, _, err := r.c.ConnPut(ctx, "s_me", ConnEmail, box)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.Dial("unix", r.c.Path)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	body, _ := json.Marshal(map[string]string{"op": "conn_commit", "pending": pid})
	frame := make([]byte, 4+len(body))
	binary.BigEndian.PutUint32(frame, uint32(len(body)))
	copy(frame[4:], body)
	conn.Write(frame)
	got, _ := io.ReadAll(conn)
	var rep struct {
		Info  *ConnInfo `json:"info"`
		Error string    `json:"error"`
	}
	if len(got) > 4 && json.Unmarshal(got[4:], &rep) == nil && rep.Info != nil {
		t.Errorf("conn_commit kept the account: %+v", rep.Info)
	}
	if l, _, _ := r.c.ConnList(ctx, "s_me"); len(l) != 0 {
		t.Errorf("listed: %v", l)
	}
	if _, err := r.leaseFor("s_me", "imap.gmail.com", ""); !errors.Is(err, ErrLoginNeeded) {
		t.Errorf("leased as the space's account: %v", err)
	}
	r.c.ConnDiscard(ctx, pid)
	if err := r.keep.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	if doc := openedState(t, dir); bytes.Contains(doc, []byte(fakeAppPassword)) || bytes.Contains(doc, []byte("me@gmail.com")) {
		t.Errorf("the put was kept: %s", doc)
	}
	sealedOnly(t, dir)
}
