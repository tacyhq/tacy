package vault

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/tacyhq/tacy/leakscan"
	"github.com/tacyhq/tacy/safety"
	"github.com/tacyhq/tacy/sealstate"
)

const fakeAppPassword = "abcd efgh ijkl mnop"

func emailJSON(edit func(m map[string]any)) []byte {
	m := map[string]any{"type": EmailType, "provider": "gmail", "host": "imap.gmail.com", "port": 993, "security": "tls",
		"address": "me@gmail.com", "username": "me@gmail.com", "password": fakeAppPassword}
	if edit != nil {
		edit(m)
	}
	b, _ := json.Marshal(m)
	return b
}

type connRig struct {
	v    *Vault
	c    *Client
	keep *sealstate.Keeper
	slot *sealstate.Slot
	mu   sync.Mutex
	recs []Record
}

// connKey stands in for the key service's conn/v1 key.
var testConnKey = bytes.Repeat([]byte{9}, 32)

// newConnRig is a vault whose connections are sealed state in dir (sealstate's file backend; on the VM the relay).
func newConnRig(t *testing.T, dir string) *connRig {
	t.Helper()
	r := &connRig{}
	p, k, err := SealedConns(context.Background(), &sealstate.File{Dir: dir}, testConnKey, "lease", nil)
	if err != nil {
		t.Fatal(err)
	}
	r.keep = k
	r.slot = p.(*sealstate.Slot)
	v, err := New(nil, ChatGrants(""), func(rec Record) { r.mu.Lock(); r.recs = append(r.recs, rec); r.mu.Unlock() })
	if err != nil {
		t.Fatal(err)
	}
	if err := v.EnableConns(p); err != nil {
		t.Fatal(err)
	}
	r.v = v
	sock, _ := os.MkdirTemp("", "vc")
	t.Cleanup(func() { os.RemoveAll(sock) })
	l, err := Listen(filepath.Join(sock, "v.sock"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go v.Serve(l, -1)
	r.c = &Client{Path: filepath.Join(sock, "v.sock")}
	return r
}

func (r *connRig) leaseFor(space, host, pending string) (*Secret, error) {
	return r.c.Lease(context.Background(), Request{Secret: ConnSecret, Connector: MailConnector, Host: host, Task: "t_1",
		Action: "s1.a0", Space: space, Conn: ConnEmail, Pending: pending})
}

// Settings' test box (v1): pending for the test login only, leased only with its pending id, for its space, and
// never kept: not listed, not leased as the space's account, gone once discarded; the sealed state stays empty.
func TestConnTestBoxNeverKept(t *testing.T) {
	dir := t.TempDir()
	r := newConnRig(t, dir)
	ctx := context.Background()
	key, err := r.c.SealKey(ctx)
	if err != nil || !strings.HasPrefix(key, "x25519:") {
		t.Fatalf("seal key %q, %v", key, err)
	}
	box, err := SealConn(key, "s_me", ConnEmail, emailJSON(nil))
	if err != nil {
		t.Fatal(err)
	}
	pid, info, err := r.c.ConnPut(ctx, "s_me", ConnEmail, box)
	if err != nil || info.Host != "imap.gmail.com" || info.Address != "me@gmail.com" || info.Port != 993 {
		t.Fatalf("put: %+v, %v", info, err)
	}
	if l, k2, _ := r.c.ConnList(ctx, "s_me"); len(l) != 0 || k2 != key {
		t.Fatalf("a pending connection is listed: %v", l)
	}
	if _, err := r.leaseFor("s_me", "imap.gmail.com", ""); !errors.Is(err, ErrLoginNeeded) {
		t.Fatalf("lease without the pending id or a task login: %v", err)
	}
	s, err := r.leaseFor("s_me", "imap.gmail.com", pid)
	if err != nil || string(s.Bytes()) != fakeAppPassword {
		t.Fatalf("test login lease: %v", err)
	}
	s.Wipe()
	if _, err := r.leaseFor("s_other", "imap.gmail.com", pid); !errors.Is(err, ErrNotSet) {
		t.Fatalf("another space's test lease: %v", err)
	}
	if _, err := r.leaseFor("s_me", "evil.example.com", pid); !errors.Is(err, ErrHost) {
		t.Fatalf("other host: %v", err)
	}
	if _, err := r.c.Lease(ctx, Request{Secret: ConnSecret, Connector: "web", Host: "imap.gmail.com", Task: "t_1", Action: "a",
		Space: "s_me", Conn: ConnEmail, Pending: pid}); !errors.Is(err, ErrNoGrant) {
		t.Fatalf("web connector: %v", err)
	}
	if _, err := r.c.Lease(ctx, Request{Secret: ConnSecret, Connector: MailConnector, Host: "imap.gmail.com", Task: "t_1", Action: "a",
		Space: "s_me"}); !errors.Is(err, ErrNoGrant) {
		t.Fatalf("by name without the connection: %v", err)
	}
	if err := r.c.ConnDiscard(ctx, pid); err != nil {
		t.Fatal(err)
	}
	if _, err := r.leaseFor("s_me", "imap.gmail.com", pid); !errors.Is(err, ErrNotSet) {
		t.Fatalf("after discard: %v", err)
	}
	if err := r.keep.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	// A restart: a box sealed to the old boot's key is stale.
	r2 := newConnRig(t, dir)
	if _, _, err := r2.c.ConnPut(ctx, "s_me", ConnEmail, box); !errors.Is(err, ErrStaleKey) {
		t.Fatalf("old boot's box: %v", err)
	}
	if err := r2.c.ConnRemove(ctx, "s_me", ConnEmail); err != nil {
		t.Fatalf("remove (nothing kept): %v", err)
	}
	// Records: names and ids, never the password, the address or the host.
	for _, rig := range []*connRig{r, r2} {
		rig.mu.Lock()
		for _, rec := range rig.recs {
			b, _ := json.Marshal(rec)
			if strings.Contains(string(b), fakeAppPassword) || strings.Contains(string(b), "me@gmail.com") {
				t.Errorf("record carries a value: %s", b)
			}
		}
		rig.mu.Unlock()
	}
}

func TestConnPutRefusals(t *testing.T) {
	r := newConnRig(t, t.TempDir())
	ctx := context.Background()
	key, _ := r.c.SealKey(ctx)
	put := func(space string, pt []byte) error {
		box, err := SealConn(key, space, ConnEmail, pt)
		if err != nil {
			t.Fatal(err)
		}
		_, _, err = r.c.ConnPut(ctx, "s_me", ConnEmail, box)
		return err
	}
	if err := put("s_me", emailJSON(nil)); err != nil {
		t.Fatalf("good box: %v", err)
	}
	// Sealed for another space (agentd or the relay moving a box): doesn't open.
	if err := put("s_other", emailJSON(nil)); !errors.Is(err, ErrBadSealed) {
		t.Fatalf("other space's box: %v", err)
	}
	for field, edit := range map[string]func(m map[string]any){
		"port":     func(m map[string]any) { m["port"] = 587 },
		"host":     func(m map[string]any) { m["host"] = "10.0.0.1" },
		"security": func(m map[string]any) { m["security"] = "plain" },
		"password": func(m map[string]any) { m["password"] = "a\r\nSTORE 1 +FLAGS" },
		"provider": func(m map[string]any) { m["provider"] = "outlook" },
		"type":     func(m map[string]any) { m["type"] = "x" },
		"address":  func(m map[string]any) { m["address"] = "nobody" },
	} {
		err := put("s_me", emailJSON(edit))
		var ce *ConnError
		if !errors.As(err, &ce) || !errors.Is(err, ErrBadSealed) || ce.Detail != field {
			t.Errorf("%s: %v", field, err)
		}
	}
	if err := put("s_me", emailJSON(func(m map[string]any) { m["extra"] = 1 })); !errors.Is(err, ErrBadSealed) {
		t.Fatalf("unknown member: %v", err)
	}
	if err := put("s_me", emailJSON(func(m map[string]any) { m["provider"], m["port"] = "other", 10993 })); err != nil {
		t.Fatalf("other provider on a high port: %v", err)
	}
	box, _ := SealConn(key, "s_me", ConnEmail, emailJSON(nil))
	box.CT[0] ^= 1
	if _, _, err := r.c.ConnPut(ctx, "s_me", ConnEmail, box); !errors.Is(err, ErrBadSealed) {
		t.Fatalf("tampered: %v", err)
	}
	if _, _, err := r.c.ConnPut(ctx, "s_me", "calendar", box); !errors.Is(err, ErrBadRequest) {
		t.Fatalf("unknown connection: %v", err)
	}
}

// Under a signed policy, a task's mail password is leased only when the policy has the mail connector and its
// fetch patterns allow the account's host.
func TestConnLeaseUnderPolicy(t *testing.T) {
	r := newConnRig(t, t.TempDir())
	st0, err := safety.NewState(safety.Config{Firm: "f_chat", Release: safety.ChatRelease("f_chat", "", nil, 300)})
	if err != nil {
		t.Fatal(err)
	}
	r.v.SetSafety(st0)
	r.putRun(t, "t_1", "s_me", "start-1", fakeAppPassword)
	// The release ceiling alone (no admin keys pinned): the mail connector is in it.
	s, err := r.leaseFor("s_me", "imap.gmail.com", "")
	if err != nil {
		t.Fatalf("under the release ceiling: %v", err)
	}
	s.Wipe()
	// A ceiling without the mail connector (an older release's): refused.
	rel := safety.ChatRelease("f_chat", "", nil, 300)
	delete(rel.Connectors, "mail")
	st, _ := safety.NewState(safety.Config{Firm: "f_chat", Release: rel})
	r.v.SetSafety(st)
	if _, err := r.leaseFor("s_me", "imap.gmail.com", ""); !errors.Is(err, ErrPolicy) {
		t.Fatalf("without the mail connector: %v", err)
	}
	// One whose mail connector names other servers only.
	rel = safety.ChatRelease("f_chat", "", nil, 300)
	m := rel.Connectors["mail"]
	m.Fetch = []string{"imap.fastmail.com"}
	rel.Connectors["mail"] = m
	st, _ = safety.NewState(safety.Config{Firm: "f_chat", Release: rel})
	r.v.SetSafety(st)
	if _, err := r.leaseFor("s_me", "imap.gmail.com", ""); !errors.Is(err, ErrPolicy) {
		t.Fatalf("host outside the mail connector's servers: %v", err)
	}
}

// sealedOnly: every file in dir is a sealed blob holding nothing of the test account, in any encoding.
func sealedOnly(t *testing.T, dir string) {
	t.Helper()
	es, _ := os.ReadDir(dir)
	if len(es) == 0 {
		t.Fatal("nothing saved")
	}
	for _, e := range es {
		b, _ := os.ReadFile(filepath.Join(dir, e.Name()))
		if !bytes.HasPrefix(b, []byte(sealstate.Magic)) {
			t.Errorf("%s isn't sealed", e.Name())
		}
		for _, f := range leakscan.ScanWith(b, [][]byte{[]byte(fakeAppPassword), []byte("me@gmail.com"), []byte("imap.gmail.com")}) {
			if f.Pattern == leakscan.ExactSecret {
				t.Errorf("%s holds the account (via %q)", e.Name(), f.Via)
			}
		}
	}
}
