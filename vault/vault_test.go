package vault

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/tacyhq/tacy/leakscan"
)

// Test values only; nothing here is a real credential.
const (
	fakeTavily  = "tvly-test-not-a-real-key-0123456789"
	fakeTinfoil = "tf-test-not-a-real-key-ABCDEFGHIJ"
)

// TestMain doubles as the vault process: with VAULT_SPIKE_CHILD set, the test binary runs as the vault (what
// cmd/vaultd does), so the tests below talk to a real separate process over a real unix socket.
func TestMain(m *testing.M) {
	if path := os.Getenv("VAULT_SPIKE_CHILD"); path != "" {
		os.Unsetenv("VAULT_SPIKE_CHILD")
		grants := ChatGrants("")
		secrets := FromEnv(grants)
		for _, g := range grants {
			if _, ok := os.LookupEnv(g.Secret); ok {
				fmt.Fprintln(os.Stderr, "secret still in the environment:", g.Secret)
				os.Exit(3)
			}
		}
		enc := json.NewEncoder(os.Stdout)
		v, err := New(secrets, grants, func(r Record) { enc.Encode(r) }) // one connection at a time in these tests
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		l, err := Listen(path)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		fmt.Fprintln(os.Stderr, v.Serve(l, -1))
		os.Exit(1)
	}
	os.Exit(m.Run())
}

// startChild runs the vault as a child process with the fake secrets in its environment only, and returns a client
// for its socket and its stdout (the records).
func startChild(t *testing.T) (*Client, *bufio.Scanner) {
	t.Helper()
	dir, err := os.MkdirTemp("", "vault") // short path: unix socket paths are limited to ~104 bytes on macOS
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	path := filepath.Join(dir, "v", "vault.sock")
	cmd := exec.Command(os.Args[0], "-test.run=^$")
	cmd.Env = append(os.Environ(), "VAULT_SPIKE_CHILD="+path, "TAVILY_API_KEY="+fakeTavily, "TINFOIL_API_KEY="+fakeTinfoil)
	cmd.Stderr = os.Stderr
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	for i := 0; ; i++ {
		if c, err := net.Dial("unix", path); err == nil {
			c.Close()
			break
		}
		if i == 200 {
			t.Fatal("vault process didn't start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("socket mode: %v %v", fi.Mode(), err)
	}
	if fi, err := os.Stat(filepath.Dir(path)); err != nil || fi.Mode().Perm() != 0o700 {
		t.Fatalf("socket dir mode: %v %v", fi.Mode(), err)
	}
	return &Client{Path: path}, bufio.NewScanner(out)
}

func nextRecord(t *testing.T, sc *bufio.Scanner) Record {
	t.Helper()
	if !sc.Scan() {
		t.Fatal("no record")
	}
	line := sc.Text()
	if strings.Contains(line, fakeTavily) || strings.Contains(line, fakeTinfoil) {
		t.Fatal("a record carries a secret value")
	}
	var r Record
	if err := json.Unmarshal([]byte(line), &r); err != nil {
		t.Fatal(err)
	}
	return r
}

func TestLeaseFromSeparateProcess(t *testing.T) {
	c, recs := startChild(t)
	ctx := context.Background()
	req := Request{Secret: "TAVILY_API_KEY", Connector: "web", Host: "api.tavily.com", Task: "t_1", Action: "s1.a0"}

	s, err := c.Lease(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	if string(s.Bytes()) != fakeTavily || !strings.HasPrefix(s.Lease, "l_") {
		t.Fatal("wrong value or lease id")
	}
	r := nextRecord(t, recs)
	if r.Decision != "released" || r.Lease != s.Lease || r.Secret != "TAVILY_API_KEY" || r.Host != "api.tavily.com" ||
		r.Task != "t_1" || r.Action != "s1.a0" {
		t.Fatalf("record: %+v", r)
	}
	s2, err := c.Lease(ctx, req)
	if err != nil || s2.Lease == s.Lease {
		t.Fatal("each lease needs its own id")
	}
	nextRecord(t, recs)
	s.Wipe()
	if s.Bytes() != nil {
		t.Fatal("Wipe left the value")
	}

	refused := []struct {
		name string
		mod  func(*Request)
		want error
	}{
		{"other host", func(r *Request) { r.Host = "evil.example.com" }, ErrHost},
		{"lookalike host", func(r *Request) { r.Host = "api.tavily.com.evil.example" }, ErrHost},
		{"other connector", func(r *Request) { r.Connector = "mail" }, ErrNoGrant},
		{"model secret to web", func(r *Request) { r.Secret = "TINFOIL_API_KEY" }, ErrNoGrant},
		{"no grant", func(r *Request) { r.Secret = "AGENT_VM_TOKEN" }, ErrNoGrant},
		{"granted, not set", func(r *Request) { r.Secret, r.Host = "BRAVE_SEARCH_API_KEY", "api.search.brave.com" }, ErrNotSet},
		{"host with port", func(r *Request) { r.Host = "api.tavily.com:443" }, ErrBadRequest},
		{"uppercase host", func(r *Request) { r.Host = "API.tavily.com" }, ErrBadRequest},
		{"bad action id", func(r *Request) { r.Action = "-x" }, ErrBadRequest},
		{"bad secret name", func(r *Request) { r.Secret = "tavily" }, ErrBadRequest},
	}
	for _, tc := range refused {
		r := req
		tc.mod(&r)
		s, err := c.Lease(ctx, r)
		if !errors.Is(err, tc.want) || s != nil {
			t.Errorf("%s: got %v, want %v", tc.name, err, tc.want)
		}
		if rec := nextRecord(t, recs); rec.Decision != "denied" || rec.Reason != tc.want.Error() || rec.Lease != "" {
			t.Errorf("%s: record %+v", tc.name, rec)
		}
	}

	// The model gateway gets its own secret for its own host.
	m, err := c.Lease(ctx, Request{Secret: "TINFOIL_API_KEY", Connector: "model", Host: "inference.tinfoil.sh", Task: "t_1", Action: "s1.m"})
	if err != nil || string(m.Bytes()) != fakeTinfoil {
		t.Fatalf("model lease: %v", err)
	}
}

// rawConn is a hand-written client that breaks the wire rules.
func rawConn(t *testing.T, c *Client) net.Conn {
	t.Helper()
	conn, err := net.Dial("unix", c.Path)
	if err != nil {
		t.Fatal(err)
	}
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	return conn
}

func TestStrictWire(t *testing.T) {
	c, _ := startChild(t)
	frame := func(body string) []byte {
		b := make([]byte, 4+len(body))
		binary.BigEndian.PutUint32(b, uint32(len(body)))
		copy(b[4:], body)
		return b
	}
	bad := map[string][]byte{
		"unknown member": frame(`{"secret":"TAVILY_API_KEY","connector":"web","host":"api.tavily.com","task":"t","action":"a","all":true}`),
		"duplicate name": frame(`{"secret":"X","secret":"TAVILY_API_KEY","connector":"web","host":"api.tavily.com","task":"t","action":"a"}`),
		"not json":       frame(`secret=TAVILY_API_KEY`),
		"oversize":       {0x7f, 0, 0, 0},
		"empty":          {0, 0, 0, 0},
	}
	for name, b := range bad {
		conn := rawConn(t, c)
		conn.Write(b)
		got, err := io.ReadAll(conn)
		if len(got) != 0 || (err != nil && !errors.Is(err, io.EOF)) {
			t.Errorf("%s: got %d bytes, %v; want the connection closed with no reply", name, len(got), err)
		}
		conn.Close()
	}
}

func TestSecretNeverPrints(t *testing.T) {
	s := &Secret{v: []byte(fakeTavily), Lease: "l_1"}
	j, _ := json.Marshal(map[string]any{"s": s})
	for _, out := range []string{fmt.Sprint(s), fmt.Sprintf("%v %s %+v %#v %q", s, s, s, s, s), string(j),
		fmt.Errorf("upstream said: %v", s).Error()} {
		if strings.Contains(out, fakeTavily) {
			t.Fatalf("value printed: %q", out)
		}
	}
}

func TestRedactVariants(t *testing.T) {
	s := &Secret{v: []byte("k3y/with+odd chars=")}
	for _, v := range leakscan.Variants(s.Bytes()) {
		body := []byte(`{"echo":"` + string(v) + `","ok":1}`)
		got, n := Redact(body, s, "{{TAVILY_API_KEY}}")
		if n != 1 || bytes.Contains(got, v) || !bytes.Contains(got, []byte("{{TAVILY_API_KEY}}")) {
			t.Errorf("variant %q: n=%d, %s", v, n, got)
		}
	}
	if got, n := Redact([]byte("nothing here"), s, "x"); n != 0 || string(got) != "nothing here" {
		t.Fatal("redacted a clean body")
	}
}

func TestDropAndGrants(t *testing.T) {
	var recs []Record
	v, err := New(map[string][]byte{"TAVILY_API_KEY": []byte(fakeTavily)}, ChatGrants(""), func(r Record) { recs = append(recs, r) })
	if err != nil {
		t.Fatal(err)
	}
	req := Request{Secret: "TAVILY_API_KEY", Connector: "web", Host: "api.tavily.com", Task: "t", Action: "a"}
	if _, _, err := v.Lease(req); err != nil {
		t.Fatal(err)
	}
	v.Drop("TAVILY_API_KEY")
	if _, _, err := v.Lease(req); !errors.Is(err, ErrNotSet) {
		t.Fatalf("after Drop: %v", err)
	}
	if len(recs) != 2 || recs[1].Decision != "denied" {
		t.Fatalf("records: %+v", recs)
	}
	for _, g := range [][]Grant{
		{{Secret: "X", Connector: "web"}},                                       // no hosts
		{{Secret: "X", Connector: "web", SendOnlyTo: []string{"*.tavily.com"}}}, // no wildcards in v0
		{{Secret: "x", Connector: "web", SendOnlyTo: []string{"api.tavily.com"}}},
	} {
		if _, err := New(nil, g, nil); err == nil {
			t.Errorf("grant %+v accepted", g)
		}
	}
}

// On Linux the vault also checks the peer's uid (SO_PEERCRED): a process running as another user gets nothing.
func TestPeerUID(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("SO_PEERCRED is Linux only")
	}
	v, _ := New(map[string][]byte{"TAVILY_API_KEY": []byte(fakeTavily)}, ChatGrants(""), nil)
	dir := t.TempDir()
	path := filepath.Join(dir, "vault.sock")
	l, err := Listen(path)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go v.Serve(l, os.Getuid()+1)
	c := &Client{Path: path}
	req := Request{Secret: "TAVILY_API_KEY", Connector: "web", Host: "api.tavily.com", Task: "t", Action: "a"}
	if s, err := c.Lease(context.Background(), req); err == nil || s != nil {
		t.Fatal("a peer with another uid got a lease")
	}
}
