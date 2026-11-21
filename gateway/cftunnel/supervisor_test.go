package cftunnel

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeStarter records starts; each child exits when released (or at once with exitNow).
type fakeStarter struct {
	mu       sync.Mutex
	tokens   [][]byte
	given    [][]byte // the slices Start was handed (cleared by the supervisor after Start)
	children []*fakeChild
	exitNow  bool
	refuse   error
}

type fakeChild struct {
	pid         int
	exit        chan struct{}
	wiped       chan struct{}
	once        sync.Once
	wipedAtExit bool
}

func (f *fakeStarter) Start(_ context.Context, token []byte) (Child, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.refuse != nil {
		return nil, f.refuse
	}
	f.tokens = append(f.tokens, slices.Clone(token))
	f.given = append(f.given, token)
	c := &fakeChild{pid: 100 + len(f.children), exit: make(chan struct{}), wiped: make(chan struct{})}
	if f.exitNow {
		close(c.exit)
	}
	f.children = append(f.children, c)
	return c, nil
}

func (f *fakeStarter) starts() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.children)
}

func (c *fakeChild) PID() int    { return c.pid }
func (c *fakeChild) Wait() error { <-c.exit; return errors.New("exit status 1") }
func (c *fakeChild) Wipe()       { c.once.Do(func() { close(c.wiped) }) }

func binWith(t *testing.T, b []byte) (string, string) {
	p := filepath.Join(t.TempDir(), "cloudflared")
	if err := os.WriteFile(p, b, 0o555); err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(b)
	return p, hex.EncodeToString(h[:])
}

// Review M2: a binary that isn't the pinned one is never started (an attested image with the wrong bytes is broken).
func TestSupervisorRefusesWrongBinary(t *testing.T) {
	bin, _ := binWith(t, []byte("not cloudflared"))
	f := &fakeStarter{}
	s := &Supervisor{Bin: bin, BinSHA256: strings.Repeat("0", 64), Start: f,
		Token: func(context.Context) ([]byte, error) { return []byte("tok"), nil }}
	err := s.Run(t.Context())
	if err == nil || !strings.Contains(err.Error(), "the pin is") || f.starts() != 0 {
		t.Fatalf("Run: %v, %d starts", err, f.starts())
	}
	ev, _ := s.Events()
	if len(ev) != 1 || ev[0].Kind != "refused" {
		t.Fatalf("events %+v", ev)
	}
}

// The token: waited for (the vault has none before the unlock), handed to Start trimmed, then cleared from the
// supervisor's memory; the child's copy wiped after TokenTTL while it runs.
func TestSupervisorTokenLifecycle(t *testing.T) {
	bin, sum := binWith(t, []byte("cloudflared"))
	f := &fakeStarter{}
	var mu sync.Mutex
	asked := 0
	var lent []byte
	s := &Supervisor{Bin: bin, BinSHA256: sum, Start: f, TokenTTL: 50 * time.Millisecond, TokenRetry: 10 * time.Millisecond,
		Token: func(context.Context) ([]byte, error) {
			mu.Lock()
			defer mu.Unlock()
			asked++
			if asked < 3 {
				return nil, errors.New("not set")
			}
			lent = []byte("  the-token\n")
			return lent, nil
		}}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go s.Run(ctx)
	deadline := time.Now().Add(2 * time.Second)
	for f.starts() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if f.starts() != 1 {
		t.Fatal("no start")
	}
	f.mu.Lock()
	tok, given, c := f.tokens[0], f.given[0], f.children[0]
	f.mu.Unlock()
	if string(tok) != "the-token" {
		t.Fatalf("token %q", tok)
	}
	time.Sleep(5 * time.Millisecond)
	mu.Lock()
	if !bytes.Equal(given, make([]byte, len(given))) || !strings.HasPrefix(string(lent), "  ") {
		t.Fatalf("the supervisor kept the token: %q / %q", given, lent)
	}
	mu.Unlock()
	select {
	case <-c.wiped:
		t.Fatal("wiped before TokenTTL")
	case <-time.After(20 * time.Millisecond):
	}
	select {
	case <-c.wiped: // TokenTTL, the child still running
	case <-time.After(time.Second):
		t.Fatal("token not wiped after TokenTTL")
	}
	ev, pid := s.Events()
	kinds := []string{}
	for _, e := range ev {
		kinds = append(kinds, e.Kind)
	}
	if pid != c.pid || !slices.Equal(kinds, []string{"lease_wait", "lease", "start"}) {
		t.Fatalf("events %v pid %d", kinds, pid)
	}
	close(c.exit)
}

// A child that exits is started again, with a fresh token each time and a growing wait; a start the launcher refuses
// (a failed confinement probe) stops the supervisor: never retried, never started another way.
func TestSupervisorRestartAndRefusal(t *testing.T) {
	bin, sum := binWith(t, []byte("cloudflared"))
	f := &fakeStarter{exitNow: true}
	n := 0
	s := &Supervisor{Bin: bin, BinSHA256: sum, Start: f, Backoff: 5 * time.Millisecond,
		Token: func(context.Context) ([]byte, error) { n++; return []byte{byte('a' + n)}, nil }}
	ctx, cancel := context.WithTimeout(t.Context(), 300*time.Millisecond)
	defer cancel()
	s.Run(ctx)
	if f.starts() < 3 || f.starts() > 12 {
		t.Fatalf("%d starts in 300 ms with backoff 5 ms doubling to 75 ms", f.starts())
	}
	if string(f.tokens[0]) == string(f.tokens[1]) {
		t.Fatal("the same token object for two starts")
	}
	for _, c := range f.children {
		select {
		case <-c.wiped:
		default:
			t.Fatal("a child's token copy wasn't wiped at its exit")
		}
	}
	r := &fakeStarter{refuse: errors.Join(ErrRefused, errors.New("confinement probe: /run/tacy/vault/vault.sock: connected"))}
	s2 := &Supervisor{Bin: bin, BinSHA256: sum, Start: r, Token: func(context.Context) ([]byte, error) { return []byte("t"), nil }}
	done := make(chan error, 1)
	go func() { done <- s2.Run(t.Context()) }()
	select {
	case err := <-done:
		if !errors.Is(err, ErrRefused) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("a refused start was retried")
	}
}

// cloudflared's arguments: the pinned config, http2, no self-update, no management diagnostics, and the token read
// from the memfd the launcher passes (never a path on a disk, never the command line or the environment).
func TestArgs(t *testing.T) {
	a := Args("/tacy/cloudflared.yml")
	j := strings.Join(a, " ")
	for _, want := range []string{"--config /tacy/cloudflared.yml", "--no-autoupdate", "--protocol http2", "--management-diagnostics=false",
		"--metrics 127.0.0.1:0", "run --token-file " + TokenPath} {
		if !strings.Contains(j, want) {
			t.Errorf("no %q in %s", want, j)
		}
	}
	if slices.Contains(a, "--token") || TokenPath != "/proc/self/fd/3" {
		t.Fatal(j)
	}
}
