// Package cftunnel is the agent VM's tunnel (a research note; decided
// 2026-11-21: in-container): a Fix B VM has no inbound path, so gatewayd's container runs Cloudflare's tunnel client,
// cloudflared (our patched, reproducible build), and serves it the only origin it may reach: an HTTP server on a
// unix socket that forwards an allowlist of agentd's routes (GET /attest, GET /health, POST /v) to agentd's socket
// and refuses everything else.
//
// cloudflared is confined in that container (review H1, 2026-11-21; launch_linux.go): gatewayd's launcher, the
// container's first process (root with only SETUID and SETGID), starts gatewayd as its own uid with no capabilities
// and cloudflared as another uid (TunnelUID) with no capabilities, no supplementary groups and no environment.
// cloudflared's uid can't open the vault's, agentd's, unlockd's or the ops sockets (their directories are other
// uids' with no access for others), has no dstack socket, can't trace or signal gatewayd (another uid, and gatewayd
// is non-dumpable), and can connect only to the ingress socket (group TunnelUID). Before every start the launcher
// runs a probe as cloudflared's uid that tries each of those and refuses to start cloudflared if any works.
//
// The tunnel token (routing and availability only; the bodies are EHBP-encrypted to agentd's attested key) is one of
// the API keys in the epoch's sealed secrets bundle: unlockd opens it only after the attested split-key unlock and
// hands it to vaultd, and gatewayd leases it from vaultd for each cloudflared start. Phala never sees it: it is never
// in the compose, the environment or on any disk; gatewayd hands it to cloudflared in a memfd (TD memory) that
// cloudflared reads at start as TokenPath, and empties it after TokenTTL.
package cftunnel

import (
	"bytes"
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"
)

// TokenPath is where cloudflared reads the token: the memfd the launcher passes as its fd 3.
const TokenPath = "/proc/self/fd/3"

// Starter starts one cloudflared with token (the launcher, launch_linux.go; a fake in tests).
type Starter interface {
	Start(ctx context.Context, token []byte) (Child, error)
}

// Child is one started cloudflared.
type Child interface {
	PID() int
	// Wait blocks until it has exited.
	Wait() error
	// Wipe empties the token's copy (cloudflared read it at start).
	Wipe()
}

// Supervisor starts cloudflared and starts it again when it exits.
type Supervisor struct {
	Bin       string // the pinned binary (/tacy/cloudflared)
	BinSHA256 string // its sha256, checked before every start ("" = not checked: tests)
	Start     Starter
	// Token is the tunnel token, fetched for each start (a vault lease); the caller keeps no copy.
	Token func(ctx context.Context) ([]byte, error)
	Logf  func(string, ...any)
	// TokenTTL is how long the token stays readable after a start (cloudflared reads it at start only).
	TokenTTL time.Duration
	// Backoff is the first wait before a restart (doubling to 15 times it, reset after a minute up); 0: 1 s.
	Backoff time.Duration
	// TokenRetry is how often the token is asked for while the vault has none (before the unlock); 0: 2 s.
	TokenRetry time.Duration

	mu     sync.Mutex
	events []Event
	pid    int
}

// Event is one start or exit (the spike reads them through /spike/cfd).
type Event struct {
	At     time.Time `json:"at"`
	Kind   string    `json:"kind"` // lease_wait, lease, start, exit, refused, probe
	PID    int       `json:"pid,omitempty"`
	Detail string    `json:"detail,omitempty"`
	MS     int64     `json:"ms,omitempty"` // lease: how long the lease took; exit: how long the process ran
}

// Args are cloudflared's arguments: the config pins the same values; the flags repeat them so a config that lost a
// line still runs this way. The token is read from TokenPath (the memfd).
func Args(config string) []string {
	return []string{"tunnel", "--config", config, "--no-autoupdate", "--protocol", "http2", "--management-diagnostics=false",
		"--metrics", "127.0.0.1:0", "--loglevel", "info", "run", "--token-file", TokenPath}
}

func (s *Supervisor) logf(f string, a ...any) {
	if s.Logf != nil {
		s.Logf(f, a...)
	}
}

// Record adds an event (the launcher's probe results come in this way too).
func (s *Supervisor) Record(e Event) { s.record(e) }

func (s *Supervisor) record(e Event) {
	e.At = time.Now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, e)
	if len(s.events) > 200 {
		s.events = s.events[len(s.events)-200:]
	}
	if e.Kind == "start" {
		s.pid = e.PID
	}
	if e.Kind == "exit" {
		s.pid = 0
	}
}

// Events is a copy of the recent events and the running pid (0: none).
func (s *Supervisor) Events() ([]Event, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Event(nil), s.events...), s.pid
}

var errNotTmpfs = errors.New("not a tmpfs: the token file must stay in TD memory")

// ErrRefused is a start the launcher refused (a failed confinement probe, a wrong binary): not retried.
var ErrRefused = errors.New("cftunnel: the launcher refused to start cloudflared")

// Run starts cloudflared until ctx ends: it checks the binary's hash, waits for the token (the vault has it only
// after the unlock), starts the child through Start, empties the token after TokenTTL, and starts again when the
// child exits (backoff 1 s doubling to 15 s, reset after a minute up). A wrong binary or a refused start stops it.
func (s *Supervisor) Run(ctx context.Context) error {
	if s.TokenTTL == 0 {
		s.TokenTTL = 20 * time.Second
	}
	first := s.Backoff
	if first == 0 {
		first = time.Second
	}
	backoff := first
	for ctx.Err() == nil {
		if s.BinSHA256 != "" {
			if err := checkSHA(s.Bin, s.BinSHA256); err != nil {
				s.record(Event{Kind: "refused", Detail: err.Error()})
				return err // the image is attested: a wrong binary is a broken image, not something to retry
			}
		}
		t0 := time.Now()
		tok, err := s.waitToken(ctx)
		if err != nil {
			return err
		}
		s.record(Event{Kind: "lease", MS: time.Since(t0).Milliseconds()})
		started := time.Now()
		ch, err := s.Start.Start(ctx, tok)
		clear(tok)
		if errors.Is(err, ErrRefused) {
			s.record(Event{Kind: "refused", Detail: err.Error()})
			return err
		}
		if err != nil {
			s.record(Event{Kind: "exit", Detail: "start: " + err.Error()})
			s.logf("cftunnel: start: %v", err)
		} else {
			s.record(Event{Kind: "start", PID: ch.PID()})
			s.logf("cftunnel: cloudflared started, pid %d", ch.PID())
			done := make(chan error, 1)
			go func() { done <- ch.Wait() }()
			var werr error
			select {
			case werr = <-done:
				ch.Wipe()
			case <-time.After(s.TokenTTL):
				ch.Wipe()
				werr = <-done
			}
			ran := time.Since(started)
			s.record(Event{Kind: "exit", PID: ch.PID(), Detail: errString(werr), MS: ran.Milliseconds()})
			s.logf("cftunnel: cloudflared exited after %s: %v", ran.Round(time.Millisecond), werr)
			if ran > time.Minute {
				backoff = first
			}
		}
		select {
		case <-ctx.Done():
		case <-time.After(backoff):
		}
		backoff = min(2*backoff, 15*first)
	}
	return ctx.Err()
}

// waitToken asks for the token every 2 s until it comes (the vault answers "not set" until the unlock).
func (s *Supervisor) waitToken(ctx context.Context) ([]byte, error) {
	logged := false
	for {
		tok, err := s.Token(ctx)
		if err == nil && len(tok) > 0 {
			return bytes.TrimSpace(tok), nil
		}
		if !logged {
			s.record(Event{Kind: "lease_wait", Detail: errString(err)})
			s.logf("cftunnel: waiting for the tunnel token: %v", err)
			logged = true
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(cmp.Or(s.TokenRetry, 2*time.Second)):
		}
	}
}

// wipe overwrites the token file with zeros and removes it (it is on tmpfs: TD memory).
func wipe(p string) {
	if fi, err := os.Stat(p); err == nil {
		if f, err := os.OpenFile(p, os.O_WRONLY, 0); err == nil {
			f.Write(make([]byte, fi.Size()))
			f.Close()
		}
	}
	os.Remove(p)
}

func checkSHA(path, want string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	h := sha256.Sum256(b)
	if got := hex.EncodeToString(h[:]); got != want {
		return fmt.Errorf("cftunnel: %s has sha256 %s, the pin is %s", path, got, want)
	}
	return nil
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
