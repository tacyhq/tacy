// Package cftunnel is the cloudflared spike (a research note, branch
// vm-fix-b-cloudflared): a Fix B VM has no inbound path, so gatewayd runs Cloudflare's tunnel client, cloudflared,
// as its own child process in its own container (the six-service compose shape doesn't change), and serves that
// child the only origin it may reach: an HTTP server on a unix socket in gatewayd's private tmpfs that forwards an
// allowlist of agentd's routes (GET /attest, GET /health, POST /v) to agentd's socket and refuses everything else.
//
// The tunnel token (routing and availability only; the bodies are EHBP-encrypted to agentd's attested key) is one of
// the API keys in the epoch's sealed secrets bundle: unlockd opens it only after the attested split-key unlock and
// hands it to vaultd, and gatewayd leases it from vaultd for each cloudflared start. Phala never sees it: it is never
// in the compose, the environment or on the disk; it lives in TD memory (a 0600 file in gatewayd's tmpfs for the
// few seconds cloudflared takes to read it at start).
//
// Throwaway spike code: not reviewed, not released.
package cftunnel

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"
)

// Supervisor starts cloudflared and starts it again when it exits.
type Supervisor struct {
	Bin       string // the pinned binary (/tacy/cloudflared)
	BinSHA256 string // its sha256, checked before every start ("" = not checked: tests)
	Config    string // the pinned locally-managed config (/tacy/cloudflared.yml)
	Dir       string // gatewayd's private tmpfs directory for the token file (made 0700)
	// Token is the tunnel token, fetched for each start (a vault lease); the caller keeps no copy.
	Token func(ctx context.Context) ([]byte, error)
	Logf  func(string, ...any)
	Out   io.Writer // cloudflared's stdout and stderr (nil: discarded)
	// TokenTTL is how long the token file stays after a start (cloudflared reads it at start only).
	TokenTTL time.Duration

	mu     sync.Mutex
	events []Event
	pid    int
}

var errNotTmpfs = errors.New("not a tmpfs: the token file must stay in TD memory")

// Event is one start or exit (the spike reads them through /spike/cfd).
type Event struct {
	At     time.Time `json:"at"`
	Kind   string    `json:"kind"` // lease_wait, lease, start, exit, refused
	PID    int       `json:"pid,omitempty"`
	Detail string    `json:"detail,omitempty"`
	MS     int64     `json:"ms,omitempty"` // lease: how long the lease took; exit: how long the process ran
}

// Args are cloudflared's arguments for a token file: the config pins the same values; the flags repeat them so a
// config that lost a line still runs this way.
func (s *Supervisor) Args(tokenFile string) []string {
	return []string{"tunnel", "--config", s.Config, "--no-autoupdate", "--protocol", "http2", "--management-diagnostics=false",
		"--metrics", "127.0.0.1:0", "--loglevel", "info", "run", "--token-file", tokenFile}
}

func (s *Supervisor) logf(f string, a ...any) {
	if s.Logf != nil {
		s.Logf(f, a...)
	}
}

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

// Run starts cloudflared until ctx ends: it waits for the token (the vault has it only after the unlock), writes it
// to a fresh 0600 file, starts the child, removes the file after TokenTTL, and starts again (backoff 1 s doubling to
// 15 s, reset after a minute up) when the child exits.
func (s *Supervisor) Run(ctx context.Context) error {
	if s.TokenTTL == 0 {
		s.TokenTTL = 20 * time.Second
	}
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(s.Dir, 0o700); err != nil {
		return err
	}
	if err := checkTmpfs(s.Dir); err != nil {
		return fmt.Errorf("cftunnel: %s: %w", s.Dir, err)
	}
	backoff := time.Second
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
		f, err := writeToken(s.Dir, tok)
		clear(tok)
		if err != nil {
			return err
		}
		cmd := exec.CommandContext(ctx, s.Bin, s.Args(f)...)
		cmd.Env = []string{"HOME=" + s.Dir} // nothing of gatewayd's environment
		cmd.Stdout, cmd.Stderr = s.Out, s.Out
		setDeathSignal(cmd)
		started := time.Now()
		if err := cmd.Start(); err != nil {
			wipe(f)
			s.record(Event{Kind: "exit", Detail: "start: " + err.Error()})
			s.logf("cftunnel: start: %v", err)
		} else {
			s.record(Event{Kind: "start", PID: cmd.Process.Pid})
			s.logf("cftunnel: cloudflared started, pid %d", cmd.Process.Pid)
			done := make(chan error, 1)
			go func() { done <- cmd.Wait() }()
			var werr error
			select {
			case werr = <-done:
				wipe(f)
			case <-time.After(s.TokenTTL):
				wipe(f)
				werr = <-done
			}
			ran := time.Since(started)
			s.record(Event{Kind: "exit", PID: cmd.Process.Pid, Detail: errString(werr), MS: ran.Milliseconds()})
			s.logf("cftunnel: cloudflared exited after %s: %v", ran.Round(time.Millisecond), werr)
			if ran > time.Minute {
				backoff = time.Second
			}
		}
		select {
		case <-ctx.Done():
		case <-time.After(backoff):
		}
		backoff = min(2*backoff, 15*time.Second)
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
		case <-time.After(2 * time.Second):
		}
	}
}

func writeToken(dir string, tok []byte) (string, error) {
	var r [8]byte
	rand.Read(r[:])
	p := filepath.Join(dir, "token-"+hex.EncodeToString(r[:]))
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", err
	}
	_, err = f.Write(tok)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		wipe(p)
		return "", err
	}
	return p, nil
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
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.String()
	}
	return err.Error()
}
