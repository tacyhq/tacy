// Package runnertest runs a runnerd for tests (runner/v0 on a real unix socket) with the brain profile, so tests
// elsewhere (agentd's parity scenarios, the conformance suite) can put the brain behind it. With TACY_RUNSC (runsc,
// its gvisor-bin/ next to it) and TACY_BRAIN_BIN (cmd/brain built for this platform) set on Linux, the brain runs in
// real gVisor (TACY_RUNSC_PLATFORM, TACY_RUNSC_ROOTLESS=1 as in the CVM); otherwise in a sandbox.Fake that runs
// brain.Run in this process on the passed socket (no isolation, same lifecycle). Not part of any binary.
package runnertest

import (
	"context"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/tacyhq/tacy/brain"
	"github.com/tacyhq/tacy/runner"
	"github.com/tacyhq/tacy/sandbox"
)

// Env is a running runnerd.
type Env struct {
	Client *runner.Client
	Kind   string // "fake" or "runsc <platform>[ rootless]"
	rec    *recorder
}

// Real reports whether TACY_RUNSC and TACY_BRAIN_BIN ask for real gVisor.
func Real() bool {
	return runtime.GOOS == "linux" && os.Getenv("TACY_RUNSC") != "" && os.Getenv("TACY_BRAIN_BIN") != ""
}

// Start runs a runnerd with the brain profile until the test ends.
func Start(t testing.TB) *Env {
	t.Helper()
	var l sandbox.Launcher
	kind := "fake"
	if os.Getenv("TACY_REQUIRE_RUNSC") == "1" && !Real() {
		t.Fatal("TACY_REQUIRE_RUNSC: TACY_RUNSC and TACY_BRAIN_BIN must be set (Linux)")
	}
	if Real() {
		cfg := runner.Config{Runsc: os.Getenv("TACY_RUNSC"), Dir: t.TempDir(), Platform: os.Getenv("TACY_RUNSC_PLATFORM"),
			Rootless: os.Getenv("TACY_RUNSC_ROOTLESS") == "1"}
		t.Cleanup(func() { os.Chmod(filepath.Join(cfg.Dir, "brain-root"), 0o755) }) // read-only root: let TempDir remove it
		r, err := runner.BrainRunsc(cfg, os.Getenv("TACY_BRAIN_BIN"), "")
		if err != nil {
			t.Fatal(err)
		}
		l, kind = r, "runsc "+r.Platform
		if kind == "runsc " {
			kind += "systrap"
		}
		if cfg.Rootless {
			kind += " rootless"
		}
	} else {
		f := sandbox.NewFake()
		f.Init = FakeBrain
		l = f
	}
	rec := &recorder{l: l, live: map[sandbox.Instance]bool{}}
	dir, err := os.MkdirTemp("", "rn") // short: unix socket paths are limited to about 100 bytes
	if err != nil {
		t.Fatal(err)
	}
	ln, err := runner.Listen(dir+"/runner.sock", 0o600)
	if err != nil {
		t.Fatal(err)
	}
	srv := &runner.Server{Profiles: map[string]runner.Profile{"brain": {Launch: rec, Files: 1, Prefix: "b-"}},
		PeerUID: -1, Max: 8, Logf: t.Logf}
	if runtime.GOOS == "linux" {
		srv.PeerUID = os.Getuid()
	}
	go srv.Serve(ln)
	t.Cleanup(func() {
		ln.Close()
		rec.killAll()
		os.RemoveAll(dir)
	})
	return &Env{Client: &runner.Client{Path: dir + "/runner.sock"}, Kind: kind, rec: rec}
}

// KillBrains kills every running brain sandbox (a crash, as the brain sees it: nothing more is sent) and returns
// how many there were.
func (e *Env) KillBrains() int { return e.rec.killAll() }

// Brains is the number of brain sandboxes running.
func (e *Env) Brains() int {
	e.rec.mu.Lock()
	defer e.rec.mu.Unlock()
	return len(e.rec.live)
}

// FakeBrain is the fake sandbox's workload: our brain, in this process, on the passed socket.
func FakeBrain(ctx context.Context, _ string, files []*os.File, _ io.Writer) int {
	c, err := net.FileConn(files[0])
	if err != nil {
		return 1
	}
	if err := brain.Run(ctx, c); err != nil && ctx.Err() == nil {
		return 1
	}
	return 0
}

type recorder struct {
	l    sandbox.Launcher
	mu   sync.Mutex
	live map[sandbox.Instance]bool
}

func (r *recorder) Launch(ctx context.Context, id string, files []*os.File, log io.Writer) (sandbox.Instance, error) {
	in, err := r.l.Launch(ctx, id, files, log)
	if err != nil {
		return nil, err
	}
	r.mu.Lock()
	r.live[in] = true
	r.mu.Unlock()
	go func() {
		<-in.Done()
		r.mu.Lock()
		delete(r.live, in)
		r.mu.Unlock()
	}()
	return in, nil
}

func (r *recorder) killAll() int {
	r.mu.Lock()
	var ins []sandbox.Instance
	for in := range r.live {
		ins = append(ins, in)
	}
	r.mu.Unlock()
	for _, in := range ins {
		in.Close()
	}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		r.mu.Lock()
		n := len(r.live)
		r.mu.Unlock()
		if n == 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	return len(ins)
}
