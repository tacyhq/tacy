package sandbox

import (
	"context"
	"fmt"
	"io"
	"os"
	"sync"
	"syscall"
	"time"
)

// Fake is the local-development and test runtime (macOS, no gVisor). It isolates nothing: each command is a Go
// function (Handler) given the sandbox's own working folder, a map. It keeps the real runtime's semantics that
// callers depend on: limits checked, time limit enforced, output capped, one working folder per sandbox, gone on
// Close, and a Close that later Execs see.
type Fake struct {
	Limits Limits
	// Handler runs one command. work is this sandbox's working folder (files by name); it must honor ctx.
	// Default: echo argv[1:] (like /bin/echo), and "cat" copies stdin.
	Handler func(ctx context.Context, sb string, work map[string][]byte, req Request, stdout, stderr Writer) (exit int, err error)
	// StartErr, if set, fails every Start and Launch (tests).
	StartErr error
	// Init is a launched sandbox's workload (Launch): it gets its own copies of the passed files and must return
	// once ctx ends (Close). Its return value is the exit code.
	Init func(ctx context.Context, id string, files []*os.File, log io.Writer) int

	mu      sync.Mutex
	started []string
	live    map[string]bool
}

// Writer is where a fake command writes its output.
type Writer interface {
	Write(p []byte) (int, error)
}

func NewFake() *Fake { return &Fake{Limits: DefaultLimits, live: map[string]bool{}} }

func (f *Fake) Start(ctx context.Context, id string) (Sandbox, error) {
	if err := checkID(id); err != nil {
		return nil, err
	}
	if f.StartErr != nil {
		return nil, f.StartErr
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.live[id] {
		return nil, fmt.Errorf("sandbox: %s exists", id)
	}
	f.started = append(f.started, id)
	f.live[id] = true
	return &fakeSandbox{f: f, id: id, work: map[string][]byte{}}, nil
}

// Started lists every sandbox id started, in order.
func (f *Fake) Started() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.started...)
}

// Live is the number of sandboxes started and not closed.
func (f *Fake) Live() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.live)
}

type fakeSandbox struct {
	f  *Fake
	id string

	mu     sync.Mutex
	work   map[string][]byte
	closed bool
	dead   bool
}

func (s *fakeSandbox) ID() string { return s.id }

func (s *fakeSandbox) Alive() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return !s.closed && !s.dead
}

// Kill marks the sandbox dead, as an out-of-memory kill would (tests).
func (s *fakeSandbox) Kill() {
	s.mu.Lock()
	s.dead = true
	s.mu.Unlock()
}

func (s *fakeSandbox) Exec(ctx context.Context, req Request) (*Result, error) {
	lim := s.f.Limits
	timeout, err := lim.check(&req)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	if s.closed || s.dead {
		s.mu.Unlock()
		return nil, ErrClosed
	}
	s.mu.Unlock()
	h := s.f.Handler
	if h == nil {
		h = echoHandler
	}
	stdout, stderr := newCapBuffer(lim.OutputBytes), newCapBuffer(lim.OutputBytes)
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	start := time.Now()
	type ret struct {
		exit int
		err  error
	}
	done := make(chan ret, 1)
	go func() {
		s.mu.Lock()
		work := s.work
		s.mu.Unlock()
		e, err := h(cctx, s.id, work, req, stdout, stderr)
		done <- ret{e, err}
	}()
	res := &Result{}
	select {
	case r := <-done:
		if r.err != nil {
			return nil, r.err
		}
		res.Exit = r.exit
	case <-cctx.Done():
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		res.Exit, res.TimedOut = 137, true
	}
	res.Duration = time.Since(start)
	var o1, o2 bool
	res.Stdout, o1 = stdout.bytes()
	res.Stderr, o2 = stderr.bytes()
	res.Truncated = o1 || o2
	return res, nil
}

func (s *fakeSandbox) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	s.work = nil
	s.mu.Unlock()
	s.f.mu.Lock()
	delete(s.f.live, s.id)
	s.f.mu.Unlock()
	return nil
}

func echoHandler(_ context.Context, _ string, _ map[string][]byte, req Request, stdout, _ Writer) (int, error) {
	if req.Argv[0] == "cat" {
		stdout.Write(req.Stdin)
		return 0, nil
	}
	for i, a := range req.Argv[1:] {
		if i > 0 {
			stdout.Write([]byte(" "))
		}
		stdout.Write([]byte(a))
	}
	stdout.Write([]byte("\n"))
	return 0, nil
}

// Launch runs Init in a goroutine on duplicates of files (the caller may close its own).
func (f *Fake) Launch(ctx context.Context, id string, files []*os.File, log io.Writer) (Instance, error) {
	if err := checkID(id); err != nil {
		return nil, err
	}
	if f.StartErr != nil {
		return nil, f.StartErr
	}
	if f.Init == nil {
		return nil, fmt.Errorf("sandbox: the fake has no Init")
	}
	var dups []*os.File
	for _, fl := range files {
		fd, err := syscall.Dup(int(fl.Fd()))
		if err != nil {
			for _, d := range dups {
				d.Close()
			}
			return nil, err
		}
		syscall.CloseOnExec(fd)
		dups = append(dups, os.NewFile(uintptr(fd), fl.Name()))
	}
	f.mu.Lock()
	if f.live[id] {
		f.mu.Unlock()
		return nil, fmt.Errorf("sandbox: %s exists", id)
	}
	f.started = append(f.started, id)
	f.live[id] = true
	f.mu.Unlock()
	ictx, cancel := context.WithCancel(context.Background())
	in := &fakeInstance{id: id, cancel: cancel, done: make(chan struct{})}
	go func() {
		in.exit = f.Init(ictx, id, dups, log)
		for _, d := range dups {
			d.Close()
		}
		f.mu.Lock()
		delete(f.live, id)
		f.mu.Unlock()
		close(in.done)
	}()
	return in, nil
}

type fakeInstance struct {
	id     string
	cancel context.CancelFunc
	done   chan struct{}
	exit   int
}

func (in *fakeInstance) ID() string            { return in.id }
func (in *fakeInstance) Done() <-chan struct{} { return in.done }
func (in *fakeInstance) ExitCode() int         { <-in.done; return in.exit }
func (in *fakeInstance) Close() error          { in.cancel(); <-in.done; return nil }
