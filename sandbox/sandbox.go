// Package sandbox runs the hands: untrusted commands an agent asks for (harness/v1 `exec`), each task in its own
// gVisor sandbox with no network, a read-only root, a tmpfs working folder and run limits (see
// docs/22-sandbox-runner.md).
//
// Runtime is the interface; Runsc is the real one (Linux, gVisor's runsc), Fake the local-development and test one
// (no isolation at all: it runs a Go function). Pool keeps a few sandboxes started ahead (single use: a sandbox
// serves one task and is destroyed with it). Hands adapts a Pool to the runtime's Guard.Exec.
package sandbox

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Limits bound one sandbox (memory, CPU, processes, working folder: the whole task) and each command in it (time,
// output).
type Limits struct {
	MemoryBytes int64         // the sandbox's memory cgroup (gVisor's kernel, the processes and the tmpfs together)
	CPUs        float64       // the sandbox's CPU quota, in CPUs (0.5 = half of one)
	Pids        int           // processes and threads per user inside (RLIMIT_NPROC: fork fails cleanly)
	PidsCgroup  int           // host-side backstop (the sandbox's own threads count too; past it the sandbox dies)
	WorkBytes   int64         // the /work tmpfs
	Timeout     time.Duration // per command, wall clock; the default when a request names none
	MaxTimeout  time.Duration // the most a request may ask for
	OutputBytes int           // per stream (stdout, stderr); the rest is dropped and Truncated set
	NoFile      int           // RLIMIT_NOFILE
}

// DefaultLimits fit a 1 vCPU / 2 GB tdx.small with a few tasks running (docs/22: measured idle cost ~15 MiB per
// sandbox).
var DefaultLimits = Limits{
	MemoryBytes: 256 << 20,
	CPUs:        0.5,
	Pids:        128,
	PidsCgroup:  512,
	WorkBytes:   64 << 20,
	Timeout:     60 * time.Second,
	MaxTimeout:  5 * time.Minute,
	OutputBytes: 256 << 10,
	NoFile:      1024,
}

// Request is one command in a task's sandbox.
type Request struct {
	Argv    []string
	Stdin   []byte
	Timeout time.Duration // 0: Limits.Timeout
}

// Result is the command's outcome. Stdout and Stderr are untrusted data.
type Result struct {
	Exit      int
	Stdout    []byte
	Stderr    []byte
	Truncated bool // an output stream hit Limits.OutputBytes
	TimedOut  bool // killed at the time limit
	OOM       bool // the sandbox hit its memory limit (it is gone; the task's next exec gets a new one)
	Duration  time.Duration
}

// Runtime starts sandboxes.
type Runtime interface {
	// Start creates and starts a sandbox: a fresh root view, an empty working folder, no network.
	Start(ctx context.Context, id string) (Sandbox, error)
}

// Launcher starts a sandbox whose first process is the workload itself (the brain), with files passed in as fds
// 3, 4, ... It ends when that process exits.
type Launcher interface {
	Launch(ctx context.Context, id string, files []*os.File, log io.Writer) (Instance, error)
}

// Instance is a launched sandbox.
type Instance interface {
	ID() string
	Done() <-chan struct{} // closed once the workload exited and the sandbox is gone
	ExitCode() int         // waits for Done; -1 when killed or unknown
	Close() error          // kills the workload and destroys the sandbox (idempotent)
}

// Sandbox is one started sandbox. It serves one task, then Close destroys it with its working folder.
type Sandbox interface {
	ID() string
	Exec(ctx context.Context, req Request) (*Result, error)
	// Alive is false once the sandbox died (OOM, killed): the caller replaces it.
	Alive() bool
	Close() error
}

var (
	ErrClosed     = errors.New("sandbox: closed")
	ErrBadRequest = errors.New("sandbox: bad request")
)

var idRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

// NewID is a random hands sandbox id. Ids never carry task, space or firm names: they show up in host process lists.
func NewID() string { return IDWith("h-") }

// IDWith is a random sandbox id with prefix ("b-" for a brain).
func IDWith(prefix string) string {
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return prefix + hex.EncodeToString(b[:])
}

func checkID(id string) error {
	if !idRe.MatchString(id) {
		return fmt.Errorf("%w: id %q", ErrBadRequest, id)
	}
	return nil
}

// check validates a request against the limits and returns its timeout.
func (l *Limits) check(req *Request) (time.Duration, error) {
	if len(req.Argv) == 0 || len(req.Argv) > 64 {
		return 0, fmt.Errorf("%w: 1 to 64 argv entries", ErrBadRequest)
	}
	for _, a := range req.Argv {
		if len(a) > 4096 || strings.ContainsRune(a, 0) {
			return 0, fmt.Errorf("%w: argv entry", ErrBadRequest)
		}
	}
	if len(req.Stdin) > 1<<20 {
		return 0, fmt.Errorf("%w: stdin over 1 MiB", ErrBadRequest)
	}
	t := req.Timeout
	if t == 0 {
		t = l.Timeout
	}
	if t < 0 || t > l.MaxTimeout {
		return 0, fmt.Errorf("%w: timeout over %s", ErrBadRequest, l.MaxTimeout)
	}
	return t, nil
}

// capBuffer keeps the first n bytes written and notes whether more came.
type capBuffer struct {
	mu   sync.Mutex
	buf  bytes.Buffer
	n    int
	over bool
}

func newCapBuffer(n int) *capBuffer { return &capBuffer{n: n} }

func (c *capBuffer) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if room := c.n - c.buf.Len(); room < len(p) {
		if room > 0 {
			c.buf.Write(p[:room])
		}
		c.over = true
		return len(p), nil // keep the writer going: a blocked pipe would stall the command
	}
	c.buf.Write(p)
	return len(p), nil
}

func (c *capBuffer) bytes() ([]byte, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return bytes.Clone(c.buf.Bytes()), c.over
}
