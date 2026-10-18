package runner

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync"
	"time"

	"github.com/tacyhq/tacy/sandbox"
)

// Profile is a fixed kind of sandbox runnerd makes. Exactly one of Launch and Start is set.
type Profile struct {
	// Launch: the sandbox's first process is the workload (the brain), with Files descriptors passed in.
	Launch sandbox.Launcher
	Files  int
	// Start: a sandbox that runs execs (the hands).
	Start sandbox.Runtime
	// Prefix starts the ids ("b-", "h-").
	Prefix string
}

// Server is runnerd's side.
type Server struct {
	Profiles map[string]Profile
	PeerUID  int // the only uid allowed (agentd's); -1: no check (tests off Linux)
	Max      int // sandboxes at once, all connections together
	Logf     func(format string, args ...any)

	once  sync.Once
	slots chan struct{}
}

func (s *Server) logf(format string, args ...any) {
	if s.Logf != nil {
		s.Logf(format, args...)
	}
}

// Serve accepts connections until l closes.
func (s *Server) Serve(l *net.UnixListener) error {
	s.once.Do(func() { s.slots = make(chan struct{}, max(1, s.Max)) })
	for {
		c, err := l.AcceptUnix()
		if err != nil {
			return err
		}
		go s.conn(c)
	}
}

func (s *Server) conn(c *net.UnixConn) {
	defer c.Close()
	if s.PeerUID >= 0 {
		if err := checkPeer(c, s.PeerUID); err != nil {
			s.logf("runner: refused a connection: %v", err)
			return
		}
	}
	fail := func(code string, err error) {
		c.SetWriteDeadline(time.Now().Add(5 * time.Second))
		writeFrame(c, &Reply{Error: code + ": " + err.Error()})
	}
	c.SetReadDeadline(time.Now().Add(10 * time.Second))
	body, files, err := readWithRights(c)
	if err != nil {
		if err != io.EOF {
			s.logf("runner: %v", err)
		}
		return
	}
	defer closeFiles(files)
	req, err := decode[Request](body)
	if err == nil && (req.Op != OpCreate || len(req.Argv) > 0 || len(req.Stdin) > 0 || req.TimeoutMs != 0) {
		err = fmt.Errorf("the first frame must be a create")
	}
	if err != nil {
		fail("bad_request", err)
		return
	}
	p, ok := s.Profiles[req.Profile]
	if !ok {
		fail("unknown_profile", fmt.Errorf("%q", req.Profile))
		return
	}
	if len(files) != p.Files {
		fail("bad_request", fmt.Errorf("profile %s takes %d descriptors, got %d", req.Profile, p.Files, len(files)))
		return
	}
	for _, f := range files {
		if err := checkSocket(f); err != nil {
			fail("bad_request", fmt.Errorf("passed descriptor: %w", err))
			return
		}
	}
	select {
	case s.slots <- struct{}{}:
		defer func() { <-s.slots }()
	default:
		fail("limit", fmt.Errorf("%d sandboxes running", cap(s.slots)))
		return
	}

	id := sandbox.IDWith(p.Prefix)
	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	var inst sandbox.Instance
	var sb sandbox.Sandbox
	if p.Launch != nil {
		inst, err = p.Launch.Launch(ctx, id, files, &lineLog{prefix: id + ": ", logf: s.logf})
	} else {
		sb, err = p.Start.Start(ctx, id)
	}
	cancel()
	closeFiles(files) // the sandbox has its own copies
	files = nil
	if err != nil {
		s.logf("runner: %s %s didn't start: %v", req.Profile, id, err)
		fail("failed", fmt.Errorf("the sandbox didn't start"))
		return
	}
	destroy := func() {
		if inst != nil {
			inst.Close()
		} else {
			sb.Close()
		}
	}
	defer func() {
		destroy()
		s.logf("runner: %s %s destroyed after %s", req.Profile, id, time.Since(start).Round(time.Millisecond))
	}()
	s.logf("runner: %s %s started in %s", req.Profile, id, time.Since(start).Round(time.Millisecond))

	var wmu sync.Mutex
	send := func(r *Reply) error {
		wmu.Lock()
		defer wmu.Unlock()
		c.SetWriteDeadline(time.Now().Add(10 * time.Second))
		return writeFrame(c, r)
	}
	if err := send(&Reply{Sandbox: id}); err != nil {
		return
	}
	c.SetReadDeadline(time.Time{})
	if inst != nil {
		go func() {
			<-inst.Done()
			code := inst.ExitCode()
			s.logf("runner: %s %s exited (%d)", req.Profile, id, code)
			send(&Reply{Exited: &code})
			c.Close() // ends the read below
		}()
	}
	for {
		body, err := readFrame(c)
		if err != nil {
			return // closed: the sandbox goes with the connection
		}
		r, err := decode[Request](body)
		if err != nil {
			fail("bad_request", err)
			return
		}
		switch {
		case r.Op == OpDestroy && r.Profile == "" && len(r.Argv) == 0:
			destroy()
			send(&Reply{OK: true})
			return
		case r.Op == OpExec && sb != nil && r.Profile == "":
			res, err := sb.Exec(context.Background(), sandbox.Request{Argv: r.Argv, Stdin: r.Stdin,
				Timeout: time.Duration(r.TimeoutMs) * time.Millisecond})
			if err != nil {
				fail("exec", err)
				return
			}
			if send(&Reply{Exec: &ExecResult{Exit: res.Exit, Stdout: res.Stdout, Stderr: res.Stderr, Truncated: res.Truncated,
				TimedOut: res.TimedOut, OOM: res.OOM, Ms: res.Duration.Milliseconds()}}) != nil {
				return
			}
			if !sb.Alive() {
				code := 137
				send(&Reply{Exited: &code})
				return
			}
		default:
			fail("bad_request", fmt.Errorf("op %q not allowed here", r.Op))
			return
		}
	}
}

// lineLog passes a sandbox's output to the log a line at a time, each prefixed with its id and cut at 2 KiB, so a
// workload can't forge another's lines or flood one line without end.
type lineLog struct {
	prefix string
	logf   func(string, ...any)
	mu     sync.Mutex
	buf    []byte
}

func (l *lineLog) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := len(p)
	for len(p) > 0 {
		i := bytes.IndexByte(p, '\n')
		if i < 0 {
			if room := 2048 - len(l.buf); room > 0 {
				l.buf = append(l.buf, p[:min(room, len(p))]...)
			}
			break
		}
		if room := 2048 - len(l.buf); room > 0 {
			l.buf = append(l.buf, p[:min(room, i)]...)
		}
		if l.logf != nil {
			line := bytes.Map(func(r rune) rune {
				if r < 0x20 && r != '\t' || r == 0x7f {
					return '?'
				}
				return r
			}, bytes.ToValidUTF8(l.buf, []byte("?")))
			l.logf("%s%s", l.prefix, line)
		}
		l.buf = l.buf[:0]
		p = p[i+1:]
	}
	return n, nil
}

// StdLogf logs with the standard logger.
func StdLogf(format string, args ...any) { log.Printf(format, args...) }

// Listen listens on a unix socket at path (a stale one removed) with mode (0660: agentd connects through the
// socket's group, runnerd's primary group).
func Listen(path string, mode os.FileMode) (*net.UnixListener, error) {
	os.Remove(path)
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, mode); err != nil {
		l.Close()
		return nil, err
	}
	return l, nil
}
