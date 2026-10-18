package runner

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"syscall"
	"time"
)

// Client is agentd's side: it asks runnerd at Path for sandboxes.
type Client struct {
	Path string
}

// Sandbox is a sandbox runnerd made for this client; it lives as long as its connection.
type Sandbox struct {
	ID string

	c       *net.UnixConn
	replies chan *Reply
	done    chan struct{}
	exit    int // valid after done
	mu      sync.Mutex
	once    sync.Once
}

// Create asks for a sandbox of profile, passing files (the brain: its end of the harness socketpair). The caller
// may close its copies of files once Create returns.
func (cl *Client) Create(ctx context.Context, profile string, files ...*os.File) (*Sandbox, error) {
	var d net.Dialer
	nc, err := d.DialContext(ctx, "unix", cl.Path)
	if err != nil {
		return nil, err
	}
	c := nc.(*net.UnixConn)
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(60 * time.Second)
	}
	c.SetDeadline(deadline)
	if err := writeFrame(c, &Request{Op: OpCreate, Profile: profile}, files...); err != nil {
		c.Close()
		return nil, err
	}
	r, err := readReply(c)
	if err == nil && r.Error != "" {
		err = fmt.Errorf("runner: %s", r.Error)
	}
	if err == nil && r.Sandbox == "" {
		err = errors.New("runner: no sandbox id")
	}
	if err != nil {
		c.Close()
		return nil, err
	}
	c.SetDeadline(time.Time{})
	s := &Sandbox{ID: r.Sandbox, c: c, replies: make(chan *Reply, 2), done: make(chan struct{}), exit: -1}
	go s.read()
	return s, nil
}

func readReply(c *net.UnixConn) (*Reply, error) {
	b, err := readFrame(c)
	if err != nil {
		return nil, err
	}
	return decode[Reply](b)
}

func (s *Sandbox) read() {
	defer s.once.Do(func() { close(s.done) })
	for {
		r, err := readReply(s.c)
		if err != nil {
			return
		}
		if r.Exited != nil {
			s.exit = *r.Exited
			return
		}
		select {
		case s.replies <- r:
		default: // a reply nobody asked for
		}
	}
}

// Done is closed when the sandbox is gone: its workload exited, it was destroyed, or runnerd went away.
func (s *Sandbox) Done() <-chan struct{} { return s.done }

// ExitCode is the workload's exit code once Done (-1: unknown, destroyed or runnerd gone).
func (s *Sandbox) ExitCode() int {
	<-s.done
	return s.exit
}

// Exec runs a command in a hands sandbox, one at a time.
func (s *Sandbox) Exec(ctx context.Context, argv []string, stdin []byte, timeout time.Duration) (*ExecResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := writeFrame(s.c, &Request{Op: OpExec, Argv: argv, Stdin: stdin, TimeoutMs: timeout.Milliseconds()}); err != nil {
		return nil, err
	}
	select {
	case r := <-s.replies:
		if r.Error != "" || r.Exec == nil {
			return nil, fmt.Errorf("runner: exec: %s", r.Error)
		}
		return r.Exec, nil
	case <-s.done:
		return nil, errors.New("runner: the sandbox is gone")
	case <-ctx.Done():
		s.c.Close() // runnerd destroys the sandbox with the connection
		return nil, ctx.Err()
	}
}

// Close destroys the sandbox and waits (up to 10 s) until runnerd says it's gone.
func (s *Sandbox) Close() error {
	s.c.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if writeFrame(s.c, &Request{Op: OpDestroy}) == nil {
		select {
		case <-s.done:
		case <-s.replies:
		case <-time.After(10 * time.Second):
		}
	}
	return s.c.Close()
}

// SocketPair is a connected unix stream socket pair, both ends close-on-exec: local for this process, remote to
// pass to a sandbox.
func SocketPair() (local net.Conn, remote *os.File, err error) {
	syscall.ForkLock.RLock()
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err == nil {
		syscall.CloseOnExec(fds[0])
		syscall.CloseOnExec(fds[1])
	}
	syscall.ForkLock.RUnlock()
	if err != nil {
		return nil, nil, err
	}
	lf := os.NewFile(uintptr(fds[0]), "harness")
	defer lf.Close()
	local, err = net.FileConn(lf)
	if err != nil {
		syscall.Close(fds[1])
		return nil, nil, err
	}
	return local, os.NewFile(uintptr(fds[1]), "harness-brain"), nil
}
