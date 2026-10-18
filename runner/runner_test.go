package runner_test

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"os"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tacyhq/tacy/harness/conformance"
	"github.com/tacyhq/tacy/runner"
	"github.com/tacyhq/tacy/runner/runnertest"
	"github.com/tacyhq/tacy/sandbox"
)

// serve runs a runner server with the given profiles on a fresh socket.
func serve(t *testing.T, profiles map[string]runner.Profile, max int) *runner.Client {
	t.Helper()
	logf := runnertest.Logf(t)
	dir, err := os.MkdirTemp("", "rn")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	l, err := runner.Listen(dir+"/r.sock", 0o600)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	srv := &runner.Server{Profiles: profiles, PeerUID: -1, Max: max, Logf: logf}
	if runtime.GOOS == "linux" {
		srv.PeerUID = os.Getuid()
	}
	go srv.Serve(l)
	return &runner.Client{Path: dir + "/r.sock"}
}

// echoInit: the fake workload answers each line on fd 3 with "echo: <line>" until ctx ends or the socket closes.
func echoInit(ctx context.Context, _ string, files []*os.File, log io.Writer) int {
	c, err := net.FileConn(files[0])
	if err != nil {
		return 2
	}
	defer c.Close()
	context.AfterFunc(ctx, func() { c.Close() })
	io.WriteString(log, "started\n")
	buf := make([]byte, 256)
	for {
		n, err := c.Read(buf)
		if err != nil {
			if ctx.Err() != nil {
				return 137
			}
			return 0
		}
		if string(buf[:n]) == "exit 3\n" {
			return 3
		}
		c.Write(append([]byte("echo: "), buf[:n]...))
	}
}

func brainProfile(f *sandbox.Fake) map[string]runner.Profile {
	return map[string]runner.Profile{"brain": {Launch: f, Files: 1, Prefix: "b-"}}
}

func roundTrip(t *testing.T, c net.Conn, msg string) string {
	t.Helper()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.WriteString(c, msg); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 256)
	n, err := c.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	return string(buf[:n])
}

func TestBrainLifecycle(t *testing.T) {
	f := sandbox.NewFake()
	f.Init = echoInit
	cl := serve(t, brainProfile(f), 4)
	ctx := t.Context()

	local, remote, err := runner.SocketPair()
	if err != nil {
		t.Fatal(err)
	}
	sb, err := cl.Create(ctx, "brain", remote)
	remote.Close()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(sb.ID, "b-") || f.Live() != 1 {
		t.Fatalf("id %q, live %d", sb.ID, f.Live())
	}
	if got := roundTrip(t, local, "hi\n"); got != "echo: hi\n" {
		t.Fatalf("got %q", got)
	}
	// Destroy: the workload is stopped, and the local end sees the other end close.
	sb.Close()
	waitLive(t, f, 0)
	local.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := local.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("after destroy: %v", err)
	}

	// The workload exits by itself: the client learns its code and the connection ends.
	local2, remote2, _ := runner.SocketPair()
	sb2, err := cl.Create(ctx, "brain", remote2)
	remote2.Close()
	if err != nil {
		t.Fatal(err)
	}
	io.WriteString(local2, "exit 3\n")
	select {
	case <-sb2.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("no exited")
	}
	if sb2.ExitCode() != 3 {
		t.Fatalf("exit %d", sb2.ExitCode())
	}
	waitLive(t, f, 0)
}

// agentd going away (its connection to runnerd closing) destroys its sandboxes.
func TestBrainDestroyedWithConnection(t *testing.T) {
	f := sandbox.NewFake()
	f.Init = echoInit
	cl := serve(t, brainProfile(f), 4)
	local, remote, _ := runner.SocketPair()
	defer local.Close() // dropped, the garbage collector may close it and the fake brain exit by itself (as in TestLimit)
	sb, err := cl.Create(t.Context(), "brain", remote)
	remote.Close()
	if err != nil {
		t.Fatal(err)
	}
	waitLive(t, f, 1)
	runner.CloseConn(sb) // as a crash would: no destroy sent
	waitLive(t, f, 0)
}

func TestLimit(t *testing.T) {
	f := sandbox.NewFake()
	f.Init = echoInit
	cl := serve(t, brainProfile(f), 1)
	// Keep the local end: dropped, the garbage collector may close it, the fake brain then exits and frees the slot
	// before the second create (a flake, seen 1 in about 100 runs).
	l1, r1, _ := runner.SocketPair()
	defer l1.Close()
	sb, err := cl.Create(t.Context(), "brain", r1)
	if err != nil {
		t.Fatal(err)
	}
	_, r2, _ := runner.SocketPair()
	if _, err := cl.Create(t.Context(), "brain", r2); err == nil || !strings.Contains(err.Error(), "limit") {
		t.Fatalf("second sandbox: %v", err)
	}
	sb.Close() // returns once runnerd freed the slot: no wait here
	_, r3, _ := runner.SocketPair()
	sb3, err := cl.Create(t.Context(), "brain", r3)
	if err != nil {
		t.Fatalf("after a destroy: %v", err)
	}
	sb3.Close()
}

// A sandbox's slot is free by the time its client learns the sandbox is gone, however it ended: destroyed, the
// brain exiting by itself, or the hands dying. A run that starts right after another ends is never refused.
func TestSlotFreeWhenGone(t *testing.T) {
	f := sandbox.NewFake()
	f.Init = echoInit
	hands := dyingRuntime{sandbox.NewFake()}
	cl := serve(t, map[string]runner.Profile{"brain": {Launch: f, Files: 1, Prefix: "b-"}, "hands": {Start: hands, Prefix: "h-"}}, 1)
	ctx := t.Context()
	brain := func() (net.Conn, *runner.Sandbox) {
		t.Helper()
		local, remote, err := runner.SocketPair()
		if err != nil {
			t.Fatal(err)
		}
		defer remote.Close()
		sb, err := cl.Create(ctx, "brain", remote)
		if err != nil {
			t.Fatal(err)
		}
		return local, sb
	}
	gone := func(sb *runner.Sandbox) {
		t.Helper()
		select {
		case <-sb.Done():
		case <-time.After(5 * time.Second):
			t.Fatal("not gone")
		}
	}
	for range 50 {
		local, sb := brain() // destroyed
		sb.Close()
		local.Close()

		local, sb = brain() // exits by itself
		io.WriteString(local, "exit 3\n")
		gone(sb)
		local.Close()

		h, err := cl.Create(ctx, "hands") // dies
		if err != nil {
			t.Fatal(err)
		}
		if _, err := h.Exec(ctx, []string{"die"}, nil, time.Second); err != nil {
			t.Fatal(err)
		}
		gone(h)
		h.Close()
	}
}

// dyingRuntime's sandboxes die (as an out-of-memory kill would) on the command "die".
type dyingRuntime struct{ *sandbox.Fake }

func (r dyingRuntime) Start(ctx context.Context, id string) (sandbox.Sandbox, error) {
	sb, err := r.Fake.Start(ctx, id)
	if err != nil {
		return nil, err
	}
	return &dyingSandbox{Sandbox: sb}, nil
}

type dyingSandbox struct {
	sandbox.Sandbox
	dead atomic.Bool
}

func (s *dyingSandbox) Exec(ctx context.Context, req sandbox.Request) (*sandbox.Result, error) {
	if len(req.Argv) > 0 && req.Argv[0] == "die" {
		s.dead.Store(true)
		return &sandbox.Result{Exit: 137, OOM: true}, nil
	}
	return s.Sandbox.Exec(ctx, req)
}

func (s *dyingSandbox) Alive() bool { return !s.dead.Load() && s.Sandbox.Alive() }

// Requests runnerd refuses: no arbitrary profile, flag, descriptor or op.
func TestRefusals(t *testing.T) {
	f := sandbox.NewFake()
	f.Init = echoInit
	hands := sandbox.NewFake()
	cl := serve(t, map[string]runner.Profile{"brain": {Launch: f, Files: 1, Prefix: "b-"}, "hands": {Start: hands, Prefix: "h-"}}, 4)
	ctx := t.Context()
	_, sock, _ := runner.SocketPair()
	pr, pw, _ := os.Pipe()
	defer pr.Close()
	defer pw.Close()
	tmp, _ := os.CreateTemp(t.TempDir(), "f")
	defer tmp.Close()
	cases := []struct {
		name    string
		profile string
		files   []*os.File
		want    string
	}{
		{"unknown profile", "root", []*os.File{sock}, "unknown_profile"},
		{"no descriptor", "brain", nil, "takes 1 descriptors, got 0"},
		{"two descriptors", "brain", []*os.File{sock, sock}, "got 2"},
		{"a pipe", "brain", []*os.File{pw}, "not a socket"},
		{"a file", "brain", []*os.File{tmp}, "not a socket"},
		{"hands with a descriptor", "hands", []*os.File{sock}, "takes 0 descriptors"},
	}
	for _, c := range cases {
		if _, err := cl.Create(ctx, c.profile, c.files...); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
	if runtime.GOOS == "linux" {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()
		tc, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		tf, _ := tc.(*net.TCPConn).File()
		if _, err := cl.Create(ctx, "brain", tf); err == nil || !strings.Contains(err.Error(), "not a unix stream socket") {
			t.Errorf("tcp socket: %v", err)
		}
		tf.Close()
		tc.Close()
	}
	// Raw frames: unknown members, a first frame that isn't a create, an oversize length.
	for name, raw := range map[string][]byte{
		"unknown member": frameOf(`{"op":"create","profile":"hands","flags":["--network=host"]}`),
		"exec first":     frameOf(`{"op":"exec","argv":["sh"]}`),
		"create + argv":  frameOf(`{"op":"create","profile":"hands","argv":["sh"]}`),
		"oversize":       binary.BigEndian.AppendUint32(nil, 64<<20),
	} {
		if r := rawReply(t, cl.Path, raw); !strings.Contains(r, "bad_request") && r != "" {
			t.Errorf("%s: %q", name, r)
		}
	}
	if f.Live() != 0 || hands.Live() != 0 {
		t.Fatalf("sandboxes left: %d %d", f.Live(), hands.Live())
	}
	// The brain profile has no exec: asking ends the connection and the sandbox.
	_, sock2, _ := runner.SocketPair()
	sb, err := cl.Create(ctx, "brain", sock2)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sb.Exec(ctx, []string{"sh"}, nil, 0); err == nil {
		t.Fatal("exec in the brain's sandbox")
	}
	waitLive(t, f, 0)
}

func TestHandsExec(t *testing.T) {
	hands := sandbox.NewFake()
	cl := serve(t, map[string]runner.Profile{"hands": {Start: hands, Prefix: "h-"}}, 4)
	sb, err := cl.Create(t.Context(), "hands")
	if err != nil {
		t.Fatal(err)
	}
	r, err := sb.Exec(t.Context(), []string{"echo", "hello"}, nil, time.Second)
	if err != nil || r.Exit != 0 || string(r.Stdout) != "hello\n" {
		t.Fatalf("%+v %v", r, err)
	}
	r, err = sb.Exec(t.Context(), []string{"cat"}, []byte("in"), 0)
	if err != nil || string(r.Stdout) != "in" {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := sb.Exec(t.Context(), nil, nil, 0); err == nil {
		t.Fatal("empty argv accepted")
	}
	waitLive(t, hands, 0)
}

func TestPeerUID(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("SO_PEERCRED: linux")
	}
	f := sandbox.NewFake()
	f.Init = echoInit
	dir, _ := os.MkdirTemp("", "rn")
	defer os.RemoveAll(dir)
	l, err := runner.Listen(dir+"/r.sock", 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go (&runner.Server{Profiles: brainProfile(f), PeerUID: os.Getuid() + 1, Max: 1}).Serve(l)
	_, sock, _ := runner.SocketPair()
	if _, err := (&runner.Client{Path: dir + "/r.sock"}).Create(t.Context(), "brain", sock); err == nil {
		t.Fatal("another uid got a sandbox")
	}
	if f.Live() != 0 {
		t.Fatal("sandbox started")
	}
}

// The brain behind runnerd passes the whole harness/v1 brain suite (kill and resume, replayed action, steering,
// cancel, malformed frames): in gVisor with TACY_RUNSC and TACY_BRAIN_BIN, else in the fake sandbox.
func TestBrainConformanceBehindRunner(t *testing.T) {
	env := runnertest.Start(t)
	t.Logf("sandbox: %s", env.Kind)
	conformance.RunBrain(t, func(ctx context.Context, conn net.Conn) error {
		f, err := conn.(*net.UnixConn).File()
		if err != nil {
			return err
		}
		sb, err := env.Client.Create(ctx, "brain", f)
		f.Close()
		if err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			sb.Close()
		case <-sb.Done():
		}
		return nil
	})
}

func frameOf(s string) []byte {
	return append(binary.BigEndian.AppendUint32(nil, uint32(len(s))), s...)
}

// rawReply sends raw bytes as the first frame and returns runnerd's reply ("" if it just closed).
func rawReply(t *testing.T, path string, raw []byte) string {
	t.Helper()
	c, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	c.Write(raw)
	b, _ := io.ReadAll(c)
	if len(b) < 4 {
		return ""
	}
	return string(b[4:])
}

func waitLive(t *testing.T, f *sandbox.Fake, n int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for f.Live() != n {
		if time.Now().After(deadline) {
			t.Fatalf("live %d, want %d", f.Live(), n)
		}
		time.Sleep(5 * time.Millisecond)
	}
}
