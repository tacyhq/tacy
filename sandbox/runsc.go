package sandbox

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Runsc runs each sandbox with gVisor's runsc, called directly (no Docker runtime: dstack's dockerd only knows
// runc, nvidia and sysbox-runc, and its config isn't ours to change). Docker's default seccomp profile must be off
// for the calling process (it refuses the namespaces runsc makes; runsc applies its own, stricter seccomp to its
// sandbox and gofer processes). With Rootless the caller needs nothing else: any uid, no capabilities, no_new_privs
// (runsc maps that uid to root in a user namespace of its own). Without it, root with CAP_SYS_ADMIN (and cgroups
// can be delegated). Measured in docs/22.
//
// Every sandbox: no network interface but loopback (--network=none, its own empty network namespace), no host
// sockets (--host-uds=none), a read-only root (RootFS, --overlay2=none), a tmpfs /work and /tmp (unless NoWork), an
// unprivileged user with no capabilities and no_new_privs, a seccomp profile inside gVisor, and, with CgroupParent,
// its own memory, CPU and pids cgroup.
type Runsc struct {
	Path      string // runsc; its sidecars (gvisor_sentry, ...) in gvisor-bin/ next to it
	StateDir  string // runsc --root: the runner's own, 0700
	BundleDir string // bundles (config.json, process files), one folder per sandbox, 0700
	RootFS    string // the hands' read-only root (a pinned image's files)
	Platform  string // "systrap" (default; TDX guests have no nested KVM), "ptrace"
	// CgroupParent is a cgroup v2 path, relative to /sys/fs/cgroup, the runner may create children in (with the
	// memory, cpu and pids controllers delegated). Empty: no cgroups (--ignore-cgroups), limits by rlimits only.
	CgroupParent string
	UID, GID     int      // inside the sandbox; default 65534 (nobody)
	Init         []string // the sandbox's first process, which keeps it up; default /bin/sleep forever
	Env          []string // every command's environment; default PATH, HOME=/work, LANG
	Limits       Limits
	NoSeccomp    bool // drop the seccomp profile inside gVisor (tests)
	// Rootless runs runsc as the calling (non-root) uid: no capabilities needed, no cgroups (--ignore-cgroups:
	// limits come from the caller's own cgroup, its container's).
	Rootless   bool
	NoDirectFS bool   // --directfs=false: the Sentry opens no host files itself, the gofer does (stricter seccomp)
	NoWork     bool   // no /work and /tmp: a workload that writes nothing (the brain)
	Hostname   string // default "hands"
}

func (r *Runsc) global() []string {
	p := r.Platform
	if p == "" {
		p = "systrap"
	}
	a := []string{"--root=" + r.StateDir, "--platform=" + p, "--network=none", "--host-uds=none", "--overlay2=none"}
	if r.Rootless {
		a = append(a, "--rootless")
	}
	if r.CgroupParent == "" || r.Rootless {
		a = append(a, "--ignore-cgroups")
	}
	if r.NoDirectFS {
		a = append(a, "--directfs=false")
	}
	if !r.NoSeccomp {
		a = append(a, "--oci-seccomp")
	}
	return a
}

func (r *Runsc) cmd(ctx context.Context, args ...string) *exec.Cmd {
	c := exec.CommandContext(ctx, r.Path, append(r.global(), args...)...)
	c.Env = []string{"PATH=/usr/bin:/bin"} // runsc's own environment: nothing from ours
	return c
}

// Start creates the sandbox and starts its init process.
func (r *Runsc) Start(ctx context.Context, id string) (Sandbox, error) {
	if err := checkID(id); err != nil {
		return nil, err
	}
	dir := filepath.Join(r.BundleDir, id)
	if err := os.Mkdir(dir, 0o700); err != nil {
		return nil, fmt.Errorf("sandbox: bundle: %w", err)
	}
	spec, err := json.Marshal(r.Spec(id))
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(dir, "config.json"), spec, 0o600); err != nil {
		os.RemoveAll(dir)
		return nil, err
	}
	// A detached sandbox keeps the stdio it was started with, so a pipe would never close: runsc's own errors go
	// to a file in the bundle, and the init process's output nowhere.
	logf, err := os.OpenFile(filepath.Join(dir, "start.log"), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		os.RemoveAll(dir)
		return nil, err
	}
	c := r.cmd(ctx, "run", "--detach", "--bundle", dir, id)
	c.Stdin, c.Stdout, c.Stderr = nil, nil, logf
	err = c.Run()
	logf.Close()
	if err != nil {
		b, _ := os.ReadFile(filepath.Join(dir, "start.log"))
		r.destroy(id)
		return nil, fmt.Errorf("sandbox: start %s: %w: %s", id, err, lastLine(string(b)))
	}
	return &runscSandbox{r: r, id: id, dir: dir}, nil
}

// destroy kills and deletes a sandbox and its bundle, ignoring what's already gone.
func (r *Runsc) destroy(id string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	r.cmd(ctx, "kill", id, "KILL").Run()
	var stderr bytes.Buffer
	c := r.cmd(ctx, "delete", "--force", id)
	c.Stderr = &stderr
	err := c.Run()
	os.RemoveAll(filepath.Join(r.BundleDir, id))
	if err != nil && !strings.Contains(stderr.String(), "does not exist") {
		return fmt.Errorf("sandbox: delete %s: %w: %s", id, err, lastLine(stderr.String()))
	}
	return nil
}

func (r *Runsc) uidgid() (int, int) {
	u, g := r.UID, r.GID
	if u == 0 {
		u = 65534
	}
	if g == 0 {
		g = 65534
	}
	return u, g
}

func (r *Runsc) env() []string {
	if r.Env != nil {
		return r.Env
	}
	return []string{"PATH=/usr/local/bin:/usr/bin:/bin", "HOME=/work", "LANG=C.UTF-8", "TMPDIR=/tmp"}
}

// Process is the OCI process for argv in a sandbox: unprivileged, no capabilities, no_new_privs, rlimits.
func (r *Runsc) Process(argv []string) map[string]any {
	u, g := r.uidgid()
	l := r.Limits
	rl := []map[string]any{
		{"type": "RLIMIT_NOFILE", "hard": l.NoFile, "soft": l.NoFile},
		{"type": "RLIMIT_CORE", "hard": 0, "soft": 0},
	}
	if l.Pids > 0 {
		rl = append(rl, map[string]any{"type": "RLIMIT_NPROC", "hard": l.Pids, "soft": l.Pids})
	}
	none := []string{}
	return map[string]any{
		"terminal": false,
		"user":     map[string]any{"uid": u, "gid": g},
		"args":     argv,
		"env":      r.env(),
		"cwd":      "/work",
		"capabilities": map[string]any{"bounding": none, "effective": none, "inheritable": none, "permitted": none,
			"ambient": none},
		"noNewPrivileges": true,
		"rlimits":         rl,
	}
}

// Spec is the sandbox's OCI runtime spec.
func (r *Runsc) Spec(id string) map[string]any {
	init := r.Init
	if init == nil {
		init = []string{"/bin/sleep", "2147483647"}
	}
	l := r.Limits
	tmpfs := func(dst string, size int64) map[string]any {
		return map[string]any{"destination": dst, "type": "tmpfs", "source": "tmpfs",
			"options": []string{"nosuid", "nodev", "mode=1777", "size=" + strconv.FormatInt(size, 10)}}
	}
	linux := map[string]any{
		"namespaces": []map[string]any{{"type": "pid"}, {"type": "ipc"}, {"type": "uts"}, {"type": "mount"},
			{"type": "network"}},
		"maskedPaths":   []string{"/proc/kcore", "/proc/keys", "/proc/timer_list", "/sys/firmware"},
		"readonlyPaths": []string{"/proc/sys", "/proc/sysrq-trigger"},
	}
	if !r.NoSeccomp {
		linux["seccomp"] = Seccomp()
	}
	if r.CgroupParent != "" && !r.Rootless {
		linux["cgroupsPath"] = strings.TrimSuffix(r.CgroupParent, "/") + "/" + id
		res := map[string]any{}
		if l.MemoryBytes > 0 {
			res["memory"] = map[string]any{"limit": l.MemoryBytes, "swap": l.MemoryBytes} // swap = limit: none
		}
		if l.CPUs > 0 {
			res["cpu"] = map[string]any{"quota": int64(l.CPUs * 100000), "period": 100000}
		}
		if l.PidsCgroup > 0 {
			res["pids"] = map[string]any{"limit": l.PidsCgroup}
		}
		linux["resources"] = res
	}
	mounts := []map[string]any{{"destination": "/proc", "type": "proc", "source": "proc"}}
	if !r.NoWork {
		mounts = append(mounts, tmpfs("/tmp", 16<<20), tmpfs("/work", l.WorkBytes))
	}
	proc := r.Process(init)
	if r.NoWork {
		proc["cwd"] = "/"
	}
	return map[string]any{
		"ociVersion": "1.0.2",
		"process":    proc,
		"root":       map[string]any{"path": r.RootFS, "readonly": true},
		"hostname":   cmp.Or(r.Hostname, "hands"),
		"mounts":     mounts,
		"linux":      linux,
	}
}

// Seccomp is the profile gVisor applies to the hands' processes (--oci-seccomp): allow by default, refuse with
// EPERM what untrusted code never needs and what widens gVisor's own attack surface. gVisor implements these
// itself (none reaches the host kernel); the profile is a second layer around its kernel, not a replacement.
func Seccomp() map[string]any {
	deny := []string{
		"ptrace", "process_vm_readv", "process_vm_writev", "mount", "umount2", "pivot_root", "chroot", "unshare",
		"setns", "keyctl", "add_key", "request_key", "bpf", "perf_event_open", "userfaultfd", "io_uring_setup",
		"io_uring_enter", "io_uring_register", "kexec_load", "kexec_file_load", "init_module", "finit_module",
		"delete_module", "reboot", "swapon", "swapoff", "acct", "quotactl", "syslog", "personality",
		"open_by_handle_at", "name_to_handle_at", "fanotify_init", "mknod", "mknodat",
	}
	return map[string]any{
		"defaultAction": "SCMP_ACT_ALLOW",
		"architectures": []string{"SCMP_ARCH_X86_64", "SCMP_ARCH_AARCH64"},
		"syscalls":      []map[string]any{{"names": deny, "action": "SCMP_ACT_ERRNO", "errnoRet": 1}},
	}
}

type runscSandbox struct {
	r   *Runsc
	id  string
	dir string

	mu     sync.Mutex
	n      int
	closed bool
	dead   bool
}

func (s *runscSandbox) ID() string { return s.id }

func (s *runscSandbox) Alive() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return !s.closed && !s.dead
}

// running asks runsc whether the sandbox is still up.
func (s *runscSandbox) running() bool {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := s.r.cmd(ctx, "state", s.id).Output()
	if err != nil {
		return false
	}
	var st struct {
		Status string `json:"status"`
	}
	return json.Unmarshal(out, &st) == nil && st.Status == "running"
}

func (s *runscSandbox) Exec(ctx context.Context, req Request) (*Result, error) {
	lim := s.r.Limits
	timeout, err := lim.check(&req)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	if s.closed || s.dead {
		s.mu.Unlock()
		return nil, ErrClosed
	}
	s.n++
	n := s.n
	s.mu.Unlock()

	proc, err := json.Marshal(s.r.Process(req.Argv))
	if err != nil {
		return nil, err
	}
	pf := filepath.Join(s.dir, fmt.Sprintf("p%d.json", n))
	pidf := filepath.Join(s.dir, fmt.Sprintf("p%d.pid", n))
	if err := os.WriteFile(pf, proc, 0o600); err != nil {
		return nil, err
	}
	defer os.Remove(pf)
	defer os.Remove(pidf)

	stdout, stderr := newCapBuffer(lim.OutputBytes), newCapBuffer(lim.OutputBytes)
	// Not CommandContext: killing the runsc exec client wouldn't stop the command inside. On the time limit we
	// kill the command in the sandbox by its pid there, and the client then returns.
	c := s.r.cmd(context.Background(), "exec", "--process", pf, "--internal-pid-file", pidf, s.id)
	c.Stdin = bytes.NewReader(req.Stdin)
	c.Stdout, c.Stderr = stdout, stderr
	start := time.Now()
	if err := c.Start(); err != nil {
		return nil, fmt.Errorf("sandbox: exec: %w", err)
	}
	done := make(chan error, 1)
	go func() { done <- c.Wait() }()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	res := &Result{}
	var werr error
	select {
	case werr = <-done:
	case <-timer.C:
		res.TimedOut = true
		werr = s.stop(c, pidf, done)
	case <-ctx.Done():
		s.stop(c, pidf, done)
		return nil, ctx.Err()
	}
	res.Duration = time.Since(start)
	var ee *exec.ExitError
	switch {
	case werr == nil:
	case errors.As(werr, &ee):
		res.Exit = ee.ExitCode()
		if res.Exit < 0 { // the client itself was killed
			res.Exit = 137
		}
	default:
		return nil, fmt.Errorf("sandbox: exec: %w", werr)
	}
	var o1, o2 bool
	res.Stdout, o1 = stdout.bytes()
	res.Stderr, o2 = stderr.bytes()
	res.Truncated = o1 || o2
	if res.Exit != 0 && !s.running() {
		// The whole sandbox went down: its memory cgroup's OOM killer (or a crash). The working folder went with it.
		s.mu.Lock()
		s.dead = true
		s.mu.Unlock()
		res.OOM = s.oomKilled()
	}
	return res, nil
}

// stop kills the command (by its pid inside the sandbox), then the client if it lingers, then the sandbox.
func (s *runscSandbox) stop(c *exec.Cmd, pidf string, done chan error) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if b, err := os.ReadFile(pidf); err == nil {
		if pid, err := strconv.Atoi(strings.TrimSpace(string(b))); err == nil && pid > 1 {
			s.r.cmd(ctx, "kill", "--pid", strconv.Itoa(pid), s.id, "KILL").Run()
		}
	}
	select {
	case err := <-done:
		return err
	case <-time.After(3 * time.Second):
	}
	c.Process.Kill()
	s.mu.Lock()
	s.dead = true // the command may still run inside: retire the sandbox
	s.mu.Unlock()
	s.r.destroy(s.id)
	return <-done
}

// oomKilled reads the sandbox cgroup's memory.events (only with CgroupParent; runsc removes the cgroup on delete,
// so this runs before Close).
func (s *runscSandbox) oomKilled() bool {
	if s.r.CgroupParent == "" {
		return false
	}
	b, err := os.ReadFile(filepath.Join("/sys/fs/cgroup", s.r.CgroupParent, s.id, "memory.events"))
	if err != nil {
		return false
	}
	for _, l := range strings.Split(string(b), "\n") {
		if f := strings.Fields(l); len(f) == 2 && f[0] == "oom_kill" && f[1] != "0" {
			return true
		}
	}
	return false
}

func (s *runscSandbox) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	s.mu.Unlock()
	return s.r.destroy(s.id)
}

func lastLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.LastIndexByte(s, '\n'); i >= 0 {
		s = s[i+1:]
	}
	if len(s) > 300 {
		s = s[:300]
	}
	return s
}

// Launch runs a sandbox whose first process is the workload itself (Init, the brain), in the foreground: it ends
// when that process exits. files are passed in as fds 3, 4, ... (--pass-fd: already connected sockets, no socket
// path inside and no --host-uds); the caller may close its copies once Launch returns. The workload's stdout and
// stderr, and runsc's own errors, go to log.
func (r *Runsc) Launch(ctx context.Context, id string, files []*os.File, log io.Writer) (Instance, error) {
	if err := checkID(id); err != nil {
		return nil, err
	}
	if len(files) > 4 {
		return nil, fmt.Errorf("%w: at most 4 passed files", ErrBadRequest)
	}
	dir := filepath.Join(r.BundleDir, id)
	if err := os.Mkdir(dir, 0o700); err != nil {
		return nil, fmt.Errorf("sandbox: bundle: %w", err)
	}
	spec, err := json.Marshal(r.Spec(id))
	if err == nil {
		err = os.WriteFile(filepath.Join(dir, "config.json"), spec, 0o600)
	}
	if err != nil {
		os.RemoveAll(dir)
		return nil, err
	}
	args := []string{"run"}
	for i := range files {
		args = append(args, "--pass-fd", fmt.Sprintf("%d:%d", 3+i, 3+i))
	}
	c := r.cmd(context.Background(), append(args, "--bundle", dir, id)...)
	c.ExtraFiles = files
	c.Stdout, c.Stderr = log, log
	if err := c.Start(); err != nil {
		os.RemoveAll(dir)
		return nil, fmt.Errorf("sandbox: launch %s: %w", id, err)
	}
	in := &runscInstance{r: r, id: id, cmd: c, done: make(chan struct{}), exit: -1}
	go func() {
		err := c.Wait()
		if c.ProcessState != nil {
			in.exit = c.ProcessState.ExitCode()
		}
		if err != nil && in.exit == 0 {
			in.exit = -1
		}
		r.destroy(id)
		close(in.done)
	}()
	return in, nil
}

type runscInstance struct {
	r    *Runsc
	id   string
	cmd  *exec.Cmd
	done chan struct{}
	exit int
	once sync.Once
}

func (in *runscInstance) ID() string            { return in.id }
func (in *runscInstance) Done() <-chan struct{} { return in.done }

func (in *runscInstance) ExitCode() int {
	<-in.done
	return in.exit
}

// Close kills the workload and destroys the sandbox, then waits for runsc to return.
func (in *runscInstance) Close() error {
	in.once.Do(func() {
		select {
		case <-in.done:
			return
		default:
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		in.r.cmd(ctx, "kill", in.id, "KILL").Run()
		select {
		case <-in.done:
		case <-time.After(5 * time.Second):
			in.cmd.Process.Kill() // runsc itself lingers: its exit destroys the sandbox (above)
			<-in.done
		}
	})
	return nil
}
