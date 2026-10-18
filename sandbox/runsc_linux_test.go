package sandbox

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Real gVisor. Runs only when TACY_RUNSC names runsc (its gvisor-bin/ next to it) and TACY_HANDS_ROOTFS a root
// with busybox; as root with CAP_SYS_ADMIN (CI: sudo; a container: --cap-add SYS_ADMIN, seccomp and AppArmor
// unconfined). TACY_CGROUP_PARENT (e.g. "hands") also delegates cgroups and checks the memory limit.
func realRunsc(t *testing.T, l Limits) *Runsc {
	t.Helper()
	bin, root := os.Getenv("TACY_RUNSC"), os.Getenv("TACY_HANDS_ROOTFS")
	if bin == "" || root == "" {
		t.Skip("TACY_RUNSC and TACY_HANDS_ROOTFS not set")
	}
	if os.Geteuid() != 0 {
		t.Skip("runsc needs root")
	}
	state := t.TempDir()
	// runsc keeps one empty network namespace for its sandboxes, bind-mounted in its state directory.
	// Concurrent first starts may each mount it, so unmount until none is left.
	t.Cleanup(func() {
		for range 64 {
			if syscall.Unmount(filepath.Join(state, "null-netns"), syscall.MNT_DETACH) != nil {
				break
			}
		}
	})
	r := &Runsc{Path: bin, StateDir: state, BundleDir: t.TempDir(), RootFS: root, Limits: l,
		Platform: os.Getenv("TACY_RUNSC_PLATFORM")}
	if p := os.Getenv("TACY_CGROUP_PARENT"); p != "" {
		if err := DelegateCgroups(p); err != nil {
			t.Fatal(err)
		}
		r.CgroupParent = "/" + strings.Trim(p, "/")
	}
	return r
}

func startReal(t *testing.T, r *Runsc) Sandbox {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	start := time.Now()
	sb, err := r.Start(ctx, NewID())
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("start %s", time.Since(start).Round(time.Millisecond))
	t.Cleanup(func() { sb.Close() })
	return sb
}

func sh(t *testing.T, sb Sandbox, script string, stdin string) *Result {
	t.Helper()
	r, err := sb.Exec(t.Context(), Request{Argv: []string{"/bin/sh", "-c", script}, Stdin: []byte(stdin),
		Timeout: 20 * time.Second})
	if err != nil {
		t.Fatalf("%q: %v", script, err)
	}
	return r
}

func TestRunscIsolation(t *testing.T) {
	r := realRunsc(t, DefaultLimits)
	sb := startReal(t, r)

	if res := sh(t, sb, "id -u; echo hello", ""); string(res.Stdout) != "65534\nhello\n" || res.Exit != 0 {
		t.Fatalf("id: %+v %q", res, res.Stderr)
	}
	if res := sh(t, sb, "exit 7", ""); res.Exit != 7 {
		t.Fatalf("exit code %d", res.Exit)
	}
	// No network: only loopback, and nothing reachable.
	res := sh(t, sb, "cat /proc/net/dev | tail -n +3 | cut -d: -f1 | tr -d ' '", "")
	if strings.TrimSpace(string(res.Stdout)) != "lo" {
		t.Errorf("interfaces: %q", res.Stdout)
	}
	if res := sh(t, sb, "wget -q -T 3 -O - http://1.1.1.1/ && echo REACHED", ""); strings.Contains(string(res.Stdout), "REACHED") {
		t.Error("the network is reachable")
	}
	// Read-only root; writable /work that keeps files between commands of the same sandbox.
	if res := sh(t, sb, "echo x > /etc/x && echo WROTE", ""); strings.Contains(string(res.Stdout), "WROTE") {
		t.Error("wrote to the root")
	}
	sh(t, sb, "cat > /work/in.txt", "client data")
	if res := sh(t, sb, "cat /work/in.txt", ""); string(res.Stdout) != "client data" {
		t.Errorf("/work: %q %q", res.Stdout, res.Stderr)
	}
	// No capabilities, no_new_privs, seccomp inside gVisor (mknod is in the profile).
	res = sh(t, sb, "grep -E '^(CapEff|NoNewPrivs)' /proc/self/status; mknod /work/n p && echo MKNOD", "")
	if !strings.Contains(string(res.Stdout), "CapEff:\t0000000000000000") ||
		!strings.Contains(string(res.Stdout), "NoNewPrivs:\t1") || strings.Contains(string(res.Stdout), "MKNOD") {
		t.Errorf("privileges: %q %q", res.Stdout, res.Stderr)
	}
	// The host's sockets and files aren't there.
	if res := sh(t, sb, "ls /run/tacy /var/run/docker.sock /cache 2>&1; true", ""); strings.Contains(string(res.Stdout), "sock ") {
		t.Errorf("host paths visible: %q", res.Stdout)
	}

	// Another sandbox doesn't see this one's working folder.
	other := startReal(t, r)
	if res := sh(t, other, "cat /work/in.txt", ""); res.Exit == 0 {
		t.Error("another sandbox sees /work")
	}
}

func TestRunscLimits(t *testing.T) {
	l := DefaultLimits
	l.WorkBytes = 8 << 20
	l.OutputBytes = 1000
	l.Pids = 16
	l.MemoryBytes = 96 << 20
	r := realRunsc(t, l)
	sb := startReal(t, r)

	if res := sh(t, sb, "dd if=/dev/zero of=/work/big bs=1M count=32 2>&1; ls -l /work/big", ""); res.Exit == 0 && strings.Contains(string(res.Stdout), "33554432") {
		t.Errorf("/work size limit not applied: %q", res.Stdout)
	}
	if res := sh(t, sb, "head -c 100000 /dev/zero", ""); !res.Truncated || len(res.Stdout) != 1000 {
		t.Errorf("output cap: truncated %v, %d bytes", res.Truncated, len(res.Stdout))
	}
	res := sh(t, sb, "ulimit -u; i=0; while [ $i -lt 40 ]; do sleep 5 & i=$((i+1)); done 2>&1", "")
	if !strings.HasPrefix(string(res.Stdout), "16\n") || !strings.Contains(string(res.Stdout), "can't fork") {
		t.Errorf("pids rlimit: %q %q", res.Stdout, res.Stderr)
	}

	// Time limit: the command is killed inside, the sandbox stays usable.
	start := time.Now()
	tr, err := sb.Exec(t.Context(), Request{Argv: []string{"sleep", "60"}, Timeout: time.Second})
	if err != nil || !tr.TimedOut || time.Since(start) > 10*time.Second {
		t.Fatalf("timeout: %+v %v after %s", tr, err, time.Since(start))
	}
	t.Logf("timeout honored after %s", time.Since(start).Round(time.Millisecond))
	if !sb.Alive() {
		t.Fatal("sandbox retired after a timeout")
	}
	if res := sh(t, sb, "echo still here", ""); string(res.Stdout) != "still here\n" {
		t.Fatalf("after timeout: %+v", res)
	}

	if r.CgroupParent == "" {
		t.Log("no TACY_CGROUP_PARENT: memory and CPU limits not checked")
		return
	}
	// Memory: the sandbox's cgroup; past it the whole sandbox goes, and the caller learns it.
	mr, err := sb.Exec(t.Context(), Request{Argv: []string{"/bin/sh", "-c", "tail /dev/zero"}, Timeout: 30 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if mr.Exit == 0 || sb.Alive() {
		t.Fatalf("memory limit: %+v alive=%v", mr, sb.Alive())
	}
	t.Logf("memory limit: exit %d, oom %v, after %s", mr.Exit, mr.OOM, mr.Duration.Round(time.Millisecond))
}

// A sandbox started ahead (as the hands' pool keeps them) answers its first exec quickly.
func TestRunscWarm(t *testing.T) {
	r := realRunsc(t, DefaultLimits)
	sb := startReal(t, r)
	start := time.Now()
	res, err := sb.Exec(t.Context(), Request{Argv: []string{"true"}})
	if err != nil || res.Exit != 0 {
		t.Fatalf("%+v %v", res, err)
	}
	t.Logf("first exec in a warm sandbox %s", time.Since(start).Round(time.Millisecond))
}
