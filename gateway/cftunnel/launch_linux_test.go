//go:build linux

package cftunnel

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// The confinement test (review H1). It runs only as root in a container shaped like gatewayd's (cap_drop ALL,
// cap_add SETUID SETGID, no-new-privileges), on a directory tree shaped like the compose's sockets that a setup
// container made first: scripts/cftunnel-confine-test.sh. TACY_LAUNCH_ROOT names the tree:
//
//	vault 10002:10001 0750, agent 10003:10001 0770, ops 10001:10001 0750, unlockgw 10001:10001 0750,
//	tunnel 10001:10006 0750, tmp 10001:10001 0700, out 0777, cfd.sh (the stand-in cloudflared, 0555)
//
// The test binary plays every part: the services listening on their sockets (each as its uid), the launcher (this
// root process), gatewayd (the launcher's child) and the probe.

const roleEnv = "TACY_TEST_ROLE"

func TestMain(m *testing.M) {
	if len(os.Args) == 3 && os.Args[1] == ProbeArg {
		RunProbe(os.Args[2])
	}
	if len(os.Args) == 2 && os.Args[1] == ReapArg {
		RunReap()
	}
	if len(os.Args) == 3 && os.Args[1] == Vsock32Arg {
		RunVsock32(os.Args[2])
	}
	switch os.Getenv(roleEnv) {
	case "listen", "sleeper", "tcplisten", "udpbind", "abstractlisten": // helpers end when the test closes their stdin, or after a minute (root without CAP_KILL can't kill them)
		go func() {
			io.Copy(io.Discard, os.Stdin)
			os.Exit(0)
		}()
		time.AfterFunc(time.Minute, func() { os.Exit(0) })
	}
	switch os.Getenv(roleEnv) {
	case "listen": // a service: listen on a socket until killed
		listenRole()
	case "udpbind": // a UDP socket in the shared network namespace
		c, err := net.ListenPacket("udp", os.Getenv("TACY_TEST_ADDR"))
		if err != nil {
			fmt.Fprintln(os.Stderr, "listen:", err)
			os.Exit(1)
		}
		defer c.Close()
		select {}
	case "abstractlisten": // an abstract UNIX socket (no file: no permissions keep any uid from it)
		l, err := net.Listen("unix", "@"+os.Getenv("TACY_TEST_SOCK"))
		if err != nil {
			fmt.Fprintln(os.Stderr, "listen:", err)
			os.Exit(1)
		}
		defer l.Close()
		select {}
	case "tcplisten": // a TCP listener in the shared network namespace
		l, err := net.Listen("tcp", os.Getenv("TACY_TEST_ADDR"))
		if err != nil {
			fmt.Fprintln(os.Stderr, "listen:", err)
			os.Exit(1)
		}
		for {
			if c, err := l.Accept(); err == nil {
				c.Close()
			}
		}
	case "launcher":
		testSkipReap = os.Getenv("TACY_TEST_NOREAP") == "1"
		if os.Getuid() == 0 {
			var cfg LaunchConfig
			json.Unmarshal([]byte(os.Getenv("TACY_TEST_CFG")), &cfg)
			Launch(cfg, os.Args, os.Environ())
		}
		gatewaydRole()
	case "sleeper": // a process of gatewayd's uid, hardened or not, for the /proc checks
		if os.Getenv("TACY_TEST_HARDEN") == "1" {
			Harden()
		}
		select {}
	case "probe-as":
		if os.Getenv("TACY_TEST_SECCOMP") == "1" { // as the launcher does before it starts the probe (seccomp.go)
			if err := InstallSeccomp(); err != nil {
				fmt.Fprintln(os.Stderr, "seccomp:", err)
				os.Exit(1)
			}
		}
		var spec ProbeSpec
		json.Unmarshal([]byte(os.Getenv("TACY_TEST_SPEC")), &spec)
		json.NewEncoder(os.Stdout).Encode(Probe(spec))
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func listenRole() {
	p, mode := os.Getenv("TACY_TEST_SOCK"), os.Getenv("TACY_TEST_MODE")
	os.Remove(p)
	l, err := net.Listen("unix", p)
	if err != nil {
		fmt.Fprintln(os.Stderr, "listen:", err)
		os.Exit(1)
	}
	m, _ := strconv.ParseUint(mode, 8, 32)
	os.Chmod(p, os.FileMode(m))
	if g := os.Getenv("TACY_TEST_GID"); g != "" {
		gid, _ := strconv.Atoi(g)
		os.Chown(p, -1, gid)
	}
	for {
		c, err := l.Accept()
		if err == nil {
			c.Close()
		}
	}
}

// gatewaydRole is gatewayd as the launcher starts it: hardened, the ingress socket for cloudflared's group, one
// start with a token, the result in out/gatewayd.json.
func gatewaydRole() {
	root := os.Getenv("TACY_LAUNCH_ROOT")
	out := map[string]any{}
	defer func() {
		b, _ := json.Marshal(out)
		os.WriteFile(filepath.Join(root, "out", "gatewayd.json"), b, 0o644)
		os.Exit(0)
	}()
	hs, err := Harden()
	out["harden"], out["harden_err"] = hs, fmt.Sprint(err)
	out["uid"], out["gid"] = os.Getuid(), os.Getgid()
	out["seccomp_filters"] = statusLines("/proc/self/status")["Seccomp_filters"]
	groups, _ := os.Getgroups()
	out["groups"] = groups
	sock := filepath.Join(root, "tunnel", "ingress.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		out["error"] = err.Error()
		return
	}
	defer l.Close()
	os.Chmod(sock, 0o660)
	out["chown_ingress"] = fmt.Sprint(os.Chown(sock, -1, TunnelUID))
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	probes := make(chan []byte, 2)
	st, err := LauncherFromEnv(func(raw []byte) { probes <- raw })
	if err != nil {
		out["error"] = err.Error()
		return
	}
	ch, err := st.Start(context.Background(), []byte("tacy-test-token-"+os.Getenv("TACY_TEST_NONCE")))
	select {
	case p := <-probes:
		out["probe"] = json.RawMessage(p)
	case <-time.After(10 * time.Second):
	}
	if err != nil {
		out["start_error"] = err.Error()
		return
	}
	out["pid"] = ch.PID()
	out["exit"] = fmt.Sprint(ch.Wait())
	ch.Wipe()
	// TACY_TEST_STARTS=2: a restart after the exit, as the supervisor does (the config memfd must be a fresh one).
	if os.Getenv("TACY_TEST_STARTS") == "2" {
		ch2, err := st.Start(context.Background(), []byte("tacy-test-token-"+os.Getenv("TACY_TEST_NONCE")))
		if err != nil {
			out["start2_error"] = err.Error()
			return
		}
		out["pid2"] = ch2.PID()
		out["exit2"] = fmt.Sprint(ch2.Wait())
		ch2.Wipe()
	}
}

func sh(t *testing.T, cred *syscall.Credential, env []string, args ...string) *exec.Cmd {
	t.Helper()
	self, _ := os.Executable()
	cmd := exec.Command(self, args...)
	cmd.Env = env
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL, Credential: cred}
	return cmd
}

// helper starts a long-running helper; the cleanup closes its stdin, which ends it.
func helper(t *testing.T, cmd *exec.Cmd) {
	t.Helper()
	w, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { w.Close() }) // the container's end takes what's left
}

func cred(uid, gid int, groups ...uint32) *syscall.Credential {
	return &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid), Groups: groups}
}

func launchRoot(t *testing.T) string {
	root := os.Getenv("TACY_LAUNCH_ROOT")
	if root == "" || os.Getuid() != 0 {
		t.Skip("the confinement test runs in scripts/cftunnel-confine-test.sh (root in a container shaped like gatewayd's)")
	}
	return root
}

// startServices listens on the compose's sockets, each as its service's uid.
func startServices(t *testing.T, root string) map[string]string {
	socks := map[string]string{
		"vault":    filepath.Join(root, "vault", "vault.sock"),
		"agent":    filepath.Join(root, "agent", "http.sock"),
		"agentgw":  filepath.Join(root, "agent", "gateway.sock"),
		"ops":      filepath.Join(root, "ops", "gateway.sock"),
		"unlockgw": filepath.Join(root, "unlockgw", "gateway.sock"),
	}
	uids := map[string][2]int{"vault": {10002, 10001}, "agent": {10003, 10003}, "agentgw": {10001, 10001}, "ops": {10001, 10001},
		"unlockgw": {10001, 10001}}
	for name, p := range socks {
		u := uids[name]
		// Each socket as its service makes it: owner the service, group gatewayd's (agentd's -listen-gid 10001).
		helper(t, sh(t, cred(u[0], u[1], 10001), []string{roleEnv + "=listen", "TACY_TEST_SOCK=" + p, "TACY_TEST_MODE=0660", "TACY_TEST_GID=10001"}))
	}
	for _, p := range socks {
		for i := 0; i < 100; i++ {
			if _, err := os.Stat(p); err == nil {
				break
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
	return socks
}

func denyList(root string, socks map[string]string) []string {
	deny := []string{"/var/run/dstack.sock", "/run/dstack.sock", filepath.Join(root, "tmp") + "/"}
	for _, p := range socks {
		deny = append(deny, p, filepath.Dir(p)+"/")
	}
	return deny
}

// probeAs runs Probe as uid:gid (groups) against spec, under the launcher's seccomp filter as a release does.
func probeAs(t *testing.T, c *syscall.Credential, spec ProbeSpec) ProbeResult {
	t.Helper()
	return probeAsWith(t, c, spec, true)
}

// probeAsWith is probeAs with the launcher's seccomp filter or without it (Docker's profile only).
func probeAsWith(t *testing.T, c *syscall.Credential, spec ProbeSpec, filter bool) ProbeResult {
	t.Helper()
	b, _ := json.Marshal(spec)
	env := []string{roleEnv + "=probe-as", "TACY_TEST_SPEC=" + string(b)}
	if filter {
		env = append(env, "TACY_TEST_SECCOMP=1")
	}
	cmd := sh(t, c, env)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	var r ProbeResult
	if err := json.Unmarshal(out, &r); err != nil {
		t.Fatal(err)
	}
	return r
}

func check(r ProbeResult, what string) *ProbeCheck {
	for i := range r.Checks {
		if r.Checks[i].What == what {
			return &r.Checks[i]
		}
	}
	return nil
}

// The probe as cloudflared's uid (10006, no groups) is refused everything sensitive; the same probe as gatewayd's uid
// (the shape before the fix: cloudflared as gatewayd's child with its uid) reaches the vault and agentd and reads
// an undumpable-less process's memory and environment: so the test fails without the fix.
func TestConfinementByUID(t *testing.T) {
	root := launchRoot(t)
	socks := startServices(t, root)
	// The same uid as gatewayd, hardened and not: what PR_SET_DUMPABLE adds.
	soft := sh(t, cred(10001, 10001), []string{roleEnv + "=sleeper"})
	hard := sh(t, cred(10001, 10001), []string{roleEnv + "=sleeper", "TACY_TEST_HARDEN=1"})
	helper(t, soft)
	helper(t, hard)
	time.Sleep(200 * time.Millisecond)
	spec := ProbeSpec{Deny: denyList(root, socks), PIDs: []int{hard.Process.Pid, os.Getpid()}, UID: TunnelUID}

	confined := probeAs(t, cred(TunnelUID, TunnelUID), spec)
	if !confined.OK {
		t.Fatalf("cloudflared's uid isn't confined: %s", failed(&confined))
	}
	t.Logf("confined: %d checks, ptrace_scope %s, status %v", len(confined.Checks), confined.YamaPtraceScope, confined.Status)

	// Without the fix: cloudflared with gatewayd's uid and groups.
	spec.UID = GatewaydUID
	spec.PIDs = []int{soft.Process.Pid}
	same := probeAs(t, cred(GatewaydUID, GatewaydUID, TunnelUID), spec)
	if same.OK {
		t.Fatal("the probe passed as gatewayd's own uid: it can't tell confinement from none")
	}
	for _, want := range []string{socks["vault"], socks["agent"], socks["ops"], socks["unlockgw"],
		fmt.Sprintf("/proc/%d/environ", soft.Process.Pid), fmt.Sprintf("/proc/%d/mem", soft.Process.Pid)} {
		if c := check(same, want); c == nil || c.OK {
			t.Errorf("as gatewayd's uid, %s: %+v", want, c)
		}
	}
	// gatewayd's uid against a hardened process of its own uid: /proc refused (non-dumpable), signals still allowed.
	spec.PIDs = []int{hard.Process.Pid}
	h := probeAs(t, cred(GatewaydUID, GatewaydUID), spec)
	for _, f := range []string{"environ", "mem", "maps", "fd", "root/"} {
		if c := check(h, fmt.Sprintf("/proc/%d/%s", hard.Process.Pid, f)); c == nil || !c.OK {
			t.Errorf("non-dumpable, same uid, %s: %+v", f, c)
		}
	}
}

// vsockChecks are the probe's AF_VSOCK checks by short name: the 64-bit socket(), io_uring (its IORING_OP_SOCKET
// needs a ring; final review M2), and on x86_64 the i386 socket and socketcall through int 0x80.
func vsockChecks() map[string]string {
	m := map[string]string{"64": "socket AF_VSOCK (64-bit)", "uring": ioUringCheck}
	if has32 {
		m["socket"], m["socketcall"] = "socket AF_VSOCK (i386 socket, int 0x80)", "socket AF_VSOCK (i386 socketcall, int 0x80)"
	}
	return m
}

// The vsock finding: under the launcher's seccomp filter cloudflared's uid can't open AF_VSOCK by any path (the
// 64-bit socket(), an io_uring ring for IORING_OP_SOCKET, and on x86_64 the i386 socket and socketcall), with Docker's
// profile or without it
// (scripts/cftunnel-confine-test.sh runs this both ways). Without the filter the same probe fails on the paths the
// environment leaves open: TACY_TEST_VSOCK_OPEN names them (Docker's default profile on x86_64: socketcall; with no
// Docker profile: every path the kernel has), so the test shows the filter is what refuses them.
func TestSeccompBlocksVsock(t *testing.T) {
	launchRoot(t)
	spec := ProbeSpec{UID: TunnelUID}
	with := probeAsWith(t, cred(TunnelUID, TunnelUID), spec, true)
	for _, name := range vsockChecks() {
		if c := check(with, name); c == nil || !c.OK {
			t.Errorf("with the filter, %s: %+v", name, c)
		} else {
			t.Logf("with the filter, %s: %s", name, c.Got)
		}
	}
	t.Logf("with the filter: Seccomp %s, filters %s", with.Status["Seccomp"], with.Status["Seccomp_filters"])
	without := probeAsWith(t, cred(TunnelUID, TunnelUID), spec, false)
	for _, name := range vsockChecks() {
		c := check(without, name)
		t.Logf("without the filter, %s: %+v", name, c)
		if c == nil {
			t.Errorf("without the filter: no check %s", name)
		}
	}
	for _, short := range strings.Split(os.Getenv("TACY_TEST_VSOCK_OPEN"), ",") {
		if short == "" {
			continue
		}
		name, ok := vsockChecks()[short]
		if !ok {
			t.Fatalf("TACY_TEST_VSOCK_OPEN: no check %q on this architecture", short)
		}
		if c := check(without, name); c == nil || c.OK || (c.Got != "opened" && c.Got != "set up") {
			t.Errorf("without the filter, %s should open (the environment leaves it open): %+v", name, c)
		}
	}
}

// runLauncher runs the launcher (and gatewayd, one start) with the stand-in cloudflared and env added, and returns
// what gatewayd wrote.
func runLauncher(t *testing.T, root string, socks map[string]string, env ...string) (map[string]json.RawMessage, string) {
	t.Helper()
	g, nonce, err := runLauncherCfg(t, root, socks, nil, env...)
	if err != nil {
		t.Fatalf("launcher: %v", err)
	}
	return g, nonce
}

// runLauncherCfg is runLauncher with the launch config changed by mut first; err is the launcher's exit.
func runLauncherCfg(t *testing.T, root string, socks map[string]string, mut func(*LaunchConfig), env ...string) (map[string]json.RawMessage, string, error) {
	t.Helper()
	bin := filepath.Join(root, "cfd.sh")
	b, err := os.ReadFile(bin)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(b)
	nonce := strconv.FormatInt(time.Now().UnixNano(), 36)
	cfg := LaunchConfig{GatewaydUID: GatewaydUID, GatewaydGID: GatewaydUID, TunnelUID: TunnelUID, Bin: bin, BinSHA256: hex.EncodeToString(h[:]),
		Config: "/dev/null", Deny: denyList(root, socks), Allow: []string{filepath.Join(root, "tunnel", "ingress.sock")}}
	if mut != nil {
		mut(&cfg)
	}
	cj, _ := json.Marshal(cfg)
	self, _ := os.Executable()
	os.Remove(filepath.Join(root, "out", "gatewayd.json"))
	os.Remove(filepath.Join(root, "out", "cfd.txt"))
	cmd := exec.Command(self, "-test.run=^$")
	cmd.Env = append([]string{roleEnv + "=launcher", "TACY_TEST_CFG=" + string(cj), "TACY_LAUNCH_ROOT=" + root, "TACY_TEST_NONCE=" + nonce}, env...)
	cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
	if err := cmd.Run(); err != nil {
		return nil, nonce, err
	}
	gb, err := os.ReadFile(filepath.Join(root, "out", "gatewayd.json"))
	if err != nil {
		t.Fatal(err)
	}
	var g map[string]json.RawMessage
	json.Unmarshal(gb, &g)
	return g, nonce, nil
}

// The Access pin (gatewayd -cloudflared-access, vm-v1-gate2): the launcher, not gatewayd, writes cloudflared's config
// from its own (attested) command line into a memfd and hands it over as fd 4: cloudflared runs with --config
// ConfigFDPath and reads exactly Config(team, aud). A launcher with both a config file and an Access pin, or neither,
// refuses to start anything.
func TestLauncherAccessConfig(t *testing.T) {
	root := launchRoot(t)
	socks := startServices(t, root)
	aud := strings.Repeat("ab", 32)
	g, _, err := runLauncherCfg(t, root, socks, func(c *LaunchConfig) { c.Config, c.Access = "", "gate-team,"+aud })
	if err != nil || len(g["pid"]) == 0 || len(g["start_error"]) > 0 {
		t.Fatalf("with an Access pin: %v %v", err, g)
	}
	cb, err := os.ReadFile(filepath.Join(root, "out", "cfd.txt"))
	if err != nil {
		t.Fatal(err)
	}
	got := string(cb)
	want, _ := Config("gate-team", aud)
	if !strings.Contains(got, "args="+strings.Join(Args(ConfigFDPath), " ")+"\n") {
		t.Errorf("cloudflared's arguments: %s", got)
	}
	if !strings.Contains(got, "config="+strings.ReplaceAll(string(want), "\n", " ")+"\n") {
		t.Errorf("cloudflared's config (fd 4): %s, want %s", got, want)
	}
	for name, mut := range map[string]func(*LaunchConfig){
		"both":    func(c *LaunchConfig) { c.Access = "gate-team," + aud },
		"neither": func(c *LaunchConfig) { c.Config = "" },
		"bad pin": func(c *LaunchConfig) { c.Config, c.Access = "", "gate-team,"+aud[:10] },
	} {
		if _, _, err := runLauncherCfg(t, root, socks, mut); err == nil {
			t.Errorf("%s: the launcher started", name)
		}
	}
	if left, ok := noneLeft(); !ok {
		t.Errorf("processes of cloudflared's uid outlive the launcher: %v", left)
	}
}

// Review lows: cloudflared gets fds 0-2, the token (3) and the config (4), nothing
// else; its config memfd is sealed (a write through /proc/self/fd/4 is refused), and each start gets a fresh one (a
// restart reads its own copy, a new inode, exactly Config(team, aud)). The stand-in records each start in
// cfd-starts.txt (scripts/cftunnel-confine-test.sh).
func TestLauncherFdsSealedFreshConfig(t *testing.T) {
	root := launchRoot(t)
	socks := startServices(t, root)
	aud := strings.Repeat("cd", 32)
	os.Remove(filepath.Join(root, "out", "cfd-starts.txt"))
	g, _, err := runLauncherCfg(t, root, socks, func(c *LaunchConfig) { c.Config, c.Access = "", "gate-team,"+aud }, "TACY_TEST_STARTS=2")
	if err != nil || len(g["pid"]) == 0 || len(g["pid2"]) == 0 || len(g["start_error"]) > 0 || len(g["start2_error"]) > 0 {
		t.Fatalf("two starts with an Access pin: %v %v", err, g)
	}
	b, err := os.ReadFile(filepath.Join(root, "out", "cfd-starts.txt"))
	if err != nil {
		t.Fatal(err)
	}
	starts := strings.Split(strings.TrimSpace(string(b)), "\n---\n")
	if len(starts) != 2 {
		t.Fatalf("starts recorded: %d\n%s", len(starts), b)
	}
	want, _ := Config("gate-team", aud)
	bin := filepath.Join(root, "cfd.sh")
	var inodes []string
	for i, st := range starts {
		lines := map[string]string{}
		for _, l := range strings.Split(st, "\n") {
			if k, v, ok := strings.Cut(l, "="); ok {
				lines[k] = v
			}
		}
		fds := strings.Split(strings.TrimPrefix(lines["fds"], "|"), "|")
		t.Logf("start %d: fds %v, config inode %s, tamper %s", i+1, fds, lines["config_inode"], lines["tamper"])
		got := map[string]bool{}
		for _, f := range fds {
			n, target, _ := strings.Cut(f, ":")
			got[n] = true
			switch n {
			case "0", "1", "2":
			case "3":
				if !strings.HasPrefix(target, "/memfd:cloudflared-token") {
					t.Errorf("start %d: fd 3 is %s", i+1, target)
				}
			case "4":
				if !strings.HasPrefix(target, "/memfd:cloudflared-config") {
					t.Errorf("start %d: fd 4 is %s", i+1, target)
				}
			default:
				if target != bin { // the shell's own copy of the script it runs (the stand-in is a script)
					t.Errorf("start %d: an fd beyond 3 and 4 reached cloudflared: %s", i+1, f)
				}
			}
		}
		if !got["3"] || !got["4"] {
			t.Errorf("start %d: fds %v", i+1, fds)
		}
		if lines["tamper"] != "refused" {
			t.Errorf("start %d: a write to the config through /proc/self/fd/4: %q (want refused: sealed)", i+1, lines["tamper"])
		}
		if lines["config"] != strings.ReplaceAll(string(want), "\n", " ") {
			t.Errorf("start %d: config %q, want %q", i+1, lines["config"], want)
		}
		inodes = append(inodes, lines["config_inode"])
	}
	if inodes[0] == "" || inodes[0] == inodes[1] {
		t.Errorf("the restart's config memfd isn't a fresh one: inodes %v", inodes)
	}
	if left, ok := noneLeft(); !ok {
		t.Errorf("processes of cloudflared's uid outlive the launcher: %v", left)
	}
}

// configSealsOf reports f's seals (F_GET_SEALS).
func configSealsOf(f *os.File) (int, error) {
	r, _, e := syscall.Syscall(syscall.SYS_FCNTL, f.Fd(), 1034, 0)
	if e != 0 {
		return 0, e
	}
	return int(r), nil
}

// The config memfd on its own (any Linux, no root): sealed against write, grow, shrink and further seals, at offset 0,
// and holding exactly the config.
func TestConfigMemfdSealed(t *testing.T) {
	aud := strings.Repeat("ab", 32)
	mf, err := configMemfd("gate-team," + aud)
	if err != nil {
		t.Fatal(err)
	}
	defer mf.Close()
	if s, err := configSealsOf(mf); err != nil || s != configSeals {
		t.Fatalf("seals %#x %v, want %#x", s, err, configSeals)
	}
	if _, err := mf.WriteAt([]byte("x"), 0); err == nil {
		t.Error("a write to the sealed config went through")
	}
	if err := mf.Truncate(0); err == nil {
		t.Error("the sealed config was truncated")
	}
	got, err := io.ReadAll(mf)
	want, _ := Config("gate-team", aud)
	if err != nil || string(got) != string(want) {
		t.Fatalf("config %q %v", got, err)
	}
}

// noneLeft waits (2 s at most) until no process of cloudflared's uid is running; false if some still are.
func noneLeft() ([]int, bool) {
	for i := 0; i < 40; i++ {
		if len(liveOf(TunnelUID)) == 0 {
			return nil, true
		}
		time.Sleep(50 * time.Millisecond)
	}
	return liveOf(TunnelUID), false
}

// Review 2, L1: a process of cloudflared's uid left running (a child an earlier cloudflared detached into its own
// session) is killed before the probe and the start; with the reaper off (the test's knob) the start is refused.
func TestLauncherReapsLeftover(t *testing.T) {
	root := launchRoot(t)
	socks := startServices(t, root)
	for _, skip := range []bool{false, true} {
		left := sh(t, cred(TunnelUID, TunnelUID), []string{roleEnv + "=sleeper"})
		left.SysProcAttr.Setsid = true
		helper(t, left)
		done := make(chan struct{})
		go func() { left.Wait(); close(done) }()
		time.Sleep(100 * time.Millisecond)
		var env []string
		if skip {
			env = []string{"TACY_TEST_NOREAP=1"}
		}
		g, _ := runLauncher(t, root, socks, env...)
		if skip {
			if !strings.Contains(string(g["start_error"]), "still running") {
				t.Errorf("a leftover process with the reaper off: %s, want a refused start", g["start_error"])
			}
			// Clean up for the next test: this one ends with its stdin.
			continue
		}
		if len(g["pid"]) == 0 || len(g["start_error"]) > 0 {
			t.Fatalf("with a leftover process: %v", g)
		}
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Fatal("the leftover process of cloudflared's uid is still running after the start")
		}
	}
}

// Review 2, L3: a TCP listener in the shared network namespace that cloudflared's uid can reach fails the probe;
// without it the probe passes. The bridge gateway's ports are reported. On a user-defined network
// (scripts/cftunnel-confine-test.sh sets TACY_TEST_DOCKER_DNS=1, as gatewayd's compose network is) Docker's embedded
// resolver listens at 127.0.0.11 as root: the probe allows it, and only it (a listener of gatewayd's uid on
// 127.0.0.11 still fails).
func TestProbeRefusesReachableTCP(t *testing.T) {
	root := launchRoot(t)
	socks := startServices(t, root)
	spec := ProbeSpec{Deny: denyList(root, socks), UID: TunnelUID}
	clean := probeAs(t, cred(TunnelUID, TunnelUID), spec)
	if !clean.OK {
		t.Fatalf("no listener but Docker's resolver: %s", failed(&clean))
	}
	t.Logf("gateway: %v, listeners %v", clean.GatewayReachable, clean.LoopbackListeners)
	if os.Getenv("TACY_TEST_DOCKER_DNS") == "1" {
		seen := false
		for _, c := range clean.Checks {
			if strings.HasPrefix(c.What, "tcp 127.0.0.11:") && c.Got == "allowed" && c.OK {
				seen = true
			}
		}
		if !seen {
			t.Fatalf("no allowed Docker resolver check on a user-defined network (listeners %v)", clean.LoopbackListeners)
		}
	}
	for _, addr := range []string{"127.0.0.1:18081", "0.0.0.0:18082", "127.0.0.11:18083"} {
		l := sh(t, cred(GatewaydUID, GatewaydUID), []string{roleEnv + "=tcplisten", "TACY_TEST_ADDR=" + addr})
		helper(t, l)
		time.Sleep(200 * time.Millisecond)
		r := probeAs(t, cred(TunnelUID, TunnelUID), spec)
		_, port, _ := strings.Cut(addr, ":")
		var hit *ProbeCheck
		for i := range r.Checks {
			if strings.HasPrefix(r.Checks[i].What, "tcp ") && strings.HasSuffix(r.Checks[i].What, ":"+port) {
				hit = &r.Checks[i]
			}
		}
		if r.OK || hit == nil || hit.OK {
			t.Errorf("a listener on %s: probe OK %v, check %+v (listeners %v)", addr, r.OK, hit, r.LoopbackListeners)
		}
	}
}

// A UDP socket or an abstract UNIX socket in the shared network namespace fails the
// probe, whoever owns it, as a reachable TCP listener does; without one the probe passes, and on a user-defined
// network (TACY_TEST_DOCKER_DNS=1) Docker's resolver's UDP socket (127.0.0.11, root's) is allowed, and only it.
func TestProbeRefusesUDPAndAbstract(t *testing.T) {
	root := launchRoot(t)
	socks := startServices(t, root)
	spec := ProbeSpec{Deny: denyList(root, socks), UID: TunnelUID}
	clean := probeAs(t, cred(TunnelUID, TunnelUID), spec)
	if !clean.OK || len(clean.AbstractUnix) != 0 {
		t.Fatalf("no UDP socket but Docker's resolver, no abstract socket: %s (udp %v, abstract %v)", failed(&clean), clean.UDPSockets, clean.AbstractUnix)
	}
	t.Logf("udp %v", clean.UDPSockets)
	if os.Getenv("TACY_TEST_DOCKER_DNS") == "1" {
		seen := 0
		for _, c := range clean.Checks {
			if strings.HasPrefix(c.What, "udp 0B00007F:") && c.Got == "allowed" && c.OK {
				seen++
			}
		}
		if seen != 1 {
			t.Fatalf("want one allowed Docker resolver UDP check on a user-defined network, got %d (udp %v)", seen, clean.UDPSockets)
		}
	}
	for _, c := range []struct {
		name string
		env  []string
		what string
	}{
		{"udp 127.0.0.1 of gatewayd's uid", []string{roleEnv + "=udpbind", "TACY_TEST_ADDR=127.0.0.1:18091"}, "udp 0100007F:46AB "},
		{"udp 0.0.0.0 (Go binds it dual-stack: on udp6)", []string{roleEnv + "=udpbind", "TACY_TEST_ADDR=0.0.0.0:18092"}, "udp6 00000000000000000000000000000000:46AC "},
		{"udp 127.0.0.11 of gatewayd's uid", []string{roleEnv + "=udpbind", "TACY_TEST_ADDR=127.0.0.11:18093"}, "udp 0B00007F:46AD "},
		{"abstract", []string{roleEnv + "=abstractlisten", "TACY_TEST_SOCK=tacy-probe-test"}, "abstract unix @tacy-probe-test"},
	} {
		// Each helper stays until the test ends (root without CAP_KILL can't kill it): each look names its own socket.
		h := sh(t, cred(GatewaydUID, GatewaydUID), c.env)
		helper(t, h)
		time.Sleep(200 * time.Millisecond)
		r := probeAs(t, cred(TunnelUID, TunnelUID), spec)
		var hit *ProbeCheck
		for i := range r.Checks {
			if strings.HasPrefix(r.Checks[i].What, c.what) {
				hit = &r.Checks[i]
			}
		}
		if r.OK || hit == nil || hit.OK {
			t.Errorf("%s: probe OK %v, check %+v (udp %v, abstract %v)", c.name, r.OK, hit, r.UDPSockets, r.AbstractUnix)
		}
	}
}

// The launcher end to end: gatewayd runs as 10001:10001 (group 10006) with no capabilities and non-dumpable; the
// probe runs and passes; cloudflared (a stand-in script) runs as 10006:10006 with no groups, no capabilities,
// no-new-privileges, only HOME in its environment, and reads the token from the memfd at TokenPath.
func TestLauncher(t *testing.T) {
	root := launchRoot(t)
	socks := startServices(t, root)
	bin := filepath.Join(root, "cfd.sh")
	b, err := os.ReadFile(bin)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(b)
	nonce := strconv.FormatInt(time.Now().UnixNano(), 36)
	cfg := LaunchConfig{GatewaydUID: GatewaydUID, GatewaydGID: GatewaydUID, TunnelUID: TunnelUID, Bin: bin, BinSHA256: hex.EncodeToString(h[:]),
		Config: "/dev/null", Deny: denyList(root, socks), Allow: []string{filepath.Join(root, "tunnel", "ingress.sock")}}
	cj, _ := json.Marshal(cfg)
	self, _ := os.Executable()
	cmd := exec.Command(self, "-test.run=^$")
	cmd.Env = []string{roleEnv + "=launcher", "TACY_TEST_CFG=" + string(cj), "TACY_LAUNCH_ROOT=" + root, "TACY_TEST_NONCE=" + nonce, "SECRET_OF_GATEWAYD=1"}
	cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("launcher: %v", err)
	}
	gb, err := os.ReadFile(filepath.Join(root, "out", "gatewayd.json"))
	if err != nil {
		t.Fatal(err)
	}
	var g struct {
		Harden HardenStatus    `json:"harden"`
		UID    int             `json:"uid"`
		GID    int             `json:"gid"`
		Groups []int           `json:"groups"`
		Probe  json.RawMessage `json:"probe"`
		PID    int             `json:"pid"`
		Error  string          `json:"error"`
		Start  string          `json:"start_error"`
		Filter string          `json:"seccomp_filters"`
	}
	json.Unmarshal(gb, &g)
	if g.Error != "" || g.Start != "" {
		t.Fatalf("gatewayd: %s", gb)
	}
	if g.UID != GatewaydUID || g.GID != GatewaydUID || len(g.Groups) != 1 || g.Groups[0] != TunnelUID {
		t.Fatalf("gatewayd's credentials: %s", gb)
	}
	if g.Harden.Dumpable != 0 || g.Harden.CapEff != "0000000000000000" || g.Harden.CapPrm != "0000000000000000" || !g.Harden.Launched {
		t.Fatalf("gatewayd not hardened: %+v", g.Harden)
	}
	var p ProbeResult
	if json.Unmarshal(g.Probe, &p) != nil || !p.OK {
		t.Fatalf("the launcher's probe: %s", g.Probe)
	}
	// The launcher's seccomp filter (seccomp.go) on top of Docker's, in gatewayd, the probe and cloudflared; the
	// probe's AF_VSOCK checks ran and passed.
	base, _ := strconv.Atoi(statusLines("/proc/self/status")["Seccomp_filters"])
	want := strconv.Itoa(base + 1)
	if g.Filter != want || p.Status["Seccomp_filters"] != want {
		t.Errorf("seccomp filters: gatewayd %q, the probe %q, want %s (Docker's %d and the launcher's)", g.Filter, p.Status["Seccomp_filters"], want, base)
	}
	for _, name := range vsockChecks() {
		if c := check(p, name); c == nil || !c.OK {
			t.Errorf("the launcher's probe, %s: %+v", name, c)
		}
	}
	cb, err := os.ReadFile(filepath.Join(root, "out", "cfd.txt"))
	if err != nil {
		t.Fatal(err)
	}
	got := string(cb)
	t.Logf("cloudflared stand-in saw:\n%s", got)
	for _, want := range []string{"uid=10006\n", "gid=10006\n", "groups=10006\n", "token=tacy-test-token-" + nonce + "\n",
		"CapInh:\t0000000000000000", "CapPrm:\t0000000000000000", "CapEff:\t0000000000000000", "CapAmb:\t0000000000000000",
		"NoNewPrivs:\t1", "Seccomp_filters:\t" + want + "\n", "env=HOME=" + Dir} {
		if !strings.Contains(got, want) {
			t.Errorf("cloudflared: no %q", want)
		}
	}
	if strings.Contains(got, "SECRET_OF_GATEWAYD") || strings.Contains(got, LauncherFDEnv) {
		t.Error("cloudflared got gatewayd's environment")
	}
	if strings.Contains(got, "vault=ok") {
		t.Error("cloudflared read the vault socket's directory")
	}
	// Review 2, L1: the stand-in left a child in its own session (setsid); once the launcher is gone, nothing of
	// cloudflared's uid runs.
	if !strings.Contains(got, "detached=") {
		t.Fatal("the stand-in didn't start its detached child")
	}
	if left, ok := noneLeft(); !ok {
		t.Errorf("processes of cloudflared's uid outlive the launcher: %v", left)
	}
}
