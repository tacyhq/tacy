//go:build linux

package cftunnel

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

// The launcher (review H1, 2026-11-21). gatewayd's container starts as root with only SETUID and SETGID (cap_drop
// ALL, no-new-privileges; the verifier's GatewaydLaunchException). Its first process, gatewayd's binary in launcher
// mode (Launch), never touches a key, a request or the network:
//
//   - it starts gatewayd as GatewaydUID:GatewaydGID, supplementary group TunnelUID only, with no capabilities (a
//     non-root uid after setuid has none, and execve gives none back: no file capabilities, no ambient set,
//     no-new-privileges), holding one end of a socket pair;
//   - on gatewayd's "start" (with the token in a memfd, SCM_RIGHTS), it checks cloudflared's sha256, runs the
//     confinement probe as TunnelUID (refusing to start cloudflared if any check fails), and starts the pinned
//     cloudflared with the pinned arguments (Args) as TunnelUID:TunnelUID with no supplementary groups, no
//     capabilities, the memfd as fd 3 and no environment but HOME; it reports the pid and the exit;
//   - it exits when gatewayd does (and kills cloudflared): Docker restarts the container.
//
// gatewayd can't make it run anything else: the binary, its arguments and the uid are its own flags.

const (
	sysPRSetDumpable = 4 // PR_SET_DUMPABLE
	sysPRGetDumpable = 3 // PR_GET_DUMPABLE
	mfdCloexec       = 1 // MFD_CLOEXEC
)

func prctl(op, arg uintptr) (uintptr, error) {
	r, _, e := syscall.RawSyscall(syscall.SYS_PRCTL, op, arg, 0)
	if e != 0 {
		return 0, e
	}
	return r, nil
}

// Harden makes this process non-dumpable (no core, no ptrace or /proc/<pid>/mem, environ, fd by its own uid either)
// and reports its capabilities and the kernel's Yama ptrace scope. gatewayd calls it first thing.
func Harden() (HardenStatus, error) {
	if _, err := prctl(sysPRSetDumpable, 0); err != nil {
		return HardenStatus{}, fmt.Errorf("prctl(PR_SET_DUMPABLE, 0): %w", err)
	}
	d, err := prctl(sysPRGetDumpable, 0)
	if err != nil {
		return HardenStatus{}, err
	}
	st := statusLines("/proc/self/status")
	return HardenStatus{Dumpable: int(d), CapEff: st["CapEff"], CapPrm: st["CapPrm"], YamaPtraceScope: yamaScope(),
		Launched: os.Getenv("TACY_LAUNCHER_FD") != ""}, nil
}

func yamaScope() string {
	b, err := os.ReadFile("/proc/sys/kernel/yama/ptrace_scope")
	if err != nil {
		return "absent"
	}
	return strings.TrimSpace(string(b))
}

func statusLines(path string) map[string]string {
	out := map[string]string{}
	b, _ := os.ReadFile(path)
	for _, ln := range strings.Split(string(b), "\n") {
		k, v, ok := strings.Cut(ln, ":")
		if !ok {
			continue
		}
		switch k {
		case "Uid", "Gid", "Groups", "CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb", "NoNewPrivs", "Seccomp", "Seccomp_filters":
			out[k] = strings.Join(strings.Fields(v), " ")
		}
	}
	return out
}

// capBits are the capability bits a hex Cap* line names.
func capBits(hex string) uint64 {
	n, err := strconv.ParseUint(hex, 16, 64)
	if err != nil {
		return ^uint64(0)
	}
	return n
}

const (
	capSetGID = 6
	capSetUID = 7
)

// Launch is gatewayd's launcher (never returns). args are gatewayd's own (os.Args), env its environment.
func Launch(cfg LaunchConfig, args, env []string) {
	log.SetPrefix("gatewayd launcher: ")
	if _, err := prctl(sysPRSetDumpable, 0); err != nil {
		log.Fatal(err)
	}
	if cfg.TunnelUID <= 0 || cfg.TunnelUID == cfg.GatewaydUID || cfg.GatewaydUID <= 0 || cfg.GatewaydGID <= 0 {
		log.Fatalf("uids: gatewayd %d:%d, cloudflared %d", cfg.GatewaydUID, cfg.GatewaydGID, cfg.TunnelUID)
	}
	// Only the release's uids (review 2, L2): cloudflared's is its own, never another service's.
	if cfg.TunnelUID != TunnelUID || cfg.GatewaydUID != GatewaydUID || cfg.GatewaydGID != GatewaydUID {
		log.Fatalf("uids: gatewayd %d:%d, cloudflared %d (want %d and %d)", cfg.GatewaydUID, cfg.GatewaydGID, cfg.TunnelUID, GatewaydUID, TunnelUID)
	}
	// Only SETUID and SETGID: anything more is a compose the verifier refuses.
	if eff := capBits(statusLines("/proc/self/status")["CapEff"]); eff&^(1<<capSetUID|1<<capSetGID) != 0 {
		log.Fatalf("capabilities %x: only SETUID and SETGID (cap_drop ALL, cap_add SETUID, SETGID)", eff)
	}
	// Its own seccomp filter (seccomp.go) before it starts anything: gatewayd, the probe, the reaper and cloudflared
	// all inherit it.
	if err := InstallSeccomp(); err != nil {
		log.Fatal(err)
	}
	if cfg.Bin != "" {
		if (cfg.Config == "") == (cfg.Access == "") {
			log.Fatal("cloudflared needs one of a config file and an Access app (-cloudflared-config, -cloudflared-access)")
		}
		if cfg.Access != "" {
			if _, err := accessConfig(cfg.Access); err != nil {
				log.Fatal(err)
			}
		}
	}
	self, err := os.Executable()
	if err != nil {
		log.Fatal(err)
	}
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_SEQPACKET|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		log.Fatal(err)
	}
	mine, theirs := os.NewFile(uintptr(fds[0]), "launcher"), os.NewFile(uintptr(fds[1]), "gatewayd")
	gw := exec.Command(self, args[1:]...)
	gw.Env = append(slices.DeleteFunc(slices.Clone(env), func(e string) bool { return strings.HasPrefix(e, LauncherFDEnv+"=") }),
		LauncherFDEnv+"=3")
	gw.ExtraFiles = []*os.File{theirs}
	gw.Stdin, gw.Stdout, gw.Stderr = nil, os.Stdout, os.Stderr
	gw.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL, Credential: &syscall.Credential{
		Uid: uint32(cfg.GatewaydUID), Gid: uint32(cfg.GatewaydGID), Groups: []uint32{uint32(cfg.TunnelUID)}}}
	l := &launcher{cfg: cfg, self: self, known: map[int]bool{}}
	if err := l.startKnown(gw); err != nil {
		log.Fatalf("start gatewayd: %v", err)
	}
	theirs.Close()
	go l.reapOrphans() // PID 1 of the container: what a child leaves behind is reparented here
	sig := make(chan os.Signal, 4)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)
	go func() {
		for s := range sig {
			gw.Process.Signal(s)
		}
	}()
	c, err := net.FileConn(mine)
	mine.Close()
	if err != nil {
		log.Fatal(err)
	}
	l.conn, l.gatewayd = c.(*net.UnixConn), gw.Process.Pid
	go l.serve()
	werr := gw.Wait()
	l.forget(gw.Process.Pid)
	l.kill()
	if err := l.reap(); err != nil { // cloudflared's whole tree, whatever group or session it put itself in
		log.Printf("reap: %v", err)
	}
	code := 1 // killed by a signal: Docker restarts the container either way
	if gw.ProcessState != nil && gw.ProcessState.ExitCode() >= 0 {
		code = gw.ProcessState.ExitCode()
	}
	log.Printf("gatewayd exited: %v", werr)
	os.Exit(code)
}

type launcher struct {
	cfg      LaunchConfig
	self     string
	conn     *net.UnixConn
	gatewayd int

	mu  sync.Mutex
	cur *os.Process
	wmu sync.Mutex

	// known are the children an exec.Cmd waits for (gatewayd, cloudflared, the probe, the reaper); reapOrphans waits
	// only for the others. kmu is held while one starts, so none is seen before it is known.
	kmu   sync.Mutex
	known map[int]bool
}

// testSkipReap turns the reaper off: set only by this package's tests (TestLauncherRefusesLeftover), never by a flag
// or the environment.
var testSkipReap bool

// startKnown starts cmd and records its pid as known before reapOrphans can look.
func (l *launcher) startKnown(cmd *exec.Cmd) error {
	l.kmu.Lock()
	defer l.kmu.Unlock()
	if err := cmd.Start(); err != nil {
		return err
	}
	l.known[cmd.Process.Pid] = true
	return nil
}

// forget drops a child its exec.Cmd has waited for.
func (l *launcher) forget(pid int) {
	l.kmu.Lock()
	delete(l.known, pid)
	l.kmu.Unlock()
}

// runKnown is cmd.Run with the pid known meanwhile.
func (l *launcher) runKnown(cmd *exec.Cmd) error {
	if err := l.startKnown(cmd); err != nil {
		return err
	}
	err := cmd.Wait()
	l.forget(cmd.Process.Pid)
	return err
}

// reapOrphans waits for the zombies reparented to this process (it is the container's PID 1) that no exec.Cmd
// waits for, on every SIGCHLD and every minute.
func (l *launcher) reapOrphans() {
	ch := make(chan os.Signal, 8)
	signal.Notify(ch, syscall.SIGCHLD)
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	me := os.Getpid()
	for {
		select {
		case <-ch:
		case <-t.C:
		}
		l.kmu.Lock()
		for _, p := range procsWhere(func(st procStat) bool { return st.state == 'Z' && st.ppid == me }) {
			if !l.known[p] {
				var ws syscall.WaitStatus
				syscall.Wait4(p, &ws, syscall.WNOHANG, nil)
			}
		}
		l.kmu.Unlock()
	}
}

// procStat is what /proc/<pid>/stat and status say about a process.
type procStat struct {
	state byte
	ppid  int
	uids  []string // real, effective, saved, filesystem
}

// procsWhere lists the pids /proc shows whose stat matches.
func procsWhere(match func(procStat) bool) []int {
	ents, _ := os.ReadDir("/proc")
	var out []int
	for _, e := range ents {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		b, err := os.ReadFile("/proc/" + e.Name() + "/stat")
		if err != nil {
			continue
		}
		// pid (comm) state ppid ...: comm may hold spaces and parentheses, so from the last ')'.
		i := bytes.LastIndexByte(b, ')')
		if i < 0 {
			continue
		}
		f := strings.Fields(string(b[i+1:]))
		if len(f) < 2 || len(f[0]) != 1 {
			continue
		}
		ppid, _ := strconv.Atoi(f[1])
		st := procStat{state: f[0][0], ppid: ppid, uids: strings.Fields(statusLines("/proc/" + e.Name() + "/status")["Uid"])}
		if match(st) {
			out = append(out, pid)
		}
	}
	return out
}

// liveOf lists the processes, zombies aside, any of whose uids is uid.
func liveOf(uid int) []int {
	u := strconv.Itoa(uid)
	return procsWhere(func(st procStat) bool { return st.state != 'Z' && slices.Contains(st.uids, u) })
}

// reap kills every process of cloudflared's uid (review 2, L1): the launcher, root without CAP_KILL, can't signal
// another uid, so it runs the reaper as that uid (gatewayd ReapArg: kill(-1, SIGKILL), which reaches every process of
// its uid whatever its process group or session), then checks /proc itself that none is left. An error names them:
// a start is then refused.
func (l *launcher) reap() error {
	for try := 0; try < 3; try++ {
		if len(liveOf(l.cfg.TunnelUID)) == 0 {
			return nil
		}
		if !testSkipReap {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			cmd := exec.CommandContext(ctx, l.self, ReapArg)
			cmd.Env, cmd.Dir = []string{}, "/"
			cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL, Credential: &syscall.Credential{
				Uid: uint32(l.cfg.TunnelUID), Gid: uint32(l.cfg.TunnelUID), Groups: []uint32{}}}
			l.runKnown(cmd)
			cancel()
		}
		time.Sleep(100 * time.Millisecond)
	}
	if left := liveOf(l.cfg.TunnelUID); len(left) > 0 {
		return fmt.Errorf("processes of cloudflared's uid %d are still running (pids %v)", l.cfg.TunnelUID, left)
	}
	return nil
}

// RunReap is the reaper (gatewayd ReapArg, as cloudflared's uid): non-dumpable first, then SIGKILL to every process
// it may signal, which is every process of its uid but itself (and init).
func RunReap() {
	prctl(sysPRSetDumpable, 0)
	syscall.Kill(-1, syscall.SIGKILL)
	os.Exit(0)
}

func (l *launcher) reply(v any) {
	b, _ := json.Marshal(v)
	l.wmu.Lock()
	defer l.wmu.Unlock()
	l.conn.Write(b)
}

func (l *launcher) kill() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.cur != nil {
		l.cur.Kill()
	}
}

// serve reads gatewayd's requests until it closes its end.
func (l *launcher) serve() {
	buf, oob := make([]byte, 64), make([]byte, syscall.CmsgSpace(4*4))
	for {
		n, oobn, _, _, err := l.conn.ReadMsgUnix(buf, oob)
		if err != nil || n == 0 {
			l.kill()
			return
		}
		var files []*os.File
		if msgs, err := syscall.ParseSocketControlMessage(oob[:oobn]); err == nil {
			for _, m := range msgs {
				if fds, err := syscall.ParseUnixRights(&m); err == nil {
					for _, fd := range fds {
						files = append(files, os.NewFile(uintptr(fd), "token"))
					}
				}
			}
		}
		if string(buf[:n]) != "start" || len(files) != 1 {
			for _, f := range files {
				f.Close()
			}
			l.reply(launchMsg{Kind: "refused", Detail: "not a start with one token fd"})
			continue
		}
		l.start(files[0])
	}
}

// launchMsg is one launcher message to gatewayd.
type launchMsg struct {
	Kind   string          `json:"kind"` // probe, started, refused, exit
	PID    int             `json:"pid,omitempty"`
	Detail string          `json:"detail,omitempty"`
	Probe  json.RawMessage `json:"probe,omitempty"`
}

func (l *launcher) start(token *os.File) {
	defer token.Close()
	l.mu.Lock()
	busy := l.cur != nil
	l.mu.Unlock()
	if busy {
		l.reply(launchMsg{Kind: "refused", Detail: "cloudflared is running"})
		return
	}
	if l.cfg.Bin == "" {
		l.reply(launchMsg{Kind: "refused", Detail: "no tunnel in this compose"})
		return
	}
	if err := checkSHA(l.cfg.Bin, l.cfg.BinSHA256); err != nil {
		l.reply(launchMsg{Kind: "refused", Detail: err.Error()})
		return
	}
	// Nothing of cloudflared's uid may be running before the probe and the start (review 2, L1): a child an earlier
	// cloudflared left could trace or fake the probe, and keep a foothold.
	if err := l.reap(); err != nil {
		l.reply(launchMsg{Kind: "refused", Detail: err.Error()})
		return
	}
	res, raw, err := l.probe()
	if raw != nil {
		l.reply(launchMsg{Kind: "probe", Probe: raw})
	}
	if err != nil || !res.OK {
		l.reply(launchMsg{Kind: "refused", Detail: fmt.Sprintf("confinement probe: %v %s", err, failed(res))})
		return
	}
	config, files := l.cfg.Config, []*os.File{token} // fd 3: TokenPath
	if l.cfg.Access != "" {
		cf, err := configMemfd(l.cfg.Access)
		if err != nil {
			l.reply(launchMsg{Kind: "refused", Detail: "config: " + err.Error()})
			return
		}
		defer cf.Close() // cloudflared has its own copy (fd 4) once started
		config, files = ConfigFDPath, append(files, cf)
	}
	cmd := exec.Command(l.cfg.Bin, Args(config)...)
	cmd.Env = []string{"HOME=" + Dir} // nothing of gatewayd's environment
	cmd.Dir = "/"
	cmd.ExtraFiles = files
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stdout
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL, Setpgid: true, Credential: &syscall.Credential{
		Uid: uint32(l.cfg.TunnelUID), Gid: uint32(l.cfg.TunnelUID), Groups: []uint32{}}}
	if err := l.startKnown(cmd); err != nil {
		l.reply(launchMsg{Kind: "refused", Detail: "start: " + err.Error()})
		return
	}
	l.mu.Lock()
	l.cur = cmd.Process
	l.mu.Unlock()
	l.reply(launchMsg{Kind: "started", PID: cmd.Process.Pid})
	go func() {
		err := cmd.Wait()
		l.forget(cmd.Process.Pid)
		if rerr := l.reap(); rerr != nil { // what it left behind goes with it (the next start checks again)
			log.Printf("reap: %v", rerr)
		}
		l.mu.Lock()
		l.cur = nil
		l.mu.Unlock()
		l.reply(launchMsg{Kind: "exit", PID: cmd.Process.Pid, Detail: errString(err)})
	}()
}

// failed lists the failed checks of a probe result.
func failed(r *ProbeResult) string {
	if r == nil {
		return ""
	}
	var out []string
	for _, c := range r.Checks {
		if !c.OK {
			out = append(out, c.What+": "+c.Got)
		}
	}
	return strings.Join(out, "; ")
}

// probe runs the confinement probe as cloudflared's uid (gatewayd's binary with ProbeArg).
func (l *launcher) probe() (*ProbeResult, []byte, error) {
	spec, _ := json.Marshal(ProbeSpec{Deny: l.cfg.Deny, Allow: l.cfg.Allow, PIDs: []int{l.gatewayd, os.Getpid()}, UID: l.cfg.TunnelUID})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, l.self, ProbeArg, string(spec))
	cmd.Env = []string{}
	cmd.Dir = "/"
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL, Credential: &syscall.Credential{
		Uid: uint32(l.cfg.TunnelUID), Gid: uint32(l.cfg.TunnelUID), Groups: []uint32{}}}
	err := l.runKnown(cmd)
	var r ProbeResult
	if jerr := json.Unmarshal(out.Bytes(), &r); jerr != nil {
		return nil, nil, fmt.Errorf("probe: %v (%v)", jerr, err)
	}
	return &r, out.Bytes(), err
}

// RunProbe is the confinement probe (gatewayd ProbeArg <spec>): it prints its ProbeResult as JSON and exits (0 when
// every check is OK, 2 otherwise).
func RunProbe(specJSON string) {
	prctl(sysPRSetDumpable, 0) // nothing of its uid may trace it or read its memory (review 2, L1)
	var spec ProbeSpec
	if err := json.Unmarshal([]byte(specJSON), &spec); err != nil {
		fmt.Fprintln(os.Stderr, "probe:", err)
		os.Exit(1)
	}
	r := Probe(spec)
	json.NewEncoder(os.Stdout).Encode(r)
	if !r.OK {
		os.Exit(2)
	}
	os.Exit(0)
}

// denied: err is a refusal by permission (or the path doesn't exist in this process's view).
func denied(err error) bool {
	return errors.Is(err, syscall.EACCES) || errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.ENOENT) ||
		errors.Is(err, syscall.ENOTDIR)
}

// Probe runs spec's checks as the calling process.
func Probe(spec ProbeSpec) ProbeResult {
	r := ProbeResult{Status: statusLines("/proc/self/status"), YamaPtraceScope: yamaScope()}
	add := func(what, want, got string, ok bool) {
		r.Checks = append(r.Checks, ProbeCheck{What: what, Want: want, Got: got, OK: ok})
	}
	// Its own credentials: cloudflared's uid and gid everywhere, no groups, no capabilities, no-new-privileges.
	u := strconv.Itoa(spec.UID)
	want := strings.Join([]string{u, u, u, u}, " ")
	add("uid", want, r.Status["Uid"], r.Status["Uid"] == want)
	add("gid", want, r.Status["Gid"], r.Status["Gid"] == want)
	add("groups", "", r.Status["Groups"], r.Status["Groups"] == "")
	for _, k := range []string{"CapInh", "CapPrm", "CapEff", "CapAmb"} {
		add(k, "0", r.Status[k], capBits(r.Status[k]) == 0)
	}
	add("NoNewPrivs", "1", r.Status["NoNewPrivs"], r.Status["NoNewPrivs"] == "1")
	// AF_VSOCK (the vsock finding, seccomp.go): the host's and the guest agent's vsock services, among them an
	// unauthenticated Shutdown. The 64-bit socket() here; on x86_64 the i386 entry too, each in a child of its own (the
	// launcher's filter kills a process that tries it).
	if fd, err := syscall.Socket(afVsock, syscall.SOCK_STREAM, 0); err == nil {
		syscall.Close(fd)
		add("socket AF_VSOCK (64-bit)", "refused", "opened", false)
	} else {
		add("socket AF_VSOCK (64-bit)", "refused", err.Error(), true)
	}
	if has32 {
		for _, how := range []string{"socket", "socketcall"} {
			got, ok := tryVsock32(how)
			add("socket AF_VSOCK (i386 "+how+", int 0x80)", "refused", got, ok)
		}
	}
	// io_uring (final review M2): a ring's IORING_OP_SOCKET opens AF_VSOCK without socket(), so the uid must not be
	// able to set one up at all.
	got, ok := tryIOUring()
	add(ioUringCheck, "refused", got, ok)
	for _, p := range spec.Deny {
		got, ok := tryOpen(p)
		add(p, "denied", got, ok)
	}
	for _, p := range spec.Allow {
		c, err := net.DialTimeout("unix", p, 2*time.Second)
		if err == nil {
			c.Close()
			add(p, "allowed", "connected", true)
		} else {
			add(p, "allowed", err.Error(), false)
		}
	}
	for _, pid := range spec.PIDs {
		ps := strconv.Itoa(pid)
		for _, f := range []string{"environ", "mem", "maps", "fd", "root/", "cwd/"} {
			got, ok := tryOpen("/proc/" + ps + "/" + f)
			add("/proc/"+ps+"/"+f, "denied", got, ok)
		}
		err := syscall.Kill(pid, 0)
		add("signal "+ps, "denied", errString(err), errors.Is(err, syscall.EPERM))
		got, ok := tryPtrace(pid)
		add("ptrace "+ps, "denied", got, ok)
	}
	// TCP in the shared network namespace (review 2, L3): cloudflared shares gatewayd's bridge network, and a uid can't
	// be kept from a listener there, so no listener may be reachable at all (a release has none: gatewayd has no
	// -listen, agentd no network) but the ones the spec allows; the bridge gateway's ports are reported.
	var resolver map[string]bool
	r.LoopbackListeners, resolver = tcpListeners()
	for _, l := range r.LoopbackListeners {
		addr := dialAddr(l)
		if addr == "" || slices.Contains(spec.AllowTCP, l) {
			continue
		}
		if resolver[l] { // Docker's embedded DNS resolver (dockerdns.go): cloudflared's lookups of the edge
			add("tcp "+addr, "Docker's embedded resolver only (127.0.0.11, root's)", "allowed", true)
			continue
		}
		c, err := net.DialTimeout("tcp", addr, time.Second)
		if err == nil {
			c.Close()
			add("tcp "+addr, "unreachable", "connected", false)
		} else {
			add("tcp "+addr, "unreachable", err.Error(), true)
		}
	}
	r.GatewayReachable = gatewayPorts()
	r.OK = true
	for _, c := range r.Checks {
		r.OK = r.OK && c.OK
	}
	return r
}

// tryVsock32 runs the probe's 32-bit child (RunVsock32) and says what happened and whether that was a refusal: an
// errno, or the child killed (SIGSYS: the filter; another signal: no 32-bit entry). Anything else fails closed.
func tryVsock32(how string) (string, bool) {
	self, err := os.Executable()
	if err != nil {
		return "executable: " + err.Error(), false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, self, Vsock32Arg, how)
	cmd.Env, cmd.Dir = []string{}, "/"
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	out, err := cmd.Output()
	got := strings.TrimSpace(string(out))
	ws, _ := cmd.ProcessState.Sys().(syscall.WaitStatus)
	switch {
	case cmd.ProcessState == nil:
		return "start: " + errString(err), false
	case ws.Signaled() && ws.Signal() == syscall.SIGSYS:
		return "killed by seccomp (SIGSYS)", true
	case ws.Signaled() && ctx.Err() == nil:
		return "killed by " + ws.Signal().String() + " (no 32-bit entry)", true
	case ws.Exited() && ws.ExitStatus() == 3 && strings.HasPrefix(got, "errno "):
		return got, true
	case got == "opened":
		return "opened", false
	}
	return fmt.Sprintf("%s (%v)", got, err), false
}

// ioUringCheck is the probe's io_uring check (its What).
const ioUringCheck = "io_uring_setup"

// sysIOUringSetup is io_uring_setup on x86_64 and arm64 (seccomp.go ioUringSyscalls).
const sysIOUringSetup = 425

// tryIOUring sets up a one-entry ring and says what happened and whether that was a refusal: any error (EPERM from
// the launcher's filter or Docker's profile, ENOSYS from a kernel without it) is; a ring is closed and fails.
func tryIOUring() (string, bool) {
	var params [120]byte // struct io_uring_params, zeroed: no flags
	fd, _, e := syscall.RawSyscall(sysIOUringSetup, 1, uintptr(unsafe.Pointer(&params[0])), 0)
	runtime.KeepAlive(&params)
	if e != 0 {
		return e.Error(), true
	}
	syscall.Close(int(fd))
	return "set up", false
}

func tryPtrace(pid int) (string, bool) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	err := syscall.PtraceAttach(pid)
	if err == nil {
		syscall.PtraceDetach(pid)
		return "attached", false
	}
	return err.Error(), errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES)
}

// tryOpen opens p (a directory: lists it; a socket: connects), and says what happened and whether that was a
// refusal.
func tryOpen(p string) (string, bool) {
	fi, err := os.Stat(strings.TrimSuffix(p, "/"))
	if err != nil {
		return "stat: " + err.Error(), denied(err)
	}
	switch {
	case fi.Mode()&os.ModeSocket != 0:
		c, err := net.DialTimeout("unix", p, 2*time.Second)
		if err == nil {
			c.Close()
			return "connected", false
		}
		return "connect: " + err.Error(), denied(err)
	case fi.IsDir() || strings.HasSuffix(p, "/"):
		_, err := os.ReadDir(p)
		if err == nil {
			return "listed", false
		}
		return "list: " + err.Error(), denied(err)
	default:
		f, err := os.Open(p)
		if err == nil {
			b := make([]byte, 1)
			_, rerr := f.Read(b)
			f.Close()
			if rerr != nil && denied(rerr) {
				return "read: " + rerr.Error(), true
			}
			return "opened", false
		}
		return "open: " + err.Error(), denied(err)
	}
}

// dialAddr is where to connect to a listener tcpListeners named ("tcp 0100007F:1F90"): its address (loopback for a
// wildcard one) and port; "" if it can't be read.
func dialAddr(l string) string {
	fam, hexAddr, ok := strings.Cut(l, " ")
	if !ok {
		return ""
	}
	ah, ph, ok := strings.Cut(hexAddr, ":")
	port, err := strconv.ParseUint(ph, 16, 16)
	if !ok || err != nil {
		return ""
	}
	raw, err := hexDecode(ah)
	if err != nil || (len(raw) != 4 && len(raw) != 16) {
		return ""
	}
	ip := make(net.IP, len(raw))
	for i := 0; i < len(raw); i += 4 { // /proc/net/tcp*: each 32-bit word in host (little-endian) order
		ip[i], ip[i+1], ip[i+2], ip[i+3] = raw[i+3], raw[i+2], raw[i+1], raw[i]
	}
	if ip.IsUnspecified() {
		if fam == "tcp6" {
			ip = net.IPv6loopback
		} else {
			ip = net.IPv4(127, 0, 0, 1)
		}
	}
	return net.JoinHostPort(ip.String(), strconv.Itoa(int(port)))
}

func hexDecode(s string) ([]byte, error) {
	if len(s)%2 != 0 {
		return nil, errors.New("odd")
	}
	out := make([]byte, len(s)/2)
	for i := range out {
		v, err := strconv.ParseUint(s[2*i:2*i+2], 16, 8)
		if err != nil {
			return nil, err
		}
		out[i] = byte(v)
	}
	return out, nil
}

// gatewayPorts are the bridge gateway's ports (the default route's next hop: the host side) this process connects
// to, from a short list (ssh, http, https, Docker's API, the usual agent ports): information for the probe's report.
func gatewayPorts() []string {
	b, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return []string{"no route table"}
	}
	gw := ""
	for _, ln := range strings.Split(string(b), "\n")[1:] {
		f := strings.Fields(ln)
		if len(f) > 2 && f[1] == "00000000" {
			if raw, err := hexDecode(f[2]); err == nil && len(raw) == 4 {
				gw = net.IPv4(raw[3], raw[2], raw[1], raw[0]).String()
			}
		}
	}
	if gw == "" {
		return []string{"no default route"}
	}
	var out []string
	for _, p := range []string{"22", "80", "443", "2375", "2376", "8000", "8080", "8090"} {
		if c, err := net.DialTimeout("tcp", net.JoinHostPort(gw, p), 300*time.Millisecond); err == nil {
			c.Close()
			out = append(out, net.JoinHostPort(gw, p))
		}
	}
	return out
}

// tcpListeners are the network namespace's listening TCP sockets (address:port in hex, as /proc/net/tcp has them),
// and which of them are Docker's embedded resolver (isDockerResolver).
func tcpListeners() ([]string, map[string]bool) {
	var out []string
	resolver := map[string]bool{}
	for _, f := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		fh, err := os.Open(f)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(fh)
		for sc.Scan() {
			fs := strings.Fields(sc.Text())
			if len(fs) > 3 && fs[3] == "0A" {
				name := filepath.Base(f) + " " + fs[1]
				out = append(out, name)
				if f == "/proc/net/tcp" && isDockerResolver(fs) {
					resolver[name] = true
				}
			}
		}
		fh.Close()
	}
	return out, resolver
}

// LauncherStarter is gatewayd's side of the launcher: it starts cloudflared through it (Supervisor.Start).
type LauncherStarter struct {
	conn    *net.UnixConn
	OnProbe func(raw []byte) // each probe result, as the launcher sent it

	mu      sync.Mutex
	replies chan launchMsg
	exits   map[int]chan string
}

// LauncherFromEnv is the LauncherStarter on the fd the launcher left in LauncherFDEnv (an error when gatewayd wasn't
// started by the launcher: the tunnel then doesn't run, never as gatewayd's uid).
func LauncherFromEnv(onProbe func([]byte)) (*LauncherStarter, error) {
	v := os.Getenv("TACY_LAUNCHER_FD") // LauncherFDEnv
	fd, err := strconv.Atoi(v)
	if v == "" || err != nil || fd < 3 {
		return nil, errors.New("cftunnel: gatewayd wasn't started by its launcher (the compose's gatewayd must be user 0:0 with SETUID and SETGID and -tunnel-uid): cloudflared never runs as gatewayd's uid")
	}
	f := os.NewFile(uintptr(fd), "launcher")
	c, err := net.FileConn(f)
	f.Close()
	if err != nil {
		return nil, err
	}
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return nil, errors.New("cftunnel: the launcher's fd isn't a unix socket")
	}
	s := &LauncherStarter{conn: uc, OnProbe: onProbe, replies: make(chan launchMsg, 4), exits: map[int]chan string{}}
	go s.read()
	return s, nil
}

func (s *LauncherStarter) read() {
	buf := make([]byte, 1<<20)
	for {
		n, err := s.conn.Read(buf)
		if err != nil || n == 0 {
			log.Fatalf("gatewayd: the launcher is gone: %v", err) // its child: Pdeathsig would end it anyway
		}
		var m launchMsg
		if json.Unmarshal(buf[:n], &m) != nil {
			continue
		}
		switch m.Kind {
		case "probe":
			if s.OnProbe != nil {
				s.OnProbe(m.Probe)
			}
		case "started":
			s.mu.Lock()
			s.exits[m.PID] = make(chan string, 1)
			s.mu.Unlock()
			s.replies <- m
		case "refused":
			s.replies <- m
		case "exit":
			s.mu.Lock()
			ch := s.exits[m.PID]
			delete(s.exits, m.PID)
			s.mu.Unlock()
			if ch != nil {
				ch <- m.Detail
			}
		}
	}
}

// Start puts token in a memfd (TD memory, no file) and asks the launcher to start cloudflared with it.
func (s *LauncherStarter) Start(ctx context.Context, token []byte) (Child, error) {
	mf, err := memfd("cloudflared-token")
	if err != nil {
		return nil, err
	}
	if _, err := mf.Write(token); err != nil {
		mf.Close()
		return nil, err
	}
	if _, _, err := s.conn.WriteMsgUnix([]byte("start"), syscall.UnixRights(int(mf.Fd())), nil); err != nil {
		mf.Close()
		return nil, err
	}
	select {
	case <-ctx.Done():
		mf.Close()
		return nil, ctx.Err()
	case m := <-s.replies:
		if m.Kind != "started" {
			mf.Truncate(0)
			mf.Close()
			return nil, fmt.Errorf("%w: %s", ErrRefused, m.Detail)
		}
		s.mu.Lock()
		ch := s.exits[m.PID]
		s.mu.Unlock()
		return &launched{pid: m.PID, mf: mf, exit: ch}, nil
	}
}

type launched struct {
	pid  int
	mf   *os.File
	exit chan string
	once sync.Once
}

func (c *launched) PID() int { return c.pid }

func (c *launched) Wait() error {
	if d := <-c.exit; d != "" {
		return errors.New(d)
	}
	return nil
}

// Wipe empties the memfd (its pages are freed) and closes gatewayd's copy.
func (c *launched) Wipe() {
	c.once.Do(func() {
		c.mf.Truncate(0)
		c.mf.Close()
	})
}

// accessConfig is Config for an Access pin (team,aud).
func accessConfig(access string) ([]byte, error) {
	team, aud, err := ParseAccess(access)
	if err != nil {
		return nil, err
	}
	return Config(team, aud)
}

// configMemfd is a fresh memfd (TD memory, no file) holding the config for access, at offset 0: one for each start,
// so nothing a previous cloudflared did to its copy carries over.
func configMemfd(access string) (*os.File, error) {
	c, err := accessConfig(access)
	if err != nil {
		return nil, err
	}
	mf, err := memfd("cloudflared-config")
	if err != nil {
		return nil, err
	}
	if _, err := mf.Write(c); err != nil {
		mf.Close()
		return nil, err
	}
	if _, err := mf.Seek(0, 0); err != nil {
		mf.Close()
		return nil, err
	}
	return mf, nil
}

// memfd is an anonymous in-memory file (memfd_create, close-on-exec).
func memfd(name string) (*os.File, error) {
	p, err := syscall.BytePtrFromString(name)
	if err != nil {
		return nil, err
	}
	fd, _, e := syscall.Syscall(sysMemfdCreate, uintptr(unsafe.Pointer(p)), mfdCloexec, 0)
	if e != 0 {
		return nil, fmt.Errorf("memfd_create: %w", e)
	}
	return os.NewFile(fd, name), nil
}
