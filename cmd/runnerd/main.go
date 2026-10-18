// runnerd runs the agent VM's gVisor sandboxes for agentd (docs/22-sandbox-runner.md; protocol
// ../../runner, runner/v0). It's the only process that runs runsc, so agentd, which holds the tasks and the HPKE
// key, never gets runsc's privileges. In the CVM it runs in its own container: no network, no keys, no secrets in
// its environment, uid 10004 with no capabilities and no_new_privs, rootless runsc (its sandboxes in a user
// namespace of their own), Docker's seccomp profile off (it refuses the namespaces runsc makes) and memory and
// process limits on the container, which bound every sandbox in it. It mounts nothing of vaultd's or gatewayd's.
//
// Profiles are fixed here; agentd only picks one. "brain": our Go brain (pinned, copied into a root holding only
// it), its harness socket passed in as fd 3. "hands" (exec) only with -hands-rootfs, which the release doesn't set.
//
// In the CVM its image holds runnerd, the brain and gVisor (cmd/compose); the compose names the gVisor release, runsc's
// hash and the brain's (the verifier shows them), and runnerd refuses to start unless they are the ones it was built
// with (sandbox/gvisor.go) and the files it finds:
//
//	runnerd -socket /run/tacy/runner/runner.sock -agent-uid 10003 -gvisor /tacy/gvisor -gvisor-release 20261012.0 \
//	  -runsc-sha256 <sha256> -brain /tacy/brain -brain-sha256 <sha256> -dir /run/runner -platform systrap -rootless
package main

import (
	"flag"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"slices"
	"syscall"

	"github.com/tacyhq/tacy/internal/procinfo"
	"github.com/tacyhq/tacy/runner"
	"github.com/tacyhq/tacy/sandbox"
)

func main() {
	if os.Getpid() == 1 {
		reap()
	}
	socket := flag.String("socket", "", "runner/v0 unix socket (mode 0660: agentd connects through the group)")
	agentUID := flag.Int("agent-uid", -1, "the only uid allowed to connect (agentd's; required on Linux)")
	gvisor := flag.String("gvisor", "", "directory holding the pinned gVisor binaries (runsc, gvisor-bin/)")
	gvisorRelease := flag.String("gvisor-release", "", "the gVisor release the compose names: must be the pinned one")
	runscSum := flag.String("runsc-sha256", "", "runsc's hash the compose names: must be the pinned one")
	brainBin := flag.String("brain", "", "the brain binary")
	brainSum := flag.String("brain-sha256", "", "the brain binary's pin")
	dir := flag.String("dir", "/run/runner", "runnerd's own directory, a tmpfs: runsc's state, bundles, the brain's root")
	platform := flag.String("platform", "systrap", "gVisor platform (TDX guests have no KVM)")
	rootless := flag.Bool("rootless", true, "rootless runsc (runnerd isn't root); false needs root with CAP_SYS_ADMIN")
	cgroupParent := flag.String("cgroup-parent", "", "not rootless: delegate this cgroup v2 subtree for per-sandbox limits")
	maxSandboxes := flag.Int("max", 4, "sandboxes at once")
	handsRoot := flag.String("hands-rootfs", "", "the hands' root (busybox and Python); empty: no hands profile")
	flag.Parse()
	log.Printf("runnerd: %s", procinfo.Line())
	if *socket == "" || *gvisor == "" || *brainBin == "" || *brainSum == "" || *gvisorRelease == "" || *runscSum == "" {
		log.Fatal("runnerd: -socket, -gvisor, -gvisor-release, -runsc-sha256, -brain and -brain-sha256 are required")
	}
	if err := sandbox.CheckPins(*gvisorRelease, *runscSum); err != nil {
		log.Fatalf("runnerd: refusing to start: %v", err)
	}
	if *agentUID < 0 && runtime.GOOS == "linux" {
		log.Fatal("runnerd: -agent-uid is required on Linux")
	}
	if *rootless && os.Getuid() == 0 {
		log.Fatal("runnerd: -rootless as root; run as an unprivileged uid")
	}
	if err := sandbox.CheckGVisor(*gvisor); err != nil {
		log.Fatalf("runnerd: refusing to start: %v", err)
	}
	cfg := runner.Config{Runsc: filepath.Join(*gvisor, "runsc"), Dir: *dir, Platform: *platform, Rootless: *rootless}
	if *cgroupParent != "" && !*rootless {
		if err := sandbox.DelegateCgroups(*cgroupParent); err != nil {
			log.Fatalf("runnerd: %v", err)
		}
		cfg.CgroupParent = *cgroupParent
	}
	brain, err := runner.BrainRunsc(cfg, *brainBin, *brainSum)
	if err != nil {
		log.Fatalf("runnerd: refusing to start: brain: %v", err)
	}
	profiles := map[string]runner.Profile{"brain": {Launch: brain, Files: 1, Prefix: "b-"}}
	if *handsRoot != "" {
		hands, err := runner.HandsRunsc(cfg, *handsRoot)
		if err != nil {
			log.Fatalf("runnerd: hands: %v", err)
		}
		profiles["hands"] = runner.Profile{Start: hands, Prefix: "h-"}
	}
	l, err := runner.Listen(*socket, 0o660)
	if err != nil {
		log.Fatal(err)
	}
	var names []string
	for n := range profiles {
		names = append(names, n)
	}
	slices.Sort(names)
	log.Printf("runnerd %s on %s: gVisor %s (%s, rootless %v), profiles %v, at most %d sandboxes", runner.Version, *socket,
		sandbox.GVisorRelease, *platform, *rootless, names, *maxSandboxes)
	srv := &runner.Server{Profiles: profiles, PeerUID: *agentUID, Max: *maxSandboxes, Logf: log.Printf}
	log.Fatal(srv.Serve(l))
}

// reap: runnerd is PID 1 in its container, so runsc processes orphaned on the way are re-parented to it. This
// process only reaps them, runs the real runnerd as its child (same binary, same arguments) and exits with it.
func reap() {
	cmd := exec.Command("/proc/self/exe", os.Args[1:]...)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Start(); err != nil {
		log.Fatalf("runnerd: %v", err)
	}
	sigs := make(chan os.Signal, 4)
	signal.Notify(sigs, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		for s := range sigs {
			cmd.Process.Signal(s)
		}
	}()
	for {
		var ws syscall.WaitStatus
		pid, err := syscall.Wait4(-1, &ws, 0, nil)
		if err == syscall.EINTR {
			continue
		}
		if err != nil {
			log.Fatalf("runnerd: wait: %v", err)
		}
		if pid == cmd.Process.Pid {
			if ws.Signaled() {
				os.Exit(128 + int(ws.Signal()))
			}
			os.Exit(ws.ExitStatus())
		}
	}
}
