package cftunnel

// The launcher's shared types (launch_linux.go has the code; other systems have no launcher).

// ProbeArg is gatewayd's first argument when it runs as the confinement probe (as cloudflared's uid, started by the
// launcher before every cloudflared start): gatewayd ProbeArg <ProbeSpec JSON>.
const ProbeArg = "-tunnel-probe"

// ReapArg is gatewayd's only argument when it runs as the reaper (as cloudflared's uid, started by the launcher before
// every probe and after cloudflared exits; review 2 L1): it kills every process of that uid but itself (kill(-1)), so
// nothing cloudflared left behind (a child in another process group or session) outlives it.
const ReapArg = "-tunnel-reap"

// Vsock32Arg is gatewayd's first argument when it runs as the probe's 32-bit child (as cloudflared's uid, started by
// the probe on x86_64): gatewayd Vsock32Arg socket|socketcall tries AF_VSOCK through the i386 entry (int 0x80).
const Vsock32Arg = "-tunnel-probe-vsock32"

// LauncherFDEnv names the fd of gatewayd's end of the launcher's socket pair (set by the launcher only).
const LauncherFDEnv = "TACY_LAUNCHER_FD"

// ConfigFDPath is where cloudflared reads its config when the compose pins the Access app (LaunchConfig.Access): the
// launcher's memfd, passed as its fd 4 (fd 3 is the token, TokenPath).
const ConfigFDPath = "/proc/self/fd/4"

// LaunchConfig is what gatewayd's launcher needs, from gatewayd's own (attested) command line.
type LaunchConfig struct {
	GatewaydUID, GatewaydGID int    // gatewayd's (GatewaydUID)
	TunnelUID                int    // cloudflared's uid and gid (TunnelUID); gatewayd's one supplementary group
	Bin, BinSHA256, Config   string // cloudflared's pinned binary, its sha256 and config file ("": no tunnel)
	// Access (gatewayd -cloudflared-access team,aud; the release's form, in place of Config): the launcher writes
	// Config(team, aud) into a memfd of its own for each start and hands it to cloudflared as fd 4 (ConfigFDPath),
	// so the config comes only from the attested command line, never from a file gatewayd could change.
	Access string
	Deny   []string
	Allow  []string
}

// ProbeSpec is what the probe checks as cloudflared's uid: Deny paths (files, directories, sockets) it must fail to
// open, list or connect to; Allow sockets it must connect to (the ingress socket: the control that shows the probe
// works); PIDs it must fail to trace, signal or read the memory and environment of (gatewayd, the launcher); its
// own UID and GID.
type ProbeSpec struct {
	Deny  []string `json:"deny"`
	Allow []string `json:"allow"`
	PIDs  []int    `json:"pids"`
	UID   int      `json:"uid"`
	// AllowTCP are TCP listeners (host:port, as tcpListeners writes them) the uid may reach; the release has none.
	AllowTCP []string `json:"allow_tcp,omitempty"`
}

// ProbeCheck is one probe attempt: OK when the result is the wanted one ("denied", or "allowed" for an Allow socket).
type ProbeCheck struct {
	What string `json:"what"`
	Want string `json:"want"`
	Got  string `json:"got"`
	OK   bool   `json:"ok"`
}

// ProbeResult is the probe's report: OK only when every check is.
type ProbeResult struct {
	OK     bool              `json:"ok"`
	Status map[string]string `json:"status"` // the probe's own /proc/self/status lines: Uid, Gid, Groups, Cap*, NoNewPrivs, Seccomp
	// YamaPtraceScope is /proc/sys/kernel/yama/ptrace_scope ("absent" without Yama). Not a check: another uid can't
	// trace gatewayd at any scope, and gatewayd is non-dumpable.
	YamaPtraceScope string `json:"yama_ptrace_scope"`
	// LoopbackListeners are the TCP listeners in the shared network namespace (/proc/net/tcp, tcp6). Each one this
	// uid can connect to is a failed check (review 2, L3: a release's gatewayd has none, and cloudflared isn't running
	// while the probe is), unless spec.AllowTCP names it.
	LoopbackListeners []string `json:"tcp_listeners"`
	// GatewayReachable are the bridge gateway's ports (the host side) this uid connected to: information only (the
	// shared network namespace can't refuse them by uid; public_logs and public_sysinfo are off, so they show
	// metadata at most). "no default route" when there is none.
	GatewayReachable []string     `json:"gateway_reachable"`
	Checks           []ProbeCheck `json:"checks"`
}

// HardenStatus is what gatewayd reports about itself after Harden.
type HardenStatus struct {
	Dumpable        int    `json:"dumpable"` // 0 after Harden
	CapEff          string `json:"cap_eff"`
	CapPrm          string `json:"cap_prm"`
	YamaPtraceScope string `json:"yama_ptrace_scope"`
	Launched        bool   `json:"launched"` // started by the launcher
}
