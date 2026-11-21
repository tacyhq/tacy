package cftunnel

// The launcher's seccomp filter (2026-11-21, the vsock finding; launch_linux.go installs it). Docker's default
// profile refuses the 64-bit socket(AF_VSOCK) but not the 32-bit socketcall through int 0x80 (its socket rule can't
// look inside socketcall's argument array), and IA32 emulation is on in dstack's kernel: a uid with no capabilities
// could open AF_VSOCK and reach the guest agent's unauthenticated Shutdown on CID 1:8000. So before it starts
// anything, the launcher adds its own filter, which every process it starts inherits (gatewayd, the probe, the
// reaper, cloudflared; no_new_privs is set, so none can drop it):
//
//   - a syscall of any other architecture than the build's (i386 by int 0x80 on x86_64, AArch32 on arm64) kills the
//     process, as does an x32 one (the x32 bit, on x86_64);
//   - socket() is allowed only for AF_UNIX, AF_INET, AF_INET6 and AF_NETLINK; any other family is EAFNOSUPPORT;
//   - io_uring_setup, io_uring_enter and io_uring_register are EPERM (final review M2): since Linux 5.19 a ring's
//     IORING_OP_SOCKET opens a socket of any family without calling socket(), so the family check above would not
//     see it; nothing the launcher starts uses io_uring (Go's runtime and cloudflared don't);
//   - everything else is left to Docker's profile, which still applies (filters stack: the strictest answer wins).
//
// Raw classic BPF, no cgo and no library: the program is short enough to read whole (seccompProgram) and is checked
// by an interpreter in the tests (seccomp_test.go) as well as in Docker and on a CVM (scripts/cftunnel-confine-test.sh).

// bpfInsn is one classic BPF instruction (struct sock_filter).
type bpfInsn struct {
	Code   uint16
	Jt, Jf uint8
	K      uint32
}

const (
	bpfLdWAbs = 0x20 // BPF_LD | BPF_W | BPF_ABS
	bpfJeqK   = 0x15 // BPF_JMP | BPF_JEQ | BPF_K
	bpfJgeK   = 0x35 // BPF_JMP | BPF_JGE | BPF_K
	bpfRetK   = 0x06 // BPF_RET | BPF_K

	seccompRetKillProcess = 0x80000000
	seccompRetErrno       = 0x00050000
	eperm                 = 1
	seccompRetAllow       = 0x7fff0000

	// struct seccomp_data: nr, arch, instruction_pointer, args[6] (each 64 bits; the low word first on these
	// little-endian architectures).
	seccompDataNr    = 0
	seccompDataArch  = 4
	seccompDataArg0  = 16
	eafnosupport     = 97
	x32SyscallBit    = 0x40000000
	auditArchX8664   = 0xc000003e
	auditArchAarch64 = 0xc00000b7
)

// ioUringSyscalls are io_uring_setup, io_uring_enter and io_uring_register: the same numbers on x86_64 and arm64
// (the generic table).
var ioUringSyscalls = []uint32{425, 426, 427}

// socketFamilies are the only families socket() may open: what gatewayd and cloudflared use (unix sockets, the
// network, and netlink for Go's interface lookups).
var socketFamilies = []uint32{1, 2, 10, 16} // AF_UNIX, AF_INET, AF_INET6, AF_NETLINK

// seccompProgram is the filter for an architecture: its audit arch, its socket syscall number, and whether it has
// the x32 bit (x86_64).
func seccompProgram(arch, sysSocket uint32, x32 bool) []bpfInsn {
	// Each instruction's jumps name labels; resolved below.
	type ins struct {
		bpfInsn
		jt, jf string
	}
	p := []ins{
		{bpfInsn{Code: bpfLdWAbs, K: seccompDataArch}, "", ""},
		{bpfInsn{Code: bpfJeqK, K: arch}, "", "kill"},
		{bpfInsn{Code: bpfLdWAbs, K: seccompDataNr}, "", ""},
	}
	if x32 {
		p = append(p, ins{bpfInsn{Code: bpfJgeK, K: x32SyscallBit}, "kill", ""})
	}
	for _, nr := range ioUringSyscalls {
		p = append(p, ins{bpfInsn{Code: bpfJeqK, K: nr}, "eperm", ""})
	}
	p = append(p,
		ins{bpfInsn{Code: bpfJeqK, K: sysSocket}, "", "allow"},
		ins{bpfInsn{Code: bpfLdWAbs, K: seccompDataArg0}, "", ""}) // the family: an int, the argument's low word
	for _, f := range socketFamilies {
		p = append(p, ins{bpfInsn{Code: bpfJeqK, K: f}, "allow", ""})
	}
	labels := map[string]int{}
	p = append(p, ins{bpfInsn{Code: bpfRetK, K: seccompRetErrno | eafnosupport}, "", ""})
	labels["allow"] = len(p)
	p = append(p, ins{bpfInsn{Code: bpfRetK, K: seccompRetAllow}, "", ""})
	labels["kill"] = len(p)
	p = append(p, ins{bpfInsn{Code: bpfRetK, K: seccompRetKillProcess}, "", ""})
	labels["eperm"] = len(p)
	p = append(p, ins{bpfInsn{Code: bpfRetK, K: seccompRetErrno | eperm}, "", ""})
	out := make([]bpfInsn, len(p))
	for i, in := range p {
		out[i] = in.bpfInsn
		if in.jt != "" {
			out[i].Jt = uint8(labels[in.jt] - i - 1)
		}
		if in.jf != "" {
			out[i].Jf = uint8(labels[in.jf] - i - 1)
		}
	}
	return out
}
