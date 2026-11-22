package cftunnel

import (
	"encoding/binary"
	"testing"
)

// runBPF interprets a seccomp program (the instructions seccompProgram uses) on one seccomp_data.
func runBPF(t *testing.T, prog []bpfInsn, nr, arch uint32, arg0 uint64) uint32 {
	t.Helper()
	data := make([]byte, 64)
	binary.LittleEndian.PutUint32(data[0:], nr)
	binary.LittleEndian.PutUint32(data[4:], arch)
	binary.LittleEndian.PutUint64(data[16:], arg0)
	var a uint32
	for pc := 0; pc < len(prog); pc++ {
		in := prog[pc]
		switch in.Code {
		case bpfLdWAbs:
			if int(in.K)+4 > len(data) {
				t.Fatalf("load past seccomp_data at %d", pc)
			}
			a = binary.LittleEndian.Uint32(data[in.K:])
		case bpfJeqK, bpfJgeK:
			hit := a == in.K
			if in.Code == bpfJgeK {
				hit = a >= in.K
			}
			if hit {
				pc += int(in.Jt)
			} else {
				pc += int(in.Jf)
			}
		case bpfRetK:
			return in.K
		default:
			t.Fatalf("unknown instruction %#x at %d", in.Code, pc)
		}
	}
	t.Fatal("ran off the end of the program")
	return 0
}

// The launcher's filter decides as seccomp.go says, on both architectures we build: another architecture's syscall
// (i386 by int 0x80, x32, AArch32) is a kill; socket() opens only AF_UNIX, AF_INET, AF_INET6 and AF_NETLINK
// (AF_VSOCK, AF_PACKET and the rest: EAFNOSUPPORT); io_uring_setup, io_uring_enter and io_uring_register are EPERM
// (final review M2: IORING_OP_SOCKET opens a socket without socket()); every other syscall is left to Docker's profile.
func TestSeccompProgram(t *testing.T) {
	const (
		archI386 = 0x40000003
		archARM  = 0x40000028
		kill     = seccompRetKillProcess
		allow    = seccompRetAllow
		refuse   = seccompRetErrno | eafnosupport
		noUring  = seccompRetErrno | 1 // EPERM
	)
	for _, a := range []struct {
		name         string
		arch, socket uint32
		x32          bool
		foreign      uint32
	}{{"amd64", auditArchX8664, 41, true, archI386}, {"arm64", auditArchAarch64, 198, false, archARM}} {
		prog := seccompProgram(a.arch, a.socket, a.x32)
		cases := []struct {
			what string
			nr   uint32
			arch uint32
			arg0 uint64
			want uint32
		}{
			{"socket AF_UNIX", a.socket, a.arch, 1, allow},
			{"socket AF_INET", a.socket, a.arch, 2, allow},
			{"socket AF_INET6", a.socket, a.arch, 10, allow},
			{"socket AF_NETLINK", a.socket, a.arch, 16, allow},
			{"socket AF_VSOCK", a.socket, a.arch, 40, refuse},
			{"socket AF_PACKET", a.socket, a.arch, 17, refuse},
			{"socket AF_VSOCK, high bits set", a.socket, a.arch, 1<<32 | 40, refuse},
			{"socket AF_ALG", a.socket, a.arch, 38, refuse},
			{"another syscall", 0, a.arch, 40, allow},
			{"io_uring_setup", 425, a.arch, 1, noUring},
			{"io_uring_enter", 426, a.arch, 3, noUring},
			{"io_uring_register", 427, a.arch, 3, noUring},
			{"the syscall before io_uring (pidfd_send_signal)", 424, a.arch, 0, allow},
			{"the syscall after io_uring (open_tree)", 428, a.arch, 0, allow},
			{"the foreign arch's io_uring_setup", 425, a.foreign, 1, kill},
			{"the foreign arch's socketcall", 102, a.foreign, 1, kill},
			{"the foreign arch's socket", 359, a.foreign, 40, kill},
			{"the foreign arch's getpid", 20, a.foreign, 0, kill},
		}
		if a.x32 {
			cases = append(cases,
				struct {
					what string
					nr   uint32
					arch uint32
					arg0 uint64
					want uint32
				}{"x32 socket", a.socket | x32SyscallBit, a.arch, 40, kill},
				struct {
					what string
					nr   uint32
					arch uint32
					arg0 uint64
					want uint32
				}{"x32 read", x32SyscallBit, a.arch, 0, kill})
		}
		for _, c := range cases {
			if got := runBPF(t, prog, c.nr, c.arch, c.arg0); got != c.want {
				t.Errorf("%s, %s: %#x, want %#x", a.name, c.what, got, c.want)
			}
		}
	}
}
