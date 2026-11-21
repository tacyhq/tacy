//go:build linux

package cftunnel

import (
	"fmt"
	"runtime"
	"syscall"
	"unsafe"
)

const (
	prSetNoNewPrivs        = 38 // PR_SET_NO_NEW_PRIVS
	seccompSetModeFilter   = 1  // SECCOMP_SET_MODE_FILTER
	seccompFilterFlagTSync = 1  // SECCOMP_FILTER_FLAG_TSYNC
	afVsock                = 40 // AF_VSOCK
)

// InstallSeccomp adds the launcher's filter (seccomp.go) to every thread of this process: what it starts from now on
// inherits it. no_new_privs first (Docker's no-new-privileges set it already; the kernel needs it for a filter
// without CAP_SYS_ADMIN).
func InstallSeccomp() error {
	if _, _, e := syscall.RawSyscall6(syscall.SYS_PRCTL, prSetNoNewPrivs, 1, 0, 0, 0, 0); e != 0 {
		return fmt.Errorf("prctl(PR_SET_NO_NEW_PRIVS): %w", e)
	}
	prog := seccompProgram(seccompArch, seccompSocketNr, seccompX32)
	fprog := struct {
		Len    uint16
		_      [6]byte
		Filter *bpfInsn
	}{Len: uint16(len(prog)), Filter: &prog[0]}
	r, _, e := syscall.RawSyscall(seccompSyscallNr, seccompSetModeFilter, seccompFilterFlagTSync, uintptr(unsafe.Pointer(&fprog)))
	runtime.KeepAlive(prog)
	if e != 0 {
		return fmt.Errorf("seccomp(SECCOMP_SET_MODE_FILTER, TSYNC): %w", e)
	}
	if r != 0 { // TSYNC: the id of a thread that couldn't take the filter
		return fmt.Errorf("seccomp: thread %d didn't take the filter", r)
	}
	return nil
}
