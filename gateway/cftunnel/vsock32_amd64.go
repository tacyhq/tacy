//go:build linux && amd64

package cftunnel

import (
	"encoding/binary"
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

func int80(nr, a1, a2, a3 uint32) int32

// has32 says this architecture has a 32-bit system call entry the probe tries (i386 through int 0x80).
const has32 = true

const (
	i386Socket     = 359 // socket (i386, since Linux 4.3)
	i386Socketcall = 102 // socketcall (i386)
	sysSocketOp    = 1   // SYS_SOCKET, socketcall's first argument
)

// RunVsock32 is the probe's 32-bit child (gatewayd Vsock32Arg <socket|socketcall>): it opens AF_VSOCK through the
// i386 entry and says what happened: "opened" (exit 0), "errno N" (exit 3), or it dies (a seccomp kill is SIGSYS;
// without IA32 emulation, int 0x80 faults).
func RunVsock32(how string) {
	var r int32
	switch how {
	case "socket":
		r = int80(i386Socket, afVsock, syscall.SOCK_STREAM, 0)
	case "socketcall":
		// The argument array must be in the low 4 GiB: the 32-bit entry truncates the pointer.
		page, err := syscall.Mmap(-1, 0, 4096, syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_PRIVATE|syscall.MAP_ANON|syscall.MAP_32BIT)
		if err != nil {
			fmt.Println("mmap:", err)
			os.Exit(4)
		}
		binary.LittleEndian.PutUint32(page[0:], afVsock)
		binary.LittleEndian.PutUint32(page[4:], syscall.SOCK_STREAM)
		binary.LittleEndian.PutUint32(page[8:], 0)
		r = int80(i386Socketcall, sysSocketOp, uint32(uintptr(unsafe.Pointer(&page[0]))), 0)
	default:
		os.Exit(1)
	}
	if r >= 0 {
		fmt.Println("opened")
		os.Exit(0)
	}
	fmt.Println("errno", -r)
	os.Exit(3)
}
