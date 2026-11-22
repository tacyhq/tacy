//go:build linux && amd64

#include "textflag.h"

// func int80(nr, a1, a2, a3 uint32) int32
// A 32-bit (i386) system call from this 64-bit process, through int 0x80: the path Docker's profile misses for
// socketcall. The confinement probe's only use (vsock32_amd64.go).
TEXT ·int80(SB), NOSPLIT, $0-20
	MOVL nr+0(FP), AX
	MOVL a1+4(FP), BX
	MOVL a2+8(FP), CX
	MOVL a3+12(FP), DX
	INT  $0x80
	MOVL AX, ret+16(FP)
	RET
