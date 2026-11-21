//go:build linux && arm64

package cftunnel

const (
	seccompArch      = auditArchAarch64
	seccompSocketNr  = 198 // socket
	seccompX32       = false
	seccompSyscallNr = 277 // seccomp
)
