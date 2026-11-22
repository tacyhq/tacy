//go:build linux && amd64

package cftunnel

const (
	seccompArch      = auditArchX8664
	seccompSocketNr  = 41 // socket
	seccompX32       = true
	seccompSyscallNr = 317 // seccomp
)
