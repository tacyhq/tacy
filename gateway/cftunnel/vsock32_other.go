//go:build linux && !amd64

package cftunnel

import "os"

// has32: on arm64 the probe has no 32-bit entry to try (the filter kills any AArch32 syscall all the same).
const has32 = false

// RunVsock32: amd64 only.
func RunVsock32(string) { os.Exit(1) }
