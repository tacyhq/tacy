//go:build !linux

package cftunnel

import (
	"context"
	"errors"
	"os"
)

var errNoLauncher = errors.New("cftunnel: the launcher runs on Linux only (the CVM)")

// Harden is a no-op off Linux (development hosts).
func Harden() (HardenStatus, error) {
	return HardenStatus{Dumpable: -1, YamaPtraceScope: "absent"}, nil
}

// Launch: Linux only.
func Launch(LaunchConfig, []string, []string) { panic(errNoLauncher) }

// RunProbe: Linux only.
func RunProbe(string) { os.Exit(1) }

// RunVsock32: Linux only.
func RunVsock32(string) { os.Exit(1) }

// RunReap: Linux only.
func RunReap() { os.Exit(1) }

// LauncherStarter: Linux only.
type LauncherStarter struct{ OnProbe func([]byte) }

// LauncherFromEnv: Linux only.
func LauncherFromEnv(func([]byte)) (*LauncherStarter, error) { return nil, errNoLauncher }

// Start: Linux only.
func (*LauncherStarter) Start(context.Context, []byte) (Child, error) { return nil, errNoLauncher }
