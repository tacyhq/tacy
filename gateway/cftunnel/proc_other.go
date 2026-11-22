//go:build !linux

package cftunnel

import "os/exec"

func setDeathSignal(*exec.Cmd) {}

// checkTmpfs: development hosts only (the CVM is Linux).
func checkTmpfs(string) error { return nil }
