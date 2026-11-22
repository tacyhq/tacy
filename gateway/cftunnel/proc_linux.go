package cftunnel

import (
	"os/exec"
	"syscall"
)

// setDeathSignal: cloudflared dies with gatewayd (a container restart takes both anyway).
func setDeathSignal(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
}

// checkTmpfs refuses a token directory that isn't on a tmpfs (TD memory).
func checkTmpfs(dir string) error {
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err != nil {
		return err
	}
	if st.Type != 0x01021994 {
		return errNotTmpfs
	}
	return nil
}
