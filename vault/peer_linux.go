package vault

import (
	"fmt"
	"net"
	"syscall"
)

// checkPeer refuses a connection whose peer process doesn't run as uid (SO_PEERCRED: the kernel's answer, not
// something the peer says).
func checkPeer(c net.Conn, uid int) error {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return fmt.Errorf("vault: not a unix connection")
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return err
	}
	var cred *syscall.Ucred
	var cerr error
	if err := raw.Control(func(fd uintptr) {
		cred, cerr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil {
		return err
	}
	if cerr != nil {
		return cerr
	}
	if int(cred.Uid) != uid {
		return fmt.Errorf("vault: peer uid %d not allowed", cred.Uid)
	}
	return nil
}
