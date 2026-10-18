package runner

import (
	"fmt"
	"os"
	"syscall"
)

// recvFlags: descriptors arrive close-on-exec, atomically (no runsc started meanwhile inherits one).
const recvFlags = syscall.MSG_CMSG_CLOEXEC

// checkSocket refuses a passed descriptor that isn't a connected unix stream socket: the brain's only link is a
// socketpair end, never a network socket or a file.
func checkSocket(f *os.File) error {
	fd := int(f.Fd())
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		return err
	}
	if st.Mode&syscall.S_IFMT != syscall.S_IFSOCK {
		return fmt.Errorf("not a socket")
	}
	dom, err := syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_DOMAIN)
	if err != nil {
		return err
	}
	typ, err := syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_TYPE)
	if err != nil {
		return err
	}
	if dom != syscall.AF_UNIX || typ != syscall.SOCK_STREAM {
		return fmt.Errorf("socket domain %d type %d: not a unix stream socket", dom, typ)
	}
	if _, err := syscall.Getpeername(fd); err != nil {
		return fmt.Errorf("not connected: %w", err)
	}
	return nil
}

// checkPeer refuses a connection whose peer process doesn't run as uid (SO_PEERCRED: the kernel's answer).
func checkPeer(c syscall.Conn, uid int) error {
	raw, err := c.SyscallConn()
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
		return fmt.Errorf("peer uid %d not allowed", cred.Uid)
	}
	return nil
}
