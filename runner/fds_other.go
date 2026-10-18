//go:build !linux

package runner

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

// Development only (the CVM runs Linux): close-on-exec is set right after receipt.
const recvFlags = 0

func checkSocket(f *os.File) error {
	fd := int(f.Fd())
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		return err
	}
	if st.Mode&syscall.S_IFMT != syscall.S_IFSOCK {
		return fmt.Errorf("not a socket")
	}
	if typ, err := syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_TYPE); err != nil || typ != syscall.SOCK_STREAM {
		return fmt.Errorf("not a stream socket")
	}
	return nil
}

func checkPeer(syscall.Conn, int) error {
	return errors.New("the peer uid check needs linux; use uid -1")
}
