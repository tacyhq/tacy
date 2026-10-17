//go:build !linux

package main

import (
	"errors"
	"net"
)

// checkPeer: no SO_PEERCRED in the standard library here, so only the socket's owner and mode protect it. The CVM
// runs Linux; use -brain-uid -1 on a laptop.
func checkPeer(net.Conn, int) error {
	return errors.New("the brain's peer uid check needs linux; use -brain-uid -1")
}
