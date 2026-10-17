//go:build !linux

package gateway

import (
	"errors"
	"net"
)

// CheckPeer: no SO_PEERCRED in the standard library here, so only the socket's owner and mode protect it. The CVM
// runs Linux; pass peer uid -1 on a laptop.
func CheckPeer(net.Conn, int) error {
	return errors.New("the peer uid check needs linux; use uid -1")
}
