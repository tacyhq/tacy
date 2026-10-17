//go:build !linux

package vault

import (
	"errors"
	"net"
)

// checkPeer: no SO_PEERCRED in the standard library here, so only the socket's file mode protects it. The CVM
// runs Linux; Serve with peerUID -1 on a laptop.
func checkPeer(net.Conn, int) error {
	return errors.New("vault: peer uid check needs linux; serve with peerUID -1")
}
