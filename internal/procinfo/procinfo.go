// Package procinfo describes the process for its start log line: who it runs as and which network interfaces it
// has. In the CVM there's no shell to look inside a container, so this line is how a release check sees that
// dstack gave each process its own uid and that agentd, the brain and vaultd have no network (loopback only). It
// reads; it never dials.
package procinfo

import (
	"fmt"
	"net"
	"os"
	"strings"
)

// Line is "uid U gid G groups [..]; network interfaces: lo, eth0 (with addresses)".
func Line() string {
	groups, _ := os.Getgroups()
	var names []string
	ifs, err := net.Interfaces()
	for _, i := range ifs {
		if i.Flags&net.FlagUp == 0 {
			continue
		}
		n := i.Name
		if addrs, _ := i.Addrs(); len(addrs) > 0 && i.Flags&net.FlagLoopback == 0 {
			n += " (with addresses)"
		}
		names = append(names, n)
	}
	ifaces := strings.Join(names, ", ")
	if err != nil {
		ifaces = "unknown: " + err.Error()
	}
	return fmt.Sprintf("uid %d gid %d groups %v; network interfaces up: %s", os.Getuid(), os.Getgid(), groups, ifaces)
}
