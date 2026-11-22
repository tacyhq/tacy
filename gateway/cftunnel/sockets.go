package cftunnel

import (
	"os"
	"strings"
)

// UDP and abstract UNIX sockets in the shared network namespace (2026-11-22). Like a TCP
// listener (review 2, L3), a UDP socket or an abstract UNIX socket there is reachable by cloudflared's uid whatever
// its owner: the namespace can't refuse either by uid, and an abstract name has no file permissions. A release has
// none but Docker's embedded resolver's UDP socket (dockerdns.go: 127.0.0.11, root's; on a real VM 2026-11-21 the
// only UDP socket, and no abstract one), so the probe fails on every other one. Named UNIX sockets are files: the
// probe's Deny and Allow lists check those by path.
//
// UDP-Lite: the seccomp filter allows any protocol on AF_INET and AF_INET6, so a UDP-Lite socket is
// as reachable as a UDP one; /proc/net/udplite and udplite6 have udp's format, and every socket there fails (Docker's
// resolver is plain UDP).
//
// Netlink: AF_NETLINK is allowed (Go's net package lists interfaces over NETLINK_ROUTE). The kernel
// lets a process send to another process's netlink socket (a non-zero port id, or a multicast group) only with
// CAP_NET_ADMIN, except on NETLINK_USERSOCK (af_netlink.c: the only protocol with NL_CFG_F_NONROOT_SEND), and
// cloudflared has no capabilities. Every other protocol's sockets talk to the kernel only. So the rule: any
// NETLINK_USERSOCK socket (protocol 2) in the namespace fails, whoever owns it (/proc/net/netlink names no owner). A
// rule on every socket with a non-zero port id would fail on Docker itself: dockerd keeps a NETLINK_ROUTE socket in
// each container's namespace (seen 2026-11-22, Docker 28.3.3: protocol 0, port id 13).

// isDockerResolverUDP says whether the fields of a /proc/net/udp line are Docker's embedded resolver's UDP socket:
// bound to 127.0.0.11 on any port, not connected (state 07, remote 0.0.0.0:0), owned by uid 0.
func isDockerResolverUDP(fields []string) bool {
	return len(fields) > 7 && strings.HasPrefix(fields[1], dockerResolverHex+":") && fields[2] == "00000000:0000" &&
		fields[3] == "07" && fields[7] == "0"
}

// udpSocketsIn lists the UDP sockets of one /proc/net/udp* file (`file` its base name: udp, udp6) as
// "<file> <local> <remote> uid <uid>", and which of them are Docker's resolver (IPv4 only). The header line is
// skipped, and so is a line too short to be a socket.
func udpSocketsIn(file, content string) ([]string, map[string]bool) {
	var out []string
	resolver := map[string]bool{}
	for i, ln := range strings.Split(content, "\n") {
		fs := strings.Fields(ln)
		if i == 0 || len(fs) < 8 || !strings.HasSuffix(fs[0], ":") {
			continue
		}
		name := file + " " + fs[1] + " " + fs[2] + " uid " + fs[7]
		out = append(out, name)
		if file == "udp" && isDockerResolverUDP(fs) {
			resolver[name] = true
		}
	}
	return out, resolver
}

// udpSocketsFrom lists the network namespace's UDP and UDP-Lite sockets (udpSocketsIn on udp, udp6, udplite,
// udplite6, as `read` gives each /proc/net file) and which of them is Docker's resolver. udp must be readable; each
// other file is skipped only when it doesn't exist (a kernel without IPv6 or UDP-Lite), and any other read error is
// the error (never fail open).
func udpSocketsFrom(read func(file string) ([]byte, error)) ([]string, map[string]bool, error) {
	var out []string
	resolver := map[string]bool{}
	for _, f := range []string{"udp", "udp6", "udplite", "udplite6"} {
		b, err := read(f)
		if err != nil {
			if f != "udp" && os.IsNotExist(err) {
				continue
			}
			return out, resolver, err
		}
		socks, res := udpSocketsIn(f, string(b))
		out = append(out, socks...)
		for k := range res {
			resolver[k] = true
		}
	}
	return out, resolver, nil
}

// abstractUnixIn lists the abstract UNIX sockets of /proc/net/unix (their path, as the kernel writes it: "@name").
// Unnamed sockets (no path) and named ones (a file path) aren't listed.
func abstractUnixIn(content string) []string {
	var out []string
	for i, ln := range strings.Split(content, "\n") {
		fs := strings.Fields(ln)
		if i == 0 || len(fs) < 8 {
			continue
		}
		if p := strings.Join(fs[7:], " "); strings.HasPrefix(p, "@") {
			out = append(out, p)
		}
	}
	return out
}

// netlinkUsersockIn lists the NETLINK_USERSOCK sockets of /proc/net/netlink (columns: sk Eth Pid Groups ... Inode; Eth
// the protocol, 2 for NETLINK_USERSOCK) as "netlink usersock pid <port id> inode <inode>". The header line, other
// protocols and a line too short to be a socket aren't listed.
func netlinkUsersockIn(content string) []string {
	var out []string
	for i, ln := range strings.Split(content, "\n") {
		fs := strings.Fields(ln)
		if i == 0 || len(fs) < 10 || fs[1] != "2" {
			continue
		}
		out = append(out, "netlink usersock pid "+fs[2]+" inode "+fs[9])
	}
	return out
}
