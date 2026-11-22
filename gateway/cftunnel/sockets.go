package cftunnel

import (
	"strings"
)

// UDP and abstract UNIX sockets in the shared network namespace (2026-11-22). Like a TCP
// listener (review 2, L3), a UDP socket or an abstract UNIX socket there is reachable by cloudflared's uid whatever
// its owner: the namespace can't refuse either by uid, and an abstract name has no file permissions. A release has
// none but Docker's embedded resolver's UDP socket (dockerdns.go: 127.0.0.11, root's; on a real VM 2026-11-21 the
// only UDP socket, and no abstract one), so the probe fails on every other one. Named UNIX sockets are files: the
// probe's Deny and Allow lists check those by path.

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
