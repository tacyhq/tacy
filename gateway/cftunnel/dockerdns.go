package cftunnel

import "strings"

// Docker's embedded DNS resolver (gate run on vm-v1-gate2, 2026-11-21). gatewayd's container is on the compose's
// own bridge network, a user-defined one, so dockerd serves the container's resolver (127.0.0.11:53, the only
// nameserver in its resolv.conf) from inside its network namespace: iptables there sends port 53 to a TCP and a UDP
// socket dockerd listens on at 127.0.0.11 on a random port, owned by root. cloudflared needs it (it looks up the
// edge's names with the system resolver), and the release's other services have no network. The confinement probe's
// TCP check (review 2, L3) refused it, so on a CVM the launcher refused every cloudflared start and gatewayd exited:
// the tunnel never came up (Docker's tests ran with --network none, which has no such listener). It is the one
// listener the probe lets cloudflared's uid reach, and only in this exact form: 127.0.0.11, uid 0, IPv4.

// dockerResolverHex is 127.0.0.11 as /proc/net/tcp writes it (each 32-bit word in host, little-endian, order).
const dockerResolverHex = "0B00007F"

// isDockerResolver says whether the fields of a /proc/net/tcp line are a listener of Docker's embedded resolver:
// state LISTEN (0A), local address 127.0.0.11 on any port, owned by uid 0.
func isDockerResolver(fields []string) bool {
	return len(fields) > 7 && fields[3] == "0A" && strings.HasPrefix(fields[1], dockerResolverHex+":") && fields[7] == "0"
}
