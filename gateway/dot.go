package gateway

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"
)

// DNS over TLS (RFC 7858; the keys plan §3.4, PX-4). The VM's traffic leaves through the provider's host network, where
// plain DNS shows (and lets the host change) every name gatewayd looks up: each site a task reads, each user's mail
// server, when Tinfoil and the search provider are called. gatewayd sends every lookup instead over TLS to one
// pinned resolver, named in the attested compose (-dns-tls), checked against its certificate's name, and never falls
// back to plain DNS: if the resolver can't be reached, nothing resolves.
//
// What stays visible to the host: the resolver's address (and that lookups happen, their sizes and times), and each
// connection's TLS server name (SNI), which TLS sends in the clear. The resolver itself sees the names; which one to
// trust with that is a choice of its own, so it is a compose argument, not code.

// DoT is a parsed -dns-tls value: the resolver's TLS name and its addresses (IP:port, tried in order).
type DoT struct {
	Name  string
	Addrs []string
	// Roots verifies the resolver's certificate; nil: the system's (the image's CA bundle). Tests only.
	Roots *x509.CertPool
}

// ParseDoT parses "<tls name>@<ip>:<port>[,<ip>:<port>...]", e.g. "dns.quad9.net@9.9.9.9:853,149.112.112.112:853".
// Addresses are IPs (looking the resolver up would need DNS) and the name is what its certificate must carry.
func ParseDoT(spec string) (*DoT, error) {
	name, addrs, ok := strings.Cut(spec, "@")
	if !ok || name == "" || addrs == "" || strings.ContainsAny(name, "/: ") {
		return nil, errors.New("dns-tls: want <tls name>@<ip>:<port>[,<ip>:<port>]")
	}
	d := &DoT{Name: name}
	for a := range strings.SplitSeq(addrs, ",") {
		ap, err := netip.ParseAddrPort(a)
		if err != nil || ap.Port() == 0 {
			return nil, fmt.Errorf("dns-tls: %q isn't an IP:port", a)
		}
		d.Addrs = append(d.Addrs, ap.String())
	}
	return d, nil
}

// dotTimeout bounds one connection to the resolver (TCP and TLS handshake).
const dotTimeout = 5 * time.Second

// Resolver is a Go resolver that sends every query over TLS to d (DNS over TCP framing on the TLS stream: Go's
// resolver frames for TCP on any connection that isn't a PacketConn). The address the resolver asks for (the
// system's nameserver) is ignored.
func (d *DoT) Resolver() *net.Resolver {
	return &net.Resolver{PreferGo: true, StrictErrors: true, Dial: d.dial}
}

func (d *DoT) dial(ctx context.Context, _, _ string) (net.Conn, error) {
	var last error
	for _, a := range d.Addrs {
		dl := &tls.Dialer{NetDialer: &net.Dialer{Timeout: dotTimeout},
			Config: &tls.Config{ServerName: d.Name, RootCAs: d.Roots, MinVersion: tls.VersionTLS12}}
		c, err := dl.DialContext(ctx, "tcp", a)
		if err == nil {
			return c, nil
		}
		last = err
	}
	return nil, fmt.Errorf("dns-tls: no resolver reachable: %w", last)
}

// UseDoT makes d every lookup's resolver in this process (net.DefaultResolver: every net.Dialer without its own).
func UseDoT(d *DoT) { net.DefaultResolver = d.Resolver() }
