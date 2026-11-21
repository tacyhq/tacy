package cftunnel

import (
	"fmt"
	"regexp"
)

// Pinned paths in gatewayd's image and container.
const (
	BinPath    = "/tacy/cloudflared"     // the pinned binary (cmd/compose's gatewayd image)
	ConfigPath = "/tacy/cloudflared.yml" // the pinned locally-managed config
	Dir        = "/tmp/tunnel"           // gatewayd's private tmpfs: the token file and the ingress socket
	SocketPath = "/tmp/tunnel/ingress.sock"
)

var (
	teamRE = regexp.MustCompile(`^[a-z0-9-]{1,63}$`)
	audRE  = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// Config is the locally-managed config pinned in the image: one ingress rule, the Ingress socket, with cloudflared
// itself checking the Access JWT (team and audience pinned), so a request that skipped Access is refused in the VM
// too. The token carries the tunnel's id and secret. The remaining lines pin the transport (http2: Phala's NAT and
// UDP/7844), no self-update, no management diagnostics, and the metrics listener on a random loopback port of
// gatewayd's network namespace (cloudflared can't run without one).
func Config(team, aud string) ([]byte, error) { return ConfigFor(SocketPath, team, aud) }

// ConfigFor is Config with another ingress socket (the confined variant's).
func ConfigFor(socket, team, aud string) ([]byte, error) {
	if !teamRE.MatchString(team) || !audRE.MatchString(aud) {
		return nil, fmt.Errorf("cftunnel: team %q / aud %q", team, aud)
	}
	return []byte(fmt.Sprintf(`# Pinned in gatewayd's image (cmd/compose). Locally managed: the only origin is gatewayd's ingress socket.
protocol: http2
no-autoupdate: true
management-diagnostics: false
metrics: 127.0.0.1:0
loglevel: info
ingress:
  - service: unix:%s
    originRequest:
      access:
        required: true
        teamName: %s
        audTag:
          - %s
`, socket, team, aud)), nil
}
