package cftunnel

import (
	"fmt"
	"regexp"
	"strings"
)

// Pinned paths in gatewayd's image and container.
const (
	BinPath    = "/tacy/cloudflared"     // the pinned binary (cmd/compose's gatewayd image)
	ConfigPath = "/tacy/cloudflared.yml" // the pinned locally-managed config
	// Dir is the tunnel's tmpfs in gatewayd's container (the compose mounts it uid 10001, gid TunnelUID, 0750): the
	// ingress socket (0660, group TunnelUID: the one thing cloudflared's uid can connect to) and confinement.json
	// (the launcher's last probe, 0600: gatewayd's only).
	Dir        = "/run/tunnel"
	SocketPath = "/run/tunnel/ingress.sock"
	ProbeFile  = "/run/tunnel/confinement.json"
	// TunnelUID is cloudflared's uid and gid (gatewayd's -tunnel-uid); GatewaydUID gatewayd's own (its launcher
	// starts it as GatewaydUID:GatewaydUID with TunnelUID as its one supplementary group).
	TunnelUID   = 10006
	GatewaydUID = 10001
)

var (
	teamRE = regexp.MustCompile(`^[a-z0-9-]{1,63}$`)
	audRE  = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// Config is the locally-managed config the compose pins (the release: the Access app on gatewayd's command line): one ingress rule, the Ingress socket, with cloudflared
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
	return []byte(fmt.Sprintf(`# Pinned by the compose (cmd/compose). Locally managed: the only origin is gatewayd's ingress socket.
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

// ParseAccess reads -cloudflared-access: "team,aud" (the release pins the Access app on gatewayd's command line, so a
// staging compose changes it as a pin, not as an image; gatewayd's launcher writes Config from it: LaunchConfig.Access).
func ParseAccess(s string) (team, aud string, err error) {
	team, aud, ok := strings.Cut(s, ",")
	if !ok || !teamRE.MatchString(team) || !audRE.MatchString(aud) {
		return "", "", fmt.Errorf("cftunnel: access %q: want <team>,<64 hex aud>", s)
	}
	return team, aud, nil
}
