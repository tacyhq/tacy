package cftunnel

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"
)

// The e2e test's diag route (the release gate's notes; the v1 design §7.4). A Fix B VM has no published port, so
// the release gate reaches the overlay's diag service (cmd/e2e overlay: crash kills, the plaintext-disk scan) through
// the tunnel, behind the same Access app and service token as every other call: /e2e/diag/<rest> on the ingress
// socket is forwarded to <origin>/cgi-bin/<rest>, the diag's token-guarded CGI script. The route exists only when
// gatewayd runs with -e2e-diag (DiagFlag), which the verifier refuses in every compose but an e2e overlay's
// (verifier.E2EDiagFlag): no production client, holder or policy accepts a compose that sets it. Without the flag the
// ingress has no such route and answers 404 before anything is forwarded.

// DiagPrefix is the diag route's path prefix on the ingress socket.
const DiagPrefix = "/e2e/diag/"

// DiagFlag is gatewayd's flag that turns the route on (its value: the diag service's http://host:port in the
// compose's own network).
const DiagFlag = "e2e-diag"

// dockerDNS is the compose network's resolver (Docker's embedded DNS). gatewayd sends every other lookup over TLS to
// the compose's pinned resolver (gateway.UseDoT), which can't know a compose service's name.
const dockerDNS = "127.0.0.11:53"

// NewDiag is the diag route's handler: it forwards GET and POST under DiagPrefix to origin's /cgi-bin/, with the
// query, Content-Type and Content-Length only (no Cloudflare or Access header reaches the diag). origin is
// http://<service>:<port> on the compose's network.
func NewDiag(origin string) (http.Handler, error) {
	u, err := url.Parse(origin)
	if err != nil || u.Scheme != "http" || u.Host == "" || u.Path != "" && u.Path != "/" || u.RawQuery != "" || u.User != nil {
		return nil, fmt.Errorf("cftunnel: -%s %q: want http://<service>:<port>", DiagFlag, origin)
	}
	if _, _, err := net.SplitHostPort(u.Host); err != nil {
		return nil, fmt.Errorf("cftunnel: -%s %q: want http://<service>:<port>", DiagFlag, origin)
	}
	res := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, dockerDNS)
	}}
	dialer := &net.Dialer{Resolver: res, Timeout: 10 * time.Second}
	tr := &http.Transport{DialContext: dialer.DialContext, MaxIdleConns: 4, IdleConnTimeout: 30 * time.Second, DisableCompression: true}
	return diagHandler(u, tr), nil
}

func diagHandler(u *url.URL, tr http.RoundTripper) http.Handler {
	proxy := &httputil.ReverseProxy{
		Transport:     tr,
		FlushInterval: -1,
		Rewrite: func(r *httputil.ProxyRequest) {
			rest := strings.TrimPrefix(r.In.URL.Path, DiagPrefix)
			r.Out.URL = &url.URL{Scheme: "http", Host: u.Host, Path: "/cgi-bin/" + rest, RawQuery: r.In.URL.RawQuery}
			r.Out.Host = u.Host
			h := http.Header{}
			for _, k := range []string{"Content-Type", "Content-Length"} {
				if v := r.In.Header.Values(k); len(v) > 0 {
					h[k] = v
				}
			}
			r.Out.Header = h
		},
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, err error) {
			http.Error(w, "e2e diag unavailable", http.StatusBadGateway)
		},
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rest := strings.TrimPrefix(r.URL.Path, DiagPrefix)
		if r.Method != http.MethodGet && r.Method != http.MethodPost || r.URL.RawPath != "" || !validDiagPath(rest) {
			http.NotFound(w, r)
			return
		}
		proxy.ServeHTTP(w, r)
	})
}

// validDiagPath: one or more path segments of [A-Za-z0-9._-], none "." or "..".
func validDiagPath(p string) bool {
	if p == "" || len(p) > 200 {
		return false
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == "" || seg == "." || seg == ".." {
			return false
		}
		for _, c := range seg {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '-') {
				return false
			}
		}
	}
	return true
}
