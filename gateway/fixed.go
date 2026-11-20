package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/tacyhq/tacy/kms/client"
)

// Fixed calls (the keys plan §2.4 item 6, §3.2). agentd and vaultd have no network. They reach the Tacy key service and the
// chat Worker's sealed-state API through gatewayd with one typed op, a "fixed" call, to hosts named only in
// gatewayd's command line (-kms-url, -state-url; the compose pins them, so the attested compose hash covers them).
// A call never names a host: it names a target and, for the key service, the index of one of its replicas. Its
// method, path and headers are checked against what that target serves; its body is opaque (the key service's
// JSON, whose replies are signed by the KMS id and sealed to the caller's attested key; or a sealed blob).
//
// Over the socket a call is a connection's only frame (agentd on gatewayd's socket; vaultd on the ops socket,
// which serves nothing else).

// Targets.
const (
	TargetKMS   = "kms"
	TargetState = "state"
)

// MaxFixedBody bounds a fixed call's body either way: a sealed state blob as a frame's base64 fits MaxFrame.
const MaxFixedBody = 11 << 20

// FixedCall is one call to a fixed host.
type FixedCall struct {
	Target string            `json:"target"`
	Host   int               `json:"host,omitzero"` // kms: the replica's index in -kms-url's order
	Method string            `json:"method"`
	Path   string            `json:"path"` // with its query
	Header map[string]string `json:"header,omitzero"`
	Body   []byte            `json:"body,omitzero"`
}

// FixedAnswer is the host's answer, or Error when the call didn't reach it.
type FixedAnswer struct {
	Status int               `json:"status,omitzero"`
	Header map[string]string `json:"header,omitzero"`
	Body   []byte            `json:"body,omitzero"`
	// Error: "bad_call" (not a call this target serves), "no_target" (gatewayd has no such host), "unreachable"
	// (network, TLS or timeout), "too_large".
	Error string `json:"error,omitzero"`
}

// FixedDoer makes fixed calls: gatewayd's Fixed in process, or a Client over gatewayd's socket.
type FixedDoer interface {
	Fixed(ctx context.Context, call *FixedCall) *FixedAnswer
}

var (
	stateName = regexp.MustCompile(`^/api/vm/state/[a-z0-9][a-z0-9_-]{0,63}$`)
	kmsCalls  = map[string]string{ // path (without query) -> method
		"/v1/status": "GET", "/v1/challenge": "GET", "/v1/release": "POST", "/v1/lease/renew": "POST",
		"/v1/lease/drop": "POST", "/v1/gen/commit": "POST", "/v1/gen": "GET",
	}
	fixedRequestHeaders  = []string{"Content-Type", "X-Tacy-Gen", "X-Tacy-Prev-Gen", "X-Tacy-Cert", "X-Tacy-Auth"}
	fixedResponseHeaders = []string{"Content-Type", "X-Tacy-Gen"}
)

// CheckFixed says whether call is one its target serves (method, path, headers, size). The hosts aren't consulted.
func CheckFixed(call *FixedCall) error {
	if call == nil {
		return errors.New("no call")
	}
	if len(call.Body) > MaxFixedBody {
		return errors.New("too_large")
	}
	for k, v := range call.Header {
		ok := false
		for _, h := range fixedRequestHeaders {
			ok = ok || http.CanonicalHeaderKey(k) == h
		}
		if !ok || len(v) > 4096 || strings.ContainsAny(v, "\r\n") {
			return fmt.Errorf("header %q isn't one a fixed call sends", k)
		}
	}
	path, query, _ := strings.Cut(call.Path, "?")
	switch call.Target {
	case TargetKMS:
		m, ok := kmsCalls[path]
		if !ok || m != call.Method || call.Host < 0 {
			return fmt.Errorf("%s %s isn't a key service call", call.Method, path)
		}
		if query != "" && path != "/v1/gen" {
			return errors.New("a query only on /v1/gen")
		}
		if _, err := url.ParseQuery(query); err != nil {
			return err
		}
	case TargetState:
		if !stateName.MatchString(path) || query != "" || (call.Method != "GET" && call.Method != "PUT") || call.Host != 0 {
			return fmt.Errorf("%s %s isn't a sealed-state call", call.Method, path)
		}
	default:
		return fmt.Errorf("unknown target %q", call.Target)
	}
	if call.Method == "GET" && len(call.Body) > 0 {
		return errors.New("a GET has no body")
	}
	return nil
}

// Fixed is gatewayd's side: the fixed hosts and the client that reaches them (HTTPS only).
type Fixed struct {
	KMS   []string // the key service's replicas, https base URLs
	State string   // the chat Worker, https base URL
	// Client: nil = HTTPS with a 60 s timeout (names resolve through the process's resolver: DNS over TLS in the
	// CVM, gateway.UseDoT).
	Client *http.Client
	// AllowHTTP: tests only (an httptest server). A release's hosts are https, which the verifier also checks
	// for -kms-url.
	AllowHTTP bool
}

// NewFixed checks the hosts.
func NewFixed(kmsURLs []string, stateURL string, allowHTTP bool) (*Fixed, error) {
	f := &Fixed{State: strings.TrimSuffix(stateURL, "/"), AllowHTTP: allowHTTP}
	for _, u := range kmsURLs {
		f.KMS = append(f.KMS, strings.TrimSuffix(u, "/"))
	}
	for _, u := range append(append([]string{}, f.KMS...), f.State) {
		if u == "" {
			continue
		}
		p, err := url.Parse(u)
		if err != nil || p.Host == "" || p.Path != "" || p.RawQuery != "" || p.User != nil ||
			(p.Scheme != "https" && !(allowHTTP && p.Scheme == "http")) {
			return nil, fmt.Errorf("fixed host %q isn't an https base URL", u)
		}
	}
	return f, nil
}

func (f *Fixed) base(call *FixedCall) string {
	switch call.Target {
	case TargetKMS:
		if call.Host >= 0 && call.Host < len(f.KMS) {
			return f.KMS[call.Host]
		}
	case TargetState:
		return f.State
	}
	return ""
}

var defaultFixedClient = &http.Client{Timeout: 60 * time.Second, Transport: &http.Transport{
	Proxy: nil, DialContext: (&net.Dialer{Timeout: 15 * time.Second}).DialContext, TLSHandshakeTimeout: 15 * time.Second,
	MaxIdleConns: 8, IdleConnTimeout: time.Minute, ForceAttemptHTTP2: true,
}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

// Fixed implements FixedDoer.
func (f *Fixed) Fixed(ctx context.Context, call *FixedCall) *FixedAnswer {
	if err := CheckFixed(call); err != nil {
		if err.Error() == "too_large" {
			return &FixedAnswer{Error: "too_large"}
		}
		return &FixedAnswer{Error: "bad_call"}
	}
	base := f.base(call)
	if base == "" {
		return &FixedAnswer{Error: "no_target"}
	}
	var rd io.Reader
	if call.Body != nil {
		rd = bytes.NewReader(call.Body)
	}
	req, err := http.NewRequestWithContext(ctx, call.Method, base+call.Path, rd)
	if err != nil {
		return &FixedAnswer{Error: "bad_call"}
	}
	for k, v := range call.Header {
		req.Header.Set(k, v)
	}
	req.Header.Set("User-Agent", "tacy-agent-vm")
	c := f.Client
	if c == nil {
		c = defaultFixedClient
	}
	res, err := c.Do(req)
	if err != nil {
		return &FixedAnswer{Error: "unreachable"}
	}
	defer res.Body.Close()
	b, err := io.ReadAll(io.LimitReader(res.Body, MaxFixedBody+1))
	if err != nil {
		return &FixedAnswer{Error: "unreachable"}
	}
	if len(b) > MaxFixedBody {
		return &FixedAnswer{Error: "too_large"}
	}
	a := &FixedAnswer{Status: res.StatusCode, Body: b}
	for _, h := range fixedResponseHeaders {
		if v := res.Header.Get(h); v != "" {
			if a.Header == nil {
				a.Header = map[string]string{}
			}
			a.Header[h] = v
		}
	}
	return a
}

// Fixed sends a fixed call to gatewayd (agentd's socket, or vaultd's ops socket): a connection's only frame.
func (c *Client) Fixed(ctx context.Context, call *FixedCall) *FixedAnswer {
	var d net.Dialer
	nc, err := d.DialContext(ctx, "unix", c.Path)
	if err != nil {
		return &FixedAnswer{Error: "unreachable"}
	}
	defer nc.Close()
	nc.SetDeadline(time.Now().Add(75 * time.Second))
	if dl, ok := ctx.Deadline(); ok {
		nc.SetDeadline(dl)
	}
	if err := writeFrame(nc, &frame{T: tFixed, Version: Version, Fixed: call}); err != nil {
		return &FixedAnswer{Error: "unreachable"}
	}
	var f frame
	if err := readFrame(nc, &f); err != nil || f.T != tResult || f.FixedResult == nil {
		return &FixedAnswer{Error: "unreachable"}
	}
	return f.FixedResult
}

// ErrUnreachable is a fixed call that didn't reach its host (KMSTransport, StateHTTP): try another replica, or later.
var ErrUnreachable = errors.New("gateway: the fixed host didn't answer")

// KMSTransport is the key service client's Transport over fixed calls to replica Host.
type KMSTransport struct {
	D    FixedDoer
	Host int
}

// Do implements client.Transport.
func (t KMSTransport) Do(ctx context.Context, method, path string, body []byte) ([]byte, error) {
	call := &FixedCall{Target: TargetKMS, Host: t.Host, Method: method, Path: path, Body: body}
	if body != nil {
		call.Header = map[string]string{"Content-Type": "application/json"}
	}
	a := t.D.Fixed(ctx, call)
	if a.Error != "" {
		return nil, fmt.Errorf("%w (%s)", ErrUnreachable, a.Error)
	}
	if a.Status != http.StatusOK {
		var e struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(a.Body, &e) != nil || e.Error == "" {
			e.Error = http.StatusText(a.Status)
		}
		return nil, &client.RefusedError{Status: a.Status, Reason: e.Error}
	}
	return a.Body, nil
}

// StateHTTP carries sealstate.Relay's requests as fixed calls to the state target (its Client).
type StateHTTP struct{ D FixedDoer }

// Do sends req (its URL's path only; the host is gatewayd's -state-url).
func (s StateHTTP) Do(req *http.Request) (*http.Response, error) {
	var body []byte
	if req.Body != nil {
		b, err := io.ReadAll(io.LimitReader(req.Body, MaxFixedBody+1))
		req.Body.Close()
		if err != nil {
			return nil, err
		}
		body = b
	}
	call := &FixedCall{Target: TargetState, Method: req.Method, Path: req.URL.EscapedPath(), Body: body}
	for _, h := range fixedRequestHeaders {
		if v := req.Header.Get(h); v != "" {
			if call.Header == nil {
				call.Header = map[string]string{}
			}
			call.Header[h] = v
		}
	}
	a := s.D.Fixed(req.Context(), call)
	if a.Error != "" {
		return nil, fmt.Errorf("%w (%s)", ErrUnreachable, a.Error)
	}
	res := &http.Response{StatusCode: a.Status, Header: http.Header{}, Body: io.NopCloser(bytes.NewReader(a.Body)),
		ContentLength: int64(len(a.Body)), Request: req}
	for k, v := range a.Header {
		res.Header.Set(k, v)
	}
	return res, nil
}

// KMSGate is what one of gatewayd's sockets may ask the key service for: a release only of Purposes and only for
// Holder, and lease and register calls only for Holder. The key service can't tell agentd from vaultd (one TD, one
// quote, one app; both have dstack's socket for their own quotes), so this is where each process is held to its own
// purposes: agentd never gets conn/v1 (or the API keys that come only with it), vaultd never state/v1. What can't be
// held here: a process that took over gatewayd itself (the only one with a network) could ask for anything the app
// may have; it still couldn't open a reply, which is sealed to the asking process's attested key.
type KMSGate struct {
	D        FixedDoer
	Holder   string
	Purposes []string
}

// The purposes each socket's process may ask for (the keys plan §2.4 item 6).
var (
	AgentKMSPurposes = []string{"state/v1", "activity-sign/v1", "task-ids/v1", "notify/v1", "operator/v1", "relay-auth/v1"}
	VaultKMSPurposes = []string{"conn/v1"}
)

// Fixed implements FixedDoer.
func (g KMSGate) Fixed(ctx context.Context, call *FixedCall) *FixedAnswer {
	if call != nil && call.Target == TargetKMS {
		path, _, _ := strings.Cut(call.Path, "?")
		var r struct {
			Purposes []string `json:"purposes"`
			Holder   string   `json:"holder"`
		}
		switch path {
		case "/v1/release":
			if json.Unmarshal(call.Body, &r) != nil || r.Holder != g.Holder || len(r.Purposes) == 0 {
				return &FixedAnswer{Error: "bad_call"}
			}
			for _, p := range r.Purposes {
				if !slices.Contains(g.Purposes, p) {
					return &FixedAnswer{Error: "bad_call"}
				}
			}
		case "/v1/lease/renew", "/v1/lease/drop", "/v1/gen/commit":
			if json.Unmarshal(call.Body, &r) != nil || r.Holder != g.Holder {
				return &FixedAnswer{Error: "bad_call"}
			}
		}
	}
	return g.D.Fixed(ctx, call)
}
