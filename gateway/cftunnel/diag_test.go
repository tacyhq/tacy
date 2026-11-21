package cftunnel

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// TestIngressDiagRouteOff: without gatewayd's -e2e-diag (Ingress.Diag nil, every release) the diag route doesn't
// exist: /e2e/diag/... answers 404 at the ingress and nothing is forwarded, to the diag or to agentd. With it, the
// route forwards to the diag's /cgi-bin/ with the query and no Cloudflare or Access header, and nothing else changes.
func TestIngressDiagRouteOff(t *testing.T) {
	var diagHits, agentHits int
	var got *http.Request
	diag := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		diagHits++
		got = r.Clone(r.Context())
		io.WriteString(w, "killed 1\n")
	}))
	defer diag.Close()
	agent := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { agentHits++ })

	call := func(in *Ingress, method, target string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, target, nil)
		req.Header.Set("Cf-Access-Jwt-Assertion", "jwt")
		req.Header.Set("Cf-Connecting-Ip", "203.0.113.9")
		w := httptest.NewRecorder()
		in.ServeHTTP(w, req)
		return w
	}
	off := &Ingress{Agent: "/nonexistent.sock"}
	off.init()
	off.proxy.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		rec := httptest.NewRecorder()
		agent.ServeHTTP(rec, r)
		return rec.Result(), nil
	})
	for _, p := range []string{"/e2e/diag/tok?gatewayd", "/e2e/diag/tok/x", "/e2e/diag/", "/cgi-bin/tok?agentd"} {
		for _, m := range []string{"GET", "POST"} {
			if w := call(off, m, p); w.Code != 404 {
				t.Errorf("no -e2e-diag: %s %s = %d, want 404", m, p, w.Code)
			}
		}
	}
	if diagHits != 0 || agentHits != 0 {
		t.Fatalf("no -e2e-diag: forwarded (diag %d, agentd %d)", diagHits, agentHits)
	}

	u, _ := url.Parse(diag.URL)
	on := &Ingress{Agent: "/nonexistent.sock", Diag: diagHandler(u, http.DefaultTransport)}
	w := call(on, "GET", "/e2e/diag/tok?gatewayd")
	if w.Code != 200 || !strings.Contains(w.Body.String(), "killed 1") || diagHits != 1 {
		t.Fatalf("-e2e-diag: %d %q (diag hits %d)", w.Code, w.Body.String(), diagHits)
	}
	if got.URL.Path != "/cgi-bin/tok" || got.URL.RawQuery != "gatewayd" {
		t.Errorf("forwarded to %s?%s, want /cgi-bin/tok?gatewayd", got.URL.Path, got.URL.RawQuery)
	}
	for _, h := range []string{"Cf-Access-Jwt-Assertion", "Cf-Connecting-Ip"} {
		if got.Header.Get(h) != "" {
			t.Errorf("%s reached the diag", h)
		}
	}
	for _, p := range []string{"/e2e/diag/../x", "/e2e/diag/a//b", "/e2e/diag/a%2Fb", "/e2e/diag/"} {
		if w := call(on, "GET", p); w.Code != 404 {
			t.Errorf("-e2e-diag: GET %s = %d, want 404", p, w.Code)
		}
	}
	if w := call(on, "DELETE", "/e2e/diag/tok"); w.Code != 404 {
		t.Errorf("-e2e-diag: DELETE = %d, want 404", w.Code)
	}
	// The allowlist is unchanged with the route on.
	if w := call(on, "GET", "/safety"); w.Code != 404 {
		t.Errorf("-e2e-diag: GET /safety = %d, want 404", w.Code)
	}
	if diagHits != 1 {
		t.Fatalf("diag hits %d, want 1", diagHits)
	}
}

func TestNewDiagOrigin(t *testing.T) {
	for _, ok := range []string{"http://e2ediag:8082", "http://e2ediag:8082/"} {
		if _, err := NewDiag(ok); err != nil {
			t.Errorf("NewDiag(%q): %v", ok, err)
		}
	}
	for _, bad := range []string{"", "e2ediag:8082", "https://e2ediag:8082", "http://e2ediag", "http://e2ediag:8082/cgi-bin", "http://u@e2ediag:8082"} {
		if _, err := NewDiag(bad); err == nil {
			t.Errorf("NewDiag(%q) accepted", bad)
		}
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
