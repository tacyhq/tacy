package main

import (
	"context"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	ehbpproto "github.com/tinfoilsh/encrypted-http-body-protocol/protocol"

	"github.com/tacyhq/tacy/vault"
)

// The API keys (the keys plan §3.6): the CVM gets no secret from Phala's encrypted env and none from the chat Worker.
// vaultd asks the Tacy key service for them itself (cmd/vaultd); agentd never holds one. agentd only asks vaultd (a
// status op through gatewayd: names, never values) whether they arrived:
//
//	GET /secrets/status   {"ready": bool}, inside an envelope like every route
//
// and until they did, everything that needs them answers 503 {"error":"starting"} (gate).

// secretsGateway is what agentd reaches vaultd's status through (gateway.Client: gatewayd).
type secretsGateway interface {
	Secrets(ctx context.Context, call *vault.SecretsCall) *vault.SecretsAnswer
}

// keysReady is whether vaultd holds the API keys this boot.
type keysReady struct{ ready atomic.Bool }

func (k *keysReady) set(r *vault.SecretsResult) { k.ready.Store(r != nil && len(r.Names) > 0) }

func (s *server) secretsGW() secretsGateway {
	if s.vaultSecrets != nil {
		return s.vaultSecrets
	}
	g, _ := s.gw.(secretsGateway)
	return g
}

// secretsRoutes serves the status route on mux.
func (s *server) secretsRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /secrets/status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if g := s.secretsGW(); g != nil { // vaultd's word now, not the last watch's (a vault that just restarted)
			ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
			if a := g.Secrets(ctx, &vault.SecretsCall{Op: "status"}); a.Error == "" {
				s.keys.set(a.Secrets)
			}
			cancel()
		}
		writeJSON(w, 200, map[string]bool{"ready": s.keys.ready.Load()})
	})
}

// watchSecrets keeps agentd's view in step with vaultd's: an agentd that restarted finds the keys vaultd still
// holds, and a vaultd that restarted (its keys gone until its next release) puts agentd back to "starting".
func (s *server) watchSecrets(ctx context.Context, every time.Duration) {
	g := s.secretsGW()
	if g == nil {
		return
	}
	for {
		c, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		a := g.Secrets(c, &vault.SecretsCall{Op: "status"})
		cancel()
		if a.Error == "" {
			s.keys.set(a.Secrets)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(every):
		}
	}
}

// offRoute is a route family this VM refuses with a code (the memory-only quick path: schedules and email wait for
// sealed state under the Tacy key service, the keys plan Stages C and D).
type offRoute struct {
	prefix, code, detail string
}

// quickPathOff are the routes a VM without sealed state refuses.
var quickPathOff = []offRoute{
	{"/schedules/", "schedules_off", "scheduled tasks are off until the Tacy key service keeps their state"},
	{"/spaces/reseal", "schedules_off", "scheduled tasks are off until the Tacy key service keeps their state"},
	{"/connections/", "connections_off", "email connections are off until the Tacy key service keeps them"},
}

// gate answers before any route: 503 {"error":"starting"} while vaultd hasn't got the API keys (when s.needKeys),
// and the off routes' codes. What needs no key (attestation, health, the status, signed controls) always passes.
func (s *server) gate(next http.Handler, off []offRoute) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		for _, o := range off {
			if strings.HasPrefix(p, o.prefix) {
				failDetail(w, 503, o.code, o.detail)
				return
			}
		}
		if s.needKeys && !s.keys.ready.Load() && !keyless(p) {
			w.Header().Set("Retry-After", "2")
			failDetail(w, 503, "starting", "the agent VM is waiting for its keys")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// keyless: routes that work before the keys arrived.
func keyless(p string) bool {
	switch p {
	case "/", "/attest", "/health", ehbpproto.KeysPath, "/safety", "/keylog", "/secrets/status":
		return true
	}
	return false
}
