package main

import (
	"context"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	jsonv2 "encoding/json/v2"

	ehbpidentity "github.com/tinfoilsh/encrypted-http-body-protocol/identity"
	ehbpproto "github.com/tinfoilsh/encrypted-http-body-protocol/protocol"

	"github.com/tacyhq/tacy/vault"
)

// Pushed secrets (vault/secrets.go; the keys plan §3.6 Stage A): the CVM gets no secret from Phala's encrypted env. The chat
// Worker verifies this VM's /attest with the browser's verifier, then
//
//	POST /secrets/key     EHBP (to the attested key, so the answer is the attested VM's): {} -> {"key": "x25519:…"},
//	                      vaultd's per-boot secrets key (through gatewayd; agentd never holds a secret).
//	POST /secrets         plaintext JSON vault.SecretsPush: sealed to that key, signed by the operator key the
//	                      compose pins; passed on to vaultd, which checks and opens it -> {"names": [...]}.
//	GET  /secrets/status  {"ready": bool}: whether a push arrived this boot (the Worker pushes when it's false).
//
// Until a push arrives, everything that needs the keys answers 503 {"error":"starting"} (gate). The relay's bearer
// token comes in the same box: agentd keeps only its sha256, from vaultd's answer.

// secretsGateway is what agentd reaches vaultd's secrets ops through (gateway.Client: gatewayd).
type secretsGateway interface {
	Secrets(ctx context.Context, call *vault.SecretsCall) *vault.SecretsAnswer
}

// pushed is agentd's side of the push: whether the keys are in vaultd, and the run token's hash.
type pushed struct {
	ready     atomic.Bool
	tokenHash atomic.Pointer[string]
}

func (p *pushed) set(r *vault.SecretsResult) {
	if r == nil || r.TokenSHA256 == "" || len(r.Names) == 0 {
		p.ready.Store(false)
		p.tokenHash.Store(nil)
		return
	}
	h := r.TokenSHA256
	p.tokenHash.Store(&h)
	p.ready.Store(true)
}

// tokenOK checks a bearer token against the pushed hash.
func (p *pushed) tokenOK(token string) bool {
	h := p.tokenHash.Load()
	return h != nil && vault.TokenMatches(*h, token)
}

func (s *server) secretsGW() secretsGateway {
	if s.vaultSecrets != nil {
		return s.vaultSecrets
	}
	g, _ := s.gw.(secretsGateway)
	return g
}

// secretsRoutes serves the push routes on mux.
func (s *server) secretsRoutes(mux *http.ServeMux, id *ehbpidentity.Identity) {
	mux.Handle("POST /secrets/key", ehbpOnly(id.Middleware()(http.HandlerFunc(s.secretsKey))))
	mux.HandleFunc("POST /secrets", s.secretsPut)
	mux.HandleFunc("GET /secrets/status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if g := s.secretsGW(); g != nil { // vaultd's word now, not the last watch's (a vault that just restarted)
			ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
			if a := g.Secrets(ctx, &vault.SecretsCall{Op: "status"}); a.Error == "" {
				s.push.set(a.Secrets)
			}
			cancel()
		}
		writeJSON(w, 200, map[string]bool{"ready": s.push.ready.Load()})
	})
}

// ehbpOnly refuses a request without an EHBP body (the middleware would pass plaintext through).
func ehbpOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(ehbpproto.EncapsulatedKeyHeader) == "" || r.ContentLength == 0 {
			fail(w, 400, "encrypted body required (EHBP)")
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
		next.ServeHTTP(w, r)
	})
}

func (s *server) secretsKey(w http.ResponseWriter, r *http.Request) {
	io.Copy(io.Discard, io.LimitReader(r.Body, 4<<10))
	g := s.secretsGW()
	if g == nil {
		fail(w, 503, "unavailable")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	a := g.Secrets(ctx, &vault.SecretsCall{Op: "key"})
	if a.Error != "" || a.Key == "" {
		fail(w, 503, "unavailable")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, map[string]string{"key": a.Key})
}

// secretsCodes are a refused push's codes (vault/secrets.go's errors).
var secretsCodes = map[string]struct {
	status int
	code   string
}{
	vault.ErrSecretsOff.Error():    {503, "secrets_off"},
	vault.ErrSecretsSig.Error():    {403, "bad_signature"},
	vault.ErrSecretsStale.Error():  {409, "stale_key"},
	vault.ErrSecretsTime.Error():   {400, "bad_time"},
	vault.ErrSecretsSealed.Error(): {400, "bad_sealed"},
	vault.ErrBadRequest.Error():    {400, "bad_request"},
}

func (s *server) secretsPut(w http.ResponseWriter, r *http.Request) {
	var p vault.SecretsPush
	body, err := io.ReadAll(io.LimitReader(r.Body, 64<<10))
	if err == nil {
		err = jsonv2.Unmarshal(body, &p, jsonv2.RejectUnknownMembers(true))
	}
	if err != nil {
		fail(w, 400, "bad_request")
		return
	}
	g := s.secretsGW()
	if g == nil {
		fail(w, 503, "unavailable")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	a := g.Secrets(ctx, &vault.SecretsCall{Op: "put", Push: &p})
	if a.Error != "" {
		c, ok := secretsCodes[a.Error]
		if !ok {
			c.status, c.code = 503, "unavailable"
		}
		fail(w, c.status, c.code)
		return
	}
	s.push.set(a.Secrets)
	if !s.push.ready.Load() {
		fail(w, 400, "bad_sealed")
		return
	}
	writeJSON(w, 200, map[string]any{"names": a.Secrets.Names})
}

// watchSecrets keeps agentd's view of the push in step with vaultd's: an agentd that restarted finds the keys
// vaultd still holds, and a vaultd that restarted (its keys gone) puts agentd back to "starting".
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
			s.push.set(a.Secrets)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(every):
		}
	}
}

// offRoute is a route family this VM refuses with a code (the quick path: schedules and email wait for sealed state
// under the Tacy key service, the keys plan Stages C and D).
type offRoute struct {
	prefix, code, detail string
}

// quickPathOff are the routes the memory-only VM refuses.
var quickPathOff = []offRoute{
	{"/schedules/", "schedules_off", "scheduled tasks are off until the Tacy key service keeps their state"},
	{"/spaces/reseal", "schedules_off", "scheduled tasks are off until the Tacy key service keeps their state"},
	{"/connections/", "connections_off", "email connections are off until the Tacy key service keeps them"},
}

// gate answers before any route: 503 {"error":"starting"} while the keys haven't been pushed (when s.needPush), and
// the off routes' codes. What needs no key (attestation, health, the push itself, signed controls) always passes.
func (s *server) gate(next http.Handler, off []offRoute) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		for _, o := range off {
			if strings.HasPrefix(p, o.prefix) {
				failDetail(w, 503, o.code, o.detail)
				return
			}
		}
		if s.needPush && !s.push.ready.Load() && !keyless(p) {
			w.Header().Set("Retry-After", "2")
			failDetail(w, 503, "starting", "the agent VM is waiting for its keys")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// keyless: routes that work before the push.
func keyless(p string) bool {
	switch p {
	case "/", "/attest", "/health", ehbpproto.KeysPath, "/safety", "/keylog":
		return true
	}
	return strings.HasPrefix(p, "/secrets")
}
