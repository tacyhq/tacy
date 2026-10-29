package main

import (
	"crypto/sha256"
	"encoding/hex"
	"log"
	"net/http"
	"time"

	ehbpidentity "github.com/tinfoilsh/encrypted-http-body-protocol/identity"

	"github.com/tacyhq/tacy/guard"
	"github.com/tacyhq/tacy/runauth"
	"github.com/tacyhq/tacy/vault"
)

// Settings → Connections (v0.19.0; the contract is the connections contract next to this package): a person connects their
// own email account for the mail tools. Every call carries the where and who of a schedule call (runauth), under its
// own label, its nonce used once and the space's seal key pinned. agentd checks who asks and passes the call on to
// gatewayd (guard.Connections): the box with the account and its app password is sealed in the browser to the
// vault's key and stays sealed here; only vaultd opens it, and gatewayd tests a login with it before it is kept.
//
//	POST /connections/list    {where and who} -> {seal_key, connections}
//	POST /connections/put     {where and who, connection, sealed} -> {connection, state, read_only, provider, address, host, port, security, folders, connected_at}
//	POST /connections/remove  {where and who, connection} -> {connection, state}

// connectionRoutes serves the routes on mux behind EHBP with id.
func (s *server) connectionRoutes(mux *http.ServeMux, id *ehbpidentity.Identity) {
	for path, h := range map[string]http.HandlerFunc{"list": s.connList, "put": s.connPut, "remove": s.connRemove} {
		mux.Handle("POST /connections/"+path, s.taskGuard(false, false, id.Middleware()(h)))
	}
}

// connView is a connection as the browser gets it: never a password.
type connView struct {
	Connection  string    `json:"connection"`
	Kind        string    `json:"kind"`
	Provider    string    `json:"provider"`
	Address     string    `json:"address"`
	Host        string    `json:"host"`
	Port        int       `json:"port"`
	Security    string    `json:"security"`
	ReadOnly    bool      `json:"read_only"`
	ConnectedAt time.Time `json:"connected_at,omitzero"`
}

func connViewOf(c vault.ConnInfo) connView {
	return connView{Connection: c.Connection, Kind: c.Kind, Provider: c.Provider, Address: c.Address, Host: c.Host, Port: c.Port,
		Security: c.Security, ReadOnly: true, ConnectedAt: c.ConnectedAt}
}

// connStatus is the HTTP status of a refused call's code (the connections contract).
var connStatus = map[string]int{
	"login_failed": 401, "app_password_required": 401, "app_passwords_blocked": 401,
	"unreachable": 502, "tls_failed": 502, "not_imap": 502,
	"policy_denied": 403, "stale_key": 409, "bad_sealed": 400, "bad_request": 400, "unavailable": 503,
}

func connFail(w http.ResponseWriter, e *guard.ConnError) {
	st, ok := connStatus[e.Code]
	if !ok {
		st = 503
	}
	failDetail(w, st, e.Code, e.Detail)
}

// conns is the guard's Settings side: gatewayd's (the CVM) or this process's guard.
func (s *server) conns() guard.Connections {
	if c, ok := s.gw.(guard.Connections); ok {
		return c
	}
	return nil
}

func (s *server) connList(w http.ResponseWriter, r *http.Request) {
	var req runauth.Where
	if !readCall(w, r, 8<<10, &req) {
		return
	}
	who, ok := s.callWho(w, runauth.ConnListLabel, &req)
	if !ok {
		return
	}
	c := s.conns()
	if c == nil {
		fail(w, 503, "unavailable")
		return
	}
	res := c.Conn(r.Context(), &guard.ConnRequest{Op: "list", Space: who.Space})
	if res.Error != nil {
		connFail(w, res.Error)
		return
	}
	out := []connView{}
	for _, ci := range res.Connections {
		out = append(out, connViewOf(ci))
	}
	writeJSON(w, 200, map[string]any{"seal_key": res.SealKey, "connections": out})
}

type connPutRequest struct {
	runauth.Where
	Connection string       `json:"connection"`
	Sealed     vault.Sealed `json:"sealed"`
}

// BoxDigest is a sealed box's item in a put's signature: hex(SHA-256(enc ‖ ct)).
func BoxDigest(s vault.Sealed) string {
	h := sha256.New()
	h.Write(s.Enc)
	h.Write(s.CT)
	return hex.EncodeToString(h.Sum(nil))
}

func (s *server) connPut(w http.ResponseWriter, r *http.Request) {
	var req connPutRequest
	if !readCall(w, r, 16<<10, &req) {
		return
	}
	if req.Connection != vault.ConnEmail || len(req.Sealed.Enc) == 0 || len(req.Sealed.CT) == 0 || len(req.Sealed.CT) > 4<<10 {
		failDetail(w, 400, "bad_request", "connection must be email, with its sealed box")
		return
	}
	who, ok := s.callWho(w, runauth.ConnPutLabel, &req.Where, req.Connection, BoxDigest(req.Sealed))
	if !ok {
		return
	}
	c := s.conns()
	if c == nil {
		fail(w, 503, "unavailable")
		return
	}
	sealed := req.Sealed
	res := c.Conn(r.Context(), &guard.ConnRequest{Op: "put", Space: who.Space, Connection: req.Connection, Sealed: &sealed})
	if res.Error != nil {
		log.Printf("connections: a connect was refused: %s", res.Error.Code) // no ids
		connFail(w, res.Error)
		return
	}
	if res.Info == nil {
		fail(w, 503, "unavailable")
		return
	}
	v := connViewOf(*res.Info)
	log.Printf("connections: an email account was connected") // no ids, no address
	writeJSON(w, 200, map[string]any{"connection": v.Connection, "state": "connected", "read_only": true, "provider": v.Provider,
		"address": v.Address, "host": v.Host, "port": v.Port, "security": v.Security, "folders": res.Folders, "connected_at": v.ConnectedAt})
}

type connRemoveRequest struct {
	runauth.Where
	Connection string `json:"connection"`
}

func (s *server) connRemove(w http.ResponseWriter, r *http.Request) {
	var req connRemoveRequest
	if !readCall(w, r, 8<<10, &req) {
		return
	}
	if req.Connection != vault.ConnEmail {
		failDetail(w, 400, "bad_request", "connection must be email")
		return
	}
	who, ok := s.callWho(w, runauth.ConnRemoveLabel, &req.Where, req.Connection)
	if !ok {
		return
	}
	c := s.conns()
	if c == nil {
		fail(w, 503, "unavailable")
		return
	}
	if res := c.Conn(r.Context(), &guard.ConnRequest{Op: "remove", Space: who.Space, Connection: req.Connection}); res.Error != nil {
		connFail(w, res.Error)
		return
	}
	log.Printf("connections: an email account was disconnected")
	writeJSON(w, 200, map[string]string{"connection": req.Connection, "state": "removed"})
}
