package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"log"
	"net/http"
	"strconv"
	"time"

	ehbpidentity "github.com/tinfoilsh/encrypted-http-body-protocol/identity"

	"github.com/tacyhq/tacy/guard"
	"github.com/tacyhq/tacy/identity"
	"github.com/tacyhq/tacy/runauth"
	"github.com/tacyhq/tacy/trigger"
	"github.com/tacyhq/tacy/vault"
)

// Settings → Connections (v0.19.0; the contract is the connections contract next to this package): a person connects their
// own email account for the mail tools. Every call carries the where and who of a schedule call (runauth), under its
// own label, its nonce used once and the space's seal key pinned. agentd checks who asks and passes the call on to
// gatewayd (guard.Connections): the box with the account and its app password is sealed in the browser to the
// vault's key and stays sealed here; only vaultd opens it, and gatewayd tests a login with it before it is kept.
//
//	POST /connections/list    {where and who} -> {seal_key, connections}
//	POST /connections/test    {where and who, connection, sealed} -> {connection, state: "tested", read_only, provider, address, host, port, security, folders}
//	POST /connections/put     -> 410 per_request (v1: the VM keeps no login; the person's app keeps it, the v1 design §5)
//	POST /connections/remove  {where and who, connection} -> {connection, state}
//	POST /connections/forget  {forgets: [{space, identity, signed_at, sig}]} -> {done: ["s_…"], refused}  (the relay's)

// connectionRoutes serves the routes on mux behind EHBP with id, and the relay's forget (plaintext in its envelope).
func (s *server) connectionRoutes(mux *http.ServeMux, id *ehbpidentity.Identity) {
	for path, h := range map[string]http.HandlerFunc{"list": s.connList, "put": s.connPut, "test": s.connTest, "remove": s.connRemove} {
		mux.Handle("POST /connections/"+path, s.taskGuard(false, false, id.Middleware()(h)))
	}
	mux.HandleFunc("POST /connections/forget", s.connForget)
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
	"per_request": 410, "bad_credential": 400, "busy": 429,
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

// connPut: POST /connections/put is gone in v1 (the v1 design §5.1): nothing is kept on the VM, so it answers
// 410 per_request without reading the box. The person's app keeps the login (mail-login/v1) and sends it with each
// task; Settings tests it with /connections/test.
func (s *server) connPut(w http.ResponseWriter, r *http.Request) {
	failDetail(w, 410, "per_request", "the VM keeps no mail login: test it with /connections/test, keep it in the app, send it with each task")
}

// connTest: POST /connections/test. The box is opened by vaultd, a test login made with it, and dropped whatever
// the outcome; the answer is put's without anything kept (state "tested", no connected_at).
func (s *server) connTest(w http.ResponseWriter, r *http.Request) {
	var req connPutRequest
	if !readCall(w, r, 16<<10, &req) {
		return
	}
	if req.Connection != vault.ConnEmail || len(req.Sealed.Enc) == 0 || len(req.Sealed.CT) == 0 || len(req.Sealed.CT) > 4<<10 {
		failDetail(w, 400, "bad_request", "connection must be email, with its sealed box")
		return
	}
	who, ok := s.callWho(w, runauth.ConnTestLabel, &req.Where, req.Connection, BoxDigest(req.Sealed))
	if !ok {
		return
	}
	c := s.conns()
	if c == nil {
		fail(w, 503, "unavailable")
		return
	}
	// The identity holds the space (as at a schedule's install): what a deleted account's forget is checked against.
	if err := s.holders.PutHolder(trigger.Holder{Space: who.Space, Identity: who.Identity, Key: who.Key, Seal: who.Seal,
		At: time.Now().UTC()}); err != nil {
		fail(w, 500, "store_unavailable")
		return
	}
	sealed := req.Sealed
	res := c.Conn(r.Context(), &guard.ConnRequest{Op: "test", Space: who.Space, Connection: req.Connection, Sealed: &sealed})
	if res.Error != nil {
		log.Printf("connections: a test was refused: %s", res.Error.Code) // no ids
		connFail(w, res.Error)
		return
	}
	if res.Info == nil {
		fail(w, 503, "unavailable")
		return
	}
	v := connViewOf(*res.Info)
	log.Printf("connections: an email account was tested") // no ids, no address
	writeJSON(w, 200, map[string]any{"connection": v.Connection, "state": "tested", "read_only": true, "provider": v.Provider,
		"address": v.Address, "host": v.Host, "port": v.Port, "security": v.Security, "folders": res.Folders})
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

// ---- account deletion: the relay's forget ------------------------------------------------------------------------

// Deleting the account (v0.21.0; the connections contract "Account deletion"). After it nothing can sign a remove,
// and a connection kept in the sealed state would stay usable on the VM with no expiry. So the browser signs one
// forget before the account goes, with the space holder's identity key (no VM call: it may be stopped, or agents or
// email connections switched off), and the Worker keeps it, written in the deletion's own batch, until the VM took
// it: its cron hands it over in its signed envelope every minute the VM is up (with the VM off, in the next boot's
// first minute). As with a collected scheduled result (handoff.go), the delete is the person's (the keys plan §3.4): it is
// checked here against the identity key the space's holder proved (recorded at a connect or a schedule's install),
// never taken on the relay's word. A relay can withhold a forget, not make one up.
//
// The signature: Ed25519 over "tacy/v2/connection-forget\n<space>\n<identity>\n<signed_at>" (decimal ms). It removes
// every connection of the space connected before signed_at plus a day (a slow browser clock still covers the one it
// means; a forget kept from a deletion that didn't go through can't remove a connection made more than a day later).
// A space with no connection is done without a check: nothing is removed, and the relay learns nothing it doesn't see
// already (it relays the connect calls).

const (
	connForgetLabel = "tacy/v2/connection-forget"
	connForgetSlack = 24 * time.Hour
	maxConnForgets  = 50
)

// connForgetMessage is what the space holder's identity key signs for a forget.
func connForgetMessage(space, ident string, signedAt int64) []byte {
	return []byte(connForgetLabel + "\n" + space + "\n" + ident + "\n" + strconv.FormatInt(signedAt, 10))
}

type connForgetEntry struct {
	Space    string `json:"space"`
	Identity string `json:"identity"`
	SignedAt int64  `json:"signed_at"`
	Sig      []byte `json:"sig"`
}

type connForgetRequest struct {
	Forgets []connForgetEntry `json:"forgets"`
}

// connForget: POST /connections/forget, the relay's cron. done: the spaces with no connection from before their
// forget any more (the relay drops those); the rest it sends again later (refused: a signature that isn't by a holder
// of the space).
func (s *server) connForget(w http.ResponseWriter, r *http.Request) {
	if !s.authorized(r) {
		fail(w, 401, "unauthorized")
		return
	}
	var req connForgetRequest
	if !readCall(w, r, 64<<10, &req) {
		return
	}
	bad := len(req.Forgets) > maxConnForgets
	for _, f := range req.Forgets {
		bad = bad || !validSpace(f.Space) || !runauth.IsID(f.Identity, "i") || f.SignedAt <= 0 || len(f.Sig) != ed25519.SignatureSize
	}
	if bad {
		failDetail(w, 400, "bad_request", `body must be {"forgets": [{"space", "identity", "signed_at", "sig"}]}, at most 50`)
		return
	}
	c := s.conns()
	if c == nil || s.holders == nil {
		fail(w, 503, "unavailable")
		return
	}
	done, refused := []string{}, 0
	for _, f := range req.Forgets {
		res := c.Conn(r.Context(), &guard.ConnRequest{Op: "list", Space: f.Space})
		if res.Error != nil {
			continue // asked again on the relay's next call
		}
		if len(res.Connections) == 0 {
			done = append(done, f.Space)
			continue
		}
		h, err := s.holders.Holder(f.Space, f.Identity)
		if err != nil {
			continue
		}
		var key ed25519.PublicKey
		if h != nil {
			key, _ = identity.ParseKey(h.Key)
		}
		if key == nil || !ed25519.Verify(key, connForgetMessage(f.Space, f.Identity, f.SignedAt), f.Sig) {
			refused++
			continue
		}
		until := time.UnixMilli(f.SignedAt).Add(connForgetSlack)
		ok := true
		for _, ci := range res.Connections {
			if ci.ConnectedAt.After(until) {
				continue
			}
			if rr := c.Conn(r.Context(), &guard.ConnRequest{Op: "remove", Space: f.Space, Connection: ci.Connection}); rr.Error != nil {
				ok = false
			}
		}
		if ok {
			done = append(done, f.Space)
		}
	}
	if len(req.Forgets) > 0 {
		log.Printf("connections: %d forgets of deleted accounts, %d done, %d refused", len(req.Forgets), len(done), refused) // no ids
	}
	writeJSON(w, 200, map[string]any{"done": done, "refused": refused})
}
