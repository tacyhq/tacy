// Package glass is the break-glass relay of the split key (package split; the keys plan §11.3),
// manual and emergency only. Not part of the VM.
package glass

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"time"

	"github.com/tacyhq/tacy/kms"
	"github.com/tacyhq/tacy/kms/client"
	"github.com/tacyhq/tacy/kms/split"
	"github.com/tacyhq/tacy/safety"
)

// The relay: the VM can't reach the admin's laptop, so it asks the relay at the policy's BreakGlass
// URL, and the admin's kmsctl break-glass, attached to the relay, answers. The relay is a mailbox: it sees the
// VM's quote and the sealed reply, never M (sealed to the VM's quote-bound key). Relay is the reference
// implementation (Go: tests and local runs); the holders Worker serves the same protocol.
//
//	VM side (what Config.BreakGlass reaches):
//	  GET  /v1/challenge, POST /v1/unlock   forwarded to the attached kmsctl; 503 when none is attached or it
//	                                        doesn't answer within RelayWait
//	admin side:
//	  POST /relay/attach   safety.Envelope (KindBreakGlassAttach, the admin keys) -> RelaySession
//	  GET  /relay/next?session=S            -> RelayRequest (id "" when none came within RelayWait)
//	  POST /relay/reply?session=S&id=I      RelayResponse -> {}
//
// Attaching needs the admin's admin signature (a fresh BreakGlassAttach for this KMS id), so no one else can take
// the VM's requests; anyone who could would still get nothing but a quote.

// KindBreakGlassAttach is the admin-signed document kmsctl attaches with.
const KindBreakGlassAttach = "kms-break-glass-attach"

// RelayWait is how long either side waits for the other.
const RelayWait = 25 * time.Second

// BreakGlassAttach is the attach document: the KMS id and when it was signed (at most split.MaxClockSkew ahead, at most
// 5 minutes old).
type BreakGlassAttach struct {
	KMSID    string    `json:"kms_id"`
	IssuedAt time.Time `json:"issued_at"`
}

// RelaySession is POST /relay/attach's answer.
type RelaySession struct {
	Session string `json:"session"`
}

// RelayRequest is one VM request handed to the admin's kmsctl.
type RelayRequest struct {
	ID     string `json:"id"`
	Method string `json:"method"`
	Path   string `json:"path"`
	Body   []byte `json:"body,omitempty"`
}

// RelayResponse is kmsctl's answer to one RelayRequest.
type RelayResponse struct {
	Status int    `json:"status"`
	Body   []byte `json:"body,omitempty"`
}

// Relay is the reference break-glass relay.
type Relay struct {
	Admin kms.AdminKeys
	KMSID string
	Now   func() time.Time
	Wait  time.Duration // 0: RelayWait

	mu      sync.Mutex
	session string
	queue   chan *pending
	waiting map[string]*pending
}

type pending struct {
	req  RelayRequest
	done chan RelayResponse
}

func (r *Relay) init() {
	if r.queue == nil {
		r.queue, r.waiting = make(chan *pending, 8), map[string]*pending{}
	}
	if r.Now == nil {
		r.Now = time.Now
	}
	if r.Wait == 0 {
		r.Wait = RelayWait
	}
}

func relayErr(w http.ResponseWriter, status int, reason string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(kms.Error{Error: reason})
}

// ServeHTTP implements the protocol above.
func (r *Relay) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	r.mu.Lock()
	r.init()
	r.mu.Unlock()
	body, err := io.ReadAll(io.LimitReader(req.Body, split.MaxBody+1))
	if err != nil || len(body) > split.MaxBody {
		relayErr(w, http.StatusRequestEntityTooLarge, "request too large")
		return
	}
	switch {
	case req.Method == http.MethodGet && req.URL.Path == "/v1/challenge", req.Method == http.MethodPost && req.URL.Path == "/v1/unlock":
		r.forward(w, req, body)
	case req.Method == http.MethodPost && req.URL.Path == "/relay/attach":
		r.attach(w, body)
	case req.Method == http.MethodGet && req.URL.Path == "/relay/next":
		r.next(w, req)
	case req.Method == http.MethodPost && req.URL.Path == "/relay/reply":
		r.reply(w, req, body)
	default:
		relayErr(w, http.StatusNotFound, "not found")
	}
}

func (r *Relay) forward(w http.ResponseWriter, req *http.Request, body []byte) {
	r.mu.Lock()
	attached := r.session != ""
	r.mu.Unlock()
	if !attached {
		relayErr(w, http.StatusServiceUnavailable, "no break-glass session (the admin isn't attached)")
		return
	}
	id := make([]byte, 16)
	rand.Read(id)
	p := &pending{req: RelayRequest{ID: hex.EncodeToString(id), Method: req.Method, Path: req.URL.Path, Body: body}, done: make(chan RelayResponse, 1)}
	r.mu.Lock()
	r.waiting[p.req.ID] = p
	r.mu.Unlock()
	defer func() { r.mu.Lock(); delete(r.waiting, p.req.ID); r.mu.Unlock() }()
	t := time.NewTimer(r.Wait)
	defer t.Stop()
	select {
	case r.queue <- p:
	case <-t.C:
		relayErr(w, http.StatusServiceUnavailable, "the break-glass session is busy")
		return
	}
	select {
	case resp := <-p.done:
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(resp.Status)
		w.Write(resp.Body)
	case <-t.C:
		relayErr(w, http.StatusServiceUnavailable, "the admin didn't answer")
	case <-req.Context().Done():
	}
}

func (r *Relay) attach(w http.ResponseWriter, body []byte) {
	var env safety.Envelope
	var doc BreakGlassAttach
	if err := kms.Strict(body, &env); err != nil {
		relayErr(w, http.StatusBadRequest, "attach isn't an envelope")
		return
	}
	if err := r.Admin.Open(&env, KindBreakGlassAttach, &doc); err != nil {
		relayErr(w, http.StatusForbidden, err.Error())
		return
	}
	now := r.Now()
	if doc.KMSID != r.KMSID || doc.IssuedAt.After(now.Add(split.MaxClockSkew)) || now.Sub(doc.IssuedAt) > 5*time.Minute {
		relayErr(w, http.StatusForbidden, "attach is for another KMS id or not fresh")
		return
	}
	s := make([]byte, 32)
	rand.Read(s)
	r.mu.Lock()
	r.session = hex.EncodeToString(s)
	r.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(RelaySession{Session: hex.EncodeToString(s)})
}

func (r *Relay) authed(req *http.Request) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.session != "" && req.URL.Query().Get("session") == r.session
}

func (r *Relay) next(w http.ResponseWriter, req *http.Request) {
	if !r.authed(req) {
		relayErr(w, http.StatusForbidden, "not the attached session")
		return
	}
	t := time.NewTimer(r.Wait)
	defer t.Stop()
	select {
	case p := <-r.queue:
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(p.req)
	case <-t.C:
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(RelayRequest{})
	case <-req.Context().Done():
	}
}

func (r *Relay) reply(w http.ResponseWriter, req *http.Request, body []byte) {
	if !r.authed(req) {
		relayErr(w, http.StatusForbidden, "not the attached session")
		return
	}
	var resp RelayResponse
	if err := kms.Strict(body, &resp); err != nil || resp.Status < 200 || resp.Status > 599 {
		relayErr(w, http.StatusBadRequest, "reply isn't a relay response")
		return
	}
	r.mu.Lock()
	p := r.waiting[req.URL.Query().Get("id")]
	r.mu.Unlock()
	if p != nil {
		select {
		case p.done <- resp:
		default:
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte("{}"))
}

// ServeRelay is kmsctl break-glass's loop: attach with the signed attach document, then hand every VM request to h
// (a break-glass holder's handler) and send its answer back, until ctx ends or stop says so (after each answer).
func ServeRelay(ctx context.Context, relay client.Transport, attach json.RawMessage, h http.Handler, stop func() bool) error {
	b, err := relay.Do(ctx, http.MethodPost, "/relay/attach", attach)
	if err != nil {
		return fmt.Errorf("break-glass: attach: %w", err)
	}
	var s RelaySession
	if err := kms.Strict(b, &s); err != nil || s.Session == "" {
		return errors.New("break-glass: attach answer isn't a session")
	}
	for ctx.Err() == nil {
		b, err := relay.Do(ctx, http.MethodGet, "/relay/next?session="+s.Session, nil)
		if err != nil {
			return fmt.Errorf("break-glass: next: %w", err)
		}
		var rq RelayRequest
		if err := kms.Strict(b, &rq); err != nil {
			return fmt.Errorf("break-glass: request: %w", err)
		}
		if rq.ID == "" {
			continue // nothing within RelayWait
		}
		hr := httptest.NewRequestWithContext(ctx, rq.Method, "http://holder"+rq.Path, bytes.NewReader(rq.Body))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, hr)
		out, _ := json.Marshal(RelayResponse{Status: rec.Code, Body: rec.Body.Bytes()})
		if _, err := relay.Do(ctx, http.MethodPost, "/relay/reply?session="+s.Session+"&id="+rq.ID, out); err != nil {
			return fmt.Errorf("break-glass: reply: %w", err)
		}
		if stop != nil && stop() {
			return nil
		}
	}
	return ctx.Err()
}
