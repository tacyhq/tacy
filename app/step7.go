package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"io"
	"log"
	"net/http"
	"time"

	jsonv2 "encoding/json/v2"

	ehbpidentity "github.com/tinfoilsh/encrypted-http-body-protocol/identity"

	"github.com/tacyhq/tacy/approval"
	"github.com/tacyhq/tacy/guard"
	"github.com/tacyhq/tacy/identity"
	"github.com/tacyhq/tacy/proto"
	"github.com/tacyhq/tacy/runauth"
	"github.com/tacyhq/tacy/safety"
	"github.com/tacyhq/tacy/trigger"
)

// Triggers and approvals (docs/27 sections 3 and 4): approve before send and authenticated triggers, agentd's routes and the
// scheduler. Each call is a POST with an EHBP-encrypted body, like the task calls; what authorizes it is a person's
// signature inside, checked here against the identity directory (keys v2). Until keys v2's key log reaches this VM
// (slices 5 and 6), no directory is set and every one of these answers identity_unavailable: nothing can be
// approved, installed or triggered (fail closed).
//
//	POST /approvals/list  {identity, space, signed_at, nonce, sig} -> {approvals: [proto.Approval]}: what waits for
//	                      this approver. sig: Ed25519 by the identity over "tacy-approvals-list/v1", this boot's
//	                      EHBP key (hex), identity, space, signed_at (RFC 3339) and nonce, NUL-separated; within 5
//	                      minutes of the VM's clock. The answer is EHBP-encrypted to the asking tab only.
//	POST /approvals       approval.Submission -> {state}: approve or deny one held effect (guard.Approvals.Answer).
//	                      404 no_such_approval (decided, expired, unknown), 403 bad_approval.
//	POST /triggers        a signed tacy.agent/v1 envelope -> {agent, version, digest, triggers}: install or update a
//	                      definition on a firm's VM (its key log the directory: later). On the shared chat VM a
//	                      personal space's schedule is installed with its space proof instead (POST /schedules/install).
//	                      definition (trigger.Engine.Install). 403 with the reason.
//	POST /triggers/event  a signed tacy.event/v1 envelope -> {task, existed}: an inbound event (trigger.Engine.Event).
//	                      409 replayed, 403 refused, 503 clock not trusted, 429 too many open tasks for the agent.

// ReleaseRP is the relying party a passkey approval must be for: the release pins the chat's origin and rpId.
var ReleaseRP = approval.RP{ID: "tacy.io", Origins: []string{"https://chat.tacy.io"}}

// listLabel prefixes what an approvals list request's signature covers.
const listLabel = "tacy-approvals-list/v1"

// listRequest is POST /approvals/list's body.
type listRequest struct {
	Identity string    `json:"identity"`
	Space    string    `json:"space"`
	SignedAt time.Time `json:"signed_at"`
	Nonce    string    `json:"nonce"`
	Sig      []byte    `json:"sig"`
}

func listSigned(vmKey string, r *listRequest) []byte {
	b := []byte(listLabel)
	for _, f := range []string{vmKey, r.Identity, r.Space, r.SignedAt.UTC().Format(time.RFC3339), r.Nonce} {
		b = append(append(b, 0), f...)
	}
	return b
}

// step7Routes serves the routes on mux behind EHBP with id.
func (s *server) step7Routes(mux *http.ServeMux, id *ehbpidentity.Identity) {
	mux.Handle("POST /approvals/list", s.taskGuard(false, false, id.Middleware()(http.HandlerFunc(s.approvalsList))))
	mux.Handle("POST /approvals", s.taskGuard(false, false, id.Middleware()(http.HandlerFunc(s.approvalsAnswer))))
	mux.Handle("POST /triggers", s.taskGuard(false, false, id.Middleware()(http.HandlerFunc(s.triggersInstall))))
	mux.Handle("POST /triggers/event", s.taskGuard(false, false, id.Middleware()(http.HandlerFunc(s.triggersEvent))))
}

func readStrict(w http.ResponseWriter, r *http.Request, max int64, v any) bool {
	body, err := io.ReadAll(io.LimitReader(r.Body, max))
	if err == nil {
		err = jsonv2.Unmarshal(body, v, jsonv2.RejectUnknownMembers(true))
	}
	if err != nil {
		fail(w, 400, "bad body")
		return false
	}
	return true
}

func (s *server) approvalsList(w http.ResponseWriter, r *http.Request) {
	if s.dir == nil || s.approvals == nil {
		fail(w, 503, "identity_unavailable")
		return
	}
	var req listRequest
	if !readStrict(w, r, 4096, &req) {
		return
	}
	now := time.Now()
	if !identity.ValidID("i", req.Identity) || !identity.ValidID("s", req.Space) || len(req.Nonce) < 16 || len(req.Nonce) > 64 ||
		now.Sub(req.SignedAt) > 5*time.Minute || req.SignedAt.Sub(now) > 5*time.Minute {
		fail(w, 400, "bad list request")
		return
	}
	k, err := s.dir.Key(s.safety.Firm(), req.Space, req.Identity)
	if err != nil || !ed25519.Verify(k, listSigned(s.id.MarshalPublicKeyHex(), &req), req.Sig) {
		fail(w, 403, "bad_signature")
		return
	}
	list := s.approvals.List(req.Identity, req.Space)
	if list == nil {
		list = []proto.Approval{}
	}
	writeJSON(w, 200, map[string]any{"approvals": list})
}

func (s *server) approvalsAnswer(w http.ResponseWriter, r *http.Request) {
	if s.dir == nil || s.approvals == nil {
		fail(w, 503, "identity_unavailable")
		return
	}
	var sub approval.Submission
	if !readStrict(w, r, 32<<10, &sub) {
		return
	}
	state, err := s.approvals.Answer(&sub)
	switch {
	case errors.Is(err, guard.ErrNoApproval):
		fail(w, 404, "no_such_approval")
	case err != nil:
		fail(w, 403, "bad_approval")
	default:
		writeJSON(w, 200, map[string]string{"state": state})
	}
}

func (s *server) triggersInstall(w http.ResponseWriter, r *http.Request) {
	if s.dir == nil || s.triggers == nil {
		fail(w, 503, "identity_unavailable")
		return
	}
	if s.personal() { // a personal space's schedule comes with its space proof and rules (schedules.go)
		fail(w, 404, "use POST /schedules/install")
		return
	}
	var env safety.Envelope
	if !readStrict(w, r, 2*trigger.MaxDefinition, &env) {
		return
	}
	in, err := s.triggers.Install(env)
	if err != nil {
		fail(w, 403, err.Error())
		return
	}
	var ids []string
	for _, t := range in.Def.Triggers {
		ids = append(ids, t.ID)
	}
	writeJSON(w, 200, map[string]any{"agent": in.Def.Agent, "version": in.Def.Version, "digest": in.Digest, "triggers": ids})
}

func (s *server) triggersEvent(w http.ResponseWriter, r *http.Request) {
	if s.dir == nil || s.triggers == nil {
		fail(w, 503, "identity_unavailable")
		return
	}
	var env safety.Envelope
	if !readStrict(w, r, 2*trigger.MaxEvent, &env) {
		return
	}
	f, err := s.triggers.Event(env)
	switch {
	case errors.Is(err, trigger.ErrReplay):
		fail(w, 409, "replayed")
		return
	case errors.Is(err, trigger.ErrClock):
		fail(w, 503, "clock_untrusted")
		return
	case err != nil:
		fail(w, 403, err.Error())
		return
	}
	existed, err := s.tasks().StartTriggered(r.Context(), f, s.safety.Firm())
	switch {
	case errors.Is(err, guard.ErrTooMany): // not recorded: the sender may deliver it again later
		fail(w, 429, "too_many_tasks")
	case err != nil:
		fail(w, 500, "task_not_started")
	default:
		if err := s.triggers.Delivered(f); err != nil {
			log.Printf("triggers: delivery not recorded: %v", err) // the derived task id still makes a repeat find it
		}
		writeJSON(w, 200, map[string]any{"task": f.Task, "existed": existed})
	}
}

// runTriggers fires due schedules and stops unattended tasks whose sponsor's authority ended, every interval, until
// ctx ends (docs/27 section 3). With no directory it cancels any unattended task left open and returns.
func (s *server) runTriggers(ctx context.Context, every time.Duration) {
	if s.dir == nil || s.triggers == nil {
		// Nobody's authority can be checked: unattended tasks a previous process left (resumed from the queue)
		// stop, as for a sponsor gone.
		for id := range s.tasks().Triggered() {
			s.rt.Cancel(id, "sponsor_gone")
		}
		return
	}
	for {
		s.triggerTick(ctx)
		select {
		case <-ctx.Done():
			return
		case <-time.After(every):
		}
	}
}

// triggerTick is one pass: due schedule slots start their tasks (a derived id: a repeat finds the first), each
// recorded as fired once started, found, or skipped for the agent's cap; an open unattended task whose sponsor was
// revoked, left the space or whose sponsorship ended is cancelled ("sponsor_gone").
func (s *server) triggerTick(ctx context.Context) {
	fires, err := s.triggers.Due()
	if err != nil && !errors.Is(err, trigger.ErrClock) {
		log.Printf("triggers: %v", err)
	}
	for _, f := range fires {
		_, err := s.tasks().StartTriggered(ctx, f, s.safety.Firm())
		if err != nil && !errors.Is(err, guard.ErrTooMany) {
			log.Printf("triggers: a scheduled task wasn't started (trigger %s): %v", f.Trigger.ID, err)
			continue
		}
		if err := s.triggers.Fired(f); err != nil {
			log.Printf("triggers: %v", err)
		}
	}
	for id, o := range s.tasks().Triggered() {
		if err := s.triggers.Sponsored(o.Space, o.Sponsor, o.NotAfter); err != nil {
			s.rt.Cancel(id, "sponsor_gone")
		}
	}
	s.triggers.Prune()
}

// memSide is the side store in memory (local runs without a state directory).
type memSide struct {
	*approvalMem
	*triggerMem
	*trigger.MemHolders
	*trigger.MemResults
	*trigger.MemMemory
	*runauth.MemPins
}

type (
	approvalMem = approval.MemStore
	triggerMem  = trigger.MemStore
)
