package main

import (
	"cmp"
	"context"
	"encoding/json"
	jsonv2 "encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	ehbpidentity "github.com/tinfoilsh/encrypted-http-body-protocol/identity"
	ehbpproto "github.com/tinfoilsh/encrypted-http-body-protocol/protocol"

	"github.com/tacyhq/tacy/guard"
	"github.com/tacyhq/tacy/proto"
	"github.com/tacyhq/tacy/safety"
)

// The task API (docs/27 section 1, slice 1). A task no longer belongs to the tab that started it: it runs whether or
// not anyone follows it, survives an agentd restart, and its starter can follow it from any event, see its state and
// cancel it. Every call is a POST with an EHBP-encrypted body, like POST /run: EHBP leaves a request without a body
// (and its response) unencrypted, and the task id goes in the encrypted body, so the relay sees only which call it
// was. Same bearer token (cost) and X-Agent-User tag (whose task, required) as /run; only the starter's tag sees a
// task, and status, events and cancel also need a MAC with the run's secret (guard.TaskMAC), which only the tab that
// started the task has (it sent it inside the encrypted start): the relay sets the tag but can't make the MAC.
//
//	POST /tasks          {model, messages, run_secret, ..., key?} -> {task, state, existing}. key makes the start
//	                     once-only: the same user and key always name the same task (a retry finds it; nothing runs
//	                     twice). X-Agent-Model as for /run. Refusals: 403 {error, code, activity?}; 429 too_many_tasks.
//	POST /tasks/status   {task, mac} -> {task, state, sub, attempt, events, held, outcome}
//	POST /tasks/events   {task, after, mac} -> SSE: "id: <seq>" and "data: <proto.Event>" per event after seq after,
//	                     as they come, then "data: [DONE]" once the task ended; reconnect with the last id seen.
//	                     At most 8 streams at once per user, 64 in all.
//	POST /tasks/cancel   {task, mac} -> {task, state}
//	POST /tasks/grant    {task, request, kind, decision, value, mac} -> {outcome}: the person's answer to a
//	                     permission prompt (guard.Prompts) of a /tasks or /run task. The MAC with the run's
//	                     secret is the authorization (only the tab that started the run has it). 404
//	                     no_such_prompt (answered, timed out or never asked), 403 bad_grant, 400 bad_value.
//
// POST /run stays as a shim over this (guard.Host.Run) until the chat moves to /tasks, then goes one release later
// (docs/27 section 8).

// taskStartRequest is POST /tasks's body: a chat request, and the start's once-only key.
type taskStartRequest struct {
	proto.RunRequest
	Key string `json:"key,omitempty"` // 1-128 printable characters
}

// taskRef names a task (POST /tasks/status, /events, /cancel), with the call's MAC (guard.TaskMAC).
type taskRef struct {
	Task  string `json:"task"`
	After int    `json:"after,omitempty"`
	MAC   string `json:"mac"`
}

// maxFollowers bounds the event streams open at once (each is a long request); maxUserFollowers those of one user
// tag, so one person (or the relay with one tag) can't take every slot.
const (
	maxFollowers     = 64
	maxUserFollowers = 8
)

// taskRoutes serves the task API on mux behind EHBP with id (the boot's key).
func (s *server) taskRoutes(mux *http.ServeMux, id *ehbpidentity.Identity) {
	mux.Handle("POST /tasks", s.taskGuard(true, true, id.Middleware()(http.HandlerFunc(s.taskStart))))
	mux.Handle("POST /tasks/status", s.taskGuard(false, true, id.Middleware()(http.HandlerFunc(s.taskStatus))))
	mux.Handle("POST /tasks/events", s.taskGuard(false, true, id.Middleware()(http.HandlerFunc(s.taskEvents))))
	mux.Handle("POST /tasks/cancel", s.taskGuard(false, true, id.Middleware()(http.HandlerFunc(s.taskCancel))))
	// A grant's MAC is its authorization; the tag is optional there, as the chat's relay sends it.
	mux.Handle("POST /tasks/grant", s.taskGuard(false, false, id.Middleware()(http.HandlerFunc(s.taskGrant))))
}

// taskGrant is behind EHBP: POST /tasks/grant. Strict JSON; the grant's MAC, kind and value are checked by
// guard.Prompts.Answer, and a prompt takes one answer.
func (s *server) taskGrant(w http.ResponseWriter, r *http.Request) {
	if s.prompts == nil {
		fail(w, 404, "no_such_prompt")
		return
	}
	var g guard.Grant
	body, err := io.ReadAll(io.LimitReader(r.Body, 16<<10))
	if err == nil {
		err = jsonv2.Unmarshal(body, &g, jsonv2.RejectUnknownMembers(true))
	}
	if err != nil {
		fail(w, 400, "body must be a JSON grant")
		return
	}
	outcome, err := s.prompts.Answer(g)
	switch {
	case errors.Is(err, guard.ErrNoPrompt):
		fail(w, 404, "no_such_prompt")
	case errors.Is(err, guard.ErrBadGrant):
		fail(w, 403, "bad_grant")
	case errors.Is(err, guard.ErrBadValue):
		fail(w, 400, "bad_value")
	case err != nil:
		fail(w, 500, "grant_unavailable")
	default:
		writeJSON(w, 200, map[string]string{"outcome": outcome})
	}
}

// tasks is the server's task host, made on first use (tests build servers without one).
func (s *server) tasks() *guard.Host {
	s.hostOnce.Do(func() {
		if s.host == nil {
			s.host = &guard.Host{RT: s.rt, GW: s.agent}
		}
		s.follows = make(chan struct{}, maxFollowers)
		s.userFollows = map[string]int{}
	})
	return s.host
}

// taskGuard is guard's checks for the task calls, before EHBP decryption: token, encrypted body, user tag (required
// when needTag); for a start, the model header. No run slot: a started task waits in the runtime's queue for the brain.
func (s *server) taskGuard(start, needTag bool, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.authorized(r) {
			fail(w, 401, "unauthorized")
			return
		}
		if r.Header.Get(ehbpproto.EncapsulatedKeyHeader) == "" || r.ContentLength == 0 {
			fail(w, 400, "encrypted body required (EHBP)")
			return
		}
		if start {
			switch m := r.Header.Get(ModelHeader); {
			case m == "":
				fail(w, 400, "model_required")
				return
			case !knownModel(m):
				fail(w, 400, "model_unknown")
				return
			}
		}
		user := r.Header.Get("X-Agent-User")
		if user != "" && !userTagRe.MatchString(user) || user == "" && needTag {
			fail(w, 400, "bad_user_tag")
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 8<<20)
		next.ServeHTTP(w, r.WithContext(withUser(r.Context(), user)))
	})
}

func validKey(k string) bool {
	if len(k) > 128 {
		return false
	}
	for _, c := range k {
		if c < 0x21 || c > 0x7e {
			return false
		}
	}
	return true
}

// taskStart is behind EHBP: POST /tasks.
func (s *server) taskStart(w http.ResponseWriter, r *http.Request) {
	var req taskStartRequest
	body, err := io.ReadAll(io.LimitReader(r.Body, 6<<20))
	if err == nil {
		err = json.Unmarshal(body, &req)
	}
	if err != nil {
		fail(w, 400, "body must be a JSON task request")
		return
	}
	if !validKey(req.Key) {
		fail(w, 400, "key must be at most 128 printable characters")
		return
	}
	if req.RunSecret == "" { // status, events and cancel need a MAC with it
		fail(w, 400, "run_secret_required")
		return
	}
	if h := r.Header.Get(ModelHeader); h != cmp.Or(req.Model, proto.DefaultModel) {
		fail(w, 400, "model_mismatch: the X-Agent-Model header doesn't match the task's model")
		return
	}
	id, existed, err := s.tasks().Start(r.Context(), guard.StartRequest{User: userFrom(r.Context()), Req: &req.RunRequest,
		Key: req.Key, Via: guard.ViaTasks})
	switch {
	case errors.Is(err, guard.ErrTooMany):
		fail(w, 429, "too_many_tasks")
		return
	case err != nil && safety.CodeOf(err) != "": // stopped, no policy, a model it doesn't allow, the day used up
		code, msg := coded(err)
		out := struct {
			Error    string            `json:"error"`
			Code     string            `json:"code"`
			Activity []json.RawMessage `json:"activity,omitempty"` // the refused record, sealed to record_to
		}{Error: msg, Code: code}
		if rg, ok := s.agent.(*recGateway); ok { // the refusal goes on the record too
			if ev, ok := rg.Refused(&req.RunRequest, err); ok {
				out.Activity = ev.Activity
			}
		}
		writeJSON(w, 403, out)
		return
	case err != nil && strings.HasPrefix(err.Error(), "model enclave not verified"):
		fail(w, 502, err.Error())
		return
	case err != nil:
		fail(w, 400, err.Error())
		return
	}
	st, err := s.tasks().Status(id, userFrom(r.Context()))
	if err != nil { // a key another user's task has can't happen (the user is in the id); say nothing about it
		fail(w, 404, "no_such_task")
		return
	}
	st.Existing = existed
	writeJSON(w, 200, st)
}

// readRef reads a task call's body.
func readRef(w http.ResponseWriter, r *http.Request) (taskRef, bool) {
	var ref taskRef
	body, err := io.ReadAll(io.LimitReader(r.Body, 4096))
	if err == nil {
		err = json.Unmarshal(body, &ref)
	}
	if err != nil || ref.After < 0 {
		fail(w, 400, `body must be {"task": "tk_...", "after": n}`)
		return ref, false
	}
	return ref, true
}

func taskFail(w http.ResponseWriter, err error) {
	if errors.Is(err, guard.ErrNoTask) {
		fail(w, 404, "no_such_task")
		return
	}
	fail(w, 500, "task_unavailable")
}

// authorized checks a task call's MAC (guard.Host.Authorize); false: it answered 404.
func (s *server) authorizedTask(w http.ResponseWriter, r *http.Request, ref taskRef, op string) bool {
	if err := s.tasks().Authorize(ref.Task, userFrom(r.Context()), op, ref.MAC); err != nil {
		taskFail(w, err)
		return false
	}
	return true
}

// taskStatus is behind EHBP: POST /tasks/status.
func (s *server) taskStatus(w http.ResponseWriter, r *http.Request) {
	ref, ok := readRef(w, r)
	if !ok || !s.authorizedTask(w, r, ref, "status") {
		return
	}
	st, err := s.tasks().Status(ref.Task, userFrom(r.Context()))
	if err != nil {
		taskFail(w, err)
		return
	}
	writeJSON(w, 200, st)
}

// taskCancel is behind EHBP: POST /tasks/cancel.
func (s *server) taskCancel(w http.ResponseWriter, r *http.Request) {
	ref, ok := readRef(w, r)
	if !ok || !s.authorizedTask(w, r, ref, "cancel") {
		return
	}
	user := userFrom(r.Context())
	if err := s.tasks().Cancel(ref.Task, user); err != nil {
		taskFail(w, err)
		return
	}
	// The cancel is in; the task ends within the brain's grace period.
	st, err := s.tasks().Status(ref.Task, user)
	if err != nil {
		taskFail(w, err)
		return
	}
	writeJSON(w, 200, st)
}

// taskEvents is behind EHBP: POST /tasks/events. The stream carries keepalives like /run's, and ends with [DONE]
// once the task ended and every event after `after` was sent.
func (s *server) taskEvents(w http.ResponseWriter, r *http.Request) {
	ref, ok := readRef(w, r)
	if !ok || !s.authorizedTask(w, r, ref, "events") {
		return
	}
	h := s.tasks()
	user := userFrom(r.Context())
	if !s.followSlot(user) {
		fail(w, 429, "busy")
		return
	}
	defer s.followDone(user)
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(200)
	out := newEventStream(w, keepaliveEvery)
	defer out.stop()
	err := h.Follow(r.Context(), ref.Task, user, ref.After, func(e guard.Event) error {
		return out.write(fmt.Sprintf("id: %d\ndata: %s\n\n", e.Seq, e.Data))
	})
	if err == nil {
		out.done()
	}
}

// followSlot takes an event stream's slot: one of maxFollowers, and of the user's maxUserFollowers.
func (s *server) followSlot(user string) bool {
	s.followMu.Lock()
	defer s.followMu.Unlock()
	if s.userFollows[user] >= maxUserFollowers {
		return false
	}
	select {
	case s.follows <- struct{}{}:
	default:
		return false
	}
	s.userFollows[user]++
	return true
}

func (s *server) followDone(user string) {
	s.followMu.Lock()
	defer s.followMu.Unlock()
	<-s.follows
	if s.userFollows[user]--; s.userFollows[user] <= 0 {
		delete(s.userFollows, user)
	}
}

// resumeTasks takes up the tasks a previous process left in the queue (POST /tasks ones go on; /run ones are
// abandoned, as before) and prunes ended ones past their keep, now and every hour.
func (s *server) resumeTasks(ctx context.Context, ids []string, logf func(string, ...any)) {
	h := s.tasks()
	if resumed, abandoned := h.Resume(ids); resumed+abandoned > 0 {
		logf("tasks: resumed %d, ended %d runs a previous process left open", resumed, abandoned)
	}
	go func() {
		for {
			if n := h.Prune(time.Now()); n > 0 {
				logf("tasks: deleted %d ended tasks past their keep", n)
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Hour):
			}
		}
	}()
}
