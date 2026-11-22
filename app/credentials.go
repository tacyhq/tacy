package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"slices"
	"time"

	jsonv2 "encoding/json/v2"

	"github.com/tacyhq/tacy/guard"
	"github.com/tacyhq/tacy/harness"
	"github.com/tacyhq/tacy/vault"
)

// Per-task mail logins (v1, the v1 design §5.4). The person's app keeps the login (the mail-login/v1 item, under
// their own key) and sends it with each task that may read mail, sealed in the app to vaultd's per-boot key and
// bound to the task's space and start key:
//
//	POST /tasks             {..., key, credentials: [{connection: "email", expires, sealed: {key, enc, ct}}]}
//	POST /tasks/credential  {task, mac, key, credentials} -> {task, accepted: true}
//
// agentd checks the shape and who asks, and passes the box unopened to gatewayd and on to vaultd (guard.ConnRequest
// run_put), which opens and checks it and holds it in its memory for that task only. agentd keeps none of it: the
// box is never in the task's start, options, journal or events (so never in the task queue, /run/tacy-tasks), and
// the task's end, cancel or delete tells vaultd to forget it (run_end).
//
// After a vaultd restart the task's next mail call finds no login: gatewayd answers it with mail_login_needed, and
// agentd holds the call (guard.CredWaits: need_credential in the task's stream) until an app sends the box again,
// then runs it again; with none in time the model is told so.

// TaskCredential is one sealed login with a task start or resend. Expires is ms since the epoch (in the box's AAD).
type TaskCredential struct {
	Connection string       `json:"connection"`
	Expires    int64        `json:"expires"`
	Sealed     vault.Sealed `json:"sealed"`
}

// credError is a refused credential: an HTTP status and the connections contract's code.
type credError struct {
	status       int
	code, detail string
}

func (e *credError) Error() string { return e.code + ": " + e.detail }

func badCred(detail string) *credError { return &credError{400, "bad_credential", detail} }

// checkCredentials is the shape check before anything is passed on: at most one, for email, with its box, and a
// start key to bind it to.
func checkCredentials(cs []TaskCredential, key string) error {
	switch {
	case len(cs) == 0:
		return nil
	case len(cs) > 1:
		return badCred("at most one credential")
	case key == "":
		return &credError{400, "key_required", "a task with a credential needs its start key"}
	}
	c := cs[0]
	if c.Connection != vault.ConnEmail || c.Expires <= 0 || len(c.Sealed.Enc) == 0 || len(c.Sealed.CT) == 0 || len(c.Sealed.CT) > 4<<10 ||
		len(c.Sealed.Enc) > 256 || len(c.Sealed.Key) > 128 {
		return badCred("connection must be email, with its expiry and sealed box")
	}
	return nil
}

// mayUseMail: the request offers a mail tool (a credential with no mail tool is refused: nothing would use it).
func mayUseMail(tools []string) bool {
	return slices.ContainsFunc(tools, func(t string) bool { return slices.Contains(guard.MailToolNames(), t) })
}

// putCredential passes a task's sealed login to vaultd (through gatewayd).
func (s *server) putCredential(ctx context.Context, task, space, identity, key string, c TaskCredential) error {
	cn := s.conns()
	if cn == nil {
		return &credError{503, "unavailable", "mail isn't available on this VM"}
	}
	res := cn.Conn(ctx, &guard.ConnRequest{Op: "run_put", Run: &vault.RunGrant{Task: task, Space: space, Identity: identity, Connection: c.Connection,
		KeyHash: vault.KeyHash(key), Expires: c.Expires, Sealed: c.Sealed}})
	if res.Error != nil {
		st, ok := connStatus[res.Error.Code]
		if !ok {
			st = 503
		}
		return &credError{st, res.Error.Code, res.Error.Detail}
	}
	return nil
}

// endCredential tells vaultd to forget a task's login (its end, cancel or delete). Best effort: vaultd forgets it
// anyway after 15 minutes without a mail call, at the box's expiry, and at its own restart.
func (s *server) endCredential(task string) {
	cn := s.conns()
	if cn == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if res := cn.Conn(ctx, &guard.ConnRequest{Op: "run_end", Task: task}); res.Error != nil && res.Error.Code != "unavailable" {
		log.Printf("credentials: a task's mail login wasn't forgotten now: %s", res.Error.Code) // no ids
	}
}

func credFail(w http.ResponseWriter, err error) bool {
	var ce *credError
	if errors.As(err, &ce) {
		failDetail(w, ce.status, ce.code, ce.detail)
		return true
	}
	return false
}

type taskCredentialRequest struct {
	Task        string           `json:"task"`
	MAC         string           `json:"mac"`
	Key         string           `json:"key"`
	Boot        string           `json:"boot,omitempty"` // as on every task call (task_unknown_after_restart)
	Credentials []TaskCredential `json:"credentials"`
}

// taskCredential is behind EHBP: POST /tasks/credential. The run's MAC (op "credential") authorizes it, as a grant;
// the start key must be the one the task was started with (it derives the task's id), so the box is bound to this
// task and no other. Then the calls the task held for it run again.
func (s *server) taskCredential(w http.ResponseWriter, r *http.Request) {
	var req taskCredentialRequest
	body, err := io.ReadAll(io.LimitReader(r.Body, 16<<10))
	if err == nil {
		err = jsonv2.Unmarshal(body, &req, jsonv2.RejectUnknownMembers(true))
	}
	if err != nil {
		fail(w, 400, `body must be {"task", "mac", "key", "credentials"}`)
		return
	}
	ref := taskRef{Task: req.Task, MAC: req.MAC, Boot: req.Boot}
	if !s.authorizedTask(w, r, ref, "credential") {
		return
	}
	if len(req.Credentials) != 1 {
		failDetail(w, 400, "bad_credential", "one credential")
		return
	}
	if err := checkCredentials(req.Credentials, req.Key); err != nil {
		credFail(w, err)
		return
	}
	st, err := s.rt.Status(req.Task)
	var o guard.TaskOptions
	if err != nil || json.Unmarshal(st.Options, &o) != nil {
		fail(w, 404, "no_such_task")
		return
	}
	h := s.tasks()
	if len(h.IDKey) == 0 || harness.DeriveTaskID(h.IDKey, "start", o.Space, o.User, req.Key) != req.Task {
		failDetail(w, 400, "bad_credential", "the key isn't this task's start key")
		return
	}
	if st.Outcome != nil {
		failDetail(w, 409, "task_ended", "the task has ended")
		return
	}
	if err := s.putCredential(r.Context(), req.Task, o.Space, o.Identity, req.Key, req.Credentials[0]); err != nil {
		if !credFail(w, err) {
			fail(w, 503, "unavailable")
		}
		return
	}
	// The task may have ended between the check above and the put (review 2, L6): its end's run_end then reached
	// vaultd first, and nothing would forget this login before its idle timeout. Read the state again.
	if st, err := s.rt.Status(req.Task); err != nil || st.Outcome != nil {
		s.endCredential(req.Task)
		failDetail(w, 409, "task_ended", "the task has ended")
		return
	}
	if cw := s.credWaits(); cw != nil {
		cw.Provided(req.Task)
	}
	writeJSON(w, 200, map[string]any{"task": req.Task, "accepted": true})
}

// credWaits is the task host's waiter for mail logins (recGateway's); nil: none.
func (s *server) credWaits() *guard.CredWaits {
	s.tasks()
	if rg, ok := s.agent.(*recGateway); ok {
		return rg.creds
	}
	return nil
}
