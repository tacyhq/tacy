package main

import (
	"cmp"
	"context"
	"encoding/json"
	jsonv2 "encoding/json/v2"
	"errors"
	"io"
	"net/http"
	"time"

	ehbpidentity "github.com/tinfoilsh/encrypted-http-body-protocol/identity"
	ehbpproto "github.com/tinfoilsh/encrypted-http-body-protocol/protocol"

	"github.com/tacyhq/tacy/guard"
	"github.com/tacyhq/tacy/harness"
	"github.com/tacyhq/tacy/proto"
	"github.com/tacyhq/tacy/safety"
)

// POST /search: the plain chat's web search (guard/searchtask.go). With agent mode off, the chat's model
// asks for a search, the person's tab shows the permission prompt with the exact masked query, and only when they allow it
// does the tab verify this VM and send that query here, EHBP-encrypted like a run. Nothing else can be asked for:
// one query (strict JSON, proto.SearchRequest), no messages, no model, no pages, no images.
//
//	POST /search  {query, count?, question?, decision, edited?, cache_secret?, space, space_seal, space_proof,
//	              identity, identity_key, nonce, signed_at, identity_sig} (the where and who: runauth, v0.10.0)
//	              -> EHBP-encrypted SSE of proto.Event: meta, tool_call, tool_result (the reader's fields with [n]
//	              sources, citations, quotes), favicon, metrics, activity, then done or error. As /run's.
//
// Same bearer token (cost) as /run; X-Agent-User is optional (the relay sends it: the per-user tool caps). It runs
// no brain: agentd itself makes the task's one action with the person's grant, under the same checks as any search
// (the policy and stop lists, the run's and the day's budgets reserved before it runs, the tool caps, gatewayd's own
// permission check, the leak scan, the quarantined reader) and on the activity record (trigger "search"). Nothing
// is kept in the queue: the stream is the only copy, as for /run.

// searchTimeout bounds one search's stream: verifying the reader's model, the search (its client gives up at 20 s),
// the reader (at most 75 s for a search's results since v0.8.14; 45 s in v0.8.13, 30 s in v0.8.12), the results'
// pictures (3 s) and the site icons' grace; 115 s leaves the reader its whole time after a slow search. The task's
// own cap is guard.SearchCap (2 minutes).
const searchTimeout = 115 * time.Second

// Searches at once: VM-wide, and per user tag (the tool caps in the guard limit the searches themselves too).
const (
	maxSearches     = 16
	maxUserSearches = 2
)

// searchStarter makes a search task: agentd's recorder and safety checks (recGateway.StartSearch).
type searchStarter interface {
	StartSearch(r *proto.SearchRequest) (harness.Start, guard.TaskOptions, []byte, error)
}

func (s *server) searchRoutes(mux *http.ServeMux, id *ehbpidentity.Identity) {
	s.searchSlots = make(chan struct{}, maxSearches)
	s.userSearches = map[string]int{}
	mux.Handle("POST /search", s.searchGuard(id.Middleware()(http.HandlerFunc(s.search))))
	mux.Handle("POST /pictures", s.searchGuard(id.Middleware()(http.HandlerFunc(s.pictures))))
}

// picturesStarter makes a pictures task: agentd's recorder and safety checks (recGateway.StartPictures).
type picturesStarter interface {
	StartPictures(r *proto.PicturesRequest) (harness.Start, guard.TaskOptions, []byte, error)
}

// picturesTimeout bounds one pictures stream: the lookups' own bound (guard laterWait, 40 s since v0.10.0: a 25 s image
// search, then 12 s for downloads) and the end's grace. The stream carries keepalives meanwhile, so the chat's stall
// check (6 s) and the relay don't cut it.
const picturesTimeout = 45 * time.Second

// POST /pictures (v0.8.21): an answer's cards' held-back photos, once the person allows pictures (guard/pictures.go).
//
//	POST /pictures  {ticket, space, space_seal, space_proof, identity, identity_key, nonce, signed_at, identity_sig}
//	              (runauth, v0.10.0); optional "X-Agent-User-Prev: <hex>" (the same person's
//	              tag for the previous UTC day, v0.8.22)
//	              -> EHBP-encrypted SSE of proto.Event: meta, image (under the run's calls, "for" its item), metrics,
//	              activity, then done or error. Same token, slots and user tag as /search; nothing is kept.
func (s *server) pictures(w http.ResponseWriter, r *http.Request) {
	var req proto.PicturesRequest
	body, err := io.ReadAll(io.LimitReader(r.Body, 16<<10))
	if err == nil {
		err = jsonv2.Unmarshal(body, &req, jsonv2.RejectUnknownMembers(true))
	}
	if err != nil {
		fail(w, 400, "body must be a JSON pictures request")
		return
	}
	starter, ok := s.agent.(picturesStarter)
	if !ok {
		fail(w, 404, "pictures_unavailable")
		return
	}
	if rg, ok := s.agent.(*recGateway); ok { // as for a search
		if err := rg.VerifyPictures(&req, userFrom(r.Context())); err != nil {
			fail(w, 400, err.Error())
			return
		}
	}
	start, opts, args, err := starter.StartPictures(&req)
	if err != nil && safety.CodeOf(err) == "" {
		fail(w, 400, err.Error())
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(200)
	out := newEventStream(w, keepaliveEvery)
	defer out.stop()
	emit := out.emit
	if err != nil {
		code, msg := coded(err)
		emit(proto.Event{Type: "error", Error: msg, Code: code})
		out.done()
		return
	}
	opts.User, opts.Space = userFrom(r.Context()), start.Space
	// The same person's tag for the previous UTC day (the relay sends it with a pictures request only): a ticket
	// from a run before midnight UTC (guard/pictures.go takePictures says why this is safe).
	if prev := r.Header.Get("X-Agent-User-Prev"); opts.User != "" && userTagRe.MatchString(prev) {
		opts.PrevUser = prev
	}
	id := harness.NewTaskID()
	ctx, cancel := context.WithTimeout(r.Context(), picturesTimeout)
	defer cancel()
	sess := s.agent.Open(id, opts, emit)
	defer sess.Close()
	obs, _ := s.agent.(guard.RunObserver)
	end := func(e guard.RunEnd, last proto.Event) {
		if obs != nil {
			for _, ev := range obs.RunEnded(id, e) {
				emit(ev)
			}
		}
		emit(last)
		out.done()
	}
	meta := &proto.Meta{Tools: []string{"image_search"}} // no model: nothing to verify
	if obs != nil {
		obs.RunStarted(id, &start, opts, meta)
	}
	emit(proto.Event{Type: "meta", Meta: meta})
	optsJSON, _ := json.Marshal(opts)
	ti := &harness.TaskInfo{ID: id, Start: &start, Options: optsJSON}
	actx := harness.WithRequestID(ctx, guard.PicturesActionID)
	res, err := s.agent.Action(actx, ti, guard.PicturesActionID, &harness.Action{Name: "web.images", Call: guard.PicturesActionID, Args: args})
	step, finish := sess.End()
	switch {
	case r.Context().Err() != nil:
		end(guard.RunEnd{State: harness.OutcomeCancelled, Reason: "person", Steps: step}, proto.Event{Type: "error", Error: "cancelled"})
	case ctx.Err() != nil:
		end(guard.RunEnd{State: harness.OutcomeCancelled, Reason: "deadline", Steps: step}, proto.Event{Type: "error", Error: "timed out"})
	case err != nil:
		code, msg := s.why(id, err)
		if code == "" {
			msg = "the pictures couldn't be looked up"
		}
		end(guard.RunEnd{State: harness.OutcomeFailed, Code: code, Msg: msg, Steps: step}, proto.Event{Type: "error", Error: msg, Code: code})
	case res.Status == harness.ActionDone:
		end(guard.RunEnd{State: harness.OutcomeSucceeded, Steps: step, Finish: finish}, proto.Event{Type: "done", Step: step})
	default:
		end(guard.RunEnd{State: harness.OutcomeFailed, Steps: step}, proto.Event{Type: "error", Error: cmp.Or(res.Error, "the pictures couldn't be looked up"), Code: "pictures_" + res.Status})
	}
}

// searchGuard is the checks before EHBP decryption: token, encrypted body, user tag, a slot. Plaintext errors,
// carrying no request data.
func (s *server) searchGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.authorized(r) {
			fail(w, 401, "unauthorized")
			return
		}
		if r.Header.Get(ehbpproto.EncapsulatedKeyHeader) == "" || r.ContentLength == 0 {
			fail(w, 400, "encrypted body required (EHBP)")
			return
		}
		user := r.Header.Get("X-Agent-User")
		if user != "" && !userTagRe.MatchString(user) {
			fail(w, 400, "bad_user_tag")
			return
		}
		select {
		case s.searchSlots <- struct{}{}:
		default:
			fail(w, 429, "busy")
			return
		}
		defer func() { <-s.searchSlots }()
		s.searchMu.Lock()
		if s.userSearches[user] >= maxUserSearches {
			s.searchMu.Unlock()
			fail(w, 429, "user_busy")
			return
		}
		s.userSearches[user]++
		s.searchMu.Unlock()
		defer func() {
			s.searchMu.Lock()
			if s.userSearches[user]--; s.userSearches[user] <= 0 {
				delete(s.userSearches, user)
			}
			s.searchMu.Unlock()
		}()
		r.Body = http.MaxBytesReader(w, r.Body, 256<<10)
		next.ServeHTTP(w, r.WithContext(withUser(r.Context(), user)))
	})
}

// search is behind EHBP: the body here is plaintext and everything written is encrypted.
func (s *server) search(w http.ResponseWriter, r *http.Request) {
	var req proto.SearchRequest
	body, err := io.ReadAll(io.LimitReader(r.Body, 64<<10))
	if err == nil {
		err = jsonv2.Unmarshal(body, &req, jsonv2.RejectUnknownMembers(true))
	}
	if err != nil {
		fail(w, 400, "body must be a JSON search request")
		return
	}
	starter, ok := s.agent.(searchStarter)
	if !ok {
		fail(w, 404, "search_unavailable")
		return
	}
	// Where and who (keys v2 spaces and identities, v0.10.0): checked once, here, as for a run; a refusal writes nothing.
	if rg, ok := s.agent.(*recGateway); ok {
		if err := rg.VerifySearch(&req, userFrom(r.Context())); err != nil {
			fail(w, 400, err.Error())
			return
		}
	}
	start, opts, args, err := starter.StartSearch(&req)
	if err != nil && safety.CodeOf(err) == "" {
		fail(w, 400, err.Error())
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(200)
	out := newEventStream(w, keepaliveEvery)
	defer out.stop()
	emit := out.emit
	if err != nil { // stopped, no policy, web search not allowed, the day used up: say why, on the record too
		code, msg := coded(err)
		if rg, ok := s.agent.(*recGateway); ok {
			if ev, ok := rg.RefusedSearch(&req, err); ok {
				emit(ev)
			}
		}
		emit(proto.Event{Type: "error", Error: msg, Code: code})
		out.done()
		return
	}
	opts.User, opts.Space = userFrom(r.Context()), start.Space
	id := harness.NewTaskID()
	ctx, cancel := context.WithTimeout(r.Context(), searchTimeout)
	defer cancel()
	sess := s.agent.Open(id, opts, emit)
	defer sess.Close()
	obs, _ := s.agent.(guard.RunObserver)
	end := func(e guard.RunEnd, last proto.Event) {
		if obs != nil {
			for _, ev := range obs.RunEnded(id, e) {
				emit(ev)
			}
		}
		emit(last)
		out.done()
	}
	meta, err := sess.Meta(ctx) // the reader's model: Tinfoil's router, verified (as for a run)
	if err != nil {
		emit(proto.Event{Type: "error", Error: "model enclave not verified"})
		out.done()
		return
	}
	meta.Tools = []string{"web_search"}
	if obs != nil {
		obs.RunStarted(id, &start, opts, meta)
	}
	emit(proto.Event{Type: "meta", Meta: meta})

	// The person's answer, given in their tab before anything was sent: the one grant this task has, for exactly
	// the value that goes out. gatewayd checks it as any grant (guard.permit); a policy that caps web search to
	// Never still denies it there.
	g, err := guard.SearchGrant(id, opts, args)
	if err != nil {
		end(guard.RunEnd{State: harness.OutcomeFailed}, proto.Event{Type: "error", Error: "no query"})
		return
	}
	actx := harness.WithRequestID(ctx, guard.SearchActionID)
	if s.prompts != nil {
		s.prompts.Approved(id, guard.SearchActionID, g, guard.PermissionOutcome{Outcome: guard.SearchOutcome(req.Decision), Edited: req.Edited})
	} else {
		actx = guard.WithGrant(actx, g)
	}
	optsJSON, _ := json.Marshal(opts)
	ti := &harness.TaskInfo{ID: id, Start: &start, Options: optsJSON}
	res, err := s.agent.Action(actx, ti, guard.SearchActionID, &harness.Action{Name: "web.search", Call: guard.SearchActionID, Args: args})
	step, finish := sess.End() // the site icons' grace
	switch {
	case r.Context().Err() != nil: // the tab went away: on the record, nothing more to send
		end(guard.RunEnd{State: harness.OutcomeCancelled, Reason: "person", Steps: step}, proto.Event{Type: "error", Error: "search cancelled"})
	case ctx.Err() != nil:
		end(guard.RunEnd{State: harness.OutcomeCancelled, Reason: "deadline", Steps: step}, proto.Event{Type: "error", Error: "search timed out"})
	case err != nil:
		code, msg := s.why(id, err) // a control refused it (a budget, a stop): say which
		e := guard.RunEnd{State: harness.OutcomeFailed, Code: code, Msg: msg, Steps: step}
		if code == "" {
			msg = "the search failed"
		}
		end(e, proto.Event{Type: "error", Error: msg, Code: code})
	case res.Status == harness.ActionDone:
		end(guard.RunEnd{State: harness.OutcomeSucceeded, Steps: step, Finish: finish}, proto.Event{Type: "done", Step: step})
	default: // denied (permission, policy, leak scan) or failed (the provider): the guard's own words, never the provider's
		end(guard.RunEnd{State: harness.OutcomeFailed, Steps: step}, proto.Event{Type: "error", Error: cmp.Or(res.Error, "the search didn't run"),
			Code: "search_" + res.Status})
	}
}

// why is the control that refused a search's action (a budget, a stop), from the error or the safety checks' note.
func (s *server) why(task string, err error) (string, string) {
	var pe *harness.Error
	if errors.As(err, &pe) {
		if c := controlCode(pe.Message); c != "" {
			return c, pe.Message
		}
	}
	if w, ok := s.agent.(interface {
		Why(task string) (string, string)
	}); ok {
		return w.Why(task)
	}
	return "", ""
}
