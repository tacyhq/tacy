package main

import (
	"context"
	"errors"
	"io"
	"log"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	jsonv2 "encoding/json/v2"

	ehbpidentity "github.com/tinfoilsh/encrypted-http-body-protocol/identity"

	"github.com/tacyhq/tacy/activity"
	"github.com/tacyhq/tacy/guard"
	"github.com/tacyhq/tacy/harness"
	"github.com/tacyhq/tacy/identity"
	"github.com/tacyhq/tacy/proto"
	"github.com/tacyhq/tacy/runauth"
	"github.com/tacyhq/tacy/safety"
	"github.com/tacyhq/tacy/trigger"
)

// Schedules for personal spaces (v0.12.0, docs/30 "Scheduled tasks"; the contract the chat builds on is
// SCHEDULES.md next to this package). On the shared chat VM a person installs, lists, stops and removes their own
// space's schedules and fetches their results. Every call carries the same where and who as a run (the space proof
// against this boot's key and the identity's signature, package runauth), each under its own label, and its nonce is
// used once. An install also records that the identity holds the space (trigger.HolderDirectory): that record is what
// the definition's signature, and the sponsor's checks at each tick, are verified against.
//
// A scheduled run's result never stays on the VM in the clear: when the run ends, its events are sealed to the
// definition's seal key (the space's), kept on the encrypted disk until the browser deletes them or 7 days pass, and
// the task itself is forgotten.
//
// Schedule upgrades (the release after v0.14.0): a definition with memory has what each run found (its result's text
// and cited sources, or a quiet run's note) kept on the VM's side file for its next runs: the newest 7, each at most
// 30 days, deleted with the schedule (remove) or when a new version drops memory. It never leaves the VM. A
// notify-changes run that called schedule.no_change has its result marked quiet (the listing's and the sealed
// body's "quiet"): the browser records that it ran and adds no message.
//
//	POST /schedules/install         {where and who, definition} -> {agent, version, digest, state, not_after, triggers}
//	POST /schedules/list            {where and who} -> {schedules}
//	POST /schedules/stop            {where and who, agent} -> {agent, version, state, cancelled}
//	POST /schedules/remove          {where and who, agent} -> {agent, version, state, cancelled, results_deleted}
//	POST /schedules/results         {where and who, after} -> {results, more}
//	POST /schedules/result          {where and who, task} -> {…, sealed: {enc, ct}}
//	POST /schedules/results/delete  {where and who, tasks} -> {deleted}
//	POST /spaces/reseal             {where and who (the new seal key), old_seal, old_proof} -> {space, seal}
//
// Every call's seal key must be the one pinned for its space (v0.16.0, runauth.CheckPin; 403 seal_mismatch
// otherwise); POST /spaces/reseal moves the pin to a new seal key, proving the old one too (runauth.CheckReseal).

// Limits.
const (
	maxSpaceSchedules = 8
	// maxSpaceStored also counts ended one-time schedules (the chat removes each once its result is saved).
	maxSpaceStored  = 64
	resultsPage     = 50
	maxResultEvents = 2000
	maxResultBytes  = 1 << 20
	resultInfo      = "tacy/v2/schedule-result"
	resultType      = "tacy.schedule.result/v1"
)

// scheduleRoutes serves the routes on mux behind EHBP with id.
func (s *server) scheduleRoutes(mux *http.ServeMux, id *ehbpidentity.Identity) {
	for path, h := range map[string]http.HandlerFunc{
		"install": s.scheduleInstall, "list": s.scheduleList, "stop": s.scheduleStop, "remove": s.scheduleRemove,
		"results": s.scheduleResults, "result": s.scheduleResult, "results/delete": s.scheduleResultsDelete,
	} {
		mux.Handle("POST /schedules/"+path, s.taskGuard(false, false, id.Middleware()(h)))
	}
	mux.Handle("POST /spaces/reseal", s.taskGuard(false, false, id.Middleware()(http.HandlerFunc(s.spaceReseal))))
}

func failDetail(w http.ResponseWriter, status int, code, detail string) {
	writeJSON(w, status, map[string]string{"error": code, "detail": detail})
}

// personal: this VM takes schedule calls (the shared chat VM, with its holder directory and result store).
func (s *server) personal() bool {
	_, ok := s.dir.(*trigger.HolderDirectory)
	return ok && s.triggers != nil && s.results != nil && s.holders != nil
}

// callWho checks a schedule call's where and who and claims its nonce; it writes the error itself (false).
func (s *server) callWho(w http.ResponseWriter, label string, where *runauth.Where, items ...string) (runauth.Who, bool) {
	rg, _ := s.agent.(*recGateway)
	if !s.personal() || rg == nil || rg.vmKey == nil {
		fail(w, 503, "identity_unavailable")
		return runauth.Who{}, false
	}
	who, err := runauth.CheckCall(rg.vmKey, label, where, time.Now(), items...)
	if err != nil {
		failDetail(w, 403, "bad_proof", err.Error())
		return runauth.Who{}, false
	}
	// The space's pinned seal key (v0.16.0): another key proven for the space changes nothing in it.
	switch err := runauth.CheckPin(rg.pins, who, time.Now()); {
	case errors.Is(err, runauth.ErrSealPinned):
		failDetail(w, 403, "seal_mismatch", err.Error())
		return runauth.Who{}, false
	case err != nil:
		fail(w, 500, "store_unavailable")
		return runauth.Who{}, false
	}
	return s.claimNonce(w, rg, who, where)
}

// claimNonce claims a checked call's nonce; it writes the error itself (false).
func (s *server) claimNonce(w http.ResponseWriter, rg *recGateway, who runauth.Who, where *runauth.Where) (runauth.Who, bool) {
	switch err := rg.nonces.Claim(where.Nonce, where.SignedAt); {
	case errors.Is(err, runauth.ErrReplay):
		fail(w, 409, "replayed")
		return runauth.Who{}, false
	case err != nil:
		fail(w, 429, "busy")
		return runauth.Who{}, false
	}
	return who, true
}

// readCall reads a schedule call's body strictly; it writes the error itself (false).
func readCall(w http.ResponseWriter, r *http.Request, max int64, v any) bool {
	body, err := io.ReadAll(io.LimitReader(r.Body, max))
	if err == nil {
		err = jsonv2.Unmarshal(body, v, jsonv2.RejectUnknownMembers(true))
	}
	if err != nil {
		failDetail(w, 400, "bad_request", "the body must be the call's JSON")
		return false
	}
	return true
}

type resealRequest struct {
	runauth.Where
	OldSeal  string `json:"old_seal"`
	OldProof []byte `json:"old_proof"`
}

// spaceReseal moves a personal space's pinned seal key to a new one (a rotation): the call proves the new key as any
// call does and the old one with its own space proof, and the pin moves only from the key it holds now.
func (s *server) spaceReseal(w http.ResponseWriter, r *http.Request) {
	var req resealRequest
	if !readCall(w, r, 8<<10, &req) {
		return
	}
	rg, _ := s.agent.(*recGateway)
	if !s.personal() || rg == nil || rg.vmKey == nil {
		fail(w, 503, "identity_unavailable")
		return
	}
	who, err := runauth.CheckReseal(rg.vmKey, &req.Where, req.OldSeal, req.OldProof, time.Now())
	if err != nil {
		failDetail(w, 403, "bad_proof", err.Error())
		return
	}
	if _, ok := s.claimNonce(w, rg, who, &req.Where); !ok {
		return
	}
	switch err := rg.pins.RepinSeal(who.Space, req.OldSeal, who.Seal, time.Now()); {
	case errors.Is(err, runauth.ErrSealPinned):
		failDetail(w, 403, "seal_mismatch", "the old seal key isn't the one pinned for the space")
		return
	case err != nil:
		fail(w, 500, "store_unavailable")
		return
	}
	log.Printf("spaces: a personal space's seal key was rotated") // no ids
	writeJSON(w, 200, map[string]string{"space": who.Space, "seal": who.Seal})
}

type installRequest struct {
	runauth.Where
	Definition safety.Envelope `json:"definition"`
}

type triggerView struct {
	ID          string     `json:"id"`
	Daily       string     `json:"daily,omitzero"`
	Days        []string   `json:"days,omitzero"`
	At          string     `json:"at,omitzero"`
	Zone        string     `json:"zone,omitzero"`
	NextRun     *time.Time `json:"next_run,omitzero"`
	LastDay     string     `json:"last_day,omitzero"`
	LastTask    string     `json:"last_task,omitzero"`
	LastSkipped string     `json:"last_skipped,omitzero"`
}

func (s *server) triggerViews(in *trigger.Installed, state string, full bool) []triggerView {
	var out []triggerView
	now := time.Now()
	for _, t := range in.Def.Triggers {
		v := triggerView{ID: t.ID, Daily: t.Daily, Days: t.Days, At: t.At, Zone: t.Zone}
		if state == trigger.StateActive {
			if n := t.NextRun(now); !n.IsZero() && n.Before(in.Def.NotAfter) {
				n = n.UTC()
				v.NextRun = &n
			}
		}
		if full && (t.IsDaily() || t.IsOnce()) {
			ran, skipped := s.triggers.LastRan(&t)
			if ran >= 0 {
				v.LastDay, v.LastTask = trigger.DayOf(ran), s.triggers.TaskFor(in.Def, &t, ran)
			}
			if skipped >= 0 {
				v.LastSkipped = trigger.DayOf(skipped)
			}
		}
		out = append(out, v)
	}
	return out
}

func (s *server) scheduleInstall(w http.ResponseWriter, r *http.Request) {
	var req installRequest
	if !readCall(w, r, 2*trigger.MaxDefinition+8<<10, &req) {
		return
	}
	who, ok := s.callWho(w, runauth.InstallLabel, &req.Where, req.Definition.Hash())
	if !ok {
		return
	}
	// The identity holds the space: it proved the seal key (only the space's holders can) and signed with its key.
	if err := s.holders.PutHolder(trigger.Holder{Space: who.Space, Identity: who.Identity, Key: who.Key, Seal: who.Seal,
		At: time.Now().UTC()}); err != nil {
		fail(w, 500, "store_unavailable")
		return
	}
	var d trigger.Definition
	decodeErr := jsonv2.Unmarshal(req.Definition.Payload, &d)
	// What the relay charges for it (v0.16.0, schedule_charge.go), checked against the signed definition first.
	charged, ok := checkScheduleCharge(r, &d, decodeErr == nil)
	if !ok {
		failDetail(w, 400, "charge_mismatch", "the X-Schedule-Charge header doesn't match the schedule's definition")
		return
	}
	if err := decodeErr; err == nil {
		if d.Space != who.Space || d.Author != who.Identity || d.Sponsor != who.Identity {
			failDetail(w, 403, "not_holder", "a personal schedule's space, author and sponsor are the request's own")
			return
		}
		if old := s.triggers.Get(d.Agent); old == nil || old.Def.Space != who.Space {
			if live, all := s.triggers.SpaceCount(who.Space); live >= maxSpaceSchedules || all >= maxSpaceStored {
				fail(w, 429, "too_many_schedules")
				return
			}
		}
	}
	in, err := s.triggers.InstallChecked(req.Definition, func(d *trigger.Definition) error {
		if err := trigger.Personal(d, who.Space, who.Seal, who.Identity); err != nil {
			return err
		}
		// Every model must be one this release has and the space's policy allows (else each slot would fail).
		e, err := s.safety.Policy(d.Space)
		for _, m := range d.Models {
			if !guard.KnownModel(m) || err != nil || !e.AllowsModel(m) {
				return errors.New("model " + m + " isn't one this release runs for the space")
			}
		}
		return nil
	})
	switch {
	case errors.Is(err, trigger.ErrStale):
		failDetail(w, 409, "stale_version", err.Error())
		return
	case errors.Is(err, identity.ErrNotHolder) || errors.Is(err, identity.ErrUnknown):
		failDetail(w, 403, "not_holder", err.Error())
		return
	case err != nil:
		failDetail(w, 403, "bad_definition", err.Error())
		return
	}
	if !in.Def.Memory && s.memory != nil { // a version without memory: what earlier runs found goes now
		if _, err := s.memory.DeleteMemory(in.Def.Space, in.Def.Agent); err != nil {
			log.Printf("schedules: memory not deleted: %v", err)
		}
	}
	log.Printf("schedules: installed (version %d, %d triggers)", in.Def.Version, len(in.Def.Triggers)) // no ids or times
	state := s.triggers.StateOf(in)
	if charged {
		w.Header().Set(schedulePricedHeader, "1")
	}
	writeJSON(w, 200, map[string]any{"agent": in.Def.Agent, "version": in.Def.Version, "digest": in.Digest, "state": state,
		"not_after": in.Def.NotAfter.UTC(), "triggers": s.triggerViews(in, state, false)})
}

type scheduleView struct {
	Agent      string          `json:"agent"`
	Version    uint64          `json:"version"`
	Digest     string          `json:"digest"`
	State      string          `json:"state"`
	NotAfter   time.Time       `json:"not_after"`
	Definition safety.Envelope `json:"definition"`
	Triggers   []triggerView   `json:"triggers"`
	Running    int             `json:"running"`
	// StopReason (v0.17.0): "uncollected" when it stopped itself because nobody collected its last results
	// (trigger/collect.go); absent otherwise.
	StopReason string `json:"stop_reason,omitzero"`
}

// mine is the space's definitions sealed to seal.
func (s *server) mine(who runauth.Who) []*trigger.Installed {
	var out []*trigger.Installed
	for _, in := range s.triggers.Installed() {
		if in.Def.Space == who.Space && in.Def.Seal == who.Seal {
			out = append(out, in)
		}
	}
	return out
}

// running is the open unattended tasks of agent.
func (s *server) running(agent string) []string {
	var out []string
	for id, o := range s.tasks().Triggered() {
		if o.DefAgent == agent {
			out = append(out, id)
		}
	}
	return out
}

func (s *server) scheduleList(w http.ResponseWriter, r *http.Request) {
	var req runauth.Where
	if !readCall(w, r, 8<<10, &req) {
		return
	}
	who, ok := s.callWho(w, runauth.ListLabel, &req)
	if !ok {
		return
	}
	out := []scheduleView{}
	for _, in := range s.mine(who) {
		state := s.triggers.StateOf(in)
		out = append(out, scheduleView{Agent: in.Def.Agent, Version: in.Def.Version, Digest: in.Digest, State: state,
			NotAfter: in.Def.NotAfter.UTC(), Definition: in.Env, Triggers: s.triggerViews(in, state, true), Running: len(s.running(in.Def.Agent)),
			StopReason: s.triggers.StopReason(in)})
	}
	writeJSON(w, 200, map[string]any{"schedules": out})
}

type agentRequest struct {
	runauth.Where
	Agent string `json:"agent"`
}

func (s *server) scheduleStop(w http.ResponseWriter, r *http.Request)   { s.stopSchedule(w, r, false) }
func (s *server) scheduleRemove(w http.ResponseWriter, r *http.Request) { s.stopSchedule(w, r, true) }

func (s *server) stopSchedule(w http.ResponseWriter, r *http.Request, remove bool) {
	var req agentRequest
	if !readCall(w, r, 8<<10, &req) {
		return
	}
	label := runauth.StopLabel
	if remove {
		label = runauth.RemoveLabel
	}
	who, ok := s.callWho(w, label, &req.Where, req.Agent)
	if !ok {
		return
	}
	// The schedule the relay stops charging (v0.16.0, schedule_charge.go): the one this signed call names.
	named := r.Header.Get(scheduleAgentHeader)
	if named != "" && named != req.Agent {
		failDetail(w, 400, "agent_mismatch", "the X-Schedule-Agent header doesn't name the call's schedule")
		return
	}
	in := s.triggers.Get(req.Agent)
	if in == nil || in.Def.Space != who.Space || in.Def.Seal != who.Seal {
		fail(w, 404, "no_such_schedule")
		return
	}
	if named != "" {
		w.Header().Set(schedulePricedHeader, "1")
	}
	out, err := s.triggers.Stop(req.Agent, remove)
	if err != nil {
		fail(w, 500, "store_unavailable")
		return
	}
	cancelled := 0
	for _, id := range s.running(req.Agent) {
		if s.rt.Cancel(id, "person") == nil {
			cancelled++
		}
	}
	resp := map[string]any{"agent": out.Def.Agent, "version": out.Def.Version, "state": out.State, "cancelled": cancelled}
	if remove {
		n, err := s.results.DeleteAgentResults(who.Space, req.Agent)
		if err != nil {
			log.Printf("schedules: results not deleted: %v", err)
		}
		resp["results_deleted"] = n
		if s.memory != nil {
			m, err := s.memory.DeleteMemory(who.Space, req.Agent)
			if err != nil {
				log.Printf("schedules: memory not deleted: %v", err)
			}
			resp["memory_deleted"] = m
		}
	}
	writeJSON(w, 200, resp)
}

type resultView struct {
	Seq         int64       `json:"seq"`
	Task        string      `json:"task"`
	Agent       string      `json:"agent"`
	Version     uint64      `json:"version"`
	Trigger     string      `json:"trigger"`
	Day         string      `json:"day,omitzero"`
	ScheduledAt time.Time   `json:"scheduled_at"`
	StartedAt   time.Time   `json:"started_at"`
	EndedAt     time.Time   `json:"ended_at"`
	State       string      `json:"state"`
	Code        string      `json:"code"`
	Size        int         `json:"size"`
	Quiet       bool        `json:"quiet,omitzero"`
	Sealed      *sealedBody `json:"sealed,omitzero"`
}

type sealedBody struct {
	Enc []byte `json:"enc"`
	CT  []byte `json:"ct"`
}

func viewOf(r trigger.Result) resultView {
	return resultView{Seq: r.Seq, Task: r.Task, Agent: r.Agent, Version: r.Version, Trigger: r.Trigger, Day: r.Day, ScheduledAt: r.ScheduledAt,
		StartedAt: r.StartedAt, EndedAt: r.EndedAt, State: r.State, Code: r.Code, Size: max(len(r.CT), cap(r.CT)), Quiet: r.Quiet}
}

type resultsRequest struct {
	runauth.Where
	After int64 `json:"after"`
}

func (s *server) scheduleResults(w http.ResponseWriter, r *http.Request) {
	var req resultsRequest
	if !readCall(w, r, 8<<10, &req) {
		return
	}
	who, ok := s.callWho(w, runauth.ResultsLabel, &req.Where, strconv.FormatInt(req.After, 10))
	if !ok {
		return
	}
	rs, err := s.results.Results(who.Space, who.Seal, req.After, resultsPage+1)
	if err != nil {
		fail(w, 500, "store_unavailable")
		return
	}
	out := []resultView{}
	for i, x := range rs {
		if i == resultsPage {
			break
		}
		out = append(out, viewOf(x))
	}
	writeJSON(w, 200, map[string]any{"results": out, "more": len(rs) > resultsPage})
}

type taskRequest struct {
	runauth.Where
	Task string `json:"task"`
}

func (s *server) scheduleResult(w http.ResponseWriter, r *http.Request) {
	var req taskRequest
	if !readCall(w, r, 8<<10, &req) {
		return
	}
	who, ok := s.callWho(w, runauth.ResultLabel, &req.Where, req.Task)
	if !ok {
		return
	}
	x, err := s.results.GetResult(who.Space, who.Seal, req.Task)
	if err != nil {
		fail(w, 500, "store_unavailable")
		return
	}
	if x == nil {
		fail(w, 404, "no_such_result")
		return
	}
	v := viewOf(*x)
	v.Sealed = &sealedBody{Enc: x.Enc, CT: x.CT}
	writeJSON(w, 200, v)
}

type tasksRequest struct {
	runauth.Where
	Tasks []string `json:"tasks"`
}

func (s *server) scheduleResultsDelete(w http.ResponseWriter, r *http.Request) {
	var req tasksRequest
	if !readCall(w, r, 16<<10, &req) {
		return
	}
	if len(req.Tasks) == 0 || len(req.Tasks) > resultsPage || slices.ContainsFunc(req.Tasks, func(t string) bool { return !harness.ValidTaskID(t) }) {
		failDetail(w, 400, "bad_request", "tasks: 1 to 50 task ids")
		return
	}
	who, ok := s.callWho(w, runauth.ResultsDeleteLabel, &req.Where, strings.Join(req.Tasks, ","))
	if !ok {
		return
	}
	n, err := s.results.DeleteResults(who.Space, who.Seal, req.Tasks)
	if err != nil {
		fail(w, 500, "store_unavailable")
		return
	}
	writeJSON(w, 200, map[string]int{"deleted": n})
}

// ---- results ------------------------------------------------------------------------------------------------

// resultBody is a sealed result's plaintext (SCHEDULES.md, "Fetch a result").
type resultBody struct {
	Type        string    `json:"type"`
	Task        string    `json:"task"`
	Space       string    `json:"space"`
	Agent       string    `json:"agent"`
	Version     uint64    `json:"version"`
	Trigger     string    `json:"trigger"`
	Day         string    `json:"day,omitzero"`
	ScheduledAt time.Time `json:"scheduled_at"`
	StartedAt   time.Time `json:"started_at"`
	EndedAt     time.Time `json:"ended_at"`
	State       string    `json:"state"`
	Code        string    `json:"code"`
	// Quiet: a notify-changes run found nothing that changed (schedule.no_change); Note is what it said it found.
	Quiet  bool          `json:"quiet,omitzero"`
	Note   string        `json:"note,omitzero"`
	Events []proto.Event `json:"events"`
}

func resultAAD(space, task string) []byte { return []byte(resultInfo + "\x00" + space + "\x00" + task) }

// resultEvents is what of a run's events the result keeps: text deltas joined per step, no reasoning or queue
// positions, no metrics but the web searches' (v0.13.0: the browser that saves the result reports them, so a
// scheduled run's failed searches and fallbacks reach the chat's request_metrics like a run in a tab), at most
// maxResultEvents (the end and the activity records always kept).
func resultEvents(evs []proto.Event) []proto.Event {
	var out []proto.Event
	for _, e := range evs {
		switch e.Type {
		case "reasoning", "queue", "meta":
			continue
		case "metrics":
			if e.Metrics == nil || e.Metrics.Kind != "search" {
				continue
			}
		case "text":
			if n := len(out); n > 0 && out[n-1].Type == "text" && out[n-1].Step == e.Step {
				out[n-1].Delta += e.Delta
				continue
			}
		}
		out = append(out, e)
	}
	if len(out) > maxResultEvents { // keep the last ones: the answer, the records and the end
		out = out[len(out)-maxResultEvents:]
	}
	return out
}

// dropOldest drops the oldest quarter of a result's events, but never a document's (guard/documents.go: its
// tool_call carries the content, its tool_result the checked name and format): a run whose result is a document
// keeps it whatever else has to go (at most guard.MaxDocuments of about 100 KB each fit in maxResultBytes). When
// the oldest quarter is all documents' events, it goes as before (the loop always ends).
func dropOldest(evs []proto.Event) []proto.Event {
	n := len(evs) / 4
	out := make([]proto.Event, 0, len(evs)-n)
	for i, e := range evs {
		if i < n && !isDocumentEvent(e) {
			continue
		}
		out = append(out, e)
	}
	if len(out) == len(evs) {
		return evs[n:]
	}
	return out
}

func isDocumentEvent(e proto.Event) bool {
	return (e.Type == "tool_call" || e.Type == "tool_result") && guard.ToolAction(e.Name) == guard.DocumentAction
}

// triggeredDone seals an ended unattended run's result to its definition's seal key, stores it, and forgets the task
// (guard.Host.TriggeredDone). A run without a seal key (none on this release) or a result that can't be sealed is
// forgotten with its keep as any task.
func (s *server) triggeredDone(id string, o guard.TaskOptions) {
	if s.results == nil || o.RecordTo == "" {
		return
	}
	var in *trigger.Installed
	if s.triggers != nil {
		in = s.triggers.Get(o.DefAgent)
	}
	if s.triggers != nil && in == nil { // removed while it ran: no result, and the run goes
		if err := s.rt.Forget(id); err != nil {
			log.Printf("schedules: a run wasn't forgotten: %v", err)
		}
		return
	}
	st, err := s.rt.Store.Task(id)
	if err != nil || st == nil {
		log.Printf("schedules: a result wasn't sealed: %v", err)
		return
	}
	evs, err := s.tasks().Events(id)
	if err != nil {
		log.Printf("schedules: a result wasn't sealed: %v", err)
		return
	}
	body := resultBody{Type: resultType, Task: id, Space: o.Space, Agent: o.DefAgent, Version: o.DefVersion, Trigger: o.Trigger,
		ScheduledAt: o.Due.UTC(), StartedAt: st.Created.UTC(), EndedAt: st.Ended.UTC(), State: st.Outcome, Events: resultEvents(evs)}
	if body.EndedAt.IsZero() {
		body.EndedAt = time.Now().UTC()
	}
	if o.Due.IsZero() {
		body.ScheduledAt = body.StartedAt
	} else {
		body.Day = trigger.DayOf(o.Slot)
	}
	for _, e := range evs {
		if e.Type == "error" && e.Code != "" {
			body.Code = e.Code
		}
	}
	if o.NoChange && body.State == harness.OutcomeSucceeded {
		body.Quiet, body.Note = guard.QuietRun(evs)
	}
	s.remember(in, o, id, &body, evs)
	b, err := jsonv2.Marshal(body)
	for err == nil && len(b) > maxResultBytes && len(body.Events) > 8 { // drop the oldest events until it fits
		body.Events = dropOldest(body.Events)
		b, err = jsonv2.Marshal(body)
	}
	if err != nil {
		log.Printf("schedules: a result wasn't sealed: %v", err)
		return
	}
	enc, ct, err := activity.SealTo(o.RecordTo, []byte(resultInfo), resultAAD(o.Space, id), b)
	clear(b)
	if err != nil {
		log.Printf("schedules: a result wasn't sealed: %v", err)
		return
	}
	if _, err := s.results.PutResult(trigger.Result{Task: id, Space: o.Space, Seal: o.RecordTo, Agent: o.DefAgent, Version: o.DefVersion,
		Trigger: o.Trigger, Day: body.Day, ScheduledAt: body.ScheduledAt, StartedAt: body.StartedAt, EndedAt: body.EndedAt,
		State: body.State, Code: body.Code, Quiet: body.Quiet, Enc: enc, CT: ct}); err != nil {
		log.Printf("schedules: a result wasn't stored: %v", err)
		return
	}
	// A new message for the person: their devices get a content-free notice, if they turned it on (notify.go).
	if resultNotifies(&body) {
		s.notify.Mark(o.Space, notifyDone)
	}
	// Sealed and stored: the run's plaintext (its start, journal and events) goes now.
	if err := s.rt.Forget(id); err != nil {
		log.Printf("schedules: a run wasn't forgotten: %v", err)
	}
}

// remember keeps what a finished run of a schedule with memory found (trigger/memory.go): its result's text and
// cited sources, or its note when quiet. Only a run that succeeded, of a schedule that (still) has memory.
func (s *server) remember(in *trigger.Installed, o guard.TaskOptions, task string, body *resultBody, evs []proto.Event) {
	if s.memory == nil || in == nil || !in.Def.Memory || !o.Memory || body.State != harness.OutcomeSucceeded {
		return
	}
	m := trigger.Remembered{Space: o.Space, Agent: o.DefAgent, Task: task, Day: body.Day, EndedAt: body.EndedAt, Quiet: body.Quiet}
	if m.Quiet {
		m.Text = body.Note
	} else if m.Text, m.Sources = guard.RunMemory(evs); m.Text == "" {
		return
	}
	if err := s.memory.PutMemory(m); err != nil {
		log.Printf("schedules: memory not kept: %v", err)
	}
}

// scheduleMemory is a schedule's memory for its next run (guard.Host.Memory): the newest runs within MemoryKeep.
// policyAllows says whether the space's effective policy allows action (guard.Host.Allows): a fired run is offered
// document_create and schedule_no_change only under a policy with their connectors (chat-v4); under an older one it
// runs without them.
func (s *server) policyAllows(space, action string) bool {
	if s.safety == nil {
		return true
	}
	e, err := s.safety.Policy(space)
	return err == nil && e.AllowsTool(action)
}

// pruneMemory drops memories past their keep (30 days) and every memory of a schedule that isn't installed in its
// space with memory on: one removed, or replaced by a version without memory, while a release that never reads
// memory ran (a rollback to v0.14.0, whose remove deletes the definition and results but not this table).
func (s *server) pruneMemory() {
	if s.memory == nil || s.triggers == nil {
		return
	}
	if err := s.memory.PruneMemory(time.Now().Add(-trigger.MemoryKeep)); err != nil {
		log.Printf("schedules: %v", err)
	}
	n, err := s.memory.PruneMemoryExcept(func(space, agent string) bool {
		in := s.triggers.Get(agent)
		return in != nil && in.Def.Space == space && in.Def.Memory
	})
	if err != nil {
		log.Printf("schedules: %v", err)
	} else if n > 0 {
		log.Printf("schedules: %d memories of schedules no longer installed deleted", n) // no ids
	}
}

func (s *server) scheduleMemory(space, agent string) ([]trigger.Remembered, error) {
	if s.memory == nil {
		return nil, nil
	}
	return s.memory.Memories(space, agent, time.Now().Add(-trigger.MemoryKeep))
}

// pruneResults drops results past their keep and prunes memories (pruneMemory), at once (agentd's start: main loads
// the definitions first) and then every hour, until ctx ends.
func (s *server) pruneResults(ctx context.Context) {
	for {
		if err := s.results.PruneResults(time.Now().Add(-trigger.ResultKeep)); err != nil {
			log.Printf("schedules: %v", err)
		}
		s.pruneMemory()
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Hour):
		}
	}
}
