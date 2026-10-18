package main

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"

	"github.com/tacyhq/tacy/guard"
	"github.com/tacyhq/tacy/harness"
	"github.com/tacyhq/tacy/proto"
	"github.com/tacyhq/tacy/safety"
)

// Step 6 on the runtime's side (docs/23-safety-controls.md). agentd checks every task and every brain request
// against the signed controls it verified itself before the guard sees them:
//   - admission: the space isn't stopped, a policy covers it (when admin keys are pinned), the model is allowed,
//     the day's budget isn't used up; the policy narrows the task's tools and its deadline;
//   - budgets: each model call and action reserves what it may use from the run's and the space's day budget,
//     under one lock, before it runs (parallel requests can't each see room only one has), then commits what it
//     used;
//   - the kill switch: when a stop list stops a running task's space (or the stop list goes stale and the policy
//     stops reads too), the task is cancelled ("kill_switch") within seconds;
//   - people see why (proto.Event.Code) and which policy the run started under (meta.controls).
// gatewayd and vaultd check the same documents again on their own.

// safeGateway wraps the guard (gatewayd's client, or this process's guard) with those checks. It is both the
// runtime's harness.Guard and Run's guard.Gateway.
type safeGateway struct {
	inner  guard.Gateway
	st     *safety.State
	ledger *safety.Ledger
	cancel func(task, reason string) // the runtime's Cancel (set once the runtime exists)

	mu    sync.Mutex
	tasks map[string]*safeTask
}

type safeTask struct {
	space     string
	code, msg string // the first control that refused something (Why)
}

var (
	_ guard.Gateway       = (*safeGateway)(nil)
	_ harness.ReplayGuard = (*safeGateway)(nil)
)

func newSafeGateway(inner guard.Gateway, st *safety.State, ledger *safety.Ledger) *safeGateway {
	return &safeGateway{inner: inner, st: st, ledger: ledger, tasks: map[string]*safeTask{}}
}

// people's wording for each code; the code itself goes in the event too.
var codeText = map[string]string{
	safety.CodeStopped:        "this agent was stopped by an administrator's stop",
	safety.CodeStale:          "the agent VM couldn't confirm it may go on (its stop list is out of date)",
	safety.CodePolicyMissing:  "no signed policy covers this space yet",
	safety.CodePolicyDenied:   "the policy doesn't allow this",
	safety.CodeBudgetExceeded: "a budget is used up",
	safety.CodeRateLimited:    "too many requests right now; try again in a minute",
}

// coded makes the message people see: "<code>: <the rule>" (the code's plain words when the rule says nothing).
func coded(err error) (string, string) {
	var se *safety.Error
	if !errors.As(err, &se) {
		return "", err.Error()
	}
	return se.Code, fmt.Sprintf("%s: %s", se.Code, cmp.Or(se.Msg, codeText[se.Code]))
}

// StartFor applies the policy to a chat request before the guard makes its task: stopped, no policy, a model the
// policy doesn't allow and a used-up day are refused (*safety.Error); tools the policy doesn't allow are taken
// out (the model never sees them); the deadline is the earliest of the run's, the policy's and the day's.
func (g *safeGateway) StartFor(r *proto.RunRequest) (harness.Start, guard.TaskOptions, error) {
	const space = "s_chat" // guard.StartFor's (one space until step 8)
	e, err := g.st.Check(space, false)
	if err != nil {
		return harness.Start{}, guard.TaskOptions{}, err
	}
	model := r.Model
	if model == "" {
		model = proto.DefaultModel
	}
	if !e.AllowsModel(model) {
		return harness.Start{}, guard.TaskOptions{}, &safety.Error{Code: safety.CodePolicyDenied, Msg: "model " + model + " isn't allowed by the policy"}
	}
	if r.Tools == nil {
		r.Tools = guard.AllTools()
	}
	tools := []string{} // not nil: none at all is a choice, not "all"
	for _, t := range r.Tools {
		if a := guard.ToolAction(t); a == "" || e.AllowsTool(a) {
			tools = append(tools, t) // unknown names stay, for the guard's own error
		}
	}
	r.Tools = tools
	end, err := g.ledger.Admit(space, e.Budget())
	if err != nil {
		return harness.Start{}, guard.TaskOptions{}, err
	}
	start, opts, err := g.inner.StartFor(r)
	if err != nil {
		return start, opts, err
	}
	if start.Space != space {
		return start, opts, errors.New("safety: unexpected space")
	}
	if d, err := time.Parse(time.RFC3339, start.Limits.Deadline); err == nil && !end.IsZero() && end.Before(d) {
		start.Limits.Deadline = end.UTC().Format(time.RFC3339)
	}
	return start, opts, nil
}

// Open registers the task (budgets, kill switch) and wraps its session (meta carries the controls).
func (g *safeGateway) Open(id string, opts guard.TaskOptions, emit func(proto.Event) error) guard.Session {
	g.ledger.Begin(id, opts.Space)
	g.mu.Lock()
	g.tasks[id] = &safeTask{space: opts.Space}
	g.mu.Unlock()
	return &safeSession{Session: g.inner.Open(id, opts, emit), g: g, id: id, space: opts.Space}
}

type safeSession struct {
	guard.Session
	g     *safeGateway
	id    string
	space string
}

func (s *safeSession) Meta(ctx context.Context) (*proto.Meta, error) {
	m, err := s.Session.Meta(ctx)
	if m != nil {
		st := s.g.st.StatusOf(s.space)
		m.Controls = &proto.Controls{Policy: st.Policy, ReleasePolicy: st.Release, OperatorSeq: st.OperatorSeq,
			FirmSeq: st.FirmSeq, Fresh: st.Fresh}
	}
	return m, err
}

// Background passes on the guard session's egress outside any request (site icons).
func (s *safeSession) Background() guard.FactsData {
	if b, ok := s.Session.(guard.BackgroundSession); ok {
		return b.Background()
	}
	return guard.FactsData{}
}

func (s *safeSession) Close() {
	s.Session.Close()
	s.g.ledger.End(s.id)
	s.g.mu.Lock()
	delete(s.g.tasks, s.id)
	s.g.mu.Unlock()
}

// trip records the first control that refused something in a task (what Why says if the run fails).
func (g *safeGateway) trip(task string, err error) {
	code, msg := coded(err)
	if code == "" {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if t := g.tasks[task]; t != nil && t.code == "" {
		t.code, t.msg = code, msg
	}
}

// Why says which control ended a task, when one did (guard.Run's error event).
func (g *safeGateway) Why(task string) (string, string) {
	g.mu.Lock()
	t := g.tasks[task]
	g.mu.Unlock()
	if t == nil {
		return "", ""
	}
	if t.code != "" {
		return t.code, t.msg
	}
	// The deadline came from a running-time budget tighter than the run's own 5 minutes, or the day's.
	e, err := g.st.Policy(t.space)
	el, ok := g.ledger.Elapsed(task)
	if err != nil || !ok {
		return "", ""
	}
	b := e.Budget()
	runOut := b.Run.WallSeconds > 0 && b.Run.WallSeconds < 300 && el >= time.Duration(b.Run.WallSeconds)*time.Second
	_, dayErr := g.ledger.Admit(t.space, b)
	if runOut || b.Day.WallSeconds > 0 && dayErr != nil {
		return coded(&safety.Error{Code: safety.CodeBudgetExceeded, Msg: "running time"})
	}
	return "", ""
}

func (g *safeGateway) space(ti *harness.TaskInfo) string {
	var o guard.TaskOptions
	if ti.Options != nil && json.Unmarshal(ti.Options, &o) == nil && o.Space != "" {
		return o.Space
	}
	if ti.Start != nil {
		return ti.Start.Space
	}
	return ""
}

// refuse is a harness error for a control's refusal; the task records why.
func (g *safeGateway) refuse(task, hcode string, err error) error {
	g.trip(task, err)
	_, msg := coded(err)
	return harness.Errf(hcode, "%s", msg)
}

func (g *safeGateway) ModelCall(ctx context.Context, ti *harness.TaskInfo, req *harness.ModelCall) (*harness.ModelResult, error) {
	e, err := g.st.Check(g.space(ti), guard.Effect(req))
	if err != nil {
		return nil, g.refuse(ti.ID, harness.CodeNotAllowed, err)
	}
	if !e.AllowsModel(req.Model) {
		return nil, g.refuse(ti.ID, harness.CodeNotAllowed, &safety.Error{Code: safety.CodePolicyDenied, Msg: "model " + req.Model})
	}
	n := 0
	for _, m := range req.Messages {
		n += len(m.Content) + 64
		for _, c := range m.ToolCalls {
			n += len(c.Args) + len(c.RawArgs) + 64
		}
	}
	prompt := safety.EstimateTokens(n)
	b := e.Budget()
	// The completion gets what the budget has left, at most CompletionReserve; the guard ends the call if its
	// output passes it (the upstream sets no cap of its own).
	completion := int64(safety.CompletionReserve)
	if left := g.ledger.TokensLeft(ti.ID, b); left >= 0 {
		completion = min(completion, left-prompt)
	}
	if completion < safety.MinCompletion {
		return nil, g.refuse(ti.ID, harness.CodeLimit, &safety.Error{Code: safety.CodeBudgetExceeded, Msg: "the budget for model tokens is used up"})
	}
	want := safety.Usage{Tokens: prompt + completion, CostMicros: safety.ModelCost(req.Model, prompt, completion)}
	commit, err := g.ledger.Reserve(ti.ID, want, b)
	if err != nil {
		return nil, g.refuse(ti.ID, harness.CodeLimit, err)
	}
	res, err := g.inner.ModelCall(guard.WithMaxTokens(ctx, completion), ti, req)
	// What it cost: the model's own count; without one (no usage reported, or the call failed after it started
	// and the provider may bill what it streamed) the whole reservation, never less.
	used := want
	if err == nil && res != nil && res.Usage.Prompt+res.Usage.Completion > 0 {
		p, c := int64(res.Usage.Prompt), int64(res.Usage.Completion)
		used = safety.Usage{Tokens: p + c, CostMicros: safety.ModelCost(req.Model, p, c)}
	}
	commit(used)
	g.tripFromGuard(ti.ID, err)
	return res, err
}

func (g *safeGateway) Action(ctx context.Context, ti *harness.TaskInfo, id string, req *harness.Action) (*harness.ActionResult, error) {
	e, err := g.st.Check(g.space(ti), guard.Effect(req))
	if err != nil {
		return nil, g.refuse(ti.ID, harness.CodeNotAllowed, err)
	}
	if !e.AllowsTool(req.Name) {
		why := "isn't allowed by the policy"
		if e.NeedsApproval(req.Name) {
			why = "needs approval, which isn't available yet"
		}
		return &harness.ActionResult{Status: harness.ActionDenied, Error: safety.CodePolicyDenied + ": " + req.Name + " " + why}, nil
	}
	want := safety.Usage{ToolCalls: 1}
	if req.Name == "web.search" || req.Name == "web.images" {
		want.CostMicros = safety.SearchCost
	}
	// The quarantined reader's model call for a page or a search (guard/reader.go) is reserved with the action, at
	// its largest: an action whose reader the budget can't cover doesn't run (the model never gets raw text instead).
	reader := readerReserve(req.Name, e)
	commit, err := g.ledger.Reserve(ti.ID, addUsage(want, reader), e.Budget())
	if err != nil {
		return nil, g.refuse(ti.ID, harness.CodeLimit, err)
	}
	f := guard.FactsFrom(ctx)
	if f == nil {
		f = &guard.Facts{}
		ctx = guard.WithFacts(ctx, f)
	}
	res, err := g.inner.Action(ctx, ti, id, req)
	commit(addUsage(want, readerUsed(f.Data().Reader, reader))) // a tool call counts whether or not it worked
	g.tripFromGuard(ti.ID, err)
	if res != nil && res.Error != "" && strings.HasPrefix(res.Error, safety.CodeRateLimited) {
		g.trip(ti.ID, &safety.Error{Code: safety.CodeRateLimited, Msg: strings.TrimPrefix(res.Error, safety.CodeRateLimited+": ")})
	}
	return res, err
}

// readerReserve is the budget the reader's call for action may use (zero for actions it doesn't read, or when the
// policy doesn't allow its model: gatewayd then refuses the reader and shows nothing of the source).
func readerReserve(action string, e *safety.Effective) safety.Usage {
	model, p, c, ok := guard.ReaderReserve(action)
	if !ok || !e.AllowsModel(model) {
		return safety.Usage{}
	}
	return safety.Usage{Tokens: p + c, CostMicros: safety.ModelCost(model, p, c)}
}

// readerUsed is what the reader's calls cost: the model's own counts, or, for a call that reached the model
// without counts (it may be billed), the whole reservation, never less.
func readerUsed(calls []guard.ReaderUse, reserved safety.Usage) safety.Usage {
	var u safety.Usage
	for _, c := range calls {
		switch {
		case c.Prompt+c.Completion > 0:
			p, q := int64(c.Prompt), int64(c.Completion)
			u = addUsage(u, safety.Usage{Tokens: p + q, CostMicros: safety.ModelCost(c.Model, p, q)})
		case c.Sent:
			u = addUsage(u, reserved)
		}
	}
	return u
}

func addUsage(a, b safety.Usage) safety.Usage {
	return safety.Usage{Tokens: a.Tokens + b.Tokens, ToolCalls: a.ToolCalls + b.ToolCalls, CostMicros: a.CostMicros + b.CostMicros,
		WallMs: a.WallMs + b.WallMs}
}

// tripFromGuard notes a refusal gatewayd or the vault made on its own ("stopped: …", "rate_limited: …").
func (g *safeGateway) tripFromGuard(task string, err error) {
	var pe *harness.Error
	if !errors.As(err, &pe) {
		return
	}
	for code := range codeText {
		if strings.HasPrefix(pe.Message, code+":") {
			g.trip(task, &safety.Error{Code: code, Msg: strings.TrimPrefix(pe.Message, code+": ")})
			return
		}
	}
}

func (g *safeGateway) Exec(ctx context.Context, ti *harness.TaskInfo, id string, req *harness.Exec) (*harness.ExecResult, error) {
	if _, err := g.st.Check(g.space(ti), true); err != nil {
		return nil, g.refuse(ti.ID, harness.CodeNotAllowed, err)
	}
	return g.inner.Exec(ctx, ti, id, req)
}

func (g *safeGateway) ReplaySafe(_ *harness.TaskInfo, req any) bool { return guard.ReplaySafe(req) }

// Untrusted: the web connector's results taint the task (guard.Untrusted; docs/27 section 5).
func (g *safeGateway) Untrusted(_ *harness.TaskInfo, req any) bool { return guard.Untrusted(req) }

// TaintedAtStart: an earlier assistant turn in the input taints the task from its start (guard.StartTaint).
func (g *safeGateway) TaintedAtStart(s *harness.Start) string { return guard.StartTaint(s) }

var _ harness.StartTaintGuard = (*safeGateway)(nil)

var _ guard.TaskResumer = (*safeGateway)(nil)

// ResumeTask takes up a task's budget after an agentd restart (guard.TaskResumer): what its journal shows it used
// counts against its run budget again, and its running time counts from when it started. Without it a restart would
// hand a task a fresh budget. The session it then opens registers it for the kill switch, as any task.
func (g *safeGateway) ResumeTask(task string, start *harness.Start, opts guard.TaskOptions, started time.Time, journal []harness.Record) {
	g.ledger.Resume(task, cmp.Or(opts.Space, start.Space), started, journalUsage(journal))
}

// journalUsage is what a task's journal shows it used, counted as the checks above count it: each model call by
// the model's own usage (one without a result, which may have been billed, by its prompt's estimate), each action
// that ran or may have run as a tool call (searches with their cost). Refusals and denials used nothing.
func journalUsage(recs []harness.Record) safety.Usage {
	var u safety.Usage
	for _, r := range recs {
		switch r.Kind {
		case harness.TypeModelCall:
			var req harness.ModelCall
			jsonv2.Unmarshal(r.Req, &req)
			var res harness.ModelResult
			if r.Done && r.Err == nil && jsonv2.Unmarshal(r.Body, &res) == nil && res.Usage.Prompt+res.Usage.Completion > 0 {
				p, c := int64(res.Usage.Prompt), int64(res.Usage.Completion)
				u.Tokens += p + c
				u.CostMicros += safety.ModelCost(req.Model, p, c)
			} else if !r.Done || r.Err != nil && r.Err.Code == harness.CodeInternal {
				p := safety.EstimateTokens(len(r.Req))
				u.Tokens += p
				u.CostMicros += safety.ModelCost(req.Model, p, 0)
			}
		case harness.TypeAction:
			var req harness.Action
			jsonv2.Unmarshal(r.Req, &req)
			var res harness.ActionResult
			ran := !r.Done && r.Held == "" || r.Done && r.Err == nil && jsonv2.Unmarshal(r.Body, &res) == nil && res.Status != harness.ActionDenied
			if ran {
				u.ToolCalls++
				if req.Name == "web.search" || req.Name == "web.images" {
					u.CostMicros += safety.SearchCost
				}
				// The reader read its source (its answer or its refusal is in the output): counted at its
				// reservation, since the journal doesn't keep the reader's own counts. On the high side, never low.
				if readOutput(res.Output) {
					if model, p, c, ok := guard.ReaderReserve(req.Name); ok {
						u.Tokens += p + c
						u.CostMicros += safety.ModelCost(model, p, c)
					}
				}
			}
		}
	}
	return u
}

// readOutput: a journaled web action's output came from the quarantined reader (it has "read" or "reader").
func readOutput(out []byte) bool {
	var o map[string]jsontext.Value
	if len(out) == 0 || jsonv2.Unmarshal(out, &o) != nil {
		return false
	}
	_, read := o["read"]
	_, reader := o["reader"]
	return read || reader
}

// enforce is the kill switch: whenever the controls change, and every few seconds (staleness comes with time),
// every running task whose space may no longer run is cancelled.
func (g *safeGateway) enforce(ctx context.Context, every time.Duration) {
	for {
		changed := g.st.Changed() // before the sweep: a change during it wakes the next one at once
		g.mu.Lock()
		var stop []string
		for id, t := range g.tasks {
			if _, err := g.st.Check(t.space, false); err != nil {
				if t.code == "" {
					t.code, t.msg = coded(err)
				}
				stop = append(stop, id)
			}
		}
		g.mu.Unlock()
		for _, id := range stop {
			if g.cancel != nil {
				g.cancel(id, "kill_switch")
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-changed:
		case <-time.After(every):
		}
	}
}

// ---- POST /safety: signed documents in --------------------------------------------------------------------------

// safetyIn takes signed policies and stop lists from anyone: an admin's browser, the operator, the relay, or
// gatewayd's poller. The signatures are the authorization (no bearer token), so a stop reaches the VM even when
// our control plane is down; whatever doesn't verify against the pinned keys, or is older than what the VM holds,
// is refused. Accepted documents go on to gatewayd (and from there to the vault) at once.
func (s *server) safetyIn(w http.ResponseWriter, r *http.Request) {
	// The body is read first, capped in size and time, so a slow sender can't hold a slot: the slots only bound
	// the signature checks.
	http.NewResponseController(w).SetReadDeadline(time.Now().Add(5 * time.Second))
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 8*2*safety.MaxEnvelope))
	if err != nil {
		fail(w, 400, "unreadable or oversize body")
		return
	}
	select {
	case s.safetySlots <- struct{}{}:
		defer func() { <-s.safetySlots }()
	default:
		fail(w, 429, "busy")
		return
	}
	docs, err := safety.DecodeEnvelopes(body)
	if err != nil {
		fail(w, 400, err.Error())
		return
	}
	errs, changed := s.safety.Apply(docs)
	out := struct {
		Results []string      `json:"results"` // "ok" or why it was refused, per document
		Status  safety.Status `json:"status"`
	}{Status: s.safety.StatusOf("s_chat")}
	for _, e := range errs {
		if e == nil {
			out.Results = append(out.Results, "ok")
		} else {
			out.Results = append(out.Results, e.Error())
		}
	}
	if changed {
		s.pushSafety()
	}
	writeJSON(w, 200, out)
}

// pushSafety passes agentd's documents to gatewayd now (in the background; the next session's open carries them
// too).
func (s *server) pushSafety() {
	c, ok := s.gw.(interface {
		PushDocs(context.Context, []safety.Envelope) error
	})
	if !ok {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := c.PushDocs(ctx, s.safety.Docs()); err != nil {
			log.Printf("safety: passing documents to gatewayd: %v", err)
		}
	}()
}
