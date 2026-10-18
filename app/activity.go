package main

import (
	"cmp"
	"context"
	"crypto/ecdh"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/tacyhq/tacy/activity"
	"github.com/tacyhq/tacy/guard"
	"github.com/tacyhq/tacy/harness"
	"github.com/tacyhq/tacy/proto"
	"github.com/tacyhq/tacy/safety"
)

// The recorder (docs/24-activity-records.md). recGateway wraps the safety checks (safeGateway) and the guard under
// them: it is the runtime's harness.Guard and Run's gateway, so it sees every model call and action the runtime
// hands on, with what the guard (here or in gatewayd) saw and did for it: hosts, bytes, key leases, leak-scan
// decisions (guard.Facts), and the safety controls' refusals. A run's start record is written when it starts,
// its end record when it ends; both go to the person in the run's last event before done or error (sealed to the
// key they sent, so only they can read them) and stay on the VM's disk for 30 days for the relay to fetch
// (GET /activity), so a record the browser didn't keep isn't lost. Records hold metadata only: no prompt, answer,
// query, URL path or page.

// recordKeep is how long the VM keeps sealed records (heads and open runs stay).
const recordKeep = 30 * 24 * time.Hour

type recGateway struct {
	*safeGateway
	rec *activity.Recorder
	// vmKey is this boot's EHBP private key: a run's record_to must come with a proof made against it
	// (activity.RecordProof), so nobody can open records in, or read the length of, a chain whose key they don't hold.
	vmKey *ecdh.PrivateKey

	mu    sync.Mutex
	bg    map[string]guard.FactsData // site icons' egress per task, from the session's End
	calls map[string]int             // calls in the guard per task
	// history: recorded tasks tainted from their start (an earlier assistant turn in the input; guard.StartTaint),
	// so their end record says tainted even if no call of theirs brought outside content.
	history map[string]bool
	// prompts holds actions that send data out until the person answered (guard.Prompts); nil: none held
	// (gatewayd then refuses every kind not set to Always allow).
	prompts *guard.Prompts
}

var (
	_ guard.Gateway       = (*recGateway)(nil)
	_ guard.RunObserver   = (*recGateway)(nil)
	_ harness.ReplayGuard = (*recGateway)(nil)
)

func newRecGateway(sg *safeGateway, rec *activity.Recorder, vmKey *ecdh.PrivateKey) *recGateway {
	return &recGateway{safeGateway: sg, rec: rec, vmKey: vmKey, bg: map[string]guard.FactsData{}}
}

// StartFor: the safety checks, then the recipient of the run's record into its options.
func (g *recGateway) StartFor(r *proto.RunRequest) (harness.Start, guard.TaskOptions, error) {
	if r.RecordTo != "" {
		if _, err := activity.ParseRecipient(r.RecordTo); err != nil {
			return harness.Start{}, guard.TaskOptions{}, errors.New("record_to must be an x25519 public key")
		}
		if g.vmKey == nil || activity.CheckRecordProof(g.vmKey, r.RecordTo, r.RecordProof) != nil {
			return harness.Start{}, guard.TaskOptions{}, errors.New("record_to needs a valid record_proof")
		}
	}
	start, opts, err := g.safeGateway.StartFor(r)
	opts.RecordTo = r.RecordTo
	return start, opts, err
}

// Open wraps the session so its End passes on the site icons' egress.
func (g *recGateway) Open(id string, opts guard.TaskOptions, emit func(proto.Event) error) guard.Session {
	return &recSession{Session: g.safeGateway.Open(id, opts, emit), g: g, id: id}
}

type recSession struct {
	guard.Session
	g  *recGateway
	id string
}

func (s *recSession) End() (int, string) {
	step, finish := s.Session.End()
	if b, ok := s.Session.(guard.BackgroundSession); ok {
		s.g.mu.Lock()
		s.g.bg[s.id] = b.Background()
		s.g.mu.Unlock()
	}
	return step, finish
}

func (s *recSession) Close() {
	s.Session.Close()
	if s.g.prompts != nil {
		s.g.prompts.Forget(s.id)
	}
	s.g.mu.Lock()
	delete(s.g.bg, s.id)
	s.g.mu.Unlock()
}

// RunStarted writes the run's start record and tells the browser (meta.activity) the signing key and where the
// chain stood before this run.
func (g *recGateway) RunStarted(task string, start *harness.Start, opts guard.TaskOptions, meta *proto.Meta) {
	if opts.RecordTo == "" {
		return
	}
	g.noteHistory(task, start)
	rec, err := g.rec.Begin(recordStart(task, start, opts, controlsOf(meta.Controls), "relay"))
	if err != nil {
		log.Printf("activity: start record not written: %v", err) // the run goes on; its record's absence shows in the chain
		return
	}
	h, _, _ := activity.Check(rec, nil)
	if h != nil {
		meta.Activity = &proto.Activity{Key: g.rec.Signer.Public(), Chain: h.Chain, Seq: h.Seq - 1, Head: h.Prev}
	}
}

// recordStart is a task's start record: who it runs as, under which controls, with what it may use; sizes only.
func recordStart(task string, start *harness.Start, opts guard.TaskOptions, controls *activity.Controls, via string) activity.Start {
	in := activity.Input{Messages: len(start.Input)}
	for _, m := range start.Input {
		in.Bytes += len(m.Content)
	}
	var tools []string
	for _, t := range start.Tools {
		tools = append(tools, t.Name)
	}
	return activity.Start{Run: task, Space: start.Space, To: opts.RecordTo,
		Agent:   activity.Agent{ID: start.Agent.ID, Version: start.Agent.Version, Digest: start.Agent.Digest},
		Trigger: activity.Trigger{Kind: "chat", Via: via}, Controls: controls, Models: start.Models, Tools: tools,
		Limits: activity.Limits{MaxSteps: start.Limits.MaxSteps, MaxModelCalls: start.Limits.MaxModelCalls, Deadline: start.Limits.Deadline},
		Input:  in}
}

var _ guard.TaskResumer = (*recGateway)(nil)

// ResumeTask takes up a task after an agentd restart (guard.TaskResumer): its budget (safeGateway), and its record.
// The old process's part of the run was ended "interrupted" at boot (Recorder.Recover); what the task does from here
// is a new start record under the same task id (trigger via "resume"), ended when the task ends, so the chain shows
// both parts and what happened while the VM was down is never claimed.
func (g *recGateway) ResumeTask(task string, start *harness.Start, opts guard.TaskOptions, started time.Time, journal []harness.Record) {
	g.safeGateway.ResumeTask(task, start, opts, started, journal)
	if opts.RecordTo == "" {
		return
	}
	g.noteHistory(task, start)
	st := g.st.StatusOf(cmp.Or(opts.Space, start.Space))
	c := &activity.Controls{Policy: st.Policy, ReleasePolicy: st.Release, OperatorSeq: st.OperatorSeq, FirmSeq: st.FirmSeq, Fresh: st.Fresh}
	if _, err := g.rec.Begin(recordStart(task, start, opts, c, "resume")); err != nil {
		log.Printf("activity: resumed start record not written: %v", err)
	}
}

func controlsOf(c *proto.Controls) *activity.Controls {
	if c == nil {
		return nil
	}
	return &activity.Controls{Policy: c.Policy, ReleasePolicy: c.ReleasePolicy, OperatorSeq: c.OperatorSeq, FirmSeq: c.FirmSeq, Fresh: c.Fresh}
}

// RunEnded writes the run's end record and returns the activity event with its start and end records.
func (g *recGateway) RunEnded(task string, e guard.RunEnd) []proto.Event {
	if !g.rec.Recording(task) {
		return nil
	}
	g.settle(task, 2*time.Second)
	end := activity.End{Status: activity.Status{State: e.State, Code: e.Code, Reason: e.Reason, Finish: e.Finish, Detail: e.Msg}, Steps: e.Steps}
	if u, ok := g.ledger.Used(task); ok {
		end.Usage = &activity.Usage{Tokens: u.Tokens, ToolCalls: u.ToolCalls, CostMicros: u.CostMicros}
		if el, ok := g.ledger.Elapsed(task); ok {
			end.Usage.WallMs = el.Milliseconds()
		}
	}
	g.mu.Lock()
	end.Background = g.bg[task].Hosts
	end.BackgroundImages = g.bg[task].Images
	end.CardPictures = g.bg[task].CardPictures
	end.Tainted = g.history[task]
	delete(g.history, task)
	g.mu.Unlock()
	recs, err := g.rec.Finish(task, end)
	if err != nil {
		log.Printf("activity: end record not written: %v", err)
		return nil
	}
	return []proto.Event{activityEvent(recs...)}
}

// noteHistory remembers a recorded task that is tainted from its start (guard.StartTaint).
func (g *recGateway) noteHistory(task string, start *harness.Start) {
	if guard.StartTaint(start) == "" {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.history == nil {
		g.history = map[string]bool{}
	}
	g.history[task] = true
}

func activityEvent(recs ...activity.Sealed) proto.Event {
	ev := proto.Event{Type: "activity"}
	for _, r := range recs {
		b, _ := json.Marshal(r)
		ev.Activity = append(ev.Activity, b)
	}
	return ev
}

// Refused records a run refused before it started (agentd's admission: a stop, no policy, a model the policy
// doesn't allow, the day used up) and returns the event that carries its record, or false.
func (g *recGateway) Refused(r *proto.RunRequest, err error) (proto.Event, bool) {
	if r.RecordTo == "" {
		return proto.Event{}, false
	}
	const space = "s_chat"
	st := g.st.StatusOf(space)
	code, msg := coded(err)
	model := r.Model
	if model == "" {
		model = proto.DefaultModel
	}
	in := activity.Input{Messages: len(r.Messages)}
	for _, m := range r.Messages {
		in.Bytes += len(m.Content)
	}
	rec, rerr := g.rec.Refused(activity.Start{Run: harness.NewTaskID(), Space: space, To: r.RecordTo,
		Agent: activity.Agent{ID: "a_chat", Version: "1", Digest: "unsigned"}, Trigger: activity.Trigger{Kind: "chat", Via: "relay"},
		Controls: &activity.Controls{Policy: st.Policy, ReleasePolicy: st.Release, OperatorSeq: st.OperatorSeq, FirmSeq: st.FirmSeq, Fresh: st.Fresh},
		Models:   []string{model}, Input: in}, activity.Status{Code: code, Detail: msg})
	if rerr != nil {
		if !errors.Is(rerr, activity.ErrNoRecipient) {
			log.Printf("activity: refused record not written: %v", rerr)
		}
		return proto.Event{}, false
	}
	return activityEvent(rec), true
}

// ---- calls ------------------------------------------------------------------------------------------------------

// begin notes a request to the guard as running (so a run that ends while it runs records it as unfinished) and
// returns what finishes its entry: what the guard saw and did, how it ended.
func (g *recGateway) begin(ti *harness.TaskInfo, id, kind, name, connector string, req any) func(f *guard.Facts, res any, err error, ok func(c *activity.Call)) {
	if !g.rec.Recording(ti.ID) {
		return func(*guard.Facts, any, error, func(*activity.Call)) {}
	}
	t0 := time.Now()
	c := activity.Call{ID: id, Kind: kind, Name: name, Connector: connector, AtMs: t0.Sub(g.rec.StartedAt(ti.ID)).Milliseconds(),
		ReqBytes: jsonSize(req), Tainted: ti.Tainted && kind != "model"}
	i := g.rec.CallStart(ti.ID, c)
	g.inflight(ti.ID, 1)
	return func(f *guard.Facts, res any, err error, ok func(c *activity.Call)) {
		defer g.inflight(ti.ID, -1)
		d := f.Data()
		c.Hosts, c.Blocked, c.Redacted, c.Ms = d.Hosts, d.Blocked, d.Redacted, time.Since(t0).Milliseconds()
		c.Images = d.Images // web.images: pictures that didn't make it, by reason
		if n := len(d.Reader); n > 0 {
			u := d.Reader[n-1]
			c.Reader = &activity.Reader{Model: u.Model, Prompt: u.Prompt, Completion: u.Completion, Ms: u.Ms, Outcome: u.Outcome,
				Why: u.Why, Quotes: u.Quotes, Dropped: u.Dropped, Instructions: u.Instructions, Verbatim: u.Verbatim}
		}
		if kind == "model" && d.Model != "" {
			c.Name = d.Model // the model it ran on (a fallback after a switch, guard/fallback.go)
		}
		if err == nil {
			c.RespBytes = jsonSize(res)
			c.Outcome = "ok"
			ok(&c)
		} else {
			c.Outcome, c.Code = errOutcome(err)
		}
		// A call that didn't go through because the policy refused its host (the guard says so in words the
		// model reads, without a code): the record names the control.
		if c.Outcome != "ok" && c.Code == "" && slices.ContainsFunc(c.Hosts, func(h activity.Host) bool { return h.Refused > 0 }) {
			c.Code = safety.CodePolicyDenied
		}
		if len(d.Abandoned) == 0 {
			g.rec.CallEnd(ti.ID, i, c, d.Leases)
			return
		}
		// A model call given up as slow or overloaded, then made again on a fallback (guard/fallback.go): the
		// given-up call first (its model, why, its time, no tokens), then the call that answered, with the egress
		// and leases of both.
		at := c.AtMs
		for j, a := range d.Abandoned {
			gave := activity.Call{ID: c.ID, Kind: c.Kind, Name: a.Model, Connector: c.Connector, Outcome: a.Outcome, AtMs: at,
				Ms: a.Ms, ReqBytes: c.ReqBytes, Tainted: c.Tainted}
			if j == 0 {
				g.rec.CallEnd(ti.ID, i, gave, nil)
			} else {
				g.rec.Call(ti.ID, gave, nil)
			}
			at += a.Ms
		}
		c.Ms -= at - c.AtMs
		c.AtMs = at
		g.rec.Call(ti.ID, c, d.Leases)
	}
}

// inflight counts a task's calls still in the guard; RunEnded waits a moment for them (a cancelled call returns
// within milliseconds), so their outcome is on the record.
func (g *recGateway) inflight(task string, d int) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.calls == nil {
		g.calls = map[string]int{}
	}
	if g.calls[task] += d; g.calls[task] <= 0 {
		delete(g.calls, task)
	}
}

func (g *recGateway) settle(task string, wait time.Duration) {
	for deadline := time.Now().Add(wait); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		g.mu.Lock()
		n := g.calls[task]
		g.mu.Unlock()
		if n == 0 {
			return
		}
	}
}

func jsonSize(v any) int {
	b, err := json.Marshal(v)
	if err != nil {
		return 0
	}
	return len(b)
}

// errOutcome names how a request that didn't go through ended, by code only (never the message, which may quote
// what the guard was asked).
func errOutcome(err error) (string, string) {
	var pe *harness.Error
	if errors.Is(err, context.Canceled) || errors.As(err, &pe) && pe.Code == harness.CodeCancelled {
		return "cancelled", harness.CodeCancelled
	}
	if pe != nil && strings.HasPrefix(pe.Message, guard.CodeModelOverloaded+":") {
		return "overloaded", guard.CodeModelOverloaded // a hand-picked model the provider said is overloaded
	}
	if errors.As(err, &pe) {
		if c := controlCode(pe.Message); c != "" {
			return "refused", c
		}
		if pe.Code == harness.CodeNotAllowed || pe.Code == harness.CodeLimit {
			return "refused", pe.Code
		}
		return "failed", pe.Code
	}
	return "failed", harness.CodeInternal
}

// controlCode is the safety code a refusal's text starts with ("budget_exceeded: ..."), or "".
func controlCode(msg string) string {
	code, _, ok := strings.Cut(msg, ":")
	if !ok {
		return ""
	}
	if _, known := codeText[code]; known {
		return code
	}
	return ""
}

func (g *recGateway) ModelCall(ctx context.Context, ti *harness.TaskInfo, req *harness.ModelCall) (*harness.ModelResult, error) {
	f := &guard.Facts{}
	done := g.begin(ti, harness.RequestID(ctx), "model", req.Model, "model", req)
	res, err := g.safeGateway.ModelCall(guard.WithFacts(ctx, f), ti, req)
	done(f, res, err, func(c *activity.Call) {
		c.Prompt, c.Completion = res.Usage.Prompt, res.Usage.Completion
	})
	if err == nil && g.prompts != nil {
		g.prompts.ModelCalled(ti, res) // the taint its tool calls are asked about with (a composed address)
	}
	return res, err
}

func (g *recGateway) Action(ctx context.Context, ti *harness.TaskInfo, id string, req *harness.Action) (*harness.ActionResult, error) {
	f := &guard.Facts{}
	connector, _, _ := strings.Cut(req.Name, ".")
	done := g.begin(ti, id, "action", req.Name, connector, req)
	// Permission prompts: an action that sends data out goes on with the person's grant, or is denied here without running.
	var res *harness.ActionResult
	var err error
	if g.prompts != nil {
		ctx, res = g.prompts.Attach(ctx, ti, id, req)
	}
	if res == nil {
		res, err = g.safeGateway.Action(guard.WithFacts(ctx, f), ti, id, req)
	}
	done(f, res, err, func(c *activity.Call) {
		if g.prompts != nil {
			if o, ok := g.prompts.Outcome(ti.ID, id); ok {
				c.Permission, c.Edited = o.Outcome, o.Edited
			}
		}
		switch res.Status {
		case harness.ActionDenied:
			c.Outcome, c.Code = "denied", controlCode(res.Error)
		case harness.ActionFailed:
			c.Outcome, c.Code = "failed", controlCode(res.Error)
		case harness.ActionDone:
			c.Untrusted = guard.Untrusted(req)
		}
	})
	return res, err
}

var (
	_ harness.HoldGuard  = (*recGateway)(nil)
	_ guard.TaskFollower = (*recGateway)(nil)
)

// Hold: an action that would send data out waits for the person's answer (guard.Prompts.Hold).
func (g *recGateway) Hold(ti *harness.TaskInfo, id string, req any) string {
	if g.prompts == nil {
		return ""
	}
	return g.prompts.Hold(ti, id, req)
}

// TaskResumed shows a resumed task's waiting prompts again (guard.Prompts.Resume).
func (g *recGateway) TaskResumed(task string, start *harness.Start, opts guard.TaskOptions, journal []harness.Record) {
	if g.prompts == nil {
		return
	}
	b, err := json.Marshal(opts)
	if err != nil {
		return
	}
	g.prompts.Resume(&harness.TaskInfo{ID: task, Start: start, Options: b}, journal)
}

func (g *recGateway) Exec(ctx context.Context, ti *harness.TaskInfo, id string, req *harness.Exec) (*harness.ExecResult, error) {
	done := g.begin(ti, id, "exec", "exec", "hands", req)
	res, err := g.safeGateway.Exec(ctx, ti, id, req)
	done(nil, res, err, func(c *activity.Call) {
		if res.Exit != 0 || res.TimedOut {
			c.Outcome = "failed"
		}
	})
	return res, err
}

// ---- GET /activity: sealed records for the relay ----------------------------------------------------------------

// activityOut serves a chain's sealed records after a sequence number (the relay's bearer token: cost and
// metadata, since the records themselves are sealed and signed). The chat's Worker fetches what a browser didn't
// store, so a record is never lost because a tab closed.
func (s *server) activityOut(w http.ResponseWriter, r *http.Request) {
	if !s.authorized(r) {
		fail(w, 401, "unauthorized")
		return
	}
	chain := r.URL.Query().Get("chain")
	if b, err := hex.DecodeString(chain); err != nil || len(b) != 16 || strings.ToLower(chain) != chain {
		fail(w, 400, "chain must be 32 lowercase hex")
		return
	}
	after, err := strconv.ParseUint(r.URL.Query().Get("after"), 10, 64)
	if err != nil && r.URL.Query().Get("after") != "" {
		fail(w, 400, "after must be a number")
		return
	}
	recs, err := s.rec.Store.Records(chain, after, 100)
	if err != nil {
		fail(w, 500, "records unavailable")
		return
	}
	head, err := s.rec.Store.Head(chain)
	if err != nil {
		fail(w, 500, "records unavailable")
		return
	}
	if recs == nil {
		recs = []activity.Sealed{}
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, struct {
		Records []activity.Sealed `json:"records"`
		Head    activity.Link     `json:"head"`
		Key     string            `json:"key"`
	}{recs, head, s.rec.Signer.Public()})
}

// pruneActivity drops sealed records older than recordKeep, now and every hour.
func pruneActivity(ctx context.Context, st activity.Store) {
	for {
		if err := st.Prune(time.Now().Add(-recordKeep)); err != nil {
			log.Printf("activity: prune: %v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Hour):
		}
	}
}
