package main

import (
	"cmp"
	"context"
	"crypto/ecdh"
	"encoding/base64"
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
	"github.com/tacyhq/tacy/runauth"
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
	// vmKey is this boot's EHBP private key: a run's space and seal key must come with a proof made against it
	// (runauth.SpaceProof), so nobody can open records in, or read the length of, a chain whose key they don't hold,
	// and its identity's signature covers it, so a request can't be replayed to another boot.
	vmKey *ecdh.PrivateKey
	// nonces this boot took (Verify): a request runs at most once.
	nonces *runauth.Nonces

	mu    sync.Mutex
	bg    map[string]guard.FactsData // site icons' egress per task, from the session's End
	calls map[string]int             // calls in the guard per task
	// history: recorded tasks tainted from their start (an earlier assistant turn in the input; guard.StartTaint),
	// so their end record says tainted even if no call of theirs brought outside content.
	history map[string]bool
	// prompts holds actions that send data out until the person answered (guard.Prompts); nil: none held
	// (gatewayd then refuses every kind not set to Always allow).
	prompts *guard.Prompts
	// approvals holds actions that need a person's approval (approve before send, guard.Approvals); nil: none held
	// (gatewayd then refuses every action that needs one).
	approvals *guard.Approvals
}

var (
	_ guard.Gateway       = (*recGateway)(nil)
	_ guard.RunObserver   = (*recGateway)(nil)
	_ harness.ReplayGuard = (*recGateway)(nil)
)

func newRecGateway(sg *safeGateway, rec *activity.Recorder, vmKey *ecdh.PrivateKey) *recGateway {
	return &recGateway{safeGateway: sg, rec: rec, vmKey: vmKey, bg: map[string]guard.FactsData{}, nonces: &runauth.Nonces{}}
}

// Verify checks a request's where and who once, when it arrives (keys v2 slice 6, docs/26 section 6; package
// runauth), and notes what it verified in r.Verified, which StartFor then requires: the space proof and the identity's
// signature against this boot's attested key (so the request can't be replayed to another boot), the time, and the
// nonce, claimed here (so it runs at most once on this one). On a firm's VM the seal key must be the one the space's
// own signed policy names and the identity must be current in the firm key log with that key: the identity is then
// whose member budget the run uses. On the shared chat VM (State.PersonalSpaces) people's personal spaces have no
// signed policy: the seal key is the one the request proves, and the member budget is the relay's daily per-user tag
// user (accounts are free to make; only the relay knows who is who). Errors are plain (400): nothing was recorded.
func (g *recGateway) Verify(r *proto.RunRequest, user string) error {
	v, err := g.verify(func(vm *ecdh.PrivateKey) (runauth.Who, error) { return runauth.Check(vm, r, time.Now()) }, r.Nonce, r.SignedAt, user)
	if err == nil {
		r.Verified = v
	}
	return err
}

// VerifySearch is Verify for a plain chat's search (POST /search; v0.10.0): its own label and digest, the same
// space, identity and nonce checks, so a search is no unsigned way in and lands in the space's chain.
func (g *recGateway) VerifySearch(r *proto.SearchRequest, user string) error {
	v, err := g.verify(func(vm *ecdh.PrivateKey) (runauth.Who, error) { return runauth.CheckSearch(vm, r, time.Now()) }, r.Nonce, r.SignedAt, user)
	if err == nil {
		r.Verified = v
	}
	return err
}

// VerifyPictures is Verify for an answer's held-back pictures (POST /pictures; v0.10.0). The ticket is then good
// only in the space its run was in (guard/pictures.go takePictures).
func (g *recGateway) VerifyPictures(r *proto.PicturesRequest, user string) error {
	v, err := g.verify(func(vm *ecdh.PrivateKey) (runauth.Who, error) { return runauth.CheckPictures(vm, r, time.Now()) }, r.Nonce, r.SignedAt, user)
	if err == nil {
		r.Verified = v
	}
	return err
}

// verify is Verify's checks for any kind of request: check is its runauth check against this boot's key.
func (g *recGateway) verify(check func(vm *ecdh.PrivateKey) (runauth.Who, error), nonce string, signedAt int64, user string) (*proto.Verified, error) {
	if g.vmKey == nil {
		return nil, errors.New("this VM can't check a request's space proof")
	}
	who, err := check(g.vmKey)
	if err != nil {
		return nil, err
	}
	v := &proto.Verified{Space: who.Space, Seal: who.Seal, Identity: who.Identity, Member: user}
	if !g.st.PersonalSpaces() {
		e, err := g.st.Policy(who.Space)
		switch {
		case err != nil:
			return nil, err
		case e.Seal() == "":
			return nil, &safety.Error{Code: safety.CodePolicyMissing, Msg: "no signed policy names this space's seal key"}
		case e.Seal() != who.Seal:
			return nil, &safety.Error{Code: safety.CodePolicyDenied, Msg: "the space's seal key isn't the one its signed policy names"}
		case !g.st.CurrentIdentity(who.Identity, who.Key):
			return nil, &safety.Error{Code: safety.CodePolicyDenied, Msg: "the identity isn't current in the firm key log"}
		}
		v.Member = who.Identity
	}
	if err := g.nonces.Claim(nonce, signedAt); err != nil {
		return nil, err
	}
	return v, nil
}

// StartFor: the safety checks, then the recipient of the run's record (the space's seal key) into its options.
func (g *recGateway) StartFor(r *proto.RunRequest) (harness.Start, guard.TaskOptions, error) {
	start, opts, err := g.safeGateway.StartFor(r)
	if r.Verified != nil {
		opts.RecordTo = r.Verified.Seal
	}
	return start, opts, err
}

// StartSearch: the safety checks (safeGateway.StartSearch), then the recipient of the search's record: the space's
// seal key, as for a run (VerifySearch).
func (g *recGateway) StartSearch(r *proto.SearchRequest) (harness.Start, guard.TaskOptions, []byte, error) {
	start, opts, args, err := g.safeGateway.StartSearch(r)
	if r.Verified != nil {
		opts.RecordTo = r.Verified.Seal
	}
	return start, opts, args, err
}

// StartPictures: as StartSearch, for a pictures request (VerifyPictures).
func (g *recGateway) StartPictures(r *proto.PicturesRequest) (harness.Start, guard.TaskOptions, []byte, error) {
	start, opts, args, err := g.safeGateway.StartPictures(r)
	if r.Verified != nil {
		opts.RecordTo = r.Verified.Seal
	}
	return start, opts, args, err
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
	if s.g.approvals != nil {
		s.g.approvals.Forget(s.id)
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
	in := activity.Input{Messages: len(start.Input), Images: len(opts.Images)}
	for _, m := range start.Input {
		in.Bytes += len(m.Content)
	}
	for _, im := range opts.Images { // that the person gave images, and their size: never what they show
		in.ImageBytes += im.Bytes
	}
	var tools []string
	for _, t := range start.Tools {
		tools = append(tools, t.Name)
	}
	kind := "chat"
	if opts.Via == guard.ViaSearch || opts.Via == guard.ViaPictures { // a plain chat's search, or an answer's held-back pictures: no model
		kind = "search"
	}
	if opts.Via == guard.ViaTrigger { // an unattended run: its schedule or event fired it, on the VM (via "trigger")
		kind = cmp.Or(opts.TriggerKind, "schedule")
		if via != "resume" {
			via = "trigger"
		}
	}
	return activity.Start{Run: task, Space: start.Space, To: opts.RecordTo, Member: opts.Identity,
		Agent:   activity.Agent{ID: start.Agent.ID, Version: start.Agent.Version, Digest: start.Agent.Digest},
		Trigger: activity.Trigger{Kind: kind, Via: via}, Controls: controls, Models: start.Models, Tools: tools,
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
	v := r.Verified
	if v == nil {
		return proto.Event{}, false
	}
	space := v.Space
	st := g.st.StatusOf(space)
	code, msg := coded(err)
	model := r.Model
	if model == "" {
		model = proto.DefaultModel
	}
	in := activity.Input{Messages: len(r.Messages)}
	for _, m := range r.Messages {
		in.Bytes += len(m.Content)
		for _, u := range m.Images {
			in.Images++
			in.ImageBytes += base64.StdEncoding.DecodedLen(len(strings.TrimPrefix(u, proto.ImageURLPrefix)))
		}
	}
	ag := guard.AgentRef(r.Agent) // the built-in agent asked for (refused at the door when unknown: never here)
	rec, rerr := g.rec.Refused(activity.Start{Run: harness.NewTaskID(), Space: space, To: v.Seal, Member: v.Identity,
		Agent: activity.Agent{ID: ag.ID, Version: ag.Version, Digest: ag.Digest}, Trigger: activity.Trigger{Kind: "chat", Via: "relay"},
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

// RefusedSearch records a plain chat's search (POST /search) refused before it started (a stop, no policy, web search
// not allowed, the day used up) and returns the event that carries its record, or false. Sizes and codes only.
func (g *recGateway) RefusedSearch(r *proto.SearchRequest, err error) (proto.Event, bool) {
	v := r.Verified
	if v == nil {
		return proto.Event{}, false
	}
	st := g.st.StatusOf(v.Space)
	code, msg := coded(err)
	rec, rerr := g.rec.Refused(activity.Start{Run: harness.NewTaskID(), Space: v.Space, To: v.Seal, Member: v.Identity,
		Agent: activity.Agent{ID: "a_search", Version: "1", Digest: "unsigned"}, Trigger: activity.Trigger{Kind: "search", Via: "relay"},
		Controls: &activity.Controls{Policy: st.Policy, ReleasePolicy: st.Release, OperatorSeq: st.OperatorSeq, FirmSeq: st.FirmSeq, Fresh: st.Fresh},
		Tools:    []string{"web.search"}}, activity.Status{Code: code, Detail: msg})
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
		c.Search = d.Search // web.search: its provider, and why it went to the fallback (guard/searchfallback.go)
		c.Reader = readerRecord(d.Reader)
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
		g.prompts.ModelCalled(ti, res) // the taint its tool calls are checked with (a composed address is refused)
	}
	return res, err
}

func (g *recGateway) Action(ctx context.Context, ti *harness.TaskInfo, id string, req *harness.Action) (*harness.ActionResult, error) {
	f := &guard.Facts{}
	connector, _, _ := strings.Cut(req.Name, ".")
	done := g.begin(ti, id, "action", req.Name, connector, req)
	// Permission prompts: an action that sends data out goes on with the person's grant, or is denied here without running.
	// Approve before send: an action decided here without running is answered now; an approved one goes on with
	// its approval (gatewayd checks it again) and its effect marked sending first.
	var res *harness.ActionResult
	var err error
	if g.approvals != nil {
		ctx, res = g.approvals.Attach(ctx, ti, id, req)
	}
	if res == nil && g.prompts != nil {
		ctx, res = g.prompts.Attach(ctx, ti, id, req)
	}
	if res == nil {
		res, err = g.safeGateway.Action(guard.WithFacts(ctx, f), ti, id, req)
		if g.approvals != nil {
			g.approvals.Done(ti.ID, id, res, err)
		}
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

// Hold: an action that needs a person's approval waits for it (guard.Approvals.Hold); one that would send data
// out waits for the person's answer (guard.Prompts.Hold). An approval decided without asking (nobody can
// approve it) is answered by Attach, never asked about as a prompt as well.
func (g *recGateway) Hold(ti *harness.TaskInfo, id string, req any) string {
	if g.approvals != nil {
		if sub, decided := g.approvals.Hold(ti, id, req); sub != "" || decided {
			return sub
		}
	}
	if g.prompts == nil {
		return ""
	}
	return g.prompts.Hold(ti, id, req)
}

// TaskResumed shows a resumed task's waiting prompts again (guard.Prompts.Resume).
func (g *recGateway) TaskResumed(task string, start *harness.Start, opts guard.TaskOptions, journal []harness.Record) {
	b, err := json.Marshal(opts)
	if err != nil {
		return
	}
	ti := &harness.TaskInfo{ID: task, Start: start, Options: b}
	if g.approvals != nil {
		g.approvals.Resume(ti, journal)
	}
	if g.prompts != nil {
		g.prompts.Resume(ti, journal)
	}
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

// readerRecord is an action's reader calls as its record's one reader entry: one call as it was; several (a search
// read one result per call, a call that went to the fallback model; v0.8.16) summed: the models that answered
// joined with "+", tokens and counts added, the longest call's time (they run at once), ok when one answered (a
// result it couldn't read is in the result as unread), else the first failure's words. nil: no reader call.
func readerRecord(calls []guard.ReaderUse) *activity.Reader {
	if len(calls) == 0 {
		return nil
	}
	if len(calls) == 1 {
		u := calls[0]
		return &activity.Reader{Model: u.Model, Prompt: u.Prompt, Completion: u.Completion, Ms: u.Ms, Outcome: u.Outcome,
			Why: u.Why, Quotes: u.Quotes, Dropped: u.Dropped, Instructions: u.Instructions, Verbatim: u.Verbatim}
	}
	r := &activity.Reader{}
	var models []string
	for _, u := range calls {
		r.Prompt += u.Prompt
		r.Completion += u.Completion
		r.Ms = max(r.Ms, u.Ms)
		r.Quotes += u.Quotes
		r.Dropped += u.Dropped
		r.Instructions += u.Instructions
		r.Verbatim += u.Verbatim
		if u.Outcome == "ok" && !slices.Contains(models, u.Model) {
			models = append(models, u.Model)
		}
		if r.Outcome == "" && u.Outcome != "ok" {
			r.Outcome, r.Why = u.Outcome, u.Why
		}
	}
	if len(models) > 0 {
		slices.Sort(models)
		r.Model, r.Outcome, r.Why = strings.Join(models, "+"), "ok", ""
	} else {
		r.Model = calls[0].Model
	}
	return r
}
