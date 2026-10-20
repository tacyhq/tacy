package guard

import (
	"context"
	"encoding/json"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"errors"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/tacyhq/tacy/approval"
	"github.com/tacyhq/tacy/harness"
	"github.com/tacyhq/tacy/proto"
	"github.com/tacyhq/tacy/safety"
)

// Approve before send, gatewayd's side (docs/27 section 4). An action whose class needs a person's approval
// (approval.Needs: a send always; a change when the task is tainted or the policy lists it) runs only with a
// submission that gatewayd checks itself (approval.Check): the effect hash recomputed here from the action's own
// arguments, the payload naming this task and request, the approver one of the task's, their passkey certificate
// and a user-verified WebAuthn assertion. agentd checked it first (Approvals); this is the second check, in the
// process that makes the call. A submission is used once per process.
//
// The only connector with effects today is the sink: a test-only stand-in (sink.post sends, sink.put changes) that
// proves the flow before the mail connector. It isn't in the release ceiling (safety.ChatRelease), so a production
// policy can't allow it, and only tests and a dev overlay set Config.Sink.

// ApprovalCheck is what gatewayd checks approvals with: the identity directory, the pinned origin and rpId, the
// clock. nil (Config.Approvals): nothing that needs an approval runs.
type ApprovalCheck = approval.Config

// MaxApprovalWait bounds how far ahead a payload's expiry may be (docs/27: at most 7 days by policy).
const MaxApprovalWait = 7 * 24 * time.Hour

type approvalKey struct{}

// WithApproval hands an action the person's approval (agentd puts it in for gatewayd to check).
func WithApproval(ctx context.Context, s *approval.Submission) context.Context {
	if s == nil {
		return ctx
	}
	return context.WithValue(ctx, approvalKey{}, s)
}

// ApprovalFrom is ctx's approval, or nil.
func ApprovalFrom(ctx context.Context) *approval.Submission {
	s, _ := ctx.Value(approvalKey{}).(*approval.Submission)
	return s
}

// EffectOf is the exact effect an action would have, in canonical JSON (approval.Canonical): what the person
// approves and the hash binds. Each connector with effects defines its own; an action with none, or arguments its
// connector refuses, is an error (and nothing runs).
func EffectOf(action string, args []byte) ([]byte, error) {
	switch action {
	case "sink.post", "sink.put":
		a, err := sinkArgs(action, args)
		if err != nil {
			return nil, err
		}
		b, err := json.Marshal(a.effect(action))
		if err != nil {
			return nil, err
		}
		return approval.Canonical(b)
	}
	if v, ok := Outgoing(action, args, nil); ok { // a permission-prompt read a policy holds for approval: what goes out
		b, _ := json.Marshal(map[string]string{"action": action, "value": v})
		return approval.Canonical(b)
	}
	return nil, errors.New("no effect for " + action)
}

// sinkArg is a sink action's arguments: sink.post {to, body}, sink.put {key, value}.
type sinkArg struct {
	To    string `json:"to,omitzero"`
	Body  string `json:"body,omitzero"`
	Key   string `json:"key,omitzero"`
	Value string `json:"value,omitzero"`
}

func sinkArgs(action string, args []byte) (*sinkArg, error) {
	var a sinkArg
	if err := jsonv2.Unmarshal(args, &a, jsonv2.RejectUnknownMembers(true)); err != nil {
		return nil, errors.New("arguments must be " + sinkSchema(action))
	}
	ok := func(s string, max int) bool { return s != "" && utf8.RuneCountInString(s) <= max && !HiddenChars(s) }
	switch {
	case action == "sink.post" && ok(a.To, 200) && ok(a.Body, 8000) && a.Key == "" && a.Value == "":
	case action == "sink.put" && ok(a.Key, 200) && ok(a.Value, 8000) && a.To == "" && a.Body == "":
	default:
		return nil, errors.New("arguments must be " + sinkSchema(action) + " (no hidden characters)")
	}
	return &a, nil
}

func (a *sinkArg) effect(action string) map[string]string {
	if action == "sink.post" {
		return map[string]string{"action": action, "to": a.To, "body": a.Body}
	}
	return map[string]string{"action": action, "key": a.Key, "value": a.Value}
}

func sinkSchema(action string) string {
	if action == "sink.post" {
		return `{"to": "...", "body": "..."}`
	}
	return `{"key": "...", "value": "..."}`
}

// SinkToolDefs are the start.tools entries for the sink's actions.
func SinkToolDefs(actions ...string) []harness.Tool {
	var out []harness.Tool
	for _, a := range actions {
		switch a {
		case "sink.post":
			out = append(out, harness.Tool{Name: a, Description: "Send a message to a recipient (test connector; a person approves each one first).",
				Parameters: jsontext.Value(`{"type":"object","properties":{"to":{"type":"string"},"body":{"type":"string"}},"required":["to","body"],"additionalProperties":false}`)})
		case "sink.put":
			out = append(out, harness.Tool{Name: a, Description: "Save a note under a key (test connector).",
				Parameters: jsontext.Value(`{"type":"object","properties":{"key":{"type":"string"},"value":{"type":"string"}},"required":["key","value"],"additionalProperties":false}`)})
		}
	}
	return out
}

// Sink is the test-only connector with effects. Each effect carries its approval id as a marker (as the mail
// connector will set a Message-ID), so a send that may have happened can be looked up (Find) instead of sent again.
type Sink struct {
	mu    sync.Mutex
	Posts []SinkEffect
	Puts  []SinkEffect
	// Fail makes every effect fail (tests).
	Fail bool
	// Hook, when set, runs inside each effect before it's recorded (tests: block, or observe).
	Hook func(ctx context.Context, e SinkEffect)
}

// SinkEffect is one effect the sink carried out.
type SinkEffect struct {
	Marker string
	Action string
	Effect map[string]string
}

// Find reports whether an effect with marker went out (reconciliation after a restart: docs/27 section 4).
func (s *Sink) Find(marker string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, e := range append(append([]SinkEffect(nil), s.Posts...), s.Puts...) {
		if e.Marker == marker {
			return true
		}
	}
	return false
}

// Count is how many effects went out for action.
func (s *Sink) Count(action string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	if action == "sink.post" {
		return len(s.Posts)
	}
	return len(s.Puts)
}

func (s *Sink) do(ctx context.Context, e SinkEffect) error {
	if s.Hook != nil {
		s.Hook(ctx, e)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.Fail {
		return errors.New("the sink refused it")
	}
	if e.Action == "sink.post" {
		s.Posts = append(s.Posts, e)
	} else {
		s.Puts = append(s.Puts, e)
	}
	return nil
}

// approvalDenial is what the model sees for an effect that didn't run for want of a valid approval.
func approvalDenial(why string) *harness.ActionResult {
	return &harness.ActionResult{Status: harness.ActionDenied,
		Error: "approval_denied: " + why + "; nothing was sent or changed. Tell the person plainly; don't try it another way."}
}

// sinkAction runs a sink action: the policy (an action it holds for approval runs with a verified approval), the
// approval check, the leak scan, then the effect, once.
func (g *Guard) sinkAction(ctx context.Context, ti *harness.TaskInfo, id string, req *harness.Action) (*harness.ActionResult, error) {
	t := g.task(ti)
	call := cmp0(req.Call, id)
	show := func(res *harness.ActionResult) *harness.ActionResult {
		out, _ := json.Marshal(map[string]any{"status": res.Status, "error": res.Error, "output": json.RawMessage(nzJSON(res.Output))})
		t.emit(proto.Event{Type: "tool_result", ID: call, Name: req.Name, Args: json.RawMessage(req.Args), Result: out})
		return res
	}
	listed := false
	if st := g.cfg.Safety; st != nil {
		e, err := st.Check(t.opts.Space, true)
		if err != nil {
			return nil, harness.Errf(harness.CodeNotAllowed, "%s", err.Error())
		}
		if !e.AllowsToolApproved(req.Name) {
			g.record(Egress{Task: ti.ID, Action: id, Op: req.Name, Decision: "denied", Rule: "policy"})
			return show(&harness.ActionResult{Status: harness.ActionDenied, Error: safety.CodePolicyDenied + ": " + req.Name + " isn't allowed by the policy"}), nil
		}
		listed = e.NeedsApproval(req.Name)
	}
	a, err := sinkArgs(req.Name, req.Args)
	if err != nil {
		return show(&harness.ActionResult{Status: harness.ActionFailed, Error: err.Error()}), nil
	}
	sub := ApprovalFrom(ctx)
	needs := approval.Needs(approval.ClassOf(req.Name), t.taintFor(ti, req.Call), listed)
	marker := ""
	if needs || sub != nil {
		p, err := g.checkApproval(ti, t, id, req, sub)
		if err != nil {
			g.record(Egress{Task: ti.ID, Action: id, Op: req.Name, Decision: "denied", Rule: "approval"})
			return show(approvalDenial(err.Error())), nil
		}
		if p.Decision != approval.Approve {
			return show(approvalDenial("the person declined")), nil
		}
		marker = p.Approval
	}
	// The connector's own once-only check: an effect whose marker it already carried out isn't done again (gatewayd
	// keeps used approvals in memory only; a real connector asks its provider, as mail will by Message-ID).
	if marker != "" && g.cfg.Sink.Find(marker) {
		return show(approvalDenial("this approved effect already went out")), nil
	}
	if ids := outboundLeak(req.Args); ids != nil {
		g.record(Egress{Task: ti.ID, Action: id, Op: req.Name, Decision: "denied", Rule: "leak_scan", Patterns: ids})
		return show(&harness.ActionResult{Status: harness.ActionDenied, Error: "leak_scan: the arguments carry what looks like a credential; nothing was sent"}), nil
	}
	if err := g.cfg.Sink.do(ctx, SinkEffect{Marker: marker, Action: req.Name, Effect: a.effect(req.Name)}); err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return show(&harness.ActionResult{Status: harness.ActionFailed, Error: err.Error()}), nil
	}
	g.record(Egress{Task: ti.ID, Action: id, Op: req.Name, Decision: "allowed"})
	out, _ := json.Marshal(map[string]any{"done": true, "approval": marker})
	return show(&harness.ActionResult{Status: harness.ActionDone, Output: out}), nil
}

// checkApproval is gatewayd's own check of an action's approval: present, for this task, request and action, over
// the effect recomputed from the action's arguments, by one of the task's approvers, not expired, never used before
// in this process. It returns the decided payload.
func (g *Guard) checkApproval(ti *harness.TaskInfo, t *task, id string, req *harness.Action, sub *approval.Submission) (*approval.Payload, error) {
	if sub == nil {
		return nil, errors.New("this action needs a person's approval")
	}
	if g.cfg.Approvals == nil {
		return nil, errors.New("approvals aren't available on this VM")
	}
	var head approval.Payload
	if err := jsonv2.Unmarshal(sub.Payload, &head, jsonv2.RejectUnknownMembers(true)); err != nil {
		return nil, errors.New("bad approval")
	}
	now := time.Now()
	if g.cfg.Approvals.Now != nil {
		now = g.cfg.Approvals.Now()
	}
	if head.ExpiresAt.Sub(now) > MaxApprovalWait {
		return nil, errors.New("approval expiry too far ahead")
	}
	if na := t.opts.NotAfter; !na.IsZero() && !now.Before(na) {
		return nil, errors.New("the sponsor's authority for this agent has ended")
	}
	eff, err := EffectOf(req.Name, req.Args)
	if err != nil {
		return nil, err
	}
	p, err := approval.Check(sub, approval.Expect{Approval: head.Approval, Firm: t.opts.Firm, Space: t.opts.Space, Task: ti.ID,
		Request: id, Action: req.Name, EffectHash: approval.EffectHash(eff), Approvers: t.opts.Approvers, ExpiresAt: head.ExpiresAt},
		*g.cfg.Approvals)
	if err != nil {
		return nil, err
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.usedApprovals == nil {
		g.usedApprovals = map[string]bool{}
	}
	if g.usedApprovals[p.Approval] {
		return nil, errors.New("approval already used")
	}
	g.usedApprovals[p.Approval] = true
	return p, nil
}

func cmp0(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}

func nzJSON(b []byte) []byte {
	if len(b) == 0 {
		return []byte("null")
	}
	return b
}

// approvedRead: a read the policy holds for approval (approve: [web.search]) carries the person's approval, which
// checks here (checkApproval), and the policy allows it otherwise.
func (g *Guard) approvedRead(ctx context.Context, ti *harness.TaskInfo, t *task, id string, req *harness.Action) bool {
	st := g.cfg.Safety
	sub := ApprovalFrom(ctx)
	if st == nil || sub == nil {
		return false
	}
	e, err := st.Check(t.opts.Space, Effect(req))
	if err != nil || !e.NeedsApproval(req.Name) || !e.AllowsToolApproved(req.Name) {
		return false
	}
	p, err := g.checkApproval(ti, t, id, req, sub)
	return err == nil && p.Decision == approval.Approve
}
