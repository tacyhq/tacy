package guard

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tacyhq/tacy/approval"
	"github.com/tacyhq/tacy/approval/approvaltest"
	"github.com/tacyhq/tacy/brain"
	"github.com/tacyhq/tacy/harness"
	"github.com/tacyhq/tacy/identity"
	"github.com/tacyhq/tacy/proto"
	"github.com/tacyhq/tacy/trigger"
)

// Approve before send and authenticated triggers, end to end in one process (docs/27 sections 3 and 4): a signed
// agent definition with a schedule or an event trigger, its sponsor, the trigger engine, the task host, the real
// brain over harness/v1, agentd's Approvals in front of this guard (as recGateway composes them), and the test-only
// sink connector, which checks every approval again itself (gatewayd's side).

const apFirm = "f_test"

// withApprovals is agentd's composition (app/activity.go recGateway) in miniature: Approvals hold and attach, this
// guard runs the action, Approvals records how it ended.
type withApprovals struct {
	*Guard
	ap *Approvals
}

func (w *withApprovals) Hold(ti *harness.TaskInfo, id string, req any) string {
	sub, _ := w.ap.Hold(ti, id, req)
	return sub
}

func (w *withApprovals) Action(ctx context.Context, ti *harness.TaskInfo, id string, req *harness.Action) (*harness.ActionResult, error) {
	ctx, res := w.ap.Attach(ctx, ti, id, req)
	if res != nil {
		return res, nil
	}
	res, err := w.Guard.Action(ctx, ti, id, req)
	w.ap.Done(ti.ID, id, res, err)
	return res, err
}

type apStack struct {
	t       *testing.T
	dir     identity.Static
	sponsor *approvaltest.Person
	other   *approvaltest.Person
	space   string
	sink    *Sink
	g       *Guard
	ap      *Approvals
	store   *approval.MemStore
	rt      *harness.Runtime
	host    *Host
	eng     *trigger.Engine
	fm      *fakeModel
	mu      sync.Mutex
	asks    chan proto.Approval // approvals shown, waiting
	settled chan proto.Approval // approvals decided (or how their effect ended)
	results chan string         // tool_result texts
}

func newID(prefix string) string {
	b := make([]byte, 16)
	rand.Read(b)
	return identity.IDFrom(prefix, b)
}

func newAPStack(t *testing.T, ttl time.Duration, responses ...string) *apStack {
	s := &apStack{t: t, space: newID("s"), sink: &Sink{}, store: approval.NewMemStore(), asks: make(chan proto.Approval, 8),
		settled: make(chan proto.Approval, 8), results: make(chan string, 16)}
	s.sponsor = approvaltest.NewPerson(t, &s.dir, apFirm, s.space)
	s.other = approvaltest.NewPerson(t, &s.dir, apFirm, s.space)
	s.fm = &fakeModel{responses: responses}
	srv := httptest.NewServer(s.fm)
	t.Cleanup(srv.Close)
	check := approval.Config{Dir: &s.dir, RP: approvaltest.RP}
	s.g = New(Config{Up: &plainUpstream{url: srv.URL, http: srv.Client()}, Search: &fakeSearch{}, Fetcher: &http.Client{Transport: stubWeb{}},
		Sink: s.sink, Approvals: &check})
	s.ap = &Approvals{Store: s.store, Check: check, IDKey: []byte("agentd id key"), TTL: ttl}
	w := &withApprovals{Guard: s.g, ap: s.ap}
	s.rt = &harness.Runtime{Guard: w, Store: harness.NewMemStore()}
	s.host = &Host{RT: s.rt, GW: w, IDKey: []byte("agentd id key")}
	s.ap.Release, s.ap.Emit = s.rt.Release, s.emit
	s.eng = trigger.New(trigger.Config{Firm: apFirm, Dir: &s.dir, Store: trigger.NewMemStore(), IDKey: []byte("agentd id key"),
		Trusted: func() (time.Time, bool) { return time.Now(), true }})
	rc, bc := net.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	stopped := make(chan struct{})
	go s.rt.Serve(ctx, rc)
	go func() { brain.Run(ctx, bc); close(stopped) }()
	t.Cleanup(func() { cancel(); bc.Close(); <-stopped })
	return s
}

func (s *apStack) emit(task string, e proto.Event) {
	s.host.Emit(task, e)
	if e.Type == "approval" && e.Approval != nil {
		if e.Approval.State == "" {
			s.asks <- *e.Approval
		} else {
			s.settled <- *e.Approval
		}
	}
}

// install signs and installs a definition by the sponsor (author and sponsor) with a schedule and an event trigger.
func (s *apStack) install(sender string) (*trigger.Installed, string, string) {
	sched, event := newID("tr"), newID("tr")
	now := time.Now().UTC()
	d := trigger.Definition{Firm: apFirm, Space: s.space, Agent: newID("a"), Version: 1, Instructions: "Send the client the daily summary.",
		Seal:   "x25519:CQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		Models: []string{defaultModel}, Tools: []string{"sink.post", "sink.put"},
		Triggers: []trigger.Trigger{{ID: sched, Kind: trigger.Schedule, Every: "1h", Anchor: now.Add(-time.Minute)},
			{ID: event, Kind: trigger.Event, Sender: sender}},
		Author: s.sponsor.ID, Sponsor: s.sponsor.ID, IssuedAt: now.Add(-time.Minute), NotAfter: now.Add(24 * time.Hour)}
	env, err := trigger.SignDefinition(d, s.sponsor.Identity)
	if err != nil {
		s.t.Fatal(err)
	}
	in, err := s.eng.Install(env)
	if err != nil {
		s.t.Fatal(err)
	}
	return in, sched, event
}

// fire starts the scheduled task due now and returns its id.
func (s *apStack) fire() string {
	s.t.Helper()
	fires, err := s.eng.Due()
	if err != nil || len(fires) != 1 {
		s.t.Fatalf("due: %+v %v", fires, err)
	}
	if existed, err := s.host.StartTriggered(context.Background(), fires[0], apFirm); err != nil || existed {
		s.t.Fatalf("start: %v %v", existed, err)
	}
	s.eng.Fired(fires[0])
	return fires[0].Task
}

func (s *apStack) ask() proto.Approval {
	s.t.Helper()
	select {
	case a := <-s.asks:
		return a
	case <-time.After(10 * time.Second):
		s.t.Fatal("no approval asked for")
	}
	return proto.Approval{}
}

func (s *apStack) wait(task string) harness.Outcome {
	s.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	o, err := s.rt.Wait(ctx, task)
	if err != nil {
		s.t.Fatalf("task didn't end: %v", err)
	}
	return o
}

func (s *apStack) decide(p *approvaltest.Person, a proto.Approval, decision string, o approvaltest.Options) (string, error) {
	rec := approval.Record{ID: a.ID, Firm: a.Firm, Space: a.Space, Task: a.Task, Request: a.Request, Action: a.Action,
		EffectHash: a.EffectHash, ExpiresAt: a.ExpiresAt}
	return s.ap.Answer(p.Sign(s.t, approvaltest.PayloadFor(rec, p.ID, decision), o))
}

const postArgs = `{"to":"client@example.com","body":"Daily summary: all good."}`

// A scheduled task's send waits for its sponsor. The approval shows exactly what would go out, and its hash is the
// canonical effect's; a forged, mismatched or other person's decision is refused and the send stays held; the
// sponsor's passkey approval lets it go out once, with the approval id as its marker.
func TestScheduledSendWaitsForTheSponsor(t *testing.T) {
	s := newAPStack(t, time.Hour, toolCallSSE("c1", "sink_post", postArgs), textSSE("Sent the summary."))
	s.install(identity.KeyString(s.sponsor.Identity.Public().(ed25519.PublicKey)))
	task := s.fire()
	a := s.ask()
	eff, _ := EffectOf("sink.post", []byte(postArgs))
	if a.Task != task || a.Action != "sink.post" || string(a.Effect) != string(eff) || a.EffectHash != approval.EffectHash(eff) ||
		len(a.Approvers) != 1 || a.Approvers[0] != s.sponsor.ID || a.Tainted || a.Firm != apFirm || a.Space != s.space {
		t.Fatalf("approval shown: %+v", a)
	}
	if st, _ := s.rt.Status(task); st.State != harness.StateWaiting || st.Sub != harness.WaitApproval {
		t.Fatalf("task while held: %+v", st)
	}
	if list := s.ap.List(s.sponsor.ID, s.space); len(list) != 1 || list[0].ID != a.ID {
		t.Fatalf("sponsor's list: %+v", list)
	}
	if list := s.ap.List(s.other.ID, ""); len(list) != 0 {
		t.Fatalf("someone else's list: %+v", list)
	}
	// Refused, nothing changes: another holder (not an approver), a changed effect, wrong origin, no UV.
	if _, err := s.decide(s.other, a, approval.Approve, approvaltest.Options{}); err != ErrBadApproval {
		t.Fatalf("non-approver: %v", err)
	}
	changed := a
	changed.EffectHash = strings.Repeat("ab", 32)
	if _, err := s.decide(s.sponsor, changed, approval.Approve, approvaltest.Options{}); err != ErrBadApproval {
		t.Fatalf("changed effect: %v", err)
	}
	for _, o := range []approvaltest.Options{{Origin: "https://evil.example"}, {NoUV: true}, {RPID: "evil.example"}} {
		if _, err := s.decide(s.sponsor, a, approval.Approve, o); err != ErrBadApproval {
			t.Fatalf("%+v: %v", o, err)
		}
	}
	if s.sink.Count("sink.post") != 0 {
		t.Fatal("sent before approval")
	}
	if state, err := s.decide(s.sponsor, a, approval.Approve, approvaltest.Options{}); err != nil || state != approval.StateApproved {
		t.Fatalf("approve: %s %v", state, err)
	}
	if _, err := s.decide(s.sponsor, a, approval.Approve, approvaltest.Options{}); err != ErrNoApproval {
		t.Fatalf("second decision: %v", err)
	}
	if o := s.wait(task); o.State != harness.OutcomeSucceeded {
		t.Fatalf("outcome %+v", o)
	}
	if s.sink.Count("sink.post") != 1 || s.sink.Posts[0].Marker != a.ID || s.sink.Posts[0].Effect["to"] != "client@example.com" {
		t.Fatalf("posts %+v", s.sink.Posts)
	}
	if rec, _ := s.store.Approval(a.ID); rec == nil || rec.State != approval.StateSent || len(rec.Decision) == 0 {
		t.Fatalf("record %+v", rec)
	}
}

// Denied, or no answer before the expiry: nothing goes out, the model is told, the task goes on and ends.
func TestDeniedAndExpiredSendsDontGoOut(t *testing.T) {
	for _, c := range []struct {
		name  string
		ttl   time.Duration
		deny  bool
		state string
	}{{"deny", time.Hour, true, approval.StateDenied}, {"expire", 300 * time.Millisecond, false, approval.StateExpired}} {
		t.Run(c.name, func(t *testing.T) {
			s := newAPStack(t, c.ttl, toolCallSSE("c1", "sink_post", postArgs), textSSE("Didn't send it."))
			s.install(identity.KeyString(s.sponsor.Identity.Public().(ed25519.PublicKey)))
			task := s.fire()
			a := s.ask()
			if c.deny {
				if state, err := s.decide(s.sponsor, a, approval.Deny, approvaltest.Options{}); err != nil || state != approval.StateDenied {
					t.Fatalf("deny: %s %v", state, err)
				}
			}
			if o := s.wait(task); o.State != harness.OutcomeSucceeded {
				t.Fatalf("outcome %+v", o)
			}
			if s.sink.Count("sink.post") != 0 {
				t.Fatal("sent")
			}
			if rec, _ := s.store.Approval(a.ID); rec == nil || rec.State != c.state {
				t.Fatalf("record %+v", rec)
			}
			if !strings.Contains(lastToolResult(s.fm), "approval_denied") {
				t.Fatalf("the model wasn't told: %s", lastToolResult(s.fm))
			}
		})
	}
}

// lastToolResult is the last tool message the model got.
func lastToolResult(fm *fakeModel) string {
	fm.mu.Lock()
	defer fm.mu.Unlock()
	out := ""
	for _, r := range fm.requests {
		msgs, _ := r["messages"].([]any)
		for _, m := range msgs {
			if mm, _ := m.(map[string]any); mm["role"] == "tool" {
				out, _ = mm["content"].(string)
			}
		}
	}
	return out
}

// An event-started task is tainted from its start, so even a change inside its scopes (sink.put) waits for the
// sponsor; a scheduled task's untainted change doesn't. A replayed event delivery starts nothing.
func TestEventTaskIsTaintedSoChangesNeedApproval(t *testing.T) {
	putArgs := `{"key":"status","value":"seen"}`
	s := newAPStack(t, time.Hour, toolCallSSE("c1", "sink_put", putArgs), textSSE("Noted."))
	_, senderK, _ := ed25519.GenerateKey(nil)
	in, _, event := s.install(identity.KeyString(senderK.Public().(ed25519.PublicKey)))
	env, _ := trigger.SignEvent(trigger.EventPayload{Trigger: event, Delivery: "msg-1", SentAt: time.Now(), Ref: "AAMk.1"}, senderK)
	f, err := s.eng.Event(env)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.host.StartTriggered(context.Background(), f, apFirm); err != nil {
		t.Fatal(err)
	}
	s.eng.Delivered(f)
	if _, err := s.eng.Event(env); err == nil {
		t.Fatal("replayed delivery accepted")
	}
	if st, _ := s.rt.Status(f.Task); st.Taint != "event" {
		t.Fatalf("event task not tainted from its start: %+v", st)
	}
	a := s.ask()
	if a.Action != "sink.put" || !a.Tainted {
		t.Fatalf("approval %+v", a)
	}
	if s.sink.Count("sink.put") != 0 {
		t.Fatal("changed before approval")
	}
	s.decide(s.sponsor, a, approval.Approve, approvaltest.Options{})
	if o := s.wait(f.Task); o.State != harness.OutcomeSucceeded || s.sink.Count("sink.put") != 1 {
		t.Fatalf("outcome %+v, puts %d", o, s.sink.Count("sink.put"))
	}
	_ = in

	// Scheduled (untainted): the same change runs without asking.
	s2 := newAPStack(t, time.Hour, toolCallSSE("c1", "sink_put", putArgs), textSSE("Noted."))
	s2.install(identity.KeyString(s2.sponsor.Identity.Public().(ed25519.PublicKey)))
	task := s2.fire()
	if o := s2.wait(task); o.State != harness.OutcomeSucceeded || s2.sink.Count("sink.put") != 1 {
		t.Fatalf("scheduled change: %+v, puts %d", o, s2.sink.Count("sink.put"))
	}
	select {
	case a := <-s2.asks:
		t.Fatalf("asked for an untainted change: %+v", a)
	default:
	}
}

// gatewayd's own check: a send without an approval, with one for other arguments, for another request, from a
// non-approver, or used twice doesn't happen, whatever agentd says.
func TestGatewaydChecksTheApprovalItself(t *testing.T) {
	var dir identity.Static
	space := newID("s")
	sponsor := approvaltest.NewPerson(t, &dir, apFirm, space)
	other := approvaltest.NewPerson(t, &dir, apFirm, space)
	sink := &Sink{}
	check := approval.Config{Dir: &dir, RP: approvaltest.RP}
	g := New(Config{Up: &plainUpstream{}, Sink: sink, Approvals: &check})
	opts, _ := json.Marshal(TaskOptions{Space: space, Firm: apFirm, Approvers: []string{sponsor.ID}})
	ti := &harness.TaskInfo{ID: "tk_g", Start: &harness.Start{}, Options: opts}
	eff, _ := EffectOf("sink.post", []byte(postArgs))
	exp := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	payload := func(p *approvaltest.Person, req string, hash string) approval.Payload {
		return approval.Payload{Approval: approval.ID([]byte("k"), "tk_g", req), Firm: apFirm, Space: space, Task: "tk_g", Request: req,
			Action: "sink.post", EffectHash: hash, Decision: approval.Approve, Approver: p.ID, ExpiresAt: exp}
	}
	post := func(id string, sub *approval.Submission, args string) *harness.ActionResult {
		t.Helper()
		ctx := WithApproval(harness.WithRequestID(context.Background(), id), sub)
		res, err := g.Action(ctx, ti, id, &harness.Action{Name: "sink.post", Args: []byte(args)})
		if err != nil {
			t.Fatal(err)
		}
		return res
	}
	otherEff, _ := EffectOf("sink.post", []byte(`{"to":"attacker@example.com","body":"Daily summary: all good."}`))
	for name, c := range map[string]struct {
		sub  *approval.Submission
		args string
	}{
		"none":            {nil, postArgs},
		"other arguments": {sponsor.Sign(t, payload(sponsor, "r1", approval.EffectHash(otherEff)), approvaltest.Options{}), postArgs},
		"args swapped":    {sponsor.Sign(t, payload(sponsor, "r1", approval.EffectHash(eff)), approvaltest.Options{}), `{"to":"attacker@example.com","body":"Daily summary: all good."}`},
		"other request":   {sponsor.Sign(t, payload(sponsor, "r0", approval.EffectHash(eff)), approvaltest.Options{}), postArgs},
		"non-approver":    {other.Sign(t, payload(other, "r1", approval.EffectHash(eff)), approvaltest.Options{}), postArgs},
		"no UV":           {sponsor.Sign(t, payload(sponsor, "r1", approval.EffectHash(eff)), approvaltest.Options{NoUV: true}), postArgs},
	} {
		if res := post("r1", c.sub, c.args); res.Status != harness.ActionDenied || !strings.HasPrefix(res.Error, "approval_denied") {
			t.Errorf("%s: %+v", name, res)
		}
	}
	if sink.Count("sink.post") != 0 {
		t.Fatalf("sent: %+v", sink.Posts)
	}
	good := sponsor.Sign(t, payload(sponsor, "r1", approval.EffectHash(eff)), approvaltest.Options{})
	if res := post("r1", good, postArgs); res.Status != harness.ActionDone {
		t.Fatalf("good: %+v", res)
	}
	if res := post("r1", good, postArgs); res.Status != harness.ActionDenied {
		t.Fatalf("used twice: %+v", res)
	}
	if sink.Count("sink.post") != 1 {
		t.Fatalf("posts %d", sink.Count("sink.post"))
	}
	// No approvals on this gatewayd (Config.Approvals nil): nothing that needs one runs.
	g2 := New(Config{Up: &plainUpstream{}, Sink: sink})
	ctx := WithApproval(harness.WithRequestID(context.Background(), "r2"), sponsor.Sign(t, payload(sponsor, "r2", approval.EffectHash(eff)), approvaltest.Options{}))
	if res, _ := g2.Action(ctx, ti, "r2", &harness.Action{Name: "sink.post", Args: []byte(postArgs)}); res.Status != harness.ActionDenied {
		t.Fatalf("no approval check configured: %+v", res)
	}
}

// A task nobody can approve for (a person's chat task before identity keys: no approvers) never sends: it's denied
// without asking.
func TestNoApproverDeniesWithoutAsking(t *testing.T) {
	ap := &Approvals{Store: approval.NewMemStore(), IDKey: []byte("k"), Emit: func(string, proto.Event) {},
		Release: func(string, string, bool, string) error { return nil }}
	opts, _ := json.Marshal(TaskOptions{Space: "s_chat"})
	ti := &harness.TaskInfo{ID: "tk_c", Start: &harness.Start{}, Options: opts}
	act := &harness.Action{Name: "sink.post", Call: "c1", Args: []byte(postArgs)}
	if sub, decided := ap.Hold(ti, "r1", act); sub != "" || !decided {
		t.Fatalf("hold %q %v", sub, decided)
	}
	_, res := ap.Attach(context.Background(), ti, "r1", act)
	if res == nil || res.Status != harness.ActionDenied || !strings.Contains(res.Error, "nobody can approve") {
		t.Fatalf("attach %+v", res)
	}
	// A read that sends data out isn't an approval (permission prompts handle it); unless the policy lists it.
	if sub, decided := ap.Hold(ti, "r2", &harness.Action{Name: "web.search", Args: []byte(`{"query":"x"}`)}); sub != "" || decided {
		t.Fatalf("web.search held for approval: %q %v", sub, decided)
	}
	ap.Listed = func(space, action string) bool { return action == "web.search" }
	if _, decided := ap.Hold(ti, "r3", &harness.Action{Name: "web.search", Args: []byte(`{"query":"x"}`)}); !decided {
		t.Fatal("a listed read wasn't held for approval")
	}
}

// After a restart: an effect found sending becomes unknown and is never sent again; a held approval is shown
// again with its first expiry and can still be approved.
func TestApprovalsAcrossARestart(t *testing.T) {
	var dir identity.Static
	space := newID("s")
	sponsor := approvaltest.NewPerson(t, &dir, apFirm, space)
	store := approval.NewMemStore()
	shown := make(chan proto.Approval, 8)
	released := make(chan string, 8)
	mk := func() *Approvals {
		return &Approvals{Store: store, IDKey: []byte("k"), Check: approval.Config{Dir: &dir, RP: approvaltest.RP},
			Emit: func(_ string, e proto.Event) {
				if e.Approval != nil {
					shown <- *e.Approval
				}
			},
			Release: func(_, id string, _ bool, _ string) error { released <- id; return nil }}
	}
	opts, _ := json.Marshal(TaskOptions{Space: space, Firm: apFirm, Approvers: []string{sponsor.ID}})
	ti := &harness.TaskInfo{ID: "tk_r", Start: &harness.Start{}, Options: opts}
	send := &harness.Action{Name: "sink.post", Call: "c1", Args: []byte(postArgs)}
	reqJSON, _ := json.Marshal(send)

	// Process 1: two sends held; one approved and handed on (sending) when the process dies.
	a1 := mk()
	a1.Hold(ti, "r1", send)
	first := <-shown
	a1.Hold(ti, "r2", send)
	second := <-shown
	rec := approval.Record{ID: first.ID, Firm: apFirm, Space: space, Task: "tk_r", Request: "r1", Action: "sink.post",
		EffectHash: first.EffectHash, ExpiresAt: first.ExpiresAt}
	if _, err := a1.Answer(sponsor.Sign(t, approvaltest.PayloadFor(rec, sponsor.ID, approval.Approve), approvaltest.Options{})); err != nil {
		t.Fatal(err)
	}
	<-shown
	<-released
	if _, res := a1.Attach(context.Background(), ti, "r1", send); res != nil {
		t.Fatalf("attach: %+v", res)
	}

	// Process 2.
	a2 := mk()
	unknown, err := a2.Recover()
	if err != nil || len(unknown) != 1 || unknown[0].ID != first.ID {
		t.Fatalf("recover: %+v %v", unknown, err)
	}
	a2.Resume(ti, []harness.Record{{ID: "r1", Kind: harness.TypeAction, Req: reqJSON, Held: harness.WaitApproval, Done: false},
		{ID: "r2", Kind: harness.TypeAction, Req: reqJSON, Held: harness.WaitApproval}})
	var again proto.Approval
	for i := 0; i < 2; i++ {
		select {
		case a := <-shown:
			if a.ID == second.ID && a.State == "" {
				again = a
			}
		case <-time.After(5 * time.Second):
			t.Fatal("not shown again")
		}
	}
	if again.ID == "" || !again.ExpiresAt.Equal(second.ExpiresAt) {
		t.Fatalf("held approval after restart: %+v (first expiry %v)", again, second.ExpiresAt)
	}
	// r1's record is unknown: decided without asking, denied, never sent again.
	_, res := a2.Attach(context.Background(), ti, "r1", send)
	if res == nil || !strings.Contains(res.Error, "never sent twice") {
		t.Fatalf("unknown effect handed on: %+v", res)
	}
	rec2 := approval.Record{ID: second.ID, Firm: apFirm, Space: space, Task: "tk_r", Request: "r2", Action: "sink.post",
		EffectHash: second.EffectHash, ExpiresAt: second.ExpiresAt}
	if state, err := a2.Answer(sponsor.Sign(t, approvaltest.PayloadFor(rec2, sponsor.ID, approval.Approve), approvaltest.Options{})); err != nil || state != approval.StateApproved {
		t.Fatalf("approve after restart: %s %v", state, err)
	}
}

// A connector call that ended without a definite answer (a lost connection, a cancel) may have gone out: unknown,
// not failed; a definite failure is failed.
func TestDoneWithoutAnAnswerIsUnknown(t *testing.T) {
	store := approval.NewMemStore()
	ap := &Approvals{Store: store, IDKey: []byte("k"), Emit: func(string, proto.Event) {}}
	for _, c := range []struct {
		res  *harness.ActionResult
		err  error
		want string
	}{{nil, context.Canceled, approval.StateUnknown}, {&harness.ActionResult{Status: harness.ActionFailed, Error: "no"}, nil, approval.StateFailed},
		{&harness.ActionResult{Status: harness.ActionDone}, nil, approval.StateSent}} {
		id := approval.ID([]byte("k"), "tk_d", c.want)
		store.PutApproval(approval.Record{ID: id, Task: "tk_d", Request: c.want})
		store.MoveApproval(id, approval.StateHeld, approval.StateApproved, nil)
		store.MoveApproval(id, approval.StateApproved, approval.StateSending, nil)
		ap.mu.Lock()
		ap.init()
		ap.outcomes[key("tk_d", c.want)] = approval.StateApproved
		ap.mu.Unlock()
		ap.Done("tk_d", c.want, c.res, c.err)
		if r, _ := store.Approval(id); r.State != c.want {
			t.Errorf("%v %v: %s, want %s", c.res, c.err, r.State, c.want)
		}
	}
}
