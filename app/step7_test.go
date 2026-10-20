package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	jsonv2 "encoding/json/v2"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tacyhq/tacy/approval"
	"github.com/tacyhq/tacy/approval/approvaltest"
	"github.com/tacyhq/tacy/guard"
	"github.com/tacyhq/tacy/harness"
	"github.com/tacyhq/tacy/identity"
	"github.com/tacyhq/tacy/proto"
	"github.com/tacyhq/tacy/safety"
	"github.com/tacyhq/tacy/trigger"
)

// Triggers and approvals in agentd (docs/27 sections 3 and 4): signed definitions installed over POST /triggers, a schedule
// firing from the scheduler's tick, the sponsor listing and approving the held send over POST /approvals/list and
// POST /approvals, agentd's safety checks and the in-process guard (gatewayd's checks) on the way, the test-only
// sink receiving it once. Without an identity directory every route answers identity_unavailable.

func randID(prefix string) string {
	b := make([]byte, 16)
	rand.Read(b)
	return identity.IDFrom(prefix, b)
}

type step7Env struct {
	*safeEnv
	dir     identity.Static
	space   string
	sponsor *approvaltest.Person
	sink    *guard.Sink
	asks    chan proto.Approval
}

func newStep7Env(t *testing.T, replies ...string) *step7Env {
	se := &step7Env{space: randID("s"), sink: &guard.Sink{}, asks: make(chan proto.Approval, 8)}
	se.sponsor = approvaltest.NewPerson(t, &se.dir, "f_chat", se.space)
	check := approval.Config{Dir: &se.dir, RP: approvaltest.RP}
	addSink := func(p *safety.Policy) {
		p.Connectors["sink"] = safety.Connector{Tools: []string{"sink.post", "sink.put"}}
	}
	se.safeEnv = newSafeEnvWith(t, safeOpts{release: addSink, sink: se.sink, check: &check}, replies...)
	se.mustPost(se.policy(1, addSink), se.heartbeat())
	s := se.s
	host := s.tasks()
	rg := s.agent.(*recGateway)
	s.dir = &se.dir
	s.approvals = &guard.Approvals{Release: s.rt.Release, Store: approval.NewMemStore(), Check: check, IDKey: []byte("agentd id key"),
		OnWait: rg.waiting, Emit: func(task string, e proto.Event) {
			host.Emit(task, e)
			if e.Approval != nil && e.Approval.State == "" {
				se.asks <- *e.Approval
			}
		}}
	rg.approvals = s.approvals
	s.triggers = trigger.New(trigger.Config{Firm: "f_chat", Dir: &se.dir, Store: trigger.NewMemStore(), IDKey: []byte("agentd id key"),
		Trusted: s.safety.OperatorTime})
	return se
}

func (se *step7Env) call(h func(w *httptest.ResponseRecorder, body []byte), v any) (int, string) {
	b, _ := jsonv2.Marshal(v)
	w := httptest.NewRecorder()
	h(w, b)
	return w.Code, strings.TrimSpace(w.Body.String())
}

func (se *step7Env) install(env safety.Envelope) (int, string) {
	return se.call(func(w *httptest.ResponseRecorder, b []byte) {
		se.s.triggersInstall(w, httptest.NewRequest("POST", "/triggers", bytes.NewReader(b)))
	}, env)
}

func (se *step7Env) list(p *approvaltest.Person, edit func(*listRequest)) (int, string) {
	nonce := make([]byte, 16)
	rand.Read(nonce)
	req := listRequest{Identity: p.ID, Space: se.space, SignedAt: time.Now().UTC().Truncate(time.Second), Nonce: hex.EncodeToString(nonce)}
	req.Sig = ed25519.Sign(p.Identity, listSigned(se.s.id.MarshalPublicKeyHex(), &req))
	if edit != nil {
		edit(&req)
	}
	return se.call(func(w *httptest.ResponseRecorder, b []byte) {
		se.s.approvalsList(w, httptest.NewRequest("POST", "/approvals/list", bytes.NewReader(b)))
	}, req)
}

func (se *step7Env) answer(sub *approval.Submission) (int, string) {
	return se.call(func(w *httptest.ResponseRecorder, b []byte) {
		se.s.approvalsAnswer(w, httptest.NewRequest("POST", "/approvals", bytes.NewReader(b)))
	}, sub)
}

func (se *step7Env) definition(edit func(*trigger.Definition)) trigger.Definition {
	now := time.Now().UTC()
	d := trigger.Definition{Firm: "f_chat", Space: se.space, Agent: randID("a"), Version: 1, Instructions: "Send the client the daily summary.",
		Seal:   testSealKey,
		Models: []string{proto.DefaultModel}, Tools: []string{"sink.post"},
		Triggers: []trigger.Trigger{{ID: randID("tr"), Kind: trigger.Schedule, Every: "1h", Anchor: now.Add(-time.Minute)}},
		Author:   se.sponsor.ID, Sponsor: se.sponsor.ID, IssuedAt: now.Add(-time.Minute), NotAfter: now.Add(24 * time.Hour)}
	if edit != nil {
		edit(&d)
	}
	return d
}

func TestStep7RoutesFailClosedWithoutDirectory(t *testing.T) {
	e := newSafeEnv(t)
	for name, h := range map[string]func(w *httptest.ResponseRecorder){
		"list": func(w *httptest.ResponseRecorder) {
			e.s.approvalsList(w, httptest.NewRequest("POST", "/", strings.NewReader("{}")))
		},
		"answer": func(w *httptest.ResponseRecorder) {
			e.s.approvalsAnswer(w, httptest.NewRequest("POST", "/", strings.NewReader("{}")))
		},
		"install": func(w *httptest.ResponseRecorder) {
			e.s.triggersInstall(w, httptest.NewRequest("POST", "/", strings.NewReader("{}")))
		},
		"event": func(w *httptest.ResponseRecorder) {
			e.s.triggersEvent(w, httptest.NewRequest("POST", "/", strings.NewReader("{}")))
		},
	} {
		w := httptest.NewRecorder()
		h(w)
		if w.Code != 503 || !strings.Contains(w.Body.String(), "identity_unavailable") {
			t.Errorf("%s: %d %s", name, w.Code, w.Body)
		}
	}
	e.s.runTriggers(context.Background(), time.Millisecond) // returns at once: nothing to run
}

func TestScheduledSendApprovedThroughAgentd(t *testing.T) {
	args := `{"to":"client@example.com","body":"Daily summary: all good."}`
	se := newStep7Env(t, pCalls([3]string{"c1", "sink_post", args}), pText("Sent the summary."))
	// Installing needs the sponsor's signature; a stranger's isn't enough.
	_, stranger, _ := ed25519.GenerateKey(nil)
	bad, _ := trigger.SignDefinition(se.definition(nil), stranger)
	if code, body := se.install(bad); code != 403 {
		t.Fatalf("stranger's definition: %d %s", code, body)
	}
	env, _ := trigger.SignDefinition(se.definition(nil), se.sponsor.Identity)
	if code, body := se.install(env); code != 200 || !strings.Contains(body, `"version":1`) {
		t.Fatalf("install: %d %s", code, body)
	}
	se.s.triggerTick(context.Background())
	a := <-se.asks
	if a.Action != "sink.post" || len(a.Approvers) != 1 || a.Approvers[0] != se.sponsor.ID {
		t.Fatalf("approval %+v", a)
	}
	// The scheduler's next tick doesn't fire the same slot again.
	se.s.triggerTick(context.Background())
	if n := len(se.s.tasks().Triggered()); n != 1 {
		t.Fatalf("%d triggered tasks after a second tick", n)
	}
	// The sponsor's list: signed for this boot's key, fresh; a bad signature or stale time is refused.
	if code, body := se.list(se.sponsor, nil); code != 200 || !strings.Contains(body, a.ID) {
		t.Fatalf("list: %d %s", code, body)
	}
	if code, _ := se.list(se.sponsor, func(r *listRequest) { r.Nonce += "00" }); code != 403 {
		t.Fatalf("tampered list request: %d", code)
	}
	if code, _ := se.list(se.sponsor, func(r *listRequest) { r.SignedAt = r.SignedAt.Add(-time.Hour) }); code != 400 {
		t.Fatalf("stale list request: %d", code)
	}
	rec := approval.Record{ID: a.ID, Firm: a.Firm, Space: a.Space, Task: a.Task, Request: a.Request, Action: a.Action, EffectHash: a.EffectHash, ExpiresAt: a.ExpiresAt}
	if code, body := se.answer(se.sponsor.Sign(t, approvaltest.PayloadFor(rec, se.sponsor.ID, approval.Approve), approvaltest.Options{NoUV: true})); code != 403 {
		t.Fatalf("no user verification: %d %s", code, body)
	}
	if code, body := se.answer(se.sponsor.Sign(t, approvaltest.PayloadFor(rec, se.sponsor.ID, approval.Approve), approvaltest.Options{})); code != 200 || !strings.Contains(body, "approved") {
		t.Fatalf("approve: %d %s", code, body)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if o, err := se.s.rt.Wait(ctx, a.Task); err != nil || o.State != harness.OutcomeSucceeded {
		t.Fatalf("outcome %+v %v", o, err)
	}
	if se.sink.Count("sink.post") != 1 || se.sink.Posts[0].Marker != a.ID {
		t.Fatalf("posts %+v", se.sink.Posts)
	}
	if code, _ := se.answer(se.sponsor.Sign(t, approvaltest.PayloadFor(rec, se.sponsor.ID, approval.Approve), approvaltest.Options{})); code != 404 {
		t.Fatalf("replayed approval: %d", code)
	}
}

// The sponsor revoked mid-task: the next tick cancels the task (sponsor_gone), nothing is sent, and the trigger
// doesn't fire again.
func TestSponsorRevokedStopsTheTask(t *testing.T) {
	args := `{"to":"client@example.com","body":"x"}`
	se := newStep7Env(t, pCalls([3]string{"c1", "sink_post", args}), pText("done"))
	env, _ := trigger.SignDefinition(se.definition(nil), se.sponsor.Identity)
	se.install(env)
	se.s.triggerTick(context.Background())
	a := <-se.asks
	se.dir.Revoke("f_chat", se.sponsor.ID)
	se.s.triggerTick(context.Background())
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	o, err := se.s.rt.Wait(ctx, a.Task)
	if err != nil || o.State != harness.OutcomeCancelled {
		t.Fatalf("outcome %+v %v", o, err)
	}
	if se.sink.Count("sink.post") != 0 {
		t.Fatal("sent after the sponsor was revoked")
	}
	if fires, _ := se.s.triggers.Due(); len(fires) != 0 {
		t.Fatalf("fires with the sponsor gone: %+v", fires)
	}
}

// An inbound event over POST /triggers/event: signed by the definition's sender, once per delivery.
func TestEventRoute(t *testing.T) {
	se := newStep7Env(t, pText("Nothing to do."))
	_, sender, _ := ed25519.GenerateKey(nil)
	evTrigger := randID("tr")
	env, _ := trigger.SignDefinition(se.definition(func(d *trigger.Definition) {
		d.Triggers = []trigger.Trigger{{ID: evTrigger, Kind: trigger.Event, Sender: identity.KeyString(sender.Public().(ed25519.PublicKey))}}
	}), se.sponsor.Identity)
	if code, body := se.install(env); code != 200 {
		t.Fatalf("install %d %s", code, body)
	}
	post := func(env safety.Envelope) (int, string) {
		return se.call(func(w *httptest.ResponseRecorder, b []byte) {
			se.s.triggersEvent(w, httptest.NewRequest("POST", "/triggers/event", bytes.NewReader(b)))
		}, env)
	}
	ev, _ := trigger.SignEvent(trigger.EventPayload{Trigger: evTrigger, Delivery: "msg-1", SentAt: time.Now()}, sender)
	code, body := post(ev)
	if code != 200 {
		t.Fatalf("event %d %s", code, body)
	}
	var out struct {
		Task string `json:"task"`
	}
	json.Unmarshal([]byte(body), &out)
	if st, _ := se.s.rt.Status(out.Task); st.Taint != "event" {
		t.Fatalf("event task %+v", st)
	}
	if code, _ := post(ev); code != 409 {
		t.Fatalf("replay: %d", code)
	}
	_, impostor, _ := ed25519.GenerateKey(nil)
	forged, _ := trigger.SignEvent(trigger.EventPayload{Trigger: evTrigger, Delivery: "msg-2", SentAt: time.Now()}, impostor)
	if code, _ := post(forged); code != 403 {
		t.Fatalf("forged: %d", code)
	}
}
