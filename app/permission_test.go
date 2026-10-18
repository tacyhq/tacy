package main

import (
	"bytes"
	"crypto/ecdh"
	"encoding/json"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/tacyhq/tacy/activity"
	"github.com/tacyhq/tacy/guard"
	"github.com/tacyhq/tacy/proto"
	"github.com/tacyhq/tacy/safety"
)

// Permission prompts in agentd (docs/27 section 6): a search, a page fetch or an image search waits for the
// person's answer from the tab that started the run (a grant with the run's secret), unless their setting already
// decides it. Run as the chat does it, through POST /run, with the in-process guard checking each grant again.

const permSecret = "0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0"

type permEnv struct {
	*safeEnv
	prompts *guard.Prompts
	asks    chan proto.Permission // prompts shown (waiting for an answer)
	settled chan proto.Permission // prompts settled
	recPriv *ecdh.PrivateKey      // the person's record key
}

func newPermEnv(t *testing.T, timeout time.Duration, edit func(p *safety.Policy), replies ...string) *permEnv {
	e := newSafeEnv(t, replies...)
	e.mustPost(e.policy(1, edit), e.heartbeat())
	host := e.s.tasks()
	pe := &permEnv{safeEnv: e, asks: make(chan proto.Permission, 16), settled: make(chan proto.Permission, 16)}
	pe.prompts = &guard.Prompts{Release: e.s.rt.Release, Cap: permissionCap(e.s.safety), Timeout: timeout,
		Emit: func(task string, ev proto.Event) {
			host.Emit(task, ev)
			if ev.Type == "permission" && ev.Permission.Decision == "" {
				pe.asks <- *ev.Permission
			} else if ev.Type == "permission" {
				pe.settled <- *ev.Permission
			}
		}}
	e.s.agent.(*recGateway).prompts = pe.prompts
	e.s.prompts = pe.prompts
	return pe
}

// start runs req through POST /run in the background.
func (pe *permEnv) start(req proto.RunRequest) chan []proto.Event {
	done := make(chan []proto.Event, 1)
	go func() { done <- runParity(pe.t, pe.s, req) }()
	return done
}

func (pe *permEnv) ask() proto.Permission {
	pe.t.Helper()
	select {
	case p := <-pe.asks:
		return p
	case <-time.After(10 * time.Second):
		pe.t.Fatal("no prompt shown")
	}
	return proto.Permission{}
}

func (pe *permEnv) noAsk() {
	pe.t.Helper()
	select {
	case p := <-pe.asks:
		pe.t.Fatalf("asked when it shouldn't: %+v", p)
	default:
	}
}

// grant posts an answer to POST /tasks/grant (as the EHBP middleware hands it on) with the MAC made with secret.
func (pe *permEnv) grant(p proto.Permission, secret, decision, value string) (int, string) {
	g := guard.Grant{Task: p.Task, Request: p.Request, Kind: p.Kind, Decision: decision, Value: value}
	g.MAC = guard.GrantMAC(secret, g)
	return pe.post(g)
}

func (pe *permEnv) post(g guard.Grant) (int, string) {
	b, _ := json.Marshal(g)
	w := httptest.NewRecorder()
	pe.s.taskGrant(w, httptest.NewRequest("POST", "/tasks/grant", bytes.NewReader(b)))
	return w.Code, strings.TrimSpace(w.Body.String())
}

func (pe *permEnv) queries() []string {
	pe.fs.mu.Lock()
	defer pe.fs.mu.Unlock()
	return slices.Clone(pe.fs.queries)
}

func wait(t *testing.T, done chan []proto.Event) []proto.Event {
	t.Helper()
	select {
	case evs := <-done:
		if evs[len(evs)-1].Type != "done" {
			t.Fatalf("the run didn't answer: %+v", evs[len(evs)-1])
		}
		return evs
	case <-time.After(20 * time.Second):
		t.Fatal("the run didn't end")
	}
	return nil
}

func askReq(msg string, perms map[string]string) proto.RunRequest {
	return proto.RunRequest{Messages: user1(msg), RunSecret: permSecret, Permissions: perms}
}

func endCalls(t *testing.T, pe *permEnv, evs []proto.Event) []activity.Call {
	t.Helper()
	runs := openedActivity(t, evs, pe.recPriv, pe.rec.Signer.Public())
	var out []activity.Call
	for _, c := range runs[len(runs)-1].Calls {
		if c.Kind == "action" {
			out = append(out, c)
		}
	}
	return out
}

func resultOf(evs []proto.Event, call string) string {
	for _, e := range evs {
		if e.Type == "tool_result" && e.ID == call {
			return string(e.Result)
		}
	}
	return ""
}

// Allow once with an edit: nothing goes out before the answer; what goes out is the person's text, not the model's;
// the person sees the outcome; the record says allowed_once and edited, never the text.
func TestPermissionAllowOnceSendsTheEdit(t *testing.T) {
	pe := newPermEnv(t, 0, nil, pCalls([3]string{"c1", "web_search", `{"query":"dstack release for jane@example.com"}`}), pText("v0.6.1 [1]"))
	pe.recPriv, _ = recipientKey(t)
	done := pe.start(pe.recorded(pe.recPriv, askReq("latest dstack?", nil)))
	p := pe.ask()
	want, _ := guard.Outgoing("web.search", []byte(`{"query":"dstack release for jane@example.com"}`))
	if p.Kind != "web.search" || p.Value != want || strings.Contains(p.Value, "jane@") || p.TimeoutS <= 0 || !strings.HasPrefix(p.Task, "tk_") {
		t.Fatalf("prompt %+v (want the masked query %q)", p, want)
	}
	time.Sleep(100 * time.Millisecond)
	if q := pe.queries(); len(q) != 0 {
		t.Fatalf("searched before the answer: %q", q)
	}
	if code, body := pe.grant(p, permSecret, guard.DecideOnce, "dstack latest release"); code != 200 || !strings.Contains(body, "allowed_once") {
		t.Fatalf("grant: %d %s", code, body)
	}
	evs := wait(t, done)
	if q := pe.queries(); !slices.Equal(q, []string{"dstack latest release"}) {
		t.Fatalf("searched %q, want the person's edit", q)
	}
	s := <-pe.settled
	if s.Decision != guard.PermAllowedOnce || !s.Edited || s.Value != "dstack latest release" {
		t.Fatalf("settled %+v", s)
	}
	calls := endCalls(t, pe, evs)
	if len(calls) != 1 || calls[0].Permission != guard.PermAllowedOnce || !calls[0].Edited || calls[0].Outcome != "ok" {
		t.Fatalf("record: %+v", calls)
	}
	b, _ := json.Marshal(calls)
	if strings.Contains(string(b), "dstack latest") || strings.Contains(string(b), "dstack release") {
		t.Fatalf("the record has the query: %s", b)
	}
}

// Deny: nothing is sent, the model is told it was denied and answers anyway, the person sees the step end, the
// record says denied.
func TestPermissionDenyStillAnswers(t *testing.T) {
	pe := newPermEnv(t, 0, nil, pCalls([3]string{"c1", "web_search", `{"query":"q"}`}), pText("I didn't check the web, but..."))
	pe.recPriv, _ = recipientKey(t)
	done := pe.start(pe.recorded(pe.recPriv, askReq("search it", nil)))
	p := pe.ask()
	if code, body := pe.grant(p, permSecret, guard.DecideDeny, p.Value); code != 200 || !strings.Contains(body, "denied") {
		t.Fatalf("grant: %d %s", code, body)
	}
	evs := wait(t, done)
	if q := pe.queries(); len(q) != 0 {
		t.Fatalf("searched after a deny: %q", q)
	}
	if r := resultOf(evs, "c1"); !strings.Contains(r, "permission_denied") {
		t.Fatalf("the person's step: %q", r)
	}
	pe.model.mu.Lock()
	last := pe.model.bodies[len(pe.model.bodies)-1]
	pe.model.mu.Unlock()
	if !strings.Contains(last, "permission_denied") || !strings.Contains(last, "didn't check the web") {
		t.Fatalf("the model wasn't told: %s", last)
	}
	if calls := endCalls(t, pe, evs); len(calls) != 1 || calls[0].Permission != guard.PermDenied || calls[0].Outcome != "denied" {
		t.Fatalf("record: %+v", calls)
	}
}

// A forged grant (another secret, another kind, a tampered value) is refused and leaves the prompt open; a grant
// is used once: a replay finds no prompt; a grant names its task.
func TestPermissionForgedOrReplayedGrantRefused(t *testing.T) {
	pe := newPermEnv(t, 0, nil, pCalls([3]string{"c1", "web_search", `{"query":"q"}`}), pText("ok"))
	done := pe.start(askReq("search it", nil))
	p := pe.ask()
	other := strings.Repeat("ab", 32)
	if code, _ := pe.grant(p, other, guard.DecideOnce, p.Value); code != 403 {
		t.Fatalf("a grant with another secret: %d", code)
	}
	wrongKind := p
	wrongKind.Kind = "web.fetch"
	if code, _ := pe.grant(wrongKind, permSecret, guard.DecideOnce, "https://example.com/"); code != 403 {
		t.Fatalf("a grant for another kind: %d", code)
	}
	g := guard.Grant{Task: p.Task, Request: p.Request, Kind: p.Kind, Decision: guard.DecideOnce, Value: p.Value}
	g.MAC = guard.GrantMAC(permSecret, g)
	g.Value = "something else" // tampered after the MAC
	if code, _ := pe.post(g); code != 403 {
		t.Fatalf("a tampered grant: %d", code)
	}
	otherTask := p
	otherTask.Task = "tk_aaaaaaaaaaaaaaaaaaaaaaaaaa"
	if code, _ := pe.grant(otherTask, permSecret, guard.DecideOnce, p.Value); code != 404 {
		t.Fatalf("a grant for another task: %d", code)
	}
	if code, _ := pe.grant(p, permSecret, "maybe", p.Value); code != 403 {
		t.Fatalf("an unknown decision: %d", code)
	}
	if code, _ := pe.grant(p, permSecret, guard.DecideOnce, "bad\x01value"); code != 400 {
		t.Fatalf("a value with control characters: %d", code)
	}
	if q := pe.queries(); len(q) != 0 {
		t.Fatalf("searched on a refused grant: %q", q)
	}
	if code, _ := pe.grant(p, permSecret, guard.DecideOnce, p.Value); code != 200 {
		t.Fatalf("the real grant: %d", code)
	}
	if code, _ := pe.grant(p, permSecret, guard.DecideOnce, p.Value); code != 404 {
		t.Fatalf("a replayed grant: %d", code)
	}
	wait(t, done)
	if q := pe.queries(); len(q) != 1 {
		t.Fatalf("searched %d times, want once", len(q))
	}
}

// Always allow covers one kind: the run's other waiting prompt of that kind is allowed with it, a later one isn't
// asked, and a page fetch still asks.
func TestPermissionAlwaysCoversOneKind(t *testing.T) {
	pe := newPermEnv(t, 0, nil,
		pCalls([3]string{"c1", "web_search", `{"query":"one"}`}, [3]string{"c2", "web_search", `{"query":"two"}`},
			[3]string{"c3", "fetch_page", `{"url":"https://127.0.0.1:1/x"}`}),
		pCalls([3]string{"c4", "web_search", `{"query":"three"}`}), pText("done"))
	pe.recPriv, _ = recipientKey(t)
	done := pe.start(pe.recorded(pe.recPriv, askReq("look", nil)))
	asked := map[string]proto.Permission{}
	for range 3 {
		p := pe.ask()
		asked[p.Value] = p
	}
	if code, _ := pe.grant(asked["one"], permSecret, guard.DecideAlways, "one"); code != 200 {
		t.Fatal("always")
	}
	// c2 is settled with it; the fetch still waits.
	time.Sleep(200 * time.Millisecond)
	if n := pe.prompts.Waiting(asked["one"].Task); n != 1 {
		t.Fatalf("%d prompts waiting, want the page fetch only", n)
	}
	if code, _ := pe.grant(asked["https://127.0.0.1:1/x"], permSecret, guard.DecideDeny, "https://127.0.0.1:1/x"); code != 200 {
		t.Fatal("deny the fetch")
	}
	evs := wait(t, done)
	pe.noAsk() // c4 wasn't asked
	q := pe.queries()
	slices.Sort(q)
	if !slices.Equal(q, []string{"one", "three", "two"}) {
		t.Fatalf("searched %q", q)
	}
	got := map[string]string{}
	for _, c := range endCalls(t, pe, evs) {
		got[c.Name+" "+c.Permission] = c.Outcome
	}
	if got["web.fetch denied"] != "denied" || got["web.search allowed_always"] != "ok" || len(got) != 2 {
		t.Fatalf("record: %v", got)
	}
}

// Never blocks without asking; Always allow (the setting) runs without asking; both on the record.
func TestPermissionSettingsDecideWithoutAsking(t *testing.T) {
	pe := newPermEnv(t, 0, nil,
		pCalls([3]string{"c1", "web_search", `{"query":"q"}`}, [3]string{"c2", "image_search", `{"query":"posters"}`}), pText("ok"))
	pe.recPriv, _ = recipientKey(t)
	evs := wait(t, pe.start(pe.recorded(pe.recPriv, askReq("q", map[string]string{"web.search": "never", "web.images": "always"}))))
	pe.noAsk()
	for _, q := range pe.queries() {
		if q == "q" {
			t.Fatal("searched with web search set to Never")
		}
	}
	s := <-pe.settled
	if s.Decision != guard.PermNeverSetting || s.Kind != "web.search" {
		t.Fatalf("the person isn't told why: %+v", s)
	}
	if r := resultOf(evs, "c1"); !strings.Contains(r, "settings don't allow web search") {
		t.Fatalf("result %q", r)
	}
	got := map[string]string{}
	for _, c := range endCalls(t, pe, evs) {
		got[c.Name] = c.Permission
	}
	if got["web.search"] != guard.PermNeverSetting || got["web.images"] != guard.PermAlwaysSetting {
		t.Fatalf("record: %v", got)
	}
}

// No answer in time is a deny; the run still answers.
func TestPermissionTimeoutDenies(t *testing.T) {
	pe := newPermEnv(t, 300*time.Millisecond, nil, pCalls([3]string{"c1", "web_search", `{"query":"q"}`}), pText("ok"))
	pe.recPriv, _ = recipientKey(t)
	done := pe.start(pe.recorded(pe.recPriv, askReq("q", nil)))
	p := pe.ask()
	if p.TimeoutS != 0 { // rounds to 0 s: still a prompt
		t.Logf("timeout_s %d", p.TimeoutS)
	}
	evs := wait(t, done)
	if s := <-pe.settled; s.Decision != guard.PermTimedOut {
		t.Fatalf("settled %+v", s)
	}
	if code, _ := pe.grant(p, permSecret, guard.DecideOnce, p.Value); code != 404 {
		t.Fatalf("a grant after the timeout: %d", code)
	}
	if len(pe.queries()) != 0 {
		t.Fatal("searched after a timeout")
	}
	if calls := endCalls(t, pe, evs); len(calls) != 1 || calls[0].Permission != guard.PermTimedOut {
		t.Fatalf("record: %+v", calls)
	}
}

// The firm's cap lowers a person's Always allow to Ask (or Never); a run that can't ask is refused, not sent.
func TestPermissionCapAndNoSecret(t *testing.T) {
	pe := newPermEnv(t, 0, func(p *safety.Policy) {
		p.AskCap = map[string]string{"web.search": safety.PermAsk, "web.images": safety.PermNever}
	}, pCalls([3]string{"c1", "web_search", `{"query":"q"}`}, [3]string{"c2", "image_search", `{"query":"posters"}`}), pText("ok"),
		pCalls([3]string{"c3", "web_search", `{"query":"q2"}`}), pText("ok"))
	done := pe.start(askReq("q", guard.AllowAll()))
	p := pe.ask() // asked despite the person's Always allow
	if p.Kind != "web.search" {
		t.Fatalf("prompt %+v", p)
	}
	pe.grant(p, permSecret, guard.DecideOnce, p.Value)
	wait(t, done)
	pe.noAsk() // image search capped to Never: not asked
	if q := pe.queries(); !slices.Equal(q, []string{"q"}) {
		t.Fatalf("searched %q", q)
	}
	// Without a run secret nothing can be asked: the Ask kind is refused at once.
	req := askReq("q", nil)
	req.RunSecret = ""
	evs := wait(t, pe.start(req))
	pe.noAsk()
	if r := resultOf(evs, "c3"); !strings.Contains(r, "can't ask the person") {
		t.Fatalf("result %q", r)
	}
	if q := pe.queries(); len(q) != 1 {
		t.Fatalf("searched %q", q)
	}
}

// A bad run secret or setting is refused at the start.
func TestPermissionStartChecks(t *testing.T) {
	pe := newPermEnv(t, 0, nil)
	for _, r := range []proto.RunRequest{
		{Messages: user1("q"), RunSecret: "short"},
		{Messages: user1("q"), RunSecret: strings.ToUpper(permSecret)},
		{Messages: user1("q"), Permissions: map[string]string{"web.search": "sometimes"}},
		{Messages: user1("q"), Permissions: map[string]string{"mail.send": "always"}},
	} {
		if _, _, err := pe.s.agent.StartFor(&r); err == nil {
			t.Errorf("accepted %+v", r)
		}
	}
}
