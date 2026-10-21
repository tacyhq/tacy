package main

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	jsonv2 "encoding/json/v2"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/tacyhq/tacy/activity"
	"github.com/tacyhq/tacy/guard"
	"github.com/tacyhq/tacy/harness"
	"github.com/tacyhq/tacy/runauth"
	"github.com/tacyhq/tacy/safety"
	"github.com/tacyhq/tacy/trigger"
)

// Schedules for personal spaces in agentd (v0.12.0, SCHEDULES.md): installs need the space proof and the identity's
// signature for this boot, once; the run is recorded in the space's chain and its result sealed to the space's seal
// key; only the space's holder lists, fetches, stops or removes; the run's budget and permissions are the
// definition's, never asked.

// testSealKey is a valid seal key for definitions whose records nobody opens (the firm-style trigger tests).
var testSealKey = func() string {
	k, _ := ecdh.X25519().GenerateKey(rand.Reader)
	return runauth.SealString(k.PublicKey())
}()

type schedEnv struct {
	*safeEnv
	me    *runauth.Asker
	store *trigger.MemStore
}

func newSchedEnv(t *testing.T, replies ...string) *schedEnv {
	e := &schedEnv{safeEnv: newSafeEnvWith(t, safeOpts{}, replies...), store: trigger.NewMemStore()}
	e.mustPost(e.policy(1, nil), e.heartbeat())
	var err error
	if e.me, err = runauth.NewAsker(); err != nil {
		t.Fatal(err)
	}
	s := e.s
	holders, results := &trigger.MemHolders{}, &trigger.MemResults{}
	dir := &trigger.HolderDirectory{Firm: "f_chat", Store: holders}
	s.dir, s.holders, s.results = dir, holders, results
	s.triggers = trigger.New(trigger.Config{Firm: "f_chat", Dir: dir, Store: e.store, IDKey: []byte("agentd id key"), Trusted: s.safety.OperatorTime})
	s.tasks().TriggeredDone = s.triggeredDone
	return e
}

func (e *schedEnv) vm() []byte { return e.vmKey.PublicKey().Bytes() }

// call posts body to a schedules handler and returns the status and the decoded answer.
func (e *schedEnv) call(h http.HandlerFunc, body any) (int, map[string]any) {
	b, _ := jsonv2.Marshal(body)
	w := httptest.NewRecorder()
	h(w, httptest.NewRequest("POST", "/schedules/x", bytes.NewReader(b)))
	var out map[string]any
	json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

// where is a fresh signed where and who for asker a.
func (e *schedEnv) where(a *runauth.Asker, label string, items ...string) runauth.Where {
	w, err := a.Call(label, e.vm(), items...)
	if err != nil {
		e.t.Fatal(err)
	}
	return w
}

// daily is a personal definition for asker a: one daily trigger two minutes ago (UTC), so the next tick fires it.
func (e *schedEnv) daily(a *runauth.Asker, edit func(*trigger.Definition)) trigger.Definition {
	now := time.Now().UTC()
	d := trigger.Definition{Firm: "f_chat", Space: a.Space, Agent: randID("a"), Version: 1, Seal: a.SealString(),
		Instructions: "Every morning, read https://news.ycombinator.com/ and send me a digest of the top stories.",
		Models:       []string{"deepseek-v4-1-flash"}, Tools: []string{"web.fetch"}, MaxSteps: 20,
		Triggers: []trigger.Trigger{{ID: randID("tr"), Kind: trigger.Schedule, Daily: now.Add(-2 * time.Minute).Format("15:04"), Zone: "UTC"}},
		Allow:    map[string]string{"web.fetch": safety.PermAlways}, Author: a.Identity, Sponsor: a.Identity,
		IssuedAt: now.Add(-10 * time.Minute), NotAfter: now.Add(trigger.DefaultSponsorship)}
	if edit != nil {
		edit(&d)
	}
	return d
}

func (e *schedEnv) sign(d trigger.Definition, keys ...ed25519.PrivateKey) safety.Envelope {
	env, err := trigger.SignDefinition(d, keys...)
	if err != nil {
		e.t.Fatal(err)
	}
	return env
}

func (e *schedEnv) install(a *runauth.Asker, env safety.Envelope) (int, map[string]any) {
	return e.call(e.s.scheduleInstall, installRequest{Where: e.where(a, runauth.InstallLabel, env.Hash()), Definition: env})
}

func errOf(out map[string]any) string { s, _ := out["error"].(string); return s }

// Forged, replayed and misdirected installs are refused; a non-holder can't sponsor; the holder's install works,
// is idempotent, and keeps its version floor.
func TestScheduleInstallRefusals(t *testing.T) {
	e := newSchedEnv(t)
	d := e.daily(e.me, nil)
	env := e.sign(d, e.me.Key)
	other, _ := runauth.NewAsker()

	cases := map[string]struct {
		req  func() installRequest
		code int
		err  string
	}{
		"signed by another key": {func() installRequest {
			w := e.where(e.me, runauth.InstallLabel, env.Hash())
			w.IdentitySig = runauth.SignCall(other.Key, runauth.InstallLabel, &w, e.vm(), env.Hash())
			return installRequest{Where: w, Definition: env}
		}, 403, "bad_proof"},
		"signed for another call": {func() installRequest {
			return installRequest{Where: e.where(e.me, runauth.ListLabel), Definition: env}
		}, 403, "bad_proof"},
		"signed for another definition": {func() installRequest {
			x := e.sign(e.daily(e.me, nil), e.me.Key)
			return installRequest{Where: e.where(e.me, runauth.InstallLabel, x.Hash()), Definition: env}
		}, 403, "bad_proof"},
		"made for another VM": {func() installRequest {
			vm2, _ := ecdh.X25519().GenerateKey(rand.Reader)
			w, _ := e.me.Call(runauth.InstallLabel, vm2.PublicKey().Bytes(), env.Hash())
			return installRequest{Where: w, Definition: env}
		}, 403, "bad_proof"},
		"no space proof": {func() installRequest {
			w := e.where(e.me, runauth.InstallLabel, env.Hash())
			w.SpaceProof = bytes.Repeat([]byte{1}, 32)
			return installRequest{Where: w, Definition: env}
		}, 403, "bad_proof"},
		"stale signed_at": {func() installRequest {
			a := *e.me
			a.Now = func() time.Time { return time.Now().Add(-10 * time.Minute) }
			return installRequest{Where: e.where(&a, runauth.InstallLabel, env.Hash()), Definition: env}
		}, 403, "bad_proof"},
		"another person's space": {func() installRequest {
			return installRequest{Where: e.where(other, runauth.InstallLabel, env.Hash()), Definition: env} // they don't sponsor it
		}, 403, "not_holder"},
		"a sponsor who never proved the space": {func() installRequest {
			x := e.sign(e.daily(e.me, func(d *trigger.Definition) { d.Author, d.Sponsor = other.Identity, other.Identity }), other.Key)
			return installRequest{Where: e.where(e.me, runauth.InstallLabel, x.Hash()), Definition: x}
		}, 403, "not_holder"},
		"definition not signed by the holder": {func() installRequest {
			x := e.sign(d, other.Key)
			return installRequest{Where: e.where(e.me, runauth.InstallLabel, x.Hash()), Definition: x}
		}, 403, "bad_definition"},
		"another seal key": {func() installRequest {
			x := e.sign(e.daily(e.me, func(d *trigger.Definition) { d.Seal = testSealKey }), e.me.Key)
			return installRequest{Where: e.where(e.me, runauth.InstallLabel, x.Hash()), Definition: x}
		}, 403, "bad_definition"},
		"a sending tool": {func() installRequest {
			x := e.sign(e.daily(e.me, func(d *trigger.Definition) { d.Tools = []string{"sink.post"} }), e.me.Key)
			return installRequest{Where: e.where(e.me, runauth.InstallLabel, x.Hash()), Definition: x}
		}, 403, "bad_definition"},
		"an every-15-minutes schedule": {func() installRequest {
			x := e.sign(e.daily(e.me, func(d *trigger.Definition) {
				d.Triggers = []trigger.Trigger{{ID: randID("tr"), Kind: trigger.Schedule, Every: "15m", Anchor: d.IssuedAt}}
			}), e.me.Key)
			return installRequest{Where: e.where(e.me, runauth.InstallLabel, x.Hash()), Definition: x}
		}, 403, "bad_definition"},
		"over 20 steps": {func() installRequest {
			x := e.sign(e.daily(e.me, func(d *trigger.Definition) { d.MaxSteps = 21 }), e.me.Key)
			return installRequest{Where: e.where(e.me, runauth.InstallLabel, x.Hash()), Definition: x}
		}, 403, "bad_definition"},
		"over a year": {func() installRequest {
			x := e.sign(e.daily(e.me, func(d *trigger.Definition) { d.NotAfter = d.IssuedAt.Add(367 * 24 * time.Hour) }), e.me.Key)
			return installRequest{Where: e.where(e.me, runauth.InstallLabel, x.Hash()), Definition: x}
		}, 403, "bad_definition"},
	}
	for name, c := range cases {
		code, out := e.call(e.s.scheduleInstall, c.req())
		if code != c.code || errOf(out) != c.err {
			t.Errorf("%s: %d %v, want %d %s", name, code, out, c.code, c.err)
		}
	}
	if _, n := e.s.triggers.SpaceCount(e.me.Space); n != 0 {
		t.Fatalf("%d installed after refusals", n)
	}
	// The holder's install; the very same request again is a replay; the same definition in a new request is fine.
	req := installRequest{Where: e.where(e.me, runauth.InstallLabel, env.Hash()), Definition: env}
	if code, out := e.call(e.s.scheduleInstall, req); code != 200 || out["state"] != "active" || out["version"] != float64(1) {
		t.Fatalf("install: %d %v", code, out)
	}
	if code, out := e.call(e.s.scheduleInstall, req); code != 409 || errOf(out) != "replayed" {
		t.Fatalf("replayed install: %d %v", code, out)
	}
	if code, _ := e.install(e.me, env); code != 200 {
		t.Fatalf("same definition again: %d", code)
	}
	// Another version 1 with other bytes: the floor.
	d2 := d
	d2.Instructions += " Keep it short."
	if code, out := e.install(e.me, e.sign(d2, e.me.Key)); code != 409 || errOf(out) != "stale_version" {
		t.Fatalf("other bytes at the same version: %d %v", code, out)
	}
	// Someone else can't take the agent id over from their own space.
	o := e.daily(other, func(x *trigger.Definition) { x.Agent, x.Version = d.Agent, 5 })
	if code, out := e.install(other, e.sign(o, other.Key)); code != 403 {
		t.Fatalf("agent id taken over from another space: %d %v", code, out)
	}
	// The renewal: version 2, one signature, a later not_after.
	d2.Version, d2.NotAfter = 2, d.NotAfter.Add(30*24*time.Hour)
	if code, out := e.install(e.me, e.sign(d2, e.me.Key)); code != 200 || out["version"] != float64(2) {
		t.Fatalf("renewal: %d %v", code, out)
	}
	// At most 8 per space.
	for i := 0; i < 7; i++ {
		if code, out := e.install(e.me, e.sign(e.daily(e.me, nil), e.me.Key)); code != 200 {
			t.Fatalf("schedule %d: %d %v", i+2, code, out)
		}
	}
	if code, out := e.install(e.me, e.sign(e.daily(e.me, nil), e.me.Key)); code != 429 || errOf(out) != "too_many_schedules" {
		t.Fatalf("ninth: %d %v", code, out)
	}
}

// A firm VM (no holder directory) takes no schedule calls; the old route refuses personal installs.
func TestScheduleRoutesFailClosed(t *testing.T) {
	e := newSafeEnv(t)
	for name, h := range map[string]http.HandlerFunc{"install": e.s.scheduleInstall, "list": e.s.scheduleList, "stop": e.s.scheduleStop,
		"results": e.s.scheduleResults, "result": e.s.scheduleResult} {
		a, _ := runauth.NewAsker()
		w, _ := a.Call(runauth.ListLabel, e.vmKey.PublicKey().Bytes())
		b, _ := jsonv2.Marshal(w)
		rr := httptest.NewRecorder()
		h(rr, httptest.NewRequest("POST", "/", bytes.NewReader(b)))
		if rr.Code != 503 || !strings.Contains(rr.Body.String(), "identity_unavailable") {
			t.Errorf("%s: %d %s", name, rr.Code, rr.Body)
		}
	}
	se := newSchedEnv(t)
	rr := httptest.NewRecorder()
	se.s.triggersInstall(rr, httptest.NewRequest("POST", "/triggers", strings.NewReader("{}")))
	if rr.Code != 404 {
		t.Fatalf("POST /triggers on the personal VM: %d %s", rr.Code, rr.Body)
	}
}

// waitResult polls for a task's sealed result.
func (e *schedEnv) waitResult(task string) *trigger.Result {
	for end := time.Now().Add(20 * time.Second); time.Now().Before(end); time.Sleep(20 * time.Millisecond) {
		if r, _ := e.s.results.GetResult(e.me.Space, e.me.SealString(), task); r != nil {
			return r
		}
	}
	e.t.Fatalf("no result for %s", task)
	return nil
}

// openResult fetches a result over the route and opens it with the seal key.
func (e *schedEnv) openResult(a *runauth.Asker, task string) (int, *resultBody) {
	code, out := e.call(e.s.scheduleResult, taskRequest{Where: e.where(a, runauth.ResultLabel, task), Task: task})
	if code != 200 {
		return code, nil
	}
	sealed, _ := out["sealed"].(map[string]any)
	enc, _ := jsonDecodeB64(sealed["enc"])
	ct, _ := jsonDecodeB64(sealed["ct"])
	pt, err := activity.OpenFrom(a.Seal, []byte(resultInfo), resultAAD(a.Space, task), enc, ct)
	if err != nil {
		e.t.Fatalf("open: %v", err)
	}
	var b resultBody
	if err := jsonv2.Unmarshal(bytes.TrimRight(pt, " "), &b); err != nil {
		e.t.Fatal(err)
	}
	return code, &b
}

func jsonDecodeB64(v any) ([]byte, error) {
	var b []byte
	s, _ := json.Marshal(v)
	err := json.Unmarshal(s, &b)
	return b, err
}

// A scheduled run end to end: fired by the tick as its sponsor, recorded in the space's chain (sealed to the seal
// key, trigger "schedule"), its result sealed to the seal key and the plaintext task forgotten; only the holder of
// that seal key lists and fetches it; a search the definition doesn't allow is denied without asking anyone.
func TestScheduledRunRecordedAndSealed(t *testing.T) {
	e := newSchedEnv(t, pCalls([3]string{"c1", "web_search", `{"query":"hacker news"}`}), pText("Today's digest: nothing new [1]."))
	// The tools include searches, but the definition doesn't allow them: denied at run time, nobody asked.
	d := e.daily(e.me, func(d *trigger.Definition) { d.Tools = []string{"web.fetch", "web.search"} })
	if code, out := e.install(e.me, e.sign(d, e.me.Key)); code != 200 {
		t.Fatalf("install %d %v", code, out)
	}
	e.s.triggerTick(context.Background())
	tasks := e.s.tasks().Triggered()
	if len(tasks) != 1 {
		t.Fatalf("%d tasks after the tick", len(tasks))
	}
	var task string
	for id, o := range tasks {
		task = id
		if o.RecordTo != e.me.SealString() || o.Identity != e.me.Identity || o.Member != guard.ScheduleMember(d.Agent) ||
			o.Agent != guard.AgentScheduled || o.DefAgent != d.Agent || o.RunSecret != "" {
			t.Fatalf("options %+v", o)
		}
	}
	e.s.triggerTick(context.Background()) // the same day doesn't fire again
	r := e.waitResult(task)
	if r.State != harness.OutcomeSucceeded || r.Agent != d.Agent || r.Day != time.Now().Add(-2*time.Minute).UTC().Format(time.DateOnly) {
		t.Fatalf("result %+v", r)
	}
	if st, _ := e.s.rt.Store.Task(task); st != nil {
		t.Fatal("the plaintext task is still kept after its result was sealed")
	}
	// The listing; fetch and open.
	code, out := e.call(e.s.scheduleResults, resultsRequest{Where: e.where(e.me, runauth.ResultsLabel, "0")})
	list, _ := out["results"].([]any)
	if code != 200 || len(list) != 1 || out["more"] != false {
		t.Fatalf("results %d %v", code, out)
	}
	_, body := e.openResult(e.me, task)
	text, denied, prompted := "", false, false
	var recs []activity.Sealed
	for _, ev := range body.Events {
		switch ev.Type {
		case "text":
			text += ev.Delta
		case "permission":
			if ev.Permission.Decision == "" {
				prompted = true
			} else {
				denied = true
			}
		case "tool_result":
			if strings.Contains(string(ev.Result), "denied") || strings.Contains(ev.Error, "denied") {
				denied = true
			}
		case "activity":
			for _, raw := range ev.Activity {
				var s activity.Sealed
				json.Unmarshal(raw, &s)
				recs = append(recs, s)
			}
		case "reasoning", "metrics":
			t.Fatalf("%s event kept in the result", ev.Type)
		}
	}
	if !strings.Contains(text, "Today's digest") || prompted || !denied {
		t.Fatalf("text %q prompted %v denied %v (events %+v)", text, prompted, denied, body.Events)
	}
	if len(e.fs.queries) != 0 {
		t.Fatalf("a search the definition doesn't allow went out: %v", e.fs.queries)
	}
	if len(recs) != 2 {
		t.Fatalf("%d activity records", len(recs))
	}
	_, start, err := activity.Open(recs[0], e.me.Seal, nil)
	if err != nil || start.Trigger.Kind != "schedule" || start.Trigger.Via != "trigger" || start.Member != e.me.Identity ||
		start.Agent.ID != d.Agent || start.Space != e.me.Space || start.Limits.MaxSteps != 20 {
		t.Fatalf("start record %+v %v", start, err)
	}
	// The records are also in the space's chain for GET /activity.
	if _, head, err := e.rec.Head(e.me.Space, e.me.SealString()); err != nil || head.Seq != 2 {
		t.Fatalf("chain head %+v %v", head, err)
	}
	// Someone else can't list or fetch it (another space, or this space with another seal key).
	other, _ := runauth.NewAsker()
	if code, out := e.call(e.s.scheduleResults, resultsRequest{Where: e.where(other, runauth.ResultsLabel, "0")}); code != 200 || len(out["results"].([]any)) != 0 {
		t.Fatalf("another's listing: %d %v", code, out)
	}
	if code, _ := e.openResult(other, task); code != 404 {
		t.Fatalf("another's fetch: %d", code)
	}
	spoof := &runauth.Asker{Space: e.me.Space, Seal: other.Seal, Identity: other.Identity, Key: other.Key}
	if code, _ := e.openResult(spoof, task); code != 404 {
		t.Fatalf("this space named with another seal key: %d", code)
	}
	// Sealed to the seal key, bound to its space and task: it doesn't open as another task's.
	if _, err := activity.OpenFrom(e.me.Seal, []byte(resultInfo), resultAAD(e.me.Space, "tk_other"), r.Enc, r.CT); err == nil {
		t.Fatal("a result opened under another task's associated data")
	}
	// The listing shows the run; deleting it.
	_, lo := e.call(e.s.scheduleList, e.where(e.me, runauth.ListLabel))
	sched := lo["schedules"].([]any)[0].(map[string]any)
	tr := sched["triggers"].([]any)[0].(map[string]any)
	if sched["state"] != "active" || tr["last_task"] != task || tr["next_run"] == nil || sched["running"] != float64(0) {
		t.Fatalf("list %v", sched)
	}
	if code, out := e.call(e.s.scheduleResultsDelete, tasksRequest{Where: e.where(e.me, runauth.ResultsDeleteLabel, task), Tasks: []string{task}}); code != 200 || out["deleted"] != float64(1) {
		t.Fatalf("delete %d %v", code, out)
	}
	if code, _ := e.openResult(e.me, task); code != 404 {
		t.Fatalf("deleted result fetched: %d", code)
	}
}

// The per-run budget ($0.25): a run whose model calls use it up ends with budget_exceeded, counted in the schedule's
// own bucket (not the person's).
func TestScheduledRunBudgetCutoff(t *testing.T) {
	const bigPrompt = 500_000 // deepseek-v4-1-flash: about $0.33, under the run's 4M tokens
	if c := safety.ModelCost("deepseek-v4-1-flash", bigPrompt, 0); c <= 250_000 {
		t.Fatalf("the test's call costs only %d micro-USD", c)
	}
	big := `data: {"choices":[{"delta":{"tool_calls":[{"index":0,"id":"c1","function":{"name":"` + modelTool("fetch_page") +
		`","arguments":"{\"url\":\"https://news.ycombinator.com/\"}"}}]},"finish_reason":"tool_calls"}]}` +
		"\n\ndata: {\"choices\":[],\"usage\":{\"prompt_tokens\":" + strconv.Itoa(bigPrompt) + ",\"completion_tokens\":5,\"total_tokens\":" +
		strconv.Itoa(bigPrompt+5) + "}}\n\ndata: [DONE]\n\n"
	e := newSchedEnv(t, big, pText("never reached"))
	d := e.daily(e.me, nil)
	if code, out := e.install(e.me, e.sign(d, e.me.Key)); code != 200 {
		t.Fatalf("install %d %v", code, out)
	}
	e.s.triggerTick(context.Background())
	var task string
	for id := range e.s.tasks().Triggered() {
		task = id
	}
	r := e.waitResult(task)
	if r.State != harness.OutcomeFailed || r.Code != safety.CodeBudgetExceeded {
		t.Fatalf("result %+v", r)
	}
	if n := e.modelReqs.Load(); n != 1 {
		t.Fatalf("%d model calls: the call past the budget went out", n)
	}
}

// GET /tasks/open's keep-on count: active schedules only, a count with no times; stop and remove.
func TestScheduleCountStopRemove(t *testing.T) {
	e := newSchedEnv(t)
	open := func() map[string]int {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "/tasks/open", nil)
		r.Header.Set("Authorization", "Bearer tok")
		e.s.tasksOpen(w, r)
		var out map[string]int
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil || len(out) != 2 {
			t.Fatalf("GET /tasks/open: %s", w.Body)
		}
		return out
	}
	if o := open(); o["schedules"] != 0 {
		t.Fatalf("%v", o)
	}
	d := e.daily(e.me, func(d *trigger.Definition) {
		d.Triggers[0].Daily = time.Now().UTC().Add(3 * time.Hour).Format("15:04") // later today: no run in this test
	})
	env := e.sign(d, e.me.Key)
	e.install(e.me, env)
	if o := open(); o["schedules"] != 1 || o["open"] != 0 {
		t.Fatalf("%v", o)
	}
	// Only the holder stops it.
	other, _ := runauth.NewAsker()
	if code, out := e.call(e.s.scheduleStop, agentRequest{Where: e.where(other, runauth.StopLabel, d.Agent), Agent: d.Agent}); code != 404 {
		t.Fatalf("another's stop: %d %v", code, out)
	}
	if code, out := e.call(e.s.scheduleStop, agentRequest{Where: e.where(e.me, runauth.RemoveLabel, d.Agent), Agent: d.Agent}); code != 403 {
		t.Fatalf("a remove signature used to stop: %d %v", code, out)
	}
	if code, out := e.call(e.s.scheduleStop, agentRequest{Where: e.where(e.me, runauth.StopLabel, d.Agent), Agent: d.Agent}); code != 200 || out["state"] != "stopped" {
		t.Fatalf("stop: %d %v", code, out)
	}
	if o := open(); o["schedules"] != 0 {
		t.Fatalf("after stop %v", o)
	}
	_, lo := e.call(e.s.scheduleList, e.where(e.me, runauth.ListLabel))
	if s := lo["schedules"].([]any); len(s) != 1 || s[0].(map[string]any)["state"] != "stopped" || s[0].(map[string]any)["triggers"].([]any)[0].(map[string]any)["next_run"] != nil {
		t.Fatalf("list after stop %v", lo)
	}
	if code, _ := e.install(e.me, env); code != 409 {
		t.Fatalf("stopped version reinstalled: %d", code)
	}
	if code, out := e.call(e.s.scheduleRemove, agentRequest{Where: e.where(e.me, runauth.RemoveLabel, d.Agent), Agent: d.Agent}); code != 200 || out["state"] != "removed" {
		t.Fatalf("remove: %d %v", code, out)
	}
	_, lo = e.call(e.s.scheduleList, e.where(e.me, runauth.ListLabel))
	if s := lo["schedules"].([]any); len(s) != 0 {
		t.Fatalf("list after remove %v", lo)
	}
	if code, _ := e.install(e.me, env); code != 409 {
		t.Fatalf("removed version reinstalled: %d", code)
	}
	d.Version = 2
	if code, out := e.install(e.me, e.sign(d, e.me.Key)); code != 200 {
		t.Fatalf("next version: %d %v", code, out)
	}
}

// Every model the chat may sign a schedule with (its model list and the plan's default) installs;
// one this release doesn't have is refused at install, not at each slot.
func TestScheduleInstallModels(t *testing.T) {
	e := newSchedEnv(t)
	for _, m := range []string{"deepseek-v4-1-flash", "gpt-oss-120b", "gemma4-31b", "glm-5-3", "kimi-k3"} {
		d := e.daily(e.me, func(d *trigger.Definition) { d.Models = []string{m} })
		if code, out := e.install(e.me, e.sign(d, e.me.Key)); code != 200 {
			t.Errorf("%s: %d %v", m, code, out)
		}
		e.s.triggers.Stop(d.Agent, true) // room for the next (8 per space)
	}
	d := e.daily(e.me, func(d *trigger.Definition) { d.Models = []string{"gpt-9"} })
	if code, out := e.install(e.me, e.sign(d, e.me.Key)); code != 403 || errOf(out) != "bad_definition" {
		t.Fatalf("unknown model: %d %v", code, out)
	}
}
