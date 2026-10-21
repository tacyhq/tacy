package main

import (
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tacyhq/tacy/approval"
	"github.com/tacyhq/tacy/guard"
	"github.com/tacyhq/tacy/harness"
	"github.com/tacyhq/tacy/identity"
	"github.com/tacyhq/tacy/queue"
	"github.com/tacyhq/tacy/runauth"
	"github.com/tacyhq/tacy/safety"
	"github.com/tacyhq/tacy/trigger"
)

// Schedule upgrades (the release after v0.14.0, SCHEDULES.md): searching, memory across runs and "only tell me when
// something changes", through agentd's routes, the trigger engine, the runtime, the brain and the guard, with a
// scripted model (no inference).

// wireApprovals wires approve-before-send as main does on the chat VM (no approvers): an action the approval table
// (approval/class.go) doesn't know is a Send and is refused, so a run's tools must all be classified.
func (e *schedEnv) wireApprovals() {
	rg := e.s.agent.(*recGateway)
	e.s.approvals = &guard.Approvals{Release: e.s.rt.Release, Store: approval.NewMemStore(), IDKey: []byte("agentd id key"),
		OnWait: rg.waiting, Emit: e.s.tasks().Emit, Check: approval.Config{RP: ReleaseRP},
		Listed: func(space, action string) bool {
			p, err := e.s.safety.Policy(space)
			return err == nil && p.NeedsApproval(action)
		}}
	rg.approvals = e.s.approvals
}

// withMemory gives the env the side file's memory (in memory), as main does on the shared chat VM.
func (e *schedEnv) withMemory() *trigger.MemMemory {
	m := &trigger.MemMemory{}
	e.s.memory = m
	e.s.tasks().Memory = e.s.scheduleMemory
	return m
}

// runOnce installs d (a one-time trigger at the engine clock's next minute, a new trigger id per version), moves the
// engine's clock just past it (forward only: it never runs back past its high-water mark; a few runs stay within the
// operator time's 5 minutes), fires it and waits for its sealed result.
func (e *schedEnv) runOnce(shift *atomic.Int64, d trigger.Definition) *trigger.Result {
	e.t.Helper()
	now := time.Now().Add(time.Duration(shift.Load())).UTC()
	at := now.Add(time.Minute).Truncate(time.Minute)
	d.Triggers = []trigger.Trigger{{ID: randID("tr"), Kind: trigger.Schedule, At: at.Format("2006-01-02T15:04"), Zone: "UTC"}}
	if code, out := e.install(e.me, e.sign(d, e.me.Key)); code != 200 {
		e.t.Fatalf("install v%d: %d %v", d.Version, code, out)
	}
	shift.Add(int64(at.Sub(time.Now().Add(time.Duration(shift.Load()))) + 2*time.Second))
	e.s.triggerTick(context.Background())
	var task string
	for id := range e.s.tasks().Triggered() {
		task = id
	}
	if task == "" {
		e.t.Fatalf("v%d didn't fire", d.Version)
	}
	return e.waitResult(task)
}

func (e *schedEnv) modelBody(i int) string {
	e.model.mu.Lock()
	defer e.model.mu.Unlock()
	if i >= len(e.model.bodies) {
		e.t.Fatalf("model call %d of %d", i+1, len(e.model.bodies))
	}
	return e.model.bodies[i]
}

// Three runs of one "tell me when a new version is out" schedule that searches and remembers:
//  1. its first run searches (the definition allows it; nobody asked), reports, and is remembered with the source it
//     cited; it isn't offered schedule_no_change (nothing to compare with);
//  2. the next run gets that memory as data and the tool; it calls it: its result is quiet (listed and sealed so),
//     with its note, and remembered as quiet;
//  3. the next run sees both, newest first; it is tainted from its start, so an address from the memory that it
//     writes itself isn't opened; it reports the change (not quiet).
//
// Removing the schedule deletes its memory; a later version without memory deletes it too.
func TestScheduleSearchMemoryAndQuiet(t *testing.T) {
	e := newSchedEnv(t,
		pCalls([3]string{"c1", "web_search", `{"query":"rust latest stable release"}`}), pText("Rust 1.90 is the latest stable release [1]."),
		pCalls([3]string{"c2", guard.NoChangeTool, `{"note":"still Rust 1.90"}`}), pText("No change."),
		pCalls([3]string{"c3", "fetch_page", `{"url":"https://github.com/Dstack-TEE/dstack/releases/tag/v0.6.1"}`}), pText("Rust 1.91 is out."))
	mem := e.withMemory()
	shift := e.shiftedEngine()
	e.wireApprovals()
	// Run notifications on (notify.go): a run that reports marks the space "done"; a quiet one marks nothing.
	e.s.notify, _ = openNotifier("")
	if code, out := e.call(e.s.notifySet, notifySetRequest{Where: e.where(e.me, runauth.NotifyLabel, "on"), On: true}); code != 200 {
		t.Fatalf("notify on: %d %v", code, out)
	}
	done := `{"events":[{"space":"` + e.me.Space + `","kind":"done"}]}`
	d := e.daily(e.me, func(d *trigger.Definition) {
		d.Instructions = "Tell me when a new stable Rust version is out."
		d.Tools = []string{"web.fetch", "web.search"}
		d.Allow = map[string]string{"web.fetch": safety.PermAlways, "web.search": safety.PermAlways}
		d.Memory, d.Notify = true, trigger.NotifyChanges
	})

	// 1: searches, reports, remembered.
	r1 := e.runOnce(shift, d)
	if r1.State != harness.OutcomeSucceeded || r1.Quiet {
		t.Fatalf("run 1: %+v", r1)
	}
	if got := e.pendingNotices(); got != done {
		t.Fatalf("run 1's notices: %s", got)
	}
	if len(e.fs.queries) != 1 || e.fs.queries[0] != "rust latest stable release" {
		t.Fatalf("searches %v", e.fs.queries)
	}
	b0 := e.modelBody(0)
	if strings.Contains(b0, guard.NoChangeTool) || !strings.Contains(b0, "first run") || !strings.Contains(b0, "at most 6 searches") || strings.Contains(b0, "earlier_run") {
		t.Fatalf("run 1's first model call: %s", b0)
	}
	m, _ := mem.Memories(e.me.Space, d.Agent, time.Time{})
	if len(m) != 1 || m[0].Quiet || !strings.Contains(m[0].Text, "Rust 1.90") || len(m[0].Sources) != 1 ||
		m[0].Sources[0].URL != "https://github.com/Dstack-TEE/dstack/releases/tag/v0.6.1" || m[0].Task != r1.Task {
		t.Fatalf("memory after run 1: %+v", m)
	}

	// 2: compares, nothing changed: quiet.
	d.Version = 2
	r2 := e.runOnce(shift, d)
	if r2.State != harness.OutcomeSucceeded || !r2.Quiet {
		t.Fatalf("run 2: %+v", r2)
	}
	if got := e.pendingNotices(); got != `{"events":[]}` {
		t.Fatalf("a quiet run notified: %s", got)
	}
	b2 := e.modelBody(2)
	if !strings.Contains(b2, guard.NoChangeTool) || !strings.Contains(b2, "earlier_run") || !strings.Contains(b2, "Rust 1.90 is the latest stable release") ||
		strings.Contains(b2, "release [1]") || !strings.Contains(b2, "Tell the person only when something changed") {
		t.Fatalf("run 2's first model call: %s", b2)
	}
	code, out := e.call(e.s.scheduleResults, resultsRequest{Where: e.where(e.me, runauth.ResultsLabel, "0")})
	list, _ := out["results"].([]any)
	if code != 200 || len(list) != 2 || list[0].(map[string]any)["quiet"] != nil || list[1].(map[string]any)["quiet"] != true {
		t.Fatalf("listing %d %v", code, out)
	}
	if _, body := e.openResult(e.me, r2.Task); body == nil || !body.Quiet || body.Note != "still Rust 1.90" {
		t.Fatalf("sealed quiet result %+v", body)
	}
	m, _ = mem.Memories(e.me.Space, d.Agent, time.Time{})
	if len(m) != 2 || !m[0].Quiet || m[0].Text != "still Rust 1.90" || m[1].Quiet {
		t.Fatalf("memory after run 2: %+v", m)
	}

	// 3: sees both; a remembered address it writes isn't opened (tainted from its start); reports the change.
	d.Version = 3
	r3 := e.runOnce(shift, d)
	if r3.State != harness.OutcomeSucceeded || r3.Quiet {
		t.Fatalf("run 3: %+v", r3)
	}
	if got := e.pendingNotices(); got != done {
		t.Fatalf("run 3's notices: %s", got)
	}
	b4 := e.modelBody(4)
	if i, j := strings.Index(b4, "still Rust 1.90"), strings.Index(b4, "Rust 1.90 is the latest"); i < 0 || j < 0 || i > j {
		t.Fatalf("run 3's memory isn't newest first: %s", b4)
	}
	if b5 := e.modelBody(5); !strings.Contains(b5, "not_from_results") {
		t.Fatalf("a remembered address the model wrote was opened: %s", b5)
	}
	if m, _ = mem.Memories(e.me.Space, d.Agent, time.Time{}); len(m) != 3 || m[0].Text != "Rust 1.91 is out." {
		t.Fatalf("memory after run 3: %+v", m)
	}

	// A version without memory deletes it; removing deletes what's left.
	d.Version, d.Memory, d.Notify = 4, false, ""
	if code, out := e.install(e.me, e.sign(d, e.me.Key)); code != 200 {
		t.Fatalf("v4 %d %v", code, out)
	}
	if m, _ = mem.Memories(e.me.Space, d.Agent, time.Time{}); len(m) != 0 {
		t.Fatalf("a version without memory kept it: %+v", m)
	}
	mem.PutMemory(trigger.Remembered{Space: e.me.Space, Agent: d.Agent, Task: "tk_x", EndedAt: time.Now(), Text: "x"})
	if code, out := e.call(e.s.scheduleRemove, agentRequest{Where: e.where(e.me, runauth.RemoveLabel, d.Agent), Agent: d.Agent}); code != 200 || out["memory_deleted"] != float64(1) {
		t.Fatalf("remove %d %v", code, out)
	}
	if m, _ = mem.Memories(e.me.Space, d.Agent, time.Time{}); len(m) != 0 {
		t.Fatal("a removed schedule's memory stayed")
	}
}

// Under a policy signed before the document and schedule connectors (chat-v3, in force until the operator uploads
// chat-v4), a schedule with document.create, memory and "only when something changes" still runs, quietly without
// them: no document_create or schedule_no_change in its start, no note about either, memory asks to skip what was
// reported (not to stay quiet); a schedule_no_change the model calls anyway is refused (it wasn't offered), and the
// result is a normal one (not quiet), which notifies. Under chat-v4 (the next part) the same schedule gets both tools.
func TestScheduleUpgradesUnderOlderPolicy(t *testing.T) {
	e := newSchedEnv(t,
		pText("Rust 1.90 is the latest stable release."),
		pCalls([3]string{"c1", guard.NoChangeTool, `{"note":"still Rust 1.90"}`}), pText("Still Rust 1.90; nothing new."),
		pCalls([3]string{"c2", guard.NoChangeTool, `{"note":"still Rust 1.90"}`}), pText("No change."))
	e.mustPost(e.policy(2, func(p *safety.Policy) {
		delete(p.Connectors, "document")
		delete(p.Connectors, "schedule")
	}), e.heartbeat())
	e.withMemory()
	shift := e.shiftedEngine()
	e.wireApprovals()
	e.s.notify, _ = openNotifier("")
	if code, out := e.call(e.s.notifySet, notifySetRequest{Where: e.where(e.me, runauth.NotifyLabel, "on"), On: true}); code != 200 {
		t.Fatalf("notify on: %d %v", code, out)
	}
	done := `{"events":[{"space":"` + e.me.Space + `","kind":"done"}]}`
	d := e.daily(e.me, func(d *trigger.Definition) {
		d.Instructions = "Tell me when a new stable Rust version is out, as a Word document."
		d.Tools = []string{"web.fetch", guard.DocumentAction}
		d.Memory, d.Notify = true, trigger.NotifyChanges
	})
	offered := func(b, tool string) bool { return strings.Contains(b, `"name":"`+tool+`"`) }
	r1 := e.runOnce(shift, d)
	if r1.State != harness.OutcomeSucceeded || r1.Quiet {
		t.Fatalf("run 1 %+v", r1)
	}
	if b := e.modelBody(0); offered(b, "document_create") || offered(b, guard.NoChangeTool) || strings.Contains(b, "document_create once") {
		t.Fatalf("run 1 under chat-v3 was offered a tool it can't use: %s", b)
	}
	if got := e.pendingNotices(); got != done {
		t.Fatalf("run 1's notices: %s", got)
	}
	d.Version = 2
	r2 := e.runOnce(shift, d)
	if r2.State != harness.OutcomeSucceeded || r2.Quiet {
		t.Fatalf("run 2 %+v", r2)
	}
	b := e.modelBody(1)
	if offered(b, guard.NoChangeTool) || offered(b, "document_create") || strings.Contains(b, "Tell the person only when something changed") ||
		!strings.Contains(b, "Skip what an earlier run already reported") {
		t.Fatalf("run 2 under chat-v3: %s", b)
	}
	if b := e.modelBody(2); !strings.Contains(b, "schedule_no_change isn't available") {
		t.Fatalf("a schedule_no_change under chat-v3 wasn't refused: %s", b)
	}
	if got := e.pendingNotices(); got != done {
		t.Fatalf("run 2's notices: %s", got)
	}

	// chat-v4: the same schedule's next run is offered both and may stay quiet.
	e.mustPost(e.policy(3, nil), e.heartbeat())
	d.Version = 3
	r3 := e.runOnce(shift, d)
	if r3.State != harness.OutcomeSucceeded || !r3.Quiet {
		t.Fatalf("run 3 under chat-v4 %+v", r3)
	}
	if b := e.modelBody(3); !offered(b, guard.NoChangeTool) || !offered(b, "document_create") {
		t.Fatalf("run 3 under chat-v4 wasn't offered its tools: %s", b)
	}
}

// A schedule removed while a release that never reads memory ran (a rollback to v0.14.0: its remove stops the
// definition and deletes the results, not the memory table) loses its memory as soon as this release is back: at
// agentd's start (pruneMemory, after the definitions load) and on each hourly pass. Another schedule's memory stays.
// On a real side file, closed and opened again between the steps as the releases would.
func TestScheduleMemoryOfRemovedScheduleGoesAtStart(t *testing.T) {
	e := newSchedEnv(t, pText("Top stories: A [1]."), pText("Top stories: B [1]."))
	path := filepath.Join(t.TempDir(), "side.db")
	open := func() *queue.Side {
		side, err := queue.OpenSide(path)
		if err != nil {
			t.Fatal(err)
		}
		dir := &trigger.HolderDirectory{Firm: "f_chat", Store: side}
		e.s.dir, e.s.holders, e.s.results, e.s.memory, e.store = dir, side, side, side, nil
		e.s.tasks().Memory = e.s.scheduleMemory
		e.s.triggers = trigger.New(trigger.Config{Firm: "f_chat", Dir: dir, Store: side, IDKey: []byte("agentd id key"), Trusted: e.s.safety.OperatorTime})
		if _, err := e.s.triggers.Load(); err != nil {
			t.Fatal(err)
		}
		return side
	}
	// v0.15.0: two schedules with memory each run once and are remembered.
	side := open()
	var agents []string
	for range 2 {
		d := e.daily(e.me, func(d *trigger.Definition) { d.Memory = true })
		if code, out := e.install(e.me, e.sign(d, e.me.Key)); code != 200 {
			t.Fatalf("install %d %v", code, out)
		}
		e.s.triggerTick(context.Background())
		for id, o := range e.s.tasks().Triggered() {
			if o.DefAgent == d.Agent {
				e.waitResult(id)
			}
		}
		if m, _ := side.Memories(e.me.Space, d.Agent, time.Time{}); len(m) != 1 {
			t.Fatalf("memory after the run: %+v", m)
		}
		agents = append(agents, d.Agent)
	}
	side.Close()

	// v0.14.0 (rolled back): removing the first schedule stops it and deletes its results, nothing else.
	side = open()
	if _, err := e.s.triggers.Stop(agents[0], true); err != nil {
		t.Fatal(err)
	}
	if _, err := side.DeleteAgentResults(e.me.Space, agents[0]); err != nil {
		t.Fatal(err)
	}
	if m, _ := side.Memories(e.me.Space, agents[0], time.Time{}); len(m) != 1 {
		t.Fatal("the setup: v0.14.0's remove left the memory")
	}
	side.Close()

	// v0.15.0 again: its start prunes.
	side = open()
	e.s.pruneMemory()
	if m, _ := side.Memories(e.me.Space, agents[0], time.Time{}); len(m) != 0 {
		t.Fatalf("a removed schedule's memory stayed: %+v", m)
	}
	if m, _ := side.Memories(e.me.Space, agents[1], time.Time{}); len(m) != 1 {
		t.Fatalf("an installed schedule's memory went: %+v", m)
	}
	side.Close()
}

// agentd checks schedule.no_change against the space's policy like any other action (its connector is "schedule"
// since chat-v4; no bypass in agentd, and gatewayd checks it too): under a policy without that connector it is
// policy_denied, even for a task whose options offer it.
func TestNoChangeNeedsPolicy(t *testing.T) {
	e := newSchedEnv(t)
	e.mustPost(e.policy(2, func(p *safety.Policy) { delete(p.Connectors, "schedule") }), e.heartbeat())
	sg := e.s.agent.(*recGateway).safeGateway
	opts, _ := json.Marshal(guard.TaskOptions{Space: e.me.Space, NoChange: true, Agent: guard.AgentScheduled})
	ti := &harness.TaskInfo{ID: "tk_nochange", Options: opts}
	res, err := sg.Action(context.Background(), ti, "a1", &harness.Action{Name: guard.NoChangeAction, Args: jsontext.Value(`{"note":"same"}`)})
	if err != nil || res == nil || res.Status != harness.ActionDenied || !strings.Contains(res.Error, safety.CodePolicyDenied) {
		t.Fatalf("schedule.no_change without its connector: %+v %v", res, err)
	}
}

// A schedule with memory but without notify is never offered schedule_no_change, nor is one with notify on its first
// run; a run that calls it anyway is refused by the runtime (not its tool) and its result isn't quiet. Memory without
// notify asks to skip what was reported before.
func TestScheduleNoChangeOnlyWhenOffered(t *testing.T) {
	e := newSchedEnv(t,
		pText("Top stories: A [1]."),
		pCalls([3]string{"c1", guard.NoChangeTool, `{"note":"same"}`}), pText("Nothing new since yesterday."))
	mem := e.withMemory()
	shift := e.shiftedEngine()
	d := e.daily(e.me, func(d *trigger.Definition) { d.Memory = true })
	if r := e.runOnce(shift, d); r.Quiet || r.State != harness.OutcomeSucceeded {
		t.Fatalf("run 1 %+v", r)
	}
	d.Version = 2
	r := e.runOnce(shift, d)
	if r.Quiet || r.State != harness.OutcomeSucceeded {
		t.Fatalf("run 2 %+v", r)
	}
	b := e.modelBody(1)
	if strings.Contains(b, `"name":"`+guard.NoChangeTool) || !strings.Contains(b, "Skip what an earlier run already reported") {
		t.Fatalf("run 2's model call: %s", b)
	}
	if m, _ := mem.Memories(e.me.Space, d.Agent, time.Time{}); len(m) != 2 || m[0].Quiet {
		t.Fatalf("memory %+v", m)
	}
}

// The chat's golden vectors for the upgrades (the chat's test/golden/v2-schedule-upgrades.json, made with node:crypto from
// the frozen fixtures' seeds): each definition decodes strictly, verifies with its one signature and passes the
// personal rules with its memory, notify and search as the chat meant them; each install call checks for this VM key.
func TestScheduleUpgradesGoldenVectors(t *testing.T) {
	b, err := os.ReadFile("../runauth/testdata/v2-schedule-upgrades.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		VMPrivate   string `json:"vm_private"`
		Seal, Space string
		Identity    struct{ Seed, ID, Key string }
		Definitions []struct {
			Name     string
			JSON     string          `json:"json"`
			Envelope safety.Envelope `json:"envelope"`
			Hash     string          `json:"hash"`
		}
		Requests []struct {
			Call, Name, Body, Digest string
			Own                      []string
		}
	}
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	unhex := func(s string) []byte { x, _ := hex.DecodeString(s); return x }
	vm, _ := ecdh.X25519().NewPrivateKey(unhex(v.VMPrivate))
	idKey := ed25519.NewKeyFromSeed(unhex(v.Identity.Seed))
	var dir identity.Static
	dir.Add("f_chat", v.Identity.ID, idKey.Public().(ed25519.PublicKey), v.Space)
	want := map[string][3]bool{"watch": {true, true, true}, "digest": {false, true, false}} // search, memory, notify
	hashes := map[string]bool{}
	for _, x := range v.Definitions {
		env := x.Envelope
		if string(env.Payload) != x.JSON || env.Hash() != x.Hash {
			t.Fatalf("%s: envelope payload or hash", x.Name)
		}
		var d trigger.Definition
		if err := jsonv2.Unmarshal(env.Payload, &d, jsonv2.RejectUnknownMembers(true)); err != nil {
			t.Fatalf("%s: %v", x.Name, err)
		}
		got, err := trigger.VerifyDefinition(&env, &dir, "f_chat", d.IssuedAt)
		if err != nil {
			t.Fatalf("%s: %v", x.Name, err)
		}
		if err := trigger.Personal(got, v.Space, v.Seal, v.Identity.ID); err != nil {
			t.Fatalf("%s: personal rules: %v", x.Name, err)
		}
		search := slices.Contains(got.Tools, "web.search") && got.Allow["web.search"] == safety.PermAlways
		if w, ok := want[x.Name]; !ok || w != [3]bool{search, got.Memory, got.Notify == trigger.NotifyChanges} {
			t.Fatalf("%s: search %v memory %v notify %q", x.Name, search, got.Memory, got.Notify)
		}
		hashes[x.Hash] = true
	}
	if len(hashes) != 2 || len(v.Requests) != 2 {
		t.Fatalf("%d definitions, %d requests", len(hashes), len(v.Requests))
	}
	for _, r := range v.Requests {
		var x installRequest
		if err := jsonv2.Unmarshal([]byte(r.Body), &x, jsonv2.RejectUnknownMembers(true)); err != nil {
			t.Fatalf("%s: body: %v", r.Name, err)
		}
		own := []string{x.Definition.Hash()}
		if !hashes[own[0]] || strings.Join(own, "|") != strings.Join(r.Own, "|") {
			t.Fatalf("%s: own items %q, the vectors say %q", r.Name, own, r.Own)
		}
		dg := runauth.CallDigest(runauth.InstallLabel, vm.PublicKey().Bytes(), &x.Where, own...)
		if hex.EncodeToString(dg[:]) != r.Digest {
			t.Fatalf("%s: digest %x", r.Name, dg)
		}
		if _, err := runauth.CheckCall(vm, runauth.InstallLabel, &x.Where, time.Unix(x.SignedAt, 0), own...); err != nil {
			t.Fatalf("%s: %v", r.Name, err)
		}
	}
}

// The definition's rules: notify needs memory; notify takes "changes" only; an older shape (no memory, no notify)
// installs as before.
func TestScheduleUpgradesInstallRules(t *testing.T) {
	e := newSchedEnv(t)
	for name, edit := range map[string]func(*trigger.Definition){
		"notify without memory": func(d *trigger.Definition) { d.Notify = trigger.NotifyChanges },
		"notify always":         func(d *trigger.Definition) { d.Memory, d.Notify = true, "always" },
	} {
		if code, out := e.install(e.me, e.sign(e.daily(e.me, edit), e.me.Key)); code != 403 || errOf(out) != "bad_definition" {
			t.Errorf("%s: %d %v", name, code, out)
		}
	}
	if code, out := e.install(e.me, e.sign(e.daily(e.me, func(d *trigger.Definition) {
		d.Memory, d.Notify = true, trigger.NotifyChanges
		d.Tools = []string{"web.fetch", "web.search"}
		d.Allow = map[string]string{"web.fetch": safety.PermAlways, "web.search": safety.PermAlways}
	}), e.me.Key)); code != 200 {
		t.Fatalf("upgraded install %d %v", code, out)
	}
	if code, out := e.install(e.me, e.sign(e.daily(e.me, nil), e.me.Key)); code != 200 {
		t.Fatalf("plain install %d %v", code, out)
	}
}
