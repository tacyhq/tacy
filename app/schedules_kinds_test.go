package main

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tacyhq/tacy/harness"
	"github.com/tacyhq/tacy/runauth"
	"github.com/tacyhq/tacy/trigger"
)

// Schedules on chosen weekdays and one-time schedules through agentd's routes (v0.13.0, the schedules contract).

// shiftedEngine gives the env an engine whose clock runs off from the real one (the calls' signed_at and the
// operator's time stay real; the shift stays within their 5 minutes).
func (e *schedEnv) shiftedEngine() *atomic.Int64 {
	var shift atomic.Int64
	s := e.s
	s.triggers = trigger.New(trigger.Config{Firm: "f_chat", Dir: s.dir, Store: e.store, IDKey: []byte("agentd id key"),
		Trusted: s.safety.OperatorTime, Now: func() time.Time { return time.Now().Add(time.Duration(shift.Load())) }})
	return &shift
}

func (e *schedEnv) open() map[string]int {
	o, _ := e.openNext()
	return o
}

// openNext is GET /tasks/open's counts and its next_run (the release after v0.17.0; nil when null). The field is
// always there on this VM: an older VM's missing field means "keep the VM on" to the relay.
func (e *schedEnv) openNext() (map[string]int, *time.Time) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/tasks/open", nil)
	r.Header.Set("Authorization", "Bearer tok")
	e.s.tasksOpen(w, r)
	var raw map[string]json.RawMessage
	var out struct {
		Open, Schedules int
		NextRun         *time.Time `json:"next_run"`
	}
	if json.Unmarshal(w.Body.Bytes(), &raw) != nil || json.Unmarshal(w.Body.Bytes(), &out) != nil || raw["next_run"] == nil {
		e.t.Fatalf("GET /tasks/open: %s", w.Body)
	}
	return map[string]int{"open": out.Open, "schedules": out.Schedules}, out.NextRun
}

func (e *schedEnv) listed(a *runauth.Asker) []map[string]any {
	code, lo := e.call(e.s.scheduleList, e.where(a, runauth.ListLabel))
	if code != 200 {
		e.t.Fatalf("list %d %v", code, lo)
	}
	var out []map[string]any
	for _, s := range lo["schedules"].([]any) {
		out = append(out, s.(map[string]any))
	}
	return out
}

// A one-time schedule a couple of minutes ahead: installed (its at echoed, its next run that instant), it keeps the
// VM on until its run starts; it fires once, its result is sealed and kept as any run's, and it is then listed as
// ended with no next run and no longer counted (/tasks/open, the 8 per space).
func TestScheduleOnceRunsThenEnds(t *testing.T) {
	e := newSchedEnv(t, pText("Today's digest: nothing new [1]."))
	shift := e.shiftedEngine()
	at := time.Now().UTC().Add(2 * time.Minute).Truncate(time.Minute)
	d := e.daily(e.me, func(d *trigger.Definition) {
		d.Triggers[0].Daily, d.Triggers[0].At = "", at.Format("2006-01-02T15:04")
	})
	code, out := e.install(e.me, e.sign(d, e.me.Key))
	if code != 200 || out["state"] != "active" {
		t.Fatalf("install %d %v", code, out)
	}
	tr := out["triggers"].([]any)[0].(map[string]any)
	if tr["at"] != d.Triggers[0].At || tr["daily"] != nil || tr["days"] != nil || tr["next_run"] != at.Format(time.RFC3339) {
		t.Fatalf("install's trigger %v", tr)
	}
	if o, next := e.openNext(); o["schedules"] != 1 || next == nil || !next.Equal(at) {
		t.Fatalf("before its run: %v, next run %v", o, next)
	}
	e.s.triggerTick(context.Background()) // not yet
	if n := len(e.s.tasks().Triggered()); n != 0 {
		t.Fatalf("fired early: %d", n)
	}
	shift.Store(int64(at.Sub(time.Now()) + 20*time.Second)) // its time has come
	e.s.triggerTick(context.Background())
	var task string
	for id := range e.s.tasks().Triggered() {
		task = id
	}
	if task == "" {
		t.Fatal("didn't fire at its time")
	}
	e.s.triggerTick(context.Background()) // never twice
	r := e.waitResult(task)
	if r.State != harness.OutcomeSucceeded || r.Day != at.Format(time.DateOnly) || !r.ScheduledAt.Equal(at) {
		t.Fatalf("result %+v", r)
	}
	if n := len(e.s.tasks().Triggered()); n != 0 {
		t.Fatalf("%d runs", n)
	}
	l := e.listed(e.me)
	if len(l) != 1 || l[0]["state"] != "ended" || l[0]["running"] != float64(0) {
		t.Fatalf("list after its run %v", l)
	}
	tr = l[0]["triggers"].([]any)[0].(map[string]any)
	if tr["next_run"] != nil || tr["last_task"] != task || tr["last_day"] != at.Format(time.DateOnly) || tr["at"] != d.Triggers[0].At {
		t.Fatalf("listed trigger %v", tr)
	}
	if o, next := e.openNext(); o["schedules"] != 0 || next != nil {
		t.Fatalf("an ended schedule keeps the VM on: %v, next run %v", o, next)
	}
	if _, body := e.openResult(e.me, task); body == nil || body.Day != r.Day {
		t.Fatalf("sealed result %+v", body)
	}
	// It doesn't count against the 8: eight more install, a ninth doesn't.
	for i := 0; i < 8; i++ {
		x := e.daily(e.me, func(d *trigger.Definition) { d.Triggers[0].Daily = time.Now().UTC().Add(3 * time.Hour).Format("15:04") })
		if code, out := e.install(e.me, e.sign(x, e.me.Key)); code != 200 {
			t.Fatalf("schedule %d: %d %v", i+1, code, out)
		}
	}
	if code, out := e.install(e.me, e.sign(e.daily(e.me, nil), e.me.Key)); code != 429 || errOf(out) != "too_many_schedules" {
		t.Fatalf("ninth live: %d %v", code, out)
	}
	// Removing it deletes its result.
	if code, out := e.call(e.s.scheduleRemove, agentRequest{Where: e.where(e.me, runauth.RemoveLabel, d.Agent), Agent: d.Agent}); code != 200 || out["results_deleted"] != float64(1) {
		t.Fatalf("remove %d %v", code, out)
	}
}

// A one-time time already past is refused with a clear detail; so is one before issued_at; nothing is installed.
// A weekly one installs with its days echoed and its next run on one of them; the replay and version rules hold.
func TestScheduleKindsInstall(t *testing.T) {
	e := newSchedEnv(t)
	now := time.Now().UTC()
	for name, at := range map[string]string{
		"a minute ago":         now.Add(-time.Minute).Format("2006-01-02T15:04"),
		"before its issued_at": now.Add(-20 * time.Minute).Format("2006-01-02T15:04"),
	} {
		d := e.daily(e.me, func(d *trigger.Definition) { d.Triggers[0].Daily, d.Triggers[0].At = "", at })
		code, out := e.install(e.me, e.sign(d, e.me.Key))
		if code != 403 || errOf(out) != "bad_definition" || !strings.Contains(out["detail"].(string), "already passed") {
			t.Errorf("%s: %d %v", name, code, out)
		}
	}
	for name, edit := range map[string]func(*trigger.Trigger){
		"all seven days": func(t *trigger.Trigger) { t.Days = []string{"mon", "tue", "wed", "thu", "fri", "sat", "sun"} },
		"days and at":    func(t *trigger.Trigger) { t.Days, t.At = []string{"tue"}, "2030-01-01T07:00" },
		"days unordered": func(t *trigger.Trigger) { t.Days = []string{"thu", "tue"} },
	} {
		d := e.daily(e.me, func(d *trigger.Definition) { edit(&d.Triggers[0]) })
		if code, out := e.install(e.me, e.sign(d, e.me.Key)); code != 403 || errOf(out) != "bad_definition" {
			t.Errorf("%s: %d %v", name, code, out)
		}
	}
	if l := e.listed(e.me); len(l) != 0 {
		t.Fatalf("installed after refusals: %v", l)
	}
	d := e.daily(e.me, func(d *trigger.Definition) {
		d.Triggers[0].Daily, d.Triggers[0].Days, d.Triggers[0].Zone = "07:00", []string{"tue", "thu"}, "Europe/Lisbon"
	})
	env := e.sign(d, e.me.Key)
	req := installRequest{Where: e.where(e.me, runauth.InstallLabel, env.Hash()), Definition: env}
	code, out := e.call(e.s.scheduleInstall, req)
	if code != 200 || out["state"] != "active" {
		t.Fatalf("weekly install %d %v", code, out)
	}
	tr := out["triggers"].([]any)[0].(map[string]any)
	next, err := time.Parse(time.RFC3339, tr["next_run"].(string))
	lis, _ := time.LoadLocation("Europe/Lisbon")
	if err != nil || tr["daily"] != "07:00" || len(tr["days"].([]any)) != 2 || tr["days"].([]any)[1] != "thu" ||
		next.In(lis).Format("15:04") != "07:00" || (next.In(lis).Weekday() != time.Tuesday && next.In(lis).Weekday() != time.Thursday) {
		t.Fatalf("weekly trigger %v", tr)
	}
	if code, out := e.call(e.s.scheduleInstall, req); code != 409 || errOf(out) != "replayed" {
		t.Fatalf("replayed: %d %v", code, out)
	}
	d2 := d
	d2.Triggers = []trigger.Trigger{{ID: d.Triggers[0].ID, Kind: trigger.Schedule, Daily: "08:00", Days: []string{"wed"}, Zone: "Europe/Lisbon"}}
	if code, out := e.install(e.me, e.sign(d2, e.me.Key)); code != 409 || errOf(out) != "stale_version" {
		t.Fatalf("same version, other days: %d %v", code, out)
	}
	d2.Version = 2
	if code, out := e.install(e.me, e.sign(d2, e.me.Key)); code != 200 || out["version"] != float64(2) {
		t.Fatalf("edit: %d %v", code, out)
	}
	if o := e.open(); o["schedules"] != 1 {
		t.Fatalf("keep-on %v", o)
	}
}
