package main

import (
	"bytes"
	"encoding/json"
	jsonv2 "encoding/json/v2"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tacyhq/tacy/runauth"
	"github.com/tacyhq/tacy/safety"
	"github.com/tacyhq/tacy/trigger"
)

// callH posts body to a schedules handler with headers; the status, the answer and its headers.
func (e *schedEnv) callH(h http.HandlerFunc, body any, headers map[string]string) (int, map[string]any, http.Header) {
	b, _ := jsonv2.Marshal(body)
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/schedules/x", bytes.NewReader(b))
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	h(w, r)
	var out map[string]any
	json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out, w.Header()
}

// One run's expected cost: the same vectors as the chat's (the chat's test/unit/agent-charge.test.ts).
func TestScheduleRunCostVectors(t *testing.T) {
	for _, v := range []struct {
		model  string
		search bool
		want   int64
	}{
		{"deepseek-v4-1-flash", false, 70_000}, {"deepseek-v4-1-flash", true, 150_000},
		{"gpt-oss-120b", false, 50_330}, {"gpt-oss-120b", true, 117_216},
		{"gemma4-31b", false, 59_844}, {"gemma4-31b", true, 133_073},
		{"glm-5-3", false, 145_340}, {"glm-5-3", true, 250_000},
		{"kimi-k3", false, 250_000}, {"kimi-k3", true, 250_000},
	} {
		if got := scheduleRunCost(v.model, v.search); got != v.want {
			t.Errorf("%s search=%v: %d, want %d", v.model, v.search, got, v.want)
		}
	}
}

// The X-Schedule-Charge value is made from the signed definition alone, as prices: a run's cost (its dearest model,
// whether it may search) times its runs a week over 7, its one-time runs' cost, and not_after's date.
func TestScheduleChargeValue(t *testing.T) {
	e := newSchedEnv(t)
	d := e.daily(e.me, func(d *trigger.Definition) {
		d.Models = []string{"deepseek-v4-1-flash", "glm-5-3", "gpt-oss-120b"}
		d.Tools = []string{"web.fetch", "web.search"}
		d.Allow = map[string]string{"web.fetch": safety.PermAlways, "web.search": safety.PermAlways}
		d.Triggers = append(d.Triggers,
			trigger.Trigger{ID: randID("tr"), Kind: trigger.Schedule, Daily: "09:00", Days: []string{"tue", "thu"}, Zone: "UTC"},
			trigger.Trigger{ID: randID("tr"), Kind: trigger.Schedule, At: "2026-12-01T09:00", Zone: "UTC"})
		d.NotAfter = time.Date(2027, 1, 19, 9, 0, 0, 0, time.UTC)
	})
	// glm-5-3 with search: the $0.25 cap a run; 9 runs a week (7 + tue, thu): 9 x 250,000 / 7, rounded up.
	if got, want := scheduleCharge(&d), "v1 "+d.Agent+" daily=321429 once=250000 until=2027-01-19"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	// Search listed but not allowed always: it never searches (glm-5-3 reading pages: 145,340 a run).
	d.Allow["web.search"] = safety.PermNever
	if got, want := scheduleCharge(&d), "v1 "+d.Agent+" daily=186866 once=145340 until=2027-01-19"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

// An install whose X-Schedule-Charge isn't its definition's is refused before it's installed; a matching one is
// witnessed (X-Schedule-Priced); one without the header installs as before, unwitnessed. A stop or remove naming
// another schedule in X-Schedule-Agent is refused and changes nothing; naming its own is witnessed.
func TestScheduleChargeChecked(t *testing.T) {
	e := newSchedEnv(t)
	d := e.daily(e.me, func(d *trigger.Definition) {
		d.Triggers[0].Daily = time.Now().UTC().Add(3 * time.Hour).Format("15:04") // later today: no run in this test
	})
	env := e.sign(d, e.me.Key)
	install := func(charge string) (int, map[string]any, http.Header) {
		h := map[string]string{}
		if charge != "" {
			h[scheduleChargeHeader] = charge
		}
		return e.callH(e.s.scheduleInstall, installRequest{Where: e.where(e.me, runauth.InstallLabel, env.Hash()), Definition: env}, h)
	}
	right := scheduleCharge(&d)
	if !strings.Contains(right, " daily=70000 once=0 ") {
		t.Fatal(right)
	}
	for _, wrong := range []string{
		strings.Replace(right, "daily=70000", "daily=10000", 1),
		strings.Replace(right, "daily=70000", "daily=70001", 1), // dearer is wrong too: it must be the definition's
		strings.Replace(right, "once=0", "once=1", 1),
		strings.Replace(right, d.Agent, randID("a"), 1),
		strings.Replace(right, "until=", "until=2099-", 1),
		right + " ",
	} {
		if code, out, h := install(wrong); code != 400 || errOf(out) != "charge_mismatch" || h.Get(schedulePricedHeader) != "" {
			t.Fatalf("%q: %d %v", wrong, code, out)
		}
	}
	if s := e.s.triggers.Get(d.Agent); s != nil {
		t.Fatal("a mismatched install was installed")
	}
	if code, out, h := install(right); code != 200 || h.Get(schedulePricedHeader) != "1" {
		t.Fatalf("matching: %d %v", code, out)
	}
	if code, _, h := install(""); code != 200 || h.Get(schedulePricedHeader) != "" { // the same envelope again: a no-op
		t.Fatalf("no header: %d %v", code, h)
	}
	stop := func(named string) (int, map[string]any, http.Header) {
		h := map[string]string{}
		if named != "" {
			h[scheduleAgentHeader] = named
		}
		return e.callH(e.s.scheduleStop, agentRequest{Where: e.where(e.me, runauth.StopLabel, d.Agent), Agent: d.Agent}, h)
	}
	if code, out, _ := stop(randID("a")); code != 400 || errOf(out) != "agent_mismatch" {
		t.Fatalf("another agent named: %d %v", code, out)
	}
	if st := e.s.triggers.StateOf(e.s.triggers.Get(d.Agent)); st != "active" {
		t.Fatalf("a refused stop stopped it: %s", st)
	}
	if code, out, h := stop(d.Agent); code != 200 || out["state"] != "stopped" || h.Get(schedulePricedHeader) != "1" {
		t.Fatalf("stop: %d %v", code, out)
	}
}
