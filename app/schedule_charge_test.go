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

	"github.com/tacyhq/tacy/guard"
	"github.com/tacyhq/tacy/proto"
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

// One run's expected cost on each table: the same vectors as the chat's (the chat's test/unit/agent-charge.test.ts).
// V1 (v0.16.0 to v0.22.0, capped at $0.25) is what shipped clients send; V2 (this release, capped at the run's $0.40)
// is what scheduleCharge prices by.
type runCostVector struct {
	model                   string
	search                  bool
	plain, files, mail, all int64 // nothing more, stored files, email, both
}

var (
	runCostV1 = []runCostVector{
		{"deepseek-v4-1-flash", false, 70_000, 120_000, 120_000, 170_000}, {"deepseek-v4-1-flash", true, 150_000, 200_000, 200_000, 250_000},
		{"gpt-oss-120b", false, 50_330, 93_773, 93_773, 137_216}, {"gpt-oss-120b", true, 117_216, 160_659, 160_659, 204_102},
		{"gemma4-31b", false, 59_844, 106_459, 106_459, 153_073}, {"gemma4-31b", true, 133_073, 179_688, 179_688, 226_302},
		{"glm-5-3", false, 145_340, 220_453, 220_453, 250_000}, {"glm-5-3", true, 250_000, 250_000, 250_000, 250_000},
		{"kimi-k3", false, 250_000, 250_000, 250_000, 250_000}, {"kimi-k3", true, 250_000, 250_000, 250_000, 250_000},
	}
	runCostV2 = []runCostVector{
		{"deepseek-v4-1-flash", false, 70_000, 120_000, 120_000, 170_000}, {"deepseek-v4-1-flash", true, 235_000, 285_000, 285_000, 335_000},
		{"gpt-oss-120b", false, 50_330, 93_773, 93_773, 137_216}, {"gpt-oss-120b", true, 195_659, 239_102, 239_102, 282_545},
		{"gemma4-31b", false, 59_844, 106_459, 106_459, 153_073}, {"gemma4-31b", true, 214_688, 261_302, 261_302, 307_917},
		{"glm-5-3", false, 145_340, 220_453, 220_453, 295_567}, {"glm-5-3", true, 385_680, 400_000, 400_000, 400_000},
		{"kimi-k3", false, 366_782, 400_000, 400_000, 400_000}, {"kimi-k3", true, 400_000, 400_000, 400_000, 400_000},
	}
)

func TestScheduleRunCostVectors(t *testing.T) {
	for name, c := range map[string]struct {
		p  scheduleTable
		vs []runCostVector
	}{"V1": {schedulePricesV1, runCostV1}, "V2": {schedulePricesV2, runCostV2}} {
		for _, v := range c.vs {
			for _, k := range []struct {
				files, mail bool
				want        int64
			}{{false, false, v.plain}, {true, false, v.files}, {false, true, v.mail}, {true, true, v.all}} {
				if got := c.p.runCost(v.model, v.search, k.files, k.mail); got != k.want {
					t.Errorf("%s %s search=%v files=%v mail=%v: %d, want %d", name, v.model, v.search, k.files, k.mail, got, k.want)
				}
			}
		}
	}
	// This release prices by V2, and no price passes the scheduled run's budget or falls below V1's.
	for _, v := range runCostV2 {
		if got := scheduleRunCost(v.model, v.search, false, false); got != v.plain {
			t.Errorf("scheduleRunCost %s search=%v: %d, want V2's %d", v.model, v.search, got, v.plain)
		}
	}
	budget := guard.RunBudget(guard.AgentScheduled).CostMicros
	for _, m := range []string{"deepseek-v4-1-flash", "gpt-oss-120b", "gemma4-31b", "glm-5-3", "kimi-k3", "llama3-3-70b", "unknown"} {
		for i := range 8 {
			search, files, mail := i&1 != 0, i&2 != 0, i&4 != 0
			v1, v2 := schedulePricesV1.runCost(m, search, files, mail), schedulePricesV2.runCost(m, search, files, mail)
			if v2 > budget || v2 < v1 {
				t.Errorf("%s search=%v files=%v mail=%v: V2 %d, V1 %d, run budget %d", m, search, files, mail, v2, v1, budget)
			}
		}
	}
}

// A definition that reads email is charged its share only with a mail tool allowed always.
func TestScheduleChargeWithMail(t *testing.T) {
	e := newSchedEnv(t)
	mail := []string{"mail.search", "mail.read", "mail.folders"}
	d := e.daily(e.me, func(d *trigger.Definition) {
		d.Models = []string{"deepseek-v4-1-flash"}
		d.Tools = append([]string{"web.fetch"}, mail...)
		d.Allow = map[string]string{"web.fetch": safety.PermAlways, "mail.search": safety.PermAlways, "mail.read": safety.PermAlways,
			"mail.folders": safety.PermAlways}
		d.NotAfter = time.Date(2027, 1, 19, 9, 0, 0, 0, time.UTC)
	})
	if got, want := scheduleCharge(&d), "v1 "+d.Agent+" daily=120000 once=0 until=2027-01-19"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	for _, m := range mail {
		d.Allow[m] = safety.PermNever
	}
	if got, want := scheduleCharge(&d), "v1 "+d.Agent+" daily=70000 once=0 until=2027-01-19"; got != want {
		t.Fatalf("never: got %q, want %q", got, want)
	}
	for _, m := range mail {
		d.Allow[m] = safety.PermAlways
	}
	d.Files = []proto.StoredFile{{Object: "ob_aaaaaaaaaaaaaaaaaaaaaaaaaa"}}
	if got, want := scheduleCharge(&d), "v1 "+d.Agent+" daily=170000 once=0 until=2027-01-19"; got != want {
		t.Fatalf("with files: got %q, want %q", got, want)
	}
}

// A definition with stored files is charged their share: deepseek reading pages and files, every day, 120,000 a run.
func TestScheduleChargeWithFiles(t *testing.T) {
	e := newSchedEnv(t)
	d := e.daily(e.me, func(d *trigger.Definition) {
		d.Files = []proto.StoredFile{{Object: "ob_aaaaaaaaaaaaaaaaaaaaaaaaaa"}}
		d.NotAfter = time.Date(2027, 1, 19, 9, 0, 0, 0, time.UTC)
	})
	if got, want := scheduleCharge(&d), "v1 "+d.Agent+" daily=120000 once=0 until=2027-01-19"; got != want {
		t.Fatalf("got %q, want %q", got, want)
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
	// glm-5-3 with search: 385,680 a run; 9 runs a week (7 + tue, thu): 9 x 385,680 / 7, rounded up. On V1 (what
	// shipped clients send) the $0.25 cap a run: 9 x 250,000 / 7.
	if got, want := scheduleCharge(&d), "v1 "+d.Agent+" daily=495875 once=385680 until=2027-01-19"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	if got, want := scheduleChargeOn(&d, schedulePricesV1), "v1 "+d.Agent+" daily=321429 once=250000 until=2027-01-19"; got != want {
		t.Fatalf("V1: got %q, want %q", got, want)
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

// Mixed versions (the no-downtime plan row 77): a schedule that may search is priced differently on V1 (what shipped clients send:
// $0.15 a run on deepseek) and V2 (this release's: $0.235). Both are accepted and witnessed, so a client from before
// this release keeps installing; anything else, a price between them included, is refused.
func TestScheduleChargeEitherTable(t *testing.T) {
	e := newSchedEnv(t)
	search := func(d *trigger.Definition) {
		d.Tools = []string{"web.fetch", "web.search"}
		d.Allow = map[string]string{"web.fetch": safety.PermAlways, "web.search": safety.PermAlways}
		d.Triggers[0].Daily = time.Now().UTC().Add(3 * time.Hour).Format("15:04") // later today: no run in this test
	}
	install := func(d trigger.Definition, charge string) (int, map[string]any, http.Header) {
		env := e.sign(d, e.me.Key)
		return e.callH(e.s.scheduleInstall, installRequest{Where: e.where(e.me, runauth.InstallLabel, env.Hash()), Definition: env},
			map[string]string{scheduleChargeHeader: charge})
	}
	d1, d2, d3 := e.daily(e.me, search), e.daily(e.me, search), e.daily(e.me, search)
	v1, v2 := scheduleChargeOn(&d1, schedulePricesV1), scheduleChargeOn(&d2, schedulePricesV2)
	if !strings.Contains(v1, " daily=150000 ") || !strings.Contains(v2, " daily=235000 ") || scheduleCharge(&d2) != v2 {
		t.Fatalf("V1 %q, V2 %q", v1, v2)
	}
	if code, out, h := install(d1, v1); code != 200 || h.Get(schedulePricedHeader) != "1" {
		t.Fatalf("V1: %d %v", code, out)
	}
	if code, out, h := install(d2, v2); code != 200 || h.Get(schedulePricedHeader) != "1" {
		t.Fatalf("V2: %d %v", code, out)
	}
	between := strings.Replace(scheduleChargeOn(&d3, schedulePricesV1), "daily=150000", "daily=200000", 1)
	if code, out, h := install(d3, between); code != 400 || errOf(out) != "charge_mismatch" || h.Get(schedulePricedHeader) != "" {
		t.Fatalf("between: %d %v", code, out)
	}
	if e.s.triggers.Get(d1.Agent) == nil || e.s.triggers.Get(d2.Agent) == nil || e.s.triggers.Get(d3.Agent) != nil {
		t.Fatal("installed: want V1's and V2's, not the mismatched one")
	}
}
