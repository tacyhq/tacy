package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tacyhq/tacy/guard"
	"github.com/tacyhq/tacy/proto"
	"github.com/tacyhq/tacy/safety"
)

// What the relay priced a task at (v0.16.0): X-Agent-Kind and X-Agent-Price-Model are checked against the encrypted
// body, and a mismatch is refused before the task starts (no model call); a start the VM checked says so in its
// plaintext answer (X-Agent-Priced: 1), with or without the headers (a tab without them was charged the dearest kind).
func TestTasksChargeHeaders(t *testing.T) {
	m := newStepModel(t, "block", "block", "block")
	p := bootTasks(t, filepath.Join(t.TempDir(), "queue.db"), m, &fakeSearch{}, false)
	c := p.conn(t, tasksUser)
	ctx := context.Background()
	chat := proto.RunRequest{Permissions: guard.AllowAll(), Messages: user1("q")}
	auto := chat
	auto.Model, auto.AutoFallback, auto.FallbackModels = "deepseek-v4-1-flash", true, []string{"glm-5-3", "gpt-oss-120b"}
	for _, tc := range []struct {
		name, kind, price, want string
		r                       proto.RunRequest
	}{
		{"review claimed for a chat task", "a_review", "", "kind_mismatch", chat},
		{"research claimed for a chat task", "a_research", "", "kind_mismatch", chat},
		{"an unknown kind (at the door)", "a_bogus", "", "kind_unknown", chat},
		{"an unknown price model (at the door)", "a_chat", "gpt-5", "model_unknown", chat},
		{"priced below its dearest fallback", "a_chat", "deepseek-v4-1-flash", "price_model_mismatch", auto},
		{"priced at a model it doesn't name", "a_chat", "kimi-k3", "price_model_mismatch", auto},
	} {
		c.Kind, c.PriceModel = tc.kind, tc.price
		if tk, err := c.StartTask(ctx, tc.r, ""); err == nil || !strings.Contains(err.Error(), "400") || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("%s: %+v %v, want 400 %s", tc.name, tk, err, tc.want)
		}
	}
	if n := m.calls.Load(); n != 0 {
		t.Fatalf("a refused start reached the model (%d calls)", n)
	}
	if n := p.s.tasks().Open(); n != 0 {
		t.Fatalf("open tasks %d after refusals", n)
	}
	// Matching headers, then none at all: both start, both witnessed.
	c.Kind, c.PriceModel = guard.AgentChat, guard.PriceModel(&auto)
	tk, err := c.StartTask(ctx, auto, "")
	if err != nil || tk.Billing.Start != "new" || !tk.Billing.Priced {
		t.Fatalf("priced start: %+v %v", tk, err)
	}
	c.Kind, c.PriceModel = "", ""
	tk2, err := c.StartTask(ctx, chat, "")
	if err != nil || !tk2.Billing.Priced {
		t.Fatalf("start without the headers: %+v %v", tk2, err)
	}
	// POST /run (the shim) checks them too.
	c.Kind = "a_review"
	if err := c.Run(ctx, chat, func(proto.Event) {}); err == nil || !strings.Contains(err.Error(), "kind_mismatch") {
		t.Fatalf("/run kind mismatch: %v", err)
	}
	c.Kind = "a_bogus"
	if err := c.Run(ctx, chat, func(proto.Event) {}); err == nil || !strings.Contains(err.Error(), "kind_unknown") {
		t.Fatalf("/run unknown kind: %v", err)
	}
}

// GET /tasks/open (v0.16.0) also says what scheduled runs cost today and yesterday, all together, from the ledger:
// one number a day, nothing about a person's runs.
func TestTasksOpenScheduledSpend(t *testing.T) {
	p := bootTasks(t, filepath.Join(t.TempDir(), "queue.db"), newStepModel(t, "block"), &fakeSearch{}, false)
	now := time.Now().UTC()
	p.s.ledger = &safety.Ledger{Now: func() time.Time { return now }}
	spend := func(task, member string, micros int64) {
		p.s.ledger.Begin(task, "s_x", member)
		commit, err := p.s.ledger.Reserve(task, safety.Usage{CostMicros: micros}, safety.Budgets{})
		if err != nil {
			t.Fatal(err)
		}
		commit(safety.Usage{CostMicros: micros})
		p.s.ledger.End(task)
	}
	spend("t1", guard.ScheduleMember("ag_digest"), 12_000)
	spend("t2", guard.ScheduleMember("ag_other"), 3_000)
	spend("t3", "0123456789abcdef", 50_000) // a person's run, charged by the relay
	mux := http.NewServeMux()
	p.s.taskRoutes(mux, p.s.id)
	r := httptest.NewRequest("GET", "/tasks/open", nil)
	r.Header.Set("Authorization", "Bearer tok")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	var got struct {
		Open, Schedules int
		Spend           map[string]int64 `json:"scheduled_spend_micros"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil || w.Code != 200 {
		t.Fatalf("%d %s %v", w.Code, w.Body, err)
	}
	today, yday := now.Format(time.DateOnly), now.Add(-24*time.Hour).Format(time.DateOnly)
	if len(got.Spend) != 2 || got.Spend[today] != 15_000 || got.Spend[yday] != 0 {
		t.Fatalf("scheduled spend %v (body %s)", got.Spend, w.Body)
	}
}
