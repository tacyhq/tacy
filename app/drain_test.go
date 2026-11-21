package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	ehbpidentity "github.com/tinfoilsh/encrypted-http-body-protocol/identity"

	"github.com/tacyhq/tacy/agentclient"
	"github.com/tacyhq/tacy/guard"
	"github.com/tacyhq/tacy/proto"
	"github.com/tacyhq/tacy/relay"
	"github.com/tacyhq/tacy/trigger"
)

// The drain the chat Worker sends before a switch (drain.go; the chat Worker's vm-switch.ts): POST /drain
// {until} and POST /undrain {}, in its signed envelope.

// drainCall posts body to h (relayed: as from inside the relay's envelope) and returns the status and answer.
func drainCall(h http.HandlerFunc, relayed bool, body string) (int, map[string]any) {
	r := httptest.NewRequest("POST", "/drain", strings.NewReader(body))
	if relayed {
		r = asRelay(r)
	}
	w := httptest.NewRecorder()
	h(w, r)
	var out map[string]any
	json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

func untilIn(d time.Duration) string {
	return `{"until":` + strconv.FormatInt(time.Now().Add(d).Unix(), 10) + `}`
}

// countingStore counts the trigger engine's writes.
type countingStore struct {
	*trigger.MemStore
	writes atomic.Int64
}

func (c *countingStore) SaveDefinition(a string, v uint64, env []byte) error {
	c.writes.Add(1)
	return c.MemStore.SaveDefinition(a, v, env)
}
func (c *countingStore) SetState(a string, v uint64, st string) error {
	c.writes.Add(1)
	return c.MemStore.SetState(a, v, st)
}
func (c *countingStore) ExpireDefinition(a string, v uint64, env []byte) error {
	c.writes.Add(1)
	return c.MemStore.ExpireDefinition(a, v, env)
}
func (c *countingStore) SetFired(tr string, slot int64) error {
	c.writes.Add(1)
	return c.MemStore.SetFired(tr, slot)
}
func (c *countingStore) See(tr, d string, until time.Time) (bool, error) {
	c.writes.Add(1)
	return c.MemStore.See(tr, d, until)
}
func (c *countingStore) Unsee(tr, d string) error { c.writes.Add(1); return c.MemStore.Unsee(tr, d) }
func (c *countingStore) PruneSeen(t time.Time) error {
	c.writes.Add(1)
	return c.MemStore.PruneSeen(t)
}
func (c *countingStore) SetHighWater(t time.Time) error {
	c.writes.Add(1)
	return c.MemStore.SetHighWater(t)
}

// A drained VM refuses every new start and change (503 draining, the handler never reached) and serves only what
// follows or finishes running work; /undrain reverts it.
func TestDrainRefusesNewWork(t *testing.T) {
	s := &server{}
	var reached []string
	h := s.gate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = append(reached, r.Method+" "+r.URL.Path)
	}), nil)
	refused := []string{"/tasks", "/run", "/schedules/install", "/schedules/stop", "/schedules/remove", "/schedules/list",
		"/schedules/results/delete", "/spaces/reseal", "/triggers", "/triggers/event", "/connections/test",
		"/connections/list", "/connections/put", "/notify/set", "/search", "/pictures", "/anything/new"}
	// Connection deletions pass (final review L5): a forget sent while the VM is drained must not be lost if it is
	// undrained later (a rollback).
	passing := []string{"POST /tasks/status", "POST /tasks/events", "POST /tasks/cancel", "POST /tasks/delete",
		"POST /tasks/grant", "POST /tasks/credential", "POST /approvals", "POST /approvals/list",
		"POST /schedules/handoff", "POST /notify/pending", "POST /safety", "POST /keylog", "POST /drain", "POST /undrain",
		"POST /connections/remove", "POST /connections/forget",
		"GET /tasks/open", "GET /activity", "GET /attest", "GET /health", "GET /safety"}
	do := func(method, path string) int {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(method, path, nil))
		if w.Code == 503 && !strings.Contains(w.Body.String(), `"draining"`) {
			t.Fatalf("%s %s: 503 %s", method, path, w.Body)
		}
		return w.Code
	}
	if code, out := drainCall(s.drainIn, true, untilIn(time.Hour)); code != 200 || out["drained"] != true {
		t.Fatalf("drain: %d %v", code, out)
	}
	for _, p := range refused {
		if code := do("POST", p); code != 503 {
			t.Errorf("drained: POST %s answered %d, want 503 draining", p, code)
		}
	}
	if len(reached) != 0 {
		t.Fatalf("drained: refused routes reached their handlers: %v", reached)
	}
	for _, mp := range passing {
		m, p, _ := strings.Cut(mp, " ")
		if code := do(m, p); code != 200 {
			t.Errorf("drained: %s answered %d, want it served", mp, code)
		}
	}
	if len(reached) != len(passing) {
		t.Fatalf("drained: %d of %d passing routes reached", len(reached), len(passing))
	}
	if code, out := drainCall(s.undrainIn, true, `{}`); code != 200 || out["drained"] != false {
		t.Fatalf("undrain: %d %v", code, out)
	}
	for _, p := range refused {
		if code := do("POST", p); code != 200 {
			t.Errorf("undrained: POST %s answered %d", p, code)
		}
	}
}

// Only the relay may drain: outside its envelope 401; a bad body or a past `until` is 400 and drains nothing.
func TestDrainNeedsTheRelay(t *testing.T) {
	s := &server{}
	for name, c := range map[string]struct {
		h       http.HandlerFunc
		relayed bool
		body    string
		code    int
	}{
		"not relayed":     {s.drainIn, false, untilIn(time.Hour), 401},
		"undrain, not":    {s.undrainIn, false, `{}`, 401},
		"no until":        {s.drainIn, true, `{}`, 400},
		"until passed":    {s.drainIn, true, untilIn(-time.Minute), 400},
		"until a string":  {s.drainIn, true, `{"until":"soon"}`, 400},
		"unknown member":  {s.drainIn, true, `{"until":1,"forever":true}`, 400},
		"not JSON at all": {s.drainIn, true, `drain`, 400},
	} {
		if code, _ := drainCall(c.h, c.relayed, c.body); code != c.code {
			t.Errorf("%s: %d, want %d", name, code, c.code)
		}
		if s.drain.on(time.Now()) {
			t.Fatalf("%s: drained", name)
		}
	}
}

// The drain ends by itself: at `until`, and never more than 2 hours after it arrived, whatever `until` says.
func TestDrainExpires(t *testing.T) {
	s := &server{}
	now := time.Now()
	code, out := drainCall(s.drainIn, true, untilIn(30*24*time.Hour))
	if code != 200 {
		t.Fatalf("drain: %d %v", code, out)
	}
	u, _ := out["until"].(float64)
	if got := time.Unix(int64(u), 0); got.After(now.Add(drainMax)) || got.Before(now.Add(drainMax-time.Minute)) {
		t.Fatalf("until %v: want 2 hours from now", got)
	}
	if !s.drain.on(now.Add(drainMax - time.Minute)) {
		t.Fatal("not drained before the 2 hours")
	}
	if s.drain.on(now.Add(drainMax + time.Second)) {
		t.Fatal("still drained after 2 hours")
	}
	drainCall(s.drainIn, true, untilIn(10*time.Minute))
	if !s.drain.on(time.Now().Add(9*time.Minute)) || s.drain.on(time.Now().Add(11*time.Minute)) {
		t.Fatal("a 10-minute drain doesn't end at its until")
	}
}

// A drained VM fires no schedule and makes no write of the trigger engine's; its running task still finishes and
// its result is kept; undrained, the next tick fires.
func TestDrainedVMWritesNothing(t *testing.T) {
	e := newSchedEnv(t, pText("Today's digest."), pText("Tomorrow's digest."))
	cs := &countingStore{MemStore: e.store}
	s := e.s
	s.triggers = trigger.New(trigger.Config{Firm: "f_chat", Dir: s.dir, Store: cs, IDKey: []byte("agentd id key"), Trusted: s.safety.OperatorTime,
		Collect: s.results.(trigger.CollectStore)})
	d := e.daily(e.me, nil)
	if code, out := e.install(e.me, e.sign(d, e.me.Key)); code != 200 {
		t.Fatalf("install %d %v", code, out)
	}

	// Drained before the slot: no fire, no write.
	drainCall(s.drainIn, true, untilIn(time.Hour))
	before := cs.writes.Load()
	for range 3 {
		s.triggerTick(context.Background())
	}
	if n := len(s.tasks().Triggered()); n != 0 {
		t.Fatalf("drained: %d scheduled tasks started", n)
	}
	if got := cs.writes.Load() - before; got != 0 {
		t.Fatalf("drained: %d trigger store writes", got)
	}
	if _, ok, _ := e.store.LastFired(d.Triggers[0].ID); ok {
		t.Fatal("drained: the slot is marked fired")
	}

	// Undrained: the slot fires.
	drainCall(s.undrainIn, true, `{}`)
	s.triggerTick(context.Background())
	var task string
	for id := range s.tasks().Triggered() {
		task = id
	}
	if task == "" || cs.writes.Load() == before {
		t.Fatalf("undrained: no fire (task %q, writes %d)", task, cs.writes.Load()-before)
	}

	// Drained while that task runs: the drain reports it, it finishes, its result is kept.
	_, out := drainCall(s.drainIn, true, untilIn(time.Hour))
	if _, ok := out["open"].(float64); !ok {
		t.Fatalf("drain answer %v: no open count", out)
	}
	if r := e.waitResult(task); r == nil {
		t.Fatal("the running task's result wasn't kept")
	}
}

// Through the front door, as the Worker calls it: POST /v with the envelope for /drain. While drained a new task
// is refused (503 draining, inside the envelope) and the open-task count still answers; /undrain lets it start.
// Outside the envelope /drain doesn't exist.
func TestDrainThroughTheEnvelope(t *testing.T) {
	a, _, _ := newTestAgent(t, textSSE("an answer"))
	id, _ := ehbpidentity.NewIdentity()
	s := newTestServer(t, a, id, defaultLimits)
	mux := http.NewServeMux()
	s.taskRoutes(mux, id)
	s.drainRoutes(mux)
	srv := httptest.NewServer(s.front(mux, &relay.Server{Key: testRelayPub(), Inner: s.gate(mux, nil)}))
	defer srv.Close()
	conn, err := agentclient.New(srv.URL, testRelaySeed, id.MarshalPublicKey())
	if err != nil {
		t.Fatal(err)
	}
	conn.User = "0123456789abcdef0123456789abcdef"
	post := func(path, body string) (int, string) {
		res, err := conn.Plain().Post(srv.URL+path, "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(res.Body)
		res.Body.Close()
		return res.StatusCode, string(b)
	}
	if code, body := post("/drain", untilIn(time.Hour)); code != 200 || !strings.Contains(body, `"drained":true`) {
		t.Fatalf("drain: %d %s", code, body)
	}
	ctx := context.Background()
	req := proto.RunRequest{Permissions: guard.AllowAll(), Messages: []proto.Message{{Role: "user", Content: "a task"}}}
	if _, err := conn.StartTask(ctx, req, ""); err == nil || !strings.Contains(err.Error(), "503") {
		t.Fatalf("drained: start %v, want 503 draining", err)
	}
	if res, err := conn.Plain().Get(srv.URL + "/tasks/open"); err != nil || res.StatusCode != 200 {
		t.Fatalf("drained: tasks/open %v %v", err, res)
	}
	if code, body := post("/undrain", `{}`); code != 200 {
		t.Fatalf("undrain: %d %s", code, body)
	}
	if _, err := conn.StartTask(ctx, req, ""); err != nil {
		t.Fatalf("undrained: start %v", err)
	}
	// Outside the envelope.
	res, err := http.Post(srv.URL+"/drain", "application/json", bytes.NewReader([]byte(untilIn(time.Hour))))
	if err != nil || res.StatusCode != 404 {
		t.Fatalf("plain POST /drain: %v %v", err, res)
	}
	if s.drain.on(time.Now()) {
		t.Fatal("a plain POST /drain drained the VM")
	}
}

// With the task queue in the host tmpfs, a drain outlives the hourly container restart (the next process takes it
// up) but not its own end; an undrain is kept too.
func TestDrainKeptAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	var first drainState
	first.restore(dir, time.Now())
	first.set(time.Now().Add(time.Hour).Truncate(time.Second))
	var second drainState
	second.restore(dir, time.Now())
	if !second.on(time.Now()) {
		t.Fatal("the next process isn't drained")
	}
	var later drainState
	later.restore(dir, time.Now().Add(61*time.Minute))
	if later.on(time.Now().Add(61 * time.Minute)) {
		t.Fatal("an ended drain was taken up")
	}
	second.set(time.Time{})
	var third drainState
	third.restore(dir, time.Now())
	if third.on(time.Now()) {
		t.Fatal("an undrain wasn't kept")
	}
}
