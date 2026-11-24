package main

import (
	"context"
	"encoding/json"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/tacyhq/tacy/agentclient"
	"github.com/tacyhq/tacy/guard"
	"github.com/tacyhq/tacy/proto"
)

// fakeProc writes the /proc files /load reads into a new directory.
func fakeProc(t *testing.T, stat string) string {
	t.Helper()
	dir := t.TempDir()
	files := map[string]string{
		"stat":                      stat,
		"meminfo":                   "MemTotal:        8000000 kB\nMemFree:          1000000 kB\nMemAvailable:     6000000 kB\n",
		"loadavg":                   "0.42 0.30 0.20 1/123 4567\n",
		"uptime":                    "5400.27 20000.00\n",
		"sys/kernel/random/boot_id": "5f0c9d6e-3c1b-4a8e-9b7d-2f6a1e0c4d3b\n",
	}
	for name, body := range files {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func setStat(t *testing.T, dir, stat string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "stat"), []byte(stat), 0o644); err != nil {
		t.Fatal(err)
	}
}

// The CPU figure is the busy share since the previous reading (iowait counts as idle); a reading close after one
// gives that figure again; with no reading, two are taken a moment apart; unreadable is null, not 0.
func TestLoadCPU(t *testing.T) {
	dir := fakeProc(t, "cpu  100 0 100 800 0 0 0 0 0 0\ncpu0 1 2 3 4\n")
	var slept []time.Duration
	m := &loadMeter{proc: dir}
	m.sleep = func(d time.Duration) {
		slept = append(slept, d)
		setStat(t, dir, "cpu  150 0 150 850 50 0 0 0 0 0\n") // 100 busy of 200
	}
	t0 := time.Unix(1_800_000_000, 0)
	if c := m.cpu(t0); c == nil || *c != 50 || len(slept) != 1 {
		t.Fatalf("first reading: %v (slept %v)", c, slept)
	}
	setStat(t, dir, "cpu  150 0 250 850 50 0 0 0 0 0\n")
	if c := m.cpu(t0.Add(time.Second)); c == nil || *c != 50 {
		t.Fatalf("a reading 1 s later must repeat the figure: %v", c)
	}
	// A minute later: 100 more busy, 0 more idle: 100%.
	if c := m.cpu(t0.Add(time.Minute)); c == nil || *c != 100 || len(slept) != 1 {
		t.Fatalf("a minute later: %v (slept %v)", c, slept)
	}
	// Past cpuMaxAge: two fresh readings again.
	if m.cpu(t0.Add(time.Hour)); len(slept) != 2 {
		t.Fatalf("an old reading must not be used: slept %v", slept)
	}
	if c := (&loadMeter{proc: t.TempDir(), sleep: func(time.Duration) {}}).cpu(t0); c != nil {
		t.Fatalf("no /proc/stat: %v, want null", *c)
	}
	setStat(t, dir, "cpu  x 0 0 0\n")
	if c := (&loadMeter{proc: dir, sleep: func(time.Duration) {}}).cpu(t0); c != nil {
		t.Fatalf("a malformed /proc/stat: %v, want null", *c)
	}
}

// GET /load: the relay's envelope only; numbers about the whole VM and exactly the documented fields, nothing a
// run carries (no task id, user tag, space, model, or text of the run), while a task runs.
func TestLoadRoute(t *testing.T) {
	m := newStepModel(t, "block")
	p := bootTasks(t, filepath.Join(t.TempDir(), "queue.db"), m, &fakeSearch{}, false)
	p.s.load = loadMeter{proc: fakeProc(t, "cpu  100 0 100 800 0 0 0 0\n"), sleep: func(time.Duration) {}}
	p.s.searchSlots = make(chan struct{}, maxSearches)
	mux := http.NewServeMux()
	p.s.loadRoutes(mux)

	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest("GET", "/load", nil))
	if w.Code != 401 {
		t.Fatalf("outside an envelope: %d, want 401", w.Code)
	}

	c := p.conn(t, tasksUser)
	const secret = "a question only the person typed 7f3a"
	tk, err := c.StartTask(context.Background(), proto.RunRequest{Permissions: guard.AllowAll(), Messages: user1(secret)}, "key-1")
	if err != nil {
		t.Fatal(err)
	}
	waitCalls(t, m, 1)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, asRelay(httptest.NewRequest("GET", "/load", nil)))
	if w.Code != 200 || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("GET /load: %d %s", w.Code, w.Body)
	}
	body := w.Body.String()
	for _, leak := range []string{tk.Task, tasksUser, secret, "7f3a", "model"} {
		if strings.Contains(body, leak) {
			t.Fatalf("/load names %q: %s", leak, body)
		}
	}
	var raw map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &raw); err != nil {
		t.Fatal(err)
	}
	want := []string{"v", "cpu_pct", "mem_pct", "mem_total_mb", "cpus", "load1", "running", "waiting", "queued", "slots", "queue_cap", "open",
		"searches", "search_slots", "ended_5m", "p50_ms", "p95_ms", "uptime_s", "agentd_s", "boot", "drained", "standby"}
	if got := slices.Sorted(maps.Keys(raw)); !slices.Equal(got, slices.Sorted(slices.Values(want))) {
		t.Fatalf("fields %v, want %v", got, want)
	}
	for k, v := range raw {
		switch v.(type) {
		case float64, bool, nil:
		case string:
			if k != "boot" {
				t.Fatalf("%s is a string: %v", k, v)
			}
		default:
			t.Fatalf("%s isn't a number: %v", k, v)
		}
	}
	var a loadAnswer
	if err := json.Unmarshal(w.Body.Bytes(), &a); err != nil {
		t.Fatal(err)
	}
	if a.V != 1 || a.Running != 1 || a.Queued != 0 || a.Open != 1 || a.Slots != defaultLimits.MaxRuns || a.QueueCap != defaultLimits.MaxQueue ||
		a.Mem == nil || *a.Mem != 25 || a.MemTotalMB != 7812 || a.Load1 == nil || *a.Load1 != 0.4 || a.UptimeS != 5400 || len(a.Boot) != 12 ||
		a.CPU == nil || a.SearchSlots != maxSearches || a.Drained || a.Standby {
		t.Fatalf("load %+v", a)
	}

	// Drained (GETs pass the gate) and the cancelled task's end counted with a time.
	if _, err := c.CancelTask(context.Background(), tk.Task); err != nil {
		t.Fatal(err)
	}
	waitTask(t, c, tk.Task, func(s *agentclient.Task) bool { return s.Outcome != "" })
	p.s.drain.until = time.Now().Add(time.Hour)
	gated := p.s.gate(mux, nil)
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		w = httptest.NewRecorder()
		gated.ServeHTTP(w, asRelay(httptest.NewRequest("GET", "/load", nil)))
		if err := json.Unmarshal(w.Body.Bytes(), &a); err != nil || w.Code != 200 {
			t.Fatalf("drained: %d %s", w.Code, w.Body)
		}
		if a.Running == 0 || time.Now().After(deadline) {
			break
		}
	}
	if a.Running != 0 || a.Open != 0 || a.Ended5m != 1 || a.P50ms < 0 || a.P95ms < a.P50ms || !a.Drained {
		t.Fatalf("after the cancel, drained: %+v", a)
	}
}

// Before the API keys arrive /load answers (it needs none): keyless.
func TestLoadKeyless(t *testing.T) {
	if !keyless("/load") {
		t.Fatal("/load must answer before the keys arrive")
	}
}
