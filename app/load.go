package main

import (
	"bufio"
	"bytes"
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

// GET /load (docs/41 §9, build step 3): how busy this VM is, for the Worker's minute cron, which keeps a rolling day
// of it per VM for Admin and its alerts (the chat Worker's load poll). In the relay's envelope like /tasks/open
// (authorized: a request without one is 401), plaintext JSON inside it. It passes while drained and as a standby (a
// GET), and before the keys arrive (keyless): it needs none.
//
// Metadata only: numbers about the whole VM, never a task, person, space, model, URL or anything a run carries.
//
//	{"v": 1,
//	 "cpu_pct": 12.5,          TD-wide CPU busy since the previous /load (at most 10 minutes back; null: /proc unreadable)
//	 "mem_pct": 40.1,          TD-wide memory in use: 1 - MemAvailable/MemTotal (null: unreadable)
//	 "mem_total_mb": 7936, "cpus": 4, "load1": 0.42,
//	 "running": 3,             tasks holding a run slot (a brain has them; includes those waiting on a person)
//	 "waiting": 1,             of those, waiting on a person's decision or answer
//	 "queued": 0,              tasks no slot has yet, plus /run requests waiting for a slot
//	 "slots": 24, "queue_cap": 48,
//	 "open": 3,                tasks not ended (the idle timer's count)
//	 "searches": 0, "search_slots": 16,  plain-chat searches in flight here (the agents' searches go through gatewayd)
//	 "ended_5m": 4, "p50_ms": 41000, "p95_ms": 90000,  tasks ended in the last 5 minutes and their start-to-end times
//	 "uptime_s": 5400,         the TD's uptime (/proc/uptime); "agentd_s": agentd's own (it restarts hourly)
//	 "boot": "3fa1c2…",        12 hex of SHA-256 of the kernel's boot_id: tells two boots apart, says nothing else
//	 "drained": false, "standby": false}
type loadAnswer struct {
	V           int      `json:"v"`
	CPU         *float64 `json:"cpu_pct"`
	Mem         *float64 `json:"mem_pct"`
	MemTotalMB  int64    `json:"mem_total_mb"`
	CPUs        int      `json:"cpus"`
	Load1       *float64 `json:"load1"`
	Running     int      `json:"running"`
	Waiting     int      `json:"waiting"`
	Queued      int      `json:"queued"`
	Slots       int      `json:"slots"`
	QueueCap    int      `json:"queue_cap"`
	Open        int      `json:"open"`
	Searches    int      `json:"searches"`
	SearchSlots int      `json:"search_slots"`
	Ended5m     int      `json:"ended_5m"`
	P50ms       int64    `json:"p50_ms"`
	P95ms       int64    `json:"p95_ms"`
	UptimeS     int64    `json:"uptime_s"`
	AgentdS     int64    `json:"agentd_s"`
	Boot        string   `json:"boot"`
	Drained     bool     `json:"drained"`
	Standby     bool     `json:"standby"`
}

// loadWindow is the window of the task-time percentiles.
const loadWindow = 5 * time.Minute

// loadMeter reads the TD's /proc and keeps the previous CPU reading, so each /load gives the CPU busy since the one
// before (the Worker asks every minute: a minute's average, not an instant). Zero value: /proc.
type loadMeter struct {
	proc string // "": /proc (tests: a directory with the same files)
	mu   sync.Mutex
	at   time.Time
	busy uint64
	all  uint64
	last *float64
	// sleep waits between two readings when there is no recent one (tests: no wait).
	sleep func(time.Duration)
}

const (
	// cpuMinGap: a /load sooner than this after the previous reading gives that reading's figure again, so two
	// callers close together don't make a figure over a few milliseconds.
	cpuMinGap = 5 * time.Second
	// cpuMaxAge: a previous reading older than this isn't used (an average over hours says nothing about now); two
	// readings cpuSample apart are taken instead.
	cpuMaxAge = 10 * time.Minute
	cpuSample = 250 * time.Millisecond
)

func (m *loadMeter) path(name string) string {
	return filepath.Join(cmp.Or(m.proc, "/proc"), name)
}

// cpuTimes is /proc/stat's first line: busy and total jiffies (iowait counts as idle; guest time is inside user).
func (m *loadMeter) cpuTimes() (busy, all uint64, ok bool) {
	b, err := os.ReadFile(m.path("stat"))
	if err != nil {
		return 0, 0, false
	}
	line, _, _ := bytes.Cut(b, []byte("\n"))
	f := strings.Fields(string(line))
	if len(f) < 5 || f[0] != "cpu" {
		return 0, 0, false
	}
	var v []uint64
	for _, s := range f[1:min(len(f), 9)] { // user nice system idle iowait irq softirq steal
		n, err := strconv.ParseUint(s, 10, 64)
		if err != nil {
			return 0, 0, false
		}
		v = append(v, n)
	}
	for _, n := range v {
		all += n
	}
	idle := v[3]
	if len(v) > 4 {
		idle += v[4]
	}
	return all - idle, all, true
}

// cpu is the CPU busy percent since the previous reading (see loadMeter), or nil.
func (m *loadMeter) cpu(now time.Time) *float64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.at.IsZero() && now.Sub(m.at) < cpuMinGap && m.last != nil {
		return m.last
	}
	if m.at.IsZero() || now.Sub(m.at) > cpuMaxAge {
		b, a, ok := m.cpuTimes()
		if !ok {
			return nil
		}
		m.busy, m.all = b, a
		if m.sleep != nil {
			m.sleep(cpuSample)
		} else {
			time.Sleep(cpuSample)
		}
	}
	b, a, ok := m.cpuTimes()
	if !ok {
		return nil
	}
	var pct float64
	if a > m.all && b >= m.busy {
		pct = round1(100 * float64(b-m.busy) / float64(a-m.all))
	} else if m.last != nil { // no jiffies passed (a coarse clock): the previous figure
		pct = *m.last
	}
	m.at, m.busy, m.all = now, b, a
	m.last = &pct
	return m.last
}

// mem is the memory in use percent and the total in MiB, from /proc/meminfo.
func (m *loadMeter) mem() (*float64, int64) {
	f, err := os.Open(m.path("meminfo"))
	if err != nil {
		return nil, 0
	}
	defer f.Close()
	var total, avail int64 = -1, -1
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), ":")
		if !ok {
			continue
		}
		n, err := strconv.ParseInt(strings.TrimSuffix(strings.TrimSpace(v), " kB"), 10, 64)
		if err != nil {
			continue
		}
		switch k {
		case "MemTotal":
			total = n
		case "MemAvailable":
			avail = n
		}
	}
	if total <= 0 || avail < 0 || avail > total {
		return nil, max(total, 0) / 1024
	}
	pct := round1(100 * float64(total-avail) / float64(total))
	return &pct, total / 1024
}

// firstFloat is the first number of a /proc file (loadavg, uptime).
func (m *loadMeter) firstFloat(name string) *float64 {
	b, err := os.ReadFile(m.path(name))
	if err != nil {
		return nil
	}
	f := strings.Fields(string(b))
	if len(f) == 0 {
		return nil
	}
	v, err := strconv.ParseFloat(f[0], 64)
	if err != nil || math.IsNaN(v) || math.IsInf(v, 0) || v < 0 {
		return nil
	}
	v = round1(v)
	return &v
}

// boot is 12 hex of SHA-256 of the kernel's boot id ("": unreadable).
func (m *loadMeter) boot() string {
	b, err := os.ReadFile(m.path("sys/kernel/random/boot_id"))
	if err != nil || len(bytes.TrimSpace(b)) == 0 {
		return ""
	}
	h := sha256.Sum256(bytes.TrimSpace(b))
	return hex.EncodeToString(h[:6])
}

func round1(v float64) float64 { return math.Round(v*10) / 10 }

// loadRoutes serves GET /load.
func (s *server) loadRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /load", s.loadOut)
}

func (s *server) loadOut(w http.ResponseWriter, r *http.Request) {
	if !s.authorized(r) {
		fail(w, 401, "unauthorized")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, s.loadNow(time.Now()))
}

// loadNow is /load's answer at now.
func (s *server) loadNow(now time.Time) loadAnswer {
	a := loadAnswer{V: 1, CPUs: runtime.NumCPU(), Slots: s.lim.MaxRuns, QueueCap: s.lim.MaxQueue, SearchSlots: maxSearches,
		Drained: s.drain.on(now), Standby: s.drain.standby.Load()}
	a.CPU = s.load.cpu(now)
	a.Mem, a.MemTotalMB = s.load.mem()
	a.Load1 = s.load.firstFloat("loadavg")
	if up := s.load.firstFloat("uptime"); up != nil {
		a.UptimeS = int64(*up)
	}
	if !s.booted.IsZero() {
		a.AgentdS = int64(now.Sub(s.booted).Seconds())
	}
	a.Boot = s.load.boot()
	if s.rt != nil {
		l := s.rt.Load(loadWindow)
		a.Running, a.Waiting, a.Queued, a.Ended5m = l.Running, l.Waiting, l.Queued, l.Ended
		a.P50ms, a.P95ms = l.P50.Milliseconds(), l.P95.Milliseconds()
	}
	if s.sched != nil {
		_, q := s.sched.stats() // /run requests waiting for a slot (their tasks aren't in the runtime yet)
		a.Queued += q
	}
	if s.rt != nil {
		a.Open = s.tasks().Open()
	}
	a.Searches = len(s.searchSlots)
	return a
}
