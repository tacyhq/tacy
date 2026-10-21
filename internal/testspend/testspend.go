// Package testspend counts what a test tool's runs on the live agent VM cost and keeps a daily total of it.
//
// cmd/e2e --live and cmd/photolab send real runs to the live VM: production Tinfoil inference and production
// searches, which no relay charges to anyone. The relay's billing alert compares Tinfoil's bill with what was charged,
// so that spend would look like a gap. A Meter adds up the cost each run already reports in its metrics events (model
// and reader calls by their tokens at the VM's own prices, safety.ModelCost; searches at safety.SearchCost: the VM's
// ledger's figures), and Record adds a tool's total to a local ledger by UTC day. The chat's
// scripts/test-spend.sh push copies each day's total into the relay's usage_global.test_spend (its database, with the
// deploy's Cloudflare token), where the alert counts it on the charged side and the admin's Health view shows it as
// test spend. Numbers only: no prompt, model text or id is kept.
package testspend

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/tacyhq/tacy/proto"
	"github.com/tacyhq/tacy/safety"
)

// EventCost is the cost (micro-USD) one event reports: a model or reader call's tokens at its model's price, or a
// web or image search. Anything else (and a refused search, which never left the VM) costs nothing.
func EventCost(e proto.Event) int64 {
	m := e.Metrics
	if e.Type != "metrics" || m == nil {
		return 0
	}
	switch m.Kind {
	case "model", "reader":
		if m.Model == "" || m.Prompt+m.Completion == 0 {
			return 0
		}
		return safety.ModelCost(m.Model, int64(m.Prompt), int64(m.Completion))
	case "search", "images":
		if m.Outcome == "refused" {
			return 0
		}
		return safety.SearchCost
	}
	return 0
}

// Meter adds up events' costs (EventCost). A task's event (a key) counts once however often it is followed.
type Meter struct {
	mu     sync.Mutex
	micros int64
	seen   map[string]bool
}

// Observe counts e; it has agentclient.Observe's signature (task "" for a stream that isn't a task's).
func (m *Meter) Observe(task string, seq int, e proto.Event) {
	c := EventCost(e)
	if c == 0 {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if task != "" {
		k := task + "#" + strconv.Itoa(seq)
		if m.seen[k] {
			return
		}
		if m.seen == nil {
			m.seen = map[string]bool{}
		}
		m.seen[k] = true
	}
	m.micros += c
}

// Micros is what was counted so far.
func (m *Meter) Micros() int64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.micros
}

// Ledger is the local file of daily totals: UTC day -> tool label -> micro-USD.
type Ledger struct {
	Days map[string]map[string]int64 `json:"days"`
}

// keepDays: days older than this are dropped (the relay's counters keep 31).
const keepDays = 31

// DefaultPath is the ledger's place: $TACY_TEST_SPEND_LEDGER, else ~/.tacy-lab/test-spend.json (next to the labs'
// Exa ledger).
func DefaultPath() string {
	if p := os.Getenv("TACY_TEST_SPEND_LEDGER"); p != "" {
		return p
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".tacy-lab", "test-spend.json")
}

var labelRe = regexp.MustCompile(`^[a-z0-9-]{1,32}$`)

// Record adds micros to label's total on now's UTC day in the ledger at path and returns that day and its total over
// every label. Not locked: two tools finishing in the same instant could lose one's addition (rare; the push takes
// the ledger as it is).
func Record(path, label string, micros int64, now time.Time) (string, int64, error) {
	if !labelRe.MatchString(label) {
		return "", 0, fmt.Errorf("testspend: bad label %q", label)
	}
	if micros < 0 {
		return "", 0, fmt.Errorf("testspend: negative spend")
	}
	var l Ledger
	if b, err := os.ReadFile(path); err == nil {
		if err := json.Unmarshal(b, &l); err != nil {
			return "", 0, fmt.Errorf("testspend: %s: %w", path, err)
		}
	} else if !os.IsNotExist(err) {
		return "", 0, err
	}
	if l.Days == nil {
		l.Days = map[string]map[string]int64{}
	}
	day := now.UTC().Format(time.DateOnly)
	if l.Days[day] == nil {
		l.Days[day] = map[string]int64{}
	}
	l.Days[day][label] += micros
	cutoff := now.UTC().AddDate(0, 0, -keepDays).Format(time.DateOnly)
	for d := range l.Days {
		if d < cutoff {
			delete(l.Days, d)
		}
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", 0, err
	}
	b, err := json.MarshalIndent(l, "", "  ")
	if err != nil {
		return "", 0, err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {
		return "", 0, err
	}
	if err := os.Rename(tmp, path); err != nil {
		return "", 0, err
	}
	return day, l.Total(day), nil
}

// Total is day's spend over every label.
func (l Ledger) Total(day string) int64 {
	var n int64
	for _, v := range l.Days[day] {
		n += v
	}
	return n
}

// Sorted is the ledger's days, oldest first.
func (l Ledger) Sorted() []string {
	out := make([]string, 0, len(l.Days))
	for d := range l.Days {
		out = append(out, d)
	}
	sort.Strings(out)
	return out
}

// Report records a tool's meter (when anything was spent) and prints one line about it: the run's spend, the day's
// total and how to push it. path "" skips the ledger (it is printed only).
func Report(path, label string, m *Meter, now time.Time) {
	micros := m.Micros()
	if micros == 0 {
		fmt.Println("test spend: $0.000 this run (nothing reported)")
		return
	}
	if path == "" {
		fmt.Printf("test spend: $%.3f this run (production inference and search, uncharged; not recorded: no ledger path)\n", float64(micros)/1e6)
		return
	}
	day, total, err := Record(path, label, micros, now)
	if err != nil {
		fmt.Printf("test spend: $%.3f this run, NOT recorded: %v\n", float64(micros)/1e6, err)
		return
	}
	fmt.Printf("test spend: $%.3f this run, $%.3f on %s (%s); push it to the relay's totals with the chat's scripts/test-spend.sh push\n",
		float64(micros)/1e6, float64(total)/1e6, day, path)
}
