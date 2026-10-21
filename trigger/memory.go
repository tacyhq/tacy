package trigger

import (
	"slices"
	"strings"
	"sync"
	"time"
)

// Memory across runs (schedule upgrades, the VM release after v0.14.0; docs/30 "Scheduled tasks", upgrades): a
// definition with memory has what its last runs found kept on the VM, per schedule, and each run starts with it,
// so a daily digest can skip what it reported before, and a "tell me only when it changes" schedule can compare.
//
//   - What: per run, its local day, whether it was quiet, its result's text (the digest, its [n] marks taken out; or
//     a quiet run's one-line note) and the sources the result cited (title and address). Never the person's
//     instructions, never the run's events.
//   - Where: the side file on the VM's encrypted disk (queue/side.go), next to the schedule; never sent anywhere (the
//     browser gets each run's result sealed, as before; the memory itself never leaves the VM).
//   - How much: the newest MemoryRuns runs of the schedule, each kept at most MemoryKeep after it ended.
//   - Until: the schedule is removed, or a new version drops memory (agentd deletes it then).

// Memory limits.
const (
	MemoryRuns = 7
	MemoryKeep = 30 * 24 * time.Hour
	// NotifyChanges is Definition.Notify's one value: tell the person only when something changed.
	NotifyChanges = "changes"

	MaxMemoryText    = 3000 // runes of a run's result kept
	MaxMemoryNote    = 300  // runes of a quiet run's note kept
	MaxMemorySources = 30
	maxMemoryTitle   = 160
	maxMemoryURL     = 500
)

// Remembered is one run's memory.
type Remembered struct {
	Space   string
	Agent   string
	Task    string
	Day     string // the slot's local date ("YYYY-MM-DD")
	EndedAt time.Time
	// Quiet: the run found nothing that changed and told nobody (Definition.Notify); Text is then its note.
	Quiet   bool
	Text    string
	Sources []RememberedSource
}

// RememberedSource is a source a run's result cited.
type RememberedSource struct {
	Title string `json:"title,omitzero"`
	URL   string `json:"url"`
}

// MemoryStore keeps schedules' memories.
type MemoryStore interface {
	// PutMemory adds a run's memory (a second one for the same task replaces nothing) and keeps only the newest
	// MemoryRuns of its agent.
	PutMemory(m Remembered) error
	// Memories is the agent's memory in the space, newest first: runs that ended after since, at most MemoryRuns.
	Memories(space, agent string, since time.Time) ([]Remembered, error)
	// DeleteMemory deletes every run's memory of the agent in the space; it returns how many.
	DeleteMemory(space, agent string) (int, error)
	// PruneMemory deletes memories of runs that ended before t.
	PruneMemory(t time.Time) error
}

// Capped is m within the limits: text and note cut, at most MaxMemorySources sources (each title and address
// capped, an address that isn't http(s) left out), no control characters but newlines in the text.
func (m Remembered) Capped() Remembered {
	limit := MaxMemoryText
	if m.Quiet {
		limit = MaxMemoryNote
	}
	m.Text = capClean(m.Text, limit, true)
	var src []RememberedSource
	for _, s := range m.Sources {
		u := capClean(s.URL, maxMemoryURL, false)
		if !strings.HasPrefix(u, "https://") && !strings.HasPrefix(u, "http://") || strings.ContainsAny(u, " \n") {
			continue
		}
		if len(src) == MaxMemorySources {
			break
		}
		src = append(src, RememberedSource{Title: capClean(s.Title, maxMemoryTitle, false), URL: u})
	}
	m.Sources = src
	return m
}

// capClean is s as valid UTF-8 without control characters (newlines kept when lines), trimmed, at most n runes.
func capClean(s string, n int, lines bool) string {
	s = strings.ToValidUTF8(s, "")
	var b strings.Builder
	k := 0
	for _, r := range s {
		if k == n {
			break
		}
		switch {
		case r == '\n' && lines:
		case r == '\t' || r == '\n' || r == '\r':
			r = ' '
		case r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0):
			continue
		}
		b.WriteRune(r)
		k++
	}
	return strings.TrimSpace(b.String())
}

// MemMemory is an in-memory MemoryStore.
type MemMemory struct {
	mu sync.Mutex
	ms []Remembered // oldest first
}

func (m *MemMemory) PutMemory(r Remembered) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, x := range m.ms {
		if x.Task == r.Task {
			return nil
		}
	}
	m.ms = append(m.ms, r.Capped())
	// Only the newest MemoryRuns of the agent stay.
	var mine []int
	for i, x := range m.ms {
		if x.Space == r.Space && x.Agent == r.Agent {
			mine = append(mine, i)
		}
	}
	if n := len(mine) - MemoryRuns; n > 0 {
		slices.SortFunc(mine, func(a, b int) int { return m.ms[a].EndedAt.Compare(m.ms[b].EndedAt) })
		drop := map[int]bool{}
		for _, i := range mine[:n] {
			drop[i] = true
		}
		out := m.ms[:0]
		for i, x := range m.ms {
			if !drop[i] {
				out = append(out, x)
			}
		}
		m.ms = out
	}
	return nil
}

func (m *MemMemory) Memories(space, agent string, since time.Time) ([]Remembered, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Remembered
	for _, x := range m.ms {
		if x.Space == space && x.Agent == agent && x.EndedAt.After(since) {
			out = append(out, x)
		}
	}
	slices.SortStableFunc(out, func(a, b Remembered) int { return b.EndedAt.Compare(a.EndedAt) })
	if len(out) > MemoryRuns {
		out = out[:MemoryRuns]
	}
	return out, nil
}

func (m *MemMemory) del(keep func(Remembered) bool) int {
	n := 0
	out := m.ms[:0]
	for _, x := range m.ms {
		if keep(x) {
			out = append(out, x)
		} else {
			n++
		}
	}
	m.ms = out
	return n
}

func (m *MemMemory) DeleteMemory(space, agent string) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.del(func(x Remembered) bool { return !(x.Space == space && x.Agent == agent) }), nil
}

func (m *MemMemory) PruneMemory(t time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.del(func(x Remembered) bool { return !x.EndedAt.Before(t) })
	return nil
}
