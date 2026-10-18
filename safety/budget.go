package safety

import (
	"encoding/json/v2"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Usage is what a run or a space's day used, or what a request reserves.
type Usage struct {
	Tokens     int64 `json:"tokens,omitzero"`
	ToolCalls  int64 `json:"tool_calls,omitzero"`
	CostMicros int64 `json:"cost_usd_micros,omitzero"`
	WallMs     int64 `json:"wall_ms,omitzero"` // days only: finished runs' running time (Ledger.Elapsed)
}

func (u *Usage) add(v Usage, sign int64) {
	u.Tokens += sign * v.Tokens
	u.ToolCalls += sign * v.ToolCalls
	u.CostMicros += sign * v.CostMicros
	u.WallMs += sign * v.WallMs
}

// over names the first limit that used + more would pass ("" when none does). wall is the time used.
func over(l Limits, used Usage, more Usage, wall time.Duration) string {
	switch {
	case l.Tokens > 0 && used.Tokens+more.Tokens > l.Tokens:
		return "model tokens"
	case l.ToolCalls > 0 && used.ToolCalls+more.ToolCalls > l.ToolCalls:
		return "tool calls"
	case l.CostMicros > 0 && used.CostMicros+more.CostMicros > l.CostMicros:
		return "cost estimate"
	case l.WallSeconds > 0 && wall >= time.Duration(l.WallSeconds)*time.Second:
		return "running time"
	}
	return ""
}

type ledgerRun struct {
	space          string
	start          time.Time
	used, reserved Usage
	// Running time leaves out the time the run only waits for its person (docs/27 section 6): while at least one
	// of its prompts is open (asks) and none of its requests is between Reserve and commit (inflight), the clock
	// stops. waited is the time stopped so far; since is when the current stop began (zero: running).
	asks, inflight int
	waited         time.Duration
	since          time.Time
}

// elapsed is the run's running time at now: from its start, less the time it only waited for its person.
func (r *ledgerRun) elapsed(now time.Time) time.Duration {
	w := r.waited
	if !r.since.IsZero() {
		w += now.Sub(r.since)
	}
	return max(0, now.Sub(r.start)-w)
}

// clock stops or restarts the run's clock after asks or inflight changed.
func (r *ledgerRun) clock(now time.Time) {
	stopped := r.asks > 0 && r.inflight == 0
	switch {
	case stopped && r.since.IsZero():
		r.since = now
	case !stopped && !r.since.IsZero():
		r.waited += now.Sub(r.since)
		r.since = time.Time{}
	}
}

type ledgerDay struct {
	Used     Usage `json:"used"`
	reserved Usage
}

// Ledger keeps the budgets: per run in memory, per space per UTC day on the encrypted disk (counts only). A
// request reserves what it may use before it runs, under one lock, so parallel requests can't each see room that
// only one of them has; the reservation is replaced by what was actually used when it ends.
type Ledger struct {
	Dir string // where the day counters persist; "": memory only
	Now func() time.Time

	mu   sync.Mutex
	runs map[string]*ledgerRun
	days map[string]*ledgerDay // space + "|" + YYYY-MM-DD
	once sync.Once
}

func (l *Ledger) init() {
	l.once.Do(func() {
		if l.Now == nil {
			l.Now = time.Now
		}
		l.runs, l.days = map[string]*ledgerRun{}, map[string]*ledgerDay{}
		if l.Dir != "" {
			if b, err := os.ReadFile(filepath.Join(l.Dir, "budget.json")); err == nil {
				json.Unmarshal(b, &l.days)
			}
		}
	})
}

func (l *Ledger) day(space string) *ledgerDay {
	k := space + "|" + l.Now().UTC().Format(time.DateOnly)
	d := l.days[k]
	if d == nil {
		d = &ledgerDay{}
		l.days[k] = d
	}
	return d
}

// dayWall is the space's running time today: finished runs plus the ones running now (time waiting for a person
// left out, as for a run).
func (l *Ledger) dayWall(space string, d *ledgerDay) time.Duration {
	w := time.Duration(d.Used.WallMs) * time.Millisecond
	now := l.Now()
	for _, r := range l.runs {
		if r.space == space {
			w += r.elapsed(now)
		}
	}
	return w
}

func budgetError(scope, what string) error {
	return errorf(CodeBudgetExceeded, "the %s budget for %s is used up", scope, what)
}

// Start registers a run in space (Admit, then Begin).
func (l *Ledger) Start(task, space string, b Budgets) (time.Time, error) {
	if _, err := l.Admit(space, b); err != nil {
		return time.Time{}, err
	}
	l.Begin(task, space)
	return l.Admit(space, b, task)
}

// Begin registers a run in space from now (again: a no-op).
func (l *Ledger) Begin(task, space string) {
	l.init()
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.runs[task] == nil {
		l.runs[task] = &ledgerRun{space: space, start: l.Now()}
	}
}

// Resume registers a run that was begun before a restart (a task taken up again): it started at start and has
// used what used says, so its run budget and running time go on from there instead of starting over. Time it
// waited for its person before the restart isn't known here, so it counts as running time: a restart can only
// shorten a run, never lengthen it. A run already registered is left as it is.
func (l *Ledger) Resume(task, space string, start time.Time, used Usage) {
	l.init()
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.runs[task] == nil {
		if start.IsZero() || start.After(l.Now()) {
			start = l.Now()
		}
		l.runs[task] = &ledgerRun{space: space, start: start, used: used}
	}
}

// Admit refuses a new run when the space's day budget is already used up, and returns the latest a run may go on
// (zero: no limit), from the day's running time. task, when given, is a run already begun. The run's own running
// time isn't a fixed end: time waiting for the person doesn't count (Pause), so Elapsed is checked as it goes
// (Reserve, and the caller's timer). The day's end is computed as if nothing paused: never later than it should be.
func (l *Ledger) Admit(space string, b Budgets, task ...string) (time.Time, error) {
	l.init()
	l.mu.Lock()
	defer l.mu.Unlock()
	d := l.day(space)
	held := d.Used
	held.add(d.reserved, 1)
	// A run needs at least a token of model budget; used-up tool calls only refuse its tool calls.
	if what := over(b.Day, held, Usage{Tokens: 1, CostMicros: 1}, l.dayWall(space, d)); what != "" {
		return time.Time{}, budgetError("daily", what)
	}
	var end time.Time
	if b.Day.WallSeconds > 0 {
		end = l.Now().Add(time.Duration(b.Day.WallSeconds)*time.Second - l.dayWall(space, d))
	}
	return end, nil
}

var errUnknownRun = errorf(CodeBudgetExceeded, "the run has no budget (not started here)")

// Reserve takes want from the run's and the day's budgets b (the current policy's), or refuses with the limit it
// would pass. commit replaces the reservation with what was used (call it exactly once).
func (l *Ledger) Reserve(task string, want Usage, b Budgets) (commit func(used Usage), err error) {
	l.init()
	l.mu.Lock()
	defer l.mu.Unlock()
	r := l.runs[task]
	if r == nil {
		return nil, errUnknownRun
	}
	d := l.day(r.space)
	held := r.used
	held.add(r.reserved, 1)
	if what := over(b.Run, held, want, r.elapsed(l.Now())); what != "" {
		return nil, budgetError("run's", what)
	}
	held = d.Used
	held.add(d.reserved, 1)
	if what := over(b.Day, held, want, l.dayWall(r.space, d)); what != "" {
		return nil, budgetError("daily", what)
	}
	r.reserved.add(want, 1)
	d.reserved.add(want, 1)
	r.inflight++ // working: the clock runs while the request does, even with a prompt open
	r.clock(l.Now())
	var once sync.Once
	return func(used Usage) {
		once.Do(func() {
			l.mu.Lock()
			defer l.mu.Unlock()
			r.reserved.add(want, -1)
			d.reserved.add(want, -1)
			r.used.add(used, 1)
			d.Used.add(used, 1)
			r.inflight--
			r.clock(l.Now())
			l.save()
		})
	}, nil
}

// TokensLeft is how many model tokens the run may still reserve: the least of the run's and the day's token
// budgets left after what is used and reserved (-1: no token limit; 0 for a run it doesn't know).
func (l *Ledger) TokensLeft(task string, b Budgets) int64 {
	l.init()
	l.mu.Lock()
	defer l.mu.Unlock()
	r := l.runs[task]
	if r == nil {
		return 0
	}
	d := l.day(r.space)
	left := int64(-1)
	for _, c := range []struct {
		lim       int64
		used, res int64
	}{{b.Run.Tokens, r.used.Tokens, r.reserved.Tokens}, {b.Day.Tokens, d.Used.Tokens, d.reserved.Tokens}} {
		if c.lim > 0 {
			if v := max(0, c.lim-c.used-c.res); left < 0 || v < left {
				left = v
			}
		}
	}
	return left
}

// Used is what the run used so far.
func (l *Ledger) Used(task string) (Usage, bool) {
	l.init()
	l.mu.Lock()
	defer l.mu.Unlock()
	if r := l.runs[task]; r != nil {
		return r.used, true
	}
	return Usage{}, false
}

// Elapsed is the run's running time (how long it has been going, less the time it only waited for its person:
// Pause), and whether the ledger knows it.
func (l *Ledger) Elapsed(task string) (time.Duration, bool) {
	l.init()
	l.mu.Lock()
	defer l.mu.Unlock()
	if r := l.runs[task]; r != nil {
		return r.elapsed(l.Now()), true
	}
	return 0, false
}

// Pause notes that a prompt of the run waits for its person (a permission prompt), Unpause that one was
// answered, timed out or dropped. While at least one waits and none of the run's requests is in flight, the run's
// running time (Elapsed, the run's and the day's running-time budgets) stops. A run the ledger doesn't know is
// ignored; Unpause without a Pause does nothing.
func (l *Ledger) Pause(task string) { l.ask(task, 1) }

// Unpause: see Pause.
func (l *Ledger) Unpause(task string) { l.ask(task, -1) }

func (l *Ledger) ask(task string, d int) {
	l.init()
	l.mu.Lock()
	defer l.mu.Unlock()
	r := l.runs[task]
	if r == nil {
		return
	}
	r.asks = max(0, r.asks+d)
	r.clock(l.Now())
}

// End adds the run's time to its space's day and forgets it.
func (l *Ledger) End(task string) {
	l.init()
	l.mu.Lock()
	defer l.mu.Unlock()
	r := l.runs[task]
	if r == nil {
		return
	}
	delete(l.runs, task)
	l.day(r.space).Used.WallMs += r.elapsed(l.Now()).Milliseconds()
	l.save()
}

// save writes today's and yesterday's counters (older days are dropped).
func (l *Ledger) save() error {
	if l.Dir == "" {
		return nil
	}
	keep := map[string]*ledgerDay{}
	today, yday := l.Now().UTC().Format(time.DateOnly), l.Now().UTC().Add(-24*time.Hour).Format(time.DateOnly)
	for k, d := range l.days {
		if n := len(k); n > 10 && (k[n-10:] == today || k[n-10:] == yday) {
			keep[k] = d
		}
	}
	l.days = keep
	b, err := json.Marshal(keep)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(l.Dir, 0o700); err != nil {
		return err
	}
	tmp := filepath.Join(l.Dir, "budget.json.tmp")
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(l.Dir, "budget.json"))
}

// ---- cost estimates (mirror the chat's model prices, checked 2026-10-14) -----------------------------------------

// modelPrices: millionths of a USD per million tokens, input and output.
var modelPrices = map[string][2]int64{
	"gpt-oss-120b":        {150_000, 600_000},
	"gemma4-31b":          {400_000, 1_000_000},
	"llama3-3-70b":        {1_750_000, 2_750_000},
	"glm-5-3":             {1_800_000, 5_750_000},
	"kimi-k3":             {4_000_000, 20_000_000},
	"deepseek-v4-1-flash": {650_000, 1_450_000},
}

// unknownPrice is used for a model without a price: the dearest one, so an estimate never runs low.
var unknownPrice = [2]int64{4_000_000, 20_000_000}

// ModelCost estimates a model call's cost in millionths of a USD.
func ModelCost(model string, prompt, completion int64) int64 {
	p, ok := modelPrices[model]
	if !ok {
		p = unknownPrice
	}
	return (prompt*p[0] + completion*p[1] + 999_999) / 1_000_000
}

// SearchCost is one search provider call (web.search, web.images), in millionths of a USD.
const SearchCost = 50_000

// CompletionReserve is the most a model call reserves for its completion before it runs (less when the budget
// has less left); the guard ends the call if its output passes the reservation, and the model's real count
// replaces the reservation afterwards.
const CompletionReserve = 32768

// MinCompletion is the least a model call needs left to start.
const MinCompletion = 256

// EstimateTokens is a rough upper estimate of a prompt's tokens from its bytes.
func EstimateTokens(bytes int) int64 { return int64(bytes)/3 + 16 }
