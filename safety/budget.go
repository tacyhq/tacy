package safety

import (
	"encoding/json/v2"
	"os"
	"path/filepath"
	"strings"
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
	space, member  string
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

// Ledger keeps the budgets (keys v2 spaces and identities): per run in memory, and per UTC day on the encrypted
// disk (counts only) for each space, each member (all spaces together) and the whole VM. A request reserves what
// it may use from all four before it runs, under one lock, so parallel requests can't each see room that only one of
// them has; the reservation is replaced by what was actually used when it ends. A member is whoever the run's
// budget is counted for (proto.Verified.Member): a firm's identity, or on the shared chat VM the relay's daily
// per-user tag. Making a new space gets nothing: the member's and the VM's days are the same whatever the space.
type Ledger struct {
	Dir string // where the day counters persist; "": memory only
	Now func() time.Time

	mu   sync.Mutex
	runs map[string]*ledgerRun
	days map[string]*ledgerDay // "<space>|YYYY-MM-DD", "m:<member>|YYYY-MM-DD", "vm|YYYY-MM-DD"
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

// A day's scope: one space ("<space>"), one member ("m:<member>") or the VM ("vm"). Space ids start with a letter
// and hold an underscore, so the three never meet.
const vmScope = "vm"

func memberScope(member string) string { return "m:" + member }

func (l *Ledger) day(scope string) *ledgerDay {
	k := scope + "|" + l.Now().UTC().Format(time.DateOnly)
	d := l.days[k]
	if d == nil {
		d = &ledgerDay{}
		l.days[k] = d
	}
	return d
}

// inScope: a run counts in a day's scope.
func (r *ledgerRun) inScope(scope string) bool {
	return scope == vmScope || scope == r.space || scope == memberScope(r.member)
}

// dayWall is a scope's running time today: finished runs plus the ones running now (time waiting for a person
// left out, as for a run).
func (l *Ledger) dayWall(scope string, d *ledgerDay) time.Duration {
	w := time.Duration(d.Used.WallMs) * time.Millisecond
	now := l.Now()
	for _, r := range l.runs {
		if r.inScope(scope) {
			w += r.elapsed(now)
		}
	}
	return w
}

// dayLimit is one day budget a run counts against.
type dayLimit struct {
	scope, name string // name: whose day, in the refusal ("the space's daily budget …")
	lim         Limits
	d           *ledgerDay
}

// daysOf are the day budgets a run in space for member counts against: the space's, the member's and the VM's.
func (l *Ledger) daysOf(space, member string, b Budgets) []dayLimit {
	return []dayLimit{
		{space, "daily", b.Day, l.day(space)},
		{memberScope(member), "member's daily", b.Member, l.day(memberScope(member))},
		{vmScope, "agent VM's daily", b.VM, l.day(vmScope)},
	}
}

func budgetError(scope, what string) error {
	return errorf(CodeBudgetExceeded, "the %s budget for %s is used up", scope, what)
}

// Start registers a run in space for member (Admit, then Begin).
func (l *Ledger) Start(task, space, member string, b Budgets) (time.Time, error) {
	if _, err := l.Admit(space, member, b); err != nil {
		return time.Time{}, err
	}
	l.Begin(task, space, member)
	return l.Admit(space, member, b, task)
}

// Begin registers a run in space for member from now (again: a no-op).
func (l *Ledger) Begin(task, space, member string) {
	l.init()
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.runs[task] == nil {
		l.runs[task] = &ledgerRun{space: space, member: member, start: l.Now()}
	}
}

// Resume registers a run that was begun before a restart (a task taken up again): it started at start and has
// used what used says, so its run budget and running time go on from there instead of starting over. Time it
// waited for its person before the restart isn't known here, so it counts as running time: a restart can only
// shorten a run, never lengthen it. A run already registered is left as it is.
func (l *Ledger) Resume(task, space, member string, start time.Time, used Usage) {
	l.init()
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.runs[task] == nil {
		if start.IsZero() || start.After(l.Now()) {
			start = l.Now()
		}
		l.runs[task] = &ledgerRun{space: space, member: member, start: start, used: used}
	}
}

// Admit refuses a new run when the space's, the member's or the VM's day budget is already used up, and returns the
// latest a run may go on (zero: no limit), from the days' running time. task, when given, is a run already begun.
// The run's own running time isn't a fixed end: time waiting for the person doesn't count (Pause), so Elapsed is
// checked as it goes (Reserve, and the caller's timer). The day's end is computed as if nothing paused: never later
// than it should be.
func (l *Ledger) Admit(space, member string, b Budgets, task ...string) (time.Time, error) {
	l.init()
	l.mu.Lock()
	defer l.mu.Unlock()
	var end time.Time
	for _, dl := range l.daysOf(space, member, b) {
		held := dl.d.Used
		held.add(dl.d.reserved, 1)
		wall := l.dayWall(dl.scope, dl.d)
		// A run needs at least a token of model budget; used-up tool calls only refuse its tool calls.
		if what := over(dl.lim, held, Usage{Tokens: 1, CostMicros: 1}, wall); what != "" {
			return time.Time{}, budgetError(dl.name, what)
		}
		if dl.lim.WallSeconds > 0 {
			if e := l.Now().Add(time.Duration(dl.lim.WallSeconds)*time.Second - wall); end.IsZero() || e.Before(end) {
				end = e
			}
		}
	}
	return end, nil
}

var errUnknownRun = errorf(CodeBudgetExceeded, "the run has no budget (not started here)")

// Reserve takes want from the run's and its days' budgets b (the current policy's), or refuses with the limit it
// would pass. commit replaces the reservation with what was used (call it exactly once).
func (l *Ledger) Reserve(task string, want Usage, b Budgets) (commit func(used Usage), err error) {
	l.init()
	l.mu.Lock()
	defer l.mu.Unlock()
	r := l.runs[task]
	if r == nil {
		return nil, errUnknownRun
	}
	held := r.used
	held.add(r.reserved, 1)
	if what := over(b.Run, held, want, r.elapsed(l.Now())); what != "" {
		return nil, budgetError("run's", what)
	}
	days := l.daysOf(r.space, r.member, b)
	for _, dl := range days {
		held = dl.d.Used
		held.add(dl.d.reserved, 1)
		if what := over(dl.lim, held, want, l.dayWall(dl.scope, dl.d)); what != "" {
			return nil, budgetError(dl.name, what)
		}
	}
	r.reserved.add(want, 1)
	for _, dl := range days {
		dl.d.reserved.add(want, 1)
	}
	r.inflight++ // working: the clock runs while the request does, even with a prompt open
	r.clock(l.Now())
	var once sync.Once
	return func(used Usage) {
		once.Do(func() {
			l.mu.Lock()
			defer l.mu.Unlock()
			r.reserved.add(want, -1)
			r.used.add(used, 1)
			for _, dl := range days {
				dl.d.reserved.add(want, -1)
				dl.d.Used.add(used, 1)
			}
			r.inflight--
			r.clock(l.Now())
			l.save()
		})
	}, nil
}

// TokensLeft is how many model tokens the run may still reserve: the least of the run's and its days' token
// budgets left after what is used and reserved (-1: no token limit; 0 for a run it doesn't know).
func (l *Ledger) TokensLeft(task string, b Budgets) int64 {
	l.init()
	l.mu.Lock()
	defer l.mu.Unlock()
	r := l.runs[task]
	if r == nil {
		return 0
	}
	type tc struct{ lim, used, res int64 }
	cs := []tc{{b.Run.Tokens, r.used.Tokens, r.reserved.Tokens}}
	for _, dl := range l.daysOf(r.space, r.member, b) {
		cs = append(cs, tc{dl.lim.Tokens, dl.d.Used.Tokens, dl.d.reserved.Tokens})
	}
	left := int64(-1)
	for _, c := range cs {
		if c.lim > 0 {
			if v := max(0, c.lim-c.used-c.res); left < 0 || v < left {
				left = v
			}
		}
	}
	return left
}

// CostLeft is how much estimated cost (micro-USD) the run may still reserve: the least of the run's and its days'
// cost budgets left after what is used and reserved (-1: no cost limit; 0 for a run it doesn't know).
func (l *Ledger) CostLeft(task string, b Budgets) int64 {
	l.init()
	l.mu.Lock()
	defer l.mu.Unlock()
	r := l.runs[task]
	if r == nil {
		return 0
	}
	left := int64(-1)
	take := func(lim, used, res int64) {
		if lim > 0 {
			if v := max(0, lim-used-res); left < 0 || v < left {
				left = v
			}
		}
	}
	take(b.Run.CostMicros, r.used.CostMicros, r.reserved.CostMicros)
	for _, dl := range l.daysOf(r.space, r.member, b) {
		take(dl.lim.CostMicros, dl.d.Used.CostMicros, dl.d.reserved.CostMicros)
	}
	return left
}

// CompletionFor is the most completion tokens a call to model with a prompt of prompt tokens can have for cost
// micro-USD (0 when the prompt alone costs more).
func CompletionFor(model string, prompt, cost int64) int64 {
	p, ok := modelPrices[model]
	if !ok {
		p = unknownPrice
	}
	left := cost*1_000_000 - prompt*p[0] // then ModelCost(model, prompt, left/p[1]) <= cost, its rounding included
	if left <= 0 || p[1] <= 0 {
		return 0
	}
	return left / p[1]
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

// End adds the run's time to its days (space, member, VM) and forgets it.
func (l *Ledger) End(task string) {
	l.init()
	l.mu.Lock()
	defer l.mu.Unlock()
	r := l.runs[task]
	if r == nil {
		return
	}
	delete(l.runs, task)
	ms := r.elapsed(l.Now()).Milliseconds()
	for _, scope := range []string{r.space, memberScope(r.member), vmScope} {
		l.day(scope).Used.WallMs += ms
	}
	l.save()
}

// MembersCost is the cost (micro-USD) that every member whose name starts with prefix used today and yesterday (UTC),
// all together, by day: one number a day, never a member, run or time. Scheduled runs' members are "schedule:<agent>"
// (guard.ScheduleMember), so MembersCost("schedule:") is what the VM's own schedules spent, which no relay charged:
// the relay's hourly cron adds it to its daily totals (agentd's GET /tasks/open).
func (l *Ledger) MembersCost(prefix string) map[string]int64 {
	l.init()
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.Now().UTC()
	out := map[string]int64{now.Format(time.DateOnly): 0, now.Add(-24 * time.Hour).Format(time.DateOnly): 0}
	for k, d := range l.days {
		scope, day, ok := strings.Cut(k, "|")
		if _, want := out[day]; ok && want && strings.HasPrefix(scope, memberScope(prefix)) {
			out[day] += d.Used.CostMicros
		}
	}
	return out
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

// PriceRank orders models by price: input plus output price per million tokens (a model without a price ranks as the
// dearest). The relay charges a run at the dearest model it may call (X-Agent-Price-Model, which agentd checks
// against the run's signed fallback list); the chat ranks them the same way (the chat's plans.ts dearestModel; a unit
// test there compares this table with prices.ts).
func PriceRank(model string) int64 {
	p, ok := modelPrices[model]
	if !ok {
		p = unknownPrice
	}
	return p[0] + p[1]
}

// PricePerM is model's input and output price in millionths of a USD per million tokens (an unknown model: the
// dearest).
func PricePerM(model string) (input, output int64) {
	p, ok := modelPrices[model]
	if !ok {
		p = unknownPrice
	}
	return p[0], p[1]
}

// ModelCost estimates a model call's cost in millionths of a USD.
func ModelCost(model string, prompt, completion int64) int64 {
	p, ok := modelPrices[model]
	if !ok {
		p = unknownPrice
	}
	return (prompt*p[0] + completion*p[1] + 999_999) / 1_000_000
}

// SearchCost is one search provider call (web.search, web.images), in millionths of a USD: about what the providers
// charge, rounded up (Exa $0.007, Tavily ~$0.008 a basic search, Brave $0.005; checked 2026-10-18). It was $0.05,
// which made a_research's $1 budget bind after about 16 searches.
const SearchCost = 10_000

// CompletionReserve is the most a model call reserves for its completion before it runs (less when the budget
// has less left); the guard ends the call if its output passes the reservation, and the model's real count
// replaces the reservation afterwards.
const CompletionReserve = 32768

// MinCompletion is the least a model call needs left to start.
const MinCompletion = 256

// EstimateTokens is a rough upper estimate of a prompt's tokens from its bytes.
func EstimateTokens(bytes int) int64 { return int64(bytes)/3 + 16 }
