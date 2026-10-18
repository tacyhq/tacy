package safety

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"
)

// PolicyType names this policy format.
const PolicyType = "tacy.policy/v1"

// Policy is a firm's (Space "") or one space's signed rules. It can only narrow: the effective policy for a space
// is the release's ceiling, the firm's policy and the space's policy all at once (Effective), so a signed policy
// can never allow what the release doesn't.
type Policy struct {
	Type     string    `json:"type"`
	Firm     string    `json:"firm"`
	Space    string    `json:"space,omitzero"` // "": the whole firm
	Version  uint64    `json:"version"`        // only ever goes up for a firm or space (rollback refused)
	IssuedAt time.Time `json:"issued_at"`
	// Models the tasks may use.
	Models []string `json:"models"`
	// Connectors allowed, by name ("model", "web"); a connector not listed is off, with all its tools.
	Connectors map[string]Connector `json:"connectors"`
	// Approve names actions that need a person's approval. Approvals aren't built yet, so listed
	// actions are refused.
	Approve []string `json:"approve,omitzero"`
	// StaleReads: when the stop list is stale, reads (model calls, searches, fetches) may go on. Side effects
	// always stop.
	StaleReads bool    `json:"stale_reads"`
	Budget     Budgets `json:"budget"`
	Rates      Rates   `json:"rates"`
	// AskCap caps people's permission settings per kind of outgoing data ("web.search" -> "ask" | "never"; or
	// "always", which caps nothing). A person's setting above the cap is lowered to it: a firm can make its members
	// be asked every time, or turn a kind off. Unnamed kinds aren't capped.
	AskCap map[string]string `json:"ask_cap,omitzero"`
}

// Permission settings, from the most open to the narrowest.
const (
	PermAlways = "always"
	PermAsk    = "ask"
	PermNever  = "never"
)

// permRank orders the settings: a higher rank is narrower.
var permRank = map[string]int{PermAlways: 0, PermAsk: 1, PermNever: 2}

// ValidPermission: one of always, ask, never.
func ValidPermission(s string) bool { _, ok := permRank[s]; return ok }

// NarrowerPermission is the narrower of two settings ("" counts as always: no limit).
func NarrowerPermission(a, b string) string {
	if a == "" {
		a = PermAlways
	}
	if b == "" {
		b = PermAlways
	}
	if permRank[b] > permRank[a] {
		return b
	}
	return a
}

// Connector is one connector's grant.
type Connector struct {
	Tools []string `json:"tools,omitzero"` // its actions the tasks may use ("web.search")
	Hosts []string `json:"hosts"`          // exact hosts its leased keys may go to
	// Fetch (web only): where page, image and site icon fetches may go: exact hosts, "*.example.com" (subdomains
	// only), or "*" for any public host.
	Fetch []string `json:"fetch,omitzero"`
}

// Budgets: per run (task) and per space per UTC day. Zero fields add no limit of their own.
type Budgets struct {
	Run Limits `json:"run"`
	Day Limits `json:"day"`
}

// Limits of one budget.
type Limits struct {
	Tokens      int64 `json:"tokens,omitzero"`          // model tokens, prompt and completion
	ToolCalls   int64 `json:"tool_calls,omitzero"`      // actions
	WallSeconds int64 `json:"wall_seconds,omitzero"`    // running time
	CostMicros  int64 `json:"cost_usd_micros,omitzero"` // estimated cost, millionths of a USD
}

// Rates are the vault's lease rates: per key (secret), per connector and per space. Zero: no limit of its own.
type Rates struct {
	Key       Rate `json:"key"`
	Connector Rate `json:"connector"`
	Space     Rate `json:"space"`
}

// Rate is a token bucket: PerMinute refill, Burst capacity.
type Rate struct {
	PerMinute int `json:"per_minute,omitzero"`
	Burst     int `json:"burst,omitzero"`
}

var (
	idRe     = regexp.MustCompile(`^[a-z][a-z0-9]*_[A-Za-z0-9_-]{1,60}\z`)
	actionRe = regexp.MustCompile(`^[a-z][a-z0-9]{0,31}\.[a-z][a-z0-9_.]{0,63}\z`)
	connRe   = regexp.MustCompile(`^[a-z][a-z0-9]{0,31}\z`)
	modelRe  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]{0,63}\z`)
)

// ValidID: firm and space ids ("f_…", "s_…").
func ValidID(s string) bool { return idRe.MatchString(s) }

func validHost(s string) bool {
	if len(s) < 3 || len(s) > 253 || !strings.Contains(s, ".") || strings.HasPrefix(s, ".") || strings.HasSuffix(s, ".") ||
		strings.Contains(s, "..") {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '.') {
			return false
		}
	}
	return true
}

func validPattern(s string) bool {
	if s == "*" {
		return true
	}
	return validHost(strings.TrimPrefix(s, "*."))
}

// Validate checks a policy's shape.
func (p *Policy) Validate() error {
	switch {
	case p.Type != PolicyType:
		return errors.New("policy: type must be " + PolicyType)
	case !ValidID(p.Firm) || p.Space != "" && !ValidID(p.Space):
		return errors.New("policy: bad firm or space id")
	case p.Version == 0:
		return errors.New("policy: version must be at least 1")
	case p.IssuedAt.IsZero():
		return errors.New("policy: issued_at is required")
	case len(p.Models) > 32 || len(p.Connectors) > 32 || len(p.Approve) > 64:
		return errors.New("policy: too many entries")
	}
	for _, m := range p.Models {
		if !modelRe.MatchString(m) {
			return fmt.Errorf("policy: bad model %q", m)
		}
	}
	for name, c := range p.Connectors {
		if !connRe.MatchString(name) || len(c.Tools) > 64 || len(c.Hosts) > 64 || len(c.Fetch) > 256 {
			return fmt.Errorf("policy: bad connector %q", name)
		}
		for _, t := range c.Tools {
			if !actionRe.MatchString(t) || !strings.HasPrefix(t, name+".") {
				return fmt.Errorf("policy: tool %q isn't connector %s's", t, name)
			}
		}
		for _, h := range c.Hosts {
			if !validHost(h) {
				return fmt.Errorf("policy: bad host %q", h)
			}
		}
		for _, h := range c.Fetch {
			if !validPattern(h) {
				return fmt.Errorf("policy: bad fetch pattern %q", h)
			}
		}
	}
	for _, a := range p.Approve {
		if !actionRe.MatchString(a) {
			return fmt.Errorf("policy: bad action %q", a)
		}
	}
	if len(p.AskCap) > 64 {
		return errors.New("policy: too many entries")
	}
	for k, v := range p.AskCap {
		if !actionRe.MatchString(k) || !ValidPermission(v) {
			return fmt.Errorf("policy: bad ask_cap %q: %q", k, v)
		}
	}
	for _, l := range []Limits{p.Budget.Run, p.Budget.Day} {
		if l.Tokens < 0 || l.ToolCalls < 0 || l.WallSeconds < 0 || l.CostMicros < 0 {
			return errors.New("policy: negative budget")
		}
	}
	for _, r := range []Rate{p.Rates.Key, p.Rates.Connector, p.Rates.Space} {
		if r.PerMinute < 0 || r.Burst < 0 || r.PerMinute > 0 && r.Burst == 0 {
			return errors.New("policy: a rate needs per_minute and burst")
		}
	}
	return nil
}

// Effective is the policy a space runs under: every layer must allow a thing (release ceiling, firm, space).
type Effective struct {
	Layers []*Policy // the release's first; never empty
	Hashes []string  // the signed layers' hashes (firm first), for records and the browser
}

func (e *Effective) all(f func(*Policy) bool) bool {
	for _, p := range e.Layers {
		if !f(p) {
			return false
		}
	}
	return true
}

// AllowsModel: every layer lists the model.
func (e *Effective) AllowsModel(m string) bool {
	return e.all(func(p *Policy) bool { return slices.Contains(p.Models, m) })
}

// AllowsTool: the action's connector is on and every layer lists the action, and no layer holds it for approval
// (approvals aren't built: held means refused).
func (e *Effective) AllowsTool(action string) bool {
	conn, _, _ := strings.Cut(action, ".")
	return !e.NeedsApproval(action) && e.all(func(p *Policy) bool {
		c, ok := p.Connectors[conn]
		return ok && slices.Contains(c.Tools, action)
	})
}

// AllowsConnector: every layer has the connector.
func (e *Effective) AllowsConnector(conn string) bool {
	return e.all(func(p *Policy) bool { _, ok := p.Connectors[conn]; return ok })
}

// PermissionCap is the narrowest cap any layer puts on a kind's permission setting: always (no cap), ask or
// never.
func (e *Effective) PermissionCap(kind string) string {
	c := PermAlways
	for _, p := range e.Layers {
		c = NarrowerPermission(c, p.AskCap[kind])
	}
	return c
}

// NeedsApproval: some layer lists the action.
func (e *Effective) NeedsApproval(action string) bool {
	return !e.all(func(p *Policy) bool { return !slices.Contains(p.Approve, action) })
}

// AllowsLeaseHost: every layer lists host for the connector's keys.
func (e *Effective) AllowsLeaseHost(conn, host string) bool {
	return e.all(func(p *Policy) bool { c, ok := p.Connectors[conn]; return ok && slices.Contains(c.Hosts, host) })
}

// AllowsFetch: every layer's web fetch patterns match host.
func (e *Effective) AllowsFetch(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	return e.all(func(p *Policy) bool {
		c, ok := p.Connectors["web"]
		if !ok {
			return false
		}
		for _, pat := range c.Fetch {
			if pat == "*" || pat == host || strings.HasPrefix(pat, "*.") && strings.HasSuffix(host, pat[1:]) {
				return true
			}
		}
		return false
	})
}

// StaleReads: every layer lets reads go on when the stop list is stale.
func (e *Effective) StaleReads() bool { return e.all(func(p *Policy) bool { return p.StaleReads }) }

func minPos(a, b int64) int64 {
	switch {
	case a <= 0:
		return b
	case b <= 0:
		return a
	}
	return min(a, b)
}

func minLimits(a, b Limits) Limits {
	return Limits{minPos(a.Tokens, b.Tokens), minPos(a.ToolCalls, b.ToolCalls), minPos(a.WallSeconds, b.WallSeconds),
		minPos(a.CostMicros, b.CostMicros)}
}

// Budget is the tightest of every layer's budgets.
func (e *Effective) Budget() Budgets {
	var b Budgets
	for _, p := range e.Layers {
		b.Run, b.Day = minLimits(b.Run, p.Budget.Run), minLimits(b.Day, p.Budget.Day)
	}
	return b
}

func minRate(a, b Rate) Rate {
	switch {
	case a.PerMinute <= 0:
		return b
	case b.PerMinute <= 0:
		return a
	}
	return Rate{min(a.PerMinute, b.PerMinute), min(a.Burst, b.Burst)}
}

// Rates is the tightest of every layer's rates.
func (e *Effective) Rates() Rates {
	var r Rates
	for _, p := range e.Layers {
		r.Key, r.Connector, r.Space = minRate(r.Key, p.Rates.Key), minRate(r.Connector, p.Rates.Connector), minRate(r.Space, p.Rates.Space)
	}
	return r
}

// Tools filters actions to the ones the policy allows, in order.
func (e *Effective) Tools(actions []string) []string {
	var out []string
	for _, a := range actions {
		if e.AllowsTool(a) {
			out = append(out, a)
		}
	}
	return out
}
