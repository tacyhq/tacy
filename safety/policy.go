package safety

import (
	"bytes"
	"encoding/base64"
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
	// Approve names actions that need a person's approval before each one runs (docs/27 section 4). Sends always
	// need one whatever this says; a policy can add approvals, never remove them. A release without approvals
	// refuses listed actions.
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
	// Seal is the space's seal public key ("x25519:<base64>"; space policies only, keys v2 spaces and identities): a run in the
	// space must prove it holds the private half (runauth), and its activity records are sealed to it. A space key
	// rotation makes a new seal key, so the space's holders sign a new policy naming it. On a firm's VM (not the
	// shared chat VM) a space can't run without a signed policy naming its seal key.
	Seal string `json:"seal,omitzero"`
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

// Budgets: per run (task), per space per UTC day, per member per UTC day (all the member's spaces together) and for
// the whole VM per UTC day. Zero fields add no limit of their own. A member is a firm's identity, or on the shared chat
// VM the relay's daily per-user tag (proto.Verified.Member).
type Budgets struct {
	Run    Limits `json:"run"`
	Day    Limits `json:"day"`
	Member Limits `json:"member,omitzero"`
	VM     Limits `json:"vm,omitzero"`
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

// validSeal: "x25519:<base64 of 32 bytes>" in its one canonical spelling, not all zero.
func validSeal(s string) bool {
	raw, ok := strings.CutPrefix(s, "x25519:")
	b, err := base64.StdEncoding.Strict().DecodeString(raw)
	return ok && err == nil && len(b) == 32 && base64.StdEncoding.EncodeToString(b) == raw && !bytes.Equal(b, make([]byte, 32))
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
	case p.Seal != "" && p.Space == "":
		return errors.New("policy: only a space's policy names a seal key")
	case p.Seal != "" && !validSeal(p.Seal):
		return errors.New("policy: bad seal key")
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
	for _, l := range []Limits{p.Budget.Run, p.Budget.Day, p.Budget.Member, p.Budget.VM} {
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
// (an action a layer holds for approval runs only with a person's approval: AllowsToolApproved).
func (e *Effective) AllowsTool(action string) bool {
	conn, _, _ := strings.Cut(action, ".")
	return !e.NeedsApproval(action) && e.all(func(p *Policy) bool {
		c, ok := p.Connectors[conn]
		return ok && slices.Contains(c.Tools, action)
	})
}

// AllowsToolApproved: the action's connector is on and every layer lists the action, whatever the layers' approve
// lists say: for an action that carries a person's verified approval (docs/27 section 4).
func (e *Effective) AllowsToolApproved(action string) bool {
	conn, _, _ := strings.Cut(action, ".")
	return e.all(func(p *Policy) bool {
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
func (e *Effective) AllowsFetch(host string) bool { return e.AllowsConnectorFetch("web", host) }

// AllowsConnectorFetch: every layer's fetch patterns for the connector match host (the files connector's: where the
// person's stored files are read from, files.fetch).
func (e *Effective) AllowsConnectorFetch(conn, host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	return e.all(func(p *Policy) bool {
		c, ok := p.Connectors[conn]
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
		b.Member, b.VM = minLimits(b.Member, p.Budget.Member), minLimits(b.VM, p.Budget.VM)
	}
	return b
}

// NarrowRun is b with its run budget narrowed to l as well (a built-in agent's own run budget: the policy can lower
// it, never raise it).
func (b Budgets) NarrowRun(l Limits) Budgets {
	b.Run = minLimits(b.Run, l)
	return b
}

// Seal is the seal key the space's own signed policy names ("": none).
func (e *Effective) Seal() string {
	for _, p := range e.Layers {
		if p.Space != "" && p.Seal != "" {
			return p.Seal
		}
	}
	return ""
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

// Widens says whether p allows anything old doesn't (docs/23: on a firm with two or more key admins, a
// policy that widens the one in force needs two admin signatures). Conservative: anything that might allow more
// counts (a fetch pattern old doesn't list word for word, unless old allows any host; an approval dropped; reads
// while stale turned on; a budget or rate raised or removed).
func Widens(old, p *Policy) bool {
	for _, m := range p.Models {
		if !slices.Contains(old.Models, m) {
			return true
		}
	}
	for name, c := range p.Connectors {
		o, ok := old.Connectors[name]
		if !ok {
			return true
		}
		for _, t := range c.Tools {
			if !slices.Contains(o.Tools, t) {
				return true
			}
		}
		for _, h := range c.Hosts {
			if !slices.Contains(o.Hosts, h) {
				return true
			}
		}
		for _, f := range c.Fetch {
			if !slices.Contains(o.Fetch, f) && !slices.Contains(o.Fetch, "*") {
				return true
			}
		}
	}
	for _, a := range old.Approve {
		if !slices.Contains(p.Approve, a) {
			return true
		}
	}
	if p.StaleReads && !old.StaleReads {
		return true
	}
	looser := func(o, n int64) bool { return o > 0 && (n <= 0 || n > o) }
	for _, l := range [][2]Limits{{old.Budget.Run, p.Budget.Run}, {old.Budget.Day, p.Budget.Day}, {old.Budget.Member, p.Budget.Member}, {old.Budget.VM, p.Budget.VM}} {
		o, n := l[0], l[1]
		if looser(o.Tokens, n.Tokens) || looser(o.ToolCalls, n.ToolCalls) || looser(o.WallSeconds, n.WallSeconds) || looser(o.CostMicros, n.CostMicros) {
			return true
		}
	}
	for _, r := range [][2]Rate{{old.Rates.Key, p.Rates.Key}, {old.Rates.Connector, p.Rates.Connector}, {old.Rates.Space, p.Rates.Space}} {
		o, n := r[0], r[1]
		if looser(int64(o.PerMinute), int64(n.PerMinute)) || o.PerMinute > 0 && n.PerMinute > 0 && n.Burst > o.Burst {
			return true
		}
	}
	return false
}
