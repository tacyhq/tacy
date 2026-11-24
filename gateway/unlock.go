package gateway

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/tacyhq/tacy/kms"
	"github.com/tacyhq/tacy/kms/client"
	"github.com/tacyhq/tacy/kms/split"
	"github.com/tacyhq/tacy/safety"
)

// unlock/v0 (the keys plan §11.2): unlockd has no network. It reaches the split key's holders through gatewayd with
// fixed calls of target "unlock" that name a holder by its id, never a host: gatewayd takes each holder's URLs (its
// url, then its alt_urls, tried in order when one doesn't answer) from the newest unlock policy the chat Worker
// serves (GET /api/vm/unlock-policy at -state-url), which it reads itself and checks against the KMS id the compose
// pins (-kms-key: its share sets must be signed by it), and every URL must be https under one of the compose's
// -unlock-domain domains (comma-separated: our own domains, the no-downtime plan row 2). So a process that took over unlockd
// can't make gatewayd call anywhere the policy doesn't name, and the Worker can't name a host outside our domain.
// The holder URLs aren't signed by the KMS id (the admin key signs the policy, and the VM pins no admin key): a
// wrong URL gets the VM's quote and nonces (public) and no share; each holder checks the admin signatures itself.

// UnlockOp names the protocol of the unlock target's calls (a holder's tacy-split/v1 routes, carried as fixed calls).
const UnlockOp = "unlock/v0"

// The chat Worker's routes unlockd uses through the state target (only unlockd's socket passes them).
const (
	UnlockPolicyPath  = "/api/vm/unlock-policy"  // GET: the newest unlock policy (a kms-unlock-policy envelope)
	UnlockSecretsPath = "/api/vm/unlock-secrets" // GET: the epoch's secrets bundle (ciphertext under a key only R_e derives)
	UnlockReportPath  = "/api/vm/unlock-report"  // POST: unlockd's unlock report (unlock.Report)
	StartTicketPath   = "/api/vm/start-ticket"   // GET: the Worker's start ticket for this start (the policy's start_ticket_keys)
)

var holderIDRe = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)

func validHolderID(s string) bool { return holderIDRe.MatchString(s) }

// UnlockHosts is gatewayd's table of holder URLs, read from the newest unlock policy.
type UnlockHosts struct {
	// Admin are the admin keys the policy must be signed by (-unlock-admin-keys).
	Admin kms.AdminKeys
	KMSID ed25519.PublicKey
	// Domain: every holder URL's host must be one of Domain's comma-separated domains or end in "."+one of them. ""
	// only with AllowHTTP (tests).
	Domain string
	// Fetch gets the unlock policy (gatewayd: a fixed GET of UnlockPolicyPath at the state target).
	Fetch     func(ctx context.Context) ([]byte, error)
	AllowHTTP bool
	// MaxAge: how long a table is used before it is read again (0: 5 min). An unknown holder reads it again at
	// once, at most every MinRefetch (0: 10 s).
	MaxAge, MinRefetch time.Duration
	Now                func() time.Time

	mu    sync.Mutex
	urls  map[string][]string // holder id: its URL, then its alternate URLs
	seq   uint64
	at    time.Time
	tried time.Time
}

// NewUnlockHosts reads holder URLs through f's state target. admin are the compose's -unlock-admin-keys (the policy
// must carry their signatures, as unlockd checks it: review triage #4), domain its -unlock-domain.
func (f *Fixed) NewUnlockHosts(kmsID ed25519.PublicKey, admin kms.AdminKeys, domain string) *UnlockHosts {
	u := &UnlockHosts{KMSID: kmsID, Admin: admin, Domain: strings.TrimPrefix(strings.ToLower(domain), "."), AllowHTTP: f.AllowHTTP}
	u.Fetch = func(ctx context.Context) ([]byte, error) {
		a := f.Fixed(ctx, &FixedCall{Target: TargetState, Method: http.MethodGet, Path: UnlockPolicyPath})
		if a.Error != "" {
			return nil, fmt.Errorf("%w (%s)", ErrUnreachable, a.Error)
		}
		if a.Status != http.StatusOK {
			return nil, fmt.Errorf("unlock policy: HTTP %d", a.Status)
		}
		return a.Body, nil
	}
	f.Unlock = u
	return u
}

func (u *UnlockHosts) now() time.Time {
	if u.Now != nil {
		return u.Now()
	}
	return time.Now()
}

// URL is holder's base URL ("" and an error when the newest policy doesn't name it).
func (u *UnlockHosts) URL(ctx context.Context, holder string) (string, error) {
	l, err := u.URLs(ctx, holder)
	if err != nil {
		return "", err
	}
	return l[0], nil
}

// URLs are holder's base URLs, in the order to try them: the policy's url, then its alt_urls.
func (u *UnlockHosts) URLs(ctx context.Context, holder string) ([]string, error) {
	if !validHolderID(holder) {
		return nil, errors.New("unlock: bad holder id")
	}
	maxAge, minRe := u.MaxAge, u.MinRefetch
	if maxAge == 0 {
		maxAge = 5 * time.Minute
	}
	if minRe == 0 {
		minRe = 10 * time.Second
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	now := u.now()
	_, known := u.urls[holder]
	if (u.urls == nil || now.Sub(u.at) > maxAge || !known) && now.Sub(u.tried) >= minRe {
		u.tried = now
		if err := u.refreshLocked(ctx, now); err != nil && u.urls == nil {
			return nil, err
		}
	}
	v, ok := u.urls[holder]
	if !ok || len(v) == 0 {
		return nil, fmt.Errorf("unlock: the unlock policy names no holder %q", holder)
	}
	return slices.Clone(v), nil
}

func (u *UnlockHosts) refreshLocked(ctx context.Context, now time.Time) error {
	if u.Fetch == nil {
		return errors.New("unlock: no policy source")
	}
	b, err := u.Fetch(ctx)
	if err != nil {
		return err
	}
	urls, seq, err := HolderURLs(b, u.KMSID, u.Admin, u.Domain, u.AllowHTTP)
	if err != nil {
		return err
	}
	if seq < u.seq { // never back to an older policy's holders
		return fmt.Errorf("unlock: policy seq %d is older than %d", seq, u.seq)
	}
	u.urls, u.seq, u.at = urls, seq, now
	return nil
}

// HolderURLs reads an unlock policy's holder URLs: the envelope of kind kms-unlock-policy signed by admin, for kmsID
// (its share sets signed by it), every URL (a holder's url and its alt_urls) https (or http with allowHTTP), without
// user, query or fragment, on one of domain's comma-separated domains or under it, and every holder of a share set
// listed. Each holder's list is its url first, then its alt_urls in order. It returns the policy's seq too. An
// unsigned policy (from a Worker that isn't ours) names no holder, and its seq never blocks a later refresh.
func HolderURLs(raw []byte, kmsID ed25519.PublicKey, admin kms.AdminKeys, domain string, allowHTTP bool) (map[string][]string, uint64, error) {
	var env safety.Envelope
	if err := kms.Strict(raw, &env); err != nil || env.Kind != split.KindUnlockPolicy {
		return nil, 0, errors.New("unlock: not an unlock policy envelope")
	}
	var pol split.UnlockPolicy
	if err := admin.Open(&env, split.KindUnlockPolicy, &pol); err != nil {
		return nil, 0, fmt.Errorf("unlock: policy: %w", err)
	}
	if err := pol.Validate(); err != nil {
		return nil, 0, err
	}
	if pol.KMSID != kms.IDString(kmsID) {
		return nil, 0, errors.New("unlock: the policy is for another KMS id")
	}
	sets, err := pol.OpenShareSets(kmsID)
	if err != nil {
		return nil, 0, err
	}
	domains := unlockDomains(domain)
	urls := map[string][]string{}
	add := func(id, raw string) error {
		p, err := url.Parse(raw)
		if err != nil || p.Host == "" || p.User != nil || p.RawQuery != "" || p.Fragment != "" ||
			(p.Scheme != "https" && !(allowHTTP && p.Scheme == "http")) {
			return fmt.Errorf("unlock: %s's URL isn't an https base URL", id)
		}
		h := strings.ToLower(p.Hostname())
		if len(domains) > 0 && !slices.ContainsFunc(domains, func(d string) bool { return h == d || strings.HasSuffix(h, "."+d) }) {
			return fmt.Errorf("unlock: %s's host %s isn't under %s", id, h, strings.Join(domains, ", "))
		}
		if len(domains) == 0 && !allowHTTP {
			return errors.New("unlock: no holder domain pinned")
		}
		urls[id] = append(urls[id], strings.TrimSuffix(raw, "/"))
		return nil
	}
	for _, h := range pol.Holders {
		for _, u := range append([]string{h.URL}, h.AltURLs...) {
			if err := add(h.Holder, u); err != nil {
				return nil, 0, err
			}
		}
	}
	if pol.BreakGlass != "" {
		if err := add(split.BreakGlassHolder, pol.BreakGlass); err != nil {
			return nil, 0, err
		}
	}
	for _, s := range sets {
		for _, h := range s.Holders {
			if _, ok := urls[h.Holder]; !ok {
				return nil, 0, fmt.Errorf("unlock: share set %d's holder %s has no URL", s.Set, h.Holder)
			}
		}
	}
	return urls, pol.Seq, nil
}

// unlockDomains is -unlock-domain as a list: comma-separated, lower case, without a leading dot, no empty ones.
func unlockDomains(s string) []string {
	var out []string
	for _, d := range strings.Split(strings.ToLower(s), ",") {
		if d = strings.TrimPrefix(strings.TrimSpace(d), "."); d != "" {
			out = append(out, d)
		}
	}
	return out
}

// UnlockTransport is split.Unlock's transport to one holder over fixed calls (unlockd: gatewayd's unlock socket).
type UnlockTransport struct {
	D      FixedDoer
	Holder string
}

// Do implements client.Transport.
func (t UnlockTransport) Do(ctx context.Context, method, path string, body []byte) ([]byte, error) {
	call := &FixedCall{Target: TargetUnlock, Holder: t.Holder, Method: method, Path: path, Body: body}
	if body != nil {
		call.Header = map[string]string{"Content-Type": "application/json"}
	}
	a := t.D.Fixed(ctx, call)
	if a.Error != "" {
		return nil, fmt.Errorf("%w (%s)", ErrUnreachable, a.Error)
	}
	if a.Status != http.StatusOK {
		var e struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(a.Body, &e) != nil || e.Error == "" {
			e.Error = http.StatusText(a.Status)
		}
		return nil, &client.RefusedError{Status: a.Status, Reason: e.Error}
	}
	return a.Body, nil
}

// FixedGate holds one socket's process to the fixed calls it may make (Allow); others answer "bad_call".
type FixedGate struct {
	D     FixedDoer
	Allow func(*FixedCall) bool
}

// Fixed implements FixedDoer.
func (g FixedGate) Fixed(ctx context.Context, call *FixedCall) *FixedAnswer {
	if call == nil || g.Allow == nil || !g.Allow(call) {
		return &FixedAnswer{Error: "bad_call"}
	}
	return g.D.Fixed(ctx, call)
}

func statePath(c *FixedCall) string { p, _, _ := strings.Cut(c.Path, "?"); return p }

// AgentCalls: agentd's socket: its sealed state, its schedule ownership rows and its state's writer lease at the
// Worker, and the Google Cloud hints (gce.go). Never a holder, never the unlock routes, never the key service.
func AgentCalls(c *FixedCall) bool {
	p := statePath(c)
	return c.Target == TargetGCE || c.Target == TargetState && (stateName.MatchString(p) || ownerName.MatchString(p) || leaseName.MatchString(p))
}

// VaultCalls: vaultd's ops socket: its sealed connections at the Worker.
func VaultCalls(c *FixedCall) bool {
	return c.Target == TargetState && stateName.MatchString(statePath(c))
}

// UnlockCalls: unlockd's socket: the holders, the Worker's unlock routes (policy, secrets.sealed, report) and the
// Google Cloud hints (gce.go). Never anyone's sealed state.
func UnlockCalls(c *FixedCall) bool {
	if c.Target == TargetUnlock || c.Target == TargetGCE {
		return true
	}
	_, ok := unlockState[statePath(c)]
	return c.Target == TargetState && ok
}
