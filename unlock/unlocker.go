package unlock

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/rand/v2"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/tacyhq/tacy/gateway"
	"github.com/tacyhq/tacy/kms"
	"github.com/tacyhq/tacy/kms/client"
	"github.com/tacyhq/tacy/kms/split"
)

// States, as every socket answers them and the unlock report carries them.
const (
	StateStarting   = "starting"    // unlocking; no failure yet (or the Worker didn't answer)
	StateHolderDown = "holder_down" // fewer than the threshold of holders answered: "a key holder is down"
	StateRefused    = "refused"     // holders answered and refused (a release not in the policy, a policy too old)
	StateReady      = "ready"
)

// Status is unlockd's state, for its sockets and the unlock report. Never key material.
type Status struct {
	State   string            `json:"state"`
	Reason  string            `json:"reason,omitempty"`
	Holders map[string]string `json:"holders,omitempty"` // each holder's outcome in the last attempt
	Tries   int               `json:"tries"`
	Since   time.Time         `json:"since"`
	// Cached: this boot's keyring came from the host tmpfs (a container restart), not from the holders.
	Cached bool `json:"cached,omitempty"`
}

// Message is what people see for a state (the chat shows it; the no-downtime plan principle 7).
func Message(state string) string {
	switch state {
	case StateReady:
		return ""
	case StateHolderDown:
		return "Agents are starting: a key holder is down. Plain chat still works."
	case StateRefused:
		return "Agents are paused: this server's release isn't approved for keys. Plain chat still works."
	default:
		return "Agents are starting."
	}
}

// Config is unlockd's setup.
type Config struct {
	KMSID ed25519.PublicKey // the compose's -kms-key
	// Admin are the admin keys the compose pins (-unlock-admin-keys): the policy must carry their
	// signatures. MinEpoch is the lowest epoch the VM takes (-min-epoch; raised by the release after a re-split).
	// Both required, except with a DevRoot.
	Admin    *kms.AdminKeys
	MinEpoch uint32
	// Fixed reaches the holders and the Worker's unlock routes (gatewayd's unlock socket).
	Fixed    gateway.FixedDoer
	Evidence client.Evidence
	Platform string // "dstack"; "local" only with DevRoot
	Release  string // this VM's release (vX.Y.Z), a claim the holders check
	// Cache keeps the keyring across container restarts (nil: none, every start unlocks).
	Cache *Cache
	// RequireMemoryRoot: refuse to unlock unless the memory-root pre-launch script ran this boot (the CVM).
	RequireMemoryRoot bool
	// DevRoot (platform local only): the root key without holders (a development VM: nothing attested).
	DevRoot func() (Root, Grant, error)
	// SecretsWait: how long the root is kept after an unlock while the epoch's secrets bundle can't be fetched
	// (0: 2 min). Then it is dropped; vaultd waits and the next try unlocks again (agentd is served meanwhile).
	SecretsWait time.Duration
	// Relock: how often an unlock without its API keys is tried again (0: 5 min).
	Relock time.Duration
	// Backoff between tries: from MinBackoff (0: 2 s) doubling to MaxBackoff (0: 60 s), with jitter.
	MinBackoff, MaxBackoff time.Duration
	Timeout                time.Duration // per holder round trip (0: 20 s)
	Now                    func() time.Time
	Sleep                  func(context.Context, time.Duration)
	Logf                   func(string, ...any)
}

// Unlocker unlocks once per boot and keeps the keyring.
type Unlocker struct {
	cfg Config

	mu     sync.Mutex
	status Status
	ring   *Keyring
	ready  chan struct{}
	grant  Grant
}

// New checks cfg.
func New(cfg Config) (*Unlocker, error) {
	if len(cfg.KMSID) != ed25519.PublicKeySize || cfg.Fixed == nil {
		return nil, errors.New("unlock: a KMS id and gatewayd are required")
	}
	if cfg.DevRoot != nil && cfg.Platform != "local" {
		return nil, errors.New("unlock: a development root is for -platform local only")
	}
	if cfg.DevRoot == nil && cfg.Evidence == nil {
		return nil, errors.New("unlock: evidence is required")
	}
	if cfg.DevRoot == nil && (cfg.Admin == nil || len(cfg.Admin.Keys) == 0 || cfg.Admin.Threshold < 1 || cfg.MinEpoch < 1) {
		return nil, errors.New("unlock: the pinned admin keys and minimum epoch are required")
	}
	if cfg.Platform == "" {
		cfg.Platform = "dstack"
	}
	if cfg.MinBackoff == 0 {
		cfg.MinBackoff = 2 * time.Second
	}
	if cfg.MaxBackoff == 0 {
		cfg.MaxBackoff = time.Minute
	}
	if cfg.SecretsWait == 0 {
		cfg.SecretsWait = 2 * time.Minute
	}
	if cfg.Relock == 0 {
		cfg.Relock = 5 * time.Minute
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Logf == nil {
		cfg.Logf = log.Printf
	}
	if cfg.Sleep == nil {
		cfg.Sleep = func(ctx context.Context, d time.Duration) {
			select {
			case <-ctx.Done():
			case <-time.After(d):
			}
		}
	}
	return &Unlocker{cfg: cfg, ready: make(chan struct{}), status: Status{State: StateStarting, Since: cfg.Now().UTC()}}, nil
}

// Status is the current state.
func (u *Unlocker) Status() Status {
	u.mu.Lock()
	defer u.mu.Unlock()
	s := u.status
	s.Holders = maps(s.Holders)
	return s
}

func maps(m map[string]string) map[string]string {
	if m == nil {
		return nil
	}
	out := map[string]string{}
	for k, v := range m {
		out[k] = v
	}
	return out
}

// Ready is closed once the keyring is there.
func (u *Unlocker) Ready() <-chan struct{} { return u.ready }

// Keys is role's share of the keyring, or the state's error while there is none.
func (u *Unlocker) Keys(role string) (*Keys, Status, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	st := u.status
	if u.ring == nil {
		return nil, st, fmt.Errorf("%s", st.State)
	}
	k, err := u.ring.For(role)
	if err != nil {
		st.State, st.Reason = StateStarting, err.Error()
		return nil, st, err
	}
	return k, st, nil
}

func (u *Unlocker) set(state, reason string, holders map[string]string) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.status.State != state {
		u.status.Since = u.cfg.Now().UTC()
	}
	u.status.State, u.status.Reason, u.status.Holders = state, reason, holders
}

// Run gets the keyring: this boot's from the cache when a container restarted, else an unlock from the holders,
// retried with backoff until ctx ends. Then, if the app's API keys aren't in yet, it keeps fetching secrets.sealed.
func (u *Unlocker) Run(ctx context.Context) error {
	if k, err := u.fromCache(); err != nil {
		u.cfg.Logf("unlock: cache: %v (unlocking from the holders)", err)
	} else if k != nil {
		u.mu.Lock()
		u.ring, u.status = k, Status{State: StateReady, Since: u.cfg.Now().UTC(), Cached: true}
		u.mu.Unlock()
		close(u.ready)
		u.cfg.Logf("unlock: this boot's keys from the host tmpfs (a container restart; no holder asked)")
		// A container restart is usually every container at once (dstack's watchdog), gatewayd too: the report's
		// one try would find no gatewayd yet and the Worker would never hear this VM is ready again (split-key
		// throwaway, 2026-11-21). Try again with backoff, in the background, for a while.
		go u.reportRetry(ctx, cachedReportFor)
		return nil
	}
	back, lastLogged := u.cfg.MinBackoff, ""
	for try := 1; ; try++ {
		u.mu.Lock()
		u.status.Tries = try
		u.mu.Unlock()
		err := u.unlockOnce(ctx)
		if err == nil {
			break
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		st := u.Status()
		if now := st.State + ": " + st.Reason; now != lastLogged {
			u.cfg.Logf("unlock: try %d: %s", try, now)
			lastLogged = now
			u.report(ctx) // the Worker hears of each new state, not of every try
		}
		u.cfg.Sleep(ctx, jitter(back))
		back = min(back*2, u.cfg.MaxBackoff)
	}
	close(u.ready)
	for u.needsSecrets() { // the API keys weren't in at the unlock: unlock again later (the root isn't kept)
		u.cfg.Sleep(ctx, u.cfg.Relock)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err := u.unlockOnce(ctx); err != nil {
			u.cfg.Logf("unlock: again for the API keys: %v", err)
		}
	}
	return nil
}

func jitter(d time.Duration) time.Duration { return d/2 + time.Duration(rand.Int64N(int64(d/2)+1)) }

func (u *Unlocker) fromCache() (*Keyring, error) {
	if u.cfg.Cache == nil {
		return nil, nil
	}
	id := kms.IDString(u.cfg.KMSID)
	k, err := u.cfg.Cache.Load(id)
	if err != nil || k == nil {
		return nil, err
	}
	if k.NeedsSecrets { // the secrets key isn't cached: unlock again
		k.Wipe()
		return nil, nil
	}
	return k, nil
}

// unlockOnce is one try: the newest policy, this VM's grant, the holders, the derivation, the secrets.
func (u *Unlocker) unlockOnce(ctx context.Context) error {
	if u.cfg.RequireMemoryRoot {
		if err := u.cfg.Cache.CheckMemoryRoot(); err != nil {
			u.set(StateRefused, err.Error(), nil)
			return err
		}
	}
	var root Root
	var g Grant
	var set, epoch uint32
	var holders map[string]string
	var floor uint64
	if u.cfg.DevRoot != nil {
		r, gr, err := u.cfg.DevRoot()
		if err != nil {
			u.set(StateRefused, err.Error(), nil)
			return err
		}
		root, g, epoch = r, gr, 1
	} else {
		raw, err := u.get(ctx, gateway.UnlockPolicyPath) // the newest, at every unlock: holders refuse an older one
		if err != nil {
			u.set(StateStarting, "the chat Worker didn't give the unlock policy: "+err.Error(), nil)
			return err
		}
		pol, _, err := OpenPolicy(raw, u.cfg.KMSID, u.cfg.Admin)
		if err != nil {
			u.set(StateRefused, "unlock policy: "+err.Error(), nil)
			return err
		}
		if g, err = u.grantFor(ctx, pol); err != nil {
			u.set(StateRefused, err.Error(), nil)
			return err
		}
		sc := split.Config{KMSID: u.cfg.KMSID, Admin: u.cfg.Admin, MinEpoch: u.cfg.MinEpoch, Policy: raw, Evidence: u.cfg.Evidence,
			Platform: u.cfg.Platform, Release: u.cfg.Release, Timeout: u.cfg.Timeout, Now: u.cfg.Now}
		if len(pol.StartTicketKeys) > 0 { // the Worker started this VM: its ticket for this start
			t, err := u.get(ctx, gateway.StartTicketPath)
			if err != nil {
				u.set(StateStarting, "no start ticket from the chat Worker: "+err.Error(), nil)
				return err
			}
			sc.StartTicket = t
		}
		for _, h := range pol.Holders {
			sc.Holders = append(sc.Holders, split.Holder{ID: h.Holder, Transport: gateway.UnlockTransport{D: u.cfg.Fixed, Holder: h.Holder}})
		}
		if pol.BreakGlass != "" {
			sc.BreakGlass = gateway.UnlockTransport{D: u.cfg.Fixed, Holder: split.BreakGlassHolder}
		}
		r, rep, err := split.Unlock(ctx, sc)
		holders = outcomes(rep)
		if err != nil {
			u.set(classify(err, rep), err.Error(), holders)
			return err
		}
		root, set, epoch, floor = r, rep.Set, r.Epoch, pol.SecretsFloor
	}
	defer root.Drop() // R_e lives no longer than this function
	k, err := Derive(root, kms.IDString(u.cfg.KMSID), epoch, set, g, u.cfg.Now())
	if err != nil {
		u.set(StateRefused, err.Error(), holders)
		return err
	}
	if d, ok := root.(*devRoot); ok { // a development VM: its dev API keys came with the root
		k.Secrets, k.NeedsSecrets = d.secrets, false
	}
	if k.NeedsSecrets {
		u.loadSecrets(ctx, root, k, g.Policy.Secrets, floor)
	}
	root.Drop()
	if u.cfg.Cache != nil {
		if k.Boot, err = u.cfg.Cache.Boot(); err != nil {
			u.cfg.Logf("unlock: no boot id (%v): the keys stay in this process only", err)
		}
	}
	u.mu.Lock()
	if u.ring != nil && k.NeedsSecrets && !u.ring.NeedsSecrets {
		k.Secrets, k.SecretsSeq, k.NeedsSecrets = u.ring.Secrets, u.ring.SecretsSeq, false
	}
	if u.ring != nil {
		u.ring.Wipe()
	}
	u.ring, u.grant = k, g
	reason := ""
	if k.NeedsSecrets {
		reason = "the API keys aren't in yet (the epoch's secrets bundle)"
	}
	u.status = Status{State: StateReady, Reason: reason, Holders: holders, Tries: u.status.Tries, Since: u.cfg.Now().UTC()}
	u.mu.Unlock()
	u.cfg.Logf("unlock: unlocked (app %s, release %s, policy seq %d, epoch %d, set %d, holders %s)", g.App, g.Release, g.PolicySeq,
		epoch, set, strings.Join(okHolders(holders), ","))
	u.report(ctx)
	if !k.NeedsSecrets {
		u.persist()
	}
	return nil
}

// loadSecrets fetches the epoch's secrets bundle and opens it with the root, for at most SecretsWait.
func (u *Unlocker) loadSecrets(ctx context.Context, root Root, k *Keyring, names []string, floor uint64) {
	start := time.Now() // wall time: how long R_e is held, whatever the clock the holders see
	back := u.cfg.MinBackoff
	for {
		err := func() error {
			sealed, err := u.get(ctx, gateway.UnlockSecretsPath)
			if err != nil {
				return err
			}
			b, err := root.OpenSecrets(sealed)
			if err != nil {
				return err
			}
			if b.Seq < floor {
				return fmt.Errorf("secrets seq %d is below the policy's floor %d", b.Seq, floor)
			}
			err = k.SetSecrets(b, names)
			clear(b.Values) // the names the grant leaves out (the other slot's tunnel token) go with the bundle
			return err
		}()
		if err == nil {
			u.cfg.Logf("unlock: API keys in (secrets seq %d)", k.SecretsSeq)
			return
		}
		if ctx.Err() != nil || time.Since(start) >= u.cfg.SecretsWait {
			u.cfg.Logf("unlock: the API keys aren't in (%v): vaultd waits, unlocking again in %s", err, u.cfg.Relock)
			return
		}
		u.cfg.Sleep(ctx, jitter(back))
		back = min(back*2, u.cfg.MaxBackoff)
	}
}

// grantFor is this VM's app and release: the policy's pin for the attested app-compose.json's hash.
func (u *Unlocker) grantFor(ctx context.Context, pol *split.UnlockPolicy) (Grant, error) {
	_, info, err := u.cfg.Evidence(ctx, make([]byte, 64))
	if err != nil {
		return Grant{}, fmt.Errorf("evidence: %w", err)
	}
	ac, err := kms.AppCompose(info)
	if err != nil {
		return Grant{}, fmt.Errorf("evidence: %w", err)
	}
	h := sha256.Sum256(ac)
	sum := hex.EncodeToString(h[:])
	for _, p := range pol.Releases {
		if p.AppComposeSHA256 == sum {
			ap, ok := pol.Apps[p.App]
			if !ok {
				return Grant{}, fmt.Errorf("the unlock policy has no grant for app %s", p.App)
			}
			if u.cfg.Release != "" && u.cfg.Release != p.Version {
				return Grant{}, fmt.Errorf("release %s claimed, %s pinned for this app-compose", u.cfg.Release, p.Version)
			}
			// Only this release's own tunnel token, of the two the grant names (tunnelslot.go).
			if ap.Secrets, err = ownTunnel(ap.Secrets, ac); err != nil {
				return Grant{}, err
			}
			return Grant{App: p.App, Release: p.Version, Policy: ap, PolicySeq: pol.Seq}, nil
		}
	}
	return Grant{}, fmt.Errorf("this VM's app-compose (%s) isn't a release the unlock policy (seq %d) pins", sum[:12], pol.Seq)
}

// classify: holders that didn't answer are "holder_down"; holders that answered and refused, "refused".
func classify(err error, rep *split.Report) string {
	if !errors.Is(err, split.ErrNotEnough) {
		return StateRefused
	}
	for _, o := range rep.Outcome {
		if strings.Contains(o, gateway.ErrUnreachable.Error()) || strings.Contains(o, "no transport") ||
			strings.Contains(o, "deadline exceeded") || strings.Contains(o, "(5") || strings.Contains(o, "(429)") {
			return StateHolderDown
		}
	}
	return StateRefused
}

func outcomes(rep *split.Report) map[string]string {
	if rep == nil || len(rep.Outcome) == 0 {
		return nil
	}
	out := map[string]string{}
	for k, v := range rep.Outcome {
		if len(v) > 200 {
			v = v[:200]
		}
		out[k] = v
	}
	return out
}

func okHolders(h map[string]string) []string {
	var out []string
	for k, v := range h {
		if v == "ok" {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

func (u *Unlocker) needsSecrets() bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.ring != nil && u.ring.NeedsSecrets
}

func (u *Unlocker) persist() {
	if u.cfg.Cache == nil {
		return
	}
	u.mu.Lock()
	k := u.ring
	u.mu.Unlock()
	if k == nil || k.Boot == "" {
		return
	}
	if err := u.cfg.Cache.Save(k); err != nil {
		u.cfg.Logf("unlock: the keys stay in this process only (a container restart unlocks again): %v", err)
	}
}

// get is a GET of one of the Worker's unlock routes through gatewayd.
func (u *Unlocker) get(ctx context.Context, path string) ([]byte, error) {
	a := u.cfg.Fixed.Fixed(ctx, &gateway.FixedCall{Target: gateway.TargetState, Method: http.MethodGet, Path: path})
	if a.Error != "" {
		return nil, fmt.Errorf("%w (%s)", gateway.ErrUnreachable, a.Error)
	}
	if a.Status != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", a.Status)
	}
	return a.Body, nil
}

// Report is unlockd's unlock report to the chat Worker (POST /api/vm/unlock/report): the state and each holder's
// outcome (the Worker alerts on a holder down and flags an unlock it didn't start a VM for). Metadata only.
type Report struct {
	Version   string            `json:"version"` // ReportVersion
	State     string            `json:"state"`
	Reason    string            `json:"reason,omitempty"`
	Message   string            `json:"message,omitempty"` // what people see
	Release   string            `json:"release,omitempty"`
	App       string            `json:"app,omitempty"`
	PolicySeq uint64            `json:"policy_seq,omitempty"`
	Set       uint32            `json:"set,omitempty"`
	Holders   map[string]string `json:"holders,omitempty"`
	Tries     int               `json:"tries"`
	Cached    bool              `json:"cached,omitempty"`
	At        time.Time         `json:"at"`
}

// ReportVersion names the report's format.
const ReportVersion = "tacy-unlock-report/v1"

// SignedReport is a report and, once unlocked, a signature over ReportLabel ‖ 0 ‖ doc by the state/v1 store-auth
// key with its StoreCert (the KMS id's, from the epoch certificate): only a VM that rebuilt R_e can sign one, and
// the Worker checks it as it checks sealed-state requests. It trusts "ready" only signed; the other states are hints.
type SignedReport struct {
	Doc  []byte         `json:"doc"`
	Sig  []byte         `json:"sig,omitempty"`
	Cert *kms.StoreCert `json:"cert,omitempty"`
}

// ReportLabel is the signature's label.
const ReportLabel = "tacy/unlock-report/v1"

// cachedReportFor is how long a cached start keeps trying to report it is ready.
const cachedReportFor = 3 * time.Minute

// reportRetry sends the report until the Worker takes it, for at most d (or until ctx ends), backing off as Run does.
func (u *Unlocker) reportRetry(ctx context.Context, d time.Duration) {
	end := time.Now().Add(d)
	for back := u.cfg.MinBackoff; ; back = min(back*2, u.cfg.MaxBackoff) {
		if u.report(ctx) || ctx.Err() != nil || time.Now().After(end) {
			return
		}
		u.cfg.Sleep(ctx, jitter(back))
	}
}

// report sends the current state to the Worker (best effort) and says whether it took it.
func (u *Unlocker) report(ctx context.Context) bool {
	st := u.Status()
	r := Report{Version: ReportVersion, State: st.State, Reason: st.Reason, Message: Message(st.State), Holders: st.Holders,
		Tries: st.Tries, Cached: st.Cached, At: u.cfg.Now().UTC()}
	var sk ed25519.PrivateKey
	var cert kms.StoreCert
	u.mu.Lock()
	if u.ring != nil {
		r.Release, r.App, r.PolicySeq, r.Set = u.ring.Release, u.ring.App, u.ring.PolicySeq, u.ring.Set
		if k, ok := u.ring.Keys["state/v1"]; ok {
			sk, _ = kms.StoreAuthKey(k)
			cert = u.ring.Certs["state/v1"]
		}
	}
	u.mu.Unlock()
	doc, _ := json.Marshal(r)
	sr := SignedReport{Doc: doc}
	if sk != nil {
		sr.Sig, sr.Cert = ed25519.Sign(sk, append(append([]byte(ReportLabel), 0), doc...)), &cert
		clear(sk)
	}
	body, _ := json.Marshal(sr)
	c, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	a := u.cfg.Fixed.Fixed(c, &gateway.FixedCall{Target: gateway.TargetState, Method: http.MethodPost, Path: gateway.UnlockReportPath,
		Header: map[string]string{"Content-Type": "application/json"}, Body: body})
	return a.Error == "" && a.Status/100 == 2 // best effort: the Worker's holder probe alerts too
}
