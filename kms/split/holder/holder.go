// Package holder is one share holder of Tacy's split key (package split; the keys plan §11): it gives its share of an
// epoch's VM root R_e (never M) only to an agent VM whose TDX attestation, fresh nonce and admin-approved release it
// checks itself, sealed to the key that VM's quote binds. The same code runs in every holder: a Go function (Vercel,
// later Google Cloud Run) and, compiled to WebAssembly, the holders Worker. A holder keeps its sealed shares (one per
// share set it is in: two while a re-split overlaps the old set) and the key that opens them; its state is its
// PolicyStore (per admin-key generation: the highest policy seq and its hash, and when each item a policy allows was
// first seen and withdrawn), its used nonces and, for a witness, the VM's highest state head. None is secret.
//
// Order of the checks (cheap and verifiable first, state last): the nonce's MAC and expiry, the policy's signatures
// and form, the share set, the attestation (quote, compose pin, floors, TCB), the start ticket's signature; then the
// rate limit, the nonce's single use and the ticket's; then the policy store (seq, items) and the 24 h delay on what
// this VM relies on; then the sealed reply. The attestation runs once per unlock.
//
// Admin key containment (pre-mortem and privacy review, 2026-11-20): everything a policy newly allows (a release pin,
// an OS image, a boot set, a pre-launch script, a KMS root, the KMS fallback, a platform, a TCB grace, a lowered
// floor) counts at a holder only PinDelay (24 h) after the holder first saw it, with an alert then; an item that
// reappears after a withdrawal waits again; withdrawals and floor raises apply at once. A seq may jump at most
// split.MaxSeqJump; two different policies with one seq are refused (the admin key signed twice); the store is per
// admin-key generation. Only an emergency override (the KMS id: two passphrase shares) expedites items.
//
// Attestation goes through a Platform chosen by the attestation's platform field and allowed by the policy.
// "dstack" (Intel TDX under dstack: Phala today, upstream dstack on Google Cloud later) is the key service's own
// check (kms/server.VerifyVM), so a holder accepts exactly what kmsd did.
package holder

import (
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"slices"
	"sync"
	"time"

	"github.com/tacyhq/tacy/kms"
	"github.com/tacyhq/tacy/kms/server"
	"github.com/tacyhq/tacy/kms/split"
	"github.com/tacyhq/tacy/safety"
	"github.com/tacyhq/tacy/verifier"
)

// Opener opens the holder's own share. KeyOpener is an HPKE private key (the Worker's and Vercel's, from a
// sensitive secret); a Cloud KMS opener (the key never leaves Google's KMS, every use logged) comes with Google.
type Opener interface {
	Open(ctx context.Context, hs split.HolderShare) ([]byte, error)
}

// KeyOpener opens with an X25519 or P-256 private key.
type KeyOpener struct{ Key *ecdh.PrivateKey }

// Open implements Opener.
func (k KeyOpener) Open(_ context.Context, hs split.HolderShare) ([]byte, error) {
	if split.RecipientString(k.Key.PublicKey()) != hs.Recipient {
		return nil, errors.New("holder: the share isn't sealed to this holder's key")
	}
	return split.OpenHolderShare(k.Key, hs)
}

// Platform verifies one kind of attestation for the bound nonce against the policy's pins and returns what it
// established (the key to seal to, the release pin, the instance, the facts the delay checks read). o.AllowStaleTCB
// is set while the policy's TCB grace runs; the holder then checks the statuses itself.
type Platform func(ctx context.Context, att json.RawMessage, bound []byte, pol *kms.Policy, o server.CheckOptions) (*server.Attested, error)

// Dstack is the "dstack" platform: Intel TDX under dstack, checked as kmsd checks a VM.
func Dstack(ctx context.Context, att json.RawMessage, bound []byte, pol *kms.Policy, o server.CheckOptions) (*server.Attested, error) {
	return server.VerifyVM(ctx, att, bound, pol, o)
}

// NonceStore remembers used nonces until they expire (Use returns true only the first time) and start-ticket
// claims (Claim: when key has no value and create is set, value is stored until expires; it returns the stored
// value, "" when none). Both atomic. Required: the Worker's is D1, Vercel's Upstash KV; MemoryNonces is one
// process's (tests and kmsctl break-glass).
type NonceStore interface {
	Use(ctx context.Context, nonce string, expires time.Time) (bool, error)
	Claim(ctx context.Context, key, value string, create bool, expires time.Time) (string, error)
}

// ErrUninitialized: the policy store has no seq for this admin-key generation. A holder refuses then: the store is
// initialized at the holder's deploy (generation, floor seq), never lazily, so a lost store can't silently restart
// at zero.
var ErrUninitialized = errors.New("holder: the policy store isn't initialized for this admin-key generation")

// ItemState is when a policy item (split.PolicyItems) was first seen at this holder and, once a newer policy left
// it out, when it was withdrawn (zero: still allowed).
type ItemState struct {
	First     time.Time
	Withdrawn time.Time
}

// PolicyStore is a holder's durable policy state (D1, Upstash KV, Firestore; MemoryStore is the reference). Every
// method is atomic, and the holder calls Apply on the durable store in every request that releases a share or takes a
// policy: nothing that can be withdrawn is cached in an instance's memory (the triage's rule).
type PolicyStore interface {
	// Apply is a policy's one step, atomic: with top the gen's seq and topHash its policy hash, it refuses a seq
	// below top (a *SeqRefusal wrapping ErrStale), above top+split.MaxSeqJump (ErrJump), or equal to top with
	// another hash (ErrEquivocation); else it sets (seq, hash), records each item not recorded or recorded as
	// withdrawn as first seen now (returned as added), marks each recorded item not in items withdrawn now, prunes
	// items withdrawn over 30 days, and returns every recorded item. ErrUninitialized when gen has no seq (the deploy
	// initializes it at the floor, never lazily).
	Apply(ctx context.Context, gen string, seq uint64, hash string, items []string, now time.Time) (map[string]ItemState, []string, error)
	// Expedite sets a present item's first-seen time to t when t is earlier (an emergency override).
	Expedite(ctx context.Context, gen, item string, t time.Time) (bool, error)
	// Top reads gen's seq: for /v1/status only (it may be cached; nothing is decided on it).
	Top(ctx context.Context, gen string) (uint64, error)
}

// The store's refusals of a policy's seq (Apply), each with the gen's seq.
var (
	ErrStale        = errors.New("older than this holder's seq")
	ErrJump         = errors.New("too far above this holder's seq")
	ErrEquivocation = errors.New("another policy with this seq was already seen here")
)

// SeqRefusal is Apply's refusal of a seq: which one, and the gen's seq.
type SeqRefusal struct {
	Err error
	Top uint64
}

func (e *SeqRefusal) Error() string { return fmt.Sprintf("%v (this holder's seq %d)", e.Err, e.Top) }
func (e *SeqRefusal) Unwrap() error { return e.Err }

// WitnessStore keeps a witness holder's highest state head per app: Put keeps head only when counter is higher and
// returns the counter kept; Get returns the head kept (empty: none). Atomic.
type WitnessStore interface {
	Put(ctx context.Context, key string, counter uint64, head []byte) (uint64, error)
	Get(ctx context.Context, key string) ([]byte, error)
}

// Event is one unlock attempt that got past the nonce check, one policy push, one witness push, or a policy change
// the holder first saw, for the holder's alerts and audit log (never key material).
type Event struct {
	Time   time.Time
	Holder string
	// Kind: "unlock", "policy", "witness"; "pin" (a release pin first seen: it counts from Time + PinDelay), "change"
	// (any other newly allowed item: OS image, boot set, pre-launch, KMS root, platform, TCB grace, a floor), or
	// "emergency" (an override expedited an item: it counts at once). Alert on pin, change and emergency.
	Kind        string
	OK          bool
	Reason      string // why it was refused, or what changed
	Item        string // pin, change, emergency: the policy item
	Platform    string
	App         string
	Release     string
	Instance    string
	ComposeHash string
	TCB         string
	PolicySeq   uint64
	Set         uint32
	Epoch       uint32
}

// DefaultPinDelay is how long after a holder first sees a policy item it counts.
const DefaultPinDelay = 24 * time.Hour

// Config is a holder's setup.
type Config struct {
	ID    string // its id in the share sets ("cloudflare", "vercel", "gcp")
	KMSID string // the pinned KMS id ("ed25519:<base64>")
	// Admin: the admin's admin keys (an unlock policy needs Threshold of their signatures), and AdminGeneration
	// names them ("kms-admin-1"): the policy store keeps its state per generation. Rotating a key is a holder deploy
	// with the new generation (initialized in the store at its floor) and the new key.
	Admin           kms.AdminKeys
	AdminGeneration string
	// PolicyFloor is the lowest unlock policy seq served (raised at a holder deploy; every security withdrawal also
	// raises it).
	PolicyFloor uint64
	// Shares are its sealed shares (public config: ciphertext), one per share set it is in.
	Shares []split.HolderShare
	Opener Opener
	// Master (break-glass only: kmsctl break-glass, ID split.BreakGlassHolder, no Shares, no Opener) is M, rebuilt
	// from two passphrase shares; it serves R_e of the policy's epoch, never M, at most MaxUnlocks times (0: one).
	Master     []byte
	MaxUnlocks int
	// PolicyHash (break-glass only, required): the one policy (PolicyHash of its payload) break-glass serves under,
	// the one the admin started it with. Any other, newer or not, is refused, so a stolen admin key can't race a
	// rogue release through it.
	PolicyHash string
	// NonceKey makes and checks its stateless nonces (32 bytes, the holder's own; never shared with another holder).
	NonceKey []byte
	Nonces   NonceStore  // required
	Store    PolicyStore // required
	// Witness, when set, makes this holder a rollback witness (the policy names it in witnesses).
	Witness WitnessStore
	// Build is this holder's build (the sha256 its reproducible build records), reported in /v1/status and compared
	// with the policy's pin for it: a mismatch is a "change" event (alert).
	Build string
	// PinDelay: how long a newly allowed item waits (0: DefaultPinDelay). NoPinDelay (staging and tests only) turns
	// the wait off.
	PinDelay   time.Duration
	NoPinDelay bool
	// Platforms by attestation platform name (nil: {"dstack": Dstack}); the policy's platforms list must name it
	// too.
	Platforms map[string]Platform
	// Check: the attestation checks' switches (production: zero, except Getter where the runtime needs one for Intel
	// PCS). KMSIDs is set from KMSID.
	Check server.CheckOptions
	// Rate, Burst: unlocks per second and at once that pass the attestation (0: 1/min, 20).
	Rate, Burst float64
	Now         func() time.Time
	Notify      func(Event)
	Rand        io.Reader
}

// Holder serves its shares.
type Holder struct {
	cfg    Config
	mu     sync.Mutex
	tok    float64
	at     time.Time
	served int // break-glass: unlocks served
}

// Refused is a refusal: its HTTP status and reason (never key material).
type Refused struct {
	Status int
	Reason string
}

func (r *Refused) Error() string { return r.Reason }

func refuse(status int, f string, a ...any) error {
	return &Refused{Status: status, Reason: fmt.Sprintf(f, a...)}
}

// New checks cfg.
func New(cfg Config) (*Holder, error) {
	if !split.ValidHolder(cfg.ID) {
		return nil, errors.New("holder: bad id")
	}
	id, err := kms.ParseID(cfg.KMSID)
	if err != nil {
		return nil, fmt.Errorf("holder: KMS id: %w", err)
	}
	if (cfg.Master != nil) != (cfg.ID == split.BreakGlassHolder) {
		return nil, errors.New("holder: only the break-glass holder serves a root from M, and it serves nothing else")
	}
	if cfg.Master != nil {
		mid, err := kms.DeriveID(cfg.Master)
		if err != nil || !mid.Public().(ed25519.PublicKey).Equal(id) || len(cfg.Shares) != 0 || cfg.PolicyHash == "" {
			return nil, errors.New("holder: break-glass needs the pinned KMS id's master key, its policy's hash and no shares")
		}
		clear(mid)
		if cfg.MaxUnlocks == 0 {
			cfg.MaxUnlocks = 1
		}
		cfg.Opener = masterOnly{}
	} else if len(cfg.Shares) == 0 || len(cfg.Shares) > split.MaxShareSets {
		return nil, fmt.Errorf("holder: 1 to %d shares", split.MaxShareSets)
	}
	for i, s := range cfg.Shares {
		if s.KMSID != cfg.KMSID || s.Holder != cfg.ID || s.Index == 0 || s.Set < 2 || s.Epoch == 0 {
			return nil, errors.New("holder: a share is for another KMS id or holder")
		}
		if slices.ContainsFunc(cfg.Shares[:i], func(o split.HolderShare) bool { return o.Set == s.Set }) {
			return nil, fmt.Errorf("holder: two shares of set %d", s.Set)
		}
	}
	if len(cfg.NonceKey) != 32 || cfg.Opener == nil || cfg.Nonces == nil || cfg.Store == nil || cfg.AdminGeneration == "" ||
		len(cfg.Admin.Keys) == 0 || cfg.Admin.Threshold < 1 {
		return nil, errors.New("holder: needs a 32-byte nonce key, an opener, a nonce store, a policy store, the admin keys and their generation")
	}
	if cfg.Check.DevLocal {
		return nil, errors.New("holder: development attestation (nothing attested) is never a holder's")
	}
	if cfg.PinDelay == 0 {
		cfg.PinDelay = DefaultPinDelay
	}
	if cfg.NoPinDelay {
		cfg.PinDelay = 0
	}
	if cfg.Platforms == nil {
		cfg.Platforms = map[string]Platform{"dstack": Dstack}
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Rand == nil {
		cfg.Rand = rand.Reader
	}
	if cfg.Rate == 0 {
		cfg.Rate, cfg.Burst = 1.0/60, 20
	}
	cfg.Check.KMSIDs = map[string]string{cfg.KMSID: "Tacy KMS"}
	cfg.Shares = slices.Clone(cfg.Shares)
	slices.SortFunc(cfg.Shares, func(a, b split.HolderShare) int { return int(b.Set) - int(a.Set) })
	return &Holder{cfg: cfg, tok: cfg.Burst}, nil
}

// Status is GET /v1/status: the sets it serves, the highest policy seq it took and its build.
func (h *Holder) Status(ctx context.Context) split.Status {
	st := split.Status{Version: split.Version, Holder: h.cfg.ID, KMSID: h.cfg.KMSID, Build: h.cfg.Build}
	if top, err := h.cfg.Store.Top(ctx, h.cfg.AdminGeneration); err == nil {
		st.PolicySeq = top
	}
	for _, s := range h.cfg.Shares {
		st.Sets = append(st.Sets, split.StatusSet{Set: s.Set, Epoch: s.Epoch, Index: s.Index})
	}
	return st
}

// Challenge is GET /v1/challenge.
func (h *Holder) Challenge() (split.Challenge, error) {
	exp := h.cfg.Now().Add(split.NonceTTL)
	n, err := split.NewNonce(h.cfg.NonceKey, h.cfg.ID, exp, h.cfg.Rand)
	return split.Challenge{Holder: h.cfg.ID, Nonce: n, Expires: exp.Unix()}, err
}

// Unlock checks req and returns this holder's share of the asked set sealed to the attested key.
func (h *Holder) Unlock(ctx context.Context, req split.UnlockRequest) (*split.UnlockReply, error) {
	ev := Event{Holder: h.cfg.ID, Kind: "unlock", Set: req.Set}
	rep, err := h.unlock(ctx, req, &ev)
	h.notify(ev, err)
	return rep, err
}

// PushPolicy is POST /v1/policy: a newer signed policy (the admin's, or relayed by anyone: it is public) raises
// this holder's seq at once, so a release it no longer pins stops unlocking here at once, and starts the delay of
// what it adds.
func (h *Holder) PushPolicy(ctx context.Context, raw json.RawMessage) (uint64, error) {
	now := h.cfg.Now()
	ev := Event{Holder: h.cfg.ID, Kind: "policy", Time: now}
	pp, err := h.parsePolicy(raw, now)
	if err == nil {
		ev.PolicySeq = pp.pol.Seq
		_, err = h.applyPolicy(ctx, pp, now)
	}
	h.notify(ev, err)
	if err != nil {
		return 0, err
	}
	return pp.pol.Seq, nil
}

func (h *Holder) notify(ev Event, err error) {
	if ev.Time.IsZero() || h.cfg.Notify == nil {
		return // refused before the nonce checked: counted by the caller's logs, not an event
	}
	ev.OK = err == nil
	if err != nil {
		ev.Reason = err.Error()
	}
	h.cfg.Notify(ev)
}

func (h *Holder) unlock(ctx context.Context, req split.UnlockRequest, ev *Event) (*split.UnlockReply, error) {
	now := h.cfg.Now()
	// 1. Our nonce: in the list, ours (MAC), not expired. (Its single use is marked in step 4.)
	bound, err := split.Bind(req.Nonces)
	if err != nil {
		return nil, refuse(http.StatusBadRequest, "%v", err)
	}
	i := slices.IndexFunc(req.Nonces, func(n split.HolderNonce) bool { return n.Holder == h.cfg.ID })
	if i < 0 {
		return nil, refuse(http.StatusBadRequest, "no nonce of this holder (%s) in the request", h.cfg.ID)
	}
	exp, err := split.CheckNonce(h.cfg.NonceKey, h.cfg.ID, req.Nonces[i].Nonce, now)
	if err != nil {
		return nil, refuse(http.StatusForbidden, "%v", err)
	}
	ev.Time = now

	// 2. The admin's unlock policy (signatures and form; no state yet), and the asked share set.
	pp, err := h.parsePolicy(req.Policy, now)
	if err != nil {
		return nil, err
	}
	pol := pp.pol
	ev.PolicySeq = pol.Seq
	var share split.HolderShare
	var entry split.SetHolder
	epoch := pol.Epoch
	if h.cfg.Master != nil {
		if req.Set != 0 || pol.BreakGlass == "" {
			return nil, refuse(http.StatusConflict, "break-glass serves set 0 only, under a policy that names a break-glass relay")
		}
		if pp.hash != h.cfg.PolicyHash {
			return nil, refuse(http.StatusForbidden, "break-glass serves only the policy it was started with")
		}
	} else {
		si := slices.IndexFunc(h.cfg.Shares, func(s split.HolderShare) bool { return s.Set == req.Set })
		set, inPolicy := split.FindSet(pp.sets, req.Set)
		if si < 0 || !inPolicy {
			return nil, refuse(http.StatusConflict, "share set %d isn't both in the policy and served by this holder", req.Set)
		}
		share = h.cfg.Shares[si]
		var ok bool
		entry, ok = set.Holder(h.cfg.ID)
		if !ok || entry.Index != share.Index || entry.Recipient != share.Recipient || set.Epoch != share.Epoch {
			return nil, refuse(http.StatusConflict, "share set %d doesn't list this holder's share", req.Set)
		}
		epoch = share.Epoch
	}
	ev.Epoch = epoch

	// 3. The VM: its attestation for the bound nonces, on a platform the policy allows, against the policy's pins;
	// then its TCB under any grace, its release and floors, and the start ticket's signature.
	var head struct {
		Platform string `json:"platform"`
	}
	json.Unmarshal(req.Attestation, &head)
	ev.Platform = head.Platform
	verify := h.cfg.Platforms[head.Platform]
	if head.Platform == "local" || verify == nil || !pol.AllowsPlatform(head.Platform) {
		return nil, refuse(http.StatusForbidden, "attestation platform %q isn't one this holder checks under this policy", head.Platform)
	}
	o := h.cfg.Check
	// The Google Cloud fallback (vm-v1): only when the signed policy names verifier.PlatformDstackGCP beside
	// "dstack" (the VM's attestation says "dstack" on either host). Off otherwise, whatever the holder's settings;
	// the policy item counts only after the pin delay (relied).
	o.GCP = head.Platform == "dstack" && pol.AllowsPlatform(verifier.PlatformDstackGCP)
	grace := pol.TCBGrace != nil && now.Before(pol.TCBGrace.Until)
	o.AllowStaleTCB = o.AllowStaleTCB || grace
	a, err := verify(ctx, req.Attestation, bound, &pol.Policy, o)
	if err != nil {
		return nil, refuse(http.StatusForbidden, "%v", err)
	}
	ev.App, ev.Release, ev.Instance, ev.ComposeHash, ev.TCB = a.Pin.App, a.Pin.Version, a.Instance, a.ComposeHash, a.Facts["TCB"]
	graceUsed := false
	if grace && !h.cfg.Check.AllowStaleTCB {
		st, qe, date := tcbFacts(a.Facts["TCB"])
		if err := pol.TCBGrace.Allows(st, qe, date, 0, now); err != nil {
			return nil, refuse(http.StatusForbidden, "%v", err)
		}
		graceUsed = st != "UpToDate" || qe != "UpToDate"
	}
	ap, ok := pol.Apps[a.Pin.App]
	if !ok {
		return nil, refuse(http.StatusForbidden, "app %s has no grant", a.Pin.App)
	}
	if req.Release != "" && req.Release != a.Pin.Version {
		return nil, refuse(http.StatusForbidden, "release %s claimed, %s pinned for this app-compose", req.Release, a.Pin.Version)
	}
	for _, f := range []struct{ what, v string }{{"policy floor", pol.Floor}, {"app floor", ap.Floor}} {
		if f.v == "" {
			continue
		}
		if c, ok := kms.CompareVersions(a.Pin.Version, f.v); !ok || c < 0 {
			return nil, refuse(http.StatusForbidden, "release %s is below the %s %s", a.Pin.Version, f.what, f.v)
		}
	}
	ticket, ticketPayload, err := h.startTicket(pol, req.StartTicket, a, now)
	if err != nil {
		return nil, err
	}

	// 4. Rate limit, then the nonce's (and the ticket's) single use.
	if !h.take(now) {
		return nil, refuse(http.StatusTooManyRequests, "too many unlocks; try again later")
	}
	fresh, err := h.cfg.Nonces.Use(ctx, req.Nonces[i].Nonce, exp)
	if err != nil {
		return nil, refuse(http.StatusServiceUnavailable, "nonce store: %v", err)
	}
	if !fresh {
		return nil, refuse(http.StatusForbidden, "nonce already used (a replayed request)")
	}
	if ticket != nil {
		// One VM per ticket: the first instance claims it (while fresh), the same one may come back (a restart).
		create := now.Sub(ticket.IssuedAt) <= split.StartTicketTTL
		stored, err := h.cfg.Nonces.Claim(ctx, "ticket:"+ticketHash(ticketPayload), a.Instance, create, ticket.IssuedAt.Add(split.StartTicketBoot))
		if err != nil {
			return nil, refuse(http.StatusServiceUnavailable, "nonce store: %v", err)
		}
		switch {
		case stored == "":
			return nil, refuse(http.StatusForbidden, "start ticket is older than %s and was never used here (the Worker issues a new one at a start)", split.StartTicketTTL)
		case stored != a.Instance:
			return nil, refuse(http.StatusForbidden, "start ticket was already used here by another VM")
		}
	}

	// 5. The policy store: seq, items; then the delay on everything this VM relies on, and the floors' delay.
	states, err := h.applyPolicy(ctx, pp, now)
	if err != nil {
		return nil, err
	}
	if err := h.delayed(pol, a, head.Platform, graceUsed, states, now); err != nil {
		return nil, err
	}

	// 6. Break-glass: R_e of the policy's epoch, from M, once (admin present).
	if h.cfg.Master != nil {
		h.mu.Lock()
		defer h.mu.Unlock()
		if h.served >= h.cfg.MaxUnlocks {
			return nil, refuse(http.StatusGone, "break-glass already served its %d boot(s)", h.cfg.MaxUnlocks)
		}
		root, err := split.EpochRoot(h.cfg.Master, pol.Epoch)
		if err != nil {
			return nil, err
		}
		defer clear(root)
		box, err := kms.Seal(a.Key, split.LabelBreakGlass, split.ReplyAAD(bound, h.cfg.KMSID, pol.Epoch, 0, h.cfg.ID, 0, pp.hash, nil), root)
		if err != nil {
			return nil, err
		}
		h.served++
		return &split.UnlockReply{Holder: h.cfg.ID, KMSID: h.cfg.KMSID, Epoch: pol.Epoch, Sealed: box}, nil
	}

	// 6. Our share, checked against its commitment, sealed to the attested key with our witness head (if any).
	var witnessHead []byte
	if h.cfg.Witness != nil && slices.Contains(pol.Witnesses, h.cfg.ID) {
		if witnessHead, err = h.cfg.Witness.Get(ctx, witnessKey(h.cfg.KMSID, a.Pin.App)); err != nil {
			return nil, refuse(http.StatusServiceUnavailable, "witness store: %v", err)
		}
	}
	y, err := h.cfg.Opener.Open(ctx, share)
	if err != nil {
		return nil, refuse(http.StatusInternalServerError, "this holder's share of set %d doesn't open", share.Set)
	}
	defer clear(y)
	if split.Commitment(share.KMSID, share.Epoch, share.Set, share.Holder, share.Index, y) != entry.Commitment {
		return nil, refuse(http.StatusInternalServerError, "this holder's share of set %d doesn't match its commitment", share.Set)
	}
	box, err := kms.Seal(a.Key, split.LabelReply, split.ReplyAAD(bound, share.KMSID, share.Epoch, share.Set, share.Holder, share.Index, pp.hash, witnessHead), y)
	if err != nil {
		return nil, err
	}
	return &split.UnlockReply{Holder: h.cfg.ID, Index: share.Index, KMSID: share.KMSID, Epoch: share.Epoch, Set: share.Set, Sealed: box,
		WitnessHead: witnessHead}, nil
}

// delayed refuses if anything this verified VM relies on was newly allowed less than PinDelay ago, or if a floor was
// lowered less than PinDelay ago and this release is below the old one.
func (h *Holder) delayed(pol *split.UnlockPolicy, a *server.Attested, platform string, graceUsed bool, states map[string]ItemState, now time.Time) error {
	if h.cfg.PinDelay <= 0 {
		return nil
	}
	for _, it := range relied(pol, a, platform, graceUsed) {
		st, ok := states[it]
		if !ok || !st.Withdrawn.IsZero() {
			return refuse(http.StatusConflict, "%s isn't in this holder's record of the policy (push the policy again)", it)
		}
		if from := st.First.Add(h.cfg.PinDelay); now.Before(from) {
			what := "a change this VM needs (" + it + ")"
			if it == split.ReleaseItem(a.Pin) {
				what = "release " + a.Pin.Version
			} else if _, ok := cutPrefix(it, split.ItemOther); ok {
				what = "a change to the policy's other fields (" + it + ")"
			}
			return refuse(http.StatusForbidden, "%s was first allowed here at %s; it counts from %s", what,
				st.First.UTC().Format(time.RFC3339), from.UTC().Format(time.RFC3339))
		}
	}
	// A floor lowered within the delay stays in force.
	for it, st := range states {
		scope, v, ok := split.ParseFloorItem(it)
		if !ok || st.Withdrawn.IsZero() || now.Sub(st.Withdrawn) >= h.cfg.PinDelay {
			continue
		}
		if scope != "*" && scope != a.Pin.App {
			continue
		}
		if c, ok := kms.CompareVersions(a.Pin.Version, v); ok && c < 0 {
			return refuse(http.StatusForbidden, "release %s is below the floor %s, which a newer policy lowered at %s; the lower floor counts from %s",
				a.Pin.Version, v, st.Withdrawn.UTC().Format(time.RFC3339), st.Withdrawn.Add(h.cfg.PinDelay).UTC().Format(time.RFC3339))
		}
	}
	return nil
}

// relied lists the policy items this verified VM relied on: its release pin, and the OS image, boot set, pre-launch
// script, KMS root, key mode, platform and TCB grace it passed by, wherever the policy lists its own (a nil list
// means the holder's built-in one, which isn't the admin key's).
func relied(pol *split.UnlockPolicy, a *server.Attested, platform string, graceUsed bool) []string {
	out := []string{split.ReleaseItem(a.Pin), split.OtherItem(pol)}
	f := a.Facts
	osHash := f["OS image hash"]
	if pol.OSImages != nil {
		out = append(out, split.ItemOS+osHash)
	}
	if pol.Boot != nil {
		for _, b := range pol.Boot {
			if b.OSImage == osHash && b.MRTD == f["MRTD"] && b.RTMR0 == f["RTMR0"] && b.RTMR1 == f["RTMR1"] && b.RTMR2 == f["RTMR2"] {
				out = append(out, split.ItemBoot+split.BootItem(b))
			}
		}
	}
	if pol.PreLaunch != nil {
		for hash, name := range pol.PreLaunch {
			if name == f["pre-launch script"] {
				out = append(out, split.ItemPreLaunch+hash)
			}
		}
	}
	if f["key mode"] == verifier.KeyProviderKMS {
		out = append(out, split.ItemFlag+"kms-fallback")
		if pol.KMSRoots != nil {
			for id, name := range pol.KMSRoots {
				if name == f["KMS root"] {
					out = append(out, split.ItemKMSRoot+id)
				}
			}
		}
	}
	if len(pol.Platforms) > 0 {
		out = append(out, split.ItemPlatform+platform)
	}
	if f[verifier.FactPlatformSet] == verifier.PlatformDstackGCP {
		// A Google Cloud boot set: the policy's dstack-gcp item, under the pin delay like any widening.
		out = append(out, split.ItemPlatform+verifier.PlatformDstackGCP)
	}
	if graceUsed {
		out = append(out, split.ItemTCBGrace+split.TCBGraceItem(pol))
	}
	return out
}

func cutPrefix(s, p string) (string, bool) {
	if len(s) >= len(p) && s[:len(p)] == p {
		return s[len(p):], true
	}
	return "", false
}

// startTicket: when the policy names start-ticket keys, one of them signed a ticket for this VM, now. Its single use
// is marked by the caller.
func (h *Holder) startTicket(pol *split.UnlockPolicy, raw json.RawMessage, a *server.Attested, now time.Time) (*split.StartTicket, []byte, error) {
	if len(pol.StartTicketKeys) == 0 {
		return nil, nil, nil
	}
	if len(raw) == 0 {
		return nil, nil, refuse(http.StatusForbidden, "this policy needs a start ticket from the Worker")
	}
	var keys []ed25519.PublicKey
	for _, k := range pol.StartTicketKeys {
		pk, _ := kms.ParseID(k) // checked by Validate
		keys = append(keys, pk)
	}
	var env safety.Envelope
	var t split.StartTicket
	if err := kms.Strict(raw, &env); err != nil {
		return nil, nil, refuse(http.StatusBadRequest, "start ticket isn't an envelope")
	}
	if err := (kms.AdminKeys{Keys: keys, Threshold: 1}).Open(&env, split.KindStartTicket, &t); err != nil {
		return nil, nil, refuse(http.StatusForbidden, "start ticket: %v", err)
	}
	if t.KMSID != h.cfg.KMSID || t.IssuedAt.After(now.Add(split.MaxClockSkew)) || now.Sub(t.IssuedAt) > split.StartTicketBoot {
		return nil, nil, refuse(http.StatusForbidden, "start ticket is for another KMS id or not valid now")
	}
	if t.AppID == "" || t.AppID != a.AppID {
		return nil, nil, refuse(http.StatusForbidden, "start ticket is for app id %s, not this VM's", t.AppID)
	}
	return &t, env.Payload, nil // the claim is keyed on the signed payload, so re-encoding the envelope changes nothing
}

// ticketHash is a start ticket payload's sha256 (hex): its single-VM claim's key.
func ticketHash(raw json.RawMessage) string {
	h := sha256.Sum256(raw)
	return hex.EncodeToString(h[:])
}

// tcbFacts reads the verifier's TCB fact: "<status> (QE <status>, TCB date <date>)".
func tcbFacts(s string) (status, qe, date string) {
	m := tcbFactRe.FindStringSubmatch(s)
	if m == nil {
		return s, "", ""
	}
	return m[1], m[2], m[3]
}

var tcbFactRe = regexp.MustCompile(`^(\S+) \(QE (\S*), TCB date (\S*)\)$`)

// parsedPolicy is a policy whose signatures and form checked, before the store.
type parsedPolicy struct {
	pol  *split.UnlockPolicy
	sets []*split.ShareSet
	hash string
	em   *split.Emergency
}

// parsePolicy opens and checks the unlock policy, its share sets and its emergency override, without state.
func (h *Holder) parsePolicy(raw json.RawMessage, now time.Time) (*parsedPolicy, error) {
	var env safety.Envelope
	if err := kms.Strict(raw, &env); err != nil {
		return nil, refuse(http.StatusBadRequest, "policy isn't an envelope")
	}
	var pol split.UnlockPolicy
	if err := h.cfg.Admin.Open(&env, split.KindUnlockPolicy, &pol); err != nil {
		return nil, refuse(http.StatusForbidden, "policy: %v", err)
	}
	if err := pol.Validate(); err != nil {
		return nil, refuse(http.StatusForbidden, "%v", err)
	}
	if pol.KMSID != h.cfg.KMSID {
		return nil, refuse(http.StatusForbidden, "policy is for another KMS id")
	}
	if pol.Seq < h.cfg.PolicyFloor {
		return nil, refuse(http.StatusForbidden, "policy seq %d is below this holder's floor %d", pol.Seq, h.cfg.PolicyFloor)
	}
	if pol.IssuedAt.After(now.Add(split.MaxClockSkew)) {
		return nil, refuse(http.StatusForbidden, "policy is issued in the future (%s)", pol.IssuedAt.UTC().Format(time.RFC3339))
	}
	if pol.AllowE2EDiag && !h.cfg.Check.AllowE2EDiag {
		return nil, refuse(http.StatusForbidden, "policy lets e2e overlays in (staging only)")
	}
	id, _ := kms.ParseID(h.cfg.KMSID)
	sets, err := pol.OpenShareSets(id)
	if err != nil {
		return nil, refuse(http.StatusForbidden, "%v", err)
	}
	pp := &parsedPolicy{pol: &pol, sets: sets, hash: split.PolicyHash(env.Payload)}
	if pol.Emergency != nil {
		if pp.em, err = pol.Emergency.Open(id, &pol); err != nil {
			return nil, refuse(http.StatusForbidden, "%v", err)
		}
	}
	return pp, nil
}

// applyPolicy raises the seq (per admin-key generation, capped, one document per seq), records the policy's items
// (first sights and withdrawals), applies an emergency override, alerts on what is new, and returns the items' state.
func (h *Holder) applyPolicy(ctx context.Context, pp *parsedPolicy, now time.Time) (map[string]ItemState, error) {
	pol, gen := pp.pol, h.cfg.AdminGeneration
	states, added, err := h.cfg.Store.Apply(ctx, gen, pol.Seq, pp.hash, split.PolicyItems(pol), now)
	var sr *SeqRefusal
	switch {
	case errors.Is(err, ErrUninitialized):
		return nil, refuse(http.StatusServiceUnavailable, "this holder's policy store isn't initialized for %s (refusing until its deploy does)", gen)
	case errors.As(err, &sr) && errors.Is(err, ErrStale):
		return nil, refuse(http.StatusForbidden, "policy seq %d is older than this holder's seq %d (fetch the newest policy)", pol.Seq, sr.Top)
	case errors.As(err, &sr) && errors.Is(err, ErrJump):
		return nil, refuse(http.StatusForbidden, "policy seq %d jumps more than %d above this holder's seq %d", pol.Seq, split.MaxSeqJump, sr.Top)
	case errors.As(err, &sr) && errors.Is(err, ErrEquivocation):
		if h.cfg.Notify != nil {
			h.cfg.Notify(Event{Time: now, Holder: h.cfg.ID, Kind: "change", Reason: "two different policies signed with seq " +
				fmt.Sprint(pol.Seq) + " (the admin key signed twice)", PolicySeq: pol.Seq})
		}
		return nil, refuse(http.StatusForbidden, "another policy with seq %d was already seen here (the admin key signed twice)", pol.Seq)
	case err != nil:
		return nil, refuse(http.StatusServiceUnavailable, "policy store: %v", err)
	}
	if pp.em != nil {
		for _, it := range pp.em.Items {
			changed, err := h.cfg.Store.Expedite(ctx, gen, it, now.Add(-h.cfg.PinDelay))
			if err != nil {
				return nil, refuse(http.StatusServiceUnavailable, "policy store: %v", err)
			}
			if changed {
				states[it] = ItemState{First: now.Add(-h.cfg.PinDelay)}
				h.alert(now, "emergency", it, pol, "emergency override (KMS id): counts at once: "+pp.em.Reason)
			}
		}
	}
	for _, hu := range pol.Holders {
		if hu.Holder == h.cfg.ID && hu.Build != "" && hu.Build != h.cfg.Build {
			h.alert(now, "change", "build:"+hu.Build, pol, "this holder runs build "+h.cfg.Build+", the policy pins "+hu.Build)
		}
	}
	for _, it := range added {
		kind := "change"
		if _, ok := cutPrefix(it, split.ItemRelease); ok {
			kind = "pin"
		}
		h.alert(now, kind, it, pol, "newly allowed; it counts here after "+h.cfg.PinDelay.String())
	}
	return states, nil
}

func (h *Holder) alert(now time.Time, kind, item string, pol *split.UnlockPolicy, why string) {
	if h.cfg.Notify == nil {
		return
	}
	ev := Event{Time: now, Holder: h.cfg.ID, Kind: kind, OK: true, Item: item, PolicySeq: pol.Seq, Reason: why}
	if _, ok := cutPrefix(item, split.ItemRelease); ok {
		for _, r := range pol.Releases {
			if split.ReleaseItem(r) == item {
				ev.App, ev.Release, ev.ComposeHash = r.App, r.Version, r.AppComposeSHA256
			}
		}
	}
	h.cfg.Notify(ev)
}

// PushWitness is POST /v1/witness (a witness holder): the VM's new state head, signed by its epoch's witness key
// (certified by the KMS id), kept if its counter is higher.
func (h *Holder) PushWitness(ctx context.Context, wp split.WitnessPush) (*split.WitnessReply, error) {
	now := h.cfg.Now()
	if h.cfg.Witness == nil {
		return nil, refuse(http.StatusNotFound, "this holder isn't a witness")
	}
	id, _ := kms.ParseID(h.cfg.KMSID)
	cert, err := wp.Cert.Open(id)
	if err != nil {
		return nil, refuse(http.StatusForbidden, "%v", err)
	}
	head, err := wp.Head.Open(cert)
	if err != nil {
		return nil, refuse(http.StatusForbidden, "%v", err)
	}
	if !h.take(now) {
		return nil, refuse(http.StatusTooManyRequests, "too many witness pushes; try again later")
	}
	raw, _ := json.Marshal(wp.Head)
	kept, err := h.cfg.Witness.Put(ctx, witnessKey(h.cfg.KMSID, head.App), head.Counter, raw)
	if err != nil {
		return nil, refuse(http.StatusServiceUnavailable, "witness store: %v", err)
	}
	if h.cfg.Notify != nil {
		h.cfg.Notify(Event{Time: now, Holder: h.cfg.ID, Kind: "witness", OK: kept == head.Counter, App: head.App, Epoch: head.Epoch,
			Reason: fmt.Sprintf("head %d pushed, %d kept", head.Counter, kept)})
	}
	return &split.WitnessReply{Counter: kept}, nil
}

func witnessKey(kmsID, app string) string { return kmsID + "\x00" + app }

func (h *Holder) take(now time.Time) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.at.IsZero() {
		if d := now.Sub(h.at).Seconds(); d > 0 {
			h.tok = min(h.cfg.Burst, h.tok+d*h.cfg.Rate)
		}
	}
	h.at = now
	if h.tok < 1 {
		return false
	}
	h.tok--
	return true
}

// Handler serves GET /v1/status, GET /v1/challenge, POST /v1/unlock, POST /v1/policy and POST /v1/witness.
func (h *Holder) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/status", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, h.Status(r.Context())) })
	mux.HandleFunc("GET /v1/challenge", func(w http.ResponseWriter, _ *http.Request) {
		c, err := h.Challenge()
		if err != nil {
			writeErr(w, err)
			return
		}
		writeJSON(w, c)
	})
	mux.HandleFunc("POST /v1/unlock", func(w http.ResponseWriter, r *http.Request) {
		var req split.UnlockRequest
		if !readStrict(w, r, &req) {
			return
		}
		rep, err := h.Unlock(r.Context(), req)
		if err != nil {
			writeErr(w, err)
			return
		}
		writeJSON(w, rep)
	})
	mux.HandleFunc("POST /v1/policy", func(w http.ResponseWriter, r *http.Request) {
		b, err := readBody(r)
		if err != nil {
			writeErr(w, err)
			return
		}
		seq, err := h.PushPolicy(r.Context(), b)
		if err != nil {
			writeErr(w, err)
			return
		}
		writeJSON(w, map[string]uint64{"policy_seq": seq})
	})
	mux.HandleFunc("POST /v1/witness", func(w http.ResponseWriter, r *http.Request) {
		var wp split.WitnessPush
		if !readStrict(w, r, &wp) {
			return
		}
		rep, err := h.PushWitness(r.Context(), wp)
		if err != nil {
			writeErr(w, err)
			return
		}
		writeJSON(w, rep)
	})
	return mux
}

func readStrict(w http.ResponseWriter, r *http.Request, v any) bool {
	b, err := readBody(r)
	if err != nil {
		writeErr(w, err)
		return false
	}
	if err := kms.Strict(b, v); err != nil {
		writeErr(w, refuse(http.StatusBadRequest, "request: %v", err))
		return false
	}
	return true
}

func readBody(r *http.Request) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r.Body, split.MaxBody+1))
	if err != nil || len(b) > split.MaxBody {
		return nil, refuse(http.StatusRequestEntityTooLarge, "request too large")
	}
	return b, nil
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, err error) {
	status := http.StatusInternalServerError
	reason := "internal error"
	var r *Refused
	if errors.As(err, &r) {
		status, reason = r.Status, r.Reason
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(kms.Error{Error: reason})
}

// masterOnly is the break-glass holder's opener: it has no shares to open.
type masterOnly struct{}

func (masterOnly) Open(context.Context, split.HolderShare) ([]byte, error) {
	return nil, errors.New("holder: the break-glass holder has no shares")
}

// PublicKeyOf names a holder key as a share set recipient (kmsctl resplit takes these from each holder's deploy).
func PublicKeyOf(k *ecdh.PrivateKey) string { return split.RecipientString(k.PublicKey()) }
