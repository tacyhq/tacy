// Package server is kmsd, the Tacy key service (wire format: package kms). It keeps everything in memory: the
// master key M, the policy, the secrets bundle, leases, the generation register and the audit log. It writes no
// file and logs no key material, so the disk under it (whoever keys it) holds only public images.
//
// States: "empty" (no KMS id pinned: one genesis allowed), "locked" (a KMS id is pinned: waits for t offline shares
// or a peer's M) and "unlocked". Roles: the primary holds the leases and the register; a standby only keeps M
// (package kms, "One primary").
//
// Memory is bounded against anyone on the internet: request bodies (kms.MaxBody), outstanding challenges
// (kms.MaxChallenges, the oldest go first), the audit log (entries and bytes, each detail at most kms.MaxDetail),
// and refusals of requests that proved nothing, which are counted per reason rather than stored one by one. Costly
// unauthenticated work (challenges, quotes, attestation checks) is rate limited.
package server

import (
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/google/go-tdx-guest/verify/trust"

	"github.com/tacyhq/tacy/internal/tdx"
	"github.com/tacyhq/tacy/kms"
	"github.com/tacyhq/tacy/proto"
	"github.com/tacyhq/tacy/safety"
)

// Platform gives this TD's attestation evidence: dstack GetQuote and Info for reportData.
type Platform interface {
	Name() string // "dstack", or "local" (development: no quote)
	Evidence(ctx context.Context, reportData []byte) (quote, info json.RawMessage, err error)
}

// Config is kmsd's setup. Everything that decides trust comes from the attested compose (flags) or from documents
// signed by the admin keys.
type Config struct {
	Admin    kms.AdminKeys     // the offline admin keys: genesis, policy, secrets, generation confirmations
	KMSID    ed25519.PublicKey // pinned KMS id: start locked; nil: start empty (genesis allowed once)
	FloorMin string            // the compose's release floor; no policy can go below it ("" = none)
	Role     string            // kms.RolePrimary ("" too) or kms.RoleStandby
	Platform Platform
	// ReleaseBundle, when set, checks a release request's Sigstore bundle against the docker compose's sha256 and
	// the pinned version (tacy's signed-release check). Without it the admin-signed release pins are the check.
	ReleaseBundle func(bundle []byte, composeSHA256, version string) error
	Now           func() time.Time // nil = time.Now
	Rand          io.Reader        // nil = crypto/rand
	Logf          func(format string, args ...any)
	// MaxLog bounds the audit entries kept in memory and MaxLogBytes their size (oldest dropped; export them
	// first). 0 = 100000 entries, 16 MiB.
	MaxLog      int
	MaxLogBytes int
	// Limits on unauthenticated work, per second and burst (0 = the defaults below).
	Limits Limits

	// Attestation checking. Production leaves these zero.
	VerifyQuote   func(ctx context.Context, raw []byte) (*tdx.Quote, error) // tests: recorded quotes
	AllowStaleTCB bool                                                      // tests: recorded collateral
	Getter        trust.HTTPSGetter
	CheckNow      time.Time
	DevLocal      bool // accept platform "local" attestations (no quote): development only, never in a release
	// Staging: a staging key service for throwaways (kmsd -staging, in its attested compose): only then may a
	// policy let a VM's e2e overlay in (kms.Policy.AllowE2EDiag: the test tool's diag service). A production key
	// service refuses such a policy.
	Staging bool
}

// Limits are token buckets: Rate a second, up to Burst at once.
type Limits struct {
	Challenge, Attest, Refusal Bucket
}

// Bucket is one token bucket's rate (per second) and burst.
type Bucket struct {
	Rate  float64
	Burst float64
}

// DefaultLimits: challenges 20/s (a release needs one; the 4096 outstanding outlast any burst), quotes 5/s, and
// counted refusals 10/s before costly unauthenticated requests are answered 429 for a while.
var DefaultLimits = Limits{Challenge: Bucket{20, 200}, Attest: Bucket{5, 40}, Refusal: Bucket{10, 400}}

type bucket struct {
	Bucket
	tokens float64
	last   time.Time
}

func (b *bucket) take(now time.Time, n float64) bool {
	if b.last.IsZero() {
		b.tokens, b.last = b.Burst, now
	}
	if d := now.Sub(b.last).Seconds(); d > 0 {
		b.tokens = min(b.Burst, b.tokens+d*b.Rate)
		b.last = now
	}
	if b.tokens < n {
		return false
	}
	b.tokens -= n
	return true
}

func (b *bucket) empty(now time.Time) bool {
	if b.last.IsZero() {
		return false
	}
	return b.tokens+now.Sub(b.last).Seconds()*b.Rate < 1
}

type lease struct {
	kms.Lease
	secret    []byte
	lastRenew int64
	expAt     time.Time // Expires on this process's clock (monotonic when it is time.Now)
	reserved  string    // after a move to an instance: only it may take the lease, until Expires
	tags      []string  // the register prefixes this lease may commit (its store purposes' tags)
}

func (l *lease) live(now time.Time) bool { return l != nil && now.Before(l.expAt) }

// regEntry is one register entry: the latest generation (reserved or stored), the hash of the one before it.
type regEntry struct {
	gen    kms.Gen
	prev   string
	stored bool
}

// Server is one kmsd replica.
type Server struct {
	cfg     Config
	boot    *ecdh.PrivateKey // this boot's X25519 key, bound in /v1/attest
	bootHex string
	booted  time.Time

	mu           sync.Mutex
	master       []byte
	epoch        uint32
	id           ed25519.PrivateKey
	genesisEnv   *safety.Envelope
	genesis      *kms.GenesisDoc
	policyEnv    *safety.Envelope
	policy       *kms.Policy
	shares       map[byte][]byte
	commitments  []string // a locked replica's share commitments (signed by the pinned KMS id)
	nonces       map[string]time.Time
	nonceQ       []string          // the nonces in the order issued (some already used): the oldest go first when full
	leases       map[string]*lease // app ‖ 0 ‖ holder
	gens         map[string]*regEntry
	gensOK       bool
	confirmNonce string // while !gensOK on an unlocked primary: what a GenConfirm must name
	secretsEnv   []byte // the admin-signed SecretsDoc envelope, JSON
	secrets      *kms.SecretsDoc
	log          []kms.AuditEntry
	logBytes     int
	logHead      string
	logSeq       uint64
	refused      map[string]uint64 // counted refusals not yet written as a "refused" entry, by reason
	refusedTotal uint64
	lim          struct{ challenge, attest, refusal, flush bucket }
}

// New makes a replica: empty, or locked when cfg.KMSID is set.
func New(cfg Config) (*Server, error) {
	if cfg.Platform == nil {
		return nil, errors.New("kmsd: no platform")
	}
	if len(cfg.Admin.Keys) == 0 || cfg.Admin.Threshold < 1 || cfg.Admin.Threshold > len(cfg.Admin.Keys) {
		return nil, errors.New("kmsd: admin keys and threshold are required")
	}
	if cfg.KMSID != nil && len(cfg.KMSID) != ed25519.PublicKeySize {
		return nil, errors.New("kmsd: bad KMS id")
	}
	if cfg.FloorMin != "" {
		if _, ok := kms.CompareVersions(cfg.FloorMin, cfg.FloorMin); !ok {
			return nil, errors.New("kmsd: floor isn't vX.Y.Z")
		}
	}
	switch cfg.Role {
	case "":
		cfg.Role = kms.RolePrimary
	case kms.RolePrimary, kms.RoleStandby:
	default:
		return nil, fmt.Errorf("kmsd: role %q (want %s or %s)", cfg.Role, kms.RolePrimary, kms.RoleStandby)
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Rand == nil {
		cfg.Rand = rand.Reader
	}
	if cfg.Logf == nil {
		cfg.Logf = func(string, ...any) {}
	}
	if cfg.MaxLog <= 0 {
		cfg.MaxLog = 100000
	}
	if cfg.MaxLogBytes <= 0 {
		cfg.MaxLogBytes = 16 << 20
	}
	if cfg.Limits.Challenge.Rate == 0 {
		cfg.Limits.Challenge = DefaultLimits.Challenge
	}
	if cfg.Limits.Attest.Rate == 0 {
		cfg.Limits.Attest = DefaultLimits.Attest
	}
	if cfg.Limits.Refusal.Rate == 0 {
		cfg.Limits.Refusal = DefaultLimits.Refusal
	}
	boot, err := ecdh.X25519().GenerateKey(cfg.Rand)
	if err != nil {
		return nil, err
	}
	s := &Server{cfg: cfg, boot: boot, bootHex: hex.EncodeToString(boot.PublicKey().Bytes()), booted: cfg.Now(),
		shares: map[byte][]byte{}, nonces: map[string]time.Time{}, leases: map[string]*lease{}, gens: map[string]*regEntry{},
		refused: map[string]uint64{}}
	s.lim.challenge.Bucket, s.lim.attest.Bucket, s.lim.refusal.Bucket = cfg.Limits.Challenge, cfg.Limits.Attest, cfg.Limits.Refusal
	s.lim.flush.Bucket = Bucket{Rate: 1.0 / 60, Burst: 30} // "refused" entries: about one a minute at most, whoever asks
	s.mu.Lock()
	s.audit("start", true, "", "", "state "+s.stateLocked()+", role "+cfg.Role)
	s.mu.Unlock()
	return s, nil
}

// refusal is an error with the HTTP status it answers with. Its text is the reason (never key material). key is
// its format (the server's own words, never a caller's) and authed whether the caller proved anything first (a
// valid signature, MAC or attestation): only those refusals get an audit entry each; the others are counted by key.
type refusal struct {
	status int
	reason string
	key    string
	authed bool
}

func (r *refusal) Error() string { return r.reason }

// refuse is a refusal of a request that proved nothing (counted).
func refuse(status int, format string, args ...any) error {
	return &refusal{status: status, reason: fmt.Sprintf(format, args...), key: format}
}

// refuseA is a refusal of a request that proved who sent it (an audit entry of its own).
func refuseA(status int, format string, args ...any) error {
	return &refusal{status: status, reason: fmt.Sprintf(format, args...), key: format, authed: true}
}

// authed marks err as a refusal after the caller proved itself.
func authed(err error) error {
	var r *refusal
	if errors.As(err, &r) {
		c := *r
		c.authed = true
		return &c
	}
	return err
}

func errLocked() error { return refuse(http.StatusServiceUnavailable, "the key service is locked") }

func errStandby() error {
	return refuse(http.StatusMisdirectedRequest, "this replica is a standby: releases, leases and the register are the primary's")
}

func errUnconfirmed() error {
	return refuse(http.StatusServiceUnavailable, "the generations aren't confirmed since this replica got M (the admins' kms-gen)")
}

// Status reports the replica's state.
func (s *Server) Status() kms.Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.statusLocked()
}

func (s *Server) statusLocked() kms.Status {
	st := kms.Status{Version: kms.Version, State: s.stateLocked(), Role: s.cfg.Role, Epoch: s.epoch, Shares: len(s.shares),
		GensOK: s.gensOK, LogSeq: s.logSeq, LogHead: s.logHead, KMSID: s.kmsIDLocked(), Refused: s.refusedTotal}
	if s.policy != nil {
		st.PolicySeq = s.policy.Seq
	}
	if s.genesis != nil && s.master == nil {
		st.Threshold = s.genesis.Threshold
	}
	if s.secrets != nil {
		st.SecretSeq = s.secrets.Seq
	}
	if s.master != nil && !s.gensOK {
		st.ConfirmNonce = s.confirmNonce
	}
	return st
}

func (s *Server) stateLocked() string {
	switch {
	case s.master != nil:
		return "unlocked"
	case s.cfg.KMSID != nil:
		return "locked"
	default:
		return "empty"
	}
}

func (s *Server) kmsIDLocked() string {
	if s.id != nil {
		return kms.IDString(s.id.Public().(ed25519.PublicKey))
	}
	if s.cfg.KMSID != nil {
		return kms.IDString(s.cfg.KMSID)
	}
	return ""
}

// wantEpoch is the epoch documents for this replica name (1 until rotation exists; also while locked).
func (s *Server) wantEpoch() uint32 {
	if s.epoch == 0 {
		return 1
	}
	return s.epoch
}

// newConfirmNonce starts a wait for the admins' GenConfirm (s.mu held).
func (s *Server) newConfirmNonce() {
	s.confirmNonce = ""
	if s.cfg.Role != kms.RolePrimary {
		return
	}
	n := make([]byte, 32)
	if _, err := io.ReadFull(s.cfg.Rand, n); err == nil {
		s.confirmNonce = hex.EncodeToString(n)
	}
}

// cleanDetail cuts a detail to kms.MaxDetail bytes and escapes everything but printable text, so no caller's
// bytes can grow the log or forge a log line.
func cleanDetail(d string) string {
	var b strings.Builder
	i := 0
	for i < len(d) {
		r, n := utf8.DecodeRuneInString(d[i:])
		var piece string
		switch {
		case r == utf8.RuneError && n <= 1:
			piece = fmt.Sprintf(`\x%02x`, d[i])
		case r == '\\':
			piece = `\\`
		case r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0):
			q := strconv.QuoteRune(r)
			piece = q[1 : len(q)-1]
		default:
			piece = d[i : i+n]
		}
		if b.Len()+len(piece) > kms.MaxDetail {
			break
		}
		b.WriteString(piece)
		i += n
	}
	if i < len(d) {
		return b.String() + "…"
	}
	return b.String()
}

// audit appends an entry (s.mu held) and returns its seq, after an entry for the refusals counted since the last.
// Entries made before M is known are signed when it is.
func (s *Server) audit(kind string, ok bool, app, instance, detail string) uint64 {
	s.flushRefusals()
	return s.appendEntry(kind, ok, app, instance, detail)
}

func (s *Server) appendEntry(kind string, ok bool, app, instance, detail string) uint64 {
	s.logSeq++
	e := kms.AuditEntry{Seq: s.logSeq, Time: s.cfg.Now().Unix(), Kind: kind, OK: ok, App: cleanDetail(app),
		Instance: cleanDetail(instance), Detail: cleanDetail(detail), Prev: s.logHead}
	e.Hash = kms.AuditHash(e)
	if s.id != nil {
		e.Sig = ed25519.Sign(s.id, kms.AuditSigMessage(e.Hash))
	}
	s.logHead = e.Hash
	s.log = append(s.log, e)
	s.logBytes += entrySize(e)
	drop := 0
	for len(s.log)-drop > s.cfg.MaxLog || (s.logBytes > s.cfg.MaxLogBytes && len(s.log)-drop > 1) {
		s.logBytes -= entrySize(s.log[drop])
		drop++
	}
	if drop > 0 {
		s.log = append([]kms.AuditEntry(nil), s.log[drop:]...)
	}
	// What the log line says is what the audit entry says: kinds, apps, instances and reasons, no key material.
	s.cfg.Logf("kmsd: %s ok=%v app=%q instance=%q %s", kind, ok, e.App, e.Instance, e.Detail)
	return e.Seq
}

func entrySize(e kms.AuditEntry) int {
	return 64 + len(e.Kind) + len(e.App) + len(e.Instance) + len(e.Detail) + len(e.Prev) + len(e.Hash) + len(e.Sig)
}

// count records a refusal of a request that proved nothing (s.mu held): its reason's format, counted.
func (s *Server) count(what, key string) {
	s.refusedTotal++
	k := what + ": " + key
	if _, ok := s.refused[k]; ok || len(s.refused) < 64 {
		s.refused[k]++
	} else {
		s.refused["other"]++
	}
	s.lim.refusal.take(s.cfg.Now(), 1)
}

// flushRefusals writes the counted refusals as one "refused" entry (s.mu held): at most about one a minute (a
// burst of 30), so no caller can turn refusals into entries faster than that; meanwhile they stay counted.
func (s *Server) flushRefusals() {
	if len(s.refused) == 0 || !s.lim.flush.take(s.cfg.Now(), 1) {
		return
	}
	keys := make([]string, 0, len(s.refused))
	var total uint64
	for k, n := range s.refused {
		keys = append(keys, k)
		total += n
	}
	sort.Slice(keys, func(i, j int) bool {
		if s.refused[keys[i]] != s.refused[keys[j]] {
			return s.refused[keys[i]] > s.refused[keys[j]]
		}
		return keys[i] < keys[j]
	})
	parts := []string{fmt.Sprintf("%d unauthenticated", total)}
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s ×%d", k, s.refused[k]))
	}
	clear(s.refused)
	s.appendEntry("refused", false, "", "", strings.Join(parts, "; "))
}

// recordRefusal is the audit of a refused request (s.mu held): an entry of its own when the caller proved itself,
// else a count.
func (s *Server) recordRefusal(what, app, instance string, err error) {
	var r *refusal
	if errors.As(err, &r) && !r.authed {
		s.count(what, r.key)
		return
	}
	s.audit("refuse", false, app, instance, what+": "+err.Error())
}

// signPending signs the entries made before M was known (s.mu held, s.id set).
func (s *Server) signPending() {
	for i := range s.log {
		if s.log[i].Sig == nil {
			s.log[i].Sig = ed25519.Sign(s.id, kms.AuditSigMessage(s.log[i].Hash))
		}
	}
}

// Log returns the entries with seq >= from (at most limit), the counted refusals written first.
func (s *Server) Log(from uint64, limit int) []kms.AuditEntry {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.flushRefusals()
	var out []kms.AuditEntry
	for _, e := range s.log {
		if e.Seq >= from && len(out) < limit {
			out = append(out, e)
		}
	}
	return out
}

// Challenge issues a single-use nonce. When kms.MaxChallenges are outstanding the oldest is dropped: the rate limit
// keeps anyone from churning through them faster than a VM uses its own.
func (s *Server) Challenge() (kms.Challenge, error) {
	n := make([]byte, 32)
	if _, err := io.ReadFull(s.cfg.Rand, n); err != nil {
		return kms.Challenge{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.cfg.Now()
	if !s.lim.challenge.take(now, 1) {
		return kms.Challenge{}, refuse(http.StatusTooManyRequests, "too many challenges; try again shortly")
	}
	for k, exp := range s.nonces {
		if now.After(exp) {
			delete(s.nonces, k)
		}
	}
	for len(s.nonces) >= kms.MaxChallenges && len(s.nonceQ) > 0 {
		delete(s.nonces, s.nonceQ[0])
		s.nonceQ = s.nonceQ[1:]
	}
	if len(s.nonceQ) > 2*kms.MaxChallenges { // drop the used and expired ones from the queue
		q := s.nonceQ[:0:0]
		for _, k := range s.nonceQ {
			if _, ok := s.nonces[k]; ok {
				q = append(q, k)
			}
		}
		s.nonceQ = q
	}
	exp := now.Add(kms.ChallengeTTL)
	s.nonces[hex.EncodeToString(n)] = exp
	s.nonceQ = append(s.nonceQ, hex.EncodeToString(n))
	return kms.Challenge{Nonce: hex.EncodeToString(n), Expires: exp.Unix()}, nil
}

// takeNonce consumes a nonce this replica issued (s.mu not held).
func (s *Server) takeNonce(h string) ([]byte, error) {
	n, err := hex.DecodeString(h)
	if err != nil || len(n) != 32 {
		return nil, refuse(http.StatusBadRequest, "nonce isn't 32 bytes of hex")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	exp, ok := s.nonces[h]
	delete(s.nonces, h)
	if !ok || s.cfg.Now().After(exp) {
		return nil, refuse(http.StatusForbidden, "unknown, used or expired nonce")
	}
	return n, nil
}

// Attest is this replica's attestation for nonce: its boot key bound in the quote's report_data.
func (s *Server) Attest(ctx context.Context, nonce []byte) (json.RawMessage, error) {
	if len(nonce) != 32 {
		return nil, refuse(http.StatusBadRequest, "nonce must be 32 bytes")
	}
	quote, info, err := s.cfg.Platform.Evidence(ctx, proto.ReportData(nonce, s.boot.PublicKey().Bytes()))
	if err != nil {
		return nil, refuse(http.StatusServiceUnavailable, "attestation unavailable: %v", err)
	}
	att := proto.Attestation{Version: proto.Version, Platform: s.cfg.Platform.Name(), Nonce: hex.EncodeToString(nonce),
		HPKEPublicKey: s.bootHex, HPKESuite: proto.HPKESuite, Quote: quote, Info: info,
		Booted: s.booted.UTC().Format(time.RFC3339)}
	return json.Marshal(att)
}

// throttled says whether costly unauthenticated work is paused (refusals came faster than Limits.Refusal).
func (s *Server) throttled() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lim.refusal.empty(s.cfg.Now())
}

func errThrottled() error {
	return refuse(http.StatusTooManyRequests, "too many refused requests; try again shortly")
}

// Handler serves the wire format.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	get := func(path string, f func(r *http.Request) (any, error)) {
		mux.HandleFunc("GET "+path, func(w http.ResponseWriter, r *http.Request) {
			v, err := f(r)
			reply(w, v, err)
		})
	}
	post := func(path string, costly bool, f func(ctx context.Context, body []byte) (any, error)) {
		mux.HandleFunc("POST "+path, func(w http.ResponseWriter, r *http.Request) {
			if costly && s.throttled() {
				reply(w, nil, errThrottled())
				return
			}
			b, err := io.ReadAll(http.MaxBytesReader(w, r.Body, kms.MaxBody))
			if err != nil {
				reply(w, nil, refuse(http.StatusRequestEntityTooLarge, "body too large"))
				return
			}
			v, err := f(r.Context(), b)
			reply(w, v, err)
		})
	}
	// decode is a strict decode whose failure is counted (the caller proved nothing).
	decode := func(what string, b []byte, v any) error {
		if err := kms.Strict(b, v); err != nil {
			s.mu.Lock()
			s.count(what, "bad request body")
			s.mu.Unlock()
			return refuse(http.StatusBadRequest, "bad %s request: %v", what, err)
		}
		return nil
	}
	get("/v1/status", func(*http.Request) (any, error) { return s.Status(), nil })
	get("/v1/challenge", func(*http.Request) (any, error) {
		if s.throttled() {
			return nil, errThrottled()
		}
		return s.Challenge()
	})
	get("/v1/attest", func(r *http.Request) (any, error) {
		n, err := hex.DecodeString(r.URL.Query().Get("nonce"))
		if err != nil || len(n) != 32 {
			return nil, refuse(http.StatusBadRequest, "nonce must be 64 hex")
		}
		s.mu.Lock()
		ok := s.lim.attest.take(s.cfg.Now(), 1)
		s.mu.Unlock()
		if !ok || s.throttled() {
			return nil, refuse(http.StatusTooManyRequests, "too many attestations; try again shortly")
		}
		b, err := s.Attest(r.Context(), n)
		return json.RawMessage(b), err
	})
	get("/v1/gen", func(r *http.Request) (any, error) {
		q := r.URL.Query()
		return s.Generation(q.Get("app"), q.Get("name"), q.Get("nonce"))
	})
	get("/v1/gen/snapshot", func(r *http.Request) (any, error) { return s.Snapshot(r.URL.Query().Get("nonce")) })
	get("/v1/log", func(r *http.Request) (any, error) {
		from, _ := strconv.ParseUint(r.URL.Query().Get("from"), 10, 64)
		return s.Log(from, 1000), nil
	})
	post("/v1/release", true, func(ctx context.Context, b []byte) (any, error) {
		var req kms.ReleaseRequest
		if err := decode("release", b, &req); err != nil {
			return nil, err
		}
		return s.Release(ctx, req)
	})
	post("/v1/lease/renew", false, func(_ context.Context, b []byte) (any, error) {
		var req kms.LeaseRenew
		if err := decode("renewal", b, &req); err != nil {
			return nil, err
		}
		return s.Renew(req)
	})
	post("/v1/lease/drop", false, func(_ context.Context, b []byte) (any, error) {
		var req kms.LeaseRenew
		if err := decode("drop", b, &req); err != nil {
			return nil, err
		}
		return s.Drop(req)
	})
	post("/v1/lease/move", false, func(_ context.Context, b []byte) (any, error) {
		var e safety.Envelope
		if err := decode("lease move", b, &e); err != nil {
			return nil, err
		}
		return s.MoveLease(&e)
	})
	post("/v1/gen/commit", false, func(_ context.Context, b []byte) (any, error) {
		var req kms.GenCommit
		if err := decode("commit", b, &req); err != nil {
			return nil, err
		}
		return s.Commit(req)
	})
	post("/v1/gen/confirm", false, func(_ context.Context, b []byte) (any, error) {
		var e safety.Envelope
		if err := decode("confirmation", b, &e); err != nil {
			return nil, err
		}
		return s.ConfirmGens(&e)
	})
	post("/v1/genesis", true, func(_ context.Context, b []byte) (any, error) {
		var req kms.GenesisRequest
		if err := decode("genesis", b, &req); err != nil {
			return nil, err
		}
		return s.Genesis(req)
	})
	post("/v1/unlock", true, func(_ context.Context, b []byte) (any, error) {
		var req kms.UnlockRequest
		if err := decode("unlock", b, &req); err != nil {
			return nil, err
		}
		return s.Unlock(req)
	})
	post("/v1/peer/join", true, func(ctx context.Context, b []byte) (any, error) {
		var req kms.JoinRequest
		if err := decode("join", b, &req); err != nil {
			return nil, err
		}
		return s.Join(ctx, req)
	})
	post("/v1/policy", false, func(_ context.Context, b []byte) (any, error) {
		var e safety.Envelope
		if err := decode("policy", b, &e); err != nil {
			return nil, err
		}
		return s.SetPolicy(&e)
	})
	post("/v1/secrets/put", false, func(_ context.Context, b []byte) (any, error) {
		var req kms.SecretsPut
		if err := decode("secrets", b, &req); err != nil {
			return nil, err
		}
		return s.PutSecrets(req)
	})
	post("/v1/secrets/load", false, func(_ context.Context, b []byte) (any, error) {
		var req kms.SecretsLoad
		if err := decode("secrets", b, &req); err != nil {
			return nil, err
		}
		return s.LoadSecrets(req.Sealed)
	})
	return mux
}

func reply(w http.ResponseWriter, v any, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if err != nil {
		status := http.StatusInternalServerError
		var r *refusal
		if errors.As(err, &r) {
			status = r.status
		}
		w.WriteHeader(status)
		json.NewEncoder(w).Encode(kms.Error{Error: err.Error()})
		return
	}
	json.NewEncoder(w).Encode(v)
}
