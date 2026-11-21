package split

import (
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/tacyhq/tacy/kms"
	"github.com/tacyhq/tacy/kms/client"
	"github.com/tacyhq/tacy/safety"
)

// Holder is one holder as the VM reaches it (in the VM, through gatewayd: the only process with a network).
type Holder struct {
	ID        string
	Transport client.Transport
}

// Config is an unlock's setup.
type Config struct {
	// KMSID is the pinned KMS id (the release compose's -kms-key): share sets and epoch certificates must be signed
	// by it.
	KMSID ed25519.PublicKey
	// Admin are the admin's admin keys the VM pins (its compose): the policy it unlocks with must carry their
	// signatures, so a forged holder list or share set never reaches it (privacy review 2026-11-20). Required.
	Admin *kms.AdminKeys
	// MinEpoch is the lowest epoch the VM accepts (its compose pins it; raised by the release after a re-split to
	// e+1), so serving it an old share set or an old-epoch break-glass reply can't undo the re-split. Required.
	MinEpoch uint32
	// Policy is the admin-signed unlock policy (safety.Envelope JSON): the newest one, fetched from the Worker at
	// every unlock (holders refuse an older one once they have seen a newer one).
	Policy json.RawMessage
	// Holders reach the holders by id. Every holder the policy and its share set name must be here; extra ones are
	// ignored.
	Holders  []Holder
	Evidence client.Evidence
	Platform string // "dstack"; "local" only against development holders
	Release  string // this VM's release (vX.Y.Z), sent as a claim
	// StartTicket is the Worker's start ticket for this start (sent to every holder; required when the policy
	// names start-ticket keys).
	StartTicket json.RawMessage
	// BreakGlass reaches the policy's break-glass relay (nil: none). Asked only after every share set failed; it
	// answers only while the admin runs kmsctl break-glass.
	BreakGlass client.Transport
	Timeout    time.Duration
	Now        func() time.Time

	certs      map[uint32]*EpochCert // the policy's, once opened
	policyHash string                // PolicyHash of the policy's payload: every reply must be under it
}

// Root is an epoch's VM root R_e after an unlock, with its epoch certificate. Derive what the VM needs, then Drop it. There is no M here and no KMS
// id private key.
type Root struct {
	r     []byte
	KMSID string
	Epoch uint32
	Set   uint32
	Cert  *EpochCert
}

// WitnessKey is the epoch's witness key (WitnessKey of R_e): what the VM signs its freshness record ops with.
func (r *Root) WitnessKey() (ed25519.PrivateKey, error) {
	if r.r == nil {
		return nil, errors.New("split: root dropped")
	}
	return WitnessKey(r.r, r.Cert.App, r.Cert.Firm, r.Epoch)
}

// Key is a per-purpose key (RootKey).
func (r *Root) Key(app, firm, purpose string) ([]byte, error) {
	if r.r == nil {
		return nil, errors.New("split: root dropped")
	}
	return RootKey(r.r, app, firm, purpose, r.Epoch)
}

// OpenSecrets opens the epoch's sealed secrets bundle (from the Worker).
func (r *Root) OpenSecrets(sealed []byte) (*SecretsBundle, error) {
	if r.r == nil {
		return nil, errors.New("split: root dropped")
	}
	return OpenSecrets(r.r, r.KMSID, r.Epoch, sealed)
}

// StoreCert is the epoch certificate's store certificate for purpose (the Worker's state API checks it).
func (r *Root) StoreCert(purpose string) (kms.StoreCert, error) {
	c, ok := r.Cert.StoreCerts[purpose]
	if !ok {
		return kms.StoreCert{}, fmt.Errorf("split: the epoch certificate has no %s store certificate", purpose)
	}
	return c, nil
}

// Drop clears R_e.
func (r *Root) Drop() {
	clear(r.r)
	r.r = nil
}

// Report says what each holder did in an unlock (for the VM's audit log and the Worker's alerts): "ok", or why it
// was skipped or refused. Never key material.
type Report struct {
	Set     uint32            // the share set that rebuilt R_e (0: break-glass, or none)
	Outcome map[string]string // per holder, for the last set tried
	Used    []string          // the holders whose shares rebuilt R_e
	// Tried: every set tried, newest first, with its per-holder outcomes (an older set is tried only when a newer
	// one didn't unlock; break-glass last, as set 0).
	Tried []SetReport
}

// SetReport is one share set's attempt.
type SetReport struct {
	Set     uint32
	Outcome map[string]string
	Err     string
}

// ErrNotEnough: fewer than the threshold of holders gave a share that checks.
var ErrNotEnough = errors.New("split: not enough holders gave a valid share")

// Unlock rebuilds an epoch's VM root from the policy's holders, trying the policy's share sets newest first (the
// old set stays usable while a re-split overlaps it): for a set, a nonce from each of its holders, one quote binding
// all of them and an in-memory key, each holder's sealed share, any threshold of shares that match their
// commitments, and R_e only if its root id is the share set's (signed by the pinned KMS id).
func Unlock(ctx context.Context, cfg Config) (*Root, *Report, error) {
	rep := &Report{Outcome: map[string]string{}}
	if len(cfg.KMSID) != ed25519.PublicKeySize || cfg.Evidence == nil || cfg.Admin == nil || cfg.MinEpoch == 0 {
		return nil, rep, errors.New("split: unlock needs the pinned KMS id, admin keys, minimum epoch and evidence")
	}
	if cfg.Platform == "" {
		cfg.Platform = "dstack"
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 20 * time.Second
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	pol, sets, certs, err := cfg.openPolicy()
	if err != nil {
		return nil, rep, err
	}
	var last error
	for _, set := range sets {
		if set.Epoch < cfg.MinEpoch {
			rep.Tried = append(rep.Tried, SetReport{Set: set.Set, Err: fmt.Sprintf("epoch %d is below this release's minimum %d", set.Epoch, cfg.MinEpoch)})
			continue
		}
		out := map[string]string{}
		r, used, err := cfg.unlockSet(ctx, pol, set, certs[set.Epoch], out)
		sr := SetReport{Set: set.Set, Outcome: out}
		if err != nil {
			sr.Err = err.Error()
		}
		rep.Tried, rep.Outcome = append(rep.Tried, sr), out
		if err == nil {
			rep.Set, rep.Used = set.Set, used
			return r, rep, nil
		}
		last = err
	}
	if cfg.BreakGlass != nil && pol.BreakGlass != "" && pol.Epoch >= cfg.MinEpoch {
		r, err := cfg.breakGlass(ctx, pol, certs[pol.Epoch])
		sr := SetReport{Set: 0, Outcome: map[string]string{BreakGlassHolder: "ok"}}
		if err != nil {
			sr.Outcome[BreakGlassHolder], sr.Err = err.Error(), err.Error()
		}
		rep.Tried = append(rep.Tried, sr)
		if err == nil {
			rep.Set, rep.Used, rep.Outcome = 0, []string{BreakGlassHolder}, sr.Outcome
			return r, rep, nil
		}
	}
	if last == nil {
		last = fmt.Errorf("%w: no share set this release may use", ErrNotEnough)
	}
	return nil, rep, last
}

// checkRoot keeps root only if its root id is want.
func checkRoot(root []byte, want string) error {
	rid, err := RootID(root)
	if err != nil || rid != want {
		return errors.New("the rebuilt root isn't the epoch's (its root id differs)")
	}
	return nil
}

// breakGlass asks the admin's break-glass relay for R_e of the policy's epoch (one boot, admin present).
func (cfg *Config) breakGlass(ctx context.Context, pol *UnlockPolicy, cert *EpochCert) (*Root, error) {
	if cert == nil {
		return nil, fmt.Errorf("break-glass: no epoch certificate for epoch %d", pol.Epoch)
	}
	ctx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()
	b, err := cfg.BreakGlass.Do(ctx, http.MethodGet, "/v1/challenge", nil)
	if err != nil {
		return nil, fmt.Errorf("break-glass challenge: %w", err)
	}
	var ch Challenge
	if err := kms.Strict(b, &ch); err != nil || ch.Holder != BreakGlassHolder {
		return nil, errors.New("break-glass challenge isn't the admin's")
	}
	hn := []HolderNonce{{Holder: BreakGlassHolder, Nonce: ch.Nonce}}
	bound, err := Bind(hn)
	if err != nil {
		return nil, err
	}
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	att, err := client.AttestWith(ctx, cfg.Evidence, cfg.Platform, bound, priv)
	if err != nil {
		return nil, err
	}
	req, _ := json.Marshal(UnlockRequest{Nonces: hn, Attestation: att, Policy: cfg.Policy, Set: 0, Release: cfg.Release,
		StartTicket: cfg.StartTicket})
	b, err = cfg.BreakGlass.Do(ctx, http.MethodPost, "/v1/unlock", req)
	if err != nil {
		return nil, fmt.Errorf("break-glass: %w", err)
	}
	var r UnlockReply
	if err := kms.Strict(b, &r); err != nil {
		return nil, fmt.Errorf("break-glass reply: %w", err)
	}
	if r.Holder != BreakGlassHolder || r.Set != 0 || r.Index != 0 || r.KMSID != pol.KMSID || r.Epoch != pol.Epoch {
		return nil, errors.New("break-glass reply names another holder, set, KMS id or epoch")
	}
	root, err := kms.Open(priv, LabelBreakGlass, ReplyAAD(bound, pol.KMSID, pol.Epoch, 0, BreakGlassHolder, 0, cfg.policyHash), r.Sealed)
	if err != nil {
		return nil, errors.New("break-glass reply doesn't open with this boot's key")
	}
	if err := checkRoot(root, cert.Root); err != nil {
		clear(root)
		return nil, errors.New("break-glass reply isn't the epoch's root")
	}
	return &Root{r: root, KMSID: pol.KMSID, Epoch: pol.Epoch, Cert: cert}, nil
}

// unlockSet is one share set's attempt; out gets each holder's outcome.
func (cfg *Config) unlockSet(ctx context.Context, pol *UnlockPolicy, set *ShareSet, cert *EpochCert, out map[string]string) (*Root, []string, error) {
	byID := map[string]client.Transport{}
	for _, h := range cfg.Holders {
		byID[h.ID] = h.Transport
	}
	var ids []string
	for _, h := range pol.Holders {
		if _, ok := set.Holder(h.Holder); !ok {
			out[h.Holder] = "not in the share set"
			continue
		}
		if byID[h.Holder] == nil {
			out[h.Holder] = "no transport"
			continue
		}
		ids = append(ids, h.Holder)
	}
	sort.Strings(ids)

	// 1. A nonce from each holder, in parallel.
	nonces := map[string]string{}
	var mu sync.Mutex
	parallel(ctx, cfg.Timeout, ids, func(ctx context.Context, id string) {
		b, err := byID[id].Do(ctx, http.MethodGet, "/v1/challenge", nil)
		var ch Challenge
		if err == nil {
			err = kms.Strict(b, &ch)
		}
		if err == nil && ch.Holder != id {
			err = fmt.Errorf("challenge names holder %q", ch.Holder)
		}
		mu.Lock()
		defer mu.Unlock()
		if err != nil {
			out[id] = "challenge: " + err.Error()
			return
		}
		nonces[id] = ch.Nonce
	})
	if len(nonces) < set.Threshold {
		return nil, nil, fmt.Errorf("%w: %d of %d holders answered a challenge", ErrNotEnough, len(nonces), set.Threshold)
	}

	// 2. One quote binding every nonce and a fresh in-memory key.
	var hn []HolderNonce
	for _, id := range ids {
		if n, ok := nonces[id]; ok {
			hn = append(hn, HolderNonce{Holder: id, Nonce: n})
		}
	}
	bound, err := Bind(hn)
	if err != nil {
		return nil, nil, err
	}
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	att, err := client.AttestWith(ctx, cfg.Evidence, cfg.Platform, bound, priv)
	if err != nil {
		return nil, nil, err
	}
	req, _ := json.Marshal(UnlockRequest{Nonces: hn, Attestation: att, Policy: cfg.Policy, Set: set.Set, Release: cfg.Release,
		StartTicket: cfg.StartTicket})

	// 3. Each holder's share, in parallel; a share is kept only if it matches its commitment.
	shares := map[string]kms.Share{}
	var asked []string
	for _, n := range hn {
		asked = append(asked, n.Holder)
	}
	parallel(ctx, cfg.Timeout, asked, func(ctx context.Context, id string) {
		y, idx, err := askShare(ctx, byID[id], req, id, set, bound, cfg.policyHash, priv)
		mu.Lock()
		defer mu.Unlock()
		if err != nil {
			out[id] = "unlock: " + err.Error()
			return
		}
		shares[id] = kms.Share{X: idx, Y: y}
		out[id] = "ok"
	})
	defer func() {
		for _, s := range shares {
			clear(s.Y)
		}
	}()
	if len(shares) < set.Threshold {
		return nil, nil, fmt.Errorf("%w: %d of %d needed", ErrNotEnough, len(shares), set.Threshold)
	}

	// 4. Any threshold of checked shares gives R_e; its root id must be the share set's.
	var got []string
	for id := range shares {
		got = append(got, id)
	}
	sort.Strings(got)
	use := got[:set.Threshold]
	parts := make([]kms.Share, 0, len(use))
	for _, id := range use {
		parts = append(parts, shares[id])
	}
	root, err := kms.Combine(parts)
	if err != nil {
		return nil, nil, err
	}
	if err := checkRoot(root, set.Root); err != nil {
		clear(root)
		return nil, nil, fmt.Errorf("split: %w", err)
	}
	return &Root{r: root, KMSID: set.KMSID, Epoch: set.Epoch, Set: set.Set, Cert: cert}, use, nil
}

// openPolicy reads the unlock policy (and checks the admin keys when the VM pins them), its share sets (newest
// first) and its epoch certificates, each signed by the pinned KMS id.
func (cfg *Config) openPolicy() (*UnlockPolicy, []*ShareSet, map[uint32]*EpochCert, error) {
	var env safety.Envelope
	if err := kms.Strict(cfg.Policy, &env); err != nil {
		return nil, nil, nil, fmt.Errorf("split: policy envelope: %w", err)
	}
	var pol UnlockPolicy
	if err := cfg.Admin.Open(&env, KindUnlockPolicy, &pol); err != nil {
		return nil, nil, nil, fmt.Errorf("split: policy: %w", err)
	}
	cfg.policyHash = PolicyHash(env.Payload)
	if err := pol.Validate(); err != nil {
		return nil, nil, nil, err
	}
	if pol.KMSID != kms.IDString(cfg.KMSID) {
		return nil, nil, nil, errors.New("split: policy is for another KMS id")
	}
	if pol.Epoch < cfg.MinEpoch {
		return nil, nil, nil, fmt.Errorf("split: the policy's epoch %d is below this release's minimum %d", pol.Epoch, cfg.MinEpoch)
	}
	sets, err := pol.OpenShareSets(cfg.KMSID)
	if err != nil {
		return nil, nil, nil, err
	}
	certs, _ := pol.OpenEpochCerts(cfg.KMSID) // checked by OpenShareSets
	cfg.certs = certs
	return &pol, sets, certs, nil
}

// askShare sends the unlock request to one holder and opens its reply: the holder, index, KMS id, epoch and set
// must be its share set entry's, and the share its commitment.
func askShare(ctx context.Context, t client.Transport, req []byte, id string, set *ShareSet, bound []byte, policyHash string,
	priv *ecdh.PrivateKey) ([]byte, byte, error) {
	b, err := t.Do(ctx, http.MethodPost, "/v1/unlock", req)
	if err != nil {
		return nil, 0, err
	}
	var r UnlockReply
	if err := kms.Strict(b, &r); err != nil {
		return nil, 0, fmt.Errorf("reply: %w", err)
	}
	e, _ := set.Holder(id)
	if r.Holder != id || r.Index != e.Index || r.KMSID != set.KMSID || r.Epoch != set.Epoch || r.Set != set.Set {
		return nil, 0, errors.New("reply names another holder, index, KMS id, epoch or set")
	}
	y, err := kms.Open(priv, LabelReply, ReplyAAD(bound, set.KMSID, set.Epoch, set.Set, id, e.Index, policyHash), r.Sealed)
	if err != nil {
		return nil, 0, errors.New("reply doesn't open with this boot's key (a reply under another policy)")
	}
	if Commitment(set.KMSID, set.Epoch, set.Set, id, e.Index, y) != e.Commitment {
		clear(y)
		return nil, 0, errors.New("share doesn't match its commitment")
	}
	return y, e.Index, nil
}

func parallel(ctx context.Context, timeout time.Duration, ids []string, f func(context.Context, string)) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var wg sync.WaitGroup
	for _, id := range slices.Clone(ids) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			f(ctx, id)
		}()
	}
	wg.Wait()
}
