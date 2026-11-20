package server

import (
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"slices"
	"sort"
	"strings"

	"github.com/tacyhq/tacy/kms"
	"github.com/tacyhq/tacy/safety"
)

// primaryOnly refuses what only the primary serves (s.mu held).
func (s *Server) primaryOnly() error {
	if s.cfg.Role != kms.RolePrimary {
		return errStandby()
	}
	if s.master == nil {
		return errLocked()
	}
	if !s.gensOK {
		return errUnconfirmed()
	}
	return nil
}

// Release checks a VM and, if every check passes, returns its keys sealed to its attested key and signed by the
// KMS id. A refusal says why (in the audit log: an entry of its own once the attestation verified, else counted)
// and carries nothing else.
func (s *Server) Release(ctx context.Context, req kms.ReleaseRequest) (*kms.ReleaseReply, error) {
	rep, app, inst, err := s.release(ctx, req)
	if err != nil {
		s.mu.Lock()
		s.recordRefusal("release", app, inst, err)
		s.mu.Unlock()
		return nil, err
	}
	return rep, nil
}

func (s *Server) release(ctx context.Context, req kms.ReleaseRequest) (*kms.ReleaseReply, string, string, error) {
	s.mu.Lock()
	err, pol := s.primaryOnly(), s.policy
	s.mu.Unlock()
	if err != nil {
		return nil, "", "", err
	}
	if pol == nil {
		return nil, "", "", refuse(http.StatusServiceUnavailable, "no policy loaded")
	}
	if !kms.ValidHolder(req.Holder) {
		return nil, "", "", refuse(http.StatusBadRequest, "holder must be a short lowercase name")
	}
	if len(req.Purposes) == 0 || len(req.Purposes) > len(kms.Purposes) {
		return nil, "", "", refuse(http.StatusBadRequest, "purposes: 1 to %d", len(kms.Purposes))
	}
	for i, p := range req.Purposes {
		if !slices.Contains(kms.Purposes, p) || slices.Contains(req.Purposes[:i], p) {
			return nil, "", "", refuse(http.StatusBadRequest, "a purpose is unknown or repeated")
		}
	}
	nonce, err := s.takeNonce(req.Nonce)
	if err != nil {
		return nil, "", "", err
	}
	a, err := VerifyVM(ctx, req.Attestation, nonce, pol, s.checkOptions())
	if err != nil {
		return nil, "", "", err
	}
	// From here the caller is an attested VM running a pinned release: each refusal gets its own audit entry.
	app, inst := a.Pin.App, a.Instance
	ap, ok := pol.Apps[app]
	if !ok {
		return nil, app, inst, refuseA(http.StatusForbidden, "app %s has no grant", app)
	}
	if req.Release != "" && req.Release != a.Pin.Version {
		return nil, app, inst, refuseA(http.StatusForbidden, "release %s claimed, %s pinned for this app-compose", req.Release, a.Pin.Version)
	}
	for _, f := range []struct{ what, v string }{{"policy floor", pol.Floor}, {"app floor", ap.Floor}, {"compose floor", s.cfg.FloorMin}, {"genesis floor", s.genesisFloor()}} {
		if f.v == "" {
			continue
		}
		if c, ok := kms.CompareVersions(a.Pin.Version, f.v); !ok || c < 0 {
			return nil, app, inst, refuseA(http.StatusForbidden, "release %s is below the %s %s", a.Pin.Version, f.what, f.v)
		}
	}
	if s.cfg.ReleaseBundle != nil {
		dc, _ := kms.DockerCompose(mustAppCompose(req.Attestation))
		d := sha256.Sum256([]byte(dc))
		if err := s.cfg.ReleaseBundle(req.ReleaseBundle, hex.EncodeToString(d[:]), a.Pin.Version); err != nil {
			return nil, app, inst, refuseA(http.StatusForbidden, "release bundle: %v", err)
		}
	}
	for _, p := range req.Purposes {
		if !slices.Contains(ap.Purposes, p) {
			return nil, app, inst, refuseA(http.StatusForbidden, "app %s may not have %s", app, p)
		}
	}
	var tags []string
	for _, p := range req.Purposes {
		if slices.Contains(kms.StorePurposes, p) {
			tags = append(tags, purposeTag(p))
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.primaryOnly(); err != nil {
		return nil, app, inst, err
	}
	l, err := s.takeLease(app, req.Holder, inst, hex.EncodeToString(a.Key.Bytes()), tags)
	if err != nil {
		return nil, app, inst, authed(err)
	}
	p := kms.ReleasePayload{App: app, Firm: ap.Firm, Release: a.Pin.Version, Epoch: s.epoch, Keys: map[string][]byte{},
		Lease: l.Lease, LeaseSecret: l.secret}
	for _, pu := range req.Purposes {
		k, err := kms.DeriveKey(s.master, app, ap.Firm, pu, s.epoch)
		if err != nil {
			return nil, app, inst, err
		}
		p.Keys[pu] = k
		if slices.Contains(kms.StorePurposes, pu) {
			sk, err := kms.StoreAuthKey(k)
			if err != nil {
				return nil, app, inst, err
			}
			c := kms.StoreCert{App: app, Firm: ap.Firm, Epoch: s.epoch, Purpose: pu, Key: kms.IDString(sk.Public().(ed25519.PublicKey))}
			clear(sk)
			c.Sig = ed25519.Sign(s.id, kms.StoreCertMessage(c))
			if p.Certs == nil {
				p.Certs = map[string]kms.StoreCert{}
			}
			p.Certs[pu] = c
		}
	}
	// Our API keys go only to the process that asks for SecretsPurpose (vaultd), never to agentd.
	if len(ap.Secrets) > 0 && slices.Contains(req.Purposes, kms.SecretsPurpose) {
		if s.secrets == nil {
			return nil, app, inst, refuseA(http.StatusServiceUnavailable, "no secrets bundle loaded")
		}
		p.Secrets = map[string]string{}
		for _, n := range ap.Secrets {
			v, ok := s.secrets.Values[n]
			if !ok {
				return nil, app, inst, refuseA(http.StatusServiceUnavailable, "secrets bundle has no %s", n)
			}
			p.Secrets[n] = v
		}
	}
	pt, err := json.Marshal(p)
	for _, k := range p.Keys {
		clear(k)
	}
	if err != nil {
		return nil, app, inst, err
	}
	sealed, err := kms.Seal(a.Key, kms.LabelRelease, nonce, pt)
	clear(pt)
	if err != nil {
		return nil, app, inst, err
	}
	seq := s.audit("release", true, app, inst, fmt.Sprintf("%s %s %s purposes %s lease %d", a.Pin.Version, short(a.ComposeHash),
		req.Holder, strings.Join(req.Purposes, ","), l.Seq))
	ah := sha256.Sum256(req.Attestation)
	sig := ed25519.Sign(s.id, kms.ReleaseSigMessage(nonce, ah[:], sealed.Hash(), l.Lease, seq))
	return &kms.ReleaseReply{Sealed: sealed, Sig: sig, Lease: l.Lease, LogSeq: seq, KMSID: s.kmsIDLocked()}, app, inst, nil
}

func mustAppCompose(att json.RawMessage) []byte {
	var a struct {
		Info json.RawMessage `json:"info"`
	}
	json.Unmarshal(att, &a)
	b, _ := kms.AppCompose(a.Info)
	return b
}

func (s *Server) genesisFloor() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.genesis == nil {
		return ""
	}
	return s.genesis.Floor
}

// purposeTag is a purpose's register prefix ("state/v1" -> "state"), as kmsvm.Tag names it.
func purposeTag(p string) string { t, _, _ := strings.Cut(p, "/"); return t }

func leaseKey(app, holder string) string { return app + "\x00" + holder }

// takeLease gives app's holder's lease to inst with boot key: renewed if that boot holds it, new if it's free or
// expired (or reserved for inst), refused while another instance, or another boot of the same instance, holds it
// (s.mu held).
func (s *Server) takeLease(app, holder, inst, key string, tags []string) (*lease, error) {
	now := s.cfg.Now()
	l := s.leases[leaseKey(app, holder)]
	if l.live(now) && l.Instance != "" {
		if l.Instance == inst && l.Key == key {
			l.expAt = now.Add(kms.LeaseTTL)
			l.Expires = l.expAt.Unix()
			for _, t := range tags {
				if !slices.Contains(l.tags, t) {
					l.tags = append(l.tags, t)
				}
			}
			return l, nil
		}
		if l.Instance == inst {
			return nil, refuse(http.StatusConflict, "instance %s's %s lease is held by another boot key until %s", short(inst), holder,
				l.expAt.UTC().Format("15:04:05Z"))
		}
		return nil, refuse(http.StatusConflict, "instance %s holds %s's %s lease until %s", short(l.Instance), app, holder,
			l.expAt.UTC().Format("15:04:05Z"))
	}
	if l.live(now) && l.reserved != "" && l.reserved != inst {
		return nil, refuse(http.StatusConflict, "%s's %s lease was moved to instance %s", app, holder, short(l.reserved))
	}
	var seq uint64
	if l != nil {
		seq = l.Seq
	}
	id := make([]byte, 16)
	secret := make([]byte, 32)
	if _, err := io.ReadFull(s.cfg.Rand, id); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(s.cfg.Rand, secret); err != nil {
		return nil, err
	}
	exp := now.Add(kms.LeaseTTL)
	nl := &lease{Lease: kms.Lease{ID: hex.EncodeToString(id), App: app, Holder: holder, Instance: inst, Key: key, Seq: seq + 1,
		Expires: exp.Unix()}, secret: secret, expAt: exp, tags: slices.Clone(tags)}
	s.leases[leaseKey(app, holder)] = nl
	s.audit("lease", true, app, inst, fmt.Sprintf("%s lease %d granted", holder, nl.Seq))
	return nl, nil
}

// Renew extends the caller's lease (proved with the lease secret).
func (s *Server) Renew(r kms.LeaseRenew) (*kms.SignedLease, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sl, err := s.renew(r)
	if err != nil {
		s.recordRefusal("renew", r.App, "", err)
	}
	return sl, err
}

func (s *Server) renew(r kms.LeaseRenew) (*kms.SignedLease, error) {
	if err := s.primaryOnly(); err != nil {
		return nil, err
	}
	now := s.cfg.Now()
	l := s.leases[leaseKey(r.App, r.Holder)]
	if !l.live(now) || l.ID != r.Lease || l.Instance == "" {
		return nil, refuse(http.StatusConflict, "no such live lease")
	}
	if skew(now.Unix(), r.At) {
		return nil, refuse(http.StatusForbidden, "renewal time is off")
	}
	if !hmac.Equal(r.MAC, kms.RenewMAC(l.secret, r.App, r.Holder, r.Lease, r.At)) {
		return nil, refuse(http.StatusForbidden, "renewal isn't from the lease holder")
	}
	if r.At <= l.lastRenew {
		return nil, refuseA(http.StatusForbidden, "renewal time is replayed")
	}
	l.lastRenew = r.At
	l.expAt = now.Add(kms.LeaseTTL)
	l.Expires = l.expAt.Unix()
	return &kms.SignedLease{Lease: l.Lease, Sig: ed25519.Sign(s.id, kms.LeaseSigMessage(l.Lease))}, nil
}

// Drop frees the caller's lease (proved with the lease secret): a process stopping cleanly lets its next boot (a new
// boot key) take the lease at once instead of after LeaseTTL. Each holder drops only its own. The lease's Seq is
// kept, so the next one is Seq+1.
func (s *Server) Drop(r kms.LeaseRenew) (*kms.SignedLease, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sl, err := s.drop(r)
	if err != nil {
		s.recordRefusal("drop", r.App, "", err)
	}
	return sl, err
}

func (s *Server) drop(r kms.LeaseRenew) (*kms.SignedLease, error) {
	if err := s.primaryOnly(); err != nil {
		return nil, err
	}
	now := s.cfg.Now()
	l := s.leases[leaseKey(r.App, r.Holder)]
	if !l.live(now) || l.ID != r.Lease || l.Instance == "" {
		return nil, refuse(http.StatusConflict, "no such live lease")
	}
	if skew(now.Unix(), r.At) {
		return nil, refuse(http.StatusForbidden, "drop time is off")
	}
	if !hmac.Equal(r.MAC, kms.DropMAC(l.secret, r.App, r.Holder, r.Lease, r.At)) {
		return nil, refuse(http.StatusForbidden, "drop isn't from the lease holder")
	}
	if r.At < l.lastRenew {
		return nil, refuseA(http.StatusForbidden, "drop time is replayed")
	}
	inst := l.Instance
	nl := &lease{Lease: kms.Lease{ID: l.ID + "-dropped", App: r.App, Holder: r.Holder, Seq: l.Seq}}
	s.leases[leaseKey(r.App, r.Holder)] = nl
	s.audit("lease", true, r.App, inst, fmt.Sprintf("%s lease %d dropped by its holder", r.Holder, l.Seq))
	return &kms.SignedLease{Lease: nl.Lease, Sig: ed25519.Sign(s.id, kms.LeaseSigMessage(nl.Lease))}, nil
}

// MoveLease applies a Worker-signed LeaseMove for this KMS id and epoch: the lease is freed, or reserved for the
// named instance.
func (s *Server) MoveLease(e *safety.Envelope) (*kms.SignedLease, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sl, err := s.moveLease(e)
	if err != nil {
		s.recordRefusal("lease move", "", "", err)
	}
	return sl, err
}

func (s *Server) moveLease(e *safety.Envelope) (*kms.SignedLease, error) {
	if err := s.primaryOnly(); err != nil {
		return nil, err
	}
	if s.policy == nil || e.Kind != kms.KindLeaseMove {
		return nil, refuse(http.StatusForbidden, "not a lease move")
	}
	var keys []ed25519.PublicKey
	for _, k := range s.policy.WorkerKeys {
		if pk, err := kms.ParseID(k); err == nil {
			keys = append(keys, pk)
		}
	}
	if len(keys) == 0 || kms.Signers(e, keys) < 1 {
		return nil, refuse(http.StatusForbidden, "lease move isn't signed by a Worker key")
	}
	var mv kms.LeaseMove
	if err := kms.Strict(e.Payload, &mv); err != nil {
		return nil, refuseA(http.StatusBadRequest, "lease move: %v", err)
	}
	if mv.KMSID != s.kmsIDLocked() || mv.Epoch != s.epoch {
		return nil, refuseA(http.StatusForbidden, "lease move is for another key service (kms id or epoch)")
	}
	now := s.cfg.Now()
	if age := now.Sub(mv.IssuedAt); age > kms.LeaseMoveTTL || age < -kms.MaxClockSkew {
		return nil, refuseA(http.StatusForbidden, "lease move is stale or from the future")
	}
	l := s.leases[leaseKey(mv.App, mv.Holder)]
	if l == nil || l.ID != mv.Lease {
		return nil, refuseA(http.StatusConflict, "lease move is for another lease")
	}
	from := l.Instance
	nl := &lease{Lease: kms.Lease{ID: l.ID + "-moved", App: mv.App, Holder: mv.Holder, Seq: l.Seq}, reserved: mv.Instance}
	if mv.Instance != "" {
		nl.expAt = now.Add(kms.LeaseTTL)
		nl.Expires = nl.expAt.Unix()
	}
	s.leases[leaseKey(mv.App, mv.Holder)] = nl
	s.audit("lease", true, mv.App, from, fmt.Sprintf("%s lease %d moved by the Worker to %q", mv.Holder, l.Seq, short(mv.Instance)))
	return &kms.SignedLease{Lease: nl.Lease, Sig: ed25519.Sign(s.id, kms.LeaseSigMessage(nl.Lease))}, nil
}

func regKey(app, name string) string { return app + "\x00" + name }

func validNonce(n string) bool {
	b, err := hex.DecodeString(n)
	return err == nil && len(b) == 32 && strings.ToLower(n) == n
}

func validHash(h string) bool {
	b, err := hex.DecodeString(h)
	return err == nil && len(b) == 32 && strings.ToLower(h) == h
}

// Commit reserves the next generation of a sealed blob, or marks the reserved one stored, from the current lease
// holder. A VM reserves before it stores, so a blob nobody reserved (a stale instance's) never counts.
func (s *Server) Commit(c kms.GenCommit) (*kms.SignedGen, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sg, err := s.commit(c)
	if err != nil {
		s.recordRefusal("commit", c.App, "", err)
	}
	return sg, err
}

func (s *Server) commit(c kms.GenCommit) (*kms.SignedGen, error) {
	if err := s.primaryOnly(); err != nil {
		return nil, err
	}
	// The form first: nothing a caller chose reaches the audit log unchecked.
	if !kms.ValidName(c.App) || !kms.ValidName(c.Name) || !kms.ValidHolder(c.Holder) || !validHash(c.Hash) || !validNonce(c.Nonce) || c.Gen.Gen == 0 {
		return nil, refuse(http.StatusBadRequest, "bad app, name, holder, hash, nonce or generation")
	}
	now := s.cfg.Now()
	l := s.leases[leaseKey(c.App, c.Holder)]
	if !l.live(now) || l.ID != c.Lease || l.Instance == "" {
		return nil, refuse(http.StatusConflict, "commit needs the holder's live lease")
	}
	if skew(now.Unix(), c.At) {
		return nil, refuse(http.StatusForbidden, "commit time is off")
	}
	if !hmac.Equal(c.MAC, kms.CommitMAC(l.secret, c)) {
		return nil, refuse(http.StatusForbidden, "commit isn't from the lease holder")
	}
	// The lease holder, from here.
	tag, _, ok := strings.Cut(c.Name, "/")
	if !ok || !slices.Contains(l.tags, tag) {
		return nil, refuseA(http.StatusForbidden, "%s's lease may not commit %s (its purposes' prefixes: %s)", c.Holder, c.Name, strings.Join(l.tags, ","))
	}
	k := regKey(c.App, c.Name)
	cur := s.gens[k]
	if cur == nil {
		cur = &regEntry{gen: kms.Gen{App: c.App, Name: c.Name}, stored: true}
	}
	what := "reserved"
	switch {
	case !c.Stored && cur.stored && c.Gen.Gen == cur.gen.Gen+1:
		s.gens[k] = &regEntry{gen: c.Gen, prev: cur.gen.Hash}
	case !c.Stored && !cur.stored && c.Gen.Gen == cur.gen.Gen:
		// The last reservation was never stored (the VM stopped, or its put failed): reserve it again.
		s.gens[k] = &regEntry{gen: c.Gen, prev: cur.prev}
		what = "reserved again"
	case c.Stored && c.Gen == cur.gen:
		cur.stored = true
		what = "stored"
	case c.Stored:
		return nil, refuseA(http.StatusConflict, "generation %d %s isn't the reserved one", c.Gen.Gen, short(c.Hash))
	case !cur.stored:
		return nil, refuseA(http.StatusConflict, "generation %d is reserved and not stored; want %d again", cur.gen.Gen, cur.gen.Gen)
	default:
		return nil, refuseA(http.StatusConflict, "generation %d, want %d", c.Gen.Gen, cur.gen.Gen+1)
	}
	e := s.gens[k]
	s.audit("gen", true, c.App, l.Instance, fmt.Sprintf("%s gen %d %s %s", c.Name, c.Gen.Gen, short(c.Hash), what))
	sg := kms.SignedGen{Gen: e.gen, Prev: e.prev, Stored: e.stored, Nonce: c.Nonce}
	sg.Sig = ed25519.Sign(s.id, kms.GenSigMessage(sg))
	return &sg, nil
}

// Generation is the register's entry (gen 0, hash "" when none), signed over the caller's nonce.
func (s *Server) Generation(app, name, nonce string) (*kms.SignedGen, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.primaryOnly(); err != nil {
		return nil, err
	}
	if !kms.ValidName(app) || !kms.ValidName(name) || !validNonce(nonce) {
		return nil, refuse(http.StatusBadRequest, "app, name and a 64-hex nonce")
	}
	sg := kms.SignedGen{Gen: kms.Gen{App: app, Name: name}, Stored: true, Nonce: nonce}
	if e := s.gens[regKey(app, name)]; e != nil {
		sg.Gen, sg.Prev, sg.Stored = e.gen, e.prev, e.stored
	}
	sg.Sig = ed25519.Sign(s.id, kms.GenSigMessage(sg))
	return &sg, nil
}

// Snapshot is the whole register, signed: kmsctl gen-snapshot keeps it offline, and after a cold start the
// admins' GenConfirm is built from it rather than from the Worker's word.
func (s *Server) Snapshot(nonce string) (*kms.SignedSnapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.primaryOnly(); err != nil {
		return nil, err
	}
	if !validNonce(nonce) {
		return nil, refuse(http.StatusBadRequest, "a 64-hex nonce")
	}
	snap := kms.Snapshot{KMSID: s.kmsIDLocked(), Epoch: s.epoch, Time: s.cfg.Now().Unix(), LogSeq: s.logSeq, Nonce: nonce,
		Entries: []kms.SnapshotEntry{}}
	for _, e := range s.gens {
		snap.Entries = append(snap.Entries, kms.SnapshotEntry{Gen: e.gen, Prev: e.prev, Stored: e.stored})
	}
	sort.Slice(snap.Entries, func(i, j int) bool {
		return regKey(snap.Entries[i].Gen.App, snap.Entries[i].Gen.Name) < regKey(snap.Entries[j].Gen.App, snap.Entries[j].Gen.Name)
	})
	return &kms.SignedSnapshot{Snapshot: snap, Sig: ed25519.Sign(s.id, kms.SnapshotSigMessage(snap))}, nil
}

// ConfirmGens sets the register after this replica got M (a cold start, or a join), from an admin-signed
// GenConfirm for this KMS id, epoch and confirm nonce, issued within kms.LeaseMoveTTL. Once the register is
// confirmed, no confirmation is taken again.
func (s *Server) ConfirmGens(e *safety.Envelope) (*kms.Status, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, err := s.confirmGens(e)
	if err != nil {
		s.recordRefusal("gen confirm", "", "", err)
	}
	return st, err
}

func (s *Server) confirmGens(e *safety.Envelope) (*kms.Status, error) {
	if s.cfg.Role != kms.RolePrimary {
		return nil, errStandby()
	}
	if s.master == nil {
		return nil, errLocked()
	}
	var gc kms.GenConfirm
	if err := s.cfg.Admin.Open(e, kms.KindGen, &gc); err != nil {
		return nil, refuse(http.StatusForbidden, "%v", err)
	}
	if s.gensOK {
		return nil, refuseA(http.StatusConflict, "the generations are confirmed already")
	}
	if gc.KMSID != s.kmsIDLocked() || gc.Epoch != s.epoch {
		return nil, refuseA(http.StatusForbidden, "generation confirmation is for another key service (kms id or epoch)")
	}
	if s.confirmNonce == "" || !hmac.Equal([]byte(gc.Nonce), []byte(s.confirmNonce)) {
		return nil, refuseA(http.StatusForbidden, "generation confirmation names another confirm nonce (GET /v1/status)")
	}
	if age := s.cfg.Now().Sub(gc.IssuedAt); age > kms.LeaseMoveTTL || age < -kms.MaxClockSkew {
		return nil, refuseA(http.StatusForbidden, "generation confirmation is stale or from the future")
	}
	gens := map[string]*regEntry{}
	for _, g := range gc.Gens {
		if !kms.ValidName(g.App) || !kms.ValidName(g.Name) || g.Gen == 0 || !validHash(g.Hash) {
			return nil, refuseA(http.StatusBadRequest, "bad generation entry")
		}
		if gens[regKey(g.App, g.Name)] != nil {
			return nil, refuseA(http.StatusBadRequest, "a generation entry is listed twice")
		}
		gens[regKey(g.App, g.Name)] = &regEntry{gen: g, stored: true}
	}
	s.gens, s.gensOK, s.confirmNonce = gens, true, ""
	s.audit("gen", true, "", "", fmt.Sprintf("confirmed %d generations (%s)", len(gens), e.Hash()[:16]))
	st := s.statusLocked()
	return &st, nil
}

func skew(now, at int64) bool {
	d := now - at
	return d > int64(kms.MaxClockSkew.Seconds()) || d < -int64(kms.MaxClockSkew.Seconds())
}
