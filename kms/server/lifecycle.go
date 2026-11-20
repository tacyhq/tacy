package server

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"sort"

	"github.com/tacyhq/tacy/kms"
	"github.com/tacyhq/tacy/kms/client"
	"github.com/tacyhq/tacy/safety"
)

// openPolicy checks an admin-signed policy, that it doesn't go below the compose's floor, and that it is for this
// key service: kmsID and epoch (kmsID "" only for the policy that comes with genesis).
func (s *Server) openPolicy(e *safety.Envelope, kmsID string, epoch uint32) (*kms.Policy, error) {
	var p kms.Policy
	if err := s.cfg.Admin.Open(e, kms.KindPolicy, &p); err != nil {
		return nil, refuse(http.StatusForbidden, "%v", err)
	}
	if err := p.Validate(); err != nil {
		return nil, refuseA(http.StatusBadRequest, "%v", err)
	}
	if p.KMSID != kmsID || p.Epoch != epoch {
		if kmsID == "" {
			return nil, refuseA(http.StatusForbidden, "the policy that comes with genesis names no kms id (it doesn't exist yet) and epoch 1")
		}
		return nil, refuseA(http.StatusForbidden, "policy is for another key service: kms id %s epoch %d, this one is %s epoch %d", short(p.KMSID), p.Epoch, short(kmsID), epoch)
	}
	if p.AllowE2EDiag && !s.cfg.Staging {
		return nil, refuseA(http.StatusForbidden, "allow_e2e_diag is for a staging key service (kmsd -staging) only")
	}
	if s.cfg.FloorMin != "" {
		if c, _ := kms.CompareVersions(p.Floor, s.cfg.FloorMin); c < 0 {
			return nil, refuseA(http.StatusForbidden, "policy floor %s is below the compose's %s", p.Floor, s.cfg.FloorMin)
		}
	}
	return &p, nil
}

// binding is the KMS id and epoch this replica's documents must name (s.mu not held).
func (s *Server) binding() (string, uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.kmsIDLocked(), s.wantEpoch()
}

// setPolicyLocked keeps p if it's newer (s.mu held). An equal seq must be the same document.
func (s *Server) setPolicyLocked(p *kms.Policy, e *safety.Envelope) error {
	if s.policy != nil {
		if p.Seq < s.policy.Seq || (p.Seq == s.policy.Seq && e.Hash() != s.policyEnv.Hash()) {
			return refuseA(http.StatusConflict, "policy seq %d isn't newer than the loaded %d", p.Seq, s.policy.Seq)
		}
		if p.Seq == s.policy.Seq {
			return nil
		}
	}
	ec := *e
	s.policy, s.policyEnv = p, &ec
	s.audit("policy", true, "", "", fmt.Sprintf("policy seq %d %s", p.Seq, e.Hash()[:16]))
	return nil
}

// SetPolicy loads a newer admin-signed policy for this KMS id and epoch (an empty replica takes its first with
// genesis).
func (s *Server) SetPolicy(e *safety.Envelope) (*kms.Status, error) {
	id, epoch := s.binding()
	var p *kms.Policy
	err := refuse(http.StatusConflict, "an empty replica takes its policy with the genesis")
	if id != "" {
		p, err = s.openPolicy(e, id, epoch)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err == nil {
		err = s.setPolicyLocked(p, e)
	}
	if err != nil {
		s.recordRefusal("policy", "", "", err)
		return nil, err
	}
	st := s.statusLocked()
	return &st, nil
}

// openGenesis checks an admin-signed genesis document names exactly the pinned admin keys.
func (s *Server) openGenesis(e *safety.Envelope) (*kms.GenesisDoc, error) {
	var g kms.GenesisDoc
	if err := s.cfg.Admin.Open(e, kms.KindGenesis, &g); err != nil {
		return nil, refuse(http.StatusForbidden, "%v", err)
	}
	if err := g.Validate(); err != nil {
		return nil, refuseA(http.StatusBadRequest, "%v", err)
	}
	if !s.cfg.Admin.SameKeys(g.AdminKeys, g.AdminThreshold) {
		return nil, refuseA(http.StatusForbidden, "genesis names other admin keys than the compose pins")
	}
	return &g, nil
}

// Genesis is the ceremony on an empty replica: M is made here, split, and each share sealed to its recipient.
func (s *Server) Genesis(req kms.GenesisRequest) (*kms.GenesisReply, error) {
	rep, err := s.genesisCeremony(req)
	if err != nil {
		s.mu.Lock()
		s.recordRefusal("genesis", "", "", err)
		s.mu.Unlock()
	}
	return rep, err
}

func (s *Server) genesisCeremony(req kms.GenesisRequest) (*kms.GenesisReply, error) {
	g, err := s.openGenesis(&req.Genesis)
	if err != nil {
		return nil, err
	}
	if g.Target != s.bootHex {
		return nil, refuseA(http.StatusForbidden, "genesis is for another replica boot")
	}
	if s.cfg.Role != kms.RolePrimary {
		return nil, refuseA(http.StatusConflict, "genesis runs on a primary")
	}
	if st := s.Status().State; st != "empty" {
		return nil, refuseA(http.StatusConflict, "genesis needs an empty replica (this one is %s)", st)
	}
	pol, err := s.openPolicy(&req.Policy, "", 1)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if st := s.stateLocked(); st != "empty" {
		return nil, refuseA(http.StatusConflict, "genesis needs an empty replica (this one is %s)", st)
	}
	master := make([]byte, kms.MasterSize)
	if _, err := io.ReadFull(s.cfg.Rand, master); err != nil {
		return nil, err
	}
	id, err := kms.DeriveID(master)
	if err != nil {
		return nil, err
	}
	idStr := kms.IDString(id.Public().(ed25519.PublicKey))
	const epoch = 1
	shares, err := kms.Split(master, len(g.Recipients), g.Threshold, s.cfg.Rand)
	if err != nil {
		clear(master)
		return nil, err
	}
	rep := &kms.GenesisReply{KMSID: idStr, Epoch: epoch, Threshold: g.Threshold}
	for i, r := range g.Recipients {
		rep.Commitments = append(rep.Commitments, kms.ShareCommitment(idStr, shares[i].X, epoch, shares[i].Y))
		pub, _ := kms.ParseRecipient(r)
		box, err := kms.Seal(pub, kms.LabelShare, kms.ShareAAD(idStr, shares[i].X, epoch), shares[i].Y)
		clear(shares[i].Y)
		if err != nil {
			clear(master)
			return nil, err
		}
		rep.Shares = append(rep.Shares, kms.SealedShare{Recipient: r, Index: shares[i].X, Epoch: epoch, KMSID: idStr, Sealed: box})
	}
	ge := req.Genesis
	s.master, s.id, s.epoch, s.genesis, s.genesisEnv, s.gensOK = master, id, epoch, g, &ge, true
	s.signPending()
	if err := s.setPolicyLocked(pol, &req.Policy); err != nil {
		return nil, err
	}
	rep.Sig = ed25519.Sign(id, kms.GenesisSigMessage(req.Genesis.Hash(), rep.Shares))
	rep.CommitSig = ed25519.Sign(id, kms.CommitmentsSigMessage(idStr, epoch, rep.Commitments))
	s.audit("genesis", true, "", "", fmt.Sprintf("kms id %s, %d-of-%d shares, genesis %s", idStr, g.Threshold,
		len(g.Recipients), req.Genesis.Hash()[:16]))
	return rep, nil
}

// Unlock takes one offline share resealed to this boot's key. With the genesis threshold of shares it rebuilds M
// and keeps it only if it derives the pinned KMS id; otherwise every share is dropped.
func (s *Server) Unlock(req kms.UnlockRequest) (*kms.UnlockReply, error) {
	var g *kms.GenesisDoc
	var err error
	if req.Genesis != nil {
		if g, err = s.openGenesis(req.Genesis); err != nil {
			return nil, s.refuseLog("unlock", err)
		}
	}
	var pol *kms.Policy
	if req.Policy != nil {
		id, epoch := s.binding()
		if pol, err = s.openPolicy(req.Policy, id, epoch); err != nil {
			return nil, s.refuseLog("unlock", err)
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if st := s.stateLocked(); st != "locked" {
		return nil, s.refuseLocked("unlock", refuse(http.StatusConflict, "unlock needs a locked replica (this one is %s)", st))
	}
	if g != nil {
		if s.genesisEnv != nil && s.genesisEnv.Hash() != req.Genesis.Hash() {
			return nil, s.refuseLocked("unlock", refuse(http.StatusConflict, "another genesis document was sent before"))
		}
		ge := *req.Genesis
		s.genesis, s.genesisEnv = g, &ge
	}
	pinned := kms.IDString(s.cfg.KMSID)
	if s.genesis == nil {
		return nil, s.refuseLocked("unlock", refuse(http.StatusBadRequest, "send the genesis document and share commitments with the first share"))
	}
	if req.Commitments != nil {
		if len(req.Commitments) != len(s.genesis.Recipients) ||
			!ed25519.Verify(s.cfg.KMSID, kms.CommitmentsSigMessage(pinned, 1, req.Commitments), req.CommitSig) {
			return nil, s.refuseLocked("unlock", refuse(http.StatusForbidden, "share commitments aren't signed by the pinned KMS id"))
		}
		s.commitments = req.Commitments
	}
	if s.commitments == nil {
		return nil, s.refuseLocked("unlock", refuse(http.StatusBadRequest, "send the genesis document and share commitments with the first share"))
	}
	if pol != nil {
		if err := s.setPolicyLocked(pol, req.Policy); err != nil {
			return nil, s.refuseLocked("unlock", err)
		}
	}
	if req.Index == 0 || int(req.Index) > len(s.genesis.Recipients) || req.Epoch != 1 {
		return nil, s.refuseLocked("unlock", refuse(http.StatusBadRequest, "share index or epoch out of range"))
	}
	y, err := kms.Open(s.boot, kms.LabelUnlock, kms.ShareAAD(pinned, req.Index, req.Epoch), req.Share)
	if err != nil || len(y) != kms.MasterSize {
		return nil, s.refuseLocked("unlock", refuse(http.StatusForbidden, "share doesn't open with this boot's key for the pinned KMS id"))
	}
	if kms.ShareCommitment(pinned, req.Index, req.Epoch, y) != s.commitments[req.Index-1] {
		clear(y)
		return nil, s.refuseLocked("unlock", refuse(http.StatusForbidden, "share %d doesn't match its commitment", req.Index))
	}
	if old := s.shares[req.Index]; old != nil {
		clear(old)
	}
	s.shares[req.Index] = y
	s.audit("unlock", true, "", "", fmt.Sprintf("share %d received (%d of %d)", req.Index, len(s.shares), s.genesis.Threshold))
	if len(s.shares) < s.genesis.Threshold {
		return &kms.UnlockReply{State: "locked", Shares: len(s.shares), Threshold: s.genesis.Threshold}, nil
	}
	var list []kms.Share
	for x, y := range s.shares {
		list = append(list, kms.Share{X: x, Y: y})
	}
	master, err := kms.Combine(list)
	s.dropShares()
	if err != nil {
		return nil, s.refuseLocked("unlock", err)
	}
	id, err := kms.DeriveID(master)
	if err != nil || !bytes.Equal(id.Public().(ed25519.PublicKey), s.cfg.KMSID) {
		clear(master)
		return nil, s.refuseLocked("unlock", refuse(http.StatusForbidden, "the shares don't rebuild the pinned KMS id; all shares dropped"))
	}
	// A cold start: nothing says which generations are current until the admin keys confirm them.
	s.master, s.id, s.epoch, s.gensOK = master, id, 1, false
	s.newConfirmNonce()
	s.signPending()
	s.audit("unlock", true, "", "", "unlocked from "+fmt.Sprint(s.genesis.Threshold)+" shares; generations wait for confirmation")
	return &kms.UnlockReply{State: "unlocked", Threshold: s.genesis.Threshold}, nil
}

func (s *Server) dropShares() {
	for k, v := range s.shares {
		clear(v)
		delete(s.shares, k)
	}
}

func (s *Server) refuseLog(what string, err error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.refuseLocked(what, err)
}

func (s *Server) refuseLocked(what string, err error) error {
	s.recordRefusal(what, "", "", err)
	return err
}

// Join gives M to a peer replica whose attestation is a pinned KMS release, sealed to its attested key and signed
// by the KMS id; the reply carries this replica's own attestation for the peer's nonce.
func (s *Server) Join(ctx context.Context, req kms.JoinRequest) (*kms.JoinReply, error) {
	rep, inst, err := s.join(ctx, req)
	if err != nil {
		s.mu.Lock()
		s.recordRefusal("join", "kms", inst, err)
		s.mu.Unlock()
	}
	return rep, err
}

func (s *Server) join(ctx context.Context, req kms.JoinRequest) (*kms.JoinReply, string, error) {
	s.mu.Lock()
	unlocked, pol, polEnv := s.master != nil, s.policy, s.policyEnv
	s.mu.Unlock()
	if !unlocked {
		return nil, "", errLocked()
	}
	if pol == nil {
		return nil, "", refuse(http.StatusServiceUnavailable, "no policy loaded")
	}
	nonce, err := s.takeNonce(req.Nonce)
	if err != nil {
		return nil, "", err
	}
	peerNonce, err := hex.DecodeString(req.PeerNonce)
	if err != nil || len(peerNonce) != 32 {
		return nil, "", refuse(http.StatusBadRequest, "peer nonce must be 64 hex")
	}
	a, err := VerifyKMS(ctx, req.Attestation, nonce, pol, s.checkOptions())
	if err != nil {
		return nil, "", err
	}
	// An attested key service release, from here.
	if a.Role == kms.RolePrimary && s.cfg.Role == kms.RolePrimary {
		return nil, a.Instance, refuseA(http.StatusForbidden, "a primary gives M to standbys only (a second primary unlocks from the shares or joins a standby)")
	}
	if err := s.sameFlags(a); err != nil {
		return nil, a.Instance, authed(err)
	}
	mine, err := s.Attest(ctx, peerNonce)
	if err != nil {
		return nil, a.Instance, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.master == nil {
		return nil, a.Instance, errLocked()
	}
	// M and the documents only: leases and the register stay with the primary.
	p := kms.JoinPayload{Master: s.master, Epoch: s.epoch, Genesis: *s.genesisEnv, Policy: polEnv}
	if s.secretsEnv != nil {
		if p.Secrets, err = s.sealSecrets(s.secretsEnv); err != nil {
			return nil, a.Instance, err
		}
	}
	pt, err := json.Marshal(p)
	if err != nil {
		return nil, a.Instance, err
	}
	sealed, err := kms.Seal(a.Key, kms.LabelJoin, peerNonce, pt)
	clear(pt)
	if err != nil {
		return nil, a.Instance, err
	}
	ah := sha256.Sum256(req.Attestation)
	sig := ed25519.Sign(s.id, kms.JoinSigMessage(peerNonce, ah[:], sealed.Hash()))
	s.audit("join", true, "kms", a.Instance, fmt.Sprintf("M sealed to %s peer %s (%s)", a.Role, a.Pin.Version, short(a.ComposeHash)))
	return &kms.JoinReply{Attestation: mine, Policy: *polEnv, Sealed: sealed, Sig: sig}, a.Instance, nil
}

// JoinFrom gets M from an unlocked peer (this replica must be locked with the same pinned KMS id). It checks the
// peer's attestation against the admin-signed policy the peer sends, and its signature by the pinned KMS id.
func (s *Server) JoinFrom(ctx context.Context, peer client.Transport) error {
	err := s.joinFrom(ctx, peer)
	if err != nil {
		s.refuseLog("join from peer", err)
	}
	return err
}

func (s *Server) joinFrom(ctx context.Context, peer client.Transport) error {
	if st := s.Status().State; st != "locked" {
		return fmt.Errorf("join needs a locked replica (this one is %s)", st)
	}
	nonce, err := client.Challenge(ctx, peer)
	if err != nil {
		return err
	}
	att, err := s.Attest(ctx, nonce)
	if err != nil {
		return err
	}
	peerNonce := make([]byte, 32)
	if _, err := io.ReadFull(s.cfg.Rand, peerNonce); err != nil {
		return err
	}
	body, _ := json.Marshal(kms.JoinRequest{Nonce: hex.EncodeToString(nonce), Attestation: att, PeerNonce: hex.EncodeToString(peerNonce)})
	b, err := peer.Do(ctx, http.MethodPost, "/v1/peer/join", body)
	if err != nil {
		return err
	}
	var r kms.JoinReply
	if err := kms.Strict(b, &r); err != nil {
		return fmt.Errorf("join reply: %w", err)
	}
	ah := sha256.Sum256(att)
	if !ed25519.Verify(s.cfg.KMSID, kms.JoinSigMessage(peerNonce, ah[:], r.Sealed.Hash()), r.Sig) {
		return errors.New("join reply isn't signed by the pinned KMS id")
	}
	id, epoch := s.binding()
	pol, err := s.openPolicy(&r.Policy, id, epoch)
	if err != nil {
		return err
	}
	pa, err := VerifyKMS(ctx, r.Attestation, peerNonce, pol, s.checkOptions())
	if err != nil {
		return fmt.Errorf("peer: %w", err)
	}
	if err := s.sameFlags(pa); err != nil {
		return fmt.Errorf("peer: %w", err)
	}
	pt, err := kms.Open(s.boot, kms.LabelJoin, peerNonce, r.Sealed)
	if err != nil {
		return errors.New("join reply doesn't open with this boot's key")
	}
	defer clear(pt)
	var p kms.JoinPayload
	if err := kms.Strict(pt, &p); err != nil {
		return fmt.Errorf("join payload: %w", err)
	}
	kid, err := kms.DeriveID(p.Master)
	if err != nil || !bytes.Equal(kid.Public().(ed25519.PublicKey), s.cfg.KMSID) {
		clear(p.Master)
		return errors.New("peer's M doesn't derive the pinned KMS id")
	}
	g, err := s.openGenesis(&p.Genesis)
	if err != nil {
		clear(p.Master)
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.master != nil {
		clear(p.Master)
		return errors.New("already unlocked")
	}
	// No register comes with M: a joined primary releases and commits nothing until the admins confirm the
	// generations for it (its confirm nonce), so two primaries never both grant without the admins' say.
	s.master, s.id, s.epoch, s.genesis, s.genesisEnv, s.gensOK = p.Master, kid, p.Epoch, g, &p.Genesis, false
	s.newConfirmNonce()
	s.dropShares()
	s.signPending()
	s.setPolicyLocked(pol, &r.Policy)
	if p.Secrets != nil {
		if err := s.loadSecretsLocked(p.Secrets); err != nil {
			s.recordRefusal("join: secrets", "", "", err)
		}
	}
	s.audit("join", true, "kms", pa.Instance, "M received from a "+pa.Role+" peer; KMS id matches the pin; generations wait for confirmation")
	return nil
}

// Secrets.

const secretsMagic = "TKS1"

func (s *Server) secretsAEAD() (cipher.AEAD, error) {
	k, err := kms.SecretsKey(s.master)
	if err != nil {
		return nil, err
	}
	defer clear(k)
	b, err := aes.NewCipher(k)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(b)
}

func (s *Server) secretsAAD() []byte {
	return binary.BigEndian.AppendUint32([]byte(secretsMagic+"\x00"+s.kmsIDLocked()+"\x00"), s.epoch)
}

// sealSecrets is secrets.sealed: "TKS1" ‖ epoch ‖ nonce ‖ AES-256-GCM(HKDF(M, "secrets/v1"), envelope JSON) (s.mu held).
func (s *Server) sealSecrets(env []byte) ([]byte, error) {
	aead, err := s.secretsAEAD()
	if err != nil {
		return nil, err
	}
	n := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(s.cfg.Rand, n); err != nil {
		return nil, err
	}
	out := binary.BigEndian.AppendUint32([]byte(secretsMagic), s.epoch)
	out = append(out, n...)
	return aead.Seal(out, n, env, s.secretsAAD()), nil
}

func (s *Server) openSecrets(b []byte) ([]byte, error) {
	aead, err := s.secretsAEAD()
	if err != nil {
		return nil, err
	}
	h := len(secretsMagic) + 4
	if len(b) < h+aead.NonceSize() || string(b[:len(secretsMagic)]) != secretsMagic ||
		binary.BigEndian.Uint32(b[len(secretsMagic):]) != s.epoch {
		return nil, errors.New("not a secrets bundle of this KMS epoch")
	}
	n := b[h : h+aead.NonceSize()]
	pt, err := aead.Open(nil, n, b[h+aead.NonceSize():], s.secretsAAD())
	if err != nil {
		return nil, errors.New("secrets bundle doesn't open under this KMS's key")
	}
	return pt, nil
}

// useSecretsLocked checks an admin-signed SecretsDoc envelope (JSON) and keeps it if its seq is at least the
// loaded one's (s.mu held).
func (s *Server) useSecretsLocked(env []byte, strictlyNewer bool) (*kms.SecretsDoc, error) {
	var e safety.Envelope
	if err := kms.Strict(env, &e); err != nil {
		return nil, refuse(http.StatusBadRequest, "secrets envelope: %v", err)
	}
	var d kms.SecretsDoc
	if err := s.cfg.Admin.Open(&e, kms.KindSecrets, &d); err != nil {
		return nil, refuse(http.StatusForbidden, "%v", err)
	}
	if d.KMSID != s.kmsIDLocked() || d.Epoch != s.epoch {
		return nil, refuseA(http.StatusForbidden, "secrets bundle is for another key service (kms id or epoch)")
	}
	if d.Seq == 0 || len(d.Values) == 0 {
		return nil, refuseA(http.StatusBadRequest, "secrets bundle needs a seq and values")
	}
	for n := range d.Values {
		if !kms.ValidName(n) {
			return nil, refuseA(http.StatusBadRequest, "bad secret name %q", n)
		}
	}
	if s.secrets != nil && (d.Seq < s.secrets.Seq || (strictlyNewer && d.Seq == s.secrets.Seq)) {
		return nil, refuseA(http.StatusConflict, "secrets seq %d isn't newer than the loaded %d", d.Seq, s.secrets.Seq)
	}
	if s.policy != nil && d.Seq < s.policy.SecretsFloor {
		return nil, refuseA(http.StatusConflict, "secrets seq %d is below the policy's secrets floor %d", d.Seq, s.policy.SecretsFloor)
	}
	s.secrets, s.secretsEnv = &d, slices.Clone(env)
	return &d, nil
}

func names(d *kms.SecretsDoc) []string {
	var n []string
	for k := range d.Values {
		n = append(n, k)
	}
	sort.Strings(n)
	return n
}

// PutSecrets takes kmsctl's admin-signed secrets bundle sealed to this boot's key and returns it sealed under M.
func (s *Server) PutSecrets(req kms.SecretsPut) (*kms.SecretsReply, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.master == nil {
		return nil, s.refuseLocked("secrets", errLocked())
	}
	env, err := kms.Open(s.boot, kms.LabelSecretPut, []byte(s.kmsIDLocked()), req.Sealed)
	if err != nil {
		return nil, s.refuseLocked("secrets", refuse(http.StatusForbidden, "secrets don't open with this boot's key for this KMS id"))
	}
	defer clear(env)
	d, err := s.useSecretsLocked(env, true)
	if err != nil {
		return nil, s.refuseLocked("secrets", err)
	}
	sealed, err := s.sealSecrets(env)
	if err != nil {
		return nil, err
	}
	s.audit("secrets", true, "", "", fmt.Sprintf("secrets seq %d put: %v", d.Seq, names(d)))
	return &kms.SecretsReply{Seq: d.Seq, Names: names(d), Sealed: sealed}, nil
}

// LoadSecrets loads a secrets.sealed (after a cold start).
func (s *Server) LoadSecrets(sealed []byte) (*kms.SecretsReply, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.master == nil {
		return nil, s.refuseLocked("secrets", errLocked())
	}
	if err := s.loadSecretsLocked(sealed); err != nil {
		return nil, s.refuseLocked("secrets", err)
	}
	d := s.secrets
	s.audit("secrets", true, "", "", fmt.Sprintf("secrets seq %d loaded: %v", d.Seq, names(d)))
	return &kms.SecretsReply{Seq: d.Seq, Names: names(d), Sealed: slices.Clone(sealed)}, nil
}

func (s *Server) loadSecretsLocked(sealed []byte) error {
	env, err := s.openSecrets(sealed)
	if err != nil {
		return refuse(http.StatusForbidden, "%v", err)
	}
	defer clear(env)
	_, err = s.useSecretsLocked(env, false)
	return err
}
