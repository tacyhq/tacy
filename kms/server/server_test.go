package server

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/tacyhq/tacy/kms"
	"github.com/tacyhq/tacy/kms/client"
)

var vmPurposes = []string{"state/v1", "activity-sign/v1"}

var testSecrets = map[string]string{"EXA_API_KEY": "exa-test-value-0123456789", "TINFOIL_API_KEY": "tinfoil-test-value-9876543210"}

// unlocked is a replica after genesis with the secrets bundle in, and its KMS id.
// vaultClient is vaultd's client: holder vaultd, its own boot key.
func (r *rig) vaultClient(s *Server, id ed25519.PublicKey, ev *evidence) *client.Client {
	r.t.Helper()
	c, err := client.New(client.Config{KMSID: id, Transport: client.Handler{H: s.Handler()}, Evidence: ev.Evidence,
		Release: vmRelease, Holder: "vaultd", Now: r.clock})
	if err != nil {
		r.t.Fatal(err)
	}
	return c
}

func (r *rig) unlocked() (*Server, ed25519.PublicKey, *kms.GenesisReply) {
	r.t.Helper()
	s := r.server(nil)
	rep := r.genesis(s)
	r.putSecrets(s, 1, testSecrets)
	id, _ := kms.ParseID(rep.KMSID)
	return s, id, rep
}

func TestGenesisThenRelease(t *testing.T) {
	r := newRig(t)
	s := r.server(nil)
	if st := s.Status(); st.State != "empty" || st.KMSID != "" {
		t.Fatalf("new replica: %+v", st)
	}
	rep := r.genesis(s)
	if len(rep.Shares) != 3 || rep.Threshold != 2 || rep.Epoch != 1 {
		t.Fatalf("genesis: %d shares, %d-of", len(rep.Shares), rep.Threshold)
	}
	if st := s.Status(); st.State != "unlocked" || st.KMSID != rep.KMSID || !st.GensOK {
		t.Fatalf("after genesis: %+v", st)
	}
	// A second genesis is refused: the replica isn't empty.
	if code, _ := call(s, http.MethodPost, "/v1/genesis", kms.GenesisRequest{Genesis: r.genesisEnv, Policy: r.policyEnv()}); code != http.StatusConflict {
		t.Fatalf("second genesis: %d", code)
	}
	sec := r.putSecrets(s, 1, testSecrets)
	if sec.Seq != 1 || len(sec.Names) != 2 || len(sec.Sealed) < 32 {
		t.Fatalf("secrets: %+v", sec)
	}
	id, _ := kms.ParseID(rep.KMSID)
	keys, err := r.vmClient(s, id, r.vm).Release(context.Background(), vmPurposes)
	if err != nil {
		t.Fatal(err)
	}
	if keys.App != vmApp || keys.Firm != "f_chat" || keys.Release != vmRelease || keys.Lease.Instance != recordedInstance {
		t.Fatalf("keys for %s/%s %s, instance %s", keys.App, keys.Firm, keys.Release, keys.Lease.Instance)
	}
	s.mu.Lock()
	want, _ := kms.DeriveKey(s.master, vmApp, "f_chat", "state/v1", 1)
	s.mu.Unlock()
	if k, _ := keys.Key("state/v1"); !bytes.Equal(k, want) {
		t.Fatal("state/v1 isn't HKDF(M, app, firm, purpose, epoch)")
	}
	if _, err := keys.Key("conn/v1"); err == nil {
		t.Fatal("a purpose not asked for was released")
	}
	if len(keys.Secrets) != 0 {
		t.Fatal("agentd's release (no conn/v1) carries the API keys")
	}
	vk, err := r.vaultClient(s, id, r.vm).Release(context.Background(), []string{"conn/v1"})
	if err != nil {
		t.Fatal(err)
	}
	if vk.Secrets["EXA_API_KEY"] != testSecrets["EXA_API_KEY"] || len(vk.Secrets) != 2 || vk.Lease.Holder != "vaultd" {
		t.Fatal("vaultd's release has no secrets, or shares agentd's lease")
	}
	// The audit log is a signed hash chain from the start.
	log := s.Log(0, 1000)
	if _, err := kms.VerifyLog(log, "", id); err != nil {
		t.Fatal(err)
	}
	var kinds []string
	for _, e := range log {
		kinds = append(kinds, e.Kind)
	}
	if got := strings.Join(kinds, ","); got != "start,policy,genesis,policy,refuse,secrets,lease,release,lease,release" {
		t.Fatalf("audit kinds %s", got)
	}
	assertNoLeak(t, "logs", []byte(r.logs.String()), secretsOf(t, s, testSecrets))
}

func TestLockedStartUnlockFromShares(t *testing.T) {
	r := newRig(t)
	s1, id, rep := r.unlocked()
	k1, err := r.vmClient(s1, id, r.vm).Release(context.Background(), vmPurposes)
	if err != nil {
		t.Fatal(err)
	}
	// Cold start: a new replica pinned to the KMS id boots locked and refuses releases.
	s2 := r.server(id)
	if st := s2.Status(); st.State != "locked" || st.KMSID != rep.KMSID {
		t.Fatalf("locked start: %+v", st)
	}
	r.advance(4 * time.Minute) // s1's lease expired (it isn't replicated to s2 here; s2 is a cold start)
	if _, err := r.vmClient(s2, id, r.vm).Release(context.Background(), vmPurposes); !isStatus(err, http.StatusServiceUnavailable) {
		t.Fatalf("release while locked: %v", err)
	}
	// One share isn't enough; the genesis document must come with the first.
	if code, b := r.unlockWith(s2, rep, 0, false); code != http.StatusBadRequest {
		t.Fatalf("share without genesis: %d %s", code, b)
	}
	if code, b := r.unlockWith(s2, rep, 0, true); code != http.StatusOK || !strings.Contains(string(b), `"locked"`) {
		t.Fatalf("share 1: %d %s", code, b)
	}
	if code, b := r.unlockWith(s2, rep, 2, false); code != http.StatusOK || !strings.Contains(string(b), `"unlocked"`) {
		t.Fatalf("share 3: %d %s", code, b)
	}
	st := s2.Status()
	if st.State != "unlocked" || st.KMSID != rep.KMSID || st.GensOK || st.ConfirmNonce == "" {
		t.Fatalf("after unlock: %+v", st)
	}
	// Nothing is released until the admins confirm the generations (here: none) for this replica's nonce.
	if _, err := r.vmClient(s2, id, r.vm).Release(context.Background(), vmPurposes); !isStatus(err, http.StatusServiceUnavailable) {
		t.Fatalf("release before confirmation: %v", err)
	}
	r.ok(s2, http.MethodPost, "/v1/gen/confirm", r.sign(kms.KindGen, kms.GenConfirm{KMSID: st.KMSID, Epoch: 1, Nonce: st.ConfirmNonce,
		IssuedAt: r.clock()}), &st)
	// The secrets bundle survives a cold start as ciphertext: load it back.
	var sl kms.SecretsReply
	s1.mu.Lock()
	sealed := s1.mustSeal(t)
	s1.mu.Unlock()
	r.ok(s2, http.MethodPost, "/v1/secrets/load", kms.SecretsLoad{Sealed: sealed}, &sl)
	// Same M: the same keys.
	k2, err := r.vmClient(s2, id, r.vm).Release(context.Background(), vmPurposes)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(k1.Keys["state/v1"], k2.Keys["state/v1"]) || !bytes.Equal(k1.Keys["activity-sign/v1"], k2.Keys["activity-sign/v1"]) {
		t.Fatal("keys changed across the cold start")
	}
	if _, err := kms.VerifyLog(s2.Log(0, 1000), "", id); err != nil {
		t.Fatalf("entries made while locked aren't signed after unlock: %v", err)
	}
}

func (s *Server) mustSeal(t *testing.T) []byte {
	b, err := s.sealSecrets(s.secretsEnv)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func isStatus(err error, code int) bool {
	var re *client.RefusedError
	return errors.As(err, &re) && re.Status == code
}

func TestUnlockRefusesWrongShares(t *testing.T) {
	r := newRig(t)
	_, id, rep := r.unlocked()
	// A replica pinned to another id refuses this KMS's share commitments (they're signed by this KMS's id).
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	s3 := r.server(otherPub)
	// The shares are sealed for the real id; reseal them as kmsctl would for the pinned one.
	reseal := func(i int, first bool) (int, []byte) {
		sh := rep.Shares[i]
		y, _ := kms.Open(r.recips[i], kms.LabelShare, kms.ShareAAD(sh.KMSID, sh.Index, sh.Epoch), sh.Sealed)
		a := r.attestKMS(s3)
		box, _ := kms.Seal(a.Key, kms.LabelUnlock, kms.ShareAAD(kms.IDString(otherPub), sh.Index, 1), y)
		req := kms.UnlockRequest{Index: sh.Index, Epoch: 1, Share: box}
		if first {
			op := r.policy
			op.KMSID = kms.IDString(otherPub) // the policy for that replica's pin; the commitments are what fail
			g, p := r.genesisEnv, r.sign(kms.KindPolicy, op)
			req.Genesis, req.Policy, req.Commitments, req.CommitSig = &g, &p, rep.Commitments, rep.CommitSig
		}
		return call(s3, http.MethodPost, "/v1/unlock", req)
	}
	if code, b := reseal(0, true); code != http.StatusForbidden || !strings.Contains(string(b), "commitments aren't signed by the pinned KMS id") {
		t.Fatalf("wrong KMS: %d %s", code, b)
	}
	if code, _ := reseal(1, false); code != http.StatusBadRequest {
		t.Fatalf("share without commitments: %d", code)
	}
	if st := s3.Status(); st.State != "locked" || st.Shares != 0 {
		t.Fatalf("after a failed unlock: %+v", st)
	}
	// A junk share sealed to a locked replica's public boot key (anyone can) is refused and spoils nothing: the
	// genuine shares still unlock it.
	s6 := r.server(id)
	g6, p6 := r.genesisEnv, r.policyEnv()
	junk, _ := kms.Seal(r.attestKMS(s6).Key, kms.LabelUnlock, kms.ShareAAD(rep.KMSID, 2, 1), make([]byte, 32))
	if code, b := call(s6, http.MethodPost, "/v1/unlock", kms.UnlockRequest{Genesis: &g6, Policy: &p6, Commitments: rep.Commitments,
		CommitSig: rep.CommitSig, Index: 2, Epoch: 1, Share: junk}); code != http.StatusForbidden || !strings.Contains(string(b), "doesn't match its commitment") {
		t.Fatalf("junk share: %d %s", code, b)
	}
	r.unlockWith(s6, rep, 0, false)
	if code, b := r.unlockWith(s6, rep, 1, false); code != http.StatusOK || s6.Status().State != "unlocked" {
		t.Fatalf("genuine shares after a junk one: %d %s", code, b)
	}
	// Commitments not signed by the KMS id are refused.
	s7 := r.server(id)
	badCommit := append([]string(nil), rep.Commitments...)
	badCommit[0] = strings.Repeat("0", 64)
	sh0 := rep.Shares[0]
	y0, _ := kms.Open(r.recips[0], kms.LabelShare, kms.ShareAAD(sh0.KMSID, sh0.Index, sh0.Epoch), sh0.Sealed)
	b0, _ := kms.Seal(r.attestKMS(s7).Key, kms.LabelUnlock, kms.ShareAAD(sh0.KMSID, sh0.Index, 1), y0)
	if code, _ := call(s7, http.MethodPost, "/v1/unlock", kms.UnlockRequest{Genesis: &g6, Policy: &p6, Commitments: badCommit, CommitSig: rep.CommitSig,
		Index: 1, Epoch: 1, Share: b0}); code != http.StatusForbidden {
		t.Fatalf("forged commitments: %d", code)
	}
	// A share resealed to one replica's boot key doesn't open on another.
	s4, s5 := r.server(id), r.server(id)
	sh := rep.Shares[0]
	y, _ := kms.Open(r.recips[0], kms.LabelShare, kms.ShareAAD(sh.KMSID, sh.Index, sh.Epoch), sh.Sealed)
	box, _ := kms.Seal(r.attestKMS(s4).Key, kms.LabelUnlock, kms.ShareAAD(sh.KMSID, sh.Index, sh.Epoch), y)
	g, p := r.genesisEnv, r.policyEnv()
	if code, _ := call(s5, http.MethodPost, "/v1/unlock", kms.UnlockRequest{Genesis: &g, Policy: &p, Commitments: rep.Commitments,
		CommitSig: rep.CommitSig, Index: 1, Epoch: 1, Share: box}); code != http.StatusForbidden {
		t.Fatalf("share for another boot: %d", code)
	}
	// A genesis document not signed by the pinned admin keys is refused.
	_, stranger, _ := ed25519.GenerateKey(rand.Reader)
	var doc kms.GenesisDoc
	kms.Strict(r.genesisEnv.Payload, &doc)
	bad := r.sign(kms.KindGenesis, doc, stranger)
	if code, _ := call(s5, http.MethodPost, "/v1/unlock", kms.UnlockRequest{Genesis: &bad, Index: 1, Epoch: 1, Share: box}); code != http.StatusForbidden {
		t.Fatalf("unsigned genesis: %d", code)
	}
}

func TestGenesisNeedsSignedDocForThisBoot(t *testing.T) {
	r := newRig(t)
	s := r.server(nil)
	a := r.attestKMS(s)
	var recips []string
	for _, k := range r.recips {
		recips = append(recips, kms.RecipientString(k.PublicKey()))
	}
	doc := kms.GenesisDoc{Recipients: recips, Threshold: 2, AdminKeys: []string{kms.IDString(r.adminPub)}, AdminThreshold: 1,
		Floor: "v0.19.0", Target: hex.EncodeToString(a.Key.Bytes()), IssuedAt: r.clock()}
	_, stranger, _ := ed25519.GenerateKey(rand.Reader)
	other := doc
	other.Target = strings.Repeat("00", 32)
	otherAdmins := doc
	otherAdmins.AdminKeys = append([]string{kms.IDString(stranger.Public().(ed25519.PublicKey))}, doc.AdminKeys...)
	for name, req := range map[string]kms.GenesisRequest{
		"signed by a stranger":    {Genesis: r.sign(kms.KindGenesis, doc, stranger), Policy: r.policyEnv()},
		"for another boot":        {Genesis: r.sign(kms.KindGenesis, other), Policy: r.policyEnv()},
		"names other admin keys":  {Genesis: r.sign(kms.KindGenesis, otherAdmins), Policy: r.policyEnv()},
		"policy signed by nobody": {Genesis: r.sign(kms.KindGenesis, doc), Policy: r.sign(kms.KindPolicy, r.policy, stranger)},
		"policy kind as genesis":  {Genesis: r.sign(kms.KindPolicy, doc), Policy: r.policyEnv()},
	} {
		if code, b := call(s, http.MethodPost, "/v1/genesis", req); code == http.StatusOK {
			t.Errorf("%s: accepted (%s)", name, b)
		}
	}
	if s.Status().State != "empty" {
		t.Fatal("a refused genesis changed the state")
	}
	// A pinned replica never runs genesis.
	p, _, _ := ed25519.GenerateKey(rand.Reader)
	if code, _ := call(r.server(p), http.MethodPost, "/v1/genesis", kms.GenesisRequest{Genesis: r.sign(kms.KindGenesis, doc), Policy: r.policyEnv()}); code == http.StatusOK {
		t.Fatal("genesis on a pinned replica")
	}
}

func TestJoinReplicatesM(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	s1, id, _ := r.unlocked()
	k1, err := r.vmClient(s1, id, r.vm).Release(ctx, vmPurposes)
	if err != nil {
		t.Fatal(err)
	}
	// A standby joins from the primary: M and the documents, never leases or the register.
	s2 := r.standby(id)
	if err := s2.JoinFrom(ctx, client.Handler{H: s1.Handler()}); err != nil {
		t.Fatal(err)
	}
	st := s2.Status()
	if st.State != "unlocked" || st.Role != kms.RoleStandby || st.KMSID != kms.IDString(id) || st.SecretSeq != 1 || st.GensOK {
		t.Fatalf("joined: %+v", st)
	}
	if _, err := kms.VerifyLog(s2.Log(0, 1000), "", id); err != nil {
		t.Fatal(err)
	}
	// It grants nothing: another instance gets no lease there (H2), nor the same one.
	other := &evidence{quote: editEvents(t, r.vmQuote, map[string]string{"instance-id": strings.Repeat("cd", 20)}), info: r.vmInfo}
	for _, ev := range []*evidence{other, r.vm} {
		if _, err := r.vmClient(s2, id, ev).Release(ctx, vmPurposes); !isStatus(err, http.StatusMisdirectedRequest) {
			t.Fatalf("a standby released: %v", err)
		}
	}
	// A primary that comes back from the standby (no shares) has M but no register: it releases nothing until the
	// admins confirm the generations for it, by its own confirm nonce.
	s3 := r.server(id)
	if err := s3.JoinFrom(ctx, client.Handler{H: s2.Handler()}); err != nil {
		t.Fatal(err)
	}
	if _, err := r.vmClient(s3, id, r.vm).Release(ctx, vmPurposes); !isStatus(err, http.StatusServiceUnavailable) {
		t.Fatalf("an unconfirmed primary released: %v", err)
	}
	st3 := s3.Status()
	if st3.GensOK || st3.ConfirmNonce == "" {
		t.Fatalf("joined primary: %+v", st3)
	}
	r.ok(s3, http.MethodPost, "/v1/gen/confirm", r.sign(kms.KindGen, kms.GenConfirm{KMSID: st3.KMSID, Epoch: 1, Nonce: st3.ConfirmNonce,
		IssuedAt: r.clock()}), &st3)
	k3, err := r.vmClient(s3, id, r.vm).Release(ctx, vmPurposes)
	if err != nil {
		t.Fatal(err)
	}
	vk, err := r.vaultClient(s3, id, r.vm).Release(ctx, []string{"conn/v1"})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(k1.Keys["state/v1"], k3.Keys["state/v1"]) || vk.Secrets["EXA_API_KEY"] != testSecrets["EXA_API_KEY"] {
		t.Fatal("joined replica gives other keys or no secrets")
	}
	// A primary gives M to standbys only.
	s4 := r.server(id)
	if err := s4.JoinFrom(ctx, client.Handler{H: s1.Handler()}); err == nil || !strings.Contains(err.Error(), "standbys only") || s4.Status().State != "locked" {
		t.Fatalf("a primary joined a primary: %v", err)
	}
	// A peer pinned to another KMS id refuses the reply (not signed by its pin) and stays locked.
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	s5 := r.standby(otherPub)
	if err := s5.JoinFrom(ctx, client.Handler{H: s1.Handler()}); err == nil || s5.Status().State != "locked" {
		t.Fatalf("join with another pin: %v", err)
	}
	// A replica refuses to give M to a peer whose compose isn't a pinned KMS release.
	r.policy.Seq, r.policy.KMS = r.policy.Seq+1, []kms.ReleasePin{r.policy.KMS[0], {App: "kms", Version: "v0.1.1", AppComposeSHA256: strings.Repeat("c", 64), Role: kms.RoleStandby}}
	var stt kms.Status
	r.ok(s1, http.MethodPost, "/v1/policy", r.policyEnv(), &stt)
	s6 := r.standby(id)
	if err := s6.JoinFrom(ctx, client.Handler{H: s1.Handler()}); err == nil || !strings.Contains(err.Error(), "isn't a pinned key service release") {
		t.Fatalf("join of an unpinned peer: %v", err)
	}
}

func TestLeaseRenewAndExpiry(t *testing.T) {
	r := newRig(t)
	s, id, _ := r.unlocked()
	c := r.vmClient(s, id, r.vm)
	k, err := c.Release(context.Background(), vmPurposes)
	if err != nil {
		t.Fatal(err)
	}
	exp := k.Lease.Expires
	r.advance(2 * time.Minute)
	l, err := c.Renew(context.Background(), k)
	if err != nil || l.Expires <= exp || l.ID != k.Lease.ID {
		t.Fatalf("renew: %v", err)
	}
	// A renewal replayed, or with another secret, is refused.
	body, _ := json.Marshal(kms.LeaseRenew{App: vmApp, Holder: "agentd", Lease: k.Lease.ID, At: r.clock().Unix(), MAC: kms.RenewMAC(k.LeaseSecret, vmApp, "agentd", k.Lease.ID, r.clock().Unix())})
	var lr kms.LeaseRenew
	json.Unmarshal(body, &lr)
	if code, _ := call(s, http.MethodPost, "/v1/lease/renew", lr); code != http.StatusForbidden {
		t.Fatalf("replayed renewal: %d", code)
	}
	lr.At++
	lr.MAC = kms.RenewMAC(make([]byte, 32), vmApp, "agentd", k.Lease.ID, lr.At)
	if code, _ := call(s, http.MethodPost, "/v1/lease/renew", lr); code != http.StatusForbidden {
		t.Fatalf("renewal without the secret: %d", code)
	}
	// Past expiry the lease is gone: renewal fails, a new release gets a new lease (seq + 1).
	r.advance(kms.LeaseTTL + time.Second)
	if _, err := c.Renew(context.Background(), k); err == nil {
		t.Fatal("renewed an expired lease")
	}
	k2, err := c.Release(context.Background(), vmPurposes)
	if err != nil || k2.Lease.ID == k.Lease.ID || k2.Lease.Seq != k.Lease.Seq+1 {
		t.Fatalf("new lease: %v", err)
	}
}

func TestGenerationRegister(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	s, id, rep := r.unlocked()
	c := r.vmClient(s, id, r.vm)
	k, err := c.Release(ctx, vmPurposes)
	if err != nil {
		t.Fatal(err)
	}
	const name = "state/side"
	h1, h2, h3 := strings.Repeat("a1", 32), strings.Repeat("b2", 32), strings.Repeat("c3", 32)
	if g, err := c.Generation(ctx, vmApp, name); err != nil || g.Gen.Gen != 0 || !g.Stored {
		t.Fatalf("empty register: %+v %v", g, err)
	}
	// A save reserves gen+1 first; the next one waits until that is stored. An unstored reservation may be made again
	// (the VM stopped before storing it), and only the reserved hash is marked stored.
	if g, err := c.Reserve(ctx, k, name, 1, h1); err != nil || g.Stored || g.Gen.Hash != h1 {
		t.Fatalf("reserve 1: %+v %v", g, err)
	}
	for _, gen := range []uint64{2, 3} {
		if _, err := c.Reserve(ctx, k, name, gen, h2); !isStatus(err, http.StatusConflict) {
			t.Fatalf("reserve %d over an unstored 1: %v", gen, err)
		}
	}
	if _, err := c.Reserve(ctx, k, name, 1, h2); err != nil {
		t.Fatalf("reserve 1 again: %v", err)
	}
	if _, err := c.MarkStored(ctx, k, name, 1, h1); !isStatus(err, http.StatusConflict) {
		t.Fatalf("stored mark for a hash not reserved: %v", err)
	}
	if g, err := c.MarkStored(ctx, k, name, 1, h2); err != nil || !g.Stored {
		t.Fatalf("stored 1: %+v %v", g, err)
	}
	for _, gen := range []uint64{1, 3} {
		if _, err := c.Reserve(ctx, k, name, gen, h3); !isStatus(err, http.StatusConflict) {
			t.Fatalf("gen %d after a stored 1: %v", gen, err)
		}
	}
	if _, err := c.Reserve(ctx, k, name, 2, h3); err != nil {
		t.Fatal(err)
	}
	if g, err := c.Generation(ctx, vmApp, name); err != nil || g.Gen.Gen != 2 || g.Gen.Hash != h3 || g.Prev != h2 || g.Stored {
		t.Fatalf("register: %+v %v", g, err)
	}
	// Only under its lease's prefixes (state/v1 gives "state/"), and only with the lease secret.
	if _, err := c.Reserve(ctx, k, "conn/connections", 1, h1); !isStatus(err, http.StatusForbidden) {
		t.Fatalf("a commit outside the lease's purposes: %v", err)
	}
	forged := *k
	forged.LeaseSecret = make([]byte, 32)
	if _, err := c.MarkStored(ctx, &forged, name, 2, h3); !isStatus(err, http.StatusForbidden) {
		t.Fatalf("commit without the lease: %v", err)
	}
	// After a cold start the register waits for the admins' confirmation.
	s2 := r.server(id)
	r.unlockWith(s2, rep, 0, true)
	r.unlockWith(s2, rep, 1, false)
	c2 := r.vmClient(s2, id, r.vm)
	if _, err := c2.Generation(ctx, vmApp, name); !isStatus(err, http.StatusServiceUnavailable) {
		t.Fatalf("read before confirmation: %v", err)
	}
	st2 := s2.Status()
	conf := r.sign(kms.KindGen, kms.GenConfirm{KMSID: st2.KMSID, Epoch: 1, Nonce: st2.ConfirmNonce,
		Gens: []kms.Gen{{App: vmApp, Name: name, Gen: 1, Hash: h2}}, IssuedAt: r.clock()})
	// A confirmation needs the admin keys.
	_, stranger, _ := ed25519.GenerateKey(rand.Reader)
	if code, _ := call(s2, http.MethodPost, "/v1/gen/confirm", r.sign(kms.KindGen, kms.GenConfirm{KMSID: st2.KMSID, Epoch: 1, Nonce: st2.ConfirmNonce,
		IssuedAt: r.clock()}, stranger)); code != http.StatusForbidden {
		t.Fatalf("stranger's confirmation: %d", code)
	}
	var st kms.Status
	r.ok(s2, http.MethodPost, "/v1/gen/confirm", conf, &st)
	if !st.GensOK || st.ConfirmNonce != "" {
		t.Fatalf("not confirmed: %+v", st)
	}
	if g, err := c2.Generation(ctx, vmApp, name); err != nil || g.Gen.Gen != 1 || !g.Stored {
		t.Fatalf("after confirmation: %+v %v", g, err)
	}
}

func TestSecretsBundle(t *testing.T) {
	r := newRig(t)
	s, _, _ := r.unlocked()
	s.mu.Lock()
	seq1 := s.mustSeal(t)
	s.mu.Unlock()
	// Not admin-signed: refused (anyone could otherwise swap in their own API keys and read the VM's traffic).
	_, stranger, _ := ed25519.GenerateKey(rand.Reader)
	a := r.attestKMS(s)
	env := r.sign(kms.KindSecrets, kms.SecretsDoc{KMSID: s.Status().KMSID, Epoch: 1, Seq: 2, Values: map[string]string{"EXA_API_KEY": "attacker"}}, stranger)
	b, _ := json.Marshal(env)
	box, _ := kms.Seal(a.Key, kms.LabelSecretPut, []byte(s.Status().KMSID), b)
	if code, _ := call(s, http.MethodPost, "/v1/secrets/put", kms.SecretsPut{Sealed: box}); code != http.StatusForbidden {
		t.Fatalf("stranger's secrets: %d", code)
	}
	// An older seq is refused; a newer one replaces.
	env = r.sign(kms.KindSecrets, kms.SecretsDoc{KMSID: s.Status().KMSID, Epoch: 1, Seq: 1, Values: map[string]string{"EXA_API_KEY": "x"}})
	b, _ = json.Marshal(env)
	box, _ = kms.Seal(a.Key, kms.LabelSecretPut, []byte(s.Status().KMSID), b)
	if code, _ := call(s, http.MethodPost, "/v1/secrets/put", kms.SecretsPut{Sealed: box}); code != http.StatusConflict {
		t.Fatalf("same seq again: %d", code)
	}
	newer := r.putSecrets(s, 2, map[string]string{"EXA_API_KEY": "exa-2", "TINFOIL_API_KEY": "tin-2"})
	// secrets.sealed is ciphertext under M: it holds no value, and doesn't open on another KMS.
	assertNoLeak(t, "secrets.sealed", newer.Sealed, [][]byte{[]byte("exa-2"), []byte("tin-2")})
	other := newRig(t)
	o, _, _ := other.unlocked()
	if code, _ := call(o, http.MethodPost, "/v1/secrets/load", kms.SecretsLoad{Sealed: newer.Sealed}); code != http.StatusForbidden {
		t.Fatalf("bundle opened on another KMS: %d", code)
	}
	// Loading an older bundle back is refused (a rollback to revoked keys); the current one loads again.
	if code, _ := call(s, http.MethodPost, "/v1/secrets/load", kms.SecretsLoad{Sealed: seq1}); code != http.StatusConflict {
		t.Fatalf("older bundle: %d", code)
	}
	var sl kms.SecretsReply
	r.ok(s, http.MethodPost, "/v1/secrets/load", kms.SecretsLoad{Sealed: newer.Sealed}, &sl)
	if sl.Seq != 2 {
		t.Fatal("seq")
	}
}

func TestPolicyUpdates(t *testing.T) {
	r := newRig(t)
	s, id, _ := r.unlocked()
	// Same seq, other content: refused. Lower: refused. Below the compose floor: refused.
	r.policy.Floor = "v0.19.1"
	if code, _ := call(s, http.MethodPost, "/v1/policy", r.policyEnv()); code != http.StatusConflict {
		t.Fatalf("same seq, other policy: %d", code)
	}
	cfg := r.config(id)
	cfg.FloorMin = "v0.20.0"
	s2, _ := New(cfg)
	r.policy.Seq = 5
	if code, _ := call(s2, http.MethodPost, "/v1/policy", r.policyEnv()); code != http.StatusForbidden {
		t.Fatalf("policy below the compose floor: %d", code)
	}
	var st kms.Status
	r.ok(s, http.MethodPost, "/v1/policy", r.policyEnv(), &st)
	if st.PolicySeq != 5 {
		t.Fatal("newer policy not loaded")
	}
}

func TestReplicaAttestationRules(t *testing.T) {
	r := newRig(t)
	s := r.server(nil)
	n := make([]byte, 32)
	rand.Read(n)
	att, err := s.Attest(context.Background(), n)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyKMS(context.Background(), att, n, &r.policy, r.opts()); err != nil {
		t.Fatal(err)
	}
	// The agent VM's pins don't make a KMS, and the KMS's don't make a VM.
	if _, err := VerifyVM(context.Background(), att, n, &r.policy, r.opts()); err == nil {
		t.Fatal("KMS attestation passed as a VM")
	}
	// Each of the KMS compose rule's refusals, on a compose otherwise like ours.
	for name, c := range map[string]string{
		"named volume":   strings.Replace(kmsComposeYAML, "      - /var/run/dstack.sock:/var/run/dstack.sock", "      - data:/data", 1) + "volumes:\n  data:\n",
		"environment":    strings.Replace(kmsComposeYAML, "    logging:", "    environment:\n      X: y\n    logging:", 1),
		"logging on":     strings.Replace(kmsComposeYAML, "driver: none", "driver: json-file", 1),
		"swap":           strings.Replace(kmsComposeYAML, "memswap_limit: 512m", "memswap_limit: 2g", 1),
		"tag":            strings.Replace(kmsComposeYAML, "@sha256:1111111111111111111111111111111111111111111111111111111111111111", ":latest", 1),
		"second service": kmsComposeYAML + "  other:\n    image: ghcr.io/x/y@sha256:" + strings.Repeat("2", 64) + "\n",
		"writable root":  strings.Replace(kmsComposeYAML, "read_only: true", "read_only: false", 1),
		"privileged":     strings.Replace(kmsComposeYAML, "    read_only: true", "    read_only: true\n    privileged: true", 1),
	} {
		if CheckCompose(c) == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if err := CheckCompose(kmsComposeYAML); err != nil {
		t.Fatal(err)
	}
	// Memory volumes are fine (nothing reaches the disk).
	withTmpfs := strings.Replace(kmsComposeYAML, "      - /var/run/dstack.sock:/var/run/dstack.sock",
		"      - /var/run/dstack.sock:/var/run/dstack.sock\n      - scratch:/scratch", 1) +
		"volumes:\n  scratch:\n    driver_opts:\n      type: tmpfs\n      device: tmpfs\n"
	if err := CheckCompose(withTmpfs); err != nil {
		t.Fatalf("tmpfs volume: %v", err)
	}
}

// The key service release's app-compose.json, as KMSAppCompose makes it, passes the verifier's rules on the real
// 0.6.5 quote (the rig's replicas use it): KMS fallback with the pinned root, port 8000 only, kmsd only.
func TestKMSAppComposeOnRecorded065(t *testing.T) {
	r := newRig(t)
	kac, err := KMSAppCompose([]byte(r.kmsCompose))
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	json.Unmarshal(kac, &m)
	pp, _ := json.Marshal(m["port_policy"])
	if m["name"] != KMSAppComposeName || m["key_provider"] != "kms" || m["swap_size"] != "0" || m["tproxy_enabled"] != true ||
		m["key_provider_id"] == nil || m["pre_launch_script"] != nil || string(pp) != `{"ports":[{"port":8000,"pp":false}],"restrict_mode":true}` ||
		strings.Contains(string(kac), `<`) {
		t.Fatalf("kms app-compose %s", kac)
	}
	a := r.attestKMS(r.server(nil))
	if a.Instance != recordedInstance || a.Facts["image kmsd"] == "" || a.Facts["OS image"] != "dstack-0.6.5" ||
		a.Facts["key mode"] != "kms" || a.ComposeHash != sum(kac) {
		t.Fatalf("facts %v", a.Facts)
	}
	// Pinned, but on the agent VM's port: the verifier's port rule refuses it.
	var m2 map[string]any
	json.Unmarshal(kac, &m2)
	m2["port_policy"] = map[string]any{"ports": []any{map[string]any{"port": 8080, "pp": false}}, "restrict_mode": true}
	alt, _ := json.Marshal(m2)
	r.policy.KMS = append(r.policy.KMS, kms.ReleasePin{App: "kms", Version: "v0.1.1", AppComposeSHA256: sum(alt)})
	r.kmsEv.set(editEvents(t, r.recQuote, map[string]string{"compose-hash": sum(alt)}), setAppCompose(t, r.vmInfo, alt))
	n := make([]byte, 32)
	rand.Read(n)
	att, _ := r.server(nil).Attest(context.Background(), n)
	if _, err := VerifyKMS(context.Background(), att, n, &r.policy, r.opts()); err == nil || !strings.Contains(err.Error(), "want only 8000") {
		t.Fatalf("KMS on port 8080: %v", err)
	}
	// And the KMS refuses to run in the fallback unless the policy allows it.
	r.kmsEv.set(editEvents(t, r.recQuote, map[string]string{"compose-hash": sum(kac)}), setAppCompose(t, r.vmInfo, kac))
	r.policy.KMSFallback = false
	att, _ = r.server(nil).Attest(context.Background(), n)
	if _, err := VerifyKMS(context.Background(), att, n, &r.policy, r.opts()); err == nil || !strings.Contains(err.Error(), "explicit KMS fallback") {
		t.Fatalf("KMS fallback not allowed: %v", err)
	}
}

// Phala writes swap_size as a string.
func TestKMSSwapSize(t *testing.T) {
	for raw, ok := range map[string]bool{`"0"`: true, `"0G"`: true, `"0 MB"`: true, `0`: true, `null`: true, ``: true,
		`"2G"`: false, `2`: false, `"10"`: false, `""`: false, `"G"`: false} {
		ac := `{"allowed_envs":[]`
		if raw != "" {
			ac += `,"swap_size":` + raw
		}
		ac += `}`
		if err := checkKMSAppCompose([]byte(ac)); (err == nil) != ok {
			t.Errorf("swap_size %s: %v", raw, err)
		}
	}
}
