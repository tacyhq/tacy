package server

// Regression tests for the independent security review of the key service (2026-11-20): each one is a probe of the
// review ported to the fixed behaviour; each failed on f4b1aedb.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/tacyhq/tacy/kms"
	"github.com/tacyhq/tacy/kms/client"
)

// H1: unauthenticated requests can't grow the audit log: refusals are counted (a summary entry at most about once a
// minute), every detail is capped and escaped, and the log is bounded by bytes.
func TestReviewH1AuditLogBounded(t *testing.T) {
	r := newRig(t)
	s, _, _ := r.unlocked()
	big := strings.Repeat("A", 900<<10)
	before := len(s.Log(0, 1<<30))
	for i := 0; i < 20; i++ {
		code, _ := call(s, http.MethodPost, "/v1/gen/commit", kms.GenCommit{Gen: kms.Gen{App: "agent-vm", Name: big, Gen: 1, Hash: "x"}})
		if code == http.StatusOK {
			t.Fatal("accepted")
		}
	}
	log := s.Log(0, 1<<30)
	total := 0
	for _, e := range log {
		total += len(e.Detail)
		if len(e.Detail) > kms.MaxDetail+len("…") {
			t.Fatalf("an entry of %d bytes", len(e.Detail))
		}
	}
	if total > 8<<10 || len(log) > before+1 || s.Status().Refused != 20 {
		t.Fatalf("20 unauthenticated commits: %d entries (were %d), %d bytes of detail, %d counted", len(log), before, total, s.Status().Refused)
	}
	if last := log[len(log)-1]; last.Kind != "refused" || !strings.Contains(last.Detail, "20 unauthenticated") || strings.Contains(last.Detail, "AAAA") {
		t.Fatalf("summary %+v", last)
	}
	// A summary entry is written at most about once a minute: more spam stays counted, not stored.
	for i := 0; i < 50; i++ {
		call(s, http.MethodPost, "/v1/gen/commit", kms.GenCommit{Gen: kms.Gen{App: "agent-vm", Name: "x", Gen: 1}})
		s.Log(0, 1)
	}
	if n := len(s.Log(0, 1<<30)); n > len(log)+30 {
		t.Fatalf("log reads turned refusals into %d entries", n-len(log))
	}
	// Details are escaped: no caller's newline or control byte reaches a log line.
	if d := cleanDetail("a\nb\x00c\\" + string([]byte{0xff}) + strings.Repeat("z", 400)); strings.ContainsAny(d, "\n\x00") ||
		!strings.HasPrefix(d, `a\nb\x00c\\\xff`) || len(d) > kms.MaxDetail+len("…") {
		t.Fatalf("detail %q", d)
	}
	// The log is bounded by bytes too.
	cfg := r.config(nil)
	cfg.MaxLogBytes = 4 << 10
	small, _ := New(cfg)
	for i := 0; i < 200; i++ {
		small.mu.Lock()
		small.audit("gen", true, "agent-vm", "", strings.Repeat("d", 200))
		small.mu.Unlock()
	}
	small.mu.Lock()
	n, size := len(small.log), small.logBytes
	small.mu.Unlock()
	if size > 4<<10 || n >= 200 {
		t.Fatalf("log kept %d entries, %d bytes (cap 4 KiB)", n, size)
	}
}

// H1 and L1: refusals, challenges and quotes are rate limited; challenges past kms.MaxChallenges push out the oldest
// rather than locking everyone out.
func TestReviewL1RateLimits(t *testing.T) {
	r := newRig(t)
	cfg := r.config(nil)
	cfg.Limits = Limits{Challenge: Bucket{1, 3}, Attest: Bucket{1, 2}, Refusal: Bucket{1, 5}}
	s, _ := New(cfg)
	for i := 0; i < 3; i++ {
		if code, b := call(s, http.MethodGet, "/v1/challenge", nil); code != http.StatusOK {
			t.Fatalf("challenge %d: %d %s", i, code, b)
		}
	}
	if code, _ := call(s, http.MethodGet, "/v1/challenge", nil); code != http.StatusTooManyRequests {
		t.Fatalf("4th challenge at once: %d", code)
	}
	r.advance(2 * time.Second)
	if code, _ := call(s, http.MethodGet, "/v1/challenge", nil); code != http.StatusOK {
		t.Fatalf("a challenge after the refill: %d", code)
	}
	n := hex.EncodeToString(make([]byte, 32))
	for i := 0; i < 2; i++ {
		if code, _ := call(s, http.MethodGet, "/v1/attest?nonce="+n, nil); code != http.StatusOK {
			t.Fatalf("attest %d: %d", i, code)
		}
	}
	if code, _ := call(s, http.MethodGet, "/v1/attest?nonce="+n, nil); code != http.StatusTooManyRequests {
		t.Fatalf("3rd quote at once: %d", code)
	}
	// Refusals drain their bucket; then costly unauthenticated work (releases, joins, unlocks) waits.
	for i := 0; i < 6; i++ {
		call(s, http.MethodPost, "/v1/gen/commit", kms.GenCommit{})
	}
	if code, b := call(s, http.MethodPost, "/v1/unlock", kms.UnlockRequest{}); code != http.StatusTooManyRequests {
		t.Fatalf("unlock while refusals pour in: %d %s", code, b)
	}
	// The outstanding challenges are bounded, the oldest go first.
	cfg.Limits = Limits{Challenge: Bucket{1e9, 1e9}}
	s2, _ := New(cfg)
	first, _ := s2.Challenge()
	for i := 0; i < kms.MaxChallenges; i++ {
		if _, err := s2.Challenge(); err != nil {
			t.Fatal(err)
		}
	}
	s2.mu.Lock()
	_, kept := s2.nonces[first.Nonce]
	outstanding := len(s2.nonces)
	s2.mu.Unlock()
	if kept || outstanding != kms.MaxChallenges {
		t.Fatalf("%d outstanding, the oldest kept %v", outstanding, kept)
	}
}

// H2: with two replicas, only one grants: a standby refuses every lease and register call; a primary that joined (or
// unlocked) grants nothing until the admins confirm it by its own nonce.
func TestReviewH2ReplicasCantBothGrant(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	s1, id, _ := r.unlocked()
	s2 := r.standby(id)
	if err := s2.JoinFrom(ctx, client.Handler{H: s1.Handler()}); err != nil {
		t.Fatal(err)
	}
	a := r.vmClient(s1, id, r.vm)
	ka, err := a.Release(ctx, vmPurposes)
	if err != nil {
		t.Fatal(err)
	}
	bEv := &evidence{quote: editEvents(t, r.vmQuote, map[string]string{"instance-id": strings.Repeat("cd", 20)}), info: r.vmInfo}
	if _, err := r.vmClient(s2, id, bEv).Release(ctx, vmPurposes); !isStatus(err, http.StatusMisdirectedRequest) {
		t.Fatalf("instance B on the standby: %v", err)
	}
	// A's own calls steered to the standby are refused too: no second register to fork.
	onStandby, _ := client.New(client.Config{KMSID: id, Transport: client.Handler{H: s2.Handler()}, Evidence: r.vm.Evidence, Holder: "agentd", Now: r.clock})
	if _, err := onStandby.Reserve(ctx, ka, "state/side", 1, strings.Repeat("a1", 32)); !isStatus(err, http.StatusMisdirectedRequest) {
		t.Fatalf("a commit on the standby: %v", err)
	}
	if _, err := onStandby.Generation(ctx, vmApp, "state/side"); !isStatus(err, http.StatusMisdirectedRequest) {
		t.Fatalf("a register read on the standby: %v", err)
	}
	if _, err := onStandby.Renew(ctx, ka); !isStatus(err, http.StatusMisdirectedRequest) {
		t.Fatalf("a renewal on the standby: %v", err)
	}
	// A second primary made from the standby: nothing until the admins confirm it.
	s3 := r.server(id)
	if err := s3.JoinFrom(ctx, client.Handler{H: s2.Handler()}); err != nil {
		t.Fatal(err)
	}
	if _, err := r.vmClient(s3, id, bEv).Release(ctx, vmPurposes); !isStatus(err, http.StatusServiceUnavailable) {
		t.Fatalf("instance B on an unconfirmed second primary: %v", err)
	}
	// The register has one writer: A commits on the primary, and only there.
	if _, err := a.Reserve(ctx, ka, "state/side", 1, strings.Repeat("a1", 32)); err != nil {
		t.Fatal(err)
	}
}

// H3: an admin document for another key service (a staging one under the very same admin keys) is refused: policy,
// generation confirmation, secrets bundle and lease move each name their KMS id and epoch.
func TestReviewH3AdminDocsBoundToOneKMS(t *testing.T) {
	r := newRig(t)
	prod := r.server(nil)
	r.genesis(prod)
	prodID := prod.Status().KMSID
	r.putSecrets(prod, 1, testSecrets)
	prodPolicy := r.policy
	staging := r.server(nil)
	r.policy.KMSID = "" // a genesis takes the policy that names no id yet
	r.genesis(staging)  // the rig's policy is now bound to the staging id, with a higher seq
	stagingID := staging.Status().KMSID
	if stagingID == prodID {
		t.Fatal("two geneses, one id")
	}
	stagingPolicy := r.policy
	stagingPolicy.Seq = 99
	stagingPolicy.Releases = append(stagingPolicy.Releases, kms.ReleasePin{App: vmApp, Version: vmRelease, AppComposeSHA256: strings.Repeat("e", 64)})
	if code, b := call(prod, http.MethodPost, "/v1/policy", r.sign(kms.KindPolicy, stagingPolicy)); code != http.StatusForbidden ||
		!strings.Contains(string(b), "another key service") {
		t.Fatalf("a staging policy on production: %d %s", code, b)
	}
	// The policy genesis takes (no id yet) isn't a policy for production either.
	unbound := prodPolicy
	unbound.KMSID, unbound.Seq = "", 50
	if code, _ := call(prod, http.MethodPost, "/v1/policy", r.sign(kms.KindPolicy, unbound)); code != http.StatusForbidden {
		t.Fatalf("an unbound policy on production: %d", code)
	}
	// Another epoch, too.
	other := prodPolicy
	other.Seq, other.Epoch = 51, 2
	if code, _ := call(prod, http.MethodPost, "/v1/policy", r.sign(kms.KindPolicy, other)); code != http.StatusForbidden {
		t.Fatalf("a policy for epoch 2: %d", code)
	}
	if prod.Status().PolicySeq != prodPolicy.Seq {
		t.Fatal("production's policy changed")
	}
	// A secrets bundle for staging, sealed to production's attested key, is refused.
	a := r.attestKMS(prod)
	env := r.sign(kms.KindSecrets, kms.SecretsDoc{KMSID: stagingID, Epoch: 1, Seq: 9, Values: map[string]string{"EXA_API_KEY": "staging"}, IssuedAt: r.clock()})
	eb := mustJSON(env)
	box, _ := kms.Seal(a.Key, kms.LabelSecretPut, []byte(prodID), eb)
	if code, b := call(prod, http.MethodPost, "/v1/secrets/put", kms.SecretsPut{Sealed: box}); code != http.StatusForbidden || !strings.Contains(string(b), "another key service") {
		t.Fatalf("staging secrets on production: %d %s", code, b)
	}
	// A lease move for staging does nothing on production.
	id, _ := kms.ParseID(prodID)
	k, err := r.vmClient(prod, id, r.vm).Release(context.Background(), vmPurposes)
	if err != nil {
		t.Fatal(err)
	}
	mv := kms.LeaseMove{KMSID: stagingID, Epoch: 1, App: vmApp, Holder: "agentd", Lease: k.Lease.ID, IssuedAt: r.clock()}
	if code, _ := call(prod, http.MethodPost, "/v1/lease/move", r.sign(kms.KindLeaseMove, mv, r.worker)); code != http.StatusForbidden {
		t.Fatalf("a staging lease move on production: %d", code)
	}
	// A generation confirmation names its KMS id and confirm nonce too: TestReviewM2ConfirmationOnceAndFresh.
}

// M1: a register read is signed over the caller's nonce: an old answer replayed doesn't verify.
func TestReviewM1RegisterReadsAreFresh(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	s, id, _ := r.unlocked()
	c := r.vmClient(s, id, r.vm)
	k, err := c.Release(ctx, vmPurposes)
	if err != nil {
		t.Fatal(err)
	}
	h1, h2 := strings.Repeat("a1", 32), strings.Repeat("b2", 32)
	c.Reserve(ctx, k, "state/side", 1, h1)
	c.MarkStored(ctx, k, "state/side", 1, h1)
	oldNonce := client.NewNonce()
	_, old := call(s, http.MethodGet, "/v1/gen?app="+vmApp+"&name=state/side&nonce="+oldNonce, nil)
	if _, err := client.CheckGen(old, id, oldNonce); err != nil {
		t.Fatalf("the fresh answer: %v", err)
	}
	c.Reserve(ctx, k, "state/side", 2, h2)
	c.MarkStored(ctx, k, "state/side", 2, h2)
	if _, err := client.CheckGen(old, id, client.NewNonce()); err == nil {
		t.Fatal("an old register answer verifies for a new read")
	}
	// The client's own read through a host that replays the old answer.
	replay := client.Handler{H: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.Write(old) })}
	rc, _ := client.New(client.Config{KMSID: id, Transport: replay, Evidence: r.vm.Evidence, Holder: "agentd"})
	if _, err := rc.Generation(ctx, vmApp, "state/side"); err == nil {
		t.Fatal("a replayed register answer was taken")
	}
	if code, _ := call(s, http.MethodGet, "/v1/gen?app="+vmApp+"&name=state/side", nil); code != http.StatusBadRequest {
		t.Fatalf("a read without a nonce: %d", code)
	}
}

// M2: a generation confirmation is taken once, while the register waits, for this replica's KMS id, epoch and
// confirm nonce, issued within five minutes and not ahead of the clock.
func TestReviewM2ConfirmationOnceAndFresh(t *testing.T) {
	r := newRig(t)
	_, id, rep := r.unlocked()
	cold := func() *Server {
		s := r.server(id)
		r.unlockWith(s, rep, 0, true)
		r.unlockWith(s, rep, 1, false)
		return s
	}
	s := cold()
	st := s.Status()
	doc := func(edit func(*kms.GenConfirm)) any {
		gc := kms.GenConfirm{KMSID: st.KMSID, Epoch: 1, Nonce: st.ConfirmNonce, IssuedAt: r.clock(),
			Gens: []kms.Gen{{App: vmApp, Name: "state/side", Gen: 4, Hash: strings.Repeat("a1", 32)}}}
		if edit != nil {
			edit(&gc)
		}
		return r.sign(kms.KindGen, gc)
	}
	for name, edit := range map[string]func(*kms.GenConfirm){
		"30 days ahead":         func(g *kms.GenConfirm) { g.IssuedAt = r.clock().Add(30 * 24 * time.Hour) },
		"two minutes ahead":     func(g *kms.GenConfirm) { g.IssuedAt = r.clock().Add(2 * time.Minute) },
		"six minutes old":       func(g *kms.GenConfirm) { g.IssuedAt = r.clock().Add(-6 * time.Minute) },
		"another kms id":        func(g *kms.GenConfirm) { g.KMSID = kms.IDString(make(ed25519.PublicKey, 32)) },
		"another epoch":         func(g *kms.GenConfirm) { g.Epoch = 2 },
		"no nonce":              func(g *kms.GenConfirm) { g.Nonce = "" },
		"another nonce":         func(g *kms.GenConfirm) { g.Nonce = client.NewNonce() },
		"an entry listed twice": func(g *kms.GenConfirm) { g.Gens = append(g.Gens, g.Gens[0]) },
	} {
		if code, b := call(s, http.MethodPost, "/v1/gen/confirm", doc(edit)); code == http.StatusOK {
			t.Errorf("%s: accepted (%s)", name, b)
		}
	}
	good := doc(nil)
	var after kms.Status
	r.ok(s, http.MethodPost, "/v1/gen/confirm", good, &after)
	if !after.GensOK || after.ConfirmNonce != "" {
		t.Fatalf("after: %+v", after)
	}
	// The VM moves on to generation 6; the captured confirmation, replayed three minutes later, changes nothing.
	c := r.vmClient(s, id, r.vm)
	k, err := c.Release(context.Background(), vmPurposes)
	if err != nil {
		t.Fatal(err)
	}
	for g := uint64(5); g <= 6; g++ {
		h := strings.Repeat(hex.EncodeToString([]byte{byte(g)}), 32)
		if _, err := c.Reserve(context.Background(), k, "state/side", g, h); err != nil {
			t.Fatal(err)
		}
		if _, err := c.MarkStored(context.Background(), k, "state/side", g, h); err != nil {
			t.Fatal(err)
		}
	}
	r.advance(3 * time.Minute)
	if code, b := call(s, http.MethodPost, "/v1/gen/confirm", good); code != http.StatusConflict {
		t.Fatalf("replayed confirmation: %d %s", code, b)
	}
	if g, err := c.Generation(context.Background(), vmApp, "state/side"); err != nil || g.Gen.Gen != 6 {
		t.Fatalf("register after the replay: %+v %v", g, err)
	}
	// Nor does it confirm another cold start (another replica, another nonce).
	s2 := cold()
	if code, _ := call(s2, http.MethodPost, "/v1/gen/confirm", good); code != http.StatusForbidden {
		t.Fatalf("the confirmation on another cold start: %d", code)
	}
}

// M3: the lease is bound to the holder's boot key: a second TD reporting the same instance id gets nothing while the
// lease is live; the holder itself renews it; once it is dropped or lapses, the next boot takes it.
func TestReviewM3LeaseBoundToBootKey(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	s, id, _ := r.unlocked()
	a := r.vmClient(s, id, r.vm)
	ka, err := a.Release(ctx, vmPurposes)
	if err != nil {
		t.Fatal(err)
	}
	clone := r.vmClient(s, id, r.vm) // same instance id, another boot key
	if _, err := clone.Release(ctx, vmPurposes); !isStatus(err, http.StatusConflict) {
		t.Fatalf("a clone with the same instance id: %v", err)
	}
	ka2, err := a.Release(ctx, vmPurposes) // the holder again: the same lease
	if err != nil || ka2.Lease.ID != ka.Lease.ID || !bytes.Equal(ka2.LeaseSecret, ka.LeaseSecret) {
		t.Fatalf("the holder's second release: %v", err)
	}
	if err := a.Drop(ctx, ka2); err != nil {
		t.Fatal(err)
	}
	kc, err := clone.Release(ctx, vmPurposes)
	if err != nil || kc.Lease.ID == ka.Lease.ID || bytes.Equal(kc.LeaseSecret, ka.LeaseSecret) {
		t.Fatalf("the next boot after the drop: %v", err)
	}
}

// M5: the API keys go only with conn/v1 (vaultd's release), never to agentd's purposes.
func TestReviewM5SecretsOnlyWithConn(t *testing.T) {
	r := newRig(t)
	s, id, _ := r.unlocked()
	k, err := r.vmClient(s, id, r.vm).Release(context.Background(), []string{"state/v1", "activity-sign/v1"})
	if err != nil {
		t.Fatal(err)
	}
	if len(k.Secrets) != 0 {
		t.Fatal("a release without conn/v1 carries the API keys")
	}
	vk, err := r.vaultClient(s, id, r.vm).Release(context.Background(), []string{"conn/v1"})
	if err != nil || len(vk.Secrets) != len(testSecrets) {
		t.Fatalf("vaultd's release: %v", err)
	}
}

// M6: the register is exported signed by the KMS id (offline proof of the generations).
func TestReviewM6RegisterSnapshot(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	s, id, _ := r.unlocked()
	c := r.vmClient(s, id, r.vm)
	k, _ := c.Release(ctx, vmPurposes)
	h := strings.Repeat("a1", 32)
	c.Reserve(ctx, k, "state/side", 1, h)
	c.MarkStored(ctx, k, "state/side", 1, h)
	c.Reserve(ctx, k, "state/side", 2, strings.Repeat("b2", 32))
	ss, err := client.Snapshot(ctx, client.Handler{H: s.Handler()}, id)
	if err != nil {
		t.Fatal(err)
	}
	if len(ss.Snapshot.Entries) != 1 || ss.Snapshot.Entries[0].Gen.Gen != 2 || ss.Snapshot.Entries[0].Stored || ss.Snapshot.Entries[0].Prev != h {
		t.Fatalf("snapshot %+v", ss.Snapshot)
	}
	ss.Snapshot.Entries[0].Gen.Gen = 9
	if client.CheckSnapshot(ss, id) == nil {
		t.Fatal("an edited snapshot verifies")
	}
	if _, err := client.Snapshot(ctx, client.Handler{H: r.standby(id).Handler()}, id); err == nil {
		t.Fatal("a standby answered for the register")
	}
}

// L4: after a cold start, a secrets bundle older than the policy's secrets floor (revoked keys) doesn't load.
func TestReviewL4SecretsFloor(t *testing.T) {
	r := newRig(t)
	s, id, rep := r.unlocked()
	s.mu.Lock()
	seq1 := s.mustSeal(t)
	s.mu.Unlock()
	r.putSecrets(s, 2, map[string]string{"EXA_API_KEY": "exa-2", "TINFOIL_API_KEY": "tin-2"})
	r.policy.Seq++
	r.policy.SecretsFloor = 2
	var st kms.Status
	r.ok(s, http.MethodPost, "/v1/policy", r.policyEnv(), &st)
	s2 := r.server(id)
	r.unlockWith(s2, rep, 0, true)
	r.unlockWith(s2, rep, 1, false)
	if code, b := call(s2, http.MethodPost, "/v1/secrets/load", kms.SecretsLoad{Sealed: seq1}); code != http.StatusConflict || !strings.Contains(string(b), "secrets floor") {
		t.Fatalf("a bundle below the floor after a cold start: %d %s", code, b)
	}
}

// L5: a peer runs with the same admin keys and floor, and at least the policy's key service floor, or no join.
func TestReviewL5JoinChecksPeerFlags(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	s1, id, _ := r.unlocked()
	// A standby built with other admin keys (pinned by the admins by mistake) gets no M.
	_, strangerPriv, _ := ed25519.GenerateKey(rand.Reader)
	strange := strings.Replace(r.kmsCompose, kms.IDString(r.adminPub), kms.IDString(strangerPriv.Public().(ed25519.PublicKey)), 1)
	strange = strings.Replace(strange, `"-admin-keys"`, `"-role", "standby", "-admin-keys"`, 1)
	sac, err := KMSAppCompose([]byte(strange))
	if err != nil {
		t.Fatal(err)
	}
	r.policy.Seq++
	r.policy.KMS = append(r.policy.KMS, kms.ReleasePin{App: "kms", Version: "v0.1.0", AppComposeSHA256: sum(sac), Role: kms.RoleStandby})
	var st kms.Status
	r.ok(s1, http.MethodPost, "/v1/policy", r.policyEnv(), &st)
	cfg := r.config(id)
	cfg.Role = kms.RoleStandby
	cfg.Platform = &evidence{quote: editEvents(t, r.recQuote, map[string]string{"compose-hash": sum(sac)}), info: setAppCompose(t, r.vmInfo, sac)}
	odd, _ := New(cfg)
	if err := odd.JoinFrom(ctx, client.Handler{H: s1.Handler()}); err == nil || odd.Status().State != "locked" {
		t.Fatalf("a peer with other admin keys joined: %v", err)
	}
	// The policy's key service floor refuses older key service releases.
	r.policy.Seq++
	r.policy.KMSFloor = "v0.2.0"
	r.ok(s1, http.MethodPost, "/v1/policy", r.policyEnv(), &st)
	if err := r.standby(id).JoinFrom(ctx, client.Handler{H: s1.Handler()}); err == nil || !strings.Contains(err.Error(), "kms floor") {
		t.Fatalf("a key service below the floor joined: %v", err)
	}
	// A standby pinned as a primary (its -role says standby) isn't taken for one.
	r.policy.KMSFloor = ""
	r.policy.Seq++
	r.policy.KMS[1].Role = kms.RolePrimary
	r.ok(s1, http.MethodPost, "/v1/policy", r.policyEnv(), &st)
	if err := r.standby(id).JoinFrom(ctx, client.Handler{H: s1.Handler()}); err == nil || !strings.Contains(err.Error(), "runs as standby, pinned as primary") {
		t.Fatalf("a mislabeled standby: %v", err)
	}
}
