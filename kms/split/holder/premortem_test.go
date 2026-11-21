package holder

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/tacyhq/tacy/kms"
	"github.com/tacyhq/tacy/kms/split"
	"github.com/tacyhq/tacy/safety"
)

// the no-downtime plan "vm-root leaked": an offline re-split to epoch e+1 (same M, same KMS id, no client change). During the
// overlap the policy names epoch 2 and carries the epoch-1 set too; the VM gets R_2 once holders serve it, keys
// differ from epoch 1's, and R_1 opens nothing of epoch 2.
func TestEpochRotation(t *testing.T) {
	r := newRig(t, twoOfTwo, 2)
	oldSet, oldCert := r.set, r.pol.EpochCerts[0]
	newSet, newShares, err := split.Resplit(r.master, r.kmsID, 2, 3, 2, []split.HolderRecipient{
		{Holder: "cloudflare", Recipient: PublicKeyOf(r.keys["cloudflare"])}, {Holder: "vercel", Recipient: PublicKeyOf(r.keys["vercel"])}},
		r.now, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	newCert, err := r.epochCert(2)
	if err != nil {
		t.Fatal(err)
	}
	r.pol.Seq, r.pol.Epoch = 6, 2
	r.pol.ShareSets = []split.SignedShareSet{*oldSet, *newSet}
	r.pol.EpochCerts = []split.SignedEpochCert{oldCert, *newCert}

	// Holders not yet redeployed: the VM falls back to epoch 1.
	m, rep, err := r.unlock(r.transports(nil), nil)
	if err != nil || rep.Set != 2 {
		t.Fatalf("epoch 1 during the overlap: %v %+v", err, rep)
	}
	r.mustEpoch(m, 1)
	k1, _ := m.Key(vmApp, "f_chat", "state/v1")

	// Holders serve both: epoch 2.
	for _, s := range newShares {
		old := r.shares[s.Holder]
		r.shares[s.Holder] = s
		r.holders[s.Holder] = r.newHolder(s.Holder, func(c *Config) { c.Shares = []split.HolderShare{s, old} })
	}
	m, rep, err = r.unlock(r.transports(nil), nil)
	if err != nil || rep.Set != 3 {
		t.Fatalf("epoch 2: %v %+v", err, rep)
	}
	r.mustEpoch(m, 2)
	if k2, _ := m.Key(vmApp, "f_chat", "state/v1"); bytes.Equal(k1, k2) {
		t.Fatal("epoch 2 derives epoch 1's keys")
	}
	if m.Cert.Epoch != 2 {
		t.Fatal("the epoch-2 root came with another epoch's certificate")
	}

	// A leaked R_1 opens nothing of epoch 2.
	r1, _ := split.EpochRoot(r.master, 1)
	r2, _ := split.EpochRoot(r.master, 2)
	sealed, err := split.SealSecrets(r2, split.SecretsBundle{KMSID: r.kmsID, Epoch: 2, Seq: 1, Values: map[string]string{"EXA_API_KEY": "x"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := split.OpenSecrets(r1, r.kmsID, 2, sealed); err == nil {
		t.Fatal("R_1 opened epoch 2's secrets")
	}
	if b, err := m.OpenSecrets(sealed); err != nil || b.Values["EXA_API_KEY"] != "x" {
		t.Fatalf("epoch 2's secrets: %v", err)
	}

	// Malformed: a share set two epochs back, a set whose epoch has no certificate.
	r.pol.Epoch = 3
	if _, _, err := r.unlock(r.transports(nil), nil); err == nil || !strings.Contains(err.Error(), "of epoch 1, the policy's is 3") {
		t.Fatalf("a set two epochs back: %v", err)
	}
	r.pol.Epoch = 2
	r.pol.EpochCerts = []split.SignedEpochCert{oldCert}
	if _, _, err := r.unlock(r.transports(nil), nil); err == nil || !strings.Contains(err.Error(), "isn't certified") {
		t.Fatalf("a set without its epoch certificate: %v", err)
	}
}

// Admin key containment: a newly pinned release unlocks only 24 h after a holder first saw it (with an alert then);
// a withdrawal and a floor raise apply at once.
func TestPinDelayAndImmediateWithdrawal(t *testing.T) {
	r := newRig(t, twoOfTwo, 2)
	for _, h := range r.ids {
		r.holders[h] = r.newHolder(h, func(c *Config) { c.NoPinDelay = false })
	}
	if _, rep, err := r.unlock(r.transports(nil), nil); err == nil || !strings.Contains(rep.Outcome["cloudflare"], "was first allowed here at") {
		t.Fatalf("a new pin unlocked at once: %v %v", err, rep.Outcome)
	}
	r.mu.Lock()
	var pinAlerts int
	for _, e := range r.events {
		if e.Kind == "pin" && e.Release == vmRelease {
			pinAlerts++
		}
	}
	r.mu.Unlock()
	if pinAlerts != 2 {
		t.Fatalf("each holder should alert once on the new pin, got %d", pinAlerts)
	}
	r.advance(23 * time.Hour)
	if _, _, err := r.unlock(r.transports(nil), nil); err == nil {
		t.Fatal("unlocked 23 h after the pin was first seen")
	}
	r.advance(time.Hour + time.Minute)
	if _, rep, err := r.unlock(r.transports(nil), nil); err != nil {
		t.Fatalf("24 h after: %v %v", err, rep.Outcome)
	}

	// A floor raise (seq 6) applies at once, at both holders, once pushed.
	newer := r.pol
	newer.Seq, newer.Floor = 6, "v0.20.0"
	env := r.sign(split.KindUnlockPolicy, newer)
	for _, h := range r.ids {
		if _, err := r.holders[h].PushPolicy(context.Background(), env); err != nil {
			t.Fatal(err)
		}
	}
	if _, rep, err := r.unlock(r.transports(nil), nil); err == nil || !strings.Contains(rep.Outcome["vercel"], "older than this holder's seq 6") {
		t.Fatalf("the old policy after the floor raise: %v %v", err, rep.Outcome)
	}
	r.pol = newer
	if _, rep, err := r.unlock(r.transports(nil), nil); err == nil || !strings.Contains(rep.Outcome["vercel"], "below the policy floor") {
		t.Fatalf("below the raised floor: %v %v", err, rep.Outcome)
	}
}

// Seq containment: a seq more than MaxSeqJump above the holder's is refused; an uninitialized store refuses
// everything; the seq is per admin-key generation, so a rotation isn't blocked by a stolen old key's pushes.
func TestSeqJumpAndGenerations(t *testing.T) {
	r := newRig(t, twoOfTwo, 2)
	h := r.holders["cloudflare"]
	jump := r.pol
	jump.Seq = 5 + split.MaxSeqJump + 1
	req := r.request(r.unlockConfig(nil, nil), nil)
	req.Policy = r.sign(split.KindUnlockPolicy, jump)
	wantRefused(t, h, req, "jumps more than 1000 above this holder's seq 0")

	// The old key's holder pushed its seq high (seq 900, under the old generation).
	high := r.pol
	high.Seq = 900
	if _, err := h.PushPolicy(context.Background(), r.sign(split.KindUnlockPolicy, high)); err != nil {
		t.Fatal(err)
	}
	// Rotation: a holder deploy with the new admin key and generation; its store isn't initialized yet: refused.
	newPub, newKey, _ := ed25519.GenerateKey(rand.Reader)
	rotated := func(c *Config) {
		c.Admin, c.AdminGeneration = kms.AdminKeys{Keys: []ed25519.PublicKey{newPub}, Threshold: 1}, "kms-admin-2"
	}
	h2 := r.newHolder("cloudflare", rotated)
	fresh := r.pol
	fresh.Seq = 1
	req = r.request(r.unlockConfig(nil, nil), nil)
	req.Policy = r.sign(split.KindUnlockPolicy, fresh, newKey)
	wantRefused(t, h2, req, "isn't initialized for kms-admin-2")
	// The deploy initializes it: seq 1 under the new key works, whatever the old generation reached.
	r.stores["cloudflare"].Init("kms-admin-2", 0)
	req = r.request(r.unlockConfig(nil, nil), nil)
	req.Policy = r.sign(split.KindUnlockPolicy, fresh, newKey)
	if _, err := h2.Unlock(context.Background(), req); err != nil {
		t.Fatalf("the new generation: %v", err)
	}
	// The old key no longer counts at the rotated holder.
	req = r.request(r.unlockConfig(nil, nil), nil)
	req.Policy = r.sign(split.KindUnlockPolicy, high)
	wantRefused(t, h2, req, "admin signatures")
}

// Start tickets: when the policy names Worker keys, a fresh ticket from one of them is required.
func TestStartTicket(t *testing.T) {
	r := newRig(t, twoOfTwo, 2)
	wpub, wkey, _ := ed25519.GenerateKey(rand.Reader)
	r.pol.StartTicketKeys = []string{kms.IDString(wpub)}
	appID := r.vmAppID(t)
	ticket := func(key ed25519.PrivateKey, at time.Time, app string) json.RawMessage {
		if app == "" {
			app = appID
		}
		b, _ := json.Marshal(split.StartTicket{KMSID: r.kmsID, AppID: app, IssuedAt: at})
		env, _ := json.Marshal(safety.Sign(split.KindStartTicket, b, key))
		return env
	}
	cfg := r.unlockConfig(r.transports(nil), nil)
	if _, rep, err := split.Unlock(context.Background(), cfg); err == nil || !strings.Contains(rep.Outcome["vercel"], "needs a start ticket") {
		t.Fatalf("no ticket: %v %v", err, rep.Outcome)
	}
	_, stranger, _ := ed25519.GenerateKey(rand.Reader)
	for name, c := range map[string]struct {
		t    json.RawMessage
		want string
	}{
		"not the Worker's":   {ticket(stranger, r.now, ""), "start ticket:"},
		"stale":              {ticket(wkey, r.now.Add(-2*time.Hour), ""), "never used here"},
		"another app's":      {ticket(wkey, r.now, strings.Repeat("ab", 20)), "is for app id"},
		"the Worker's fresh": {ticket(wkey, r.now, ""), ""},
	} {
		cfg := r.unlockConfig(r.transports(nil), nil)
		cfg.StartTicket = c.t
		m, rep, err := split.Unlock(context.Background(), cfg)
		if c.want == "" {
			if err != nil {
				t.Fatalf("%s: %v %v", name, err, rep.Outcome)
			}
			r.mustMaster(m)
			// One VM per ticket: the same VM again (a container restart, hours later) unlocks with it; another
			// instance with the same ticket gets nothing.
			r.advance(3 * time.Hour)
			if _, rep, err := split.Unlock(context.Background(), cfg); err != nil {
				t.Fatalf("the same VM after a restart: %v %v", err, rep.Outcome)
			}
			q := editEvents(t, r.recQuote, map[string]string{"compose-hash": r.vmACHash(t), "instance-id": strings.Repeat("ab", 20)})
			other := r.unlockConfig(r.transports(nil), &evidence{quote: q, info: r.vm.info})
			other.StartTicket = c.t
			if _, rep, err := split.Unlock(context.Background(), other); err == nil || !strings.Contains(rep.Outcome["vercel"], "by another VM") {
				t.Fatalf("another VM with the same ticket: %v %v", err, rep.Outcome)
			}
			continue
		}
		if err == nil || !strings.Contains(rep.Outcome["cloudflare"], c.want) {
			t.Fatalf("%s: %v %v", name, err, rep.Outcome)
		}
	}
}

// vmAppID is the rig VM's attested app id.
func (r *rig) vmAppID(t *testing.T) string {
	b, _ := json.Marshal(map[string]any{})
	_ = b
	var info struct {
		AppID string `json:"app_id"`
	}
	json.Unmarshal(r.vm.info, &info)
	return info.AppID
}

// vmACHash is the rig VM's app-compose sha256 (its release pin).
func (r *rig) vmACHash(t *testing.T) string { return r.pol.Releases[0].AppComposeSHA256 }
