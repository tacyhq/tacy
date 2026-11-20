package main

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/tacyhq/tacy/activity"
	"github.com/tacyhq/tacy/kms/kmsdev"
	"github.com/tacyhq/tacy/safety"
	"github.com/tacyhq/tacy/sealstate"
	"github.com/tacyhq/tacy/trigger"
	"github.com/tacyhq/tacy/vault"
)

// stubKMS stands in for the key service where a test needs no network: lasting keys from one seed.
type stubKMS struct{ devKeys }

func newStubKMS(seed byte) stubKMS { return stubKMS{devKeys{seed: bytes.Repeat([]byte{seed}, 32)}} }

func (stubKMS) Binding() string { return "agent-vm" }

// providerStub is a host as Phala's would be: its own keys (what dstack's GetKey derived) and its own disk. Nothing
// agentd keeps may depend on either.
type providerStub struct {
	local
	getKey []byte // what /GetKey would answer on this host
	disk   string // the host's data disk (a fresh one per CVM)
}

func newProviderStub(t *testing.T) providerStub {
	k := make([]byte, 32)
	rand.Read(k)
	return providerStub{getKey: k, disk: t.TempDir()}
}

const testIMAPPassword = "canary-imap-app-password-71c2"

// The provider changed its keys (the keys plan §7.3, local part), against a real key service (kms/server) and the Worker's
// sealed-state API over HTTP, through gatewayd's fixed calls: a second boot as another instance on another host
// (another GetKey, an empty disk). Every state comes back: schedules' holders, memory and results, the notification
// switches, the budgets' day counters, the activity chain (same signing key, verifying from its first record across
// both boots), the once-only task-id key, and vaultd's email connection. The generation register goes on; neither
// host's disk holds anything; the Worker holds only sealed blobs.
func TestTwoBootsDifferentProviderSameKeys(t *testing.T) {
	ctx := context.Background()
	w := newKMSWorld(t)
	host1, host2 := newProviderStub(t), newProviderStub(t)
	if bytes.Equal(host1.getKey, host2.getKey) || host1.disk == host2.disk {
		t.Fatal("the two hosts must differ")
	}
	seal, _ := ecdh.X25519().GenerateKey(rand.Reader)
	to := activity.RecipientString(seal.PublicKey())
	now := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)

	// ---- boot 1: instance 1 on host 1 ----
	b1, k1 := w.bootAgent(t, "inst-1")
	if !b1.kept.schedules || b1.kept.keeper == nil {
		t.Fatal("sealed state should turn schedules on")
	}
	if _, err := b1.rec.Begin(activity.Start{Run: "r1", Space: "s_one", To: to, Started: now}); err != nil {
		t.Fatal(err)
	}
	if _, err := b1.rec.Finish("r1", activity.End{Status: activity.Status{State: "succeeded"}}); err != nil {
		t.Fatal(err)
	}
	side := b1.kept.side
	if err := side.PutHolder(trigger.Holder{Space: "s_one", Identity: "i_one", Key: "ed25519:k", Seal: to, At: now}); err != nil {
		t.Fatal(err)
	}
	if err := side.PutMemory(trigger.Remembered{Space: "s_one", Agent: "ag_1", Task: "t1", Day: "2026-11-20", EndedAt: now,
		Text: "canary-memory: the digest remembered"}); err != nil {
		t.Fatal(err)
	}
	if _, err := side.PutResult(trigger.Result{Task: "t1", Space: "s_one", Seal: to, Agent: "ag_1", Version: 1, Trigger: "daily",
		Day: "2026-11-20", ScheduledAt: now, StartedAt: now, EndedAt: now, State: "done", Enc: []byte("enc"), CT: []byte("ct")}); err != nil {
		t.Fatal(err)
	}
	if err := b1.kept.notify.Set("s_one", true); err != nil {
		t.Fatal(err)
	}
	b1.kept.ledger.Now = func() time.Time { return now }
	b1.kept.ledger.Begin("t1", "s_one", "schedule:ag_1")
	commit, err := b1.kept.ledger.Reserve("t1", safety.Usage{CostMicros: 1234}, safety.Budgets{})
	if err != nil {
		t.Fatal(err)
	}
	commit(safety.Usage{CostMicros: 1234})
	b1.kept.ledger.End("t1")
	// vaultd on the same instance: an email account.
	v1, vk1, kv1 := w.bootVault(t, "inst-1")
	putTestConn(t, v1, "s_one")
	// SIGTERM: the keepers' last saves, then each process frees its own lease.
	if err := b1.kept.keeper.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	if err := vk1.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	if err := k1.Drop(ctx); err != nil {
		t.Fatal(err)
	}
	if err := kv1.Drop(ctx); err != nil {
		t.Fatal(err)
	}

	// What the Worker holds: sealed, every state, in the app's namespaces, nothing in the clear.
	held := w.state.Blobs()
	for _, key := range []string{"agent-vm/state/" + stateSide, "agent-vm/state/" + stateActivity, "agent-vm/state/" + stateBudget,
		"agent-vm/state/" + stateNotify, "agent-vm/conn/" + vault.ConnState} {
		blob, ok := held[key]
		if !ok {
			t.Fatalf("%s not saved (held: %d)", key, len(held))
		}
		if !bytes.HasPrefix(blob, []byte(sealstate.Magic)) || bytes.Contains(blob, []byte("canary")) || bytes.Contains(blob, []byte("s_one")) {
			t.Fatalf("%s isn't sealed", key)
		}
	}

	// ---- boot 2: instance 2 on host 2: another GetKey, an empty disk; the same key service and Worker ----
	b2, k2 := w.bootAgent(t, "inst-2")
	if b1.signer.Public() != b2.signer.Public() || !bytes.Equal(b1.idKey, b2.idKey) {
		t.Fatal("the signing or task-id key changed with the instance and host")
	}
	if k2.Lease().Seq != k1.Lease().Seq+1 {
		t.Fatalf("lease seq %d after %d", k2.Lease().Seq, k1.Lease().Seq)
	}
	if h, err := b2.kept.side.Holder("s_one", "i_one"); err != nil || h == nil || h.Seal != to {
		t.Fatalf("holder: %+v %v", h, err)
	}
	if m, err := b2.kept.side.Memories("s_one", "ag_1", now.Add(-time.Hour)); err != nil || len(m) != 1 || m[0].Text != "canary-memory: the digest remembered" {
		t.Fatalf("memory: %+v %v", m, err)
	}
	if r, err := b2.kept.side.Results("s_one", to, 0, 10); err != nil || len(r) != 1 || r[0].Task != "t1" {
		t.Fatalf("results: %+v %v", r, err)
	}
	if !b2.kept.notify.On("s_one") {
		t.Fatal("notifications off after the move")
	}
	b2.kept.ledger.Now = func() time.Time { return now }
	if c := b2.kept.ledger.MembersCost("schedule:"); c["2026-11-20"] != 1234 {
		t.Fatalf("budget: %v", c)
	}
	v2, _, _ := w.bootVault(t, "inst-2")
	if list := v2.ConnList("s_one"); len(list) != 1 {
		t.Fatalf("connections after the move: %+v", list)
	}
	// The chain goes on.
	if _, err := b2.rec.Begin(activity.Start{Run: "r2", Space: "s_one", To: to, Started: now.Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	if _, err := b2.rec.Finish("r2", activity.End{Status: activity.Status{State: "succeeded"}}); err != nil {
		t.Fatal(err)
	}
	chain, head, _ := b2.rec.Head("s_one", to)
	recs, err := b2.kept.activity.Records(chain, 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	trusted := func(k string) bool { return k == b1.signer.Public() }
	end, err := activity.VerifyChain(recs, trusted, nil)
	if err != nil || end != head || head.Seq != 4 {
		t.Fatalf("chain across the boots: %v, end %+v head %+v (%d records)", err, end, head, len(recs))
	}
	if err := b2.kept.keeper.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	// The register followed every save: activity at generation 2 after two boots' saves.
	if e, err := k2.Register(PurposeState).Generation(ctx, stateActivity); err != nil || e.Gen != 2 || !e.Stored ||
		e.Hash != sealstate.BlobHash(w.state.Blobs()["agent-vm/state/"+stateActivity]) {
		t.Fatalf("register: %+v %v", e, err)
	}

	// Neither host's disk holds anything.
	for _, h := range []providerStub{host1, host2} {
		filepath.WalkDir(h.disk, func(p string, d os.DirEntry, err error) error {
			if err == nil && !d.IsDir() {
				t.Errorf("%s on a host's disk", p)
			}
			return nil
		})
	}
	if err := k2.Drop(ctx); err != nil {
		t.Fatal(err)
	}

	// The Worker hands back an older activity blob: the register refuses it (no rollback).
	oldActivity := held["agent-vm/state/"+stateActivity]
	w.state.Set("agent-vm/state/"+stateActivity, oldActivity)
	k3 := w.release(t, "inst-3", agentPurposes...)
	if _, err := bootState(ctx, kmsKeys{k3}, w.relayBackend(t, k3, PurposeState), k3.Register(PurposeState), "f_chat"); !errors.Is(err, sealstate.ErrRollback) {
		t.Fatalf("an older blob: %v", err)
	}
	k3.Drop(ctx)

	// Another key service (its own master key): the sealed states don't open, and agentd refuses to start over
	// people's schedules rather than starting empty.
	other := newKMSWorld(t)
	for k, b := range held {
		other.state.Set(k, b)
	}
	ko := other.release(t, "inst-4", agentPurposes...)
	if _, err := bootState(ctx, kmsKeys{ko}, other.relayBackend(t, ko, PurposeState), ko.Register(PurposeState), "f_chat"); !errors.Is(err, sealstate.ErrSealed) {
		t.Fatalf("another key service: %v", err)
	}
	// Boot keys can't keep state at all.
	if _, err := bootState(ctx, newBootKeys(), &sealstate.Mem{}, nil, "f_chat"); err == nil {
		t.Fatal("sealed state under boot keys")
	}
	_ = kmsdev.App
}

// putTestConn connects an email account for space (an IMAP app password, the canary) on v.
func putTestConn(t *testing.T, v *vault.Vault, space string) {
	t.Helper()
	box, _ := vault.SealConn(v.SealKey(), space, vault.ConnEmail, []byte(`{"type":"`+vault.EmailType+
		`","provider":"other","host":"imap.canary.example","port":993,"security":"tls","address":"me@canary.example","username":"me@canary.example","password":"`+
		testIMAPPassword+`"}`))
	pid, _, err := v.ConnPut(space, vault.ConnEmail, box)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.ConnCommit(pid); err != nil {
		t.Fatal(err)
	}
}
