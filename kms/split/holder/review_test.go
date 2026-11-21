package holder

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"maps"
	"strings"
	"testing"
	"time"

	"github.com/tacyhq/tacy/kms"
	"github.com/tacyhq/tacy/kms/split"
	"github.com/tacyhq/tacy/verifier"
)

// agedRig: two holders with the 24 h delay; the release in use aged past it.
func agedRig(t *testing.T) *rig {
	r := newRig(t, twoOfTwo, 2)
	for _, h := range r.ids {
		r.holders[h] = r.newHolder(h, func(c *Config) { c.NoPinDelay = false })
	}
	r.unlock(r.transports(nil), nil)
	r.advance(25 * time.Hour)
	if _, rep, err := r.unlock(r.transports(nil), nil); err != nil {
		t.Fatalf("the aged release: %v %v", err, rep.Outcome)
	}
	return r
}

// push sends the rig's policy to every holder, as kmsctl holder-push does with every policy the admin signs:
// that is how a holder learns of withdrawals and floor changes even when no VM unlocks under them.
func (r *rig) push(t *testing.T) {
	t.Helper()
	env := r.policyEnv()
	for _, h := range r.ids {
		if _, err := r.holders[h].PushPolicy(context.Background(), env); err != nil {
			t.Fatalf("push to %s: %v", h, err)
		}
	}
}

func (r *rig) wantOutcome(t *testing.T, want string) {
	t.Helper()
	if _, rep, err := r.unlock(r.transports(nil), nil); err == nil || !strings.Contains(rep.Outcome["vercel"], want) {
		t.Fatalf("want %q: %v %v", want, err, rep.Outcome)
	}
}

// Privacy review #3: not only release pins wait. A policy that starts listing its own OS images (here: the very
// image the VM runs) counts only 24 h after a holder first saw it, with a "change" alert.
func TestDelayCoversOSImages(t *testing.T) {
	r := agedRig(t)
	r.pol.Seq = 6
	r.pol.OSImages = maps.Clone(verifier.ProdImages)
	r.wantOutcome(t, "a change this VM needs (os:")
	r.mu.Lock()
	changes := 0
	for _, e := range r.events {
		if e.Kind == "change" && strings.HasPrefix(e.Item, split.ItemOS) {
			changes++
		}
	}
	r.mu.Unlock()
	if changes != 2 {
		t.Fatalf("each holder should alert on the new OS image item, got %d", changes)
	}
	r.advance(24*time.Hour + time.Minute)
	if _, rep, err := r.unlock(r.transports(nil), nil); err != nil {
		t.Fatalf("24 h later: %v %v", err, rep.Outcome)
	}
}

// A lowered floor keeps the old floor in force for 24 h; a raise applies at once.
func TestFloorLoweringWaits(t *testing.T) {
	r := agedRig(t)
	r.pol.Seq, r.pol.Floor = 6, "v0.19.5" // a raise: at once
	r.push(t)
	r.wantOutcome(t, "below the policy floor v0.19.5")
	r.pol.Seq, r.pol.Floor = 7, "v0.19.0" // lowered back
	r.push(t)
	r.wantOutcome(t, "which a newer policy lowered")
	r.advance(24*time.Hour + time.Minute)
	if _, rep, err := r.unlock(r.transports(nil), nil); err != nil {
		t.Fatalf("24 h after the lowering: %v %v", err, rep.Outcome)
	}
}

// A release withdrawn and then pinned again waits again.
func TestReappearanceWaitsAgain(t *testing.T) {
	r := agedRig(t)
	pins := r.pol.Releases
	r.pol.Seq, r.pol.Releases = 6, nil
	r.push(t)
	r.wantOutcome(t, "isn't a pinned release")
	r.pol.Seq, r.pol.Releases = 7, pins
	r.push(t)
	r.wantOutcome(t, "release v0.19.3 was first allowed here at")
	r.advance(24*time.Hour + time.Minute)
	if _, rep, err := r.unlock(r.transports(nil), nil); err != nil {
		t.Fatalf("24 h after its return: %v %v", err, rep.Outcome)
	}
}

// Two different documents signed with one seq: the second is refused (the admin key signed twice).
func TestEquivocationRefused(t *testing.T) {
	r := newRig(t, twoOfTwo, 2)
	if _, _, err := r.unlock(r.transports(nil), nil); err != nil {
		t.Fatal(err)
	}
	r.pol.Floor = "v0.19.1" // seq 5 still
	r.wantOutcome(t, "another policy with seq 5 was already seen here")
}

// Every item kind PolicyItems names.
func TestPolicyItems(t *testing.T) {
	r := newRig(t, twoOfTwo, 2)
	p := r.pol
	p.OSImages = map[string]string{strings.Repeat("a", 64): "x"}
	p.PreLaunch = map[string]string{strings.Repeat("b", 64): "y"}
	p.KMSRoots = map[string]string{"abcd": "z"}
	p.Platforms = []string{"dstack"}
	p.Boot = []kms.BootSet{{Name: "b", OSImage: strings.Repeat("a", 64), MRTD: strings.Repeat("1", 96), RTMR0: strings.Repeat("2", 96),
		RTMR1: strings.Repeat("3", 96), RTMR2: strings.Repeat("4", 96)}}
	items := strings.Join(split.PolicyItems(&p), " ")
	for _, want := range []string{"release:", "os:" + strings.Repeat("a", 64), "prelaunch:", "kmsroot:abcd", "flag:kms-fallback",
		"platform:dstack", "boot:", "floor:*:v0.19.0"} {
		if !strings.Contains(items, want) {
			t.Fatalf("items %q lack %q", items, want)
		}
	}
}

// Privacy review #4: the VM checks the admin signature itself and refuses an epoch below its pinned minimum, so an
// old set (or an old-epoch break-glass) can't undo a re-split.
func TestVMChecksAdminAndMinEpoch(t *testing.T) {
	r := newRig(t, twoOfTwo, 2)
	cfg := r.unlockConfig(r.transports(nil), nil)
	cfg.Admin = nil
	if _, _, err := split.Unlock(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), "admin keys") {
		t.Fatalf("no admin keys pinned: %v", err)
	}
	cfg = r.unlockConfig(r.transports(nil), nil)
	cfg.Policy = r.sign(split.KindUnlockPolicy, r.pol, r.otherKey())
	if _, _, err := split.Unlock(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), "admin signatures") {
		t.Fatalf("a policy not signed by the admin: %v", err)
	}
	cfg = r.unlockConfig(r.transports(nil), nil)
	cfg.MinEpoch = 2 // the release after a re-split to epoch 2
	if _, _, err := split.Unlock(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), "below this release's minimum 2") {
		t.Fatalf("an epoch-1 policy under minimum epoch 2: %v", err)
	}
}

// Privacy review #9: the rollback witness. The VM's signed state head goes to the witness; each unlock brings back
// the highest one (inside the reply's AAD); a stripped or swapped head breaks the reply; a forged head is refused.
func TestRollbackWitness(t *testing.T) {
	r := newRig(t, twoOfTwo, 2)
	r.pol.Witnesses = []string{"vercel"}
	witness := &MemoryWitness{}
	r.holders["vercel"] = r.newHolder("vercel", func(c *Config) { c.Witness = witness })

	// First boot: no head yet.
	m, rep, err := r.unlock(r.transports(nil), nil)
	if err != nil || m.Head != nil {
		t.Fatalf("first boot: %v %v %+v", err, rep, m)
	}
	// The VM signs heads 1 and 2 and pushes them; a lower counter afterwards is kept out.
	wk, _ := m.WitnessKey()
	var certs []split.SignedEpochCert
	certs = append(certs, r.pol.EpochCerts...)
	push := func(counter uint64, gen uint64) uint64 {
		sh, err := split.SignHead(wk, split.StateHead{KMSID: r.kmsID, App: vmApp, Epoch: 1, Counter: counter,
			Names: map[string]split.HeadEntry{"side": {Gen: gen, Hash: strings.Repeat("c", 64)}}, At: r.now})
		if err != nil {
			t.Fatal(err)
		}
		wr, err := r.holders["vercel"].PushWitness(context.Background(), split.WitnessPush{Cert: certs[0], Head: *sh})
		if err != nil {
			t.Fatal(err)
		}
		return wr.Counter
	}
	if push(1, 4) != 1 || push(2, 7) != 2 || push(1, 3) != 2 {
		t.Fatal("the witness should keep the highest counter")
	}
	m, rep, err = r.unlock(r.transports(nil), nil)
	if err != nil || m.Head == nil || m.Head.Counter != 2 || m.Head.Names["side"].Gen != 7 {
		t.Fatalf("the head back at unlock: %v %v %+v", err, rep, m)
	}

	// A forged head (not the epoch's witness key) isn't taken by the witness.
	_, other, _ := edKey()
	sh, _ := split.SignHead(other, split.StateHead{KMSID: r.kmsID, App: vmApp, Epoch: 1, Counter: 99, At: r.now})
	if _, err := r.holders["vercel"].PushWitness(context.Background(), split.WitnessPush{Cert: certs[0], Head: *sh}); err == nil {
		t.Fatal("a forged head was kept")
	}

	// Someone on the path strips the head from the reply: the reply no longer opens.
	strip := func(next interface {
		Do(context.Context, string, string, []byte) ([]byte, error)
	}) stripper {
		return stripper{next: next}
	}
	hs := r.transports(nil)
	hs[1].Transport = strip(hs[1].Transport)
	if _, rep, err := r.unlock(hs, nil); err == nil || !strings.Contains(rep.Outcome["vercel"], "witness head was changed") {
		t.Fatalf("a stripped head: %v %v", err, rep.Outcome)
	}
}

type stripper struct {
	next interface {
		Do(context.Context, string, string, []byte) ([]byte, error)
	}
}

func (s stripper) Do(ctx context.Context, method, path string, body []byte) ([]byte, error) {
	b, err := s.next.Do(ctx, method, path, body)
	if err != nil || path != "/v1/unlock" {
		return b, err
	}
	var rep split.UnlockReply
	json.Unmarshal(b, &rep)
	rep.WitnessHead = nil
	return json.Marshal(rep)
}

func edKey() (ed25519.PublicKey, ed25519.PrivateKey, error) { return ed25519.GenerateKey(rand.Reader) }
