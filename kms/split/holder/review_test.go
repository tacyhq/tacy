package holder

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"maps"
	"net/http/httptest"
	"reflect"
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

// The legacy rollback witness is removed before the genesis ceremony (V1-DESIGN §2.5 step 1): no witness store in a
// holder's config, no POST /v1/witness, no state head in the unlock reply. A policy that still names witnesses
// unlocks with no head, and a reply that carries one anyway is refused by the VM's strict decoder.
func TestLegacyWitnessRemoved(t *testing.T) {
	if _, ok := reflect.TypeOf(Config{}).FieldByName("Witness"); ok {
		t.Fatal("holder.Config still has a witness store")
	}
	if _, ok := reflect.TypeOf(split.UnlockReply{}).FieldByName("WitnessHead"); ok {
		t.Fatal("the unlock reply still carries a witness head")
	}
	if _, ok := reflect.TypeOf(&Holder{}).MethodByName("PushWitness"); ok {
		t.Fatal("the holder still takes witness pushes")
	}
	r := newRig(t, twoOfTwo, 2)
	r.pol.Witnesses = []string{"vercel"}
	r.holders["vercel"] = r.newHolder("vercel", nil)
	w := httptest.NewRecorder()
	r.holders["vercel"].Handler().ServeHTTP(w, httptest.NewRequest("POST", "/v1/witness", strings.NewReader(`{"cert":{},"head":{}}`)))
	if w.Code != 404 || strings.Contains(w.Body.String(), "witness") {
		t.Fatalf("POST /v1/witness: %d %s", w.Code, w.Body)
	}
	if _, rep, err := r.unlock(r.transports(nil), nil); err != nil {
		t.Fatalf("an unlock under a policy naming witnesses: %v %v", err, rep)
	}
	hs := r.transports(nil)
	hs[1].Transport = addHead{next: hs[1].Transport}
	if _, rep, err := r.unlock(hs, nil); err == nil || !strings.Contains(rep.Outcome["vercel"], "witness_head") {
		t.Fatalf("a reply with a witness head: %v %v", err, rep.Outcome)
	}
}

// addHead adds a witness head to every unlock reply, as a holder with the legacy path would.
type addHead struct {
	next interface {
		Do(context.Context, string, string, []byte) ([]byte, error)
	}
}

func (a addHead) Do(ctx context.Context, method, path string, body []byte) ([]byte, error) {
	b, err := a.next.Do(ctx, method, path, body)
	if err != nil || path != "/v1/unlock" {
		return b, err
	}
	var rep map[string]any
	json.Unmarshal(b, &rep)
	rep["witness_head"] = "e30="
	return json.Marshal(rep)
}

func edKey() (ed25519.PublicKey, ed25519.PrivateKey, error) { return ed25519.GenerateKey(rand.Reader) }
