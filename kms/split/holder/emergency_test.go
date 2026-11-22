package holder

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/tacyhq/tacy/kms"
	"github.com/tacyhq/tacy/kms/split"
)

// emergencyRig: two holders with the 24 h pin delay on; the release in use (v0.19.3) aged past it; a fix (another
// app-compose, v0.19.4) ready.
func emergencyRig(t *testing.T) (*rig, *evidence, string) {
	r := newRig(t, twoOfTwo, 2)
	for _, h := range r.ids {
		r.holders[h] = r.newHolder(h, func(c *Config) { c.NoPinDelay = false })
	}
	r.unlock(r.transports(nil), nil) // the holders first see v0.19.3 now
	r.advance(25 * time.Hour)
	if _, rep, err := r.unlock(r.transports(nil), nil); err != nil {
		t.Fatalf("the aged release: %v %v", err, rep.Outcome)
	}
	q, info, fixHash := r.variant(func(m map[string]any) {
		m["docker_compose_file"] = strings.Replace(r.vmCompose, "services:", "services:\n  # the fix", 1)
	})
	return r, &evidence{quote: q, info: info}, fixHash
}

// fixPolicy: seq 6 pins the fix and withdraws the vulnerable release, in one push.
func fixPolicy(r *rig, fixHash string) split.UnlockPolicy {
	p := r.pol
	p.Seq = 6
	p.Releases = []kms.ReleasePin{{App: vmApp, Version: "v0.19.4", AppComposeSHA256: fixHash}}
	return p
}

// the no-downtime plan row 13: with the emergency override (admin key plus the KMS id, from two passphrase shares) the fix
// unlocks at once and the vulnerable release is withdrawn in the same push: no downtime. Every holder alerts.
func TestEmergencyOverride(t *testing.T) {
	r, fix, fixHash := emergencyRig(t)
	p := fixPolicy(r, fixHash)
	em, err := split.NewEmergency(r.master, r.kmsID, p.Seq, []string{split.ReleaseItem(p.Releases[0])}, "CVE-2026-0001 in v0.19.3", r.now)
	if err != nil {
		t.Fatal(err)
	}
	p.Emergency = em
	r.pol = p
	m, rep, err := unlockFix(r, fix)
	if err != nil {
		t.Fatalf("the fix under the override: %v %v", err, rep.Outcome)
	}
	r.mustMaster(m)
	if _, rep, err := r.unlock(r.transports(nil), nil); err == nil || !strings.Contains(rep.Outcome["vercel"], "isn't a pinned release") {
		t.Fatalf("the withdrawn release: %v %v", err, rep.Outcome)
	}
	r.mu.Lock()
	alerts := map[string]bool{}
	for _, e := range r.events {
		if e.Kind == "emergency" && e.Release == "v0.19.4" && strings.Contains(e.Reason, "CVE-2026-0001") {
			alerts[e.Holder] = true
		}
	}
	r.mu.Unlock()
	if !alerts["cloudflare"] || !alerts["vercel"] {
		t.Fatalf("every holder should alert on the override: %v", alerts)
	}
	// The next policy (seq 7) carries no override; the fix stays expedited (the store keeps the earlier time).
	r.pol.Seq, r.pol.Emergency = 7, nil
	if _, rep, err := unlockFix(r, fix); err != nil {
		t.Fatalf("the fix under the next policy: %v %v", err, rep.Outcome)
	}
}

// Without the override the fix waits 24 h; an admin-key thief can't make one (it takes the KMS id), nor reuse one
// for another seq or another pin.
func TestEmergencyOverrideRefusals(t *testing.T) {
	r, fix, fixHash := emergencyRig(t)
	r.pol = fixPolicy(r, fixHash)
	if _, rep, err := unlockFix(r, fix); err == nil || !strings.Contains(rep.Outcome["cloudflare"], "was first allowed here") {
		t.Fatalf("the fix without an override: %v %v", err, rep.Outcome)
	}

	// The thief has the admin key (the policy's signature is valid) but not M: its override is signed by another
	// key. The whole policy is refused at every holder.
	_, thiefKey, _ := ed25519.GenerateKey(rand.Reader)
	doc, _ := json.Marshal(split.Emergency{KMSID: r.kmsID, PolicySeq: 6, Items: []string{split.ReleaseItem(r.pol.Releases[0])}, Reason: "forged", IssuedAt: r.now})
	r.pol.Emergency = &split.SignedEmergency{Doc: doc, Sig: ed25519.Sign(thiefKey, append([]byte("tacy-split/emergency/v1\x00"), doc...))}
	if _, rep, err := unlockFix(r, fix); err == nil || !strings.Contains(rep.Outcome["vercel"], "isn't signed by the KMS id") {
		t.Fatalf("a forged override: %v %v", err, rep.Outcome)
	}

	// A real override for another seq, or naming a pin this policy doesn't pin.
	for name, c := range map[string]struct {
		seq  uint64
		pin  string
		want string
	}{
		"another seq": {5, split.ReleaseItem(r.pol.Releases[0]), "is for policy seq 5, not 6"},
		"another pin": {6, split.ItemRelease + strings.Repeat("ab", 32), "which this policy doesn't allow"},
	} {
		em, err := split.NewEmergency(r.master, r.kmsID, c.seq, []string{c.pin}, "test", r.now)
		if err != nil {
			t.Fatal(err)
		}
		r.pol.Emergency = em
		if _, rep, err := unlockFix(r, fix); err == nil || !strings.Contains(rep.Outcome["cloudflare"], c.want) {
			t.Fatalf("%s: %v %v", name, err, rep.Outcome)
		}
	}
	// And no override can be made without M.
	other := make([]byte, kms.MasterSize)
	rand.Read(other)
	if _, err := split.NewEmergency(other, r.kmsID, 6, []string{split.ReleaseItem(r.pol.Releases[0])}, "x", r.now); err == nil {
		t.Fatal("an override from another M")
	}
}

// unlockFix is the fixed VM's unlock (it claims v0.19.4).
func unlockFix(r *rig, fix *evidence) (*split.Root, *split.Report, error) {
	cfg := r.unlockConfig(r.transports(nil), fix)
	cfg.Release = "v0.19.4"
	return split.Unlock(context.Background(), cfg)
}
