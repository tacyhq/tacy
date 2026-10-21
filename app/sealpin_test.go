package main

import (
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/tacyhq/tacy/guard"
	"github.com/tacyhq/tacy/proto"
	"github.com/tacyhq/tacy/runauth"
	"github.com/tacyhq/tacy/safety"
	"github.com/tacyhq/tacy/trigger"
)

// A personal space is pinned to the first seal key proven for it (v0.16.0, the security review's item 2): someone
// who knows the space's id, with a seal key and identity of their own, can't run in it (its budget), install into it
// (its 8 schedule slots), overwrite, stop or remove its schedules, or list them. The holder rotates the key with a
// reseal call proving both keys; nobody else can move the pin, and the old key is refused after it.
func TestPersonalSpaceSealPinned(t *testing.T) {
	e := newSchedEnv(t)
	later := func(d *trigger.Definition) { d.Triggers[0].Daily = time.Now().UTC().Add(3 * time.Hour).Format("15:04") }
	d := e.daily(e.me, later)
	if code, out := e.install(e.me, e.sign(d, e.me.Key)); code != 200 {
		t.Fatalf("the holder's install: %d %v", code, out)
	}
	other, _ := runauth.NewAsker()
	spoof := &runauth.Asker{Space: e.me.Space, Seal: other.Seal, Identity: other.Identity, Key: other.Key}
	refused := func(what string, code int, out map[string]any) {
		t.Helper()
		if code != 403 || errOf(out) != "seal_mismatch" {
			t.Fatalf("%s with another seal key: %d %v", what, code, out)
		}
	}
	// A schedule of their own in the space (its slots).
	code, out := e.install(spoof, e.sign(e.daily(spoof, later), spoof.Key))
	refused("install", code, out)
	// A newer version of the holder's schedule (overwriting it), signed by them.
	over := d
	over.Version, over.Seal, over.Author, over.Sponsor = 2, spoof.SealString(), spoof.Identity, spoof.Identity
	code, out = e.install(spoof, e.sign(over, spoof.Key))
	refused("overwrite", code, out)
	code, out = e.call(e.s.scheduleStop, agentRequest{Where: e.where(spoof, runauth.StopLabel, d.Agent), Agent: d.Agent})
	refused("stop", code, out)
	code, out = e.call(e.s.scheduleRemove, agentRequest{Where: e.where(spoof, runauth.RemoveLabel, d.Agent), Agent: d.Agent})
	refused("remove", code, out)
	code, out = e.call(e.s.scheduleList, e.where(spoof, runauth.ListLabel))
	refused("list", code, out)
	// A run (the space's budget): refused at the door, before its nonce or any budget.
	rg := e.s.agent.(*recGateway)
	run := proto.RunRequest{Model: proto.DefaultModel, Permissions: guard.AllowAll(), Messages: user1("hi")}
	if err := spoof.Authorize(&run, e.vm()); err != nil {
		t.Fatal(err)
	}
	var se *safety.Error
	if err := rg.Verify(&run, tasksUser); !errors.As(err, &se) || se.Code != safety.CodePolicyDenied {
		t.Fatalf("a run with another seal key: %v", err)
	}
	// The holder's schedule is untouched.
	_, lo := e.call(e.s.scheduleList, e.where(e.me, runauth.ListLabel))
	if s := lo["schedules"].([]any); len(s) != 1 || s[0].(map[string]any)["state"] != "active" || s[0].(map[string]any)["version"] != float64(1) {
		t.Fatalf("the holder's schedules: %v", lo)
	}

	// Rotation: the holder proves both keys and the pin moves.
	next, _ := ecdh.X25519().GenerateKey(rand.Reader)
	reseal := func(a *runauth.Asker, to *ecdh.PrivateKey) resealRequest {
		t.Helper()
		w, oldSeal, oldProof, err := a.Reseal(to, e.vm())
		if err != nil {
			t.Fatal(err)
		}
		return resealRequest{Where: w, OldSeal: oldSeal, OldProof: oldProof}
	}
	// Not by someone else: they hold their own old key, not the pinned one.
	third, _ := ecdh.X25519().GenerateKey(rand.Reader)
	code, out = e.call(e.s.spaceReseal, reseal(spoof, third))
	refused("a reseal from another key", code, out)
	// Not with an old proof that isn't the old key's.
	bad := reseal(e.me, next)
	bad.OldProof = append([]byte(nil), bad.OldProof...)
	bad.OldProof[0] ^= 1
	if code, out := e.call(e.s.spaceReseal, bad); code != 403 || errOf(out) != "bad_proof" {
		t.Fatalf("a reseal with a forged old proof: %d %v", code, out)
	}
	good := reseal(e.me, next)
	if code, out := e.call(e.s.spaceReseal, good); code != 200 || out["seal"] != runauth.SealString(next.PublicKey()) {
		t.Fatalf("the holder's reseal: %d %v", code, out)
	}
	if code, out := e.call(e.s.spaceReseal, good); code != 409 {
		t.Fatalf("the same reseal again: %d %v", code, out)
	}
	moved := &runauth.Asker{Space: e.me.Space, Seal: next, Identity: e.me.Identity, Key: e.me.Key}
	if code, out := e.call(e.s.scheduleList, e.where(moved, runauth.ListLabel)); code != 200 {
		t.Fatalf("the new key after the reseal: %d %v", code, out)
	}
	code, out = e.call(e.s.scheduleList, e.where(e.me, runauth.ListLabel))
	refused("the old key after the reseal", code, out)
	// A stale reseal (from the old key again, a fresh call) can't move it back.
	code, out = e.call(e.s.spaceReseal, reseal(e.me, third))
	refused("a stale reseal", code, out)
}
