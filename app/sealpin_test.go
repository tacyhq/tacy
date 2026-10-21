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

// What the chat does when a data key rotation gives the space a new seal key (its schedule-center.ts moveSeal; the
// body's bytes are checked against the chat's in TestResealGoldenVectors), against the handlers: the pin moves, each
// schedule is installed again under the new key as its next version (a paused one stopped again) and lists there as it
// was, and the old key is refused for every call. An interrupted move goes on: the same reseal again is seal_mismatch
// while the new key is pinned, and a move back reaches what is still under the old key.
func TestRotationMovesSchedules(t *testing.T) {
	e := newSchedEnv(t)
	later := func(d *trigger.Definition) { d.Triggers[0].Daily = time.Now().UTC().Add(3 * time.Hour).Format("15:04") }
	active, paused, left := e.daily(e.me, later), e.daily(e.me, later), e.daily(e.me, later)
	for _, d := range []trigger.Definition{active, paused, left} {
		if code, out := e.install(e.me, e.sign(d, e.me.Key)); code != 200 {
			t.Fatalf("install: %d %v", code, out)
		}
	}
	if code, out := e.call(e.s.scheduleStop, agentRequest{Where: e.where(e.me, runauth.StopLabel, paused.Agent), Agent: paused.Agent}); code != 200 {
		t.Fatalf("pause: %d %v", code, out)
	}
	next, _ := ecdh.X25519().GenerateKey(rand.Reader)
	moved := &runauth.Asker{Space: e.me.Space, Seal: next, Identity: e.me.Identity, Key: e.me.Key}
	reseal := func(from *runauth.Asker, to *ecdh.PrivateKey) (int, map[string]any) {
		t.Helper()
		w, oldSeal, oldProof, err := from.Reseal(to, e.vm())
		if err != nil {
			t.Fatal(err)
		}
		return e.call(e.s.spaceReseal, resealRequest{Where: w, OldSeal: oldSeal, OldProof: oldProof})
	}
	listed := func(a *runauth.Asker) (int, map[string]map[string]any) {
		t.Helper()
		code, out := e.call(e.s.scheduleList, e.where(a, runauth.ListLabel))
		got := map[string]map[string]any{}
		if s, ok := out["schedules"].([]any); ok {
			for _, x := range s {
				m := x.(map[string]any)
				got[m["agent"].(string)] = m
			}
		}
		return code, got
	}
	reinstall := func(d trigger.Definition) {
		t.Helper()
		d.Version, d.Seal, d.IssuedAt = d.Version+1, moved.SealString(), time.Now().UTC().Add(-time.Second)
		if code, out := e.install(moved, e.sign(d, moved.Key)); code != 200 || out["version"] != float64(d.Version) {
			t.Fatalf("install again under the new key: %d %v", code, out)
		}
	}

	// Before the pin moves, the new key can't install (the chat's reinstall comes after the reseal).
	early := active
	early.Version, early.Seal = 2, moved.SealString()
	if code, out := e.install(moved, e.sign(early, moved.Key)); code != 403 || errOf(out) != "seal_mismatch" {
		t.Fatalf("install under the new key before the reseal: %d %v", code, out)
	}
	if code, out := reseal(e.me, next); code != 200 {
		t.Fatalf("reseal: %d %v", code, out)
	}
	reinstall(active)
	// Interrupted here: the pin is the new key and `paused` and `left` are still under the old one, which can't list.
	if code, _ := listed(e.me); code != 403 {
		t.Fatalf("the old key lists after the reseal: %d", code)
	}
	// The same move again: seal_mismatch, and the new key answers (so the chat knows the pin is already the new key).
	if code, out := reseal(e.me, next); code != 403 || errOf(out) != "seal_mismatch" {
		t.Fatalf("the reseal again: %d %v", code, out)
	}
	// The move goes on: back to the old key, which lists what is left under it, then forward again.
	if code, out := reseal(moved, e.me.Seal); code != 200 {
		t.Fatalf("the move back: %d %v", code, out)
	}
	if code, l := listed(e.me); code != 200 || len(l) != 2 || l[paused.Agent]["state"] != "stopped" || l[left.Agent]["state"] != "active" {
		t.Fatalf("what the old key still holds: %d %v", code, l)
	}
	if code, out := reseal(e.me, next); code != 200 {
		t.Fatalf("reseal after the move back: %d %v", code, out)
	}
	reinstall(paused)
	if code, out := e.call(e.s.scheduleStop, agentRequest{Where: e.where(moved, runauth.StopLabel, paused.Agent), Agent: paused.Agent}); code != 200 || out["state"] != "stopped" {
		t.Fatalf("paused again: %d %v", code, out)
	}
	reinstall(left)

	code, l := listed(moved)
	if code != 200 || len(l) != 3 {
		t.Fatalf("under the new key: %d %v", code, l)
	}
	for agent, want := range map[string]string{active.Agent: "active", paused.Agent: "stopped", left.Agent: "active"} {
		if l[agent]["state"] != want || l[agent]["version"] != float64(2) {
			t.Fatalf("%s under the new key: %v", agent, l[agent])
		}
		// Its next run as before (the trigger is the same; nothing ran today).
		if tr := l[agent]["triggers"].([]any)[0].(map[string]any); want == "active" && tr["next_run"] == nil {
			t.Fatalf("%s has no next run: %v", agent, tr)
		}
	}
	// The old key, afterwards: refused for every call.
	refused := func(what string, code int, out map[string]any) {
		t.Helper()
		if code != 403 || errOf(out) != "seal_mismatch" {
			t.Fatalf("%s with the old key after the move: %d %v", what, code, out)
		}
	}
	code, out := e.call(e.s.scheduleList, e.where(e.me, runauth.ListLabel))
	refused("list", code, out)
	code, out = e.call(e.s.scheduleStop, agentRequest{Where: e.where(e.me, runauth.StopLabel, active.Agent), Agent: active.Agent})
	refused("stop", code, out)
	code, out = e.call(e.s.scheduleResults, resultsRequest{Where: e.where(e.me, runauth.ResultsLabel, "0")})
	refused("results", code, out)
	over := active
	over.Version = 3
	code, out = e.install(e.me, e.sign(over, e.me.Key))
	refused("install", code, out)
	rg := e.s.agent.(*recGateway)
	run := proto.RunRequest{Model: proto.DefaultModel, Permissions: guard.AllowAll(), Messages: user1("hi")}
	if err := e.me.Authorize(&run, e.vm()); err != nil {
		t.Fatal(err)
	}
	var se *safety.Error
	if err := rg.Verify(&run, tasksUser); !errors.As(err, &se) || se.Code != safety.CodePolicyDenied {
		t.Fatalf("a run with the old key after the move: %v", err)
	}
}
