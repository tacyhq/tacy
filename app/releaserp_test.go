package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	jsonv2 "encoding/json/v2"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/tacyhq/tacy/approval"
	"github.com/tacyhq/tacy/approval/approvaltest"
	"github.com/tacyhq/tacy/harness"
	"github.com/tacyhq/tacy/identity"
	"github.com/tacyhq/tacy/trigger"
)

// The release's relying party is tacy.io with exactly two origins: the web chat's page and what the desktop app's
// operating-system passkey API writes. Adding one is a release decision, so this test names them.
func TestReleaseRPPinned(t *testing.T) {
	if ReleaseRP.ID != "tacy.io" || !slices.Equal(ReleaseRP.Origins, []string{"https://chat.tacy.io", "https://tacy.io"}) {
		t.Fatalf("ReleaseRP %+v", ReleaseRP)
	}
}

func rpRecord(firm, space string, approvers ...string) approval.Record {
	eff, _ := approval.Canonical([]byte(`{"action":"sink.post","to":"client@example.com","body":"hello"}`))
	return approval.Record{ID: approval.ID([]byte("agentd id key"), "tk_rp", "s2.a0"), Firm: firm, Space: space, Task: "tk_rp",
		Request: "s2.a0", Action: "sink.post", Effect: eff, EffectHash: approval.EffectHash(eff), Approvers: approvers,
		ExpiresAt: time.Now().Add(time.Hour).UTC().Truncate(time.Second)}
}

func payloadBytes(t *testing.T, p approval.Payload) []byte {
	t.Helper()
	p.Type = approval.PayloadType
	b, err := jsonv2.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// The desktop app's approvals (origin https://tacy.io, as macOS writes it for an app) verify on the release's
// relying party, and the web chat's still do. Every other origin is refused, compared exactly: scheme, host, port,
// path, case and whitespace. So are an rpId other than tacy.io, a framed or cross-origin page, no user verification,
// and an app-origin assertion over anything but the held approval's own payload.
func TestReleaseRPOrigins(t *testing.T) {
	var dir identity.Static
	const firm, space = "f_chat", "s_rp"
	alice := approvaltest.NewPerson(t, &dir, firm, space)
	cfg := approval.Config{Dir: &dir, RP: ReleaseRP}
	r := rpRecord(firm, space, alice.ID)
	approve := approvaltest.PayloadFor(r, alice.ID, approval.Approve)
	deny := approvaltest.PayloadFor(r, alice.ID, approval.Deny)

	for name, o := range map[string]approvaltest.Options{
		"web chat":                       {Origin: "https://chat.tacy.io"},
		"desktop app":                    {Origin: "https://tacy.io"},
		"desktop app, macOS client data": {Origin: "https://tacy.io", NativeClientData: true},
	} {
		for _, pl := range []approval.Payload{approve, deny} {
			if p, err := approval.Check(alice.Sign(t, pl, o), r.Expect(), cfg); err != nil || p.Decision != pl.Decision {
				t.Errorf("%s, %s: refused: %v", name, pl.Decision, err)
			}
		}
	}

	for _, origin := range []string{
		"http://tacy.io", "https://tacy.io/", "https://tacy.io:443", "https://tacy.io:8443", "https://tacy.io/app",
		"https://tacy.io.", "https://www.tacy.io", "https://evil.tacy.io", "https://tacy.io.evil.example", "https://evil-tacy.io",
		"https://TACY.IO", "https://Tacy.io", " https://tacy.io", "https://tacy.io ", "https://tacy.io\x00", "https://tacy.io?x=1",
		"https://chat.tacy.io/", "http://chat.tacy.io", "https://chat.tacy.io:443", "https://chat.tacy.io.evil.example",
		"tauri://localhost", "http://tauri.localhost", "io.tacy.app:", "https://evil.example", "null", "tacy.io",
	} {
		for _, native := range []bool{false, true} {
			if _, err := approval.Check(alice.Sign(t, approve, approvaltest.Options{Origin: origin, NativeClientData: native}), r.Expect(), cfg); err == nil {
				t.Errorf("origin %q (native client data %v): accepted", origin, native)
			}
		}
	}

	app := "https://tacy.io"
	for name, o := range map[string]approvaltest.Options{
		"rpId chat.tacy.io":    {Origin: app, RPID: "chat.tacy.io"},
		"rpId evil.example":    {Origin: app, RPID: "evil.example"},
		"rpId www.tacy.io":     {Origin: app, RPID: "www.tacy.io"},
		"cross-origin":         {Origin: app, CrossOrigin: true},
		"framed by a site":     {Origin: app, TopOrigin: "https://evil.example"},
		"framed by itself":     {Origin: app, TopOrigin: app},
		"no user verification": {Origin: app, NoUV: true},
		"registration":         {Origin: app, Type: "webauthn.create"},
	} {
		if _, err := approval.Check(alice.Sign(t, approve, o), r.Expect(), cfg); err == nil {
			t.Errorf("app origin, %s: accepted", name)
		}
	}

	// What a page could get signed without the held approval: its own challenge, a guessed approval id, the right
	// ids with another expiry or effect. None is the held payload, so none verifies.
	guessed := approve
	guessed.Approval = approval.ID([]byte("another key"), r.Task, r.Request)
	later := approve
	later.ExpiresAt = approve.ExpiresAt.Add(time.Second)
	otherEffect := approve
	h := sha256.Sum256([]byte("another effect"))
	otherEffect.EffectHash = hex.EncodeToString(h[:])
	for name, pl := range map[string]approval.Payload{"guessed id": guessed, "another expiry": later, "another effect": otherEffect} {
		if _, err := approval.Check(alice.Sign(t, pl, approvaltest.Options{Origin: app, NativeClientData: true}), r.Expect(), cfg); err == nil {
			t.Errorf("app origin, %s: accepted", name)
		}
	}
	page := alice.SignBytes(t, []byte(`{"type":"tacy.approval/v1"}`), approvaltest.Options{Origin: app, NativeClientData: true})
	page.Payload = payloadBytes(t, approve) // the page's signature handed in with the real payload
	if _, err := approval.Check(page, r.Expect(), cfg); err == nil {
		t.Error("app origin, a page's own challenge: accepted")
	}

	// This release's agentd and gatewayd keep no identity directory: there, nothing verifies, the app's origin
	// included.
	if _, err := approval.Check(alice.Sign(t, approve, approvaltest.Options{Origin: app}), r.Expect(), approval.Config{RP: ReleaseRP}); err == nil {
		t.Error("no directory: the app's approval accepted")
	}
}

// End to end through agentd and gatewayd, both checking with ReleaseRP: a scheduled send held for approval is
// refused with a near-miss origin, approved once from the desktop app's origin, sent once, and the same approval
// again is refused.
func TestDesktopAppApprovalThroughAgentd(t *testing.T) {
	args := `{"to":"client@example.com","body":"Daily summary: all good."}`
	se := newTriggerEnvRP(t, ReleaseRP, pCalls([3]string{"c1", "sink_post", args}), pText("Sent the summary."))
	env, _ := trigger.SignDefinition(se.definition(nil), se.sponsor.Identity)
	if code, body := se.install(env); code != 200 {
		t.Fatalf("install: %d %s", code, body)
	}
	se.s.triggerTick(context.Background())
	a := <-se.asks
	rec := approval.Record{ID: a.ID, Firm: a.Firm, Space: a.Space, Task: a.Task, Request: a.Request, Action: a.Action,
		EffectHash: a.EffectHash, ExpiresAt: a.ExpiresAt}
	pl := approvaltest.PayloadFor(rec, se.sponsor.ID, approval.Approve)
	for _, origin := range []string{"https://www.tacy.io", "https://tacy.io/", "http://tacy.io", "tauri://localhost"} {
		if code, body := se.answer(se.sponsor.Sign(t, pl, approvaltest.Options{Origin: origin, NativeClientData: true})); code != 403 {
			t.Fatalf("origin %s: %d %s", origin, code, body)
		}
	}
	if se.sink.Count("sink.post") != 0 {
		t.Fatal("sent before approval")
	}
	if code, body := se.answer(se.sponsor.Sign(t, pl, approvaltest.Options{Origin: "https://tacy.io", NativeClientData: true})); code != 200 || !strings.Contains(body, "approved") {
		t.Fatalf("approve from the app: %d %s", code, body)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if o, err := se.s.rt.Wait(ctx, a.Task); err != nil || o.State != harness.OutcomeSucceeded {
		t.Fatalf("outcome %+v %v", o, err)
	}
	if se.sink.Count("sink.post") != 1 || se.sink.Posts[0].Marker != a.ID {
		t.Fatalf("posts %+v", se.sink.Posts)
	}
	if code, _ := se.answer(se.sponsor.Sign(t, pl, approvaltest.Options{Origin: "https://tacy.io", NativeClientData: true})); code != 404 {
		t.Fatalf("replayed approval: %d", code)
	}
}
