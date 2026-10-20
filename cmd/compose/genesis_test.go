package main

import (
	"encoding/json/v2"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/tacyhq/tacy/guard"
	"github.com/tacyhq/tacy/keylog"
	"github.com/tacyhq/tacy/safety"
)

// Keys v2 slice 5: the release pins f_chat's real genesis. testdata/fchat-genesis.json is the entry f_chat's owner
// signed offline on 2026-10-18, byte for byte as it is uploaded in Admin → Safety (the chat's
// test/golden/fchat-genesis.json is the same file, replayed by the browser's verifier), and
// testdata/chat-policy-v1.signed.json is the live policy as /api/safety/docs serves it (signed by the old compose
// admin key). Both are public.
func TestPinnedGenesis(t *testing.T) {
	var g keylog.Entry
	b, err := os.ReadFile("testdata/fchat-genesis.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &g, json.RejectUnknownMembers(true)); err != nil {
		t.Fatal(err)
	}
	st, err := keylog.Replay(safetyFirm, []keylog.Entry{g})
	if err != nil {
		t.Fatalf("the pinned genesis doesn't verify as %s's: %v", safetyFirm, err)
	}
	if keylogGenesis == "" || st.Genesis != keylogGenesis || st.Head != keylogGenesis || st.Seq != 1 {
		t.Fatalf("keylogGenesis %s, the entry's %s (head %s, seq %d)", keylogGenesis, st.Genesis, st.Head, st.Seq)
	}
	// The kit is the offline admin key the compose pinned before (so the carried policy it signed stays in force),
	// and the owner's identity is the one key admin.
	if st.Kit != adminKeys {
		t.Errorf("kit %s, want the old compose admin key %s", st.Kit, adminKeys)
	}
	if a := st.Admins(); !slices.Equal(a, []string{"i_nrqykwaqqhlrcbdruyhwgqty2i"}) || st.Effective() != 1 {
		t.Errorf("key admins %v, threshold %d", a, st.Effective())
	}
	if _, err := keylog.Replay("f_"+"aaaaaaaaaaaaaaaaaaaaaaaaaa", []keylog.Entry{g}); err == nil {
		t.Error("f_chat's genesis verified as another firm's")
	}

	// A VM with this release's trust roots takes the genesis, then the live chat-policy-v1 (carried: signed by the
	// kit only), and nothing else the kit signs.
	var pol safety.Envelope
	pb, err := os.ReadFile("testdata/chat-policy-v1.signed.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(pb, &pol, json.RejectUnknownMembers(true)); err != nil {
		t.Fatal(err)
	}
	if pol.Hash() != keylogCarry || pol.Hash() != safety.ChatPolicyV1 {
		t.Fatalf("the signed policy hashes to %s", pol.Hash())
	}
	now := time.Date(2026, 10, 19, 0, 0, 0, 0, time.UTC)
	s, err := safety.NewState(safety.Config{Firm: safetyFirm, Genesis: keylogGenesis, Carry: []string{keylogCarry},
		Release: guard.ReleasePolicy(safetyFirm, ""), Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	ge := safety.Envelope{Kind: g.Kind, Payload: g.Payload}
	for _, sg := range g.Sigs {
		ge.Sigs = append(ge.Sigs, safety.Sig{Key: sg.Key, Sig: sg.Sig})
	}
	errs, _ := s.Apply([]safety.Envelope{ge, pol})
	for i, err := range errs {
		if err != nil {
			t.Fatalf("document %d: %v", i, err)
		}
	}
	e, err := s.Policy("s_" + "aaaaaaaaaaaaaaaaaaaaaaaaaa")
	if err != nil || !slices.Equal(e.Hashes, []string{safety.ChatPolicyV1}) {
		t.Fatalf("policy in force: %v %v", e, err)
	}
	if k := s.KeysStatus(); k == nil || k.Genesis != keylogGenesis || k.Seq != 1 || k.Head != keylogGenesis || k.Fork {
		t.Fatalf("keys: %+v", k)
	}
}
