package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json/v2"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/tacyhq/tacy/guard"
	"github.com/tacyhq/tacy/keylog"
	"github.com/tacyhq/tacy/safety"
)

// Keys v2 slice 5: the release pins f_chat's real genesis. testdata/fchat-genesis.json is the entry f_chat's owner
// signed offline on 2026-10-18, byte for byte as it is uploaded in Admin → Safety (the chat's
// test/golden/fchat-genesis.json is the same file, replayed by the browser's verifier), and
// testdata/chat-policy-v1.signed.json and chat-policy-v2.signed.json are the policies the old compose admin key
// signed (v2, as /api/safety/docs serves it, is the one in force). All public.
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

	// A VM with this release's trust roots takes the genesis, then the live chat policies the old admin key signed
	// (carried: signed by the kit only), and nothing else the kit signs.
	readPol := func(name string) safety.Envelope {
		var pol safety.Envelope
		pb, err := os.ReadFile("testdata/" + name)
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(pb, &pol, json.RejectUnknownMembers(true)); err != nil {
			t.Fatal(err)
		}
		return pol
	}
	v1, v2 := readPol("chat-policy-v1.signed.json"), readPol("chat-policy-v2.signed.json")
	if v1.Hash() != safety.ChatPolicyV1 || v2.Hash() != safety.ChatPolicyV2 {
		t.Fatalf("the signed policies hash to %s and %s", v1.Hash(), v2.Hash())
	}
	carry := strings.Split(keylogCarry, ",")
	if !slices.Equal(carry, []string{safety.ChatPolicyV1, safety.ChatPolicyV2}) {
		t.Fatalf("carried %v", carry)
	}
	ge := safety.Envelope{Kind: g.Kind, Payload: g.Payload}
	for _, sg := range g.Sigs {
		ge.Sigs = append(ge.Sigs, safety.Sig{Key: sg.Key, Sig: sg.Sig})
	}
	now := time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC)
	space := "s_" + "aaaaaaaaaaaaaaaaaaaaaaaaaa"
	newState := func(dir string, cfg safety.Config) *safety.State {
		cfg.Firm, cfg.Release, cfg.Dir, cfg.Now = safetyFirm, guard.ReleasePolicy(safetyFirm, ""), dir, func() time.Time { return now }
		s, err := safety.NewState(cfg)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	inForce := func(s *safety.State) []string {
		e, err := s.Policy(space)
		if err != nil {
			return []string{err.Error()}
		}
		return e.Hashes
	}
	apply := func(s *safety.State, envs ...safety.Envelope) {
		errs, _ := s.Apply(envs)
		for i, err := range errs {
			if err != nil {
				t.Fatalf("document %d: %v", i, err)
			}
		}
	}

	// A fresh VM: genesis, then the documents as /api/safety/docs serves them.
	s := newState("", safety.Config{Genesis: keylogGenesis, Carry: carry})
	apply(s, ge, v2)
	if h := inForce(s); !slices.Equal(h, []string{safety.ChatPolicyV2}) {
		t.Fatalf("policy in force: %v", h)
	}
	if k := s.KeysStatus(); k == nil || k.Genesis != keylogGenesis || k.Seq != 1 || k.Head != keylogGenesis || k.Fork {
		t.Fatalf("keys: %+v", k)
	}

	// The live VM's disk: v0.8.x (-admin-keys) took v1 and then v2, so v2's version floor is held. After the
	// upgrade, v2 is in force again once the genesis arrives; with v1 carried alone it wouldn't be (v2 isn't carried,
	// v1 is below the floor), so every run would be refused policy_missing.
	dir := t.TempDir()
	legacy := newState(dir, safety.Config{Admins: []ed25519.PublicKey{kitKey(t, adminKeys)}})
	apply(legacy, v1, v2)
	up := newState(dir, safety.Config{Genesis: keylogGenesis, Carry: carry})
	apply(up, ge)
	apply(up, v2)
	if h := inForce(up); !slices.Equal(h, []string{safety.ChatPolicyV2}) {
		t.Fatalf("policy in force after the upgrade: %v", h)
	}
	dir1 := t.TempDir()
	old := newState(dir1, safety.Config{Admins: []ed25519.PublicKey{kitKey(t, adminKeys)}})
	apply(old, v1, v2)
	v1only := newState(dir1, safety.Config{Genesis: keylogGenesis, Carry: []string{safety.ChatPolicyV1}})
	apply(v1only, ge)
	if errs, _ := v1only.Apply([]safety.Envelope{v2, v1}); errs[0] == nil || errs[1] == nil {
		t.Fatalf("with v1 carried alone the upgraded VM took a policy: %v", errs)
	}
}

// kitKey parses an "ed25519:<base64>" public key.
func kitKey(t *testing.T, s string) ed25519.PublicKey {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(s, "ed25519:"))
	if err != nil || len(b) != ed25519.PublicKeySize {
		t.Fatalf("key %s", s)
	}
	return ed25519.PublicKey(b)
}
