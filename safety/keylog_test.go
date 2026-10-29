package safety

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json/v2"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/tacyhq/tacy/keylog"
)

// The firm key log: admin signers from the firm key log. The log is the browser's golden one
// (../keysv2/testdata/v2-keylog.json): 1 genesis (owner + kit), 2 owner adds bea (admin), 3 bea adds cal,
// 4 threshold 2, 5 bea revokes herself, 6 the kit names owner and cal admins, 7 owner and cal rotate the root.
type klFixture struct {
	firm, genesis         string
	entries               []Envelope
	owner, bea, cal       ed25519.PrivateKey
	kit                   ed25519.PrivateKey
	operator              ed25519.PrivateKey
	dir                   string
	now                   time.Time
	carry                 []string
	ownerID, beaID, calID string
}

func newKL(t *testing.T) *klFixture {
	t.Helper()
	b, err := os.ReadFile("../keysv2/testdata/v2-keylog.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Firm       string `json:"firm"`
		Identities map[string]struct {
			ID   string `json:"id"`
			Seed string `json:"ed25519SeedHex"`
		} `json:"identities"`
		Kit struct {
			Seed string `json:"ed25519SeedHex"`
		} `json:"kit"`
		Keylog []struct {
			Envelope string `json:"envelope"`
		} `json:"keylog"`
		State struct {
			Genesis string `json:"genesis"`
		} `json:"state"`
	}
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	seed := func(h string) ed25519.PrivateKey {
		s, _ := hex.DecodeString(h)
		return ed25519.NewKeyFromSeed(s)
	}
	f := &klFixture{firm: v.Firm, genesis: v.State.Genesis, owner: seed(v.Identities["owner"].Seed), bea: seed(v.Identities["bea"].Seed),
		cal: seed(v.Identities["cal"].Seed), kit: seed(v.Kit.Seed), operator: key(t), dir: t.TempDir(), now: t0,
		ownerID: v.Identities["owner"].ID, beaID: v.Identities["bea"].ID, calID: v.Identities["cal"].ID}
	for _, lv := range v.Keylog {
		var e Envelope
		if err := json.Unmarshal([]byte(lv.Envelope), &e, json.RejectUnknownMembers(true)); err != nil {
			t.Fatal(err)
		}
		f.entries = append(f.entries, e)
	}
	return f
}

// hash is entry i's key log hash (0-based).
func (f *klFixture) hash(i int) string { e := entryOf(f.entries[i]); return e.Hash() }

func (f *klFixture) cfg(dir string) Config {
	r := release()
	r.Firm = f.firm
	return Config{Firm: f.firm, Operator: pub(f.operator), Genesis: f.genesis, Carry: f.carry, Release: r, Dir: dir,
		Now: func() time.Time { return f.now }}
}

func (f *klFixture) state(t *testing.T) *State {
	t.Helper()
	s, err := NewState(f.cfg(f.dir))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func (f *klFixture) policy(v uint64) *Policy {
	p := policy(v, "")
	p.Firm = f.firm
	return p
}

func (f *klFixture) heartbeat(t *testing.T) Envelope {
	e, err := Heartbeat(f.operator, 0, f.now, 15*time.Minute, false)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func applyAll(t *testing.T, s *State, envs ...Envelope) []error {
	t.Helper()
	errs, _ := s.Apply(envs)
	return errs
}

func noErr(t *testing.T, errs []error) {
	t.Helper()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("envelope %d: %v", i, err)
		}
	}
}

func policyHashes(t *testing.T, s *State) []string {
	t.Helper()
	e, err := s.Policy("s_x")
	if err != nil {
		t.Fatalf("policy: %v", err)
	}
	return e.Hashes
}

func TestKeylogAdminSigners(t *testing.T) {
	f := newKL(t)
	s := f.state(t)
	if !s.KeyLogged() || !s.Keyed() {
		t.Fatal("a genesis pin serves POST /keylog and /safety")
	}
	// Before the log arrives nothing admin-signed verifies, and nothing runs.
	if err := apply(t, s, signP(t, f.policy(1), f.owner)); err == nil || !strings.Contains(err.Error(), "hasn't received") {
		t.Errorf("policy before the log: %v", err)
	}
	if _, err := s.Check("s_x", false); CodeOf(err) != CodePolicyMissing {
		t.Errorf("before a policy: %v", err)
	}
	if k := s.KeysStatus(); k.Seq != 0 || k.Head != "" || k.Genesis != f.genesis || k.Firm != f.firm {
		t.Errorf("keys before the log: %+v", k)
	}
	// Entries out of order (a gap) are refused; in order they are taken.
	if errs := applyAll(t, s, f.entries[1]); errs[0] == nil {
		t.Error("entry 2 before the genesis")
	}
	noErr(t, applyAll(t, s, f.entries[:2]...))
	// owner is a key admin; the kit, a non-member, the operator and cal (not in the log yet) aren't.
	for name, k := range map[string]ed25519.PrivateKey{"kit": f.kit, "stranger": key(t), "operator": f.operator, "cal": f.cal} {
		if err := apply(t, s, signP(t, f.policy(1), k)); err == nil || !strings.Contains(err.Error(), "current key admins") {
			t.Errorf("policy signed by %s: %v", name, err)
		}
	}
	p1 := signP(t, f.policy(1), f.owner)
	noErr(t, applyAll(t, s, p1, f.heartbeat(t)))
	if h := policyHashes(t, s); !slices.Equal(h, []string{p1.Hash()}) {
		t.Errorf("policy in force: %v", h)
	}
	// The firm's stop list needs a key admin too.
	stop := &StopList{Type: StopType, Issuer: IssuerFirm, Firm: f.firm, Seq: 1, IssuedAt: t0, All: true}
	if err := apply(t, s, signS(t, stop, f.kit)); err == nil {
		t.Error("the kit signed a stop list")
	}
	noErr(t, applyAll(t, s, signS(t, stop, f.owner)))
	if _, err := s.Check("s_x", false); CodeOf(err) != CodeStopped {
		t.Errorf("stopped: %v", err)
	}
	if k := s.KeysStatus(); k.Seq != 2 || k.Head != f.hash(1) || k.Fork {
		t.Errorf("keys: %+v", k)
	}
	if st := s.StatusOf("s_x"); st.Keys == nil || st.Keys.Seq != 2 {
		t.Errorf("status keys: %+v", st.Keys)
	}
	// A key log entry is no safety document, and a VM without a genesis pin takes none.
	legacy, _ := NewState(Config{Firm: f.firm, Admins: []ed25519.PublicKey{pub(f.owner)}, Release: release(), Now: func() time.Time { return f.now }})
	if errs := applyAll(t, legacy, f.entries[0]); errs[0] == nil || legacy.KeysStatus() != nil || legacy.KeyLogged() {
		t.Error("a VM without a genesis pin took a key log entry")
	}
	if _, err := NewState(Config{Firm: f.firm, Genesis: f.genesis, Admins: []ed25519.PublicKey{pub(f.owner)}, Release: release()}); err == nil {
		t.Error("both admin keys and a genesis pinned")
	}
	if _, err := NewState(Config{Firm: f.firm, Carry: []string{p1.Hash()}, Release: release()}); err == nil {
		t.Error("carry without a genesis")
	}
	var fl Flags
	fl.Firm, fl.Admins, fl.Genesis, fl.Threshold = f.firm, KeyString(pub(f.owner)), f.genesis, 1
	if _, err := fl.Config(release(), ""); err == nil {
		t.Error("flags: both admin keys and a genesis")
	}
}

// a revoked key admin's policy stays in force until another admin re-signs it; their new
// documents are refused. Also across a restart (agentd's disk) and in a process fed agentd's documents in order
// (gatewayd, the vault), but not for anyone else who presents it later.
func TestRevokedAdminPolicyStaysInForce(t *testing.T) {
	f := newKL(t)
	s := f.state(t)
	noErr(t, applyAll(t, s, f.entries[:3]...)) // owner and bea are key admins (effective threshold 1)
	byBea := signP(t, f.policy(1), f.bea)
	stopBea := signS(t, &StopList{Type: StopType, Issuer: IssuerFirm, Firm: f.firm, Seq: 1, IssuedAt: t0, Stop: []Target{{Firm: f.firm, Space: "s_other"}}}, f.bea)
	noErr(t, applyAll(t, s, byBea, stopBea, f.heartbeat(t)))
	noErr(t, applyAll(t, s, f.entries[3:5]...)) // threshold 2, then bea revoked: owner is the only admin
	if h := policyHashes(t, s); !slices.Equal(h, []string{byBea.Hash()}) {
		t.Fatalf("bea's policy after her revocation: %v", h)
	}
	if stop, by := s.Stopped("s_other"); !stop || by != IssuerFirm {
		t.Error("bea's stop list should stay")
	}
	// Presented again: held, a no-op (not an error although its signer left).
	noErr(t, applyAll(t, s, byBea))
	// Her new documents are refused.
	if err := apply(t, s, signP(t, f.policy(2), f.bea)); err == nil || !strings.Contains(err.Error(), "current key admins") {
		t.Errorf("revoked admin's new policy: %v", err)
	}
	if err := apply(t, s, signS(t, &StopList{Type: StopType, Issuer: IssuerFirm, Firm: f.firm, Seq: 2, IssuedAt: t0}, f.bea)); err == nil {
		t.Error("revoked admin's new stop list (it would lift a stop)")
	}

	// Restart: agentd's disk holds the log and bea's policy at entry 3, where she was an admin.
	r := f.state(t)
	if h := policyHashes(t, r); !slices.Equal(h, []string{byBea.Hash()}) {
		t.Fatalf("after restart: %v", h)
	}
	if k := r.KeysStatus(); k.Seq != 5 || k.Head != f.hash(4) {
		t.Errorf("keys after restart: %+v", k)
	}
	// gatewayd and the vault (memory only) get agentd's documents in order: the policy follows entry 3.
	// Docs: the operator's list (no key log position), entries 1-3, bea's stop list and policy, entries 4-5.
	docs := r.Docs()
	var kinds []string
	for _, d := range docs {
		kinds = append(kinds, d.Kind)
	}
	if !slices.Equal(kinds, []string{"stop", "genesis", "identity.add", "identity.add", "stop", "policy", "threshold", "identity.revoke"}) ||
		docs[5].Hash() != byBea.Hash() {
		t.Fatalf("docs order: %v", kinds)
	}
	gw, _ := NewState(f.cfg(""))
	noErr(t, func() []error { e, _ := gw.ApplyOrdered(docs); return e }())
	if h := policyHashes(t, gw); !slices.Equal(h, []string{byBea.Hash()}) {
		t.Errorf("ordered (gatewayd): %v", h)
	}
	// Anyone else presenting it now (POST /safety on a fresh VM) is refused: a new document from a revoked admin.
	fresh, _ := NewState(f.cfg(""))
	errs := applyAll(t, fresh, f.entries[:5]...)
	noErr(t, errs)
	if err := apply(t, fresh, byBea); err == nil {
		t.Error("a revoked admin's policy taken as new")
	}
	// The order can't name a point before the log starts, or an entry the receiver doesn't verify.
	gw2, _ := NewState(f.cfg(""))
	if errs, _ := gw2.ApplyOrdered([]Envelope{byBea}); errs[0] == nil {
		t.Error("ordered with no log")
	}
	// Re-signed by the remaining admin: in force, and bea's is gone for good (rollback refused).
	byOwner := signP(t, f.policy(2), f.owner)
	noErr(t, applyAll(t, r, byOwner))
	if err := apply(t, r, byBea); err == nil {
		t.Error("old policy back")
	}
	if h := policyHashes(t, r); !slices.Equal(h, []string{byOwner.Hash()}) {
		t.Errorf("re-signed: %v", h)
	}
}

func TestKeylogRollbackAndFork(t *testing.T) {
	f := newKL(t)
	s := f.state(t)
	noErr(t, applyAll(t, s, f.entries[:5]...))
	p1 := signP(t, f.policy(1), f.owner)
	noErr(t, applyAll(t, s, p1, f.heartbeat(t)))
	// Rollback: a shorter log changes nothing (its entries are held), also after a restart.
	noErr(t, applyAll(t, s, f.entries[:3]...))
	if k := s.KeysStatus(); k.Seq != 5 {
		t.Fatalf("rolled back: %+v", k)
	}
	if k := f.state(t).KeysStatus(); k.Seq != 5 {
		t.Fatalf("rolled back after restart: %+v", k)
	}
	// A forged entry 6 (the kit naming bea, who is revoked; or a signature changed) is refused quietly.
	forged := f.entries[5]
	forged.Sigs = []Sig{{Key: forged.Sigs[0].Key, Sig: append([]byte{forged.Sigs[0].Sig[0] ^ 1}, forged.Sigs[0].Sig[1:]...)}}
	if errs := applyAll(t, s, forged); errs[0] == nil || s.KeysStatus().Fork {
		t.Error("forged entry")
	}
	// Fork: owner (the only admin after 5) signs another valid entry 5 (threshold 1 in place of bea's revocation
	// needs owner and bea, threshold 2, at entry 4).
	before, _ := keylog.Replay(f.firm, toEntries(f.entries[:4]))
	alt := keylog.Payload{Kind: keylog.KindThresh, Firm: f.firm, Seq: 5, Prev: before.Head, Time: 1_800_000_000, Threshold: 1}
	ab, _ := alt.Canonical()
	altEntry := envelopeOf(keylog.Sign(keylog.KindThresh, ab, f.owner, f.bea))
	errs := applyAll(t, s, altEntry)
	if errs[0] == nil || !s.KeysStatus().Fork {
		t.Fatalf("fork not raised: %v", errs[0])
	}
	// From now on: no entry past the head, no policy, no firm stop list; the policy in force stays; the operator's
	// lists still work (availability only).
	if errs := applyAll(t, s, f.entries[5]); errs[0] == nil || !strings.Contains(errs[0].Error(), "forked") {
		t.Errorf("entry 6 after the fork: %v", errs[0])
	}
	if err := apply(t, s, signP(t, f.policy(2), f.owner)); err == nil || !strings.Contains(err.Error(), "forked") {
		t.Errorf("policy after the fork: %v", err)
	}
	if err := apply(t, s, signS(t, &StopList{Type: StopType, Issuer: IssuerFirm, Firm: f.firm, Seq: 1, IssuedAt: t0, All: true}, f.owner)); err == nil {
		t.Error("firm stop list after the fork")
	}
	f.now = f.now.Add(time.Minute)
	noErr(t, applyAll(t, s, f.heartbeat(t)))
	if h := policyHashes(t, s); !slices.Equal(h, []string{p1.Hash()}) {
		t.Errorf("policy in force after the fork: %v", h)
	}
	// The proof outlives a restart.
	r := f.state(t)
	if k := r.KeysStatus(); !k.Fork || k.Seq != 5 {
		t.Errorf("fork after restart: %+v", k)
	}
	if h := policyHashes(t, r); !slices.Equal(h, []string{p1.Hash()}) {
		t.Errorf("policy after restart: %v", h)
	}
	// A new release pinning another genesis starts over (the proof was about the old log).
	f.genesis = strings.Repeat("ab", 32)
	if k := f.state(t).KeysStatus(); k.Fork || k.Seq != 0 {
		t.Errorf("another genesis: %+v", k)
	}
}

func toEntries(envs []Envelope) []keylog.Entry {
	var out []keylog.Entry
	for _, e := range envs {
		out = append(out, entryOf(e))
	}
	return out
}

// the compose's old admin key becomes the log's recovery kit. A document it signed before the
// move stays in force when the release pins its hash (Carry), and only then; the kit signs nothing new.
func TestCarriedDocument(t *testing.T) {
	f := newKL(t)
	old := signP(t, f.policy(1), f.kit) // signed when the kit's key was the compose's admin key
	// Before the move: the legacy VM takes it under the compose key (and keeps it and its floor on disk).
	r := release()
	r.Firm = f.firm
	legacy, err := NewState(Config{Firm: f.firm, Operator: pub(f.operator), Admins: []ed25519.PublicKey{pub(f.kit)}, Release: r, Dir: f.dir,
		Now: func() time.Time { return f.now }})
	if err != nil {
		t.Fatal(err)
	}
	noErr(t, applyAll(t, legacy, old, f.heartbeat(t)))

	// The new release without Carry: dropped at load, and refused when presented again.
	s := f.state(t)
	if _, err := s.Check("s_x", false); CodeOf(err) != CodePolicyMissing {
		t.Errorf("after the move: %v", err)
	}
	noErr(t, applyAll(t, s, f.entries[:2]...))
	if err := apply(t, s, old); err == nil {
		t.Error("a kit-signed policy taken without Carry")
	}

	// With Carry on the upgraded VM (its disk has the floor and, now, the log): the same document is taken again.
	f.carry = []string{old.Hash()}
	up := f.state(t)
	noErr(t, applyAll(t, up, old, f.heartbeat(t)))
	if h := policyHashes(t, up); !slices.Equal(h, []string{old.Hash()}) {
		t.Fatalf("carried policy on the upgraded VM: %v", h)
	}
	// With Carry on a fresh VM: taken once the log (and so the kit) is known.
	f.dir = t.TempDir()
	c := f.state(t)
	if err := apply(t, c, old); err == nil || !strings.Contains(err.Error(), "hasn't received") {
		t.Errorf("carried before the log: %v", err)
	}
	noErr(t, applyAll(t, c, f.entries[:2]...))
	noErr(t, applyAll(t, c, old, f.heartbeat(t)))
	if h := policyHashes(t, c); !slices.Equal(h, []string{old.Hash()}) {
		t.Fatalf("carried policy: %v", h)
	}
	// Survives a restart (and the ordered hand-on to gatewayd).
	if h := policyHashes(t, f.state(t)); !slices.Equal(h, []string{old.Hash()}) {
		t.Fatalf("carried after restart: %v", h)
	}
	gw, _ := NewState(f.cfg(""))
	noErr(t, func() []error { e, _ := gw.ApplyOrdered(c.Docs()); return e }())
	if h := policyHashes(t, gw); !slices.Equal(h, []string{old.Hash()}) {
		t.Errorf("carried in gatewayd: %v", h)
	}
	// Nothing else the kit signs counts: another policy, a stop list, the pinned one signed by someone else.
	if err := apply(t, c, signP(t, f.policy(2), f.kit)); err == nil {
		t.Error("the kit signed a new policy")
	}
	stranger := key(t)
	other := Sign(KindPolicy, old.Payload, stranger) // the same bytes (map order isn't fixed in signP's encoding)
	if other.Hash() != old.Hash() {
		t.Fatal("same payload, same hash")
	}
	c2 := func() *State { f2 := *f; f2.dir = t.TempDir(); return f2.state(t) }()
	noErr(t, applyAll(t, c2, f.entries[:2]...))
	if err := apply(t, c2, other); err == nil {
		t.Error("the carried document signed by another key")
	}
	// A newer policy from a key admin replaces it, and it can't come back.
	newer := signP(t, f.policy(2), f.owner)
	noErr(t, applyAll(t, c, newer))
	if err := apply(t, c, old); err == nil || !strings.Contains(err.Error(), "rollback") {
		t.Errorf("carried after a newer one: %v", err)
	}
}

// docs/23: with two or more key admins, a policy that widens the one in force needs two signatures.
func TestWideningNeedsTwoAdmins(t *testing.T) {
	f := newKL(t)
	s := f.state(t)
	noErr(t, applyAll(t, s, f.entries[:3]...)) // owner and bea: two admins, effective threshold 1
	noErr(t, applyAll(t, s, signP(t, f.policy(1), f.owner)))
	narrower := f.policy(2)
	narrower.Budget.Run.Tokens = 400
	noErr(t, applyAll(t, s, signP(t, narrower, f.owner)))
	for name, mod := range map[string]func(*Policy){
		"a model":         func(p *Policy) { p.Models = append(p.Models, "kimi-k3") },
		"a budget raised": func(p *Policy) { p.Budget.Run.Tokens = 500 },
		"a fetch host": func(p *Policy) {
			c := p.Connectors["web"]
			c.Fetch = append(c.Fetch, "tacy.io")
			p.Connectors["web"] = c
		},
	} {
		w := f.policy(3)
		w.Budget.Run.Tokens = 400
		mod(w)
		if err := apply(t, s, signP(t, w, f.owner)); err == nil || !strings.Contains(err.Error(), "two key admins") {
			t.Errorf("widening (%s) with one signature: %v", name, err)
		}
	}
	w := f.policy(3)
	noErr(t, applyAll(t, s, signP(t, w, f.owner, f.bea)))

	// Widens: dropping an approval and turning on stale reads count; narrowing doesn't.
	a := f.policy(1)
	a.Approve, a.StaleReads = []string{"web.fetch"}, false
	b := f.policy(1)
	b.StaleReads = false
	if !Widens(a, b) || !Widens(b, f.policy(1)) || Widens(f.policy(1), a) {
		t.Error("Widens")
	}
	// One admin: one signature is enough (the firm can't have two yet).
	one := newKL(t)
	o := one.state(t)
	noErr(t, applyAll(t, o, one.entries[:1]...))
	noErr(t, applyAll(t, o, signP(t, one.policy(1), one.owner)))
	wide := one.policy(2)
	wide.Models = append(wide.Models, "kimi-k3")
	noErr(t, applyAll(t, o, signP(t, wide, one.owner)))
}
