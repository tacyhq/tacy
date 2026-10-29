package keylog

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"os"
	"slices"
	"strings"
	"testing"
)

// The browser's golden vectors (the firm key log's vectors): the same file as the chat's test/golden/v2-keylog.json.
type vectors struct {
	Firm       string `json:"firm"`
	Identities map[string]struct {
		ID      string `json:"id"`
		Member  string `json:"member"`
		User    string `json:"user"`
		Seed    string `json:"ed25519SeedHex"`
		Ed25519 string `json:"ed25519"`
		X25519  string `json:"x25519"`
		FP      string `json:"fingerprint"`
	} `json:"identities"`
	Kit struct {
		Seed    string `json:"ed25519SeedHex"`
		Ed25519 string `json:"ed25519"`
	} `json:"kit"`
	Keylog []struct {
		Kind     string `json:"kind"`
		Hash     string `json:"hash"`
		Envelope string `json:"envelope"`
	} `json:"keylog"`
	State struct {
		Seq       int64    `json:"seq"`
		Head      string   `json:"head"`
		Genesis   string   `json:"genesis"`
		Admins    []string `json:"admins"`
		Threshold int64    `json:"threshold"`
		Current   []string `json:"current"`
		Revoked   []string `json:"revoked"`
		RootGen   int64    `json:"rootGen"`
		Root      string   `json:"root"`
		Kit       string   `json:"kit"`
	} `json:"state"`
}

func load(t *testing.T) (*vectors, []Entry) {
	t.Helper()
	b, err := os.ReadFile("../keysv2/testdata/v2-keylog.json")
	if err != nil {
		t.Fatal(err)
	}
	var v vectors
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	var es []Entry
	for _, lv := range v.Keylog {
		var e Entry
		if err := json.Unmarshal([]byte(lv.Envelope), &e, json.RejectUnknownMembers(true)); err != nil {
			t.Fatal(err)
		}
		if e.Hash() != lv.Hash {
			t.Fatalf("%s: hash", lv.Kind)
		}
		es = append(es, e)
	}
	return &v, es
}

func seedKey(t *testing.T, h string) ed25519.PrivateKey {
	t.Helper()
	b, err := hex.DecodeString(h)
	if err != nil || len(b) != 32 {
		t.Fatal("seed")
	}
	return ed25519.NewKeyFromSeed(b)
}

func (v *vectors) key(t *testing.T, name string) ed25519.PrivateKey {
	if name == "kit" {
		return seedKey(t, v.Kit.Seed)
	}
	return seedKey(t, v.Identities[name].Seed)
}

func stateOf(s *State) (admins, current, revoked []string) {
	admins = s.Admins()
	for id, i := range s.ids {
		if i.Revoked != 0 {
			revoked = append(revoked, id)
		} else {
			current = append(current, id)
		}
	}
	slices.Sort(current)
	slices.Sort(revoked)
	return
}

func TestVectorsReplay(t *testing.T) {
	v, es := load(t)
	s, err := Replay(v.Firm, es)
	if err != nil {
		t.Fatal(err)
	}
	admins, current, revoked := stateOf(s)
	if s.Seq != v.State.Seq || s.Head != v.State.Head || s.Genesis != v.State.Genesis || s.Threshold != v.State.Threshold ||
		s.RootGen != v.State.RootGen || s.Root != v.State.Root || s.Kit != v.State.Kit {
		t.Errorf("state: %+v", s)
	}
	if !slices.Equal(admins, v.State.Admins) || !slices.Equal(current, v.State.Current) || !slices.Equal(revoked, v.State.Revoked) {
		t.Errorf("admins %v current %v revoked %v", admins, current, revoked)
	}
	// Every payload decodes and re-encodes to its exact bytes.
	for i, e := range es {
		p, err := DecodePayload(e.Kind, e.Payload, v.Firm)
		if err != nil {
			t.Fatalf("entry %d: %v", i+1, err)
		}
		c, _ := p.Canonical()
		if string(c) != string(e.Payload) {
			t.Fatalf("entry %d: canonical", i+1)
		}
	}
	// Not for another firm, and not as the placeholder's log.
	if _, err := Replay("f_ymaaaaaaaaaaaaaaaaaaaaaaci", es); err == nil {
		t.Error("another firm's log accepted")
	}
	if _, err := Replay(Placeholder, es); err == nil {
		t.Error("a real firm's log accepted as f_chat's")
	}
}

func TestLogAddAndViews(t *testing.T) {
	v, es := load(t)
	l, err := New(v.Firm, v.State.Genesis)
	if err != nil {
		t.Fatal(err)
	}
	// Nothing before the genesis; the genesis must be the pinned one.
	if c, _ := Check(es[1], v.Firm); c != nil {
		if _, err := l.Add(c); err == nil {
			t.Error("entry 2 before the genesis")
		}
	}
	other, _ := New(v.Firm, strings.Repeat("ab", 32))
	c1, err := Check(es[0], v.Firm)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := other.Add(c1); err == nil {
		t.Error("a genesis that isn't the pinned one")
	}
	for i, e := range es {
		c, err := Check(e, v.Firm)
		if err != nil {
			t.Fatal(err)
		}
		if r, err := l.Add(c); err != nil || r != Appended {
			t.Fatalf("entry %d: %v %v", i+1, r, err)
		}
	}
	if l.Seq() != v.State.Seq || l.Head() != v.State.Head {
		t.Fatal("head")
	}
	// Held again: a no-op (a shorter log offered again is a rollback attempt, which changes nothing).
	for _, e := range es[:3] {
		c, _ := Check(e, v.Firm)
		if r, err := l.Add(c); err != nil || r != Held {
			t.Fatalf("held: %v %v", r, err)
		}
	}
	// Views: bea is a key admin after entry 3, not after her revocation (5); cal after the kit's admins entry (6).
	bea, cal, owner := v.Identities["bea"].Ed25519, v.Identities["cal"].Ed25519, v.Identities["owner"].Ed25519
	for _, c := range []struct {
		seq       int64
		key       string
		admin     bool
		threshold int64
	}{{1, owner, true, 1}, {2, bea, true, 1}, {3, bea, true, 1}, {4, bea, true, 2}, {5, bea, false, 1}, {5, cal, false, 1}, {6, cal, true, 2}, {7, owner, true, 2}} {
		vw, ok := l.ViewAt(c.seq)
		if !ok || slices.Contains(vw.Admins, c.key) != c.admin || vw.Threshold != c.threshold || vw.Kit != v.Kit.Ed25519 {
			t.Errorf("view at %d: %+v", c.seq, vw)
		}
	}
	if slices.Contains(l.State().AdminKeys(), v.Kit.Ed25519) {
		t.Error("the kit is never an admin signer")
	}
	// Restart: Load replays and stops at the first bad entry.
	l2, _ := New(v.Firm, v.State.Genesis)
	if n, err := l2.Load(es); err != nil || n != len(es) || l2.Head() != l.Head() {
		t.Fatalf("load: %d %v", n, err)
	}
	l3, _ := New(v.Firm, v.State.Genesis)
	if n, err := l3.Load(append([]Entry{es[0], es[2]}, es[1:]...)); err == nil || n != 1 {
		t.Fatalf("load of a gap: %d %v", n, err)
	}
}

// fixture: a log after entry k, keys at hand.
func fixture(t *testing.T, k int) (*vectors, []Entry, *Log) {
	v, es := load(t)
	l, _ := New(v.Firm, v.State.Genesis)
	if n, err := l.Load(es[:k]); err != nil || n != k {
		t.Fatal(err)
	}
	return v, es, l
}

func payloadAt(l *Log, kind string, fields map[string]any) []byte {
	p := Payload{Kind: kind, Firm: l.firm, Seq: l.Seq() + 1, Prev: l.Head(), Time: 1_800_000_000}
	b, _ := json.Marshal(fields)
	json.Unmarshal(b, &p)
	p.Kind = kind
	out, _ := p.Canonical()
	return out
}

func TestForkAndRefusals(t *testing.T) {
	v, es, l := fixture(t, 4) // owner, bea, cal; threshold 2
	owner, bea, cal, kit := v.key(t, "owner"), v.key(t, "bea"), v.key(t, "cal"), v.key(t, "kit")
	add := func(e Entry) error {
		c, err := Check(e, v.Firm)
		if err != nil {
			return err
		}
		_, err = l.Add(c)
		return err
	}
	// Threshold 2: one admin signature isn't enough; a non-admin's signature is a forgery; the kit may only
	// change admins; a gap is refused.
	revokeCal := payloadAt(l, KindRevoke, map[string]any{"identity": v.Identities["cal"].ID})
	if err := add(Sign(KindRevoke, revokeCal, owner)); err == nil || !strings.Contains(err.Error(), "needs 2") {
		t.Errorf("one signature at threshold 2: %v", err)
	}
	if err := add(Sign(KindRevoke, revokeCal, owner, cal)); err == nil || !strings.Contains(err.Error(), "isn't a current key admin") {
		t.Errorf("a non-admin co-signer: %v", err)
	}
	if err := add(Sign(KindRevoke, revokeCal, owner, kit)); err == nil || !strings.Contains(err.Error(), "kit") {
		t.Errorf("the kit on a revoke: %v", err)
	}
	gap := Payload{Kind: KindThresh, Firm: v.Firm, Seq: 9, Prev: l.Head(), Threshold: 1}
	gb, _ := gap.Canonical()
	if err := add(Sign(KindThresh, gb, owner, bea)); err == nil || !strings.Contains(err.Error(), "before entry 5") {
		t.Errorf("gap: %v", err)
	}
	// The held entry 5 is bea's own revocation; owner and bea also sign a different valid entry 5: a fork.
	if err := add(es[4]); err != nil {
		t.Fatal(err)
	}
	l4, _ := New(v.Firm, v.State.Genesis)
	l4.Load(es[:4])
	alt := payloadAt(l4, KindThresh, map[string]any{"threshold": 1})
	err := add(Sign(KindThresh, alt, owner, bea))
	var fe *ForkError
	if !errors.As(err, &fe) || !errors.Is(err, ErrFork) || fe.Fork.Seq != 5 || fe.Fork.Ours != v.Keylog[4].Hash {
		t.Fatalf("fork: %v", err)
	}
	// A different entry 5 that isn't valid (one signature) is refused, but proves nothing.
	err = add(Sign(KindThresh, alt, owner))
	if err == nil || errors.Is(err, ErrFork) {
		t.Errorf("an invalid alternative raised a fork: %v", err)
	}
	// Payload tampering, bad signatures, duplicates.
	bad := es[5]
	bad.Payload = []byte(strings.Replace(string(bad.Payload), `"seq":6`, `"seq": 6`, 1))
	if err := add(bad); err == nil {
		t.Error("non-canonical payload")
	}
	dup := es[5]
	dup.Sigs = append(dup.Sigs, dup.Sigs[0])
	if err := add(dup); err == nil {
		t.Error("duplicate signer")
	}
	flip := es[5]
	flip.Sigs = []Sig{{Key: flip.Sigs[0].Key, Sig: append([]byte{flip.Sigs[0].Sig[0] ^ 1}, flip.Sigs[0].Sig[1:]...)}}
	if err := add(flip); err == nil {
		t.Error("bad signature")
	}
	if err := add(es[5]); err != nil {
		t.Errorf("entry 6 after the refusals: %v", err)
	}
}

func TestPayloadStrictness(t *testing.T) {
	v, es := load(t)
	firm := v.Firm
	for _, c := range []struct{ kind, payload string }{
		{KindRevoke, `{"firm":"` + firm + `","seq":2,"prev":"` + strings.Repeat("a", 64) + `","time":1,"identity":"i_ymaaaaaaaaaaaaaaaaaaaaaacb"}`}, // non-canonical id tail
		{KindRevoke, `{"firm":"` + firm + `","seq":2,"prev":"` + strings.Repeat("a", 64) + `","time":1,"identity":"i_ymaaaaaaaaaaaaaaaaaaaaaace","x":1}`},
		{KindRevoke, `{"seq":2,"firm":"` + firm + `","prev":"` + strings.Repeat("a", 64) + `","time":1,"identity":"i_ymaaaaaaaaaaaaaaaaaaaaaace"}`},
		{KindRevoke, `{"firm":"` + firm + `","seq":1,"prev":"","time":1,"identity":"i_ymaaaaaaaaaaaaaaaaaaaaaace"}`},
		{KindRevoke, `{"firm":"` + firm + `","seq":2,"prev":"` + strings.Repeat("a", 64) + `","time":-1,"identity":"i_ymaaaaaaaaaaaaaaaaaaaaaace"}`},
		{KindAdmins, `{"firm":"` + firm + `","seq":2,"prev":"` + strings.Repeat("a", 64) + `","time":1,"admins":["i_ymaaaaaaaaaaaaaaaaaaaaaaci","i_ymaaaaaaaaaaaaaaaaaaaaaace"]}`},
		{KindAdmins, `{"firm":"` + firm + `","seq":2,"prev":"` + strings.Repeat("a", 64) + `","time":1,"admins":[]}`},
		{KindThresh, `{"firm":"` + firm + `","seq":2,"prev":"` + strings.Repeat("a", 64) + `","time":1,"threshold":9}`},
		{KindRevoke, `{"firm":"f_chat","seq":2,"prev":"` + strings.Repeat("a", 64) + `","time":1,"identity":"i_ymaaaaaaaaaaaaaaaaaaaaaace"}`},
	} {
		if _, err := DecodePayload(c.kind, []byte(c.payload), firm); err == nil {
			t.Errorf("accepted: %s", c.payload)
		}
	}
	if _, err := DecodePayload("policy", es[0].Payload, firm); err == nil {
		t.Error("a safety kind as a key log kind")
	}
}

// ---- the placeholder firm's log: testdata/fchat-keylog.json, made here once, replayed by the browser --------

type fchatVectors struct {
	Format  string `json:"format"`
	Note    string `json:"note"`
	Firm    string `json:"firm"`
	Entries []struct {
		Kind     string `json:"kind"`
		Hash     string `json:"hash"`
		Envelope string `json:"envelope"`
	} `json:"entries"`
	State struct {
		Seq     int64    `json:"seq"`
		Head    string   `json:"head"`
		Genesis string   `json:"genesis"`
		Admins  []string `json:"admins"`
		Kit     string   `json:"kit"`
	} `json:"state"`
	// Refused: each of these, appended to the log above (or as its genesis, for "genesis" ones), must be refused
	// by both verifiers.
	Refused []struct {
		Why      string `json:"why"`
		At       int    `json:"at"` // entries before it
		Envelope string `json:"envelope"`
	} `json:"refused"`
}

func xpub(t *testing.T, seedHex string) string {
	b, _ := hex.DecodeString(seedHex)
	k, err := ecdh.X25519().NewPrivateKey(b)
	if err != nil {
		t.Fatal(err)
	}
	return "x25519:" + base64.StdEncoding.EncodeToString(k.PublicKey().Bytes())
}

func envString(e Entry) string {
	b, _ := json.Marshal(e)
	return string(b)
}

// makeFchat builds the placeholder log from fixed seeds: genesis by the owner's identity (legacy hex user)
// and the kit, then a second admin, then that admin revoked by the owner.
func makeFchat(t *testing.T) *fchatVectors {
	owner := seedKey(t, strings.Repeat("11", 32))
	kit := seedKey(t, strings.Repeat("22", 32))
	second := seedKey(t, strings.Repeat("33", 32))
	fx, sx, root := xpub(t, strings.Repeat("44", 32)), xpub(t, strings.Repeat("55", 32)), xpub(t, strings.Repeat("66", 32))
	fe, se, ke := EdString(owner.Public().(ed25519.PublicKey)), EdString(second.Public().(ed25519.PublicKey)), EdString(kit.Public().(ed25519.PublicKey))
	ffp, _ := Fingerprint(fe, fx)
	sfp, _ := Fingerprint(se, sx)
	const (
		fid, fmem, fuser = "i_ceaaaaaaaaaaaaaaaaaaaaaaaa", "m_ceaaaaaaaaaaaaaaaaaaaaaaaa", "0123456789abcdef0123456789abcdef"
		sid, smem, suser = "i_dmaaaaaaaaaaaaaaaaaaaaaaaa", "m_dmaaaaaaaaaaaaaaaaaaaaaaaa", "u_dmaaaaaaaaaaaaaaaaaaaaaaaa"
	)
	out := &fchatVectors{Format: "tacy-golden-crypto-vectors", Firm: Placeholder,
		Note: "The firm key log: the f_chat placeholder's key log (the VM's keylog package, TestFchatVectors). Made once from fixed seeds; never regenerate."}
	var es []Entry
	push := func(e Entry) {
		es = append(es, e)
		out.Entries = append(out.Entries, struct {
			Kind     string `json:"kind"`
			Hash     string `json:"hash"`
			Envelope string `json:"envelope"`
		}{e.Kind, e.Hash(), envString(e)})
	}
	feh, _ := EmailHash(Placeholder, "Owner@Example.org ")
	seh, _ := EmailHash(Placeholder, "second@example.org")
	g := Payload{Kind: KindGenesis, Firm: Placeholder, Seq: 1, Time: 1_792_000_000, Identity: fid, Member: fmem, User: fuser, EmailHash: feh,
		Ed25519: fe, X25519: fx, Fingerprint: ffp, Kit: ke, Root: root, Threshold: 1}
	gb, _ := g.Canonical()
	push(Sign(KindGenesis, gb, owner, kit))
	a := Payload{Kind: KindAdd, Firm: Placeholder, Seq: 2, Prev: es[0].Hash(), Time: 1_792_000_100, Identity: sid, Member: smem,
		User: suser, EmailHash: seh, Ed25519: se, X25519: sx, Fingerprint: sfp, Admin: true}
	ab, _ := a.Canonical()
	push(Sign(KindAdd, ab, owner))
	r := Payload{Kind: KindRevoke, Firm: Placeholder, Seq: 3, Prev: es[1].Hash(), Time: 1_792_000_200, Identity: sid}
	rb, _ := r.Canonical()
	push(Sign(KindRevoke, rb, owner))
	st, err := Replay(Placeholder, es)
	if err != nil {
		t.Fatal(err)
	}
	out.State.Seq, out.State.Head, out.State.Genesis, out.State.Admins, out.State.Kit = st.Seq, st.Head, st.Genesis, st.Admins(), st.Kit

	refuse := func(why string, at int, e Entry) {
		out.Refused = append(out.Refused, struct {
			Why      string `json:"why"`
			At       int    `json:"at"`
			Envelope string `json:"envelope"`
		}{why, at, envString(e)})
	}
	// The kit can't sign a threshold (only admins).
	th := Payload{Kind: KindThresh, Firm: Placeholder, Seq: 4, Prev: es[2].Hash(), Time: 1_792_000_300, Threshold: 1}
	thb, _ := th.Canonical()
	refuse("the kit signs only admins", 3, Sign(KindThresh, thb, kit))
	// A revoked admin can't sign.
	refuse("a revoked admin", 3, Sign(KindThresh, thb, second))
	// A genesis whose user is a legacy id for a real firm (not the placeholder): refused by a real firm's log.
	// (Here: the placeholder genesis with an unknown-format user.)
	g2 := g
	g2.User = "0123456789ABCDEF0123456789ABCDEF"
	g2b, _ := g2.Canonical()
	refuse("a user id that is neither u_ nor 32 lowercase hex", 0, Sign(KindGenesis, g2b, owner, kit))
	return out
}

func TestFchatVectors(t *testing.T) {
	want := makeFchat(t)
	path := "testdata/fchat-keylog.json"
	if os.Getenv("KEYLOG_WRITE_VECTORS") == "1" {
		b, _ := json.Marshal(want, json.Deterministic(true))
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, append(b, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var got fchatVectors
	if err := json.Unmarshal(b, &got, json.RejectUnknownMembers(true)); err != nil {
		t.Fatal(err)
	}
	// The file never changes: what the code makes now must equal it byte for byte (Ed25519 is deterministic).
	wb, _ := json.Marshal(want, json.Deterministic(true))
	if string(append(wb, '\n')) != string(b) {
		t.Fatal("testdata/fchat-keylog.json differs from what the code makes (never regenerate it; fix the code)")
	}
	var es []Entry
	for _, e := range got.Entries {
		var en Entry
		if err := json.Unmarshal([]byte(e.Envelope), &en, json.RejectUnknownMembers(true)); err != nil {
			t.Fatal(err)
		}
		es = append(es, en)
	}
	st, err := Replay(Placeholder, es)
	if err != nil {
		t.Fatal(err)
	}
	if st.Head != got.State.Head || st.Genesis != got.State.Genesis || !slices.Equal(st.Admins(), got.State.Admins) || st.Kit != got.State.Kit {
		t.Fatal("state")
	}
	// The placeholder is accepted only for itself: not as a real firm's log.
	if _, err := Replay("f_ceaaaaaaaaaaaaaaaaaaaaaaaa", es); err == nil {
		t.Error("f_chat's log accepted for a real firm")
	}
	for _, r := range got.Refused {
		var en Entry
		json.Unmarshal([]byte(r.Envelope), &en)
		if _, err := Replay(Placeholder, append(slices.Clone(es[:r.At]), en)); err == nil {
			t.Errorf("accepted: %s", r.Why)
		}
	}
	// A legacy hex user in a real firm's log is refused.
	p, _ := DecodePayload(KindGenesis, es[0].Payload, Placeholder)
	p.Firm = "f_ceaaaaaaaaaaaaaaaaaaaaaaaa"
	pb, _ := p.Canonical()
	if _, err := DecodePayload(KindGenesis, pb, p.Firm); err == nil || !strings.Contains(err.Error(), "user") {
		t.Errorf("legacy user in a real firm: %v", err)
	}
}
