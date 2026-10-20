package safety

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json/v2"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

var t0 = time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)

func key(t testing.TB) ed25519.PrivateKey {
	_, k, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func pub(k ed25519.PrivateKey) ed25519.PublicKey { return k.Public().(ed25519.PublicKey) }

func release() *Policy {
	return &Policy{Type: PolicyType, Firm: "f_release", Version: 1, IssuedAt: t0,
		Models: []string{"gpt-oss-120b", "kimi-k3"},
		Connectors: map[string]Connector{
			"model": {Hosts: []string{"inference.tinfoil.sh"}},
			"web":   {Tools: []string{"web.search", "web.fetch", "web.images"}, Hosts: []string{"api.tavily.com"}, Fetch: []string{"*"}},
		},
		StaleReads: true,
		Budget:     Budgets{Run: Limits{Tokens: 1000, ToolCalls: 10, WallSeconds: 300, CostMicros: 1_000_000}, Day: Limits{Tokens: 5000}},
		Rates:      Rates{Key: Rate{60, 10}},
	}
}

func policy(v uint64, space string) *Policy {
	return &Policy{Type: PolicyType, Firm: "f_test", Space: space, Version: v, IssuedAt: t0,
		Models:     []string{"gpt-oss-120b"},
		Connectors: map[string]Connector{"model": {Hosts: []string{"inference.tinfoil.sh"}}, "web": {Tools: []string{"web.search", "web.fetch"}, Hosts: []string{"api.tavily.com"}, Fetch: []string{"*.example.com", "docs.tacy.io"}}},
		StaleReads: true,
		Budget:     Budgets{Run: Limits{Tokens: 500}},
	}
}

func signP(t testing.TB, p *Policy, keys ...ed25519.PrivateKey) Envelope {
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	return Sign(KindPolicy, b, keys...)
}

func signS(t testing.TB, l *StopList, keys ...ed25519.PrivateKey) Envelope {
	b, err := json.Marshal(l)
	if err != nil {
		t.Fatal(err)
	}
	return Sign(KindStop, b, keys...)
}

func opList(seq uint64, at time.Time, stop ...Target) *StopList {
	return &StopList{Type: StopType, Issuer: IssuerOperator, Seq: seq, IssuedAt: at, ExpiresAt: at.Add(15 * time.Minute), Stop: stop}
}

type fixture struct {
	admin, operator ed25519.PrivateKey
	now             atomic.Pointer[time.Time]
	dir             string
}

func newFixture(t *testing.T) *fixture {
	f := &fixture{admin: key(t), operator: key(t), dir: t.TempDir()}
	n := t0
	f.now.Store(&n)
	return f
}

func (f *fixture) advance(d time.Duration) { n := f.now.Load().Add(d); f.now.Store(&n) }

func (f *fixture) state(t *testing.T) *State {
	s, err := NewState(Config{Firm: "f_test", Operator: pub(f.operator), Admins: []ed25519.PublicKey{pub(f.admin)},
		Release: release(), Dir: f.dir, Now: func() time.Time { return *f.now.Load() }})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func apply(t *testing.T, s *State, e Envelope) error {
	t.Helper()
	errs, _ := s.Apply([]Envelope{e})
	return errs[0]
}

func TestForgedPolicyRefused(t *testing.T) {
	f := newFixture(t)
	s := f.state(t)
	stranger := key(t)
	cases := map[string]Envelope{
		"unpinned key":          signP(t, policy(1, ""), stranger),
		"operator key":          signP(t, policy(1, ""), f.operator), // the operator can't sign policy
		"no signature":          {Kind: KindPolicy, Payload: signP(t, policy(1, ""), f.admin).Payload},
		"signed as a stop list": func() Envelope { e := signP(t, policy(1, ""), f.admin); e.Kind = KindStop; return e }(),
		"payload changed after signing": func() Envelope {
			e := signP(t, policy(1, ""), f.admin)
			e.Payload = []byte(strings.Replace(string(e.Payload), `"web.fetch"`, `"web.images"`, 1))
			return e
		}(),
		"admin key claimed, other key's signature": func() Envelope {
			e := signP(t, policy(1, ""), stranger)
			e.Sigs[0].Key = KeyString(pub(f.admin))
			return e
		}(),
		"another firm":         signP(t, func() *Policy { p := policy(1, ""); p.Firm = "f_other"; return p }(), f.admin),
		"issued in the future": signP(t, func() *Policy { p := policy(1, ""); p.IssuedAt = t0.Add(time.Hour); return p }(), f.admin),
		"unknown field":        Sign(KindPolicy, []byte(`{"type":"tacy.policy/v1","firm":"f_test","version":1,"issued_at":"2026-10-17T12:00:00Z","models":[],"connectors":{},"stale_reads":true,"budget":{"run":{},"day":{}},"rates":{"key":{},"connector":{},"space":{}},"allow_all":true}`), f.admin),
		"duplicate field":      Sign(KindPolicy, []byte(`{"type":"tacy.policy/v1","firm":"f_test","firm":"f_test","version":1,"issued_at":"2026-10-17T12:00:00Z","models":[],"connectors":{},"stale_reads":true,"budget":{"run":{},"day":{}},"rates":{"key":{},"connector":{},"space":{}}}`), f.admin),
	}
	for name, e := range cases {
		if err := apply(t, s, e); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := s.Policy(""); CodeOf(err) != CodePolicyMissing {
		t.Fatalf("no policy should be in force, got %v", err)
	}
}

func TestPolicyRollbackRefused(t *testing.T) {
	f := newFixture(t)
	s := f.state(t)
	v1, v2 := signP(t, policy(1, ""), f.admin), signP(t, policy(2, ""), f.admin)
	if err := apply(t, s, v1); err != nil {
		t.Fatal(err)
	}
	if err := apply(t, s, v2); err != nil {
		t.Fatal(err)
	}
	if err := apply(t, s, v1); err == nil || !strings.Contains(err.Error(), "rollback") {
		t.Fatalf("v1 after v2: %v", err)
	}
	if err := apply(t, s, v2); err != nil { // the same document again: a no-op
		t.Fatalf("v2 again: %v", err)
	}
	other := policy(2, "")
	other.Models = append(other.Models, "kimi-k3")
	if err := apply(t, s, signP(t, other, f.admin)); err == nil {
		t.Fatal("a second, different v2 was accepted")
	}
	// After a restart the floor is still there: v1 can't come back.
	s2 := f.state(t)
	if err := apply(t, s2, v1); err == nil {
		t.Fatal("v1 accepted after a restart")
	}
	if e, err := s2.Policy("s_x"); err != nil || len(e.Hashes) != 1 || e.Hashes[0] != v2.Hash() {
		t.Fatalf("v2 not restored: %v %v", e, err)
	}
	// A tampered state file can't widen anything: documents are verified again on load.
	b, _ := os.ReadFile(filepath.Join(f.dir, "safety.json"))
	os.WriteFile(filepath.Join(f.dir, "safety.json"), []byte(strings.Replace(string(b), v2.Hash(), strings.Repeat("0", 64), -1)), 0o600)
	s3 := f.state(t)
	if _, err := s3.Policy(""); CodeOf(err) != CodePolicyMissing {
		t.Fatalf("a mismatched floor must fail closed, got %v", err)
	}
}

func TestEffectiveNarrowsOnly(t *testing.T) {
	f := newFixture(t)
	s := f.state(t)
	firm := policy(1, "")
	firm.Models = []string{"gpt-oss-120b", "kimi-k3", "made-up-model"} // more than the release: still only the release's
	space := policy(1, "s_a")
	space.Connectors = map[string]Connector{"model": {Hosts: []string{"inference.tinfoil.sh"}}, "web": {Tools: []string{"web.search"}, Hosts: []string{"api.tavily.com"}}}
	space.Budget.Run.Tokens = 2_000 // looser than the firm's: the firm's 500 holds
	space.Approve = []string{"web.search"}
	for _, e := range []Envelope{signP(t, firm, f.admin), signP(t, space, f.admin)} {
		if err := apply(t, s, e); err != nil {
			t.Fatal(err)
		}
	}
	e, err := s.Policy("s_a")
	if err != nil {
		t.Fatal(err)
	}
	if e.AllowsModel("made-up-model") || !e.AllowsModel("gpt-oss-120b") || e.AllowsModel("kimi-k3") /* not in the space's */ {
		t.Error("models")
	}
	if e.AllowsTool("web.fetch") || e.AllowsTool("web.images") || e.AllowsTool("web.search") /* held for approval */ {
		t.Error("tools")
	}
	if e.AllowsFetch("www.example.com") { // the space lists no fetch hosts
		t.Error("fetch")
	}
	if got := e.Budget().Run.Tokens; got != 500 {
		t.Errorf("run tokens %d, want 500", got)
	}
	if got := e.Rates().Key; got != (Rate{60, 10}) {
		t.Errorf("rates %+v", got)
	}
	fe, _ := s.Policy("s_b")
	if !fe.AllowsFetch("www.example.com") || fe.AllowsFetch("example.com") || !fe.AllowsFetch("docs.tacy.io") || fe.AllowsFetch("evil.com") ||
		fe.AllowsFetch("example.com.evil.com") {
		t.Error("fetch patterns")
	}
	if !fe.AllowsTool("web.fetch") || fe.AllowsTool("web.images") || fe.AllowsConnector("mail") {
		t.Error("firm-wide tools")
	}
}

func TestStopListsAndStaleness(t *testing.T) {
	f := newFixture(t)
	s := f.state(t)
	apply(t, s, signP(t, policy(1, ""), f.admin))
	// No operator list yet: stale. With an operator key pinned nothing goes on, reads included, whatever the
	// policy's stale_reads says (the release's floor).
	if _, err := s.Check("s_a", false); CodeOf(err) != CodeStale {
		t.Fatalf("read while stale: %v", err)
	}
	if _, err := s.Check("s_a", true); CodeOf(err) != CodeStale {
		t.Fatalf("side effect while stale: %v", err)
	}
	if err := apply(t, s, signS(t, opList(10, t0), f.operator)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Check("s_a", true); err != nil {
		t.Fatalf("fresh: %v", err)
	}
	// The admin can't sign the operator's list, and the operator can't sign the firm's.
	if err := apply(t, s, signS(t, opList(11, t0, Target{"f_test", ""}), f.admin)); err == nil {
		t.Fatal("operator list signed by the admin accepted")
	}
	fl := &StopList{Type: StopType, Issuer: IssuerFirm, Firm: "f_test", Seq: 1, IssuedAt: t0, Stop: []Target{{"f_test", "s_a"}}}
	if err := apply(t, s, signS(t, fl, f.operator)); err == nil {
		t.Fatal("firm list signed by the operator accepted")
	}
	if err := apply(t, s, signS(t, fl, f.admin)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Check("s_a", false); CodeOf(err) != CodeStopped {
		t.Fatalf("s_a must be stopped: %v", err)
	}
	if _, err := s.Check("s_b", true); err != nil {
		t.Fatalf("s_b: %v", err)
	}
	// Stale after the max age even though the list hasn't expired.
	f.advance(11 * time.Minute)
	if _, err := s.Check("s_b", true); CodeOf(err) != CodeStale {
		t.Fatalf("11 min later: %v", err)
	}
	// An expired list is refused; replaying the old one changes nothing; a newer one is fresh again.
	if err := apply(t, s, signS(t, opList(11, t0.Add(-20*time.Minute)), f.operator)); err == nil {
		t.Fatal("an expired operator list was accepted")
	}
	if err := apply(t, s, signS(t, opList(9, *f.now.Load()), f.operator)); err == nil {
		t.Fatal("an older seq was accepted")
	}
	if err := apply(t, s, signS(t, opList(12, *f.now.Load(), Target{"f_test", ""}), f.operator)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Check("s_b", false); CodeOf(err) != CodeStopped {
		t.Fatalf("the operator's firm stop: %v", err)
	}
	// The firm's stop survives a restart, and an operator list without it doesn't lift it.
	s2 := f.state(t)
	apply(t, s2, signS(t, opList(13, *f.now.Load()), f.operator))
	if _, err := s2.Check("s_a", false); CodeOf(err) != CodeStopped {
		t.Fatalf("firm stop lost: %v", err)
	}
	if _, err := s2.Check("s_b", true); err != nil {
		t.Fatalf("s_b after the operator lifted its stop: %v", err)
	}
	// A global stop.
	g := opList(14, *f.now.Load())
	g.All = true
	apply(t, s2, signS(t, g, f.operator))
	if _, err := s2.Check("s_z", false); CodeOf(err) != CodeStopped {
		t.Fatalf("global stop: %v", err)
	}
}

func TestEmptySpaceRefused(t *testing.T) {
	f := newFixture(t)
	s := f.state(t)
	apply(t, s, signP(t, policy(1, ""), f.admin))
	apply(t, s, signS(t, opList(1, t0), f.operator))
	if _, err := s.Check("", false); err == nil {
		t.Fatal("a request without a space must be refused (it would skip space stops)")
	}
}

func TestStaleReadsOff(t *testing.T) {
	f := newFixture(t)
	s := f.state(t)
	p := policy(1, "")
	p.StaleReads = false
	apply(t, s, signP(t, p, f.admin))
	if _, err := s.Check("s_a", false); CodeOf(err) != CodeStale {
		t.Fatalf("reads must stop when stale and the policy says so: %v", err)
	}
}

// A policy that says stale_reads true (as the live one does): with an operator key pinned, the release refuses
// reads anyway once the list is stale (11 minutes after it was signed) or silent (not delivered again for 3
// minutes, as when the host drops the pull), and lets them go on again when a fresh list is delivered.
func TestStaleOrSilentStopsReads(t *testing.T) {
	f := newFixture(t)
	s, err := NewState(Config{Firm: "f_test", Operator: pub(f.operator), Admins: []ed25519.PublicKey{pub(f.admin)},
		Release: release(), MaxSilence: DefaultMaxSilence, Now: func() time.Time { return *f.now.Load() }})
	if err != nil {
		t.Fatal(err)
	}
	apply(t, s, signP(t, policy(1, ""), f.admin))
	if e, _ := s.Policy("s_a"); !e.StaleReads() {
		t.Fatal("the test policy allows reads while stale")
	}
	if st := s.StatusOf("s_a"); st.Fresh || !st.Blocked || st.HeardS != nil {
		t.Fatalf("before any list: %+v", st)
	}
	hb := signS(t, opList(1, t0), f.operator)
	apply(t, s, hb)
	if _, err := s.Check("s_a", false); err != nil {
		t.Fatalf("fresh: %v", err)
	}
	// The pull delivers the same list every 10 s: still heard.
	for range 30 {
		f.advance(10 * time.Second)
		apply(t, s, hb)
	}
	if _, err := s.Check("s_a", false); err != nil {
		t.Fatalf("the same list delivered again keeps it heard: %v", err)
	}
	// The pull is dropped: 3 minutes later nothing goes out, reads included; the status says so.
	f.advance(DefaultMaxSilence - time.Second)
	if _, err := s.Check("s_a", false); err != nil {
		t.Fatalf("just under the silence limit: %v", err)
	}
	f.advance(2 * time.Second)
	for _, effect := range []bool{false, true} {
		if _, err := s.Check("s_a", effect); CodeOf(err) != CodeStale {
			t.Fatalf("silent, effect %v: %v", effect, err)
		}
	}
	st := s.StatusOf("s_a")
	if st.Fresh || !st.Blocked || st.HeardS == nil || *st.HeardS != int64(DefaultMaxSilence/time.Second)+1 {
		t.Fatalf("silent status: %+v", st)
	}
	// A list that expired while it wasn't delivered doesn't count as heard; a fresh one does.
	f.advance(15 * time.Minute)
	if err := apply(t, s, hb); err == nil {
		t.Fatal("an expired list was accepted")
	}
	if _, err := s.Check("s_a", false); CodeOf(err) != CodeStale {
		t.Fatalf("expired list delivered: %v", err)
	}
	apply(t, s, signS(t, opList(2, *f.now.Load()), f.operator))
	if _, err := s.Check("s_a", false); err != nil {
		t.Fatalf("a fresh list again: %v", err)
	}
	if st := s.StatusOf("s_a"); !st.Fresh || st.Blocked {
		t.Fatalf("fresh status: %+v", st)
	}
	// Delivered every few seconds but signed long ago (someone replays an old list and drops new ones): stale
	// once it is older than the max age, reads included.
	old := signS(t, opList(3, *f.now.Load()), f.operator)
	apply(t, s, old)
	for range 66 {
		f.advance(10 * time.Second)
		apply(t, s, old)
	}
	if _, err := s.Check("s_a", false); CodeOf(err) != CodeStale {
		t.Fatalf("an old list replayed: %v", err)
	}
}

// A list loaded from the process's own disk after a restart isn't a delivery: the process isn't heard from until
// the pull (or a push) reaches it.
func TestRestartNotHeardUntilDelivered(t *testing.T) {
	f := newFixture(t)
	cfg := func() Config {
		return Config{Firm: "f_test", Operator: pub(f.operator), Admins: []ed25519.PublicKey{pub(f.admin)},
			Release: release(), Dir: f.dir, MaxSilence: DefaultMaxSilence, Now: func() time.Time { return *f.now.Load() }}
	}
	s, _ := NewState(cfg())
	apply(t, s, signP(t, policy(1, ""), f.admin))
	hb := signS(t, opList(1, t0), f.operator)
	apply(t, s, hb)
	s2, err := NewState(cfg())
	if err != nil {
		t.Fatal(err)
	}
	if s2.Heard() {
		t.Fatal("heard from the disk")
	}
	if _, err := s2.Check("s_a", false); CodeOf(err) != CodeStale {
		t.Fatalf("before a delivery: %v", err)
	}
	apply(t, s2, hb) // the held list, delivered again
	if _, err := s2.Check("s_a", false); err != nil || !s2.Heard() {
		t.Fatalf("after a delivery: %v", err)
	}
}

// gatewayd and vaultd don't check silence (MaxSilence 0: they get the list from agentd, not the pull); they
// still stop reads once the list is stale.
func TestNoSilenceCheckStillStale(t *testing.T) {
	f := newFixture(t)
	s := f.state(t)
	apply(t, s, signP(t, policy(1, ""), f.admin))
	apply(t, s, signS(t, opList(1, t0), f.operator))
	f.advance(9 * time.Minute)
	if _, err := s.Check("s_a", false); err != nil {
		t.Fatalf("not checked for silence: %v", err)
	}
	f.advance(2 * time.Minute)
	if _, err := s.Check("s_a", false); CodeOf(err) != CodeStale {
		t.Fatalf("stale: %v", err)
	}
}

// An operator seq far ahead of its signing time would lock the floor: refused. The Worker's seq (now in ms, or one
// more than the last) passes.
func TestOperatorSeqAheadRefused(t *testing.T) {
	f := newFixture(t)
	s := f.state(t)
	far := opList(uint64(t0.Add(time.Hour).UnixMilli()), t0)
	if err := apply(t, s, signS(t, far, f.operator)); err == nil || !strings.Contains(err.Error(), "ahead") {
		t.Fatalf("seq an hour ahead: %v", err)
	}
	huge := opList(1<<62, t0)
	if err := apply(t, s, signS(t, huge, f.operator)); err == nil {
		t.Fatal("a huge seq was accepted")
	}
	ok := opList(uint64(t0.UnixMilli())+3, t0)
	if err := apply(t, s, signS(t, ok, f.operator)); err != nil {
		t.Fatalf("the Worker's seq: %v", err)
	}
	if _, err := Heartbeat(f.operator, 0, t0, 15*time.Minute, false); err != nil {
		t.Fatalf("Heartbeat: %v", err)
	}
}

func TestNoKeysMeansReleaseDefault(t *testing.T) {
	s, err := NewState(Config{Firm: "f_test", Release: release()})
	if err != nil {
		t.Fatal(err)
	}
	e, err := s.Check("s_chat", false)
	if err != nil || len(e.Hashes) != 0 || !e.AllowsTool("web.images") {
		t.Fatalf("release default: %v %v", e, err)
	}
	if _, err := s.Check("s_chat", true); CodeOf(err) != CodeStale {
		t.Fatal("without an operator key, side effects must fail closed")
	}
	k := key(t)
	if errs, _ := s.Apply([]Envelope{signP(t, policy(1, ""), k)}); errs[0] == nil {
		t.Fatal("a policy was accepted with no admin keys pinned")
	}
}

// A VM that ran a release with admin keys and then one without them (a rollback to stage 1) runs on the release
// policy: the old floors stay on disk, but without keys no policy could ever arrive to satisfy them. Keys
// rotated to others still fail closed until a policy they signed arrives.
func TestFloorsWithoutKeys(t *testing.T) {
	f := newFixture(t)
	s := f.state(t)
	if err := apply(t, s, signP(t, policy(3, ""), f.admin)); err != nil {
		t.Fatal(err)
	}
	cfg := func(admins ...ed25519.PublicKey) Config {
		return Config{Firm: "f_test", Admins: admins, Release: release(), Dir: f.dir, Now: func() time.Time { return *f.now.Load() }}
	}
	none, err := NewState(cfg())
	if err != nil {
		t.Fatal(err)
	}
	if e, err := none.Check("s_x", false); err != nil || len(e.Hashes) != 0 {
		t.Fatalf("no keys pinned: want the release policy alone, got %v %v", e, err)
	}
	rotated, err := NewState(cfg(pub(key(t))))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rotated.Check("s_x", false); CodeOf(err) != CodePolicyMissing {
		t.Fatalf("rotated keys: want policy_missing, got %v", err)
	}
	// Back with the original key: the floor still refuses the older version.
	back := f.state(t)
	if err := apply(t, back, signP(t, policy(2, ""), f.admin)); err == nil {
		t.Fatal("v2 accepted after v3, across a keyless release")
	}
}

func TestThreshold(t *testing.T) {
	a, b := key(t), key(t)
	s, _ := NewState(Config{Firm: "f_test", Admins: []ed25519.PublicKey{pub(a), pub(b)}, Threshold: 2, Release: release(),
		Now: func() time.Time { return t0 }})
	if errs, _ := s.Apply([]Envelope{signP(t, policy(1, ""), a, a)}); errs[0] == nil {
		t.Fatal("one key signing twice counted as two")
	}
	if errs, _ := s.Apply([]Envelope{signP(t, policy(1, ""), a, b)}); errs[0] != nil {
		t.Fatal(errs[0])
	}
}

func TestBudgetParallelEvasion(t *testing.T) {
	l := &Ledger{}
	b := Budgets{Run: Limits{ToolCalls: 5, Tokens: 10_000}, Day: Limits{ToolCalls: 7}}
	if _, err := l.Start("t1", "s_a", "m1", b); err != nil {
		t.Fatal(err)
	}
	var ok atomic.Int32
	var wg sync.WaitGroup
	for range 50 { // a brain sending many actions at once
		wg.Add(1)
		go func() {
			defer wg.Done()
			commit, err := l.Reserve("t1", Usage{ToolCalls: 1}, b)
			if err == nil {
				ok.Add(1)
				time.Sleep(time.Millisecond)
				commit(Usage{ToolCalls: 1})
			} else if CodeOf(err) != CodeBudgetExceeded {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if ok.Load() != 5 {
		t.Fatalf("%d tool calls ran in parallel, budget 5", ok.Load())
	}
	// The day budget spans runs: a second run gets the 2 left.
	l.Start("t2", "s_a", "m1", b)
	n := 0
	for range 5 {
		if c, err := l.Reserve("t2", Usage{ToolCalls: 1}, b); err == nil {
			c(Usage{ToolCalls: 1})
			n++
		}
	}
	if n != 2 {
		t.Fatalf("second run got %d, want 2 (day budget 7)", n)
	}
	l.End("t1")
	l.End("t2")
	l.Start("t3", "s_a", "m1", b)
	if _, err := l.Reserve("t3", Usage{ToolCalls: 1}, b); CodeOf(err) != CodeBudgetExceeded {
		t.Fatalf("the day's tool calls are used up: %v", err)
	}
	// Reservations count while they run: two model calls that each fit alone don't both start.
	l2 := &Ledger{}
	l2.Start("t", "s", "m1", b)
	c1, err := l2.Reserve("t", Usage{Tokens: 6000}, b)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := l2.Reserve("t", Usage{Tokens: 6000}, b); CodeOf(err) != CodeBudgetExceeded {
		t.Fatal("the second reservation must be refused while the first runs")
	}
	c1(Usage{Tokens: 100})
	if _, err := l2.Reserve("t", Usage{Tokens: 6000}, b); err != nil {
		t.Fatal("after the first used only 100 tokens, there's room")
	}
	if _, err := l2.Reserve("nope", Usage{ToolCalls: 1}, b); err == nil {
		t.Fatal("an unknown run got budget")
	}
}

func TestBudgetWallAndPersist(t *testing.T) {
	now := t0
	dir := t.TempDir()
	l := &Ledger{Dir: dir, Now: func() time.Time { return now }}
	b := Budgets{Run: Limits{WallSeconds: 60}, Day: Limits{WallSeconds: 100, Tokens: 1000}}
	end, err := l.Start("t1", "s_a", "m1", b)
	if err != nil || !end.Equal(t0.Add(100*time.Second)) { // the day's: the run's own isn't a fixed end (v0.8.1)
		t.Fatalf("deadline %v %v", end, err)
	}
	c, _ := l.Reserve("t1", Usage{Tokens: 10}, b)
	c(Usage{Tokens: 900})
	now = now.Add(61 * time.Second)
	if _, err := l.Reserve("t1", Usage{Tokens: 1}, b); CodeOf(err) != CodeBudgetExceeded {
		t.Fatal("past the run's running time")
	}
	l.End("t1")
	// Restarted: the day's tokens and time are still counted.
	l2 := &Ledger{Dir: dir, Now: func() time.Time { return now }}
	end, err = l2.Start("t2", "s_a", "m1", b)
	if err != nil || !end.Equal(now.Add(39*time.Second)) {
		t.Fatalf("second run: deadline %v (want 39 s left of the day), %v", end, err)
	}
	if _, err := l2.Reserve("t2", Usage{Tokens: 101}, b); CodeOf(err) != CodeBudgetExceeded {
		t.Fatal("the day's tokens were forgotten")
	}
	c2, _ := l2.Reserve("t2", Usage{Tokens: 100}, b)
	c2(Usage{Tokens: 100})
	if _, err := l2.Start("t3", "s_a", "m1", b); CodeOf(err) != CodeBudgetExceeded {
		t.Fatalf("a new run must be refused once the day's tokens are used up: %v", err)
	}
	if ModelCost("gpt-oss-120b", 1_000_000, 1_000_000) != 750_000 || ModelCost("unknown", 1, 0) != 4 {
		t.Error("cost")
	}
}

// v0.8.1: time a run only waits for its person (a prompt open, nothing in flight) isn't running time, for the
// run's budget or the day's; time with a request in flight is, prompt or not; a pause the ledger can't place
// (an unknown run, an Unpause too many) changes nothing.
func TestBudgetWaitingForThePerson(t *testing.T) {
	now := t0
	l := &Ledger{Now: func() time.Time { return now }}
	b := Budgets{Run: Limits{WallSeconds: 60}, Day: Limits{WallSeconds: 1000}}
	if _, err := l.Start("t1", "s_a", "m1", b); err != nil {
		t.Fatal(err)
	}
	el := func(want time.Duration) {
		t.Helper()
		if got, _ := l.Elapsed("t1"); got != want {
			t.Fatalf("running time %v, want %v", got, want)
		}
	}
	now = now.Add(10 * time.Second) // working
	el(10 * time.Second)
	l.Pause("t1")
	now = now.Add(9 * time.Minute) // a long prompt: the clock stops
	el(10 * time.Second)
	// Nine minutes in, 50 s of the 60 left: a request fits, and while it is in flight (the prompt still open) the
	// clock runs.
	c, err := l.Reserve("t1", Usage{Tokens: 1}, b)
	if err != nil {
		t.Fatalf("a request after a long wait: %v", err)
	}
	now = now.Add(20 * time.Second)
	el(30 * time.Second)
	c(Usage{Tokens: 1}) // back to waiting only
	now = now.Add(time.Minute)
	el(30 * time.Second)
	l.Unpause("t1")
	l.Unpause("t1") // one too many: no effect
	now = now.Add(30 * time.Second)
	el(60 * time.Second)
	if _, err := l.Reserve("t1", Usage{Tokens: 1}, b); CodeOf(err) != CodeBudgetExceeded {
		t.Fatal("past 60 s of running time")
	}
	// Two prompts at once: the clock stops until both are closed.
	l.Pause("t1")
	l.Pause("t1")
	now = now.Add(time.Minute)
	l.Unpause("t1")
	now = now.Add(time.Minute)
	el(60 * time.Second)
	l.Unpause("t1")
	now = now.Add(5 * time.Second)
	el(65 * time.Second)
	l.Pause("nope") // unknown run: ignored
	l.End("t1")     // the day counts running time only
	if got := l.day("s_a").Used.WallMs; got != 65_000 {
		t.Fatalf("the day counted %d ms, want 65000", got)
	}
}

func TestRate(t *testing.T) {
	now := t0
	l := &Limiter{Now: func() time.Time { return now }}
	r := []Rate{{60, 3}, {600, 100}}
	keys := []string{"key:A", "space:s"}
	n := 0
	for range 10 {
		if l.Allow(keys, r) == "" {
			n++
		}
	}
	if n != 3 {
		t.Fatalf("burst: %d", n)
	}
	now = now.Add(time.Second)
	if l.Allow(keys, r) != "" {
		t.Fatal("one token per second at 60/min")
	}
	if l.Allow(keys, r) != "key:A" {
		t.Fatal("refill")
	}
	// All or none: a refusal by the first key doesn't take from the second.
	l2 := &Limiter{Now: func() time.Time { return now }}
	for range 5 {
		l2.Allow([]string{"a", "b"}, []Rate{{1, 1}, {1, 3}})
	}
	if l2.Allow([]string{"b"}, []Rate{{1, 3}}) != "" {
		t.Fatal("b lost tokens to refused requests")
	}
}

func TestDecodeEnvelopes(t *testing.T) {
	k := key(t)
	e := signP(t, policy(1, ""), k)
	one, _ := json.Marshal(e)
	two, _ := json.Marshal([]Envelope{e, e})
	for _, b := range [][]byte{one, two} {
		if _, err := DecodeEnvelopes(b); err != nil {
			t.Fatal(err)
		}
	}
	for _, bad := range []string{``, `{}x`, `{"kind":"policy","payload":"eA==","sigs":[],"extra":1}`, `[` + strings.Repeat(string(one)+",", 8) + string(one) + `]`} {
		if _, err := DecodeEnvelopes([]byte(bad)); err == nil {
			t.Errorf("accepted %.40q", bad)
		}
	}
}

// Permission prompts: a firm caps people's permission settings per kind; layers only narrow, and a bad cap is refused.
func TestPermissionCap(t *testing.T) {
	f := newFixture(t)
	s := f.state(t)
	firm := policy(1, "")
	firm.AskCap = map[string]string{"web.search": PermAsk, "web.images": PermAlways}
	space := policy(1, "s_a")
	space.AskCap = map[string]string{"web.fetch": PermNever, "web.search": PermAlways /* looser: the firm's ask holds */}
	for _, e := range []Envelope{signP(t, firm, f.admin), signP(t, space, f.admin)} {
		if err := apply(t, s, e); err != nil {
			t.Fatal(err)
		}
	}
	e, err := s.Policy("s_a")
	if err != nil {
		t.Fatal(err)
	}
	for kind, want := range map[string]string{"web.search": PermAsk, "web.fetch": PermNever, "web.images": PermAlways, "mail.list": PermAlways} {
		if got := e.PermissionCap(kind); got != want {
			t.Errorf("cap %s = %s, want %s", kind, got, want)
		}
	}
	for _, c := range []struct{ a, b, want string }{{"", "", PermAlways}, {PermAlways, PermAsk, PermAsk}, {PermNever, PermAsk, PermNever}, {PermAsk, "", PermAsk}} {
		if got := NarrowerPermission(c.a, c.b); got != c.want {
			t.Errorf("NarrowerPermission(%q, %q) = %q, want %q", c.a, c.b, got, c.want)
		}
	}
	bad := policy(2, "")
	bad.AskCap = map[string]string{"web.search": "sometimes"}
	if bad.Validate() == nil {
		t.Error("a bad ask_cap value was accepted")
	}
	bad.AskCap = map[string]string{"Web Search": PermAsk}
	if bad.Validate() == nil {
		t.Error("a bad ask_cap kind was accepted")
	}
}

// Keys v2 slice 6: the member's and the VM's day budgets (docs/26 section 7). A member's runs count together in
// every space, so a new space gets no new budget; parallel runs of one member in many spaces can't each see room
// only one has; one member using up their day leaves the others theirs, until the VM's day is used up for all.
func TestBudgetPerMemberAndVM(t *testing.T) {
	now := t0
	dir := t.TempDir()
	l := &Ledger{Dir: dir, Now: func() time.Time { return now }}
	b := Budgets{Run: Limits{ToolCalls: 100}, Day: Limits{ToolCalls: 100}, Member: Limits{ToolCalls: 10}, VM: Limits{ToolCalls: 25}}
	// m1 runs in 20 spaces at once (each a fresh s_ id), every run sending 5 tool calls in parallel.
	var ok atomic.Int32
	var wg sync.WaitGroup
	for i := range 20 {
		task, space := fmt.Sprintf("a%d", i), fmt.Sprintf("s_m1space%d", i)
		if _, err := l.Start(task, space, "m1", b); err != nil {
			t.Fatal(err)
		}
		for range 5 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				commit, err := l.Reserve(task, Usage{ToolCalls: 1}, b)
				if err == nil {
					ok.Add(1)
					commit(Usage{ToolCalls: 1})
				} else if CodeOf(err) != CodeBudgetExceeded || !strings.Contains(err.Error(), "member's daily") {
					t.Error(err)
				}
			}()
		}
	}
	wg.Wait()
	if ok.Load() != 10 {
		t.Fatalf("member m1 ran %d tool calls across new spaces, budget 10", ok.Load())
	}
	// Another new space: its tool calls are refused too (used-up tool calls refuse tool calls, not the run).
	refused := func(l *Ledger, task, space, member, why string) {
		t.Helper()
		if _, err := l.Start(task, space, member, b); err != nil {
			t.Fatal(err)
		}
		if _, err := l.Reserve(task, Usage{ToolCalls: 1}, b); CodeOf(err) != CodeBudgetExceeded || !strings.Contains(err.Error(), why) {
			t.Fatalf("%s in %s: %v, want the %s budget", member, space, err, why)
		}
	}
	refused(l, "a-new", "s_m1another", "m1", "member's daily")
	// Others still have theirs, until the VM's day (25) is used up for everyone.
	n := 0
	for i, m := range []string{"m2", "m3"} {
		task := fmt.Sprintf("b%d", i)
		if _, err := l.Start(task, "s_shared", m, b); err != nil {
			t.Fatal(err)
		}
		for range 10 {
			if c, err := l.Reserve(task, Usage{ToolCalls: 1}, b); err == nil {
				c(Usage{ToolCalls: 1})
				n++
			} else if !strings.Contains(err.Error(), "agent VM's daily") {
				t.Fatalf("m%d: %v", i+2, err)
			}
		}
	}
	if n != 15 {
		t.Fatalf("m2 and m3 got %d, want 15 (VM day 25, m1 used 10)", n)
	}
	refused(l, "c", "s_new", "m4", "agent VM's daily")
	// Counters persist on disk (ids and counts only) and a new day starts over.
	l2 := &Ledger{Dir: dir, Now: func() time.Time { return now }}
	refused(l2, "d", "s_x", "m1", "member's daily")
	now = now.Add(24 * time.Hour)
	l2.Start("e", "s_x", "m1", b)
	if _, err := l2.Reserve("e", Usage{ToolCalls: 1}, b); err != nil {
		t.Fatalf("next day: %v", err)
	}
	// Model tokens used up: a member's new run is refused at the door, in any space.
	bt := Budgets{Member: Limits{Tokens: 100}}
	l2.Start("f", "s_a", "m5", bt)
	c, _ := l2.Reserve("f", Usage{Tokens: 100}, bt)
	c(Usage{Tokens: 100})
	if _, err := l2.Admit("s_brand_new", "m5", bt); CodeOf(err) != CodeBudgetExceeded || !strings.Contains(err.Error(), "member's daily budget for model tokens") {
		t.Fatalf("a new space must get no new budget: %v", err)
	}
	// Running time: the member's day counts runs in every space.
	l3 := &Ledger{Now: func() time.Time { return now }}
	bw := Budgets{Member: Limits{WallSeconds: 100}}
	l3.Start("w1", "s_one", "m1", bw)
	l3.Start("w2", "s_two", "m1", bw)
	now = now.Add(60 * time.Second)
	if _, err := l3.Admit("s_three", "m1", bw); CodeOf(err) != CodeBudgetExceeded {
		t.Fatalf("two runs of 60 s each passed the member's 100 s: %v", err)
	}
	if end, err := l3.Admit("s_three", "m2", bw); err != nil || !end.Equal(now.Add(100*time.Second)) {
		t.Fatalf("another member: %v %v", end, err)
	}
}

// Keys v2 slice 6: a space's policy may name its seal key (a firm policy may not); the member's and the VM's day
// budgets narrow across layers like the others, and raising or removing one widens.
func TestPolicySealAndNewBudgets(t *testing.T) {
	seal := "x25519:" + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
	sp := policy(1, "s_a")
	sp.Seal = seal
	if err := sp.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"x25519:AAAA", "x25519:" + base64.StdEncoding.EncodeToString(make([]byte, 32)), strings.TrimSuffix(seal, "="), "ed25519:" + seal[7:]} {
		p := policy(1, "s_a")
		p.Seal = bad
		if p.Validate() == nil {
			t.Errorf("seal %q accepted", bad)
		}
	}
	fp := policy(1, "")
	fp.Seal = seal
	if fp.Validate() == nil {
		t.Error("a firm policy named a seal key")
	}
	firm := policy(1, "")
	firm.Budget.Member, firm.Budget.VM = Limits{Tokens: 1000, ToolCalls: 5}, Limits{CostMicros: 900}
	space := policy(1, "s_a")
	space.Seal = seal
	space.Budget.Member = Limits{Tokens: 400}
	e := &Effective{Layers: []*Policy{ChatRelease("f_test", "", []string{"gpt-oss-120b"}, 300), firm, space}}
	b := e.Budget()
	if b.Member != (Limits{Tokens: 400, ToolCalls: 5, WallSeconds: 6 * 3600, CostMicros: 50_000_000}) || b.VM.CostMicros != 900 || b.VM.Tokens != 200_000_000 {
		t.Fatalf("narrowed: member %+v vm %+v", b.Member, b.VM)
	}
	if e.Seal() != seal || (&Effective{Layers: []*Policy{firm}}).Seal() != "" {
		t.Error("Effective.Seal")
	}
	up := *firm
	up.Budget.Member = Limits{Tokens: 2000, ToolCalls: 5}
	if !Widens(firm, &up) {
		t.Error("a raised member budget doesn't widen")
	}
	up.Budget.Member, up.Budget.VM = firm.Budget.Member, Limits{}
	if !Widens(firm, &up) {
		t.Error("a removed VM budget doesn't widen")
	}
	up.Budget.VM = Limits{CostMicros: 800}
	if Widens(firm, &up) {
		t.Error("a lowered VM budget widens")
	}
}
