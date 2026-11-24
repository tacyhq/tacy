package unlock_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tacyhq/tacy/gateway"
	"github.com/tacyhq/tacy/kms"
	"github.com/tacyhq/tacy/kms/split"
	"github.com/tacyhq/tacy/proto"
	"github.com/tacyhq/tacy/unlock"
	"github.com/tacyhq/tacy/unlock/unlocktest"
)

// rig is unlockd's world: the split key's holders (real, kms/split/holder, on the recorded 0.6.5 quote), the chat
// Worker's twin, gatewayd's fixed calls (unlock target, holder URLs from the Worker's newest policy) over in-process
// routes, and the host tmpfs as a test directory.
type rig struct {
	t      *testing.T
	w      *unlocktest.World
	worker *unlocktest.Worker
	routes *unlocktest.Routes
	fixed  *gateway.Fixed
	cache  *unlock.Cache
	boot   string
}

func newRig(t *testing.T, ids []string, threshold int) *rig {
	w := unlocktest.New(t, ids, threshold)
	r := &rig{t: t, w: w, routes: &unlocktest.Routes{}, boot: "boot-1"}
	r.worker = unlocktest.NewWorker(w.IDPub, w.Now)
	r.worker.SetPolicy(w.PolicyEnv())
	r.worker.SetSecrets(w.SecretsBundle(3))
	r.fixed = w.Gateway(r.routes, r.worker)
	dir := t.TempDir()
	r.cache = &unlock.Cache{Dir: dir, IsMemory: func(string) (bool, error) { return true, nil },
		BootID: func() (string, error) { return r.boot, nil }}
	return r
}

func (r *rig) config() unlock.Config {
	return unlock.Config{KMSID: r.w.IDPub, Admin: &kms.AdminKeys{Keys: []ed25519.PublicKey{r.w.AdminPub}, Threshold: 1}, MinEpoch: 1,
		Fixed:    gateway.FixedGate{D: r.fixed, Allow: gateway.UnlockCalls},
		Evidence: r.w.VM.Evidence, Release: unlocktest.Release, Cache: r.cache, Timeout: 5 * time.Second,
		MinBackoff: 20 * time.Millisecond, MaxBackoff: 40 * time.Millisecond, SecretsWait: 100 * time.Millisecond, Relock: 30 * time.Millisecond, Now: r.w.Now, Logf: r.t.Logf}
}

func (r *rig) unlocker(edit func(*unlock.Config)) *unlock.Unlocker {
	cfg := r.config()
	if edit != nil {
		edit(&cfg)
	}
	u, err := unlock.New(cfg)
	if err != nil {
		r.t.Fatal(err)
	}
	return u
}

// run runs u until it is ready or d passes, and returns its last status.
func (r *rig) run(u *unlock.Unlocker, d time.Duration) unlock.Status {
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	done := make(chan struct{})
	go func() { u.Run(ctx); close(done) }()
	select {
	case <-u.Ready():
	case <-ctx.Done():
	}
	cancel()
	<-done
	return u.Status()
}

func (r *rig) mustKeys(u *unlock.Unlocker, role string) *unlock.Keys {
	r.t.Helper()
	k, st, err := u.Keys(role)
	if err != nil {
		r.t.Fatalf("%s keys: %v (%+v)", role, err, st)
	}
	return k
}

// noLeak: nothing of M, a share, the KMS id's seed, the secrets key or a secret in text.
func (r *rig) noLeak(what string, text []byte) {
	r.t.Helper()
	for _, s := range r.w.Forbidden() {
		if len(s) >= 8 && bytes.Contains(text, []byte(s)) {
			r.t.Fatalf("%s carries key material or a secret", what)
		}
	}
}

func (r *rig) holderUnlocks(h string) int {
	n := 0
	for _, e := range r.w.HolderEvents() {
		if e.Holder == h && e.Kind == "unlock" {
			n++
		}
	}
	return n
}

// A boot: the newest policy from the Worker, 2-of-2 holders, the keys M derives, store certificates the KMS id
// signed, the API keys from secrets.sealed, a signed report; agentd and vaultd each get only their own.
func TestUnlockBoot(t *testing.T) {
	r := newRig(t, []string{"cloudflare", "vercel"}, 2)
	u := r.unlocker(nil)
	if st := r.run(u, 30*time.Second); st.State != unlock.StateReady || st.Cached {
		t.Fatalf("status %+v", st)
	}
	a, v := r.mustKeys(u, unlock.RoleAgent), r.mustKeys(u, unlock.RoleVault)
	for _, p := range []string{"state/v1", "activity-sign/v1", "task-ids/v1"} {
		if !bytes.Equal(a.Keys[p], r.w.Key(p)) {
			t.Fatalf("agentd's %s isn't the one M derives", p)
		}
	}
	if _, ok := a.Keys["conn/v1"]; ok || len(a.Secrets) > 0 {
		t.Fatal("agentd got conn/v1 or an API key")
	}
	if !bytes.Equal(v.Keys["conn/v1"], r.w.Key("conn/v1")) || len(v.Keys) != 1 || v.Secrets["EXA_API_KEY"] != r.w.Secrets["EXA_API_KEY"] {
		t.Fatalf("vaultd's: %d keys, secrets %d", len(v.Keys), len(v.Secrets))
	}
	for p, k := range map[string]*unlock.Keys{"state/v1": a, "conn/v1": v} {
		c := k.Certs[p]
		if !ed25519.Verify(r.w.IDPub, kms.StoreCertMessage(c), c.Sig) || c.App != unlocktest.App || c.Purpose != p {
			t.Fatalf("%s's store certificate isn't the KMS id's", p)
		}
	}
	rs := r.worker.Reports()
	if len(rs) == 0 {
		t.Fatal("no unlock report")
	}
	last := rs[len(rs)-1]
	var rep unlock.Report
	json.Unmarshal(last.Doc, &rep)
	// Signed by the state/v1 store-auth key, whose certificate the KMS id signed (the epoch certificate's).
	signed := last.Cert != nil && ed25519.Verify(r.w.IDPub, kms.StoreCertMessage(*last.Cert), last.Cert.Sig)
	if signed {
		pub, err := kms.ParseID(last.Cert.Key)
		signed = err == nil && ed25519.Verify(pub, append(append([]byte(unlock.ReportLabel), 0), last.Doc...), last.Sig)
	}
	if rep.State != unlock.StateReady || !signed {
		t.Fatalf("report %+v not ready or not signed under the KMS id's certificate", rep)
	}
	for _, s := range rs {
		b, _ := json.Marshal(s)
		r.noLeak("a report", b)
	}
	st, _ := json.Marshal(u.Status())
	r.noLeak("the status", st)
}

// The watchdog restarts the container: the keys come back from the host tmpfs, no holder is asked. A real boot (a
// new boot id) unlocks again from the holders.
func TestRestartUsesTheCacheBootUnlocks(t *testing.T) {
	r := newRig(t, []string{"cloudflare", "vercel"}, 2)
	r.run(r.unlocker(nil), 30*time.Second)
	before := r.holderUnlocks("cloudflare")
	if before == 0 {
		t.Fatal("no unlock at the holders")
	}
	if _, err := os.Stat(filepath.Join(r.cache.Dir, "keyring.json")); err != nil {
		t.Fatalf("keyring not kept: %v", err)
	}
	u2 := r.unlocker(nil)
	if st := r.run(u2, 10*time.Second); st.State != unlock.StateReady || !st.Cached {
		t.Fatalf("after a container restart: %+v", st)
	}
	if r.holderUnlocks("cloudflare") != before {
		t.Fatal("a container restart asked the holders")
	}
	if a := r.mustKeys(u2, unlock.RoleAgent); !bytes.Equal(a.Keys["state/v1"], r.w.Key("state/v1")) {
		t.Fatal("cached keys differ")
	}
	if v := r.mustKeys(u2, unlock.RoleVault); v.Secrets["TINFOIL_API_KEY"] == "" {
		t.Fatal("cached keyring lost the API keys")
	}
	r.boot = "boot-2"
	u3 := r.unlocker(nil)
	if st := r.run(u3, 30*time.Second); st.State != unlock.StateReady || st.Cached {
		t.Fatalf("after a reboot: %+v", st)
	}
	if r.holderUnlocks("cloudflare") != before+1 {
		t.Fatal("a reboot didn't unlock from the holders")
	}
	// A cache directory that isn't memory is never written or read.
	r.boot = "boot-3"
	disk := &unlock.Cache{Dir: t.TempDir(), IsMemory: func(string) (bool, error) { return false, nil }, BootID: r.cache.BootID}
	r.run(r.unlocker(func(c *unlock.Config) { c.Cache = disk }), 30*time.Second)
	if fs, _ := os.ReadDir(disk.Dir); len(fs) != 0 {
		t.Fatal("keys written to a directory that isn't tmpfs")
	}
}

// A container restart is usually every container at once, gatewayd too: the cached start's ready report is tried
// again until the Worker takes it (the split-key throwaway's restart lost it: one try, no gatewayd yet).
func TestCachedStartReportsWhenGatewaydIsBack(t *testing.T) {
	r := newRig(t, []string{"cloudflare", "vercel"}, 2)
	r.run(r.unlocker(nil), 30*time.Second)
	n := len(r.worker.Reports())
	var mu sync.Mutex
	down := 3 // gatewayd's socket isn't there for the first three tries
	r.fixed = r.w.Gateway(r.routes, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		mu.Lock()
		fail := req.URL.Path == gateway.UnlockReportPath && down > 0
		if fail {
			down--
		}
		mu.Unlock()
		if fail {
			http.Error(w, "no gatewayd", http.StatusBadGateway)
			return
		}
		r.worker.ServeHTTP(w, req)
	}))
	u2 := r.unlocker(nil)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	go u2.Run(ctx)
	<-u2.Ready()
	for ctx.Err() == nil && len(r.worker.Reports()) == n {
		time.Sleep(10 * time.Millisecond)
	}
	rs := r.worker.Reports()
	if len(rs) != n+1 {
		t.Fatalf("the cached start's report never reached the Worker (%d reports, want %d)", len(rs), n+1)
	}
	var rep unlock.Report
	if json.Unmarshal(rs[len(rs)-1].Doc, &rep) != nil || rep.State != unlock.StateReady || !rep.Cached || rs[len(rs)-1].Sig == nil {
		t.Fatalf("report %+v", rep)
	}
}

// 2-of-2 with a holder down: "holder_down", retried; it unlocks once the holder is back. 2-of-3 with one down: no
// effect.
func TestHolderDown(t *testing.T) {
	r := newRig(t, []string{"cloudflare", "vercel"}, 2)
	r.routes.Set(unlocktest.HolderHost("vercel"), nil)
	u := r.unlocker(func(c *unlock.Config) { c.Cache = nil })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go u.Run(ctx)
	deadline := time.Now().Add(20 * time.Second)
	for u.Status().State != unlock.StateHolderDown || u.Status().Tries < 2 {
		if time.Now().After(deadline) {
			t.Fatalf("status %+v", u.Status())
		}
		time.Sleep(5 * time.Millisecond)
	}
	if _, _, err := u.Keys(unlock.RoleAgent); err == nil {
		t.Fatal("keys while a holder is down")
	}
	if !strings.Contains(unlock.Message(u.Status().State), "key holder is down") {
		t.Fatal("no message for people")
	}
	var down unlock.Report
	for _, s := range r.worker.Reports() {
		json.Unmarshal(s.Doc, &down)
		if down.State == unlock.StateHolderDown && down.Holders["vercel"] != "" {
			break
		}
	}
	if down.State != unlock.StateHolderDown {
		t.Fatal("the Worker wasn't told a holder is down")
	}
	r.routes.Set(unlocktest.HolderHost("vercel"), r.w.Handler("vercel"))
	select {
	case <-u.Ready():
	case <-time.After(20 * time.Second):
		t.Fatalf("no unlock after the holder came back: %+v", u.Status())
	}

	r3 := newRig(t, []string{"cloudflare", "gcp", "vercel"}, 2)
	r3.routes.Set(unlocktest.HolderHost("gcp"), nil)
	if st := r3.run(r3.unlocker(nil), 30*time.Second); st.State != unlock.StateReady {
		t.Fatalf("2-of-3 with one down: %+v", st)
	}
}

// lying wraps a holder: its sealed share is changed in the reply.
func lying(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path != "/v1/unlock" {
			next.ServeHTTP(w, req)
			return
		}
		rec := &recorder{h: http.Header{}}
		next.ServeHTTP(rec, req)
		var rep split.UnlockReply
		if json.Unmarshal(rec.b.Bytes(), &rep) == nil && len(rep.Sealed.CT) > 0 {
			rep.Sealed.CT[0] ^= 1
		}
		json.NewEncoder(w).Encode(rep)
	})
}

type recorder struct {
	h    http.Header
	b    bytes.Buffer
	code int
}

func (r *recorder) Header() http.Header         { return r.h }
func (r *recorder) Write(b []byte) (int, error) { return r.b.Write(b) }
func (r *recorder) WriteHeader(c int)           { r.code = c }

// A lying holder: its share doesn't open (or doesn't match its commitment). 2-of-3: unlocked by the other two;
// 2-of-2: refused, nothing derived.
func TestLyingHolder(t *testing.T) {
	r := newRig(t, []string{"cloudflare", "gcp", "vercel"}, 2)
	r.routes.Set(unlocktest.HolderHost("gcp"), lying(r.w.Handler("gcp")))
	u := r.unlocker(nil)
	if st := r.run(u, 30*time.Second); st.State != unlock.StateReady || st.Holders["gcp"] == "ok" {
		t.Fatalf("2-of-3 with a liar: %+v", st)
	}
	r2 := newRig(t, []string{"cloudflare", "vercel"}, 2)
	r2.routes.Set(unlocktest.HolderHost("vercel"), lying(r2.w.Handler("vercel")))
	u2 := r2.unlocker(func(c *unlock.Config) { c.Cache = nil })
	if st := r2.run(u2, 300*time.Millisecond); st.State != unlock.StateRefused {
		t.Fatalf("2-of-2 with a liar: %+v", st)
	}
	if _, _, err := u2.Keys(unlock.RoleAgent); err == nil {
		t.Fatal("keys from a lying holder")
	}
}

// A release the policy doesn't pin: refused before any holder is asked (and every holder refuses it anyway).
func TestWrongRelease(t *testing.T) {
	r := newRig(t, []string{"cloudflare", "vercel"}, 2)
	r.w.Policy.Releases[0].AppComposeSHA256 = strings.Repeat("0", 64)
	r.worker.SetPolicy(r.w.PolicyEnv())
	u := r.unlocker(func(c *unlock.Config) { c.Cache = nil })
	if st := r.run(u, 300*time.Millisecond); st.State != unlock.StateRefused || !strings.Contains(st.Reason, "isn't a release") {
		t.Fatalf("status %+v", st)
	}
	if r.routes.Calls(unlocktest.HolderHost("cloudflare")) != 0 {
		t.Fatal("a holder was asked for an unpinned release")
	}
	// A VM claiming another release than the one pinned for its app-compose.
	r2 := newRig(t, []string{"cloudflare", "vercel"}, 2)
	u2 := r2.unlocker(func(c *unlock.Config) { c.Cache, c.Release = nil, "v9.9.9" })
	if st := r2.run(u2, 300*time.Millisecond); st.State != unlock.StateRefused {
		t.Fatalf("wrong release claim: %+v", st)
	}
}

// Replays: an unlock request seen in transit is refused when sent again (its nonces are used), and an old
// holder reply handed to a new boot doesn't open with that boot's key.
func TestReplay(t *testing.T) {
	r := newRig(t, []string{"cloudflare", "vercel"}, 2)
	var mu sync.Mutex
	var lastReq, lastRep []byte
	tap := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			if req.URL.Path != "/v1/unlock" {
				next.ServeHTTP(w, req)
				return
			}
			b, _ := io.ReadAll(req.Body)
			req.Body = io.NopCloser(bytes.NewReader(b))
			rec := &recorder{h: http.Header{}}
			next.ServeHTTP(rec, req)
			mu.Lock()
			lastReq, lastRep = b, rec.b.Bytes()
			mu.Unlock()
			if rec.code != 0 {
				w.WriteHeader(rec.code)
			}
			w.Write(rec.b.Bytes())
		})
	}
	r.routes.Set(unlocktest.HolderHost("vercel"), tap(r.w.Handler("vercel")))
	r.run(r.unlocker(func(c *unlock.Config) { c.Cache = nil }), 30*time.Second)
	mu.Lock()
	req, rep := lastReq, lastRep
	mu.Unlock()
	if req == nil {
		t.Fatal("nothing tapped")
	}
	replay := httptest.NewRecorder()
	r.w.Handler("vercel").ServeHTTP(replay, httptest.NewRequest(http.MethodPost, "/v1/unlock", bytes.NewReader(req)))
	if replay.Code == 200 || !strings.Contains(replay.Body.String(), "nonce") {
		t.Fatalf("a replayed unlock request: %d %s", replay.Code, replay.Body.String())
	}
	// The old reply, served to a new boot in place of the holder's.
	stale := http.HandlerFunc(func(w http.ResponseWriter, q *http.Request) {
		if q.URL.Path == "/v1/unlock" {
			w.Write(rep)
			return
		}
		r.w.Handler("vercel").ServeHTTP(w, q)
	})
	r.routes.Set(unlocktest.HolderHost("vercel"), stale)
	u := r.unlocker(func(c *unlock.Config) { c.Cache = nil })
	if st := r.run(u, 300*time.Millisecond); st.State == unlock.StateReady || !strings.Contains(st.Holders["vercel"], "open") {
		t.Fatalf("an old reply at a new boot: %+v", st)
	}
	r.noLeak("a replay's outcome", []byte(strings.Join(mapValues(u.Status().Holders), " ")))
}

func mapValues(m map[string]string) []string {
	var out []string
	for _, v := range m {
		out = append(out, v)
	}
	return out
}

// The Worker serves an older policy than the holders have seen (a removed release, pushed): every holder refuses
// it, nothing unlocks.
func TestStalePolicy(t *testing.T) {
	r := newRig(t, []string{"cloudflare", "vercel"}, 2)
	old := r.w.PolicyEnv()
	r.w.Policy.Seq++
	newer := r.w.PolicyEnv()
	for _, h := range r.w.IDs {
		if _, err := r.w.Holders[h].PushPolicy(context.Background(), newer); err != nil {
			t.Fatal(err)
		}
	}
	r.worker.SetPolicy(old)
	u := r.unlocker(func(c *unlock.Config) { c.Cache = nil })
	if st := r.run(u, 300*time.Millisecond); st.State != unlock.StateRefused {
		t.Fatalf("an older policy: %+v", st)
	}
	r.worker.SetPolicy(newer)
	if st := r.run(r.unlocker(func(c *unlock.Config) { c.Cache = nil }), 30*time.Second); st.State != unlock.StateReady {
		t.Fatalf("the newest policy: %+v", st)
	}
}

// Without the memory-root marker of this boot (the images may be on the provider's disk), unlockd asks no holder.
func TestMemoryRootRequired(t *testing.T) {
	r := newRig(t, []string{"cloudflare", "vercel"}, 2)
	u := r.unlocker(func(c *unlock.Config) { c.RequireMemoryRoot = true })
	if st := r.run(u, 300*time.Millisecond); st.State != unlock.StateRefused || !strings.Contains(st.Reason, "memory-root") {
		t.Fatalf("no marker: %+v", st)
	}
	if r.routes.Calls(unlocktest.HolderHost("cloudflare")) != 0 {
		t.Fatal("a holder was asked without the memory root")
	}
	os.WriteFile(filepath.Join(r.cache.Dir, unlock.MemoryRootMarker), []byte("boot=old docker=/var/lib/docker fs=tmpfs\n"), 0o644)
	if st := r.run(r.unlocker(func(c *unlock.Config) { c.RequireMemoryRoot = true }), 300*time.Millisecond); st.State != unlock.StateRefused {
		t.Fatalf("another boot's marker: %+v", st)
	}
	os.WriteFile(filepath.Join(r.cache.Dir, unlock.MemoryRootMarker), []byte("boot=boot-1 docker=/var/lib/docker containerd=/var/lib/containerd fs=tmpfs\n"), 0o644)
	if st := r.run(r.unlocker(func(c *unlock.Config) { c.RequireMemoryRoot = true }), 30*time.Second); st.State != unlock.StateReady {
		t.Fatalf("this boot's marker: %+v", st)
	}
}

// The API keys arrive after the unlock (secrets.sealed missing at first): agentd is served at once, vaultd once
// they open; M isn't kept meanwhile, only the secrets key.
func TestSecretsLater(t *testing.T) {
	r := newRig(t, []string{"cloudflare", "vercel"}, 2)
	r.worker.SetSecrets(nil)
	u := r.unlocker(nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go u.Run(ctx)
	<-u.Ready()
	r.mustKeys(u, unlock.RoleAgent)
	if _, _, err := u.Keys(unlock.RoleVault); err == nil {
		t.Fatal("vaultd served without its API keys")
	}
	r.worker.SetSecrets(r.w.SecretsBundle(4))
	deadline := time.Now().Add(10 * time.Second)
	for {
		if k, _, err := u.Keys(unlock.RoleVault); err == nil && k.Secrets["EXA_API_KEY"] != "" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the API keys never came")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// The sockets: each role gets only its own; agentd's socket makes quotes under agentd's label (never an unlock's),
// vaultd's makes none.
func TestSockets(t *testing.T) {
	r := newRig(t, []string{"cloudflare", "vercel"}, 2)
	u := r.unlocker(nil)
	r.run(u, 30*time.Second)
	var seen []byte
	ev := func(ctx context.Context, rd []byte) (json.RawMessage, json.RawMessage, error) {
		seen = append([]byte(nil), rd...)
		return r.w.VM.Evidence(ctx, rd)
	}
	s := &unlock.Server{U: u, Evidence: ev, Logf: t.Logf}
	dir, _ := os.MkdirTemp("/tmp", "tacy-ul-")
	t.Cleanup(func() { os.RemoveAll(dir) })
	listen := func(role string) *unlock.Client {
		p := filepath.Join(dir, role+".sock")
		l, err := net.Listen("unix", p)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { l.Close() })
		go s.Serve(l, -1, role)
		return &unlock.Client{Path: p}
	}
	ac, vc := listen(unlock.RoleAgent), listen(unlock.RoleVault)
	ctx := context.Background()
	ak, err := ac.Wait(ctx, t.Logf, "state/v1")
	if err != nil || ak.Keys["conn/v1"] != nil || len(ak.Secrets) > 0 {
		t.Fatalf("agentd: %v", err)
	}
	vk, err := vc.Wait(ctx, t.Logf, "conn/v1")
	if err != nil || vk.Keys["state/v1"] != nil || vk.Secrets["EXA_API_KEY"] == "" {
		t.Fatalf("vaultd: %v", err)
	}
	nonce, key := bytes.Repeat([]byte{7}, 32), bytes.Repeat([]byte{9}, 32)
	if _, _, err := ac.Attest(ctx, nonce, key); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(seen, proto.AgentReportData(nonce, key)) || bytes.Equal(seen, proto.ReportData(nonce, key)) {
		t.Fatal("agentd's quote isn't under agentd's own label")
	}
	if _, _, err := vc.Attest(ctx, nonce, key); err == nil {
		t.Fatal("vaultd's socket made a quote")
	}
	// The store-auth signer is the one the Worker checks.
	auth, err := ak.StoreAuth("state/v1", r.w.Now)
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest(http.MethodGet, "https://state/api/vm/state/side", nil)
	auth(req)
	if req.Header.Get("X-Tacy-Cert") == "" || req.Header.Get("X-Tacy-Auth") == "" {
		t.Fatal("no store auth headers")
	}
}

// unlockd's gate on gatewayd: only the holders and the Worker's unlock routes, never anyone's sealed state.
func TestUnlockdGate(t *testing.T) {
	g := gateway.FixedGate{D: nil, Allow: gateway.UnlockCalls}
	if a := g.Fixed(context.Background(), &gateway.FixedCall{Target: gateway.TargetState, Method: "GET", Path: "/api/vm/state/side"}); a.Error != "bad_call" {
		t.Fatal("unlockd's socket reached sealed state")
	}
	ag := gateway.FixedGate{D: nil, Allow: gateway.AgentCalls}
	for _, c := range []*gateway.FixedCall{
		{Target: gateway.TargetUnlock, Holder: "cloudflare", Method: "GET", Path: "/v1/challenge"},
		{Target: gateway.TargetState, Method: "GET", Path: gateway.UnlockSecretsPath},
	} {
		if a := ag.Fixed(context.Background(), c); a.Error != "bad_call" {
			t.Fatalf("agentd's socket made %+v", c)
		}
	}
}

// Slots review M1: the agent VM's grant names both slots' tunnel tokens and the bundle carries both, but a VM keeps,
// and vaultd gets, only the one its attested compose's gatewayd names (-tunnel-secret). The release compose (slot a)
// gets CF_TUNNEL_TOKEN_VMA alone; the same compose on slot b, CF_TUNNEL_TOKEN_VMB alone. So no VM holds the other
// slot's token, and no gatewayd can lease it. Either slot's compose may be the tree's.
func TestOwnTunnelTokenOnly(t *testing.T) {
	const a, b = "CF_TUNNEL_TOKEN_VMA", "CF_TUNNEL_TOKEN_VMB"
	values := map[string]string{a: "tunnel-a-canary-6d5c4b3a29180716", b: "tunnel-b-canary-0f1e2d3c4b5a6978"}
	for _, slot := range []struct{ own, other string }{{a, b}, {b, a}} {
		r := newRig(t, []string{"cloudflare", "vercel"}, 2)
		g := r.w.Policy.Apps[unlocktest.App]
		g.Secrets = append(slices.Clone(g.Secrets), a, b)
		r.w.Policy.Apps[unlocktest.App] = g
		r.w.Secrets[a], r.w.Secrets[b] = values[a], values[b]
		// The tree's compose names one slot (a release leases the slot the live one isn't on): the other slot's run
		// is the same compose with the other token.
		if !strings.Contains(r.w.VMCompose, `"-tunnel-secret", "`+slot.own+`"`) {
			dc := strings.Replace(r.w.VMCompose, `"-tunnel-secret", "`+slot.other+`"`, `"-tunnel-secret", "`+slot.own+`"`, 1)
			if dc == r.w.VMCompose {
				t.Fatal("compose.yaml names no -tunnel-secret " + slot.other)
			}
			q, info, ac := r.w.Variant(func(m map[string]any) { m["docker_compose_file"] = dc })
			r.w.VM = &unlocktest.Evidence{Quote: q, Info: info}
			h := sha256.Sum256([]byte(dc))
			pin := &r.w.Policy.Releases[len(r.w.Policy.Releases)-1]
			pin.AppComposeSHA256, pin.ComposeSHA256 = ac, hex.EncodeToString(h[:])
		}
		r.worker.SetPolicy(r.w.PolicyEnv())
		r.worker.SetSecrets(r.w.SecretsBundle(3))
		u := r.unlocker(func(c *unlock.Config) { c.Cache = nil })
		if st := r.run(u, 30*time.Second); st.State != unlock.StateReady || st.Reason != "" {
			t.Fatalf("%s: status %+v", slot.own, st)
		}
		v := r.mustKeys(u, unlock.RoleVault)
		if _, held := v.Secrets[slot.other]; held || v.Secrets[slot.own] != values[slot.own] || v.Secrets["EXA_API_KEY"] == "" {
			t.Fatalf("compose on %s: vaultd got %s %t, %s %t", slot.own, slot.own, v.Secrets[slot.own] != "", slot.other, held)
		}
	}
}

func TestTunnelSecret(t *testing.T) {
	ac := func(dc string) []byte { b, _ := json.Marshal(map[string]string{"docker_compose_file": dc}); return b }
	for dc, want := range map[string]string{
		"services:\n  agentvm:\n    command: [\"-x\", \"1\", \"-tunnel-secret\", \"CF_TUNNEL_TOKEN_VMB\"]\n": "CF_TUNNEL_TOKEN_VMB",
		"services:\n  agentvm:\n    command: [\"--tunnel-secret=CF_TUNNEL_TOKEN_VMA\"]\n":                    "CF_TUNNEL_TOKEN_VMA",
		"services:\n  agentvm:\n    command: -a -tunnel-secret CF_TUNNEL_TOKEN_VMB\n":                        "CF_TUNNEL_TOKEN_VMB",
		"services:\n  agentvm:\n    command: [\"-socket\", \"/s\"]\n":                                        "",
	} {
		if got, err := unlock.TunnelSecret(ac(dc)); err != nil || got != want {
			t.Fatalf("%q: %q %v, want %q", dc, got, err, want)
		}
	}
	for _, dc := range []string{
		"services:\n  agentvm:\n    command: [\"-tunnel-secret\", \"CF_TUNNEL_TOKEN_VMA\"]\n  other:\n    entrypoint: [\"-tunnel-secret\", \"CF_TUNNEL_TOKEN_VMB\"]\n",
		"services:\n  agentvm:\n    command: [\"-tunnel-secret\"]\n",
		"services: [\n",
		"",
	} {
		if got, err := unlock.TunnelSecret(ac(dc)); err == nil {
			t.Fatalf("%q: %q, want an error", dc, got)
		}
	}
}
