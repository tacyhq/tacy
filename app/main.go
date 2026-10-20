// Tacy agent VM: an agent loop with web search, running in a confidential VM (Phala dstack, Intel TDX).
//
//	GET  /attest?nonce=<64 hex>   TDX quote whose report_data binds the nonce and this boot's HPKE key, plus dstack
//	                              info (app compose, event log). Format: proto.Attestation, proto.ReportData.
//	POST /tasks, /tasks/status, /tasks/events, /tasks/cancel
//	                              the task API (tasks.go, docs/27): start a task, see it, follow its events from any
//	                              point, cancel it. EHBP bodies and the bearer token, as /run. Plaintext billing
//	                              witness headers for the relay (X-Agent-Task, X-Agent-Bill, X-Agent-Refundable).
//	GET  /tasks/open              {"open": n}: open tasks, for the relay's idle timer (bearer token; a count only).
//	POST /run                     EHBP-encrypted proto.RunRequest -> EHBP-encrypted SSE stream of proto.Event: a
//	                              shim over the task API (start, then follow; cancelled when the tab goes away).
//	                              Kept one release after the chat moved to /tasks (temporary chats still use it).
//	                              Needs "Authorization: Bearer <AGENT_VM_TOKEN>" (cost control; the relay holds it).
//	                              Optional "X-Agent-User: <hex>": the relay's opaque per-user tag, for fairness
//	                              only (limits.go). Required "X-Agent-Model: <model id>": the run's model in
//	                              plaintext, so the relay can charge for it; the run is refused (400
//	                              model_mismatch, encrypted) unless it equals the model in the encrypted body,
//	                              like Tinfoil's router does with X-Tinfoil-Model. With every slot busy the run is queued (encrypted "queue"
//	                              events); a full queue is a plaintext 429 {"error":"queue_full"|"user_queue_full"}.
//	GET  /.well-known/hpke-keys   the same HPKE key in RFC 9458 form (EHBP discovery). Only trust it after
//	                              checking it equals the attested key.
//	GET  /activity?chain=&after=  sealed activity records of one chain (docs/24), for the relay (bearer token).
//	GET  /health                  "ok" once listening.
//
// This is agentd (docs/21-gateway-v0.md): the front door and the runtime. A run is a harness/v1 task
// (docs/20-harness-protocol.md): this process is the runtime (../harness, the queue in ../queue); the agent loop is
// the brain (../brain, cmd/brain), untrusted, in a gVisor sandbox that runnerd (cmd/runnerd, -runner-socket) starts
// for it with no network and no secrets, reached only over a socketpair this process makes (brains.go); every
// model call and action the runtime accepts goes to gatewayd
// (../gateway, cmd/gatewayd) over -gateway-socket, which leases keys from vaultd per call. In the CVM this process
// has no network at all (its container's network_mode is none) and no keys: requests reach it through gatewayd,
// which forwards the published port's connections to -listen-unix. Locally (-platform local) the brain and the
// guard can run in this process instead.
//
// The HPKE private key is generated at boot and lives only in memory; requests and responses are never logged. A
// /run's task (its input, options, journal and events) is in the queue on the VM's encrypted disk only while it
// runs and is deleted when it ends; /run tasks a previous process left open are ended at boot (nobody can see their
// answer). A POST /tasks task is kept until it ends plus a day, and goes on after a restart.
// compose.yaml embeds this source (cmd/compose), and the CVM runs binaries whose SHA-256 are pinned in the
// compose, so the attested compose hash covers the exact code.
package main

import (
	"cmp"
	"context"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	ehbpidentity "github.com/tinfoilsh/encrypted-http-body-protocol/identity"
	ehbpproto "github.com/tinfoilsh/encrypted-http-body-protocol/protocol"

	"github.com/tacyhq/tacy/activity"
	"github.com/tacyhq/tacy/brain"
	"github.com/tacyhq/tacy/gateway"
	"github.com/tacyhq/tacy/guard"
	"github.com/tacyhq/tacy/harness"
	"github.com/tacyhq/tacy/internal/procinfo"
	"github.com/tacyhq/tacy/internal/tinfoil"
	"github.com/tacyhq/tacy/proto"
	"github.com/tacyhq/tacy/queue"
	"github.com/tacyhq/tacy/runner"
	"github.com/tacyhq/tacy/safety"
)

type server struct {
	platform Platform
	id       *ehbpidentity.Identity
	agent    guard.Gateway    // gatewayd over its socket (the CVM), or this process's guard (local development)
	rt       *harness.Runtime // the harness/v1 runtime the brain connects to
	token    string
	booted   time.Time
	sched    *scheduler // /run slots and queue
	lim      Limits
	quotes   chan struct{} // concurrent /attest limit
	runsDone atomic.Int64  // finished runs (local platform stats only)

	rec         *activity.Recorder // the runs' activity records (activity.go, docs/24)
	safety      *safety.State      // signed policies and stop lists agentd verified (step 6, safety.go)
	gw          guard.Gateway      // the guard under the safety checks (pushSafety reaches gatewayd through it)
	safetySlots chan struct{}      // concurrent POST /safety limit

	host     *guard.Host // tasks (tasks.go); made on first use when nil
	hostOnce sync.Once
	follows  chan struct{} // concurrent POST /tasks/events limit
	// userFollows counts each user tag's open event streams (maxUserFollowers), under followMu.
	followMu    sync.Mutex
	userFollows map[string]int
	// prompts are the permission prompts (guard.Prompts): POST /tasks/grant answers them. nil: none.
	prompts *guard.Prompts

	// POST /search (search.go): slots VM-wide, and each user tag's searches at once (under searchMu).
	searchSlots  chan struct{}
	searchMu     sync.Mutex
	userSearches map[string]int
}

type ticketKey struct{}

// ModelHeader carries the run's model in plaintext (checked against the encrypted body).
const ModelHeader = "X-Agent-Model"

func knownModel(m string) bool { return guard.KnownModel(m) }

// brainWait is how long a run waits for a brain to be connected before it gives up (a brain restarts in about a
// second; this covers the first boot, when the brain's container starts right after this one listens).
const brainWait = 20 * time.Second

// userTagRe: the relay's tag is hex (an HMAC). Anything else is refused rather than used as a key.
var userTagRe = regexp.MustCompile(`^[0-9a-f]{16,64}\z`)

func randomHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func fail(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func (s *server) attest(w http.ResponseWriter, r *http.Request) {
	nonce, err := hex.DecodeString(r.URL.Query().Get("nonce"))
	if err != nil || len(nonce) != 32 {
		fail(w, 400, "nonce must be 32 bytes of hex")
		return
	}
	select {
	case s.quotes <- struct{}{}:
		defer func() { <-s.quotes }()
	default:
		fail(w, 429, "busy")
		return
	}
	pub := s.id.MarshalPublicKey()
	quote, info, err := s.platform.Evidence(r.Context(), proto.ReportData(nonce, pub))
	if err != nil {
		fail(w, 502, "attestation evidence unavailable")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, proto.Attestation{Version: proto.Version, Platform: s.platform.Name(),
		Nonce: hex.EncodeToString(nonce), HPKEPublicKey: hex.EncodeToString(pub), HPKESuite: proto.HPKESuite,
		Quote: quote, Info: info, Booted: s.booted.Format(time.RFC3339)})
}

// authorized checks the relay's bearer token in constant time. It only guards cost: privacy comes from EHBP.
func (s *server) authorized(r *http.Request) bool {
	if s.token == "" {
		return false
	}
	got, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	return ok && subtle.ConstantTimeCompare([]byte(got), []byte(s.token)) == 1
}

// guard runs before EHBP decryption: token, encrypted body required (EHBP's middleware would pass plaintext
// through), admission (a slot or a place in the queue). Errors here are plaintext and carry no request data.
func (s *server) guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.authorized(r) {
			fail(w, 401, "unauthorized")
			return
		}
		if r.Header.Get(ehbpproto.EncapsulatedKeyHeader) == "" || r.ContentLength == 0 {
			fail(w, 400, "encrypted body required (EHBP)")
			return
		}
		// The model header: present and a model this VM runs, before anything is queued. That it matches the
		// encrypted body is checked after decryption (run).
		switch m := r.Header.Get(ModelHeader); {
		case m == "":
			fail(w, 400, "model_required")
			return
		case !knownModel(m):
			fail(w, 400, "model_unknown")
			return
		}
		user := r.Header.Get("X-Agent-User")
		if user != "" && !userTagRe.MatchString(user) {
			fail(w, 400, "bad_user_tag")
			return
		}
		t, err := s.sched.admit(user)
		if err != nil {
			fail(w, 429, err.Error()) // queue_full | user_queue_full
			return
		}
		defer t.release()
		defer s.runsDone.Add(1)
		r.Body = http.MaxBytesReader(w, r.Body, 8<<20) // ciphertext cap; framing adds a little over plaintext
		ctx := context.WithValue(withUser(r.Context(), user), ticketKey{}, t)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// run is behind EHBP: the body here is plaintext and everything written is encrypted.
func (s *server) run(w http.ResponseWriter, r *http.Request) {
	var req proto.RunRequest
	body, err := io.ReadAll(io.LimitReader(r.Body, 6<<20))
	if err == nil {
		err = json.Unmarshal(body, &req)
	}
	if err != nil {
		fail(w, 400, "body must be a JSON RunRequest")
		return
	}
	// The relay charged for the model in the header: a body that asks for another one is refused before
	// anything runs or is recorded (this response is encrypted, so the reason only reaches the browser).
	if h := r.Header.Get(ModelHeader); h != cmp.Or(req.Model, proto.DefaultModel) {
		fail(w, 400, "model_mismatch: the X-Agent-Model header doesn't match the run's model")
		return
	}
	// Where and who (keys v2 slice 6): checked once, here; StartFor then uses what was verified.
	err = s.verifyWho(&req, userFrom(r.Context()))
	if err == nil {
		_, _, err = s.agent.StartFor(&req) // the request checks (Run makes the task from it again)
	}
	if err != nil {
		if safety.CodeOf(err) != "" { // stopped, no policy, a model it doesn't allow, the day used up: say why
			w.Header().Set("Content-Type", "text/event-stream")
			w.Header().Set("Cache-Control", "no-store")
			w.WriteHeader(200)
			out := newEventStream(w, keepaliveEvery)
			code, msg := coded(err)
			if rg, ok := s.agent.(*recGateway); ok { // the refusal goes on the record too
				if ev, ok := rg.Refused(&req, err); ok {
					out.emit(ev)
				}
			}
			out.emit(proto.Event{Type: "error", Error: msg, Code: code})
			out.done()
			out.stop()
			return
		}
		fail(w, 400, err.Error())
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(200)
	out := newEventStream(w, keepaliveEvery)
	defer out.stop()
	emit := out.emit
	if t, ok := r.Context().Value(ticketKey{}).(*ticket); ok {
		err := t.wait(r.Context(), s.lim.QueueTimeout, 5*time.Second, func(pos int) error {
			return emit(proto.Event{Type: "queue", Position: pos})
		})
		switch {
		case errors.Is(err, errQueueTimeout):
			emit(proto.Event{Type: "error", Error: fmt.Sprintf("queue_timeout: the agent VM is busy and no slot freed up within %d s. Try again in a minute.",
				int(s.lim.QueueTimeout.Seconds()))})
			out.done()
			return
		case err != nil:
			return // the client went away
		}
		if err := emit(proto.Event{Type: "metrics", Metrics: &proto.Metric{Kind: "queue", Ms: t.waited.Milliseconds(),
			Running: t.runningAtStart, Outcome: "ok"}}); err != nil {
			return
		}
	}
	if !s.waitBrain(r.Context(), brainWait) {
		if r.Context().Err() == nil {
			emit(proto.Event{Type: "error", Error: "agent_unavailable: the agent VM's brain isn't running. Try again in a minute."})
			out.done()
		}
		return
	}
	s.tasks().Run(r.Context(), userFrom(r.Context()), &req, emit)
	out.done()
}

// verifyWho checks a request's where and who (recGateway.Verify) and notes it in req.Verified. A server whose gateway
// isn't the recorder (a guard alone: local development and tests, where nothing is recorded) takes the space as named.
func (s *server) verifyWho(req *proto.RunRequest, user string) error {
	if rg, ok := s.agent.(*recGateway); ok {
		return rg.Verify(req, user)
	}
	return nil
}

// waitBrain reports whether a brain is connected, waiting up to d for one.
func (s *server) waitBrain(ctx context.Context, d time.Duration) bool {
	deadline := time.Now().Add(d)
	for !s.rt.Connected() {
		if time.Now().After(deadline) || ctx.Err() != nil {
			return false
		}
		select {
		case <-ctx.Done():
		case <-time.After(50 * time.Millisecond):
		}
	}
	return true
}

type userKey struct{}

// withUser puts the relay's opaque per-user tag (X-Agent-User) in ctx, for the tool caps. Never logged.
func withUser(ctx context.Context, user string) context.Context {
	return context.WithValue(ctx, userKey{}, user)
}

func userFrom(ctx context.Context) string {
	u, _ := ctx.Value(userKey{}).(string)
	return u
}

func main() {
	addr := flag.String("addr", ":8080", "listen address (TCP)")
	listenUnix := flag.String("listen-unix", "", "serve HTTP on this unix socket instead of -addr (the CVM: gatewayd forwards the published port to it)")
	listenUID := flag.Int("listen-uid", -1, "the only uid allowed to connect to -listen-unix (gatewayd's); -1: no check")
	listenGID := flag.Int("listen-gid", -1, "group of -listen-unix (mode 0660); -1: mode 0600")
	gatewaySocket := flag.String("gateway-socket", "", "gatewayd's unix socket: model calls and actions go there (required on dstack); empty: this process's guard (local only)")
	platformName := flag.String("platform", "dstack", "dstack | local (no attestation; development only)")
	sock := flag.String("dstack-sock", "/var/run/dstack.sock", "dstack guest agent socket")
	storage := flag.String("storage", "", "directory on the encrypted disk for the runtime's queue (queue.db); empty: in memory")
	runnerSocket := flag.String("runner-socket", "", "runnerd's socket: the brain runs in a gVisor sandbox it starts (required on dstack); empty: the brain in this process (local only)")
	lim := defaultLimits
	flag.IntVar(&lim.MaxRuns, "max-runs", lim.MaxRuns, "runs at once")
	flag.IntVar(&lim.MaxQueue, "max-queue", lim.MaxQueue, "runs waiting for a slot")
	flag.DurationVar(&lim.QueueTimeout, "queue-timeout", lim.QueueTimeout, "longest wait for a slot")
	flag.IntVar(&lim.UserRuns, "user-runs", lim.UserRuns, "runs at once per user")
	flag.IntVar(&lim.UserQueue, "user-queue", lim.UserQueue, "runs waiting per user")
	flag.IntVar(&lim.RunTools, "run-tools", lim.RunTools, "tool calls at once within a run")
	flag.IntVar(&lim.UserTools, "user-tools", lim.UserTools, "searches and fetches at once per user")
	flag.IntVar(&lim.Searches, "searches", lim.Searches, "web searches at once, all users")
	flag.IntVar(&lim.SearchesPerMin, "searches-per-min", lim.SearchesPerMin, "web searches per minute, all users")
	flag.IntVar(&lim.Fetches, "fetches", lim.Fetches, "page and image fetches at once, all users")
	flag.IntVar(&lim.ImageDecodes, "image-decodes", lim.ImageDecodes, "images decoded at once, all users")
	flag.IntVar(&lim.Favicons, "favicons", lim.Favicons, "site icons fetched at once, all users")
	memLimit := flag.Int("mem-limit-mib", 1200, "Go soft memory limit (GOMEMLIMIT), MiB; 0 = none")
	// Development only (refused unless -platform local): the load test's stand-ins for Tinfoil, the search
	// provider and the web.
	devModel := flag.String("dev-model", "", "local only: plain OpenAI-compatible chat completions URL instead of Tinfoil")
	devSearch := flag.String("dev-search", "", "local only: Tavily-compatible search URL")
	devFetchAny := flag.Bool("dev-fetch-any", false, "local only: let fetch_page reach private addresses")
	var sf safety.Flags
	sf.Register(flag.CommandLine)
	flag.Parse()
	log.Printf("agentd: %s", procinfo.Line())
	if lim.MaxRuns > 256 {
		log.Fatal("-max-runs is at most 256 (harness/v1 max_tasks)")
	}
	if *memLimit > 0 {
		debug.SetMemoryLimit(int64(*memLimit) << 20)
	}

	var p Platform
	switch *platformName {
	case "dstack":
		p = newDstack(*sock, *storage)
		if *devModel != "" || *devSearch != "" || *devFetchAny {
			log.Fatal("-dev-* flags are for -platform local only")
		}
		if *runnerSocket == "" {
			log.Fatal("-runner-socket is required on dstack: the brain runs in a gVisor sandbox (runnerd)")
		}
		if *gatewaySocket == "" {
			log.Fatal("-gateway-socket is required on dstack: model calls and actions go through gatewayd")
		}
	case "local":
		p = local{}
	default:
		log.Fatalf("unknown platform %q", *platformName)
	}
	id, err := ehbpidentity.NewIdentity() // per boot, memory only
	if err != nil {
		log.Fatal(err)
	}
	// Step 6: the signed controls, kept on the encrypted disk (the version floors outlive a restart).
	safetyDir := ""
	if dir := p.StoragePath(); dir != "" {
		safetyDir = filepath.Join(dir, "safety")
	}
	scfg, err := sf.Config(guard.ReleasePolicy(sf.Firm, p.Secret("TINFOIL_ENCLAVE")), safetyDir)
	if err != nil {
		log.Fatal(err)
	}
	// agentd takes the pulled lists (gatewayd's pull posts them here every 10 s), so it alone can tell the pull
	// stopped reaching the VM: then nothing goes out (safety.DefaultMaxSilence).
	scfg.MaxSilence = safety.DefaultMaxSilence
	st, err := safety.NewState(scfg)
	if err != nil {
		log.Fatalf("safety: %v", err)
	}
	var gw guard.Gateway
	searchName := "gatewayd"
	var tc *tinfoil.Client
	if *gatewaySocket != "" {
		if *devModel != "" || *devSearch != "" || *devFetchAny {
			log.Fatal("-dev-* flags configure this process's guard: not with -gateway-socket")
		}
		gw = &gateway.Client{Path: *gatewaySocket, Now: func() time.Time { return time.Now().UTC() }, Docs: st.Docs}
	} else {
		// Local development and the load test: the guard in this process, keys from the environment.
		keys := guard.RecordLeases(guard.StaticKeys(p.Secret))
		tc = tinfoil.NewClient(p.Secret("TINFOIL_ENCLAVE"), "")
		up := guard.NewTinfoilUpstream(tc, keys)
		if *devModel != "" {
			up = guard.NewPlainUpstream(*devModel, &http.Client{Transport: &http.Transport{MaxIdleConnsPerHost: 256}})
		}
		search := guard.NewSearch(p.Secret("SEARCH_PROVIDER"), func(n string) bool { return p.Secret(n) != "" }, keys)
		if *devSearch != "" {
			search = guard.NewDevSearch(*devSearch)
		}
		searchName = search.Name()
		fetcher := guard.NewFetcher(*devFetchAny)
		reader := guard.DefaultReader // the quarantined reader, as in gatewayd
		gw = guard.New(guard.Config{Up: up, Search: search, Fetcher: fetcher, Reader: &reader,
			Icons:  fetcher, // site icons go through the same guarded client (guard/favicons.go)
			Limits: &lim, CacheSecret: randomHex(32), Now: func() time.Time { return time.Now().UTC() }, Safety: st})
	}
	sg := newSafeGateway(gw, st, &safety.Ledger{Dir: safetyDir})
	sg.firstHeard = 20 * time.Second
	// Activity records (docs/24): signed with a key derived from dstack's KMS for this app and firm (locally, a
	// key per boot), kept on the encrypted disk.
	ikm, err := p.ActivityKey(context.Background())
	if err != nil {
		log.Fatalf("activity: signing key: %v", err)
	}
	signer, err := activity.DeriveSigner(ikm, st.Firm())
	clear(ikm)
	if err != nil {
		log.Fatalf("activity: %v", err)
	}
	var astore activity.Store = activity.NewMemStore()
	if dir := p.StoragePath(); dir != "" {
		if astore, err = activity.OpenStore(filepath.Join(dir, "activity", "activity.db")); err != nil {
			log.Fatalf("activity: %v", err)
		}
	}
	rec := &activity.Recorder{Signer: signer, Store: astore}
	if n, err := rec.Recover(); err != nil {
		log.Fatalf("activity: %v", err)
	} else if n > 0 {
		log.Printf("activity: ended %d runs a previous process left open (interrupted)", n)
	}
	skb, err := id.PrivateKey().Bytes()
	if err != nil {
		log.Fatalf("activity: %v", err)
	}
	vmKey, err := ecdh.X25519().NewPrivateKey(skb)
	clear(skb)
	if err != nil {
		log.Fatalf("activity: %v", err)
	}
	rg := newRecGateway(sg, rec, vmKey)
	var store harness.Store = harness.NewMemStore()
	if dir := p.StoragePath(); dir != "" {
		q, err := queue.Open(filepath.Join(dir, "queue.db"))
		if err != nil {
			log.Fatalf("queue: %v", err)
		}
		store = q
	}
	rt := newRuntime(rg, store, lim)
	sg.cancel = func(id, reason string) { rt.Cancel(id, reason) }
	ids, err := rt.Restore()
	if err != nil {
		log.Fatalf("queue: %v", err)
	}
	// Once-only task ids (docs/27): a key only this app gets from dstack's KMS, per firm.
	tk, err := p.TaskIDKey(context.Background())
	if err != nil {
		log.Fatalf("tasks: id key: %v", err)
	}
	idKey, err := hkdf.Key(sha256.New, tk, nil, "tacy/task-ids/v1\x00"+st.Firm(), 32)
	clear(tk)
	if err != nil {
		log.Fatalf("tasks: %v", err)
	}
	host := &guard.Host{RT: rt, GW: rg, IDKey: idKey}
	// Permission prompts: actions that send data out wait for the person's answer; the policy may cap their settings.
	// OnWait stops the run's running-time clock while a prompt waits for the person (v0.8.1).
	rg.prompts = &guard.Prompts{Release: rt.Release, Emit: host.Emit, Cap: permissionCap(st), OnWait: sg.waiting,
		Sources: host.Sources}
	s := &server{platform: p, id: id, agent: rg, rt: rt, rec: rec, token: p.Secret("AGENT_VM_TOKEN"), booted: time.Now().UTC(),
		sched: newScheduler(lim), lim: lim, quotes: make(chan struct{}, 8), safety: st, gw: gw, safetySlots: make(chan struct{}, 4),
		host: host, prompts: rg.prompts}
	ctx := context.Background()
	s.resumeTasks(ctx, ids, log.Printf)
	if d, ok := p.(*dstack); ok { // the first /attest after a cold start then waits for one guest agent call, not two
		go d.PrefetchInfo(ctx, 2*time.Second, 3*time.Minute)
	}
	go sg.enforce(ctx, 2*time.Second)
	go pruneActivity(ctx, astore)
	go func() { // gatewayd (and through it the vault) gets agentd's documents now and every 10 s
		for {
			s.pushSafety()
			select {
			case <-st.Changed():
			case <-time.After(10 * time.Second):
			}
		}
	}()
	if *runnerSocket == "" {
		go localBrain(ctx, rt)
	} else {
		go runBrains(ctx, rt, &runner.Client{Path: *runnerSocket})
	}

	// Verify Tinfoil's router now, so the first request doesn't wait for it (gatewayd does its own).
	if tc != nil && *devModel == "" {
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			if _, _, err := tc.Current(ctx); err != nil {
				log.Printf("tinfoil verification failed (will retry on first request): %v", err)
				return
			}
			log.Printf("tinfoil router verified")
		}()
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /attest", s.attest)
	mux.HandleFunc("GET "+ehbpproto.KeysPath, id.ConfigHandler)
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) { fmt.Fprintln(w, "ok") })
	mux.Handle("POST /run", s.guard(id.Middleware()(http.HandlerFunc(s.run))))
	s.taskRoutes(mux, id)
	// The plain chat's web search (search.go, docs/29).
	s.searchRoutes(mux, id)
	mux.HandleFunc("GET /activity", s.activityOut) // sealed activity records, for the relay (docs/24)
	// Signed policies and stop lists; the signature is the authorization. Only served when the compose pins a key
	// (stage 2): without one nothing could verify, so there's nothing to take.
	if st.Keyed() {
		mux.HandleFunc("POST /safety", s.safetyIn)
	}
	// Firm key log entries (keys v2 slice 5); only when the compose pins the log's genesis.
	if st.KeyLogged() {
		mux.HandleFunc("POST /keylog", s.keylogIn)
	}
	mux.HandleFunc("GET /safety", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, st.StatusOf("")) }) // the firm's controls
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		fmt.Fprintln(w, "Tacy agent VM: GET /attest?nonce=<hex>, POST /run (EHBP), GET /health")
	})
	if p.Name() == "local" {
		mux.HandleFunc("GET /debug/stats", s.stats) // load test only; not served in the CVM
	}
	srv := &http.Server{Addr: *addr, Handler: mux, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 2 * time.Minute,
		ErrorLog: log.New(io.Discard, "", 0)}
	where := *addr
	var l net.Listener
	if *listenUnix != "" {
		where = *listenUnix
		if l, err = listenSocket(*listenUnix, *listenGID); err == nil && *listenUID >= 0 {
			l = &peerListener{Listener: l, uid: *listenUID}
		}
	} else {
		l, err = net.Listen("tcp", *addr)
	}
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	log.Printf("agent VM listening on %s (platform %s, hpke key %s, run token set: %v, search %s, brain %s, queue %s, limits %+v)",
		where, p.Name(), id.MarshalPublicKeyHex(), s.token != "", searchName, cmp.Or(*runnerSocket, "in process"),
		cmp.Or(p.StoragePath(), "in memory"), lim)
	log.Fatal(srv.Serve(l))
}

// stats: process numbers for the load test (local platform only).
func (s *server) stats(w http.ResponseWriter, r *http.Request) {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	running, queued := s.sched.stats()
	var ru syscall.Rusage
	syscall.Getrusage(syscall.RUSAGE_SELF, &ru)
	cpu := time.Duration(ru.Utime.Nano() + ru.Stime.Nano())
	writeJSON(w, 200, map[string]any{"goroutines": runtime.NumGoroutine(), "heap_alloc": m.HeapAlloc, "heap_inuse": m.HeapInuse,
		"sys": m.Sys, "num_gc": m.NumGC, "running": running, "queued": queued, "runs_done": s.runsDone.Load(),
		"cpu_ms": cpu.Milliseconds()})
}

// newRuntime is the harness/v1 runtime on g and store: as many tasks at once as runs (MaxRuns), as many requests
// in flight per task as a run's tool calls at once (RunTools; the brain runs that many actions at once).
func newRuntime(g harness.Guard, store harness.Store, lim Limits) *harness.Runtime {
	return &harness.Runtime{Guard: g, Store: store, Info: harness.Info{Name: "tacy-runtime", Version: "0.1"},
		Limits:   harness.Limits{MaxTasks: lim.MaxRuns, MaxInflight: max(1, lim.RunTools)},
		OnReject: func(err error) { log.Printf("brain frame refused: %v", err) }}
}

// listenSocket listens on a unix socket at path (a stale one is removed): group gid and mode 0660, so the one
// peer process connects through the group (it isn't this process's uid); gid -1: mode 0600.
func listenSocket(path string, gid int) (net.Listener, error) {
	os.Remove(path)
	l, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	mode := os.FileMode(0o600)
	if gid >= 0 {
		mode = 0o660
		if err := os.Chown(path, -1, gid); err != nil {
			l.Close()
			return nil, err
		}
	}
	if err := os.Chmod(path, mode); err != nil {
		l.Close()
		return nil, err
	}
	return l, nil
}

// peerListener accepts only connections from uid (Linux, SO_PEERCRED): the HTTP socket takes gatewayd's
// forwarded connections only.
type peerListener struct {
	net.Listener
	uid int
}

func (p *peerListener) Accept() (net.Conn, error) {
	for {
		c, err := p.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if err := checkPeer(c, p.uid); err != nil {
			log.Printf("http socket: %v", err)
			c.Close()
			continue
		}
		return c, nil
	}
}

// localBrain runs the brain in this process over an in-memory connection (-platform local without -brain-socket:
// development and the load test), started again whenever it stops.
func localBrain(ctx context.Context, rt *harness.Runtime) {
	for ctx.Err() == nil {
		rc, bc := net.Pipe()
		go rt.Serve(ctx, rc)
		brain.Run(ctx, bc)
		time.Sleep(100 * time.Millisecond)
	}
}
