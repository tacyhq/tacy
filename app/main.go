// Tacy agent VM: an agent loop with web search, running in a confidential VM (Phala dstack, Intel TDX).
//
// The published port answers only GET /attest, its key, /health, the signed safety documents (front) and
//
//	POST /v                       one envelope the relay signed (../relay; the keys plan §3.4), EHBP-encrypted to this
//	                              boot's key: the method, path and headers of one of the routes below and its body;
//	                              the answer's status, headers and body come back inside it. The provider's gateway,
//	                              which ends TLS in front of the VM, sees POST /v, padded sizes and timing only. The
//	                              signature (-relay-auth-key, pinned in the compose) is what the bearer token was.
//
// Every route below is reached only from inside an envelope; the headers named are the envelope's.
//
//	GET  /attest?nonce=<64 hex>   TDX quote whose report_data binds the nonce and this boot's HPKE key, plus dstack
//	                              info (app compose, event log). Format: proto.Attestation, proto.ReportData.
//	POST /tasks, /tasks/status, /tasks/events, /tasks/cancel
//	                              the task API (tasks.go, docs/27): start a task, see it, follow its events from any
//	                              point, cancel it. EHBP bodies, as /run. Billing witness headers for the relay
//	                              (X-Agent-Task, X-Agent-Bill, X-Agent-Refundable), inside the envelope.
//	GET  /tasks/open              {"open": n}: open tasks, for the relay's idle timer (a count only).
//	POST /run                     EHBP-encrypted proto.RunRequest -> EHBP-encrypted SSE stream of proto.Event: a
//	                              shim over the task API (start, then follow; cancelled when the tab goes away).
//	                              Kept one release after the chat moved to /tasks (temporary chats still use it).
//	                              Optional "X-Agent-User: <hex>": the relay's opaque per-user tag, for fairness
//	                              only (limits.go). Required "X-Agent-Model: <model id>": the run's model in
//	                              plaintext, so the relay can charge for it; the run is refused (400
//	                              model_mismatch, encrypted) unless it equals the model in the encrypted body,
//	                              like Tinfoil's router does with X-Tinfoil-Model. With every slot busy the run is queued (encrypted "queue"
//	                              events); a full queue is a 429 (inside the envelope) {"error":"queue_full"|"user_queue_full"}.
//	GET  /.well-known/hpke-keys   the same HPKE key in RFC 9458 form (EHBP discovery). Only trust it after
//	                              checking it equals the attested key.
//	GET  /activity?chain=&after=  sealed activity records of one chain (docs/24), for the relay.
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
// The HPKE private key is generated at boot and lives only in memory; requests and responses are never logged.
// Nothing is kept on a disk (the keys plan, "Keys: never a provider's": the CVM's disk is under Phala's key):
// the queue, activity records, approvals and the signed controls' floors live in this process's memory (state.go),
// the keys are made at boot (keysource.go) and the API keys arrive by the Worker's push (secrets.go). A task ends
// with the process. Schedules and email are off until sealed state under the Tacy key service (the keys plan C, D).
// compose.yaml embeds this source (cmd/compose), and the CVM runs binaries whose SHA-256 are pinned in the
// compose, so the attested compose hash covers the exact code.
package main

import (
	"cmp"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
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
	"os/signal"
	"regexp"
	"runtime"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	_ "time/tzdata" // the daily schedules' zones, fixed by the attested build (trigger/daily.go)

	ehbpidentity "github.com/tinfoilsh/encrypted-http-body-protocol/identity"
	ehbpproto "github.com/tinfoilsh/encrypted-http-body-protocol/protocol"

	"github.com/tacyhq/tacy/activity"
	"github.com/tacyhq/tacy/approval"
	"github.com/tacyhq/tacy/brain"
	"github.com/tacyhq/tacy/gateway"
	"github.com/tacyhq/tacy/guard"
	"github.com/tacyhq/tacy/harness"
	"github.com/tacyhq/tacy/identity"
	"github.com/tacyhq/tacy/internal/procinfo"
	"github.com/tacyhq/tacy/internal/tinfoil"
	"github.com/tacyhq/tacy/proto"
	"github.com/tacyhq/tacy/queue"
	"github.com/tacyhq/tacy/relay"
	"github.com/tacyhq/tacy/runner"
	"github.com/tacyhq/tacy/safety"
	"github.com/tacyhq/tacy/sealstate"
	"github.com/tacyhq/tacy/trigger"
	"github.com/tacyhq/tacy/unlock"
	"github.com/tacyhq/tacy/vault"
)

type server struct {
	platform Platform
	// attester makes /attest's evidence through unlockd (proto.VersionAgent); nil: the platform's (local runs).
	attester func(ctx context.Context, nonce, key []byte) (json.RawMessage, json.RawMessage, error)
	// proof makes /attest's unlock proof (proto.UnlockProof) for the info unlockd returned: nil without an unlock
	// (local runs) or an epoch certificate (a development root).
	proof func(info json.RawMessage) *proto.UnlockProof
	// owner holds the spaces' schedule ownership rows at the Worker (unlock/owner.go); nil: this VM fires them all.
	owner    *unlock.Owner
	id       *ehbpidentity.Identity
	agent    guard.Gateway    // gatewayd over its socket (the CVM), or this process's guard (local development)
	rt       *harness.Runtime // the harness/v1 runtime the brain connects to
	booted   time.Time
	sched    *scheduler // /run slots and queue
	lim      Limits
	quotes   chan struct{} // concurrent /attest limit
	runsDone atomic.Int64  // finished runs (local platform stats only)
	drain    drainState    // the Worker's drain before a switch (drain.go)

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
	// saveState saves one sealed state now (Keeper.SaveNow; nil: memory only): an event's delivery is lasting
	// before its task starts (triggers.go, V1-DESIGN §6.3).
	saveState func(ctx context.Context, name string) error
	// starts records once-only start keys as used (claimStart, review 2 M2): the side store's seen set, saved with
	// saveState before the task runs. nil: the live map and the queue are the only record.
	starts startClaimStore
	// Triggers and approvals (triggers.go): the identity directory (keys v2's key log; nil until it reaches this VM, and then
	// nothing that needs a person's signature works), approvals (POST /approvals) and triggers (POST /triggers).
	dir       identity.Directory
	approvals *guard.Approvals
	triggers  *trigger.Engine
	// Schedules for personal spaces (schedules.go, v0.12.0): who proved they hold a space, and scheduled runs'
	// sealed results. nil on a firm VM.
	holders trigger.HolderStore
	results trigger.ResultStore
	// memory is schedules' memory across runs (schedule upgrades: trigger/memory.go), on the same side file. nil on a
	// firm VM.
	memory trigger.MemoryStore
	// ledger is the safety budgets' ledger (the safe gateway's): GET /tasks/open reads scheduled runs' cost from it.
	// nil: none.
	ledger *safety.Ledger
	// Run notifications (notify.go): the spaces that turned them on and their marks; nil: none (every call is a no-op).
	notify *notifier
	// taskFollows counts each task's open event streams (a prompt in a followed task notifies nobody), under followMu.
	taskFollows map[string]int
	// handed: the results the relay said it stored (POST /schedules/handoff, handoff.go), memory only.
	handed handedSet
	// The API keys vaultd gets from the key service (secrets.go): needKeys: the routes that need them answer
	// "starting" until vaultd has them (the CVM); keys: whether it does.
	needKeys     bool
	keys         keysReady
	vaultSecrets secretsGateway // nil: s.gw's (gatewayd's); tests set a stand-in
}

type ticketKey struct{}

// ModelHeader carries the run's model in plaintext (checked against the encrypted body).
const ModelHeader = "X-Agent-Model"

// What the relay prices a run at (v0.16.0, guard/charge.go), both optional and checked against the encrypted body:
// the built-in agent (X-Agent-Kind) and the dearest model the run may call (X-Agent-Price-Model). pricedHeader is
// this VM's plaintext witness on a task start's answer that it checked them: a relay that priced a start lower on
// their word charges the rest when the witness is missing (a release before them doesn't check).
const (
	KindHeader       = "X-Agent-Kind"
	PriceModelHeader = "X-Agent-Price-Model"
	pricedHeader     = "X-Agent-Priced"
)

func knownModel(m string) bool { return guard.KnownModel(m) }

// chargeHeadersError is why the pricing headers are refused at the door ("": they're fine): a kind or a model this
// release doesn't have. That they match the body is checked after decryption (guard.CheckCharge).
func chargeHeadersError(r *http.Request) string {
	if k := r.Header.Get(KindHeader); k != "" && !guard.KnownKind(k) {
		return "kind_unknown"
	}
	if m := r.Header.Get(PriceModelHeader); m != "" && !knownModel(m) {
		return "model_unknown"
	}
	return ""
}

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

// writeJSON writes v as one chunk, padded with trailing spaces to its size class (proto.PadJSON: a power of two,
// at least 512 bytes; the keys plan §3.4), so an answer's size says little about what it holds.
func writeJSON(w http.ResponseWriter, code int, v any) {
	b, _ := json.Marshal(v)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	w.Write(proto.PadJSON(append(b, '\n')))
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
	version := proto.Version
	var quote, info json.RawMessage
	if s.attester != nil { // a release with unlockd: it alone has dstack's socket, and quotes agentd's key under agentd's label
		version = proto.VersionAgent
		quote, info, err = s.attester(r.Context(), nonce, pub)
	} else {
		quote, info, err = s.platform.Evidence(r.Context(), proto.ReportData(nonce, pub))
	}
	if err != nil {
		fail(w, 502, "attestation evidence unavailable")
		return
	}
	var proof *proto.UnlockProof
	if s.attester != nil && s.proof != nil {
		proof = s.proof(info) // this boot's key only (pub), for the info this quote came with
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, proto.Attestation{Version: version, Platform: s.platform.Name(),
		Nonce: hex.EncodeToString(nonce), HPKEPublicKey: hex.EncodeToString(pub), HPKESuite: proto.HPKESuite,
		Quote: quote, Info: info, Booted: s.booted.Format(time.RFC3339), UnlockProof: proof})
}

// authorized says the request came in an envelope the relay signed (POST /v, ../relay; the keys plan §3.4). It replaces
// the bearer token, which crossed the provider's gateway in plaintext: the relay's key never leaves the relay. It
// only guards cost: privacy comes from EHBP, and what changes a person's data needs that person's signature.
func (s *server) authorized(r *http.Request) bool { return relay.Relayed(r.Context()) }

// front is the handler the published port reaches: the one request type the relay sends (POST /v, an envelope it
// signed, encrypted to this boot's key; inner holds every route and serves it), and what needs no relay at all:
// the attestation and its key, health, and the signed safety documents gatewayd's pull posts here (their signatures
// are their authorization). Nothing else answers outside an envelope.
func (s *server) front(inner http.Handler, rs *relay.Server) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /attest", s.attest)
	mux.HandleFunc("GET "+ehbpproto.KeysPath, s.id.ConfigHandler)
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) { fmt.Fprintln(w, "ok") })
	if s.safety != nil && s.safety.Keyed() {
		mux.HandleFunc("POST /safety", s.safetyIn)
	}
	if s.safety != nil && s.safety.KeyLogged() {
		mux.HandleFunc("POST /keylog", s.keylogIn)
	}
	mux.Handle("GET /safety", inner)
	if s.platform != nil && s.platform.Name() == "local" {
		mux.HandleFunc("GET /debug/stats", s.stats) // load test only; not served in the CVM
	}
	open := s.id.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Cache-Control", "no-store")
		rs.ServeHTTP(w, r)
	}))
	mux.Handle("POST "+relay.Path, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// EHBP's middleware passes a plaintext body through: an envelope must be encrypted.
		if r.Header.Get(ehbpproto.EncapsulatedKeyHeader) == "" || r.ContentLength == 0 {
			fail(w, 400, "encrypted body required (EHBP)")
			return
		}
		open.ServeHTTP(w, r)
	}))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { // anything else: 404, whatever the method
		if r.URL.Path != "/" || r.Method != "GET" {
			http.NotFound(w, r)
			return
		}
		fmt.Fprintln(w, "Tacy agent VM: GET /attest?nonce=<hex>, POST /v (a signed EHBP envelope), GET /health")
	})
	return mux
}

// guard runs before EHBP decryption: the relay's envelope, encrypted body required (EHBP's middleware would pass plaintext
// through), admission (a slot or a place in the queue). Errors here are plaintext inside the envelope and carry no request data.
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
		if msg := chargeHeadersError(r); msg != "" {
			fail(w, 400, msg)
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
	// The same for what it priced: the run's kind and the dearest model it may call (v0.16.0).
	if err := guard.CheckCharge(&req, r.Header.Get(ModelHeader), r.Header.Get(KindHeader), r.Header.Get(PriceModelHeader)); err != nil {
		fail(w, 400, err.Error())
		return
	}
	// Where and who (keys v2 spaces and identities): checked once, here; StartFor then uses what was verified.
	err = s.verifyWho(&req, userFrom(r.Context()))
	if _, known := guard.Definition(req.Agent); err == nil && known && !guard.IsChat(req.Agent) {
		err = fmt.Errorf("%s starts through POST /tasks", req.Agent) // its task outlives the tab
	}
	if err == nil {
		_, _, err = s.agent.StartFor(&req) // the request checks (Run makes the task from it again)
	}
	if err != nil {
		if safety.CodeOf(err) != "" { // stopped, no policy, a model it doesn't allow, the day used up: say why
			w.Header().Set("Content-Type", "text/event-stream")
			w.Header().Set("Cache-Control", "no-store")
			w.WriteHeader(200)
			out := newEventStream(w, keepaliveEvery)
			s.refuseRun(out, &req, err)
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
	// The task's own start checks the request again (Host.Start's StartFor): what was admitted above may be refused
	// there (the day used up by parallel runs meanwhile, a stop that just came in), and then nothing was emitted.
	// That refusal reaches the person and the record as the one above does, never as an empty stream.
	var emitted atomic.Bool
	err = s.tasks().Run(r.Context(), userFrom(r.Context()), &req, func(e proto.Event) error {
		emitted.Store(true)
		return emit(e)
	})
	if err != nil && !emitted.Load() && r.Context().Err() == nil {
		s.refuseRun(out, &req, err)
		return
	}
	out.done()
}

// refuseRun ends a /run stream with a refusal: a safety control's (stopped, no policy, a model it doesn't allow, the
// day used up) with its code and its record in the space's chain; any other error as a plain error event.
func (s *server) refuseRun(out *eventStream, req *proto.RunRequest, err error) {
	code, msg := coded(err)
	if rg, ok := s.agent.(*recGateway); ok && safety.CodeOf(err) != "" { // the refusal goes on the record too
		if ev, ok := rg.Refused(req, err); ok {
			out.emit(ev)
		}
	}
	out.emit(proto.Event{Type: "error", Error: msg, Code: code})
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
	started := time.Now() // the tmpfs queue's heartbeat is compared with this (queue.Tmpfs.Started)
	addr := flag.String("addr", ":8080", "listen address (TCP)")
	listenUnix := flag.String("listen-unix", "", "serve HTTP on this unix socket instead of -addr (the CVM: gatewayd forwards the published port to it)")
	listenUID := flag.Int("listen-uid", -1, "the only uid allowed to connect to -listen-unix (gatewayd's); -1: no check")
	listenGID := flag.Int("listen-gid", -1, "group of -listen-unix (mode 0660); -1: mode 0600")
	gatewaySocket := flag.String("gateway-socket", "", "gatewayd's unix socket: model calls and actions go there (required on dstack); empty: this process's guard (local only)")
	platformName := flag.String("platform", "dstack", "dstack | local (no attestation; development only)")
	sock := flag.String("dstack-sock", "/var/run/dstack.sock", "dstack guest agent socket")
	schedules := flag.Bool("schedules", false, "local only: schedules in memory (on the CVM they wait for sealed state, the keys plan Stage C)")
	tasksDir := flag.String("tasks-dir", "", "the task queue in this host tmpfs (made by setup for agentd alone, 0700; refused unless statfs says tmpfs), "+
		"so open tasks survive a container restart (V1-DESIGN §6.2); empty: the queue is in memory and ends with the process")
	stateMode := flag.String("state", "memory", "memory (nothing outlives the process) | relay (sealed snapshots at the chat Worker through gatewayd; needs -kms-key) | dir (local only: sealed snapshots in -state-dir)")
	unlockSocket := flag.String("unlock-socket", "", "unlockd's socket for agentd: its keys (from the split-key unlock) and its quotes")
	stateDir := flag.String("state-dir", "", "-state dir (local only): the directory for the sealed snapshots")
	devStateKey := flag.String("dev-state-key", "", "-state dir (local only): 64 hex, the seed of local lasting keys")
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
	relayAuth := flag.String("relay-auth-key", "", "the relay's request-signing public key, ed25519:<base64> (the compose pins it; required on dstack): every call comes in a POST /v envelope it signed")
	var sf safety.Flags
	sf.Register(flag.CommandLine)
	flag.Parse()
	if flag.NArg() != 0 { // the attested command line is flags only (review 2, M1)
		log.Fatalf("agentd: unexpected arguments %q", flag.Args())
	}
	log.Printf("agentd: %s", procinfo.Line())
	var relayKey ed25519.PublicKey
	if *relayAuth != "" {
		k, err := safety.ParseKey(*relayAuth)
		if err != nil {
			log.Fatalf("-relay-auth-key: %v", err)
		}
		relayKey = k
	} else if *platformName == "dstack" {
		log.Fatal("-relay-auth-key is required on dstack: nothing but a signed envelope reaches the routes")
	}
	if lim.MaxRuns > 256 {
		log.Fatal("-max-runs is at most 256 (harness/v1 max_tasks)")
	}
	if *memLimit > 0 {
		debug.SetMemoryLimit(int64(*memLimit) << 20)
	}

	var p Platform
	switch *platformName {
	case "dstack":
		p = newDstack(*sock)
		if *devModel != "" || *devSearch != "" || *devFetchAny || *schedules || *stateDir != "" || *devStateKey != "" {
			log.Fatal("-dev-*, -schedules and -state-dir flags are for -platform local only")
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
	// Keys and state (state.go): never the platform's (the keys plan). With -kms-key, the Tacy key service's release of
	// agentd's own purposes (state, activity signing, task ids), through gatewayd; sealed snapshots of what must
	// outlive the process at the chat Worker (-state relay), checked against the key service's generation register.
	// Without it, keys made at boot and everything in memory (the quick path; local runs).
	var keys KeySource = newBootKeys()
	var uk *unlock.Keys
	var uc *unlock.Client
	var gwc *gateway.Client
	if *gatewaySocket != "" {
		gwc = &gateway.Client{Path: *gatewaySocket}
		if d, ok := p.(*dstack); ok {
			d.gce = &gateway.GCEHinter{D: gwc} // Google Cloud only: the registry-mode hints (gateway/gce.go)
		}
	}
	if *unlockSocket != "" {
		if gwc == nil {
			log.Fatal("-unlock-socket needs -gateway-socket: agentd has no network, gatewayd carries its sealed state")
		}
		uc = &unlock.Client{Path: *unlockSocket}
		k, err := uc.Wait(context.Background(), log.Printf, agentPurposes...)
		if err != nil {
			log.Fatalf("keys: %v", err)
		}
		uk, keys = k, unlockKeys{k}
	} else if p.Name() == "dstack" && *stateMode != "memory" {
		log.Fatal("-state relay needs -unlock-socket: sealed state needs the split-key unlock's lasting keys")
	}
	var backend sealstate.Backend
	var reg sealstate.Register // none: the Worker's compare-and-set on the generation (D1) is the register
	switch *stateMode {
	case "memory":
	case "relay":
		if uk == nil {
			log.Fatal("-state relay needs -unlock-socket (the state key and its store certificate)")
		}
		auth, err := uk.StoreAuth(PurposeState, nil)
		if err != nil {
			log.Fatalf("state: %v", err)
		}
		// The chat Worker's sealed-state API (vm-state.ts) at gatewayd's -state-url: ciphertext only.
		backend = &sealstate.Relay{Base: "https://state", Client: gateway.StateHTTP{D: gwc}, Auth: auth}
	case "dir":
		seed, err := hex.DecodeString(*devStateKey)
		if p.Name() != "local" || *stateDir == "" || err != nil || len(seed) != 32 {
			log.Fatal("-state dir is local only, with -state-dir and -dev-state-key <64 hex>")
		}
		keys, backend = devKeys{seed: seed}, &sealstate.File{Dir: *stateDir}
	default:
		log.Fatalf("unknown -state %q", *stateMode)
	}
	boot, err := bootState(context.Background(), keys, backend, reg, sf.Firm)
	if err != nil {
		log.Fatalf("state: %v", err)
	}
	kept := boot.kept
	if *tasksDir != "" {
		if err := kept.useTasksQueue(queue.Tmpfs{Dir: *tasksDir, Started: started}); err != nil {
			log.Fatalf("tasks: %v", err)
		}
		go kept.beatTasks(context.Background(), log.Printf)
	}
	// Step 6: the signed controls; their floors sealed with the rest when the state is kept (else they come back
	// from the signed documents gatewayd pulls).
	scfg, err := sf.Config(guard.ReleasePolicy(sf.Firm, p.Secret("TINFOIL_ENCLAVE")), "")
	if err != nil {
		log.Fatal(err)
	}
	scfg.Persist = kept.safety
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
		// Connections in this process's memory (no vaultd here): a local run's email account lasts until it stops.
		lv, err := vault.New(nil, nil, nil)
		if err != nil {
			log.Fatal(err)
		}
		if err := lv.EnableConns(nil); err != nil {
			log.Fatal(err)
		}
		gw = guard.New(guard.Config{Up: up, Search: search, Fetcher: fetcher, Reader: &reader,
			Icons:  fetcher, // site icons go through the same guarded client (guard/favicons.go)
			Limits: &lim, CacheSecret: randomHex(32), Now: func() time.Time { return time.Now().UTC() }, Safety: st,
			Stored: guard.NewStoredConfig(), Mail: &guard.MailConfig{Vault: vault.Local{V: lv}}})
	}
	sg := newSafeGateway(gw, st, kept.ledger)
	sg.firstHeard = 20 * time.Second
	// Activity records (docs/24): signed with a key for this firm from the KeySource (a key per boot until the Tacy key
	// service is wired in: a new chain each boot).
	astore := kept.activity
	rec := boot.rec
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
	rt := newRuntime(rg, kept.queue, lim)
	sg.cancel = func(id, reason string) { rt.Cancel(id, reason) }
	ids, err := rt.Restore()
	if err != nil {
		log.Fatalf("queue: %v", err)
	}
	// Once-only task ids (docs/27): a key from the KeySource, per firm.
	idKey := boot.idKey
	host := &guard.Host{RT: rt, GW: rg, IDKey: idKey, Boot: kept.queueBoot}
	// Permission prompts: actions that send data out wait for the person's answer; the policy may cap their settings.
	// OnWait stops the run's running-time clock while a prompt waits for the person (v0.8.1).
	rg.prompts = &guard.Prompts{Release: rt.Release, Emit: host.Emit, Cap: permissionCap(st), OnWait: sg.waiting,
		Sources: host.Sources}
	// Approve before send and triggers (docs/27 sections 3 and 4): their records in memory. No identity directory on
	// this VM yet (keys v2's key log comes later): no approval, definition or event verifies, so sends are denied and
	// nothing is triggered.
	side := kept.side
	// Personal spaces' seal keys pinned on first use (v0.16.0; runauth.PinStore), in memory: pinned again after a boot.
	rg.pins = side
	// Schedules (v0.12.0, schedules.go): on the shared chat VM, the directory is who proved they hold a personal
	// space (recorded at a schedule's install). A firm VM's comes with its key log (later): none, nothing installs.
	// Approvals keep no directory either way: no definition a personal space can install sends or changes anything.
	var directory identity.Directory
	var holders trigger.HolderStore
	var results trigger.ResultStore
	var memory trigger.MemoryStore
	var collect trigger.CollectStore
	if st.PersonalSpaces() && (*schedules || kept.schedules) { // the CVM: off until sealed state (the keys plan Stage C)
		holders, results, memory, collect = side, side, side, side
		directory = &trigger.HolderDirectory{Firm: st.Firm(), Store: side}
	}
	rg.approvals = &guard.Approvals{Release: rt.Release, Emit: host.Emit, Store: side, IDKey: idKey, OnWait: sg.waiting,
		Check: approval.Config{Dir: nil, RP: ReleaseRP},
		Listed: func(space, action string) bool {
			e, err := st.Policy(space)
			return err == nil && e.NeedsApproval(action)
		}}
	host.Forgotten = func(id string) { side.DeleteApprovals(id) } // with the task, after its keep
	if unknown, err := rg.approvals.Recover(); err != nil {
		log.Fatalf("approvals: %v", err)
	} else if len(unknown) > 0 {
		log.Printf("approvals: %d effects were being sent when the last process stopped: unknown, never sent again", len(unknown))
	}
	engine := trigger.New(trigger.Config{Firm: st.Firm(), Dir: directory, Store: side, IDKey: idKey, Trusted: st.OperatorTime,
		Collect: collect})
	if directory != nil {
		if n, err := engine.Load(); err != nil {
			log.Fatalf("triggers: %v", err)
		} else if n > 0 {
			log.Printf("triggers: %d agent definitions loaded", n)
		}
	}
	s := &server{platform: p, id: id, agent: rg, rt: rt, rec: rec, needKeys: p.Name() != "local" || uk != nil, booted: time.Now().UTC(),
		sched: newScheduler(lim), lim: lim, quotes: make(chan struct{}, 8), safety: st, gw: gw, safetySlots: make(chan struct{}, 4),
		host: host, prompts: rg.prompts, dir: directory, approvals: rg.approvals, triggers: engine, holders: holders, results: results,
		memory: memory, ledger: sg.ledger}
	if uc != nil {
		s.attester = uc.Attest
		s.proof = unlockProofs(boot.signer, uk, id.MarshalPublicKey())
		// Schedule ownership (unlock/owner.go): this VM fires a space's schedules only while it holds the space's row
		// at the Worker, named by its attested instance id.
		auth, err := uk.StoreAuth(PurposeState, nil)
		if err != nil {
			log.Fatalf("owner: %v", err)
		}
		inst, err := instanceID(context.Background(), uc)
		if err != nil {
			log.Fatalf("owner: %v", err)
		}
		s.owner = &unlock.Owner{Client: gateway.StateHTTP{D: gwc}, Auth: auth, ID: inst}
	}
	if kept.keeper != nil { // a change that must be lasting before what follows it runs (an event's delivery)
		s.saveState = kept.keeper.SaveNow
	}
	if sc, ok := side.(startClaimStore); ok { // both side stores can (queue.Side, trigger.MemStore)
		s.starts = sc
	} else {
		log.Fatal("tasks: the side store can't record start keys")
	}
	host.ClaimStart = s.claimStart
	host.TriggeredDone = s.triggeredDone
	host.Memory = s.scheduleMemory
	host.Allows = s.policyAllows
	// Run notifications (notify.go): off for every space until its holder turns them on (memory only).
	s.notify = kept.notify
	host.TaskEnded = s.taskEnded
	rg.prompts.OnWait = s.onWait(rg.prompts.OnWait, sg.spaceOf)
	if cw := s.credWaits(); cw != nil { // a call waiting for its mail login stops the run's clock, as a prompt does
		cw.OnWait = s.onWait(sg.waiting, sg.spaceOf)
	}
	rg.approvals.OnWait = s.onWait(rg.approvals.OnWait, sg.spaceOf)
	if kept.tasksTmpfs != nil { // a drain an earlier process of this boot kept (drain.go), before any schedule fires
		s.drain.restore(kept.tasksTmpfs.Dir, time.Now())
	}
	ctx := context.Background()
	s.resumeTasks(ctx, ids, log.Printf)
	if d, ok := p.(*dstack); ok { // the first /attest after a cold start then waits for one guest agent call, not two
		go d.PrefetchInfo(ctx, 2*time.Second, 3*time.Minute)
	}
	go s.watchSecrets(ctx, 5*time.Second)
	go s.runTriggers(ctx, 30*time.Second)
	if results != nil {
		go s.pruneResults(ctx)
	}
	go sg.enforce(ctx, 2*time.Second)
	go pruneActivity(ctx, astore, func() bool { return s.drain.on(time.Now()) })
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

	// Every route below is served only from inside an envelope (front): the relay's signed POST /v.
	mux := http.NewServeMux()
	mux.HandleFunc("GET /attest", s.attest)
	mux.HandleFunc("GET "+ehbpproto.KeysPath, id.ConfigHandler)
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) { fmt.Fprintln(w, "ok") })
	mux.Handle("POST /run", s.guard(id.Middleware()(http.HandlerFunc(s.run))))
	s.taskRoutes(mux, id)
	// The plain chat's web search (search.go).
	s.searchRoutes(mux, id)
	s.triggerRoutes(mux, id)
	s.scheduleRoutes(mux, id)                                    // schedules for personal spaces (schedules.go, the schedules contract)
	s.connectionRoutes(mux, id)                                  // Settings → Connections (connections.go, the connections contract)
	s.notifyRoutes(mux, id)                                      // run notifications (notify.go, the schedules contract)
	s.secretsRoutes(mux)                                         // whether vaultd has the API keys (secrets.go)
	s.drainRoutes(mux)                                           // the Worker's drain before a switch (drain.go)
	mux.HandleFunc("POST /schedules/handoff", s.scheduleHandoff) // sealed results to the relay (handoff.go, the schedules contract)
	mux.HandleFunc("GET /activity", s.activityOut)               // sealed activity records, for the relay (docs/24)
	// Signed policies and stop lists; the signature is the authorization. Only served when the compose pins a key
	// (stage 2): without one nothing could verify, so there's nothing to take.
	if st.Keyed() {
		mux.HandleFunc("POST /safety", s.safetyIn)
	}
	// Firm key log entries (the firm key log); only when the compose pins the log's genesis.
	if st.KeyLogged() {
		mux.HandleFunc("POST /keylog", s.keylogIn)
	}
	mux.HandleFunc("GET /safety", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, st.StatusOf("")) }) // the firm's controls
	off := quickPathOff
	if *schedules || kept.schedules {
		off = nil
	}
	if kept.keeper != nil { // the sealed snapshots: within a second of a change, and once more on SIGTERM
		// Another instance holds the state now (a refused reservation, a conflict at the Worker): stop serving.
		kept.keeper.OnFatal = func(err error) { log.Fatalf("state: %v", err) }
		kctx, stop := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() { kept.keeper.Run(kctx); close(done) }()
		go func() {
			sig := make(chan os.Signal, 1)
			signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
			<-sig
			stop()
			<-done
			os.Exit(0)
		}()
	}
	rs := &relay.Server{Key: relayKey, Inner: s.gate(mux, off), Now: time.Now, Trusted: st.OperatorTime}
	front := s.front(mux, rs)
	srv := &http.Server{Addr: *addr, Handler: front, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 2 * time.Minute,
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
	log.Printf("agent VM listening on %s (platform %s, hpke key %s, relay key set: %v, key service: %v, search %s, brain %s, state %s, limits %+v)",
		where, p.Name(), id.MarshalPublicKeyHex(), relayKey != nil, uk != nil, searchName, cmp.Or(*runnerSocket, "in process"),
		*stateMode, lim)
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
		OnReject: func(err error) { log.Printf("brain frame refused: %v", err) },
		// An ended task's options keep no content (v0.16.0): its run's input, files and model calls go as it ends.
		KeepOptions: guard.EndedOptions}
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

// instanceID is this VM's attested instance id (dstack's Info, through unlockd): its schedule ownership rows' owner.
func instanceID(ctx context.Context, uc *unlock.Client) (string, error) {
	_, info, err := uc.Attest(ctx, make([]byte, 32), make([]byte, 32))
	if err != nil {
		return "", err
	}
	var i struct {
		InstanceID string `json:"instance_id"`
		AppID      string `json:"app_id"`
	}
	if err := json.Unmarshal(info, &i); err != nil || i.InstanceID == "" {
		return "", errors.New("no instance id in the attested info")
	}
	return i.AppID + "/" + i.InstanceID, nil
}

// unlockProofs makes /attest's unlock proofs (gcp-prod review H1): this boot's HPKE key pub (s.id's: never a key
// agentd was handed), signed with the activity signer agentd derived from R_e, which clients check against the KMS
// id's epoch certificate (uk.EpochCert). nil without a certificate (a development root).
func unlockProofs(signer *activity.Signer, uk *unlock.Keys, pub []byte) func(info json.RawMessage) *proto.UnlockProof {
	if signer == nil || uk == nil || len(uk.EpochCert) == 0 {
		return nil
	}
	cert, kmsID, epoch, pub := uk.EpochCert, uk.KMSID, uk.Epoch, append([]byte(nil), pub...)
	return func(info json.RawMessage) *proto.UnlockProof {
		pr, err := unlock.NewUnlockProof(signer.SignLabeled, cert, kmsID, epoch, pub, info)
		if err != nil {
			log.Printf("attest: no unlock proof: %v", err)
			return nil
		}
		return pr
	}
}
