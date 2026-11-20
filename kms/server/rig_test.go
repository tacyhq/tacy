package server

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tacyhq/tacy/internal/tdx"
	"github.com/tacyhq/tacy/kms"
	"github.com/tacyhq/tacy/kms/client"
	"github.com/tacyhq/tacy/proto"
	"github.com/tacyhq/tacy/safety"
)

// The tests run kmsd against a real recorded attestation: testdata/attest-065-kms.json is a real /attest response
// from a throwaway CVM on dstack-0.6.5 (Phala, tdx.small, 2026-11-20) in the KMS fallback (key_provider kms with the
// pinned KMS root, an ephemeral data disk, no swap, nothing public, no deployer env, no pre-launch script; instance
// abe98e7b…). Its compose had named volumes on the disk (refused in the fallback), so the rig gives the agent VM a
// release compose with memory volumes and the key service its own compose, each with the compose-hash event and
// RTMR3 the TD would have measured for it. The quote is parsed offline (tdx.Parse: no Intel chain, as the
// verifier's own offline tests), so a test can put a report_data or RTMR3 into it; everything else the verifier
// checks (OS image, boot measurements, KMS root, app-compose flags and pin, images) runs on the recorded bytes.

const (
	recordedInstance = "abe98e7b121288921464025561b3657da4754364"
	vmApp            = "agent-vm"
	vmRelease        = "v0.19.3"
)

// TDX quote v4 offsets: header 48, then the TD report (RTMR3 at 48+472, report_data after it).
const (
	offRTMR3      = 48 + 472
	offReportData = offRTMR3 + 48
)

func patchQuote(t testing.TB, quote json.RawMessage, off int, b []byte) json.RawMessage {
	t.Helper()
	out, err := patch(quote, off, b)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func patch(quote json.RawMessage, off int, b []byte) (json.RawMessage, error) {
	var q map[string]any
	if err := json.Unmarshal(quote, &q); err != nil {
		return nil, err
	}
	hx, _ := q["quote"].(string)
	raw, err := hex.DecodeString(hx)
	if err != nil || len(raw) < off+len(b) {
		return nil, fmt.Errorf("not a quote")
	}
	copy(raw[off:], b)
	q["quote"] = hex.EncodeToString(raw)
	return json.Marshal(q)
}

func offline(_ context.Context, raw []byte) (*tdx.Quote, error) { return tdx.Parse(raw) }

// evidence is a TD's dstack: it puts the asked report_data into its (recorded) quote.
type evidence struct {
	mu          sync.Mutex
	quote, info json.RawMessage
}

func (e *evidence) Name() string { return "dstack" }

func (e *evidence) Evidence(_ context.Context, rd []byte) (json.RawMessage, json.RawMessage, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	q, err := patch(e.quote, offReportData, rd)
	return q, e.info, err
}

func (e *evidence) set(q, i json.RawMessage) {
	e.mu.Lock()
	e.quote, e.info = q, i
	e.mu.Unlock()
}

func load065(t testing.TB) (proto.Attestation, []byte) {
	t.Helper()
	b, err := os.ReadFile("../../testdata/attest-065-kms.json")
	if errors.Is(err, fs.ErrNotExist) {
		t.Skip("no testdata/attest-065-kms.json (the recorded quote these tests run on)")
	}
	if err != nil {
		t.Fatal(err)
	}
	var a proto.Attestation
	if err := json.Unmarshal(b, &a); err != nil {
		t.Fatal(err)
	}
	nonce, _ := hex.DecodeString(a.Nonce)
	return a, nonce
}

// setAppCompose puts exactly these app-compose.json bytes into info.
func setAppCompose(t testing.TB, info json.RawMessage, appCompose []byte) json.RawMessage {
	t.Helper()
	var i map[string]any
	json.Unmarshal(info, &i)
	var tcb map[string]any
	json.Unmarshal([]byte(i["tcb_info"].(string)), &tcb)
	tcb["app_compose"] = string(appCompose)
	b, _ := json.Marshal(tcb)
	i["tcb_info"] = string(b)
	out, _ := json.Marshal(i)
	return out
}

// releaseCompose is the recording's compose as a release in the KMS fallback has it: without the spike's diag
// service, every named volume in memory.
func releaseCompose(t testing.TB, dc string) string {
	t.Helper()
	i, j := strings.Index(dc, "\n  spikediag:"), strings.Index(dc, "\nvolumes:\n")
	if i < 0 || j < i {
		t.Fatal("the recorded compose isn't the spike's")
	}
	dc = dc[:i+1] + "volumes:\n"
	for _, v := range []string{"state", "runnersock", "agentsock", "vaultsock", "vaultstate"} {
		dc += "  " + v + ":\n    driver_opts:\n      type: tmpfs\n      device: tmpfs\n"
	}
	return dc
}

// variant is the release VM with its app-compose.json edited (quote and RTMR3 consistent): its quote, info and the
// app-compose's sha256.
func (r *rig) variant(edit func(map[string]any)) (json.RawMessage, json.RawMessage, string) {
	r.t.Helper()
	info, ac := editAppCompose(r.t, r.vmInfo, edit)
	return editEvents(r.t, r.recQuote, map[string]string{"compose-hash": sum(ac)}), info, sum(ac)
}

// editAppCompose edits the app-compose.json in info and returns the new info and app-compose bytes.
func editAppCompose(t testing.TB, info json.RawMessage, edit func(map[string]any)) (json.RawMessage, []byte) {
	t.Helper()
	var i map[string]any
	json.Unmarshal(info, &i)
	var tcb map[string]any
	json.Unmarshal([]byte(i["tcb_info"].(string)), &tcb)
	var ac map[string]any
	json.Unmarshal([]byte(tcb["app_compose"].(string)), &ac)
	edit(ac)
	appCompose, _ := json.Marshal(ac)
	tcb["app_compose"] = string(appCompose)
	b, _ := json.Marshal(tcb)
	i["tcb_info"] = string(b)
	out, _ := json.Marshal(i)
	return out, appCompose
}

// editEvents sets RTMR3 events in quote's event log (name -> payload; a compose-hash payload of "" means
// sha256(appCompose)) and puts the replayed RTMR3 into the quote, as the TD would have measured it.
func editEvents(t testing.TB, quote json.RawMessage, set map[string]string) json.RawMessage {
	t.Helper()
	var q map[string]any
	json.Unmarshal(quote, &q)
	ev, err := tdx.ParseEventLog(json.RawMessage(mustJSON(q["event_log"])))
	if err != nil {
		t.Fatal(err)
	}
	for i := range ev {
		if p, ok := set[ev[i].Event]; ok && ev[i].IMR == 3 {
			ev[i].EventPayload, ev[i].Digest = p, ""
		}
	}
	rt, err := tdx.ReplayRTMR3(ev)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(ev)
	q["event_log"] = string(b)
	out, _ := json.Marshal(q)
	return patchQuote(t, out, offRTMR3, rt.RTMR3)
}

func mustJSON(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}

func sum(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// kmsComposeYAML is a key service compose (cmd/compose's kms-compose.yaml shape).
const kmsComposeYAML = `services:
  kmsd:
    image: ghcr.io/tacyhq/tacy/kmsd@sha256:1111111111111111111111111111111111111111111111111111111111111111
    entrypoint: ["/tacy/kmsd"]
    command: ["-listen", ":8000", "-admin-keys", "ed25519:AAAA"]
    restart: unless-stopped
    user: "10005:10005"
    read_only: true
    cap_drop: [ALL]
    security_opt: ["no-new-privileges:true"]
    ports:
      - "8000:8000"
    volumes:
      - /var/run/dstack.sock:/var/run/dstack.sock
    logging:
      driver: none
    mem_limit: 512m
    memswap_limit: 512m
`

// rig is one test's world: admin, Worker and share holder keys, the VM's and the KMS's recorded evidence, a clock and
// the policy.
type rig struct {
	t          *testing.T
	mu         sync.Mutex
	now        time.Time
	adminPub   ed25519.PublicKey
	admin      ed25519.PrivateKey
	workerPub  ed25519.PublicKey
	worker     ed25519.PrivateKey
	recips     []*ecdh.PrivateKey
	vm         *evidence       // the agent VM (the recording)
	kmsEv      *evidence       // the key service replicas (the recording with a KMS compose)
	standbyEv  *evidence       // a standby replica (the same with -role standby)
	kmsCompose string          // the primary's compose (kmsComposeYAML with the rig's admin key)
	recQuote   json.RawMessage // as recorded
	vmQuote    json.RawMessage
	vmInfo     json.RawMessage
	vmACHash   string
	altQuote   json.RawMessage // a variant a test pins
	altInfo    json.RawMessage
	vmCompose  string
	recNonce   []byte
	policy     kms.Policy
	genesisEnv safety.Envelope
	logs       *logBuf
}

type logBuf struct {
	mu sync.Mutex
	b  strings.Builder
}

func (l *logBuf) logf(f string, a ...any) {
	l.mu.Lock()
	fmt.Fprintf(&l.b, f+"\n", a...)
	l.mu.Unlock()
}

func (l *logBuf) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

func newRig(t *testing.T) *rig {
	t.Helper()
	r := &rig{t: t, now: time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC), logs: &logBuf{}}
	r.adminPub, r.admin, _ = ed25519.GenerateKey(rand.Reader)
	r.workerPub, r.worker, _ = ed25519.GenerateKey(rand.Reader)
	for range 3 {
		k, _ := ecdh.P256().GenerateKey(rand.Reader)
		r.recips = append(r.recips, k)
	}
	a, nonce := load065(t)
	r.recNonce, r.recQuote = nonce, a.Quote
	ac, err := kms.AppCompose(a.Info)
	if err != nil {
		t.Fatalf("recording's app-compose: %v", err)
	}
	dc, _ := kms.DockerCompose(ac)
	r.vmCompose = releaseCompose(t, dc)
	r.vmInfo = a.Info
	r.vmQuote, r.vmInfo, r.vmACHash = r.variant(func(m map[string]any) { m["docker_compose_file"] = r.vmCompose })
	r.vm = &evidence{quote: r.vmQuote, info: r.vmInfo}
	// The key service: the same TD with the key service release's app-compose.json (KMSAppCompose: its compose on
	// port 8000, the fallback's settings); compose-hash and RTMR3 consistent.
	r.kmsCompose = strings.Replace(kmsComposeYAML, "ed25519:AAAA", kms.IDString(r.adminPub), 1)
	kac, err := KMSAppCompose([]byte(r.kmsCompose))
	if err != nil {
		t.Fatal(err)
	}
	r.kmsEv = &evidence{quote: editEvents(t, a.Quote, map[string]string{"compose-hash": sum(kac)}), info: setAppCompose(t, a.Info, kac)}
	sac, err := KMSAppCompose([]byte(strings.Replace(r.kmsCompose, `"-admin-keys"`, `"-role", "standby", "-admin-keys"`, 1)))
	if err != nil {
		t.Fatal(err)
	}
	r.standbyEv = &evidence{quote: editEvents(t, a.Quote, map[string]string{"compose-hash": sum(sac)}), info: setAppCompose(t, a.Info, sac)}
	r.policy = kms.Policy{Epoch: 1, Seq: 1, IssuedAt: r.now, Floor: "v0.19.0", KMSFallback: true,
		Apps: map[string]kms.AppPolicy{vmApp: {Firm: "f_chat", Purposes: []string{"state/v1", "activity-sign/v1", "task-ids/v1", "conn/v1"},
			Secrets: []string{"EXA_API_KEY", "TINFOIL_API_KEY"}}},
		Releases: []kms.ReleasePin{{App: vmApp, Version: vmRelease, ComposeSHA256: sum([]byte(r.vmCompose)), AppComposeSHA256: r.vmACHash}},
		KMS: []kms.ReleasePin{{App: "kms", Version: "v0.1.0", AppComposeSHA256: sum(kac), Role: kms.RolePrimary},
			{App: "kms", Version: "v0.1.0", AppComposeSHA256: sum(sac), Role: kms.RoleStandby}},
		WorkerKeys: []string{kms.IDString(r.workerPub)}}
	return r
}

func (r *rig) clock() time.Time {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.now
}

func (r *rig) advance(d time.Duration) {
	r.mu.Lock()
	r.now = r.now.Add(d)
	r.mu.Unlock()
}

func (r *rig) sign(kind string, v any, keys ...ed25519.PrivateKey) safety.Envelope {
	b, err := json.Marshal(v)
	if err != nil {
		r.t.Fatal(err)
	}
	if len(keys) == 0 {
		keys = []ed25519.PrivateKey{r.admin}
	}
	return safety.Sign(kind, b, keys...)
}

func (r *rig) policyEnv() safety.Envelope { return r.sign(kms.KindPolicy, r.policy) }

func (r *rig) config(pinned ed25519.PublicKey) Config {
	return Config{Admin: kms.AdminKeys{Keys: []ed25519.PublicKey{r.adminPub}, Threshold: 1}, KMSID: pinned,
		Platform: r.kmsEv, Now: r.clock, Logf: r.logs.logf, VerifyQuote: offline, AllowStaleTCB: true}
}

func (r *rig) server(pinned ed25519.PublicKey) *Server {
	s, err := New(r.config(pinned))
	if err != nil {
		r.t.Fatal(err)
	}
	return s
}

// standby is a standby replica pinned to the KMS id (its own compose, -role standby).
func (r *rig) standby(pinned ed25519.PublicKey) *Server {
	cfg := r.config(pinned)
	cfg.Role, cfg.Platform = kms.RoleStandby, r.standbyEv
	s, err := New(cfg)
	if err != nil {
		r.t.Fatal(err)
	}
	return s
}

func (r *rig) opts() CheckOptions { return CheckOptions{VerifyQuote: offline, AllowStaleTCB: true} }

// call sends one request through the HTTP handler; it returns the status and body.
func call(s *Server, method, path string, body any) (int, []byte) {
	var b []byte
	if body != nil {
		b, _ = json.Marshal(body)
	}
	req := httptest.NewRequest(method, "http://kms"+path, bytes.NewReader(b))
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	return w.Code, w.Body.Bytes()
}

func (r *rig) ok(s *Server, method, path string, body, out any) {
	r.t.Helper()
	code, b := call(s, method, path, body)
	if code != http.StatusOK {
		r.t.Fatalf("%s %s: %d %s", method, path, code, b)
	}
	if out != nil {
		if err := kms.Strict(b, out); err != nil {
			r.t.Fatalf("%s %s: %v", method, path, err)
		}
	}
}

// attestKMS is kmsctl's first step: the replica's attestation for a fresh nonce, checked against the KMS pins.
func (r *rig) attestKMS(s *Server) *Attested {
	r.t.Helper()
	n := make([]byte, 32)
	rand.Read(n)
	code, b := call(s, http.MethodGet, "/v1/attest?nonce="+hex.EncodeToString(n), nil)
	if code != http.StatusOK {
		r.t.Fatalf("attest: %d %s", code, b)
	}
	a, err := VerifyKMS(context.Background(), b, n, &r.policy, r.opts())
	if err != nil {
		r.t.Fatalf("replica attestation: %v", err)
	}
	return a
}

// genesis runs the ceremony on an empty replica: 2-of-3 to the rig's recipients.
func (r *rig) genesis(s *Server) *kms.GenesisReply {
	r.t.Helper()
	a := r.attestKMS(s)
	var recips []string
	for _, k := range r.recips {
		recips = append(recips, kms.RecipientString(k.PublicKey()))
	}
	doc := kms.GenesisDoc{Recipients: recips, Threshold: 2, AdminKeys: []string{kms.IDString(r.adminPub)}, AdminThreshold: 1,
		Floor: "v0.19.0", Target: hex.EncodeToString(a.Key.Bytes()), IssuedAt: r.clock()}
	r.genesisEnv = r.sign(kms.KindGenesis, doc)
	var rep kms.GenesisReply
	r.ok(s, http.MethodPost, "/v1/genesis", kms.GenesisRequest{Genesis: r.genesisEnv, Policy: r.policyEnv()}, &rep)
	id, err := kms.ParseID(rep.KMSID)
	if err != nil || !ed25519.Verify(id, kms.GenesisSigMessage(r.genesisEnv.Hash(), rep.Shares), rep.Sig) ||
		!ed25519.Verify(id, kms.CommitmentsSigMessage(rep.KMSID, rep.Epoch, rep.Commitments), rep.CommitSig) || len(rep.Commitments) != 3 {
		r.t.Fatalf("genesis reply isn't signed by its KMS id: %v", err)
	}
	// kmsctl genesis: the same policy bound to the new KMS id, loaded at once.
	r.policy.KMSID = rep.KMSID
	r.policy.Seq++
	var st kms.Status
	r.ok(s, http.MethodPost, "/v1/policy", r.policyEnv(), &st)
	return &rep
}

// unlockWith is kmsctl unlock for share i: open it on recipient i's key, reseal it at once to the replica's
// attested key.
func (r *rig) unlockWith(s *Server, rep *kms.GenesisReply, i int, first bool) (int, []byte) {
	r.t.Helper()
	sh := rep.Shares[i]
	y, err := kms.Open(r.recips[i], kms.LabelShare, kms.ShareAAD(sh.KMSID, sh.Index, sh.Epoch), sh.Sealed)
	if err != nil {
		r.t.Fatalf("share %d doesn't open on its recipient: %v", i, err)
	}
	a := r.attestKMS(s)
	box, err := kms.Seal(a.Key, kms.LabelUnlock, kms.ShareAAD(sh.KMSID, sh.Index, sh.Epoch), y)
	clear(y)
	if err != nil {
		r.t.Fatal(err)
	}
	req := kms.UnlockRequest{Index: sh.Index, Epoch: sh.Epoch, Share: box}
	if first {
		g, p := r.genesisEnv, r.policyEnv()
		req.Genesis, req.Policy, req.Commitments, req.CommitSig = &g, &p, rep.Commitments, rep.CommitSig
	}
	return call(s, http.MethodPost, "/v1/unlock", req)
}

func (r *rig) vmClient(s *Server, id ed25519.PublicKey, ev *evidence) *client.Client {
	r.t.Helper()
	c, err := client.New(client.Config{KMSID: id, Transport: client.Handler{H: s.Handler()}, Evidence: ev.Evidence,
		Release: vmRelease, Holder: "agentd", Now: r.clock})
	if err != nil {
		r.t.Fatal(err)
	}
	return c
}

// putSecrets is kmsctl secret put.
func (r *rig) putSecrets(s *Server, seq uint64, values map[string]string) kms.SecretsReply {
	r.t.Helper()
	a := r.attestKMS(s)
	env := r.sign(kms.KindSecrets, kms.SecretsDoc{KMSID: s.Status().KMSID, Epoch: 1, Seq: seq, Values: values, IssuedAt: r.clock()})
	b, _ := json.Marshal(env)
	box, err := kms.Seal(a.Key, kms.LabelSecretPut, []byte(s.Status().KMSID), b)
	if err != nil {
		r.t.Fatal(err)
	}
	var rep kms.SecretsReply
	r.ok(s, http.MethodPost, "/v1/secrets/put", kms.SecretsPut{Sealed: box}, &rep)
	return rep
}

// forbidden lists every encoding of b a leak would show as.
func encodings(b []byte) []string {
	return []string{hex.EncodeToString(b), base64.StdEncoding.EncodeToString(b), base64.RawStdEncoding.EncodeToString(b),
		base64.URLEncoding.EncodeToString(b), base64.RawURLEncoding.EncodeToString(b), string(b)}
}

// secretsOf is everything a reply or a log line must never show for this replica: M, the KMS id's seed, every
// key it can derive for the app and every secret value.
func secretsOf(t *testing.T, s *Server, values map[string]string) [][]byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.master == nil {
		return nil
	}
	out := [][]byte{s.master, s.id.Seed()}
	for _, p := range kms.Purposes {
		k, _ := kms.DeriveKey(s.master, vmApp, "f_chat", p, s.epoch)
		out = append(out, k)
	}
	sk, _ := kms.SecretsKey(s.master)
	out = append(out, sk)
	for _, l := range s.leases {
		if l.secret != nil {
			out = append(out, l.secret)
		}
	}
	for _, v := range values {
		out = append(out, []byte(v))
	}
	return out
}

func assertNoLeak(t *testing.T, what string, text []byte, secrets [][]byte) {
	t.Helper()
	if leaks(text, secrets) {
		t.Fatalf("%s carries key material", what)
	}
}

func leaks(text []byte, secrets [][]byte) bool {
	for _, sec := range secrets {
		for _, e := range encodings(sec) {
			if len(e) >= 8 && bytes.Contains(text, []byte(e)) {
				return true
			}
		}
	}
	return false
}
