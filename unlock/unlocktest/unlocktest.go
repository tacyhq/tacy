// Package unlocktest is a test world for the VM's side of the split-key unlock (the keys plan §11.2): a development split
// key (kms/split/splitdev: dev KMS id, dev admin key, the epoch root R_e split across real holders from
// kms/split/holder, each behind its own handler) and an agent VM whose attestation is a real recorded one. Tests of
// unlockd (package unlock), agentd and vaultd use it; nothing in the VM's binaries imports it.
//
// The recording is testdata/attest-065-kms.json, a real /attest response from a throwaway CVM on dstack-0.6.5
// (Phala, tdx.small, 2026-11-20) in the KMS fallback, as the holders' own tests use it: the VM gets a release
// compose with memory volumes, the compose-hash event and RTMR3 the TD would have measured for it, and each asked
// report_data is put into the quote. The quote is parsed offline (tdx.Parse: no Intel chain); everything else the
// holders' verifier checks runs on the recorded bytes.
package unlocktest

import (
	"context"
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tacyhq/tacy/internal/tdx"
	"github.com/tacyhq/tacy/kms"
	"github.com/tacyhq/tacy/kms/server"
	"github.com/tacyhq/tacy/kms/split"
	"github.com/tacyhq/tacy/kms/split/holder"
	"github.com/tacyhq/tacy/kms/split/splitdev"
	"github.com/tacyhq/tacy/proto"
	"github.com/tacyhq/tacy/safety"
)

// The VM's app, release and firm in the world's policy.
const (
	App     = splitdev.App
	Firm    = splitdev.Firm
	Release = "v0.22.0"
)

const (
	offRTMR3      = 48 + 472
	offReportData = offRTMR3 + 48
)

// World is the split-key world.
type World struct {
	*splitdev.Dev
	t       testing.TB
	mu      sync.Mutex
	now     time.Time
	IDs     []string
	Holders map[string]*holder.Holder
	// VM is the release VM's evidence (its dstack); VMCompose its docker compose; AppComposeSHA256 the attested
	// hash the policy pins.
	VM               *Evidence
	VMCompose        string
	AppComposeSHA256 string
	recQuote         json.RawMessage
	recInfo          json.RawMessage
	// Secrets are the app's API keys in SecretsBundle.
	Secrets map[string]string
	events  []holder.Event
}

// Testdata is the module's testdata directory.
func Testdata() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "..", "testdata")
}

// New makes a world with holders ids and a threshold-of-len(ids) split. It skips the test when the recording
// isn't there.
func New(t testing.TB, ids []string, threshold int) *World {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(Testdata(), "attest-065-kms.json"))
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
	now := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	d, err := splitdev.New(ids, threshold, now.Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	w := &World{Dev: d, t: t, now: now, IDs: ids, Holders: map[string]*holder.Holder{}, recQuote: a.Quote, recInfo: a.Info,
		Secrets: map[string]string{"TINFOIL_API_KEY": "tinfoil-canary-0a9b8c7d6e5f4a3b", "EXA_API_KEY": "exa-canary-5f1e2d3c4b5a6978",
			"TAVILY_API_KEY": "tvly-canary-1122334455667788"}}
	ac, err := kms.AppCompose(a.Info)
	if err != nil {
		t.Fatal(err)
	}
	dc, _ := kms.DockerCompose(ac)
	w.VMCompose = releaseCompose(t, dc)
	q, info, acHash := w.Variant(func(m map[string]any) { m["docker_compose_file"] = w.VMCompose })
	w.VM, w.AppComposeSHA256 = &Evidence{Quote: q, Info: info}, acHash
	d.Policy.KMSFallback, d.Policy.Seq, d.Policy.Floor = true, 5, "v0.19.0"
	d.AddRelease(Release, acHash, sum([]byte(w.VMCompose)))
	for i := range d.Policy.Holders {
		d.Policy.Holders[i].URL = "https://" + HolderHost(d.Policy.Holders[i].Holder)
	}
	for _, h := range ids {
		w.Holders[h] = w.NewHolder(h, nil)
	}
	return w
}

// Now is the world's clock.
func (w *World) Now() time.Time {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.now
}

// Advance moves the clock.
func (w *World) Advance(d time.Duration) {
	w.mu.Lock()
	w.now = w.now.Add(d)
	w.mu.Unlock()
}

// HolderEvents are the holders' events so far.
func (w *World) HolderEvents() []holder.Event {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]holder.Event(nil), w.events...)
}

// Variant is the release VM with its app-compose.json edited (quote and RTMR3 consistent): its quote, info and
// app-compose hash.
func (w *World) Variant(edit func(map[string]any)) (json.RawMessage, json.RawMessage, string) {
	info, ac := editAppCompose(w.t, w.recInfo, edit)
	return editEvents(w.t, w.recQuote, map[string]string{"compose-hash": sum(ac)}), info, sum(ac)
}

// NewHolder is holder h as the world deploys it (a fresh instance: its own memory of nonces and seqs); edit changes
// its config.
func (w *World) NewHolder(h string, edit func(*holder.Config)) *holder.Holder {
	cfg := w.HolderConfig(h)
	cfg.Check = server.CheckOptions{VerifyQuote: offline, AllowStaleTCB: true}
	cfg.Now = w.Now
	cfg.Notify = func(e holder.Event) { w.mu.Lock(); w.events = append(w.events, e); w.mu.Unlock() }
	if edit != nil {
		edit(&cfg)
	}
	x, err := holder.New(cfg)
	if err != nil {
		w.t.Fatal(err)
	}
	return x
}

// PolicyEnv is the world's unlock policy, signed with the dev admin key.
func (w *World) PolicyEnv() json.RawMessage {
	b, err := w.SignPolicy()
	if err != nil {
		w.t.Fatal(err)
	}
	return b
}

// SignWith signs v as kind with another key (a forged document).
func SignWith(kind string, v any, key []byte) json.RawMessage {
	b, _ := json.Marshal(v)
	env, _ := json.Marshal(safety.Sign(kind, b, key))
	return env
}

// SecretsBundle is the epoch's secrets.sealed for the world's secrets (seq), as kmsctl secrets-seal makes it.
func (w *World) SecretsBundle(seq uint64) []byte {
	b, err := split.SealSecrets(w.Root, split.SecretsBundle{KMSID: w.KMSID, Epoch: w.Epoch, Seq: seq, Values: w.Secrets})
	if err != nil {
		w.t.Fatal(err)
	}
	return b
}

// Handler is holder h's HTTP handler (what the VM reaches through gatewayd).
func (w *World) Handler(h string) http.Handler { return w.Holders[h].Handler() }

// Key is the key R_e derives for the app and purpose (what the VM must end up with).
func (w *World) Key(purpose string) []byte {
	k, err := split.RootKey(w.Root, App, Firm, purpose, w.Epoch)
	if err != nil {
		w.t.Fatal(err)
	}
	return k
}

// Forbidden is every encoding of M, R_e, each plaintext share, the KMS id's seed and each secret value: nothing a
// reply's metadata, a refusal, a status or a report may show.
func (w *World) Forbidden() []string {
	raw := [][]byte{w.Master, w.Root}
	for h, s := range w.Shares {
		y, err := split.OpenHolderShare(w.Keys[h], s)
		if err != nil {
			w.t.Fatal(err)
		}
		raw = append(raw, y)
	}
	id, _ := kms.DeriveID(w.Master)
	raw = append(raw, id.Seed())
	var out []string
	for _, b := range raw {
		out = append(out, hex.EncodeToString(b), base64.StdEncoding.EncodeToString(b), base64.RawStdEncoding.EncodeToString(b),
			base64.URLEncoding.EncodeToString(b), base64.RawURLEncoding.EncodeToString(b), string(b))
	}
	for _, v := range w.Secrets {
		out = append(out, v)
	}
	return out
}

// HolderKey is holder h's private key (tests that open its share).
func (w *World) HolderKey(h string) *ecdh.PrivateKey { return w.Keys[h] }

// Evidence is a TD's dstack: it puts the asked report_data into its (recorded) quote.
type Evidence struct{ Quote, Info json.RawMessage }

// Evidence implements client.Evidence.
func (e *Evidence) Evidence(_ context.Context, rd []byte) (json.RawMessage, json.RawMessage, error) {
	q, err := patch(e.Quote, offReportData, rd)
	return q, e.Info, err
}

func offline(_ context.Context, raw []byte) (*tdx.Quote, error) { return tdx.Parse(raw) }

// SHA256 is sha256(b), hex.
func SHA256(b []byte) string { return sum(b) }

func sum(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
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

func editEvents(t testing.TB, quote json.RawMessage, set map[string]string) json.RawMessage {
	t.Helper()
	var q map[string]any
	json.Unmarshal(quote, &q)
	b, _ := json.Marshal(q["event_log"])
	ev, err := tdx.ParseEventLog(b)
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
	eb, _ := json.Marshal(ev)
	q["event_log"] = string(eb)
	out, _ := json.Marshal(q)
	out, err = patch(out, offRTMR3, rt.RTMR3)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// releaseCompose is the recording's compose as a release has it: no diag service, every named volume in memory.
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
