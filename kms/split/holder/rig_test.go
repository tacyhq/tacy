package holder

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
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tacyhq/tacy/internal/tdx"
	"github.com/tacyhq/tacy/kms"
	"github.com/tacyhq/tacy/kms/client"
	"github.com/tacyhq/tacy/kms/server"
	"github.com/tacyhq/tacy/kms/split"
	"github.com/tacyhq/tacy/proto"
	"github.com/tacyhq/tacy/safety"
)

// The tests run the holders against a real recorded attestation, as kmsd's do (kms/server rig_test.go):
// testdata/attest-065-kms.json is a real /attest response from a throwaway CVM on dstack-0.6.5 (Phala, tdx.small,
// 2026-11-20) in the KMS fallback. The rig gives the agent VM a release compose with memory volumes, with the
// compose-hash event and RTMR3 the TD would have measured for it, and puts each asked report_data into the quote.
// The quote is parsed offline (tdx.Parse: no Intel chain); everything else the verifier checks runs on the
// recorded bytes.

const (
	vmApp     = "agent-vm"
	vmRelease = "v0.19.3"
)

const (
	offRTMR3      = 48 + 472
	offReportData = offRTMR3 + 48
)

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
type evidence struct{ quote, info json.RawMessage }

func (e *evidence) Evidence(_ context.Context, rd []byte) (json.RawMessage, json.RawMessage, error) {
	q, err := patch(e.quote, offReportData, rd)
	return q, e.info, err
}

func sum(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
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

// editEvents sets RTMR3 events (name -> payload) and puts the replayed RTMR3 into the quote.
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

// rig: the admin's admin key, M and its KMS id, one re-split across the holders, the holders, the VM.
type rig struct {
	t         *testing.T
	mu        sync.Mutex
	now       time.Time
	admin     ed25519.PrivateKey
	adminPub  ed25519.PublicKey
	master    []byte
	kmsID     string
	idPub     ed25519.PublicKey
	ids       []string
	threshold int
	keys      map[string]*ecdh.PrivateKey
	set       *split.SignedShareSet
	shares    map[string]split.HolderShare
	holders   map[string]*Holder
	nonceKeys map[string][]byte
	stores    map[string]*MemoryStore // each holder's durable policy store (kept across its instances)
	events    []Event
	recQuote  json.RawMessage
	recInfo   json.RawMessage
	vm        *evidence
	vmCompose string
	pol       split.UnlockPolicy
}

func newRig(t *testing.T, ids []string, threshold int) *rig {
	t.Helper()
	b, err := os.ReadFile("../../../testdata/attest-065-kms.json")
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
	r := &rig{t: t, now: time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC), ids: ids, threshold: threshold,
		keys: map[string]*ecdh.PrivateKey{}, shares: map[string]split.HolderShare{}, holders: map[string]*Holder{},
		nonceKeys: map[string][]byte{}, stores: map[string]*MemoryStore{}, recQuote: a.Quote, recInfo: a.Info}
	r.adminPub, r.admin, _ = ed25519.GenerateKey(rand.Reader)
	r.master = make([]byte, kms.MasterSize)
	rand.Read(r.master)
	id, _ := kms.DeriveID(r.master)
	r.idPub = id.Public().(ed25519.PublicKey)
	r.kmsID = kms.IDString(r.idPub)

	ac, err := kms.AppCompose(a.Info)
	if err != nil {
		t.Fatal(err)
	}
	dc, _ := kms.DockerCompose(ac)
	r.vmCompose = releaseCompose(t, dc)
	q, info, acHash := r.variant(func(m map[string]any) { m["docker_compose_file"] = r.vmCompose })
	r.vm = &evidence{quote: q, info: info}

	// The re-split (kmsctl resplit): each holder's key, its sealed share, the KMS-id-signed share set.
	var recips []split.HolderRecipient
	for i, h := range ids {
		var k *ecdh.PrivateKey
		if i%2 == 0 {
			k, _ = ecdh.X25519().GenerateKey(rand.Reader)
		} else {
			k, _ = ecdh.P256().GenerateKey(rand.Reader)
		}
		r.keys[h] = k
		recips = append(recips, split.HolderRecipient{Holder: h, Recipient: PublicKeyOf(k)})
	}
	set, shares, err := split.Resplit(r.master, r.kmsID, 1, 2, threshold, recips, r.now, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	r.set = set
	for _, s := range shares {
		r.shares[s.Holder] = s
	}
	cert, err := r.epochCert(1)
	if err != nil {
		t.Fatal(err)
	}
	r.pol = split.UnlockPolicy{
		Policy: kms.Policy{KMSID: r.kmsID, Epoch: 1, Seq: 5, IssuedAt: r.now.Add(-time.Hour), Floor: "v0.19.0", KMSFallback: true,
			Apps:     map[string]kms.AppPolicy{vmApp: {Firm: "f_chat", Purposes: []string{"state/v1", "activity-sign/v1", "task-ids/v1", "conn/v1"}}},
			Releases: []kms.ReleasePin{{App: vmApp, Version: vmRelease, ComposeSHA256: sum([]byte(r.vmCompose)), AppComposeSHA256: acHash}}},
		ShareSets: []split.SignedShareSet{*set}, EpochCerts: []split.SignedEpochCert{*cert}}
	for _, h := range ids {
		r.pol.Holders = append(r.pol.Holders, split.HolderURL{Holder: h, URL: "https://" + h + ".holder.test"})
	}
	for _, h := range ids {
		r.holders[h] = r.newHolder(h, nil)
	}
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

// variant is the release VM with its app-compose.json edited (quote and RTMR3 consistent).
func (r *rig) variant(edit func(map[string]any)) (json.RawMessage, json.RawMessage, string) {
	info, ac := editAppCompose(r.t, r.recInfo, edit)
	return editEvents(r.t, r.recQuote, map[string]string{"compose-hash": sum(ac)}), info, sum(ac)
}

func (r *rig) config(h string) Config {
	if r.nonceKeys[h] == nil {
		k := make([]byte, 32)
		rand.Read(k)
		r.nonceKeys[h] = k
	}
	if r.stores[h] == nil {
		r.stores[h] = &MemoryStore{}
		r.stores[h].Init(adminGen, 0)
	}
	return Config{ID: h, KMSID: r.kmsID, Admin: kms.AdminKeys{Keys: []ed25519.PublicKey{r.adminPub}, Threshold: 1},
		AdminGeneration: adminGen, Shares: []split.HolderShare{r.shares[h]}, Opener: KeyOpener{Key: r.keys[h]}, NonceKey: r.nonceKeys[h],
		Nonces: NewMemoryNonces(4096), Store: r.stores[h], NoPinDelay: true,
		Check: server.CheckOptions{VerifyQuote: offline, AllowStaleTCB: true}, Now: r.clock,
		Notify: func(e Event) { r.mu.Lock(); r.events = append(r.events, e); r.mu.Unlock() }}
}

// newHolder is holder h (a fresh instance: its own memory of used nonces); edit changes its config.
func (r *rig) newHolder(h string, edit func(*Config)) *Holder {
	cfg := r.config(h)
	if edit != nil {
		edit(&cfg)
	}
	x, err := New(cfg)
	if err != nil {
		r.t.Fatal(err)
	}
	return x
}

func (r *rig) sign(kind string, v any, keys ...ed25519.PrivateKey) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		r.t.Fatal(err)
	}
	if len(keys) == 0 {
		keys = []ed25519.PrivateKey{r.admin}
	}
	env, _ := json.Marshal(safety.Sign(kind, b, keys...))
	return env
}

func (r *rig) policyEnv() json.RawMessage { return r.sign(split.KindUnlockPolicy, r.pol) }

// otherKey is an Ed25519 key that isn't the admin's.
func (r *rig) otherKey() ed25519.PrivateKey {
	_, k, _ := ed25519.GenerateKey(rand.Reader)
	return k
}

// transports reach each holder through its HTTP handler; wrap may replace one.
func (r *rig) transports(wrap map[string]func(client.Transport) client.Transport) []split.Holder {
	var out []split.Holder
	for _, h := range r.ids {
		var t client.Transport = client.Handler{H: r.holders[h].Handler()}
		if w := wrap[h]; w != nil {
			t = w(t)
		}
		out = append(out, split.Holder{ID: h, Transport: t})
	}
	return out
}

func (r *rig) unlockConfig(holders []split.Holder, ev *evidence) split.Config {
	if ev == nil {
		ev = r.vm
	}
	return split.Config{KMSID: r.idPub, Admin: &kms.AdminKeys{Keys: []ed25519.PublicKey{r.adminPub}, Threshold: 1}, MinEpoch: 1,
		Policy: r.policyEnv(), Holders: holders, Evidence: ev.Evidence, Release: vmRelease, Timeout: 5 * time.Second, Now: r.clock}
}

func (r *rig) unlock(holders []split.Holder, ev *evidence) (*split.Root, *split.Report, error) {
	return split.Unlock(context.Background(), r.unlockConfig(holders, ev))
}

// mustMaster checks m is the rig's epoch-1 root (its derived keys equal those from R_1 = EpochRoot(M, 1)).
func (r *rig) mustMaster(m *split.Root) {
	r.t.Helper()
	r.mustEpoch(m, 1)
}

// mustEpoch checks m is the rig's root of epoch e.
func (r *rig) mustEpoch(m *split.Root, e uint32) {
	r.t.Helper()
	got, err := m.Key(vmApp, "f_chat", "state/v1")
	if err != nil {
		r.t.Fatal(err)
	}
	root, _ := split.EpochRoot(r.master, e)
	want, _ := split.RootKey(root, vmApp, "f_chat", "state/v1", e)
	if !bytes.Equal(got, want) || m.KMSID != r.kmsID || m.Epoch != e {
		r.t.Fatal("unlock rebuilt another key")
	}
	if _, err := m.StoreCert("state/v1"); err != nil {
		r.t.Fatal(err)
	}
}

// adminGen is the rig's admin-key generation.
const adminGen = "kms-admin-test"

// down is a holder that doesn't answer.
type down struct{}

func (down) Do(context.Context, string, string, []byte) ([]byte, error) {
	return nil, errors.New("connection refused")
}

// recorder keeps the last unlock request a transport carried.
type recorder struct {
	next client.Transport
	mu   sync.Mutex
	last []byte
}

func (c *recorder) Do(ctx context.Context, method, path string, body []byte) ([]byte, error) {
	if path == "/v1/unlock" {
		c.mu.Lock()
		c.last = bytes.Clone(body)
		c.mu.Unlock()
	}
	return c.next.Do(ctx, method, path, body)
}

// secrets are every encoding of M and each plaintext share: nothing a reply's metadata, a refusal or an event may
// show.
func (r *rig) secrets() []string {
	var raw [][]byte
	r1, _ := split.EpochRoot(r.master, 1)
	raw = append(raw, r.master, r1)
	for h, s := range r.shares {
		y, err := split.OpenHolderShare(r.keys[h], s)
		if err != nil {
			r.t.Fatal(err)
		}
		raw = append(raw, y)
	}
	var out []string
	for _, b := range raw {
		out = append(out, hex.EncodeToString(b), base64.StdEncoding.EncodeToString(b), base64.RawStdEncoding.EncodeToString(b), string(b))
	}
	return out
}

func (r *rig) assertNoLeak(what, text string) {
	r.t.Helper()
	for _, s := range r.secrets() {
		if len(s) >= 8 && strings.Contains(text, s) {
			r.t.Fatalf("%s carries key material", what)
		}
	}
}

// epochCert is epoch e's certificate, naming its witness key (kmsctl resplit names the activity signer too).
func (r *rig) epochCert(e uint32) (*split.SignedEpochCert, error) {
	root, _ := split.EpochRoot(r.master, e)
	wpub, err := split.WitnessPublic(root, vmApp, "f_chat", e)
	if err != nil {
		return nil, err
	}
	return split.NewEpochCert(r.master, r.kmsID, e, vmApp, "f_chat", map[string]string{split.WitnessPurpose: wpub}, r.now)
}
