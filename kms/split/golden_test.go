package split

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/tacyhq/tacy/kms"
	"github.com/tacyhq/tacy/safety"
)

// Golden vectors of the split-key wire contract (the split-key interfaces, the canonical contract), shared by every
// implementation: this test (Go: the core, the holders, unlockd) and the chat's split-golden.test.ts (TypeScript:
// the Worker and the clients) read testdata/golden/v1.json and check the same values. Everything deterministic is
// recomputed and compared; what carries randomness (the share set's shares, HPKE) is checked by its signature and
// shape. Regenerate only on a deliberate contract change: go test ./kms/split -run Golden -update.

var updateGolden = flag.Bool("update", false, "rewrite testdata/golden/v1.json")

// golden is the vector file.
type golden struct {
	Note           string          `json:"note"`
	Master         string          `json:"master_hex"` // test M (never a real key)
	KMSID          string          `json:"kms_id"`
	Epoch          uint32          `json:"epoch"`
	EpochRoot      string          `json:"epoch_root_hex"`
	RootID         string          `json:"root_id"`
	AdminSeed      string          `json:"admin_seed_hex"`
	AdminKey       string          `json:"admin_key"`
	Release        kms.ReleasePin  `json:"release"`
	ReleaseItem    string          `json:"release_item"`
	PolicyEnvelope json.RawMessage `json:"policy_envelope"` // safety.Envelope, kind kms-unlock-policy
	PolicyHash     string          `json:"policy_hash"`
	PolicyItems    []string        `json:"policy_items"`
	OtherItem      string          `json:"other_item"`
	Nonces         []HolderNonce   `json:"nonces"`
	Bound          string          `json:"bound_hex"`
	ReplyAAD       struct {
		KMSID      string `json:"kms_id"`
		Epoch      uint32 `json:"epoch"`
		Set        uint32 `json:"set"`
		Holder     string `json:"holder"`
		Index      byte   `json:"index"`
		PolicyHash string `json:"policy_hash"`
		Head       string `json:"head_hex"`
		AAD        string `json:"aad_hex"`
	} `json:"reply_aad"`
	Commitment struct {
		Share string `json:"share_hex"`
		Value string `json:"value"`
	} `json:"commitment"`
	TicketSeed     string          `json:"ticket_seed_hex"`
	TicketEnvelope json.RawMessage `json:"ticket_envelope"` // safety.Envelope, kind vm-start-ticket
	TicketClaim    string          `json:"ticket_claim"`    // "ticket:" + sha256(payload)
	EpochCert      SignedEpochCert `json:"epoch_cert"`
	ShareSet       SignedShareSet  `json:"share_set"` // random shares: checked by signature and shape
}

func seed(label string) []byte { h := sha256.Sum256([]byte("tacy golden v1: " + label)); return h[:] }

func makeGolden(t *testing.T) *golden {
	g := &golden{Note: "split-key wire contract vectors, v1; test keys only", Epoch: 1}
	m := seed("master")
	g.Master = hex.EncodeToString(m)
	id, _ := kms.DeriveID(m)
	g.KMSID = kms.IDString(id.Public().(ed25519.PublicKey))
	r1, _ := EpochRoot(m, 1)
	g.EpochRoot = hex.EncodeToString(r1)
	g.RootID, _ = RootID(r1)
	as := seed("admin")[:32]
	g.AdminSeed = hex.EncodeToString(as)
	admin := ed25519.NewKeyFromSeed(as)
	g.AdminKey = kms.IDString(admin.Public().(ed25519.PublicKey))
	at := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)

	g.Release = kms.ReleasePin{App: "agent-vm", Version: "v0.22.0", ComposeSHA256: hex.EncodeToString(seed("compose")),
		AppComposeSHA256: hex.EncodeToString(seed("app-compose"))}
	g.ReleaseItem = ReleaseItem(g.Release)

	cert, err := NewEpochCert(m, g.KMSID, 1, "agent-vm", "f_chat", map[string]string{"activity-sign/v1": "ed25519:" + base64.StdEncoding.EncodeToString(seed("activity")[:32])}, at)
	if err != nil {
		t.Fatal(err)
	}
	g.EpochCert = *cert
	k1, _ := ecdh.X25519().NewPrivateKey(seed("holder cloudflare"))
	k2, _ := ecdh.X25519().NewPrivateKey(seed("holder vercel"))
	ss, _, err := Resplit(m, g.KMSID, 1, 2, 2, []HolderRecipient{{Holder: "cloudflare", Recipient: RecipientString(k1.PublicKey())},
		{Holder: "vercel", Recipient: RecipientString(k2.PublicKey())}}, at, bytes.NewReader(bytes.Repeat(seed("split"), 4)))
	if err != nil {
		t.Fatal(err)
	}
	g.ShareSet = *ss
	pol := UnlockPolicy{Policy: kms.Policy{KMSID: g.KMSID, Epoch: 1, Seq: 7, IssuedAt: at, Floor: "v0.21.0",
		Apps:     map[string]kms.AppPolicy{"agent-vm": {Firm: "f_chat", Purposes: []string{"state/v1", "activity-sign/v1", "task-ids/v1", "conn/v1"}}},
		Releases: []kms.ReleasePin{g.Release}},
		Holders:   []HolderURL{{Holder: "cloudflare", URL: "https://keys-cf.tacy.io"}, {Holder: "vercel", URL: "https://keys-v.tacy.io"}},
		ShareSets: []SignedShareSet{*ss}, EpochCerts: []SignedEpochCert{*cert}}
	payload, _ := json.Marshal(pol)
	env, _ := json.Marshal(safety.Sign(KindUnlockPolicy, payload, admin))
	g.PolicyEnvelope = env
	g.PolicyHash = PolicyHash(payload)
	g.PolicyItems = PolicyItems(&pol)
	g.OtherItem = OtherItem(&pol)

	g.Nonces = []HolderNonce{{Holder: "cloudflare", Nonce: hex.EncodeToString(seed("nonce cloudflare"))},
		{Holder: "vercel", Nonce: hex.EncodeToString(seed("nonce vercel"))}}
	b, _ := Bind(g.Nonces)
	g.Bound = hex.EncodeToString(b)
	head := []byte(`{"doc":"","sig":""}`)
	g.ReplyAAD.KMSID, g.ReplyAAD.Epoch, g.ReplyAAD.Set, g.ReplyAAD.Holder, g.ReplyAAD.Index = g.KMSID, 1, 2, "vercel", 2
	g.ReplyAAD.PolicyHash, g.ReplyAAD.Head = g.PolicyHash, hex.EncodeToString(head)
	g.ReplyAAD.AAD = hex.EncodeToString(ReplyAAD(b, g.KMSID, 1, 2, "vercel", 2, g.PolicyHash, head))
	g.Commitment.Share = hex.EncodeToString(seed("share"))
	g.Commitment.Value = Commitment(g.KMSID, 1, 2, "vercel", 2, seed("share"))

	ts := seed("worker ticket key")[:32]
	g.TicketSeed = hex.EncodeToString(ts)
	tp, _ := json.Marshal(StartTicket{KMSID: g.KMSID, AppID: hex.EncodeToString(seed("app id")[:20]), IssuedAt: at})
	tenv, _ := json.Marshal(safety.Sign(KindStartTicket, tp, ed25519.NewKeyFromSeed(ts)))
	g.TicketEnvelope = tenv
	th := sha256.Sum256(tp)
	g.TicketClaim = "ticket:" + hex.EncodeToString(th[:])
	return g
}

func TestGolden(t *testing.T) {
	path := filepath.Join("testdata", "golden", "v1.json")
	fresh := makeGolden(t)
	if *updateGolden {
		b, _ := json.MarshalIndent(fresh, "", "  ")
		os.MkdirAll(filepath.Dir(path), 0o755)
		if err := os.WriteFile(path, append(b, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run with -update once)", err)
	}
	var g golden
	if err := kms.Strict(raw, &g); err != nil {
		t.Fatal(err)
	}
	// Deterministic values: recomputed now, they must equal the file's.
	for name, pair := range map[string][2]any{
		"kms_id": {g.KMSID, fresh.KMSID}, "epoch_root": {g.EpochRoot, fresh.EpochRoot}, "root_id": {g.RootID, fresh.RootID},
		"admin_key": {g.AdminKey, fresh.AdminKey}, "release_item": {g.ReleaseItem, fresh.ReleaseItem},
		"bound": {g.Bound, fresh.Bound}, "reply_aad": {g.ReplyAAD.AAD, fresh.ReplyAAD.AAD}, "commitment": {g.Commitment.Value, fresh.Commitment.Value},
		"ticket_envelope": {envKey(g.TicketEnvelope), envKey(fresh.TicketEnvelope)}, "ticket_claim": {g.TicketClaim, fresh.TicketClaim},
		"epoch_cert": {string(g.EpochCert.Doc), string(fresh.EpochCert.Doc)},
	} {
		if pair[0] != pair[1] {
			t.Errorf("%s changed: %v, now %v (a contract change? then -update and tell every branch)", name, pair[0], pair[1])
		}
	}
	// The file's documents verify as the contract says.
	id, _ := kms.ParseID(g.KMSID)
	ss, err := g.ShareSet.Open(id)
	if err != nil || ss.Root != g.RootID || ss.Threshold != 2 {
		t.Fatalf("share set: %v", err)
	}
	if _, err := g.EpochCert.Open(id); err != nil {
		t.Fatal(err)
	}
	var env safety.Envelope
	kms.Strict(g.PolicyEnvelope, &env)
	adminPub, _ := kms.ParseID(g.AdminKey)
	var pol UnlockPolicy
	if err := (kms.AdminKeys{Keys: []ed25519.PublicKey{adminPub}, Threshold: 1}).Open(&env, KindUnlockPolicy, &pol); err != nil {
		t.Fatal(err)
	}
	if PolicyHash(env.Payload) != g.PolicyHash || OtherItem(&pol) != g.OtherItem {
		t.Fatal("the policy's hash or catch-all item")
	}
	items := PolicyItems(&pol)
	if len(items) != len(g.PolicyItems) {
		t.Fatalf("items %v, file %v", items, g.PolicyItems)
	}
	for i := range items {
		if items[i] != g.PolicyItems[i] {
			t.Fatalf("items %v, file %v", items, g.PolicyItems)
		}
	}
	if _, err := pol.OpenShareSets(id); err != nil {
		t.Fatal(err)
	}
	var tenv safety.Envelope
	kms.Strict(g.TicketEnvelope, &tenv)
	var tk StartTicket
	if err := kms.Strict(tenv.Payload, &tk); err != nil || tk.KMSID != g.KMSID {
		t.Fatalf("ticket: %v", err)
	}
}

// envKey is an envelope's payload and signatures (its JSON's whitespace aside).
func envKey(raw json.RawMessage) string {
	var e safety.Envelope
	json.Unmarshal(raw, &e)
	b, _ := json.Marshal(e)
	return string(b)
}
