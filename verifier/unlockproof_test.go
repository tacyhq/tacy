package verifier

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/tacyhq/tacy/activity"
	"github.com/tacyhq/tacy/internal/tdx"
	"github.com/tacyhq/tacy/kms"
	"github.com/tacyhq/tacy/kms/split"
	"github.com/tacyhq/tacy/proto"
	"github.com/tacyhq/tacy/safety"
	"github.com/tacyhq/tacy/unlock"
)

// Registry mode by proof of unlock (unlockproof.go; gcp-prod review H1, design review H1-1). A verifier behind a
// relay (EndorsementsOnly: the WASM, the chat Worker's own check) takes a registry-mode machine certificate only
// with the VM's unlock proof: agentd's HPKE key signed with the epoch's activity signer (unlock.NewUnlockProof, the
// VM's own code), which the KMS id's epoch certificate names. The registry is never read there.

// proofEpoch is a test key epoch: its KMS id (M's), its epoch root's activity signer and signed epoch certificate.
type proofEpoch struct {
	kmsID  string
	epoch  uint32
	signer *activity.Signer
	cert   json.RawMessage
}

func newProofEpoch(t *testing.T, epoch uint32) *proofEpoch {
	t.Helper()
	m := make([]byte, kms.MasterSize)
	rand.Read(m)
	id, err := kms.DeriveID(m)
	if err != nil {
		t.Fatal(err)
	}
	kmsID := kms.IDString(id.Public().(ed25519.PublicKey))
	root, err := split.EpochRoot(m, epoch)
	if err != nil {
		t.Fatal(err)
	}
	// As kmsctl's ceremony makes it (cmd/kmsctl epochCert) and agentd derives it (app/state.go).
	k, err := split.RootKey(root, "agent-vm", "f_chat", signerPurpose, epoch)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := activity.DeriveSigner(k, "f_chat")
	if err != nil {
		t.Fatal(err)
	}
	sc, err := split.NewEpochCert(m, kmsID, epoch, "agent-vm", "f_chat", map[string]string{signerPurpose: signer.Public()}, listNow)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(sc)
	return &proofEpoch{kmsID: kmsID, epoch: epoch, signer: signer, cert: b}
}

// proof is what the VM serves for att (its key and info).
func (e *proofEpoch) proof(t *testing.T, att *proto.Attestation) *proto.UnlockProof {
	t.Helper()
	key, _ := hex.DecodeString(att.HPKEPublicKey)
	pr, err := unlock.NewUnlockProof(e.signer.SignLabeled, e.cert, e.kmsID, e.epoch, key, att.Info)
	if err != nil {
		t.Fatal(err)
	}
	return pr
}

// proofCase is a recorded genuine Google quote (c3-standard-4) as a registry-mode VM of a stated project, instance
// and zone (MR_OWNER set to that PZID: the recordings have none of ours), verified as the WASM does (through a relay).
type proofCase struct {
	a     *proto.Attestation
	nonce []byte
	p     Policy
	g     *registryFiles
	reg   safety.Machine
	e     *proofEpoch
}

func newProofCase(t *testing.T) *proofCase {
	t.Helper()
	a, nonce, p, _ := gcpPolicy(t, gcpRecordings[0])
	q0, _ := tdx.Parse(rawQuote(t, a))
	e := newProofEpoch(t, 1)
	// The recording's app names no Tacy KMS; an agent VM's compose does (-kms-key), and the proof must be of that
	// KMS id's epoch. So the recorded app-compose gets the test KMS id in its command (the edit made consistent:
	// RTMR3's compose-hash event, the policy's compose and pin), as an agent VM release has it.
	appCompose := withKMSKey(t, a, e.kmsID)
	rtmr3 := recompose(t, a, appCompose)
	var ac struct {
		DockerCompose string `json:"docker_compose_file"`
	}
	json.Unmarshal(appCompose, &ac)
	p.Compose, p.AppCompose = []byte(ac.DockerCompose), appCompose
	const project, instance, zone = "123456789012", "4815162342", "us-central1-a"
	digest := sha512.Sum384([]byte(fmt.Sprintf(`{"instanceId":%s,"numericalProjectId":%s,"zone":"%s"}`, instance, project, zone)))
	inner := p.VerifyQuote
	p.VerifyQuote = func(ctx context.Context, b []byte) (*tdx.Quote, error) {
		x, err := inner(ctx, b)
		if x != nil {
			x.MrOwner = hex.EncodeToString(digest[:])
			x.Rtmrs[3] = rtmr3
		}
		return x, err
	}
	// The values a real VM's dstack Info has (the recordings' test app has no instance-id event: its attested
	// instance id is empty, so the Info says the same).
	var info map[string]any
	json.Unmarshal(a.Info, &info)
	info["gce_instance_id"], info["gce_zone"], info["instance_id"] = instance, zone, ""
	a.Info, _ = json.Marshal(info)
	doc := safety.MachineDoc{Type: safety.MachineType, Platform: "dstack", Host: safety.MachineHostGoogle, Mode: safety.MachineModeRegistry,
		FMSPC: q0.FMSPC, ProjectNumber: project, Label: "gcp c3 (registry)", IssuedAt: listNow}
	h, _ := safety.MachineDocHash(doc)
	reg := safety.Machine{Doc: doc, Hash: h, Source: "test"}
	// The registry document is there: a verifier that read it would pass. Through the relay it is never read.
	g := &registryFiles{doc: `{"timestamp":"2026-11-20T21:53:55Z","zone":"us-central1-a"}`, inner: p.GoogleGetter}
	p.GoogleGetter = EndorsementsOnly(g)
	p.Machines = &safety.MachineSet{Machines: []safety.Machine{reg}, Revoked: map[string]bool{}}
	p.KMSIDs = map[string]string{e.kmsID: "test KMS"}
	return &proofCase{a: a, nonce: nonce, p: p, g: g, reg: reg, e: e}
}

// withKMSKey is a's app-compose.json with "-kms-key <id>" added to its service's command, set in a's info.
func withKMSKey(t *testing.T, a *proto.Attestation, id string) []byte {
	t.Helper()
	var info map[string]any
	json.Unmarshal(a.Info, &info)
	var tcb map[string]any
	json.Unmarshal([]byte(info["tcb_info"].(string)), &tcb)
	var ac map[string]any
	json.Unmarshal([]byte(tcb["app_compose"].(string)), &ac)
	dc := ac["docker_compose_file"].(string)
	if !strings.HasSuffix(dc, "serve_forever()\n") {
		t.Fatalf("the recording's compose changed: %q", dc[len(dc)-40:])
	}
	ac["docker_compose_file"] = dc + "      - -kms-key\n      - " + id + "\n"
	b, _ := json.Marshal(ac)
	setAppComposeRaw(t, a, b)
	return b
}

func (c *proofCase) verify() (*Result, error) {
	return Verify(context.Background(), c.a, c.nonce, c.p)
}

func TestUnlockProofAcceptsRegistryVM(t *testing.T) {
	c := newProofCase(t)
	c.a.UnlockProof = c.e.proof(t, c.a)
	res, err := c.verify()
	if err != nil {
		t.Fatalf("a registry VM with its unlock proof, through the relay: %v", err)
	}
	if c.g.asked != "" {
		t.Fatalf("the registry was read through the relay: %q", c.g.asked)
	}
	if countCheck(res, UnlockProofCheck) != 1 || countCheck(res, MachineCheck) != 1 {
		t.Fatalf("checks: %+v", res.Checks)
	}
	if f := res.Facts[FactMachine]; !strings.Contains(f, "by both key holders (unlock proof, epoch 1)") || !strings.Contains(f, "host Google: not defended") {
		t.Fatalf("machine fact %q", f)
	}
	// The proof doesn't replace MR_OWNER: another project's VM with a valid proof is refused.
	inner := c.p.VerifyQuote
	c.p.VerifyQuote = func(ctx context.Context, b []byte) (*tdx.Quote, error) {
		x, err := inner(ctx, b)
		if x != nil {
			x.MrOwner = strings.Repeat("00", 48)
		}
		return x, err
	}
	res, err = c.verify()
	mustRefuse(t, "another project's VM, with a proof", res, err, "MR_OWNER isn't this project's PZID")
}

// Each way a proof can be wrong is refused, with the machine check (the proof's signature and certificate) or the
// binding check after the compose (what the proof names against what the quote attests).
func TestUnlockProofRefusals(t *testing.T) {
	for _, tc := range []struct {
		name    string
		mutate  func(t *testing.T, c *proofCase)
		binding bool // refused at the binding check, not the machine check
		want    string
	}{
		{"no proof", func(t *testing.T, c *proofCase) { c.a.UnlockProof = nil }, false, "has no unlock proof"},
		{"another boot's key (a copied proof)", func(t *testing.T, c *proofCase) {
			other := *c.a
			k := make([]byte, 32)
			rand.Read(k)
			other.HPKEPublicKey = hex.EncodeToString(k)
			c.a.UnlockProof = c.e.proof(t, &other)
		}, false, "over this VM's key"},
		{"an unpinned KMS id's epoch", func(t *testing.T, c *proofCase) {
			c.a.UnlockProof = newProofEpoch(t, 1).proof(t, c.a)
		}, false, "isn't a pinned one"},
		{"a certificate not signed by its KMS id", func(t *testing.T, c *proofCase) {
			pr := c.e.proof(t, c.a)
			var sc split.SignedEpochCert
			json.Unmarshal(pr.EpochCert, &sc)
			sc.Sig[0] ^= 1
			pr.EpochCert, _ = json.Marshal(sc)
			c.a.UnlockProof = pr
		}, false, "isn't signed by its KMS id"},
		{"signed by a key the certificate doesn't name", func(t *testing.T, c *proofCase) {
			seed := make([]byte, 32)
			rand.Read(seed)
			s, _ := activity.NewSigner(seed)
			key, _ := hex.DecodeString(c.a.HPKEPublicKey)
			pr, _ := unlock.NewUnlockProof(s.SignLabeled, c.e.cert, c.e.kmsID, c.e.epoch, key, c.a.Info)
			c.a.UnlockProof = pr
		}, false, "over this VM's key"},
		{"a field changed after signing", func(t *testing.T, c *proofCase) {
			pr := c.e.proof(t, c.a)
			pr.InstanceID = "00"
			c.a.UnlockProof = pr
		}, false, "over this VM's key"},
		{"another epoch's certificate (the signature names epoch 1)", func(t *testing.T, c *proofCase) {
			pr := c.e.proof(t, c.a)
			pr.EpochCert = newProofEpochSameKMS(t, c, 2)
			c.a.UnlockProof = pr
		}, false, "over this VM's key"},
		{"another app id", func(t *testing.T, c *proofCase) {
			c.a.UnlockProof = c.e.proof(t, proofInfo(t, c.a, "app_id", strings.Repeat("ab", 20)))
		}, true, "the proof is for app id"},
		{"another instance", func(t *testing.T, c *proofCase) {
			c.a.UnlockProof = c.e.proof(t, proofInfo(t, c.a, "instance_id", strings.Repeat("cd", 20)))
		}, true, "the proof is for instance"},
		{"another pinned KMS id than the compose names (a trust list's kms_ids)", func(t *testing.T, c *proofCase) {
			o := newProofEpoch(t, 1)
			c.p.KMSIDs[o.kmsID] = "added by a trust list"
			c.a.UnlockProof = o.proof(t, c.a)
		}, true, "the compose names"},
		{"a revoked registry certificate", func(t *testing.T, c *proofCase) {
			c.p.Machines.Revoked[c.reg.Hash] = true
		}, false, "has no machine certificate"},
		{"another GCE instance than MR_OWNER binds", func(t *testing.T, c *proofCase) {
			c.a.UnlockProof = c.e.proof(t, proofInfo(t, c.a, "gce_instance_id", "4815162343"))
		}, false, "the VM's MR_OWNER is for"},
		{"another zone than MR_OWNER binds", func(t *testing.T, c *proofCase) {
			c.a.UnlockProof = c.e.proof(t, proofInfo(t, c.a, "gce_zone", "us-central1-b"))
		}, false, "the VM's MR_OWNER is for"},
		{"another release (app-compose)", func(t *testing.T, c *proofCase) {
			c.a.UnlockProof = c.e.proof(t, proofOtherAppCompose(t, c.a))
		}, true, "the proof is for app-compose"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := newProofCase(t)
			c.a.UnlockProof = c.e.proof(t, c.a)
			tc.mutate(t, c)
			res, err := c.verify()
			if c.g.asked != "" {
				t.Fatalf("the registry was read through the relay: %q", c.g.asked)
			}
			if !tc.binding {
				mustRefuse(t, tc.name, res, err, tc.want)
				return
			}
			last := res.Checks[len(res.Checks)-1]
			if err == nil || last.Name != UnlockProofCheck || last.OK || !strings.Contains(last.Detail, tc.want) || res.HPKEPublicKey != nil {
				t.Fatalf("%s: want the binding check refused with %q: %+v, %v", tc.name, tc.want, last, err)
			}
		})
	}
}

// newProofEpochSameKMS is another epoch's certificate of c's KMS id: c's KMS id is M's, which the test doesn't keep,
// so it re-signs with a fresh M and pins that one instead (the proof was signed under c's epoch 1).
func newProofEpochSameKMS(t *testing.T, c *proofCase, epoch uint32) json.RawMessage {
	e := newProofEpoch(t, epoch)
	c.p.KMSIDs[e.kmsID] = "test KMS 2"
	return e.cert
}

func proofInfo(t *testing.T, a *proto.Attestation, k, v string) *proto.Attestation {
	t.Helper()
	var info map[string]any
	json.Unmarshal(a.Info, &info)
	info[k] = v
	o := *a
	o.Info, _ = json.Marshal(info)
	return &o
}

func proofOtherAppCompose(t *testing.T, a *proto.Attestation) *proto.Attestation {
	t.Helper()
	var info map[string]any
	json.Unmarshal(a.Info, &info)
	info["tcb_info"] = `{"app_compose":"{\"name\":\"another release\"}"}`
	o := *a
	o.Info, _ = json.Marshal(info)
	return &o
}

// The H1 scenario itself: a forged quote (an attestation key from a TDX machine Google doesn't list, so another
// PPID) on a registry-mode certificate, with a relay serving a fake registry document for it. Through the relay it
// is refused whatever the relay serves: the registry is never read, and the only proofs there are are genuine VMs',
// which name their own HPKE keys. The same quote is accepted by a verifier reading the (here, forged) registry
// directly, which is why only the holders, who read Google themselves, may do that.
func TestUnlockProofForgedQuote(t *testing.T) {
	c := newProofCase(t)
	genuine := c.e.proof(t, c.a) // a real VM's proof, for its own key
	inner := c.p.VerifyQuote
	c.p.VerifyQuote = func(ctx context.Context, b []byte) (*tdx.Quote, error) {
		x, err := inner(ctx, b)
		if x != nil {
			x.PPID = strings.Repeat("e1", 16) // the forger's machine
		}
		return x, err
	}
	forged := *c.a
	k := make([]byte, 32)
	rand.Read(k)
	forged.HPKEPublicKey = hex.EncodeToString(k) // the forger's key; report_data is the forger's to choose
	for _, pr := range []*proto.UnlockProof{nil, genuine} {
		forged.UnlockProof = pr
		res, err := Verify(context.Background(), &forged, c.nonce, c.p)
		if err == nil || res.HPKEPublicKey != nil {
			t.Fatalf("a forged quote with proof %v: accepted", pr != nil)
		}
		mc := machineCheck(res)
		if mc == nil || mc.OK || (!strings.Contains(mc.Detail, "has no unlock proof") && !strings.Contains(mc.Detail, "over this VM's key")) {
			t.Fatalf("forged quote, proof %v: %+v", pr != nil, mc)
		}
		if c.g.asked != "" {
			t.Fatalf("the registry was read through the relay: %q", c.g.asked)
		}
	}
	// What a forger can get past the check: a quote that binds the genuine VM's own HPKE key and claims exactly its
	// app id, instance and release (the proof's binding). That is the genuine VM's attestation in all but the signing
	// machine: what the client encrypts to only that VM can open, and it runs what the client was told.
	clone := *c.a
	clone.UnlockProof = genuine
	res, err := Verify(context.Background(), &clone, c.nonce, c.p)
	if err != nil || hex.EncodeToString(res.HPKEPublicKey) != c.a.HPKEPublicKey {
		t.Fatalf("the genuine VM's key and proof on a forged quote: %v", err)
	}
}

// The key holders read the registry themselves (no EndorsementsOnly): no proof is needed or looked at there, as
// before (TestGCPRegistryMode); a proof present changes nothing.
func TestUnlockProofNotForDirectReaders(t *testing.T) {
	c := newProofCase(t)
	c.p.GoogleGetter = c.g // straight to "Google"
	res, err := c.verify()
	if err != nil || c.g.asked == "" || countCheck(res, UnlockProofCheck) != 0 {
		t.Fatalf("direct registry read: %v, asked %q, checks %+v", err, c.g.asked, res.Checks)
	}
}

// Phala's path is unchanged: a Phala VM (ppid-mode certificate) through the relay passes with the same checks
// whether or not its attestation carries a proof, and no proof check is added.
func TestUnlockProofPhalaUnchanged(t *testing.T) {
	c, ok := phalaRecorded(t)
	if !ok {
		t.Fatal("the Phala release case must pass in full")
	}
	c.p.GoogleGetter = EndorsementsOnly(c.p.GoogleGetter)
	base, err := Verify(context.Background(), c.a, c.nonce, c.p)
	if err != nil {
		t.Fatal(err)
	}
	e := newProofEpoch(t, 1)
	c.a.UnlockProof = e.proof(t, c.a)
	with, err := Verify(context.Background(), c.a, c.nonce, c.p)
	if err != nil || len(with.Checks) != len(base.Checks) || countCheck(with, UnlockProofCheck) != 0 {
		t.Fatalf("Phala with a proof: %v, %d checks vs %d", err, len(with.Checks), len(base.Checks))
	}
}

// The compose's minimum epoch: unlockd's -min-epoch (1 without it).
func TestComposeMinEpoch(t *testing.T) {
	for _, c := range []struct {
		compose string
		want    uint32
		bad     bool
	}{
		{"services:\n  agentd:\n    image: x\n", 1, false},
		{"services:\n  unlockd:\n    command: [\"-kms-key\", \"k\"]\n", 1, false},
		{"services:\n  unlockd:\n    command: [\"-min-epoch\", \"3\"]\n", 3, false},
		{"services:\n  unlockd:\n    command: [\"--min-epoch=4\"]\n", 4, false},
		{"services:\n  unlockd:\n    command: [\"-min-epoch\", \"x\"]\n", 0, true},
		{"services:\n  unlockd:\n    command: [\"-min-epoch\"]\n", 0, true},
	} {
		got, err := composeMinEpoch(c.compose)
		if (err != nil) != c.bad || got != c.want {
			t.Fatalf("%q: %d, %v", c.compose, got, err)
		}
	}
	// A proof below it is refused at the binding check.
	r := &Result{Facts: map[string]string{"app id": "a", "instance id": "i", "compose hash": "c"},
		proof: &unlockProof{kmsID: "ed25519:k", epoch: 2, appID: "a", instance: "i", appComposeSHA256: "c"}}
	if r.checkUnlockProofBinding("services:\n  unlockd:\n    command: [\"-min-epoch\", \"3\", \"-kms-key\", \"ed25519:k\"]\n") {
		t.Fatal("epoch 2 under min-epoch 3: accepted")
	}
	r.Checks = nil
	if !r.checkUnlockProofBinding("services:\n  unlockd:\n    command: [\"-min-epoch\", \"2\", \"-kms-key\", \"ed25519:k\"]\n") {
		t.Fatalf("epoch 2 under min-epoch 2: %+v", r.Checks)
	}
	r.Checks = nil
	if r.checkUnlockProofBinding("services:\n  gatewayd:\n    command: [\"-kms-key\", \"ed25519:other\"]\n") {
		t.Fatal("a proof of another KMS id than the compose's: accepted")
	}
}

// The proof's signature and the activity records' never verify as each other (design review H1-1: the activity
// signer is reused under a prefix-free label).
func TestUnlockProofLabelPrefixFree(t *testing.T) {
	if proto.UnlockProofLabel == activity.Label || strings.HasPrefix(proto.UnlockProofLabel, activity.Label) ||
		strings.HasPrefix(activity.Label, proto.UnlockProofLabel) {
		t.Fatalf("labels overlap: %q, %q", proto.UnlockProofLabel, activity.Label)
	}
	seed := make([]byte, 32)
	rand.Read(seed)
	s, _ := activity.NewSigner(seed)
	if _, err := s.SignLabeled(activity.Label, [32]byte{}); err == nil {
		t.Fatal("SignLabeled took the records' label")
	}
	// A record's signed bytes start "tacy-activity/v1\x00"; a proof's "tacy-agent/unlock-proof/v1\x00": a signature
	// over one is never over the other.
	d := (&proto.UnlockProof{AppID: "a", InstanceID: "i", AppComposeSHA256: "c"}).Digest(make([]byte, 32), "ed25519:k", 1)
	sig, _ := s.SignLabeled(proto.UnlockProofLabel, d)
	pub, _ := activity.ParseKey(s.Public())
	if ed25519.Verify(pub, append([]byte(activity.Label+"\x00"), d[:]...), sig) {
		t.Fatal("a proof signature verifies as a record's bytes")
	}
}

type phalaCase struct {
	a     *proto.Attestation
	nonce []byte
	p     Policy
}

// phalaRecorded is a genuine Phala quote (prod5 or prod9, a built-in machine) running this tree's release
// app-compose, passing in full (as TestPhalaUnchangedWithGCP's "release on" runs build it).
func phalaRecorded(t *testing.T) (*phalaCase, bool) {
	t.Helper()
	compose := composeYAML(t)
	release, err := ReleaseAppCompose(compose, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	a, nonce, _, _ := loadNone(t, noneRecordings[0])
	setAppComposeRaw(t, a, release)
	rtmr3 := recompose(t, a, release)
	rd := agentLabel(t, a, nonce, HasUnlockd(string(compose)))
	p := Policy{AllowStaleTCB: true, Compose: compose, AppCompose: release, GoogleGetter: &googleFiles{}, VerifyQuote: changeQuote(func(q *tdx.Quote) {
		q.Rtmrs[3] = rtmr3
		if rd != nil {
			q.ReportData = rd
		}
	})}
	if _, err := Verify(context.Background(), a, nonce, p); err != nil {
		t.Logf("the Phala recording doesn't pass: %v", err)
		return nil, false
	}
	return &phalaCase{a: a, nonce: nonce, p: p}, true
}
