package verifier

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"errors"
	"fmt"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/tacyhq/tacy/internal/tdx"
	"github.com/tacyhq/tacy/proto"
	"github.com/tacyhq/tacy/safety"
)

// The machine allowlist at clients (V1-DESIGN §3.7). Holders: kms/split/holder machines_test.go and key-holders'
// pre-gate. Each test fails without the check: before it, every one of these quotes passed this point.

const (
	prod5PPID  = "3e306e133b7fdaa7bb79f67634cb520c"
	prod9PPID  = "62d54040cb9dfc08bb13006fa75ece56"
	phalaFMSPC = "20a06f000000"
)

// loadProd9 is the recorded prod9 VM (as load in verifier_test.go: testdata/attest-v1.json, which names the live CVM's
// app id and so stays out of the public repo). The tests that need a prod9 quote skip without it; the others use the
// public prod5 recordings (load061).
func loadProd9(t *testing.T) (*proto.Attestation, []byte, []byte) {
	t.Helper()
	raw, err := os.ReadFile("../testdata/attest-v1.json")
	if err != nil {
		t.Skip("no prod9 recording (testdata/attest-v1.json) in this tree")
	}
	var a proto.Attestation
	if err := jsonv2.Unmarshal(raw, &a); err != nil {
		t.Fatal(err)
	}
	n, err := os.ReadFile("../testdata/attest-v1.nonce")
	if err != nil {
		t.Fatal(err)
	}
	nonce, err := hex.DecodeString(strings.TrimSpace(string(n)))
	if err != nil {
		t.Fatal(err)
	}
	compose, err := os.ReadFile("../testdata/compose-deployed-v1.yaml")
	if err != nil {
		t.Fatal(err)
	}
	return &a, nonce, compose
}

// machineCheck is the machine check's outcome in res (nil: not reached).
func machineCheck(res *Result) *Check {
	if res == nil {
		return nil
	}
	for i, c := range res.Checks {
		if c.Name == MachineCheck {
			return &res.Checks[i]
		}
	}
	return nil
}

// mustPass and mustRefuse check the machine check alone (later checks may fail for their own reasons).
func mustPass(t *testing.T, what string, res *Result) {
	t.Helper()
	if c := machineCheck(res); c == nil || !c.OK {
		t.Fatalf("%s: the machine check didn't pass: %+v", what, c)
	}
}

func mustRefuse(t *testing.T, what string, res *Result, err error, want string) {
	t.Helper()
	c := machineCheck(res)
	if c == nil || c.OK || err == nil || !strings.HasPrefix(err.Error(), MachineCheck+": ") || !strings.Contains(c.Detail, want) {
		t.Fatalf("%s: want the machine check refused with %q: %+v, %v", what, want, c, err)
	}
	if last := res.Checks[len(res.Checks)-1]; last.Name != MachineCheck || res.HPKEPublicKey != nil {
		t.Fatalf("%s: checks ran past the machine refusal (last %q)", what, last.Name)
	}
}

// testKMS pins a fresh KMS id as the build's (trustKMSID) for the test, as TestTrustDelayEmergency does.
func testKMS(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, k, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	old := trustKMSID
	trustKMSID = k.Public().(ed25519.PublicKey)
	t.Cleanup(func() { trustKMSID = old })
	return k
}

func phalaDoc(ppid, label string, at time.Time) safety.MachineDoc {
	return safety.MachineDoc{Type: safety.MachineType, Platform: safety.PlatformDstack, Host: safety.MachineHostPhala,
		Mode: safety.MachineModePPID, PPID: ppid, FMSPC: phalaFMSPC, Label: label, IssuedAt: at}
}

func signCert(t *testing.T, k ed25519.PrivateKey, d safety.MachineDoc) safety.SignedMachineCert {
	t.Helper()
	c, err := safety.SignMachineCert(k, d)
	if err != nil {
		t.Fatal(err)
	}
	return *c
}

// listWithMachines is a trust list carrying machine certificates and revocations in its optional members.
func listWithMachines(t *testing.T, seq uint64, certs []safety.SignedMachineCert, revoked []string) safety.TrustList {
	t.Helper()
	l := safety.TrustList{Type: safety.TrustListType, Seq: seq, IssuedAt: listNow.Add(-time.Hour)}
	if err := l.SetMachines(certs, revoked); err != nil {
		t.Fatal(err)
	}
	return l
}

// gcpMachines are the GCP recordings' hosts as one-host certificates (the tests' stand-in for registry mode, whose
// MR_OWNER binding the recordings can't show: TestGCPRegistryMode does it on an edited quote).
func gcpMachines(t *testing.T) *safety.MachineSet {
	t.Helper()
	s := &safety.MachineSet{Revoked: map[string]bool{}}
	for _, name := range gcpRecordings {
		a, _, _, _ := loadNone(t, name)
		q, err := tdx.Parse(rawQuote(t, a))
		if err != nil {
			t.Fatal(err)
		}
		if slices.ContainsFunc(s.Machines, func(m safety.Machine) bool { return m.Doc.PPID == q.PPID }) {
			continue
		}
		s.Machines = append(s.Machines, safety.Machine{Doc: safety.MachineDoc{Type: safety.MachineType, Platform: "dstack",
			Host: safety.MachineHostGoogle, Mode: safety.MachineModePPID, PPID: q.PPID, FMSPC: q.FMSPC, Label: "gcp " + name},
			Hash: strings.Repeat("0", 63) + fmt.Sprint(len(s.Machines)%10), Source: "test"})
	}
	return s
}

// The built-in machines: prod5 and prod9 (Intel PCK PPIDs, FMSPC 20a06f000000), valid documents, distinct hashes,
// no Google one; and the recorded quotes from both nodes pass the check with the default policy, prod5's and
// prod9's through Intel's full chain on the recorded collateral (the PPID read from the checked certificate).
func TestMachineCertsBuiltInDefault(t *testing.T) {
	set := BuiltinMachines()
	if len(set.Machines) != 2 || set.Machines[0].Doc.PPID != prod5PPID || set.Machines[1].Doc.PPID != prod9PPID ||
		set.Machines[0].Hash == set.Machines[1].Hash || len(MachinesRevoked) != 0 {
		t.Fatalf("built-in machines %+v", set.Machines)
	}
	for _, d := range MachineDocs {
		if err := d.Validate(); err != nil || d.FMSPC != phalaFMSPC || d.Host != safety.MachineHostPhala || d.KMSID != ReleaseKMSID ||
			!d.IssuedAt.Equal(MachineIssuedAt) || MachineNode(d) == "" {
			t.Fatalf("built-in %+v: %v (node %q)", d, err, MachineNode(d))
		}
	}
	c := recordedCollateral(t)
	full := func(ctx context.Context, b []byte) (*tdx.Quote, error) {
		return tdx.VerifyWith(ctx, b, tdx.Options{Getter: c, Now: collateralNow})
	}
	for _, rec := range []struct{ file, ppid, label string }{
		{"attest-065-none.json", prod5PPID, "phala prod5"}, {"attest-065-none-restart.json", prod5PPID, "phala prod5"},
		{"attest-065-kms.json", prod5PPID, "phala prod5"}, {"attest-064.json", prod5PPID, "phala prod5"},
		{"attest-061.json", prod5PPID, "phala prod5"}, {"attest-v1.json", prod9PPID, "phala prod9"},
	} {
		if _, err := os.Stat("../testdata/" + rec.file); err != nil && rec.file == "attest-v1.json" {
			t.Log("no prod9 recording (testdata/attest-v1.json) in this tree: prod9 checked by its certificate only")
			continue
		}
		a, nonce, attested, compose := loadNone(t, rec.file)
		p := Policy{AllowStaleTCB: true, Compose: []byte(compose), AppCompose: []byte(attested), VerifyQuote: full}
		res, _ := Verify(context.Background(), a, nonce, p)
		mustPass(t, rec.file, res)
		if !strings.HasPrefix(res.Facts[FactMachine], rec.label+" ("+rec.ppid[:16]) || res.Facts["PPID"] != rec.ppid ||
			res.Facts["machine source"] != "built in" {
			t.Fatalf("%s: facts %v", rec.file, res.Facts)
		}
	}
}

// A quote from a machine without a certificate is refused right after the TCB check, before report_data, the event
// log or anything else: a random PPID by default; prod5 under a trust list that certifies only prod9.
func TestMachineNotCertifiedRefused(t *testing.T) {
	a, nonce, compose := load061(t)
	p := offline
	p.Compose = compose
	p.VerifyQuote = changeQuote(func(q *tdx.Quote) { q.PPID = "00112233445566778899aabbccddeeff" })
	res, err := Verify(context.Background(), a, nonce, p)
	mustRefuse(t, "a random PPID", res, err, "has no machine certificate")

	admin, kms := testAdmin(t), testKMS(t)
	s := &TrustState{}
	l := listWithMachines(t, 2, []safety.SignedMachineCert{signCert(t, kms, phalaDoc(prod9PPID, "phala prod9", listNow))}, nil)
	if info := s.Take(signedList(t, admin, l), 0, listNow); !info.OK || !slices.Equal(info.Machines, []string{"phala prod9"}) {
		t.Fatalf("take: %+v", info)
	}
	q, _ := s.Apply(offline, listNow)
	a5, n5, _, c5 := loadNone(t, "attest-065-none.json")
	q.Compose = []byte(c5)
	res, err = Verify(context.Background(), a5, n5, q)
	mustRefuse(t, "prod5 under a list certifying only prod9", res, err, "platform "+prod5PPID)
	a9, n9, c9 := loadProd9(t)
	q.Compose = c9
	res, _ = Verify(context.Background(), a9, n9, q)
	mustPass(t, "prod9 under that list", res)
	if res.Facts["machine source"] != "trust list 2" {
		t.Fatalf("facts %v", res.Facts)
	}
}

// The FMSPC must be the certificate's: the same PPID under another FMSPC is refused.
func TestMachineFMSPCMismatchRefused(t *testing.T) {
	a, nonce, compose := load061(t)
	p := offline
	p.Compose = compose
	p.VerifyQuote = changeQuote(func(q *tdx.Quote) { q.FMSPC = "00806f050000" })
	res, err := Verify(context.Background(), a, nonce, p)
	mustRefuse(t, "prod5 with another FMSPC", res, err, "names FMSPC 20a06f000000")
}

// A quote check that reads no PPID (a VerifyQuote stub, an old tdx) is refused, never waved through.
func TestMachineEmptyPPIDRefused(t *testing.T) {
	a, nonce, compose := load061(t)
	p := offline
	p.Compose = compose
	p.VerifyQuote = changeQuote(func(q *tdx.Quote) { q.PPID, q.FMSPC = "", "" })
	res, err := Verify(context.Background(), a, nonce, p)
	mustRefuse(t, "no PPID", res, err, "names no PPID and FMSPC")
	p.Machines = &safety.MachineSet{}
	p.VerifyQuote = offline.VerifyQuote
	res, err = Verify(context.Background(), a, nonce, p)
	mustRefuse(t, "an empty machine set", res, err, "no machine certificates")
}

// A certificate counts only signed by the build's pinned KMS id: one signed by the trust list's admin key, or by any
// other key, refuses the whole list (as a bad emergency override does); so does an edited document.
func TestMachineCertNeedsKMSID(t *testing.T) {
	admin, kms := testAdmin(t), testKMS(t)
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	good := signCert(t, kms, phalaDoc(prod5PPID, "phala prod5", listNow))
	edited := good
	edited.Doc = []byte(strings.Replace(string(good.Doc), prod5PPID, "00112233445566778899aabbccddeeff", 1))
	for name, c := range map[string]safety.SignedMachineCert{
		"the admin key": signCert(t, admin, phalaDoc(prod5PPID, "phala prod5", listNow)),
		"another key":   signCert(t, other, phalaDoc(prod5PPID, "phala prod5", listNow)),
		"edited":        edited,
	} {
		s := &TrustState{}
		info := s.Take(signedList(t, admin, listWithMachines(t, 3, []safety.SignedMachineCert{c}, nil)), 0, listNow)
		if info.OK || !strings.Contains(info.Error, "isn't signed by the KMS id") {
			t.Fatalf("%s: %+v", name, info)
		}
	}
	if _, err := good.Open(kms.Public().(ed25519.PublicKey)); err != nil {
		t.Fatal(err)
	}
}

// Revocations are permanent at a client (second review N8): a list revokes prod5's certificate; the next list (the
// admin key alone) lists the same genuine KMS-signed certificate again and leaves the revocation out; prod5 stays
// refused, from the kept record, also in a fresh TrustState given that record. Re-allowing takes a new certificate
// (a new issued_at: another hash), which only the KMS id signs.
func TestMachineRevocationMonotonic(t *testing.T) {
	admin, kms := testAdmin(t), testKMS(t)
	c5 := signCert(t, kms, phalaDoc(prod5PPID, "phala prod5", listNow.Add(-48*time.Hour)))
	c9 := signCert(t, kms, phalaDoc(prod9PPID, "phala prod9", listNow.Add(-48*time.Hour)))
	a5, n5, _, comp5 := loadNone(t, "attest-065-none.json")
	verify := func(s *TrustState) (*Result, error) {
		p, info := s.Apply(offline, listNow)
		if info == nil || !info.OK {
			t.Fatalf("apply: %+v", info)
		}
		p.Compose = []byte(comp5)
		return Verify(context.Background(), a5, n5, p)
	}
	s := &TrustState{}
	info := s.Take(signedList(t, admin, listWithMachines(t, 4, []safety.SignedMachineCert{c5, c9}, nil)), 0, listNow)
	res, _ := verify(s)
	mustPass(t, "prod5 certified", res)
	info = s.TakeSeen(signedList(t, admin, listWithMachines(t, 5, []safety.SignedMachineCert{c5, c9}, []string{c5.Hash()})), 0, listNow, []byte(info.Seen))
	res, err := verify(s)
	mustRefuse(t, "prod5 revoked", res, err, "revoked")
	info = s.TakeSeen(signedList(t, admin, listWithMachines(t, 6, []safety.SignedMachineCert{c5, c9}, nil)), 0, listNow, []byte(info.Seen))
	res, err = verify(s)
	mustRefuse(t, "prod5 re-listed by the admin key", res, err, "revoked")
	fresh := &TrustState{}
	fresh.TakeSeen(signedList(t, admin, listWithMachines(t, 6, []safety.SignedMachineCert{c5, c9}, nil)), 0, listNow, []byte(info.Seen))
	res, err = verify(fresh)
	mustRefuse(t, "a fresh state with the kept record", res, err, "revoked")
	if info.MachinesRevoked != 1 || !strings.Contains(info.Seen, c5.Hash()) {
		t.Fatalf("info %+v", info)
	}
	// TestUnrevokeNeedsNewCertificate: a new certificate (new issued_at) re-allows prod5; only the KMS id makes one.
	c5b := signCert(t, kms, phalaDoc(prod5PPID, "phala prod5", listNow))
	if c5b.Hash() == c5.Hash() {
		t.Fatal("a new issued_at kept the hash")
	}
	s.TakeSeen(signedList(t, admin, listWithMachines(t, 7, []safety.SignedMachineCert{c5b, c9}, nil)), 0, listNow, []byte(info.Seen))
	res, _ = verify(s)
	mustPass(t, "prod5's new certificate", res)
	// A built-in machine is revoked by the same hash its ceremony certificate has.
	h, _ := safety.MachineDocHash(MachineDocs[0])
	ceremony, err := safety.MarshalMachineDoc(MachineDocs[0])
	if err != nil || safety.MachineHash(ceremony) != h || BuiltinMachines().Machines[0].Hash != h {
		t.Fatalf("built-in hash %s: %v", h, err)
	}
}

// A certificate isn't bound to a list seq (review M2): taken from list 8, it stays accepted in list 9 and later
// lists that carry it, with no new KMS-id signature; and certificates have no 24 h delay (they need the KMS id).
func TestMachineCertNotSeqBound(t *testing.T) {
	admin, kms := testAdmin(t), testKMS(t)
	c5 := signCert(t, kms, phalaDoc(prod5PPID, "phala prod5", listNow))
	s := &TrustState{}
	var seen string
	a5, n5, _, comp5 := loadNone(t, "attest-065-none.json")
	for seq := uint64(8); seq <= 10; seq++ {
		info := s.TakeSeen(signedList(t, admin, listWithMachines(t, seq, []safety.SignedMachineCert{c5}, nil)), 0, listNow, []byte(seen))
		seen = info.Seen
		p, _ := s.Apply(offline, listNow) // no time passed: no delay applies
		p.Compose = []byte(comp5)
		res, _ := Verify(context.Background(), a5, n5, p)
		mustPass(t, fmt.Sprintf("list %d", seq), res)
	}
}

// Every verification says what the list doesn't defend against: the host (review H3).
func TestMachineFactSaysHostNotDefended(t *testing.T) {
	a, nonce, compose := loadProd9(t)
	p := offline
	p.Compose = compose
	res, _ := Verify(context.Background(), a, nonce, p)
	mustPass(t, "prod9", res)
	if f := res.Facts[FactMachine]; f != "phala prod9 (62d54040cb9dfc08…); host Phala: not defended by the machine list" {
		t.Fatalf("fact %q", f)
	}
}

// An older client (the vm-v1 build before machine certificates, d2bbea2b) reads a trust list carrying
// optional.machine_certs and optional.machines_revoked, and ignores them: the members are optional ones, so the list
// decodes strictly into that build's TrustList (copied below field for field) and passes its Validate (which this
// build's still is: TestTrustListMembersUnchanged). A named member would make every older build refuse the list whole.
func TestOldTrustListStillReadsWithOptionalMachines(t *testing.T) {
	admin, kms := testAdmin(t), testKMS(t)
	l := listWithMachines(t, 11, []safety.SignedMachineCert{signCert(t, kms, phalaDoc(prod5PPID, "phala prod5", listNow)),
		signCert(t, kms, phalaDoc(prod9PPID, "phala prod9", listNow))}, []string{strings.Repeat("ab", 32)})
	l.RevokedReleases = []string{"v0.20.0"}
	env := signedList(t, admin, l)
	e, err := safety.DecodeTrustList(env)
	if err != nil {
		t.Fatal(err)
	}
	var old trustListD2bbea2b
	if err := jsonv2.Unmarshal(e.Payload, &old, jsonv2.RejectUnknownMembers(true)); err != nil {
		t.Fatalf("the older build's strict decode refuses the list: %v", err)
	}
	if len(old.Optional) != 2 || old.Seq != 11 || !slices.Equal(old.RevokedReleases, []string{"v0.20.0"}) {
		t.Fatalf("older build read %+v", old)
	}
	if info := (&TrustState{}).Take(env, 0, listNow); !info.OK || len(info.Machines) != 2 || info.MachinesRevoked != 1 {
		t.Fatalf("this build: %+v", info)
	}
	// The member names fit the optional rules every build since the optional members checks (Validate).
	for _, n := range []string{safety.TrustMachineCertsMember, safety.TrustMachinesRevokedMember} {
		if len(n) > 32 || strings.ToLower(n) != n {
			t.Fatal(n)
		}
	}
}

// trustListD2bbea2b is safety.TrustList as the vm-v1 build before machine certificates had it (d2bbea2b).
type trustListD2bbea2b struct {
	Type             string                    `json:"type"`
	Seq              uint64                    `json:"seq"`
	IssuedAt         time.Time                 `json:"issued_at"`
	Expires          time.Time                 `json:"expires,omitzero"`
	OSImages         map[string]string         `json:"os_images,omitzero"`
	BootMeasurements []safety.TrustBoot        `json:"boot_measurements,omitzero"`
	PreLaunch        map[string]string         `json:"pre_launch,omitzero"`
	KMSIDs           map[string]string         `json:"kms_ids,omitzero"`
	VMReleaseFloor   string                    `json:"vm_release_floor,omitzero"`
	Releases         []safety.TrustRelease     `json:"releases,omitzero"`
	TCBGrace         *safety.TCBGrace          `json:"tcb_grace,omitempty"`
	Platforms        []string                  `json:"platforms,omitempty"`
	NextAdminKeys    []string                  `json:"next_admin_keys,omitempty"`
	RevokedReleases  []string                  `json:"revoked_releases,omitzero"`
	Services         []string                  `json:"services,omitzero"`
	KMSRoots         map[string]string         `json:"kms_roots,omitzero"`
	StartTicketKeys  []string                  `json:"start_ticket_keys,omitzero"`
	RollbackWitness  *safety.TrustWitness      `json:"rollback_witness,omitzero"`
	Optional         map[string]jsontext.Value `json:"optional,omitzero"`
}

// This build's trust list has exactly the older build's named members: the machine allowlist added none.
func TestTrustListMembersUnchanged(t *testing.T) {
	names := func(v any) []string {
		var out []string
		ty := reflect.TypeOf(v)
		for i := range ty.NumField() {
			out = append(out, strings.Split(ty.Field(i).Tag.Get("json"), ",")[0])
		}
		return out
	}
	if a, b := names(safety.TrustList{}), names(trustListD2bbea2b{}); !slices.Equal(a, b) {
		t.Fatalf("trust list members changed: %v, was %v (a new named member makes older apps refuse every list)", a, b)
	}
}

// No Google certificate while the VM runs on Phala (V1-DESIGN §2.7, second review N3): none is built in, and a
// trust list that carries one (registry mode or one Google host) without naming the Google fallback (platform
// dstack-gcp) is refused whole. With the fallback named, a client takes it, counting the Google certificate once the
// fallback counts (24 h later).
func TestNoRegistryCertWhileOnPhala(t *testing.T) {
	for _, d := range MachineDocs {
		if d.Host != safety.MachineHostPhala || d.Mode != safety.MachineModePPID {
			t.Fatalf("a built-in non-Phala machine: %+v", d)
		}
	}
	admin, kms := testAdmin(t), testKMS(t)
	reg := signCert(t, kms, safety.MachineDoc{Type: safety.MachineType, Platform: "dstack", Host: safety.MachineHostGoogle,
		Mode: safety.MachineModeRegistry, FMSPC: "00806f050000", ProjectNumber: "123456789012", Label: "gcp c3", IssuedAt: listNow})
	host := signCert(t, kms, safety.MachineDoc{Type: safety.MachineType, Platform: "dstack", Host: safety.MachineHostGoogle,
		Mode: safety.MachineModePPID, PPID: strings.Repeat("ab", 16), FMSPC: "00806f050000", Label: "gcp host", IssuedAt: listNow})
	p5 := signCert(t, kms, phalaDoc(prod5PPID, "phala prod5", listNow))
	for name, c := range map[string]safety.SignedMachineCert{"registry": reg, "one Google host": host} {
		l := listWithMachines(t, 12, []safety.SignedMachineCert{p5, c}, nil)
		if info := (&TrustState{}).Take(signedList(t, admin, l), 0, listNow); info.OK || !strings.Contains(info.Error, "Google fallback") {
			t.Fatalf("%s without dstack-gcp: %+v", name, info)
		}
		l.Platforms = []string{"dstack", PlatformDstackGCP}
		// Taken, but the Google certificate counts only once dstack-gcp does (its 24 h delay, review2 L1).
		var s TrustState
		if info := s.Take(signedList(t, admin, l), 0, listNow); !info.OK || len(info.Machines) != 1 {
			t.Fatalf("%s with the fallback named: %+v", name, info)
		}
		if _, info := s.Apply(Policy{}, listNow.Add(safety.TrustDelay)); info == nil || !info.OK || len(info.Machines) != 2 {
			t.Fatalf("%s with the fallback in force: %+v", name, info)
		}
	}
}

// Registry mode (F9(a): shipped, issued only on the day of a switch to Google): a GCP quote passes when Google's
// host registry has its PPID in the VM's zone and MR_OWNER is the PZID digest of the VM in the certificate's
// project. The recordings' MR_OWNER can't be matched (no instance id recorded), so the quote's MR_OWNER is set to
// the digest of a stated instance: what is shown is the rule, on a real PCK certificate and registry document form.
func TestGCPRegistryMode(t *testing.T) {
	a, nonce, p, _ := gcpPolicy(t, gcpRecordings[0])
	q0, _ := tdx.Parse(rawQuote(t, a))
	const project, instance, zone = "123456789012", "4815162342", "us-central1-a"
	payload := fmt.Sprintf(`{"instanceId":%s,"numericalProjectId":%s,"zone":"%s"}`, instance, project, zone)
	digest := sha512.Sum384([]byte(payload))
	inner := p.VerifyQuote
	withOwner := func(owner string) func(context.Context, []byte) (*tdx.Quote, error) {
		return func(ctx context.Context, b []byte) (*tdx.Quote, error) {
			q, err := inner(ctx, b)
			if q != nil {
				q.MrOwner = owner
			}
			return q, err
		}
	}
	var info map[string]any
	json.Unmarshal(a.Info, &info)
	info["gce_instance_id"], info["gce_zone"] = instance, zone
	a.Info, _ = json.Marshal(info)
	reg := safety.MachineDoc{Type: safety.MachineType, Platform: "dstack", Host: safety.MachineHostGoogle, Mode: safety.MachineModeRegistry,
		FMSPC: q0.FMSPC, ProjectNumber: project, Label: "gcp c3 (registry)", IssuedAt: listNow}
	h, _ := safety.MachineDocHash(reg)
	for _, c := range []struct {
		name, owner, registry string
		want                  string
	}{
		{"registered, this project", hex.EncodeToString(digest[:]), `{"timestamp":"2026-11-20T21:53:55Z","zone":"us-central1-a"}`, ""},
		{"another project's VM", strings.Repeat("00", 48), `{"timestamp":"2026-11-20T21:53:55Z","zone":"us-central1-a"}`, "MR_OWNER isn't this project's PZID"},
		{"not in the registry", hex.EncodeToString(digest[:]), "", "host registry has no document"},
		{"another zone", hex.EncodeToString(digest[:]), `{"timestamp":"2026-11-20T21:53:55Z","zone":"us-east1-c"}`, "isn't for zone us-central1-a"},
	} {
		t.Run(c.name, func(t *testing.T) {
			g := &registryFiles{doc: c.registry, inner: p.GoogleGetter}
			q := p
			q.GoogleGetter, q.VerifyQuote = g, withOwner(c.owner)
			q.Machines = &safety.MachineSet{Machines: []safety.Machine{{Doc: reg, Hash: h, Source: "test"}}, Revoked: map[string]bool{}}
			res, err := Verify(context.Background(), a, nonce, q)
			if c.want == "" {
				mustPass(t, c.name, res)
				if err != nil || !strings.Contains(res.Facts[FactMachine], "host Google: not defended") || g.asked != RegistryURL+q0.PPID {
					t.Fatalf("%v; facts %v; asked %q", err, res.Facts, g.asked)
				}
				return
			}
			mustRefuse(t, c.name, res, err, c.want)
			q.Machines.Revoked[h] = true
			res, err = Verify(context.Background(), a, nonce, q)
			mustRefuse(t, c.name+", revoked", res, err, "has no machine certificate")
		})
	}
}

// A verifier behind a relay (the WASM: EndorsementsOnly, gcp-prod review H1) never reads the host registry: the same
// registered quote that passes TestGCPRegistryMode is refused at the machine check without an unlock proof (unlockproof_test.go: with one), with no registry request, while
// a ppid-mode Google certificate still passes (the endorsement is still fetched, through the relay).
func TestGCPRegistryNotThroughRelay(t *testing.T) {
	a, nonce, p, _ := gcpPolicy(t, gcpRecordings[0])
	q0, _ := tdx.Parse(rawQuote(t, a))
	const project, instance, zone = "123456789012", "4815162342", "us-central1-a"
	digest := sha512.Sum384([]byte(fmt.Sprintf(`{"instanceId":%s,"numericalProjectId":%s,"zone":"%s"}`, instance, project, zone)))
	inner := p.VerifyQuote
	var info map[string]any
	json.Unmarshal(a.Info, &info)
	info["gce_instance_id"], info["gce_zone"] = instance, zone
	a.Info, _ = json.Marshal(info)
	reg := safety.MachineDoc{Type: safety.MachineType, Platform: "dstack", Host: safety.MachineHostGoogle, Mode: safety.MachineModeRegistry,
		FMSPC: q0.FMSPC, ProjectNumber: project, Label: "gcp c3 (registry)", IssuedAt: listNow}
	h, _ := safety.MachineDocHash(reg)
	g := &registryFiles{doc: `{"timestamp":"2026-11-20T21:53:55Z","zone":"us-central1-a"}`, inner: p.GoogleGetter}
	q := p
	q.GoogleGetter = EndorsementsOnly(g)
	q.VerifyQuote = func(ctx context.Context, b []byte) (*tdx.Quote, error) {
		x, err := inner(ctx, b)
		if x != nil {
			x.MrOwner = hex.EncodeToString(digest[:])
		}
		return x, err
	}
	q.Machines = &safety.MachineSet{Machines: []safety.Machine{{Doc: reg, Hash: h, Source: "test"}}, Revoked: map[string]bool{}}
	res, err := Verify(context.Background(), a, nonce, q)
	mustRefuse(t, "registry mode through a relay, no unlock proof", res, err, "has no unlock proof")
	if g.asked != "" {
		t.Fatalf("the registry was asked through the relay: %q", g.asked)
	}
	// A ppid-mode Google certificate for the same quote: passes, the endorsement fetched through the wrapper.
	ppid := safety.MachineDoc{Type: safety.MachineType, Platform: "dstack", Host: safety.MachineHostGoogle, Mode: safety.MachineModePPID,
		PPID: q0.PPID, FMSPC: q0.FMSPC, Label: "gcp c3 (ppid)", IssuedAt: listNow}
	hp, _ := safety.MachineDocHash(ppid)
	q.Machines = &safety.MachineSet{Machines: []safety.Machine{{Doc: ppid, Hash: hp, Source: "test"}}, Revoked: map[string]bool{}}
	res, err = Verify(context.Background(), a, nonce, q)
	if err != nil {
		t.Fatalf("ppid mode through the relay: %v", err)
	}
	mustPass(t, "ppid mode through the relay", res)
}

// registryFiles serves one registry document (none: 404) and passes every other URL on.
type registryFiles struct {
	doc   string
	asked string
	inner interface {
		Get(string) (map[string][]string, []byte, error)
	}
}

func (r *registryFiles) Get(url string) (map[string][]string, []byte, error) {
	if !strings.HasPrefix(url, RegistryURL) {
		return r.inner.Get(url)
	}
	r.asked = url
	if r.doc == "" {
		return nil, nil, errors.New("HTTP 404")
	}
	return nil, []byte(r.doc), nil
}

// The built-in machines' certificate hashes, which the KMS ceremony's certificates must have (kmsctl
// machine-cert -builtin prints them; the KMS ceremony lists them): a revocation names a machine by this hash.
func TestBuiltInMachineHashes(t *testing.T) {
	want := []string{"fab2413988a95fc10e908c1a3d90f1f915853bb5361a050319c5c79a54041eff", "ab4e5d537c73efc0cee98b3d3bd1c0eae03b3d11a700c59e94c9e0230f892e45"}
	for i, m := range BuiltinMachines().Machines {
		if m.Hash != want[i] {
			t.Fatalf("%s: hash %s, want %s (the KMS ceremony's values)", m.Doc.Label, m.Hash, want[i])
		}
	}
}
