package split

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/tacyhq/tacy/kms"
	"github.com/tacyhq/tacy/safety"
)

func testMachineCert(t *testing.T, m []byte, kmsID, ppid string, at time.Time) safety.SignedMachineCert {
	t.Helper()
	c, err := NewMachineCert(m, kmsID, safety.MachineDoc{Type: safety.MachineType, Platform: "dstack", Host: safety.MachineHostPhala,
		Mode: safety.MachineModePPID, PPID: ppid, FMSPC: "20a06f000000", Label: "phala test", IssuedAt: at})
	if err != nil {
		t.Fatal(err)
	}
	return *c
}

func machinePolicy(t *testing.T) ([]byte, ed25519.PublicKey, UnlockPolicy) {
	t.Helper()
	m, idStr, id := master(t)
	now := time.Now()
	return m, id, UnlockPolicy{Policy: kms.Policy{KMSID: idStr, Epoch: 1, Seq: 1, IssuedAt: now, Floor: "v0.21.0"},
		Holders:      []HolderURL{{Holder: "cloudflare", URL: "https://keys-cf.tacy.io"}, {Holder: "vercel", URL: "https://x.vercel.app"}},
		MachineCerts: []safety.SignedMachineCert{testMachineCert(t, m, idStr, "3e306e133b7fdaa7bb79f67634cb520c", now)}}
}

// Machine certificates and their revocations don't touch the catch-all item (no 24 h delay for them, F3), and a
// policy without them has the catch-all item it had before the fields existed (a holder upgrade starts no wait).
// Revocations are items (the store's permanent record), certificates aren't.
func TestMachineCertsOutsideOther(t *testing.T) {
	m, _, p := machinePolicy(t)
	before := OtherItem(&p)
	q := p
	q.MachineCerts = append(q.MachineCerts, testMachineCert(t, m, p.KMSID, "62d54040cb9dfc08bb13006fa75ece56", time.Now()))
	q.MachinesRevoked = []string{p.MachineCerts[0].Hash()}
	if OtherItem(&q) != before {
		t.Fatal("a machine change moved the catch-all item (it would wait 24 h)")
	}
	items := PolicyItems(&q)
	n := 0
	for _, it := range items {
		if strings.HasPrefix(it, ItemMachineRevoked) {
			n++
		}
	}
	if n != 1 || len(items) != len(PolicyItems(&p))+1 {
		t.Fatalf("items %v", items)
	}
	none := p
	none.MachineCerts = nil
	b, _ := json.Marshal(none)
	if strings.Contains(string(b), "machine") {
		t.Fatalf("a policy without machines marshals them: %s", b)
	}
}

// Every unlock policy needs machine certificates: absent and empty are refused alike (review L2: no reading of
// "none" as "the built-in ones"; a holder has none built in); one not signed by the KMS id (the admin key's, or
// edited) refuses the policy; bad revocations too.
func TestProductionPolicyNeedsMachineCerts(t *testing.T) {
	m, id, p := machinePolicy(t)
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	if s, err := p.OpenMachines(id); err != nil || len(s.Machines) != 1 {
		t.Fatalf("open: %v", err)
	}
	_, admin, _ := ed25519.GenerateKey(rand.Reader)
	byAdmin, _ := safety.SignMachineCert(admin, safety.MachineDoc{Type: safety.MachineType, Platform: "dstack", Host: "phala",
		Mode: "ppid", PPID: strings.Repeat("ab", 16), FMSPC: "20a06f000000", Label: "x", IssuedAt: time.Now()})
	for name, edit := range map[string]func(*UnlockPolicy){
		"absent":         func(p *UnlockPolicy) { p.MachineCerts = nil },
		"empty":          func(p *UnlockPolicy) { p.MachineCerts = []safety.SignedMachineCert{} },
		"bad revocation": func(p *UnlockPolicy) { p.MachinesRevoked = []string{"nothex"} },
	} {
		q := p
		edit(&q)
		if err := q.Validate(); err == nil {
			t.Fatalf("%s: validated", name)
		}
	}
	b, _ := json.Marshal(UnlockPolicy{Policy: p.Policy, Holders: p.Holders, MachineCerts: []safety.SignedMachineCert{}})
	var back UnlockPolicy
	if err := kms.Strict(b, &back); err != nil || back.Validate() == nil {
		t.Fatalf("an empty list round-tripped into a valid policy: %v", err)
	}
	q := p
	q.MachineCerts = append(q.MachineCerts, *byAdmin)
	if _, err := q.OpenMachines(id); err == nil || !strings.Contains(err.Error(), "isn't signed by the KMS id") {
		t.Fatalf("an admin-signed certificate: %v", err)
	}
	_ = m
}

// No Google Cloud host (the v1 Google host removal): a policy carrying a certificate of the old Google modes (gcp-registry, or one
// host "google"), validly signed by the KMS id, doesn't open, whatever platforms it names. Before the change, one
// opened when the policy named "dstack-gcp".
func TestPolicyMachineCertsPhalaOnly(t *testing.T) {
	m, id, p := machinePolicy(t)
	k, err := kms.DeriveID(m)
	if err != nil {
		t.Fatal(err)
	}
	sign := func(doc string) safety.SignedMachineCert {
		return safety.SignedMachineCert{Doc: []byte(doc), Sig: ed25519.Sign(k, append([]byte("tacy-split/machine/v1\x00"), doc...))}
	}
	if c := sign(string(p.MachineCerts[0].Doc)); string(c.Sig) != string(p.MachineCerts[0].Sig) {
		t.Fatal("the test's signing isn't the KMS id's (the refusals below would prove nothing)")
	}
	at := time.Now().UTC().Format(time.RFC3339)
	for name, doc := range map[string]string{
		"registry": `{"type":"tacy.machine/v1","kms_id":"` + p.KMSID + `","platform":"dstack","host":"google","mode":"gcp-registry",` +
			`"fmspc":"00806f050000","project_number":"123456789012","label":"gcp c3","issued_at":"` + at + `"}`,
		"one Google host": `{"type":"tacy.machine/v1","kms_id":"` + p.KMSID + `","platform":"dstack","host":"google","mode":"ppid",` +
			`"ppid":"` + strings.Repeat("ab", 16) + `","fmspc":"00806f050000","label":"gcp host","issued_at":"` + at + `"}`,
	} {
		for _, plats := range [][]string{nil, {"dstack"}, {"dstack", "dstack-gcp"}} {
			q := p
			q.MachineCerts, q.Platforms = append(slices.Clone(p.MachineCerts), sign(doc)), plats
			if _, err := q.OpenMachines(id); err == nil || !strings.Contains(err.Error(), "machine certificate") {
				t.Fatalf("%s, platforms %v: %v", name, plats, err)
			}
		}
	}
	if _, err := p.OpenMachines(id); err != nil {
		t.Fatalf("the Phala certificates alone: %v", err)
	}
}
