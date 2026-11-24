package main

import (
	"encoding/json"
	"github.com/tacyhq/tacy/kms"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/tacyhq/tacy/safety"
	"github.com/tacyhq/tacy/verifier"
)

// slotBuild writes one tunnel slot's build (compose.yaml, the app-compose.json embedding it, its trust entry R.json)
// into dir/slot-<s> and returns the -release spec and the entry's file.
func slotBuild(t *testing.T, dir, slot, version string) (rel, entryFile string, entry safety.TrustRelease) {
	t.Helper()
	d := filepath.Join(dir, "slot-"+slot)
	os.MkdirAll(d, 0o755)
	cy, ac := filepath.Join(d, "compose.yaml"), filepath.Join(d, "app-compose.json")
	compose := "services: {gatewayd: {command: [\"-tunnel-secret\", \"CF_TUNNEL_TOKEN_VM" + strings.ToUpper(slot) + "\"]}}\n"
	os.WriteFile(cy, []byte(compose), 0o644)
	b, _ := json.Marshal(map[string]any{"name": "agent-vm", "docker_compose_file": compose})
	os.WriteFile(ac, b, 0o644)
	entry = safety.TrustRelease{Version: version, Commit: strings.Repeat("3", 40), ComposeSHA256: fileSHA256(cy), Bundle: []byte(`{}`)}
	entryFile = writeJSONFile(t, filepath.Join(d, "R.json"), entry)
	return "app=agent-vm,version=" + version + ",app-compose=" + ac + ",compose=" + cy, entryFile, entry
}

// Hook TWO-BUILDS: one approval signs one build per tunnel slot, each its own version (a trust list lists a version
// once), each -release paired with exactly its own -trust-release. The dry run shows both and the signing run signs
// exactly that; every pairing mistake is refused and nothing is signed.
func TestApproveTwoBuilds(t *testing.T) {
	f := newApproveFixture(t)
	relA, trA, eA := slotBuild(t, f.dir, "a", "v1.0.1")
	relB, trB, eB := slotBuild(t, f.dir, "b", "v1.0.0")
	tl := f.approve[slices.Index(f.approve, "-trust-base")+1]
	base := []string{"approve", "-base", f.base, "-trust-base", tl}
	args := append(slices.Clone(base), "-release", relB, "-release", relA, "-trust-release", trA, "-trust-release", trB)

	out, errOut, err := kmsctl(t, append(slices.Clone(args), "-dry-run")...)
	if err != nil {
		t.Fatalf("two builds, dry run: %v\n%s", err, errOut)
	}
	var doc dryRunDoc
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatal(err)
	}
	var pinned []string
	for _, r := range doc.UnlockPolicy.Releases {
		pinned = append(pinned, r.Version)
	}
	if !slices.Equal(pinned, []string{"v1.0.0", "v1.0.1"}) {
		t.Fatalf("pinned %v", pinned)
	}
	// The entries in -release order whatever order -trust-release came in, each its own build's.
	if len(doc.TrustList.Releases) != 2 || doc.TrustList.Releases[0].ComposeSHA256 != eB.ComposeSHA256 || doc.TrustList.Releases[1].ComposeSHA256 != eA.ComposeSHA256 {
		t.Fatalf("trust entries %+v", doc.TrustList.Releases)
	}
	ws := filepath.Join(f.dir, "would-sign-two.json")
	os.WriteFile(ws, []byte(out), 0o644)
	signed := filepath.Join(f.dir, "signed-two")
	sign := append(slices.Clone(args), "-sign-key", f.key, "-trust-key", f.key, "-dev-plain-keys", "-out", signed, "-expect", ws)
	if _, errOut, err := kmsctl(t, sign...); err != nil {
		t.Fatalf("two builds, signing: %v\n%s", err, errOut)
	}
	var env safety.Envelope
	readJSON(filepath.Join(signed, "trust-list-4.signed.json"), &env)
	var got safety.TrustList
	if err := json.Unmarshal(env.Payload, &got); err != nil || len(got.Releases) != 2 {
		t.Fatalf("signed trust list: %v %+v", err, got.Releases)
	}
	// The signing run with one entry dropped derives another trust list: refused against the dry run, nothing signed.
	short := filepath.Join(f.dir, "signed-short")
	if _, errOut, err := kmsctl(t, append(append(slices.Clone(base), "-release", relB, "-release", relA, "-trust-release", trB),
		"-sign-key", f.key, "-trust-key", f.key, "-dev-plain-keys", "-out", short, "-expect", ws)...); err == nil || !strings.Contains(errOut, "without its -trust-release") {
		t.Fatalf("signing with an entry dropped: %v\n%s", err, errOut)
	}
	if _, err := os.Stat(short); !os.IsNotExist(err) {
		t.Fatal("written with an entry dropped")
	}

	// Refusals (each a dry run: nothing is signed or written either way).
	_, otherB, _ := slotBuild(t, filepath.Join(f.dir, "other"), "b", "v1.0.1") // slot b's build under slot a's version
	mixed := filepath.Join(f.dir, "mixed")
	os.MkdirAll(mixed, 0o755)
	mixedAC := filepath.Join(mixed, "app-compose.json")
	os.WriteFile(mixedAC, readFile(filepath.Join(f.dir, "slot-b", "app-compose.json")), 0o644) // b's app-compose with a's compose
	noTrust := []string{"approve", "-base", f.base}
	for _, c := range []struct {
		name string
		args []string
		want string
	}{
		{"one entry for two builds", append(slices.Clone(base), "-release", relA, "-release", relB, "-trust-release", trA), "v1.0.0 is added to the trust list without its -trust-release"},
		{"an entry twice", append(slices.Clone(base), "-release", relA, "-release", relB, "-trust-release", trA, "-trust-release", trA, "-trust-release", trB), "-trust-release v1.0.1 given twice"},
		{"an entry of no build", append(slices.Clone(base), "-release", relA, "-trust-release", trA, "-trust-release", trB), "the -trust-release entry v1.0.0 isn't a -release added"},
		{"one version for two builds", append(slices.Clone(base), "-release", relA, "-release", strings.Replace(relB, "v1.0.0", "v1.0.1", 1), "-trust-release", trA), "-release v1.0.1 given twice"},
		{"the entries swapped", append(slices.Clone(base), "-release", relA, "-trust-release", otherB), "is for another compose than its -release's"},
		{"another build's app-compose", append(slices.Clone(base), "-release", strings.Replace(relA, filepath.Join(f.dir, "slot-a", "app-compose.json"), mixedAC, 1), "-trust-release", trA), "doesn't embed its compose"},
		{"no compose= with a trust list", append(slices.Clone(base), "-release", relA[:strings.Index(relA, ",compose=")], "-trust-release", trA), "needs compose=FILE"},
		{"an entry without a trust base", append(slices.Clone(noTrust), "-release", relA, "-trust-release", trA), "-trust-release needs -trust-base"},
		{"an entry with no release", append(slices.Clone(base), "-end-overlap", "-trust-release", trA), "-trust-release without a -release"},
		{"one app-compose under two versions", append(slices.Clone(base), "-release", relA, "-release", strings.Replace(relA, "v1.0.1", "v1.0.2", 1),
			"-trust-release", trA, "-trust-release", writeJSONFile(t, filepath.Join(f.dir, "R-102.json"), safety.TrustRelease{Version: "v1.0.2", Commit: eA.Commit, ComposeSHA256: eA.ComposeSHA256, Bundle: eA.Bundle})), "listed already as v1.0.1"},
	} {
		if out, errOut, err := kmsctl(t, append(c.args, "-dry-run")...); err == nil || !strings.Contains(errOut, c.want) {
			t.Errorf("%s: %v (want %q)\n%s%s", c.name, err, c.want, out, errOut)
		}
	}

	// A version the base trust list already lists is refused (listed once), even as another build.
	listed := writeJSONFile(t, filepath.Join(f.dir, "T-listed.json"), safety.TrustList{Type: safety.TrustListType, Seq: 3, IssuedAt: time.Now().Add(-time.Hour),
		Releases: []safety.TrustRelease{{Version: "v1.0.1", Commit: strings.Repeat("1", 40), ComposeSHA256: strings.Repeat("2", 64), Bundle: []byte(`{}`)}}})
	if _, errOut, err := kmsctl(t, "approve", "-base", f.base, "-trust-base", listed, "-release", relA, "-trust-release", trA, "-dry-run"); err == nil || !strings.Contains(errOut, "listed twice") {
		t.Errorf("a version listed already: %v\n%s", err, errOut)
	}
}

// Hook MIN-EPOCH: -min-unlock-epoch puts the trust list's min_unlock_epoch, only raised, never past the policy's epoch
// or with a share set of an older epoch still in the policy, and needs -trust-base. Alone it is the next seq of both
// documents; the dry run shows it and the signing run must have it too; a client's verifier takes it from the list.
func TestApproveMinUnlockEpoch(t *testing.T) {
	f := newApproveFixture(t)
	tl := f.approve[slices.Index(f.approve, "-trust-base")+1]
	served := servedPolicy(t, f)
	base := append([]string{"approve", "-base", f.base, "-trust-base", tl}, served...)

	out, errOut, err := kmsctl(t, append(slices.Clone(base), "-min-unlock-epoch", "1", "-dry-run")...)
	if err != nil {
		t.Fatalf("-min-unlock-epoch 1 alone: %v\n%s", err, errOut)
	}
	if !strings.Contains(errOut, "min_unlock_epoch 0 -> 1") {
		t.Errorf("no notice of the change: %s", errOut)
	}
	var doc dryRunDoc
	json.Unmarshal([]byte(out), &doc)
	var u map[string]any
	json.Unmarshal(readFile(f.base), &u)
	if doc.UnlockPolicy.Seq != uint64(u["seq"].(float64))+1 || len(doc.UnlockPolicy.Releases) != 0 || doc.TrustList.Seq != 4 {
		t.Fatalf("not the next seqs, unchanged otherwise: policy %d, %d releases, list %d", doc.UnlockPolicy.Seq, len(doc.UnlockPolicy.Releases), doc.TrustList.Seq)
	}
	if e, err := doc.TrustList.MinUnlockEpoch(); err != nil || e != 1 {
		t.Fatalf("min_unlock_epoch %d %v", e, err)
	}
	ws := filepath.Join(f.dir, "would-sign-epoch.json")
	os.WriteFile(ws, []byte(out), 0o644)
	// Signing without the flag derives another document: refused. With it: signed, and a verifier takes the epoch.
	if _, errOut, err := kmsctl(t, append(slices.Clone(base), "-end-overlap", "-sign-key", f.key, "-trust-key", f.key, "-dev-plain-keys",
		"-out", filepath.Join(f.dir, "no-epoch"), "-expect", ws)...); err == nil || !strings.Contains(errOut, "nothing signed") {
		t.Fatalf("signed without -min-unlock-epoch: %v\n%s", err, errOut)
	}
	signed := filepath.Join(f.dir, "signed-epoch")
	if _, errOut, err := kmsctl(t, append(slices.Clone(base), "-min-unlock-epoch", "1", "-sign-key", f.key, "-trust-key", f.key, "-dev-plain-keys",
		"-out", signed, "-expect", ws)...); err != nil {
		t.Fatalf("signing: %v\n%s", err, errOut)
	}
	var env safety.Envelope
	readJSON(filepath.Join(signed, "trust-list-4.signed.json"), &env)
	var got safety.TrustList
	json.Unmarshal(env.Payload, &got)
	p, err := verifier.Policy{}.WithTrustList(&got)
	if err != nil || p.MinUnlockEpoch != 1 {
		t.Fatalf("a verifier with the signed list: min epoch %d, %v", p.MinUnlockEpoch, err)
	}
	// With a release in the same run: both changes.
	rel, tr, _ := slotBuild(t, f.dir, "b", "v1.0.0")
	if out, errOut, err := kmsctl(t, append(slices.Clone(base), "-release", rel, "-trust-release", tr, "-min-unlock-epoch", "1", "-dry-run")...); err != nil ||
		!strings.Contains(out, `"min_unlock_epoch": 1`) || !strings.Contains(out, `"v1.0.0"`) {
		t.Fatalf("with a release: %v\n%s", err, errOut)
	}

	at := func(e uint32) string {
		l := safety.TrustList{Type: safety.TrustListType, Seq: 3, IssuedAt: time.Now().Add(-time.Hour)}
		if e > 0 {
			l.SetMinUnlockEpoch(e)
		}
		return writeJSONFile(t, filepath.Join(f.dir, "T-epoch-"+string(rune('0'+e))+".json"), l)
	}
	for _, c := range []struct {
		name string
		args []string
		want string
	}{
		{"no trust base", []string{"approve", "-base", f.base, "-min-unlock-epoch", "1"}, "-min-unlock-epoch needs -trust-base"},
		{"past the policy's epoch", append(slices.Clone(base), "-min-unlock-epoch", "2"), "past the policy's epoch 1"},
		{"the same again", append([]string{"approve", "-base", f.base, "-trust-base", at(1), "-min-unlock-epoch", "1"}, served...), "is 1 already"},
		{"lowered", append([]string{"approve", "-base", f.base, "-trust-base", at(3), "-min-unlock-epoch", "2"}, served...), "below the trust list's 3"},
		{"no served policy (re-review M2')", []string{"approve", "-base", f.base, "-trust-base", tl, "-min-unlock-epoch", "1"}, "needs -policy"},
		{"a base that isn't the served policy (re-review M2')", append([]string{"approve", "-base", otherBase(t, f), "-trust-base", tl, "-min-unlock-epoch", "1"}, served...), "-base isn't the served policy"},
	} {
		if out, errOut, err := kmsctl(t, append(c.args, "-dry-run")...); err == nil || !strings.Contains(errOut, c.want) {
			t.Errorf("%s: %v (want %q)\n%s%s", c.name, err, c.want, out, errOut)
		}
	}
}

// servedPolicy signs f's base as the served policy (-policy) and returns -policy and -admin-keys for it.
func servedPolicy(t *testing.T, f *approveFixture) []string {
	t.Helper()
	out, errOut, err := kmsctl(t, "sign", "-kind", "kms-unlock-policy", "-key", f.key, "-dev-plain-keys", f.base)
	if err != nil {
		t.Fatalf("sign: %v\n%s", err, errOut)
	}
	p := filepath.Join(f.dir, "served-policy.signed.json")
	os.WriteFile(p, []byte(out), 0o644)
	return []string{"-policy", p, "-admin-keys", kms.IDString(f.d.AdminPub)}
}

// otherBase is f's base changed (its floor) and never served: an unlock-policy output.
func otherBase(t *testing.T, f *approveFixture) string {
	t.Helper()
	var u map[string]any
	json.Unmarshal(readFile(f.base), &u)
	u["floor"] = "v1.0.1"
	return writeJSONFile(t, filepath.Join(f.dir, "U-other.json"), u)
}
