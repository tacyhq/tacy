package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/tacyhq/tacy/kms/split"
	"github.com/tacyhq/tacy/kms/split/splitdev"
	"github.com/tacyhq/tacy/safety"
)

// mainEnv makes the test binary run main() with the arguments after "--".
const mainEnv = "TACY_KMSCTL_TEST_MAIN"

func TestMain(m *testing.M) {
	if os.Getenv(mainEnv) == "1" {
		for i, a := range os.Args {
			if a == "--" {
				os.Args = append([]string{os.Args[0]}, os.Args[i+1:]...)
				break
			}
		}
		main()
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func kmsctl(t *testing.T, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	cmd := exec.Command(os.Args[0], append([]string{"-test.run=^$", "--"}, args...)...)
	cmd.Env = append(os.Environ(), mainEnv+"=1")
	var o, e strings.Builder
	cmd.Stdout, cmd.Stderr = &o, &e
	err = cmd.Run()
	return o.String(), e.String(), err
}

func writeJSONFile(t *testing.T, path string, v any) string {
	t.Helper()
	b, _ := json.Marshal(v)
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// The first production policy (deploy checklist step 11) is made with no -base, so its agent-vm grant comes from
// the repository's grants file (-apps): without it the policy is refused, since approve would refuse the release pin
// ("release pin for unknown app"). With it, the grant names both tunnel tokens, and approve -dry-run shows the
// policy it would sign and writes nothing.
func TestFirstPolicyApps(t *testing.T) {
	now := time.Now().UTC()
	d, err := splitdev.New([]string{"cloudflare", "vercel"}, 2, now.Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	set := writeJSONFile(t, filepath.Join(dir, "share-set-1.json"), d.Set)
	cert := writeJSONFile(t, filepath.Join(dir, "epoch-cert-1.json"), d.Cert)
	args := []string{"unlock-policy", "-kms-id", d.KMSID, "-seq", "1", "-floor", "v1.0.0",
		"-holders", "cloudflare=https://keys-cf.tacy.io,vercel=https://keys-v.tacy.io", "-share-set", set, "-epoch-cert", cert}
	for i, c := range d.Policy.MachineCerts {
		args = append(args, "-machine-cert", writeJSONFile(t, filepath.Join(dir, "machine-"+string(rune('a'+i))+".json"), c))
	}

	// Step 11 as the checklist had it: refused, nothing on stdout.
	out, errOut, err := kmsctl(t, args...)
	if err == nil || out != "" || !strings.Contains(errOut, "no app grant") || !strings.Contains(errOut, "-apps kms/policies/agent-vm-v1.json") {
		t.Fatalf("unlock-policy without -apps: %v\nstdout %s\nstderr %s", err, out, errOut)
	}

	// With the repository's grants file.
	out, errOut, err = kmsctl(t, append(args, "-apps", "../../kms/policies/agent-vm-v1.json")...)
	if err != nil {
		t.Fatalf("unlock-policy -apps: %v\n%s", err, errOut)
	}
	var u split.UnlockPolicy
	if err := json.Unmarshal([]byte(out), &u); err != nil {
		t.Fatal(err)
	}
	g, ok := u.Apps[splitdev.App]
	if len(u.Apps) != 1 || !ok || g.Firm != splitdev.Firm || !slices.Contains(g.Secrets, "CF_TUNNEL_TOKEN_VMA") || !slices.Contains(g.Secrets, "CF_TUNNEL_TOKEN_VMB") {
		t.Fatalf("the policy's grants: %+v", u.Apps)
	}
	if !strings.Contains(errOut, "app agent-vm: firm f_chat, floor the policy's, purposes state/v1 ") ||
		!strings.Contains(errOut, "secrets TINFOIL_API_KEY EXA_API_KEY TAVILY_API_KEY CF_TUNNEL_TOKEN_VMA CF_TUNNEL_TOKEN_VMB") {
		t.Fatalf("the grant isn't summed up on stderr:\n%s", errOut)
	}
	base := filepath.Join(dir, "U.json")
	os.WriteFile(base, []byte(out), 0o644)

	// A grants file naming one tunnel token is refused.
	one := filepath.Join(dir, "one-slot.json")
	os.WriteFile(one, []byte(`{"agent-vm": {"firm": "f_chat", "purposes": ["conn/v1"], "secrets": ["CF_TUNNEL_TOKEN_VMA"]}}`), 0o644)
	if _, errOut, err := kmsctl(t, append(args, "-apps", one)...); err == nil || !strings.Contains(errOut, "names one tunnel token") {
		t.Fatalf("one tunnel token: %v\n%s", err, errOut)
	}

	// approve -dry-run: the next seq with the release pinned, unsigned, on stdout; nothing written, no key needed.
	ac, cy := filepath.Join(dir, "app-compose.json"), filepath.Join(dir, "compose.yaml")
	os.WriteFile(ac, []byte(`{"name":"agent-vm","docker_compose_file":"services: {}\n"}`), 0o644)
	os.WriteFile(cy, []byte("services: {}\n"), 0o644)
	rel := "app=agent-vm,version=v1.0.0,app-compose=" + ac + ",compose=" + cy
	outDir := filepath.Join(dir, "signed")
	out, errOut, err = kmsctl(t, "approve", "-base", base, "-release", rel, "-out", outDir, "-dry-run")
	if err != nil {
		t.Fatalf("approve -dry-run: %v\n%s", err, errOut)
	}
	var dry struct {
		UnlockPolicy split.UnlockPolicy `json:"unlock_policy"`
	}
	if err := json.Unmarshal([]byte(out), &dry); err != nil {
		t.Fatalf("approve -dry-run's stdout: %v\n%s", err, out)
	}
	np := dry.UnlockPolicy
	if np.Seq != 2 || len(np.Releases) != 1 || np.Releases[0].App != "agent-vm" || np.Releases[0].AppComposeSHA256 != fileSHA256(ac) ||
		!strings.Contains(errOut, "unsigned, nothing written") || !strings.Contains(errOut, "CF_TUNNEL_TOKEN_VMB") {
		t.Fatalf("approve -dry-run: %+v\n%s", np.Releases, errOut)
	}
	if _, err := os.Stat(outDir); !os.IsNotExist(err) {
		t.Fatalf("approve -dry-run wrote %s: %v", outDir, err)
	}
	// -emergency can be previewed (slots re-check Low 1): everything but the override, no shares, nothing written.
	if _, errOut, err := kmsctl(t, "approve", "-base", base, "-release", rel, "-out", outDir, "-dry-run", "-emergency", "x"); err != nil ||
		!strings.Contains(errOut, `-emergency "x": the override expedites release:`) {
		t.Fatalf("approve -dry-run -emergency: %v\n%s", err, errOut)
	}
	if _, err := os.Stat(outDir); !os.IsNotExist(err) {
		t.Fatalf("approve -dry-run -emergency wrote %s: %v", outDir, err)
	}
	if _, errOut, err := kmsctl(t, "approve", "-base", base, "-release", rel); err == nil || !strings.Contains(errOut, "-sign-key K -out DIR") {
		t.Fatalf("approve without -dry-run, -out or -sign-key: %v\n%s", err, errOut)
	}

	// The gap -apps closes: a base without the grant can't pin the release.
	u.Apps = nil
	noApps := writeJSONFile(t, filepath.Join(dir, "U-no-apps.json"), u)
	if _, errOut, err := kmsctl(t, "approve", "-base", noApps, "-release", rel, "-dry-run"); err == nil || !strings.Contains(errOut, "release pin for unknown app") {
		t.Fatalf("approve on a policy without the grant: %v\n%s", err, errOut)
	}
}

// secrets-seal (deploy checklist step 10) takes the grants file and seals only a bundle with exactly its names: both
// tunnel tokens among them, so a later v1 release on the other slot needs no second ceremony. Missing one is refused
// before anything is written, and the error names names, never values.
func TestSecretsSealBothTunnels(t *testing.T) {
	d, err := splitdev.New([]string{"cloudflare", "vercel"}, 2, time.Now().Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	dm := filepath.Join(dir, "dev-master")
	os.WriteFile(dm, []byte(base64.StdEncoding.EncodeToString(d.Master)), 0o600)
	values := map[string]string{"TINFOIL_API_KEY": "tin-value", "EXA_API_KEY": "exa-value", "TAVILY_API_KEY": "tav-value",
		"CF_TUNNEL_TOKEN_VMA": "tunnel-a-value", "CF_TUNNEL_TOKEN_VMB": "tunnel-b-value"}
	seal := func(name string, v map[string]string, extra ...string) (string, string, error) {
		in := writeJSONFile(t, filepath.Join(dir, name+".json"), v)
		out := filepath.Join(dir, name+".sealed")
		_, errOut, err := kmsctl(t, append([]string{"secrets-seal", "-kms-id", d.KMSID, "-dev-master", dm, "-epoch", "1", "-seq", "1",
			"-in", in, "-out", out}, extra...)...)
		return out, errOut, err
	}
	apps := []string{"-apps", "../../kms/policies/agent-vm-v1.json"}

	if out, errOut, err := seal("no-apps", values); err == nil || !strings.Contains(errOut, "-apps F") {
		t.Fatalf("secrets-seal without -apps: %v\n%s", err, errOut)
	} else if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Fatal("written without -apps")
	}
	onlyA := map[string]string{}
	for k, v := range values {
		if k != "CF_TUNNEL_TOKEN_VMB" {
			onlyA[k] = v
		}
	}
	extra := map[string]string{"OTHER": "other-value"}
	for k, v := range values {
		extra[k] = v
	}
	with := func(name, value string) map[string]string {
		m := map[string]string{}
		for k, x := range values {
			m[k] = x
		}
		m[name] = value
		return m
	}
	for name, v := range map[string]map[string]string{"only-a": onlyA, "extra": extra, "empty-b": with("CF_TUNNEL_TOKEN_VMB", ""),
		"blank-b": with("CF_TUNNEL_TOKEN_VMB", " \t\n"), "blank-exa": with("EXA_API_KEY", "  ")} {
		out, errOut, err := seal(name, v, apps...)
		if err == nil || !strings.Contains(errOut, "exactly the grants' names") || strings.Contains(errOut, "-value") {
			t.Fatalf("%s: %v\n%s", name, err, errOut)
		}
		if _, err := os.Stat(out); !os.IsNotExist(err) {
			t.Fatalf("%s: written", name)
		}
	}
	out, errOut, err := seal("both", values, apps...)
	if err != nil {
		t.Fatalf("secrets-seal: %v\n%s", err, errOut)
	}
	b, err := split.OpenSecrets(d.Root, d.KMSID, 1, readFile(out))
	if err != nil {
		t.Fatal(err)
	}
	if len(b.Values) != 5 || b.Values["CF_TUNNEL_TOKEN_VMA"] != "tunnel-a-value" || b.Values["CF_TUNNEL_TOKEN_VMB"] != "tunnel-b-value" {
		t.Fatalf("the bundle's names: %d", len(b.Values))
	}
}

// Slots review M2: the approve that signs takes the dry run's output back (-expect) and signs only what it showed. It
// derives the policy and trust list again from its inputs and compares bytes, issued_at aside, so an input changed
// between the two runs (here the app-compose, the trust entry, the base) is refused and nothing is signed. Both runs print
// the same sha256 for each document.
// approveFixture is a first policy (agent-vm grant), a release to pin, a trust list and its entry, and the dev admin
// key: approve's arguments for them (no -sign-key, -out, -dry-run or -expect) and the files a test changes.
type approveFixture struct {
	d                      *splitdev.Dev
	dir, base, ac, tr, key string
	baseJSON               string
	entry                  safety.TrustRelease
	approve                []string
}

func newApproveFixture(t *testing.T) *approveFixture {
	t.Helper()
	now := time.Now().UTC()
	d, err := splitdev.New([]string{"cloudflare", "vercel"}, 2, now.Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	d.Policy.Apps = nil
	set := writeJSONFile(t, filepath.Join(dir, "share-set-1.json"), d.Set)
	cert := writeJSONFile(t, filepath.Join(dir, "epoch-cert-1.json"), d.Cert)
	args := []string{"unlock-policy", "-kms-id", d.KMSID, "-seq", "1", "-floor", "v1.0.0", "-apps", "../../kms/policies/agent-vm-v1.json",
		"-holders", "cloudflare=https://keys-cf.tacy.io,vercel=https://keys-v.tacy.io", "-share-set", set, "-epoch-cert", cert}
	for i, c := range d.Policy.MachineCerts {
		args = append(args, "-machine-cert", writeJSONFile(t, filepath.Join(dir, "machine-"+string(rune('a'+i))+".json"), c))
	}
	out, errOut, err := kmsctl(t, args...)
	if err != nil {
		t.Fatalf("unlock-policy: %v\n%s", err, errOut)
	}
	base := filepath.Join(dir, "U.json")
	os.WriteFile(base, []byte(out), 0o644)
	ac, cy := filepath.Join(dir, "app-compose.json"), filepath.Join(dir, "compose.yaml")
	os.WriteFile(ac, []byte(`{"name":"agent-vm","docker_compose_file":"services: {}\n"}`), 0o644)
	os.WriteFile(cy, []byte("services: {}\n"), 0o644)
	tl := writeJSONFile(t, filepath.Join(dir, "T.json"), safety.TrustList{Type: safety.TrustListType, Seq: 3, IssuedAt: now.Add(-24 * time.Hour)})
	entry := safety.TrustRelease{Version: "v1.0.0", Commit: strings.Repeat("3", 40), ComposeSHA256: fileSHA256(cy), Bundle: []byte(`{}`)}
	tr := writeJSONFile(t, filepath.Join(dir, "R.json"), entry)
	key := filepath.Join(dir, "admin.key")
	os.WriteFile(key, []byte(base64.StdEncoding.EncodeToString(d.Admin.Seed())), 0o600)
	approve := []string{"approve", "-base", base, "-release", "app=agent-vm,version=v1.0.0,app-compose=" + ac + ",compose=" + cy,
		"-trust-base", tl, "-trust-release", tr}
	return &approveFixture{d: d, dir: dir, base: base, ac: ac, tr: tr, key: key, baseJSON: out, entry: entry, approve: approve}
}

// sign runs approve with the admin keys, -out outDir, -expect expect (if any) and extra; it returns stdout and stderr.
func (f *approveFixture) sign(t *testing.T, expect, outDir string, extra ...string) (string, string, error) {
	t.Helper()
	a := append(slices.Clone(f.approve), "-sign-key", f.key, "-trust-key", f.key, "-dev-plain-keys", "-out", outDir)
	if expect != "" {
		a = append(a, "-expect", expect)
	}
	return kmsctl(t, append(a, extra...)...)
}

// dryRun runs approve -dry-run (and extra) into the file name; it returns that file, the digest lines and stderr.
func (f *approveFixture) dryRun(t *testing.T, name string, extra ...string) (string, []string, string) {
	t.Helper()
	out, errOut, err := kmsctl(t, append(append(slices.Clone(f.approve), "-dry-run"), extra...)...)
	if err != nil {
		t.Fatalf("approve -dry-run: %v\n%s", err, errOut)
	}
	p := filepath.Join(f.dir, name)
	os.WriteFile(p, []byte(out), 0o644)
	return p, digestLines(errOut), errOut
}

func digestLines(s string) []string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if strings.Contains(l, " sha256 ") {
			out = append(out, l)
		}
	}
	return out
}

func TestApproveSignsTheDryRun(t *testing.T) {
	f := newApproveFixture(t)
	dir, ac, tr, base, out, entry := f.dir, f.ac, f.tr, f.base, f.baseJSON, f.entry
	sign := func(expect, outDir string) (string, error) {
		_, errOut, err := f.sign(t, expect, outDir)
		return errOut, err
	}
	digests := digestLines

	wouldSign, dd, _ := f.dryRun(t, "would-sign.json")
	if len(dd) != 2 || !strings.HasPrefix(dd[0], "unlock policy seq 2 sha256 ") || !strings.HasPrefix(dd[1], "trust list seq 4 sha256 ") {
		t.Fatalf("approve -dry-run's digests: %q", dd)
	}
	var doc struct {
		UnlockPolicy json.RawMessage `json:"unlock_policy"`
		TrustList    json.RawMessage `json:"trust_list"`
	}
	if err := json.Unmarshal(readFile(wouldSign), &doc); err != nil || len(doc.TrustList) == 0 {
		t.Fatalf("approve -dry-run shows no trust list: %v", err)
	}

	// No -expect: refused, nothing written.
	if errOut, err := sign("", filepath.Join(dir, "no-expect")); err == nil || !strings.Contains(errOut, "-expect would-sign.json") {
		t.Fatalf("approve without -expect: %v\n%s", err, errOut)
	}
	// An input changed after the dry run: refused, nothing written.
	refused := func(name, wantDoc string) {
		t.Helper()
		outDir := filepath.Join(dir, name)
		if errOut, err := sign(wouldSign, outDir); err == nil || !strings.Contains(errOut, wantDoc+" this run derives isn't the one the dry run showed") ||
			!strings.Contains(errOut, "nothing signed") {
			t.Fatalf("%s: %v\n%s", name, err, errOut)
		}
		if _, err := os.Stat(outDir); !os.IsNotExist(err) {
			t.Fatalf("%s: written", name)
		}
	}
	os.WriteFile(ac, []byte(`{"name":"agent-vm-2","docker_compose_file":"services: {}\n"}`), 0o644) // the app-compose
	refused("changed-app-compose", "the unlock policy")
	os.WriteFile(ac, []byte(`{"name":"agent-vm","docker_compose_file":"services: {}\n"}`), 0o644)
	entry.Commit = strings.Repeat("4", 40) // the trust entry
	writeJSONFile(t, tr, entry)
	refused("changed-entry", "the trust list")
	entry.Commit = strings.Repeat("3", 40)
	writeJSONFile(t, tr, entry)
	var u split.UnlockPolicy // the base
	json.Unmarshal([]byte(out), &u)
	u.Floor = "v1.0.1"
	writeJSONFile(t, base, u)
	refused("changed-base", "the unlock policy")
	os.WriteFile(base, []byte(out), 0o644)
	// The dry run's file edited: refused.
	edited := filepath.Join(dir, "edited.json")
	os.WriteFile(edited, []byte(strings.Replace(string(readFile(wouldSign)), `"seq": 2`, `"seq": 3`, 1)), 0o644)
	if errOut, err := sign(edited, filepath.Join(dir, "edited")); err == nil || !strings.Contains(errOut, "nothing signed") {
		t.Fatalf("an edited dry run: %v\n%s", err, errOut)
	}

	// The same inputs: signed, with the dry run's digests.
	outDir := filepath.Join(dir, "signed")
	errOut, err := sign(wouldSign, outDir)
	if err != nil {
		t.Fatalf("approve -expect: %v\n%s", err, errOut)
	}
	if got := digests(errOut); !slices.Equal(got, dd) {
		t.Fatalf("the signing run's digests %q aren't the dry run's %q", got, dd)
	}
	var env safety.Envelope
	if err := json.Unmarshal(readFile(filepath.Join(outDir, "unlock-policy-2.signed.json")), &env); err != nil {
		t.Fatal(err)
	}
	var signed split.UnlockPolicy
	json.Unmarshal(env.Payload, &signed)
	signed.IssuedAt = time.Time{}
	b, _ := json.Marshal(&signed)
	h := sha256.Sum256(b)
	if !strings.Contains(dd[0], hex.EncodeToString(h[:])) {
		t.Fatalf("the signed policy's digest isn't the one printed: %s", dd[0])
	}
	if _, err := os.Stat(filepath.Join(outDir, "trust-list-4.signed.json")); err != nil {
		t.Fatal(err)
	}
}

// Slots re-check Low 1: approve -emergency signs only what a -dry-run -emergency showed, the override aside. The dry
// run needs no shares and shows everything but the override; the signing run needs -expect, matches both documents
// with the override left out, and only then attaches it.
func TestApproveEmergencySignsTheDryRun(t *testing.T) {
	f := newApproveFixture(t)
	master := filepath.Join(f.dir, "master.b64")
	os.WriteFile(master, []byte(base64.StdEncoding.EncodeToString(f.d.Master)), 0o600)
	em := []string{"-emergency", "CVE fix", "-dev-master", master}

	wouldSign, dd, errOut := f.dryRun(t, "would-sign-emergency.json", "-emergency", "CVE fix")
	if len(dd) != 2 || !strings.Contains(errOut, `-emergency "CVE fix": the override expedites release:`) {
		t.Fatalf("approve -dry-run -emergency: %q\n%s", dd, errOut)
	}
	var doc struct {
		UnlockPolicy json.RawMessage  `json:"unlock_policy"`
		TrustList    json.RawMessage  `json:"trust_list"`
		Emergency    *dryRunEmergency `json:"emergency"`
	}
	if err := json.Unmarshal(readFile(wouldSign), &doc); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(doc.UnlockPolicy), `"emergency"`) || strings.Contains(string(doc.TrustList), `"emergency"`) {
		t.Fatal("approve -dry-run -emergency shows an override it can't sign")
	}
	// Slots4 1: the override's reason and items, shown as the dry run's unsigned "emergency" member.
	if e := doc.Emergency; e == nil || e.Reason != "CVE fix" || len(e.Items) != 1 || !strings.HasPrefix(e.Items[0], "release:") ||
		len(e.TrustItems) != 1 {
		t.Fatalf("approve -dry-run -emergency's emergency member: %+v", doc.Emergency)
	}
	plainFile, plain, _ := f.dryRun(t, "would-sign.json")
	if !slices.Equal(dd, plain) {
		t.Fatalf("with -emergency the dry run's documents %q aren't the plain run's %q", dd, plain)
	}

	// Slots4 1: -expect binds the override too. A different -emergency-item or reason, -emergency against a plain dry
	// run, or a plain run against an -emergency dry run: refused before anything is signed, nothing written.
	overrideRefused := func(name, expect string, extra ...string) {
		t.Helper()
		outDir := filepath.Join(f.dir, name)
		stdout, errOut, err := f.sign(t, expect, outDir, extra...)
		if err == nil || !strings.Contains(errOut, "the emergency override (its reason or items) this run derives isn't the one the dry run showed") ||
			!strings.Contains(errOut, "nothing signed") || strings.Contains(stdout, "EMERGENCY override") {
			t.Fatalf("%s: %v\n%s%s", name, err, stdout, errOut)
		}
		if _, err := os.Stat(outDir); !os.IsNotExist(err) {
			t.Fatalf("%s: written", name)
		}
	}
	overrideRefused("other-item", wouldSign, append(slices.Clone(em), "-emergency-item", "other")...)
	overrideRefused("other-reason", wouldSign, "-emergency", "another reason", "-dev-master", master)
	overrideRefused("emergency-on-plain", plainFile, em...)
	overrideRefused("plain-on-emergency", wouldSign)

	// No -expect: refused, nothing written.
	noExpect := filepath.Join(f.dir, "no-expect")
	if _, errOut, err := f.sign(t, "", noExpect, em...); err == nil || !strings.Contains(errOut, "-expect would-sign.json") {
		t.Fatalf("approve -emergency without -expect: %v\n%s", err, errOut)
	}
	if _, err := os.Stat(noExpect); !os.IsNotExist(err) {
		t.Fatal("approve -emergency without -expect: written")
	}
	// An input changed after the dry run: refused before the override is signed, nothing written.
	os.WriteFile(f.ac, []byte(`{"name":"agent-vm-2","docker_compose_file":"services: {}\n"}`), 0o644)
	changed := filepath.Join(f.dir, "changed")
	stdout, errOut, err := f.sign(t, wouldSign, changed, em...)
	if err == nil || !strings.Contains(errOut, "nothing signed") || strings.Contains(stdout, "EMERGENCY override") {
		t.Fatalf("approve -emergency, app-compose changed: %v\n%s%s", err, stdout, errOut)
	}
	if _, err := os.Stat(changed); !os.IsNotExist(err) {
		t.Fatal("approve -emergency, app-compose changed: written")
	}
	os.WriteFile(f.ac, []byte(`{"name":"agent-vm","docker_compose_file":"services: {}\n"}`), 0o644)

	// The same inputs: signed, with the dry run's digests, and the override in both documents.
	outDir := filepath.Join(f.dir, "signed")
	stdout, errOut, err = f.sign(t, wouldSign, outDir, em...)
	if err != nil || !strings.Contains(stdout, "EMERGENCY override") {
		t.Fatalf("approve -emergency -expect: %v\n%s%s", err, stdout, errOut)
	}
	if got := digestLines(errOut); !slices.Equal(got, dd) {
		t.Fatalf("the signing run's digests %q aren't the dry run's %q", got, dd)
	}
	var env safety.Envelope
	var signed split.UnlockPolicy
	if json.Unmarshal(readFile(filepath.Join(outDir, "unlock-policy-2.signed.json")), &env) != nil || json.Unmarshal(env.Payload, &signed) != nil ||
		signed.Emergency == nil {
		t.Fatal("the signed policy carries no override")
	}
	// Left out, the override: the signed policy is the dry run's.
	signed.Emergency = nil
	if !strings.Contains(dd[0], digest(&signed)) {
		t.Fatalf("the signed policy without its override isn't the dry run's: %s", dd[0])
	}
	var tenv safety.Envelope
	var stl safety.TrustList
	if json.Unmarshal(readFile(filepath.Join(outDir, "trust-list-4.signed.json")), &tenv) != nil || json.Unmarshal(tenv.Payload, &stl) != nil {
		t.Fatal("no signed trust list")
	}
	if _, ok := stl.Optional[safety.TrustEmergencyMember]; !ok {
		t.Fatal("the signed trust list carries no override")
	}
	delete(stl.Optional, safety.TrustEmergencyMember)
	if len(stl.Optional) == 0 {
		stl.Optional = nil
	}
	if !strings.Contains(dd[1], digest(&stl)) {
		t.Fatalf("the signed trust list without its override isn't the dry run's: %s", dd[1])
	}
}
