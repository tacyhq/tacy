package main

import (
	"encoding/base64"
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
	os.WriteFile(ac, []byte(`{"name":"agent-vm"}`), 0o644)
	os.WriteFile(cy, []byte("services: {}\n"), 0o644)
	rel := "app=agent-vm,version=v1.0.0,app-compose=" + ac + ",compose=" + cy
	outDir := filepath.Join(dir, "signed")
	out, errOut, err = kmsctl(t, "approve", "-base", base, "-release", rel, "-out", outDir, "-dry-run")
	if err != nil {
		t.Fatalf("approve -dry-run: %v\n%s", err, errOut)
	}
	var np split.UnlockPolicy
	if err := json.Unmarshal([]byte(out), &np); err != nil {
		t.Fatalf("approve -dry-run's stdout: %v\n%s", err, out)
	}
	if np.Seq != 2 || len(np.Releases) != 1 || np.Releases[0].App != "agent-vm" || np.Releases[0].AppComposeSHA256 != fileSHA256(ac) ||
		!strings.Contains(errOut, "unsigned, nothing written") || !strings.Contains(errOut, "CF_TUNNEL_TOKEN_VMB") {
		t.Fatalf("approve -dry-run: %+v\n%s", np.Releases, errOut)
	}
	if _, err := os.Stat(outDir); !os.IsNotExist(err) {
		t.Fatalf("approve -dry-run wrote %s: %v", outDir, err)
	}
	if _, errOut, err := kmsctl(t, "approve", "-base", base, "-release", rel, "-dry-run", "-emergency", "x"); err == nil || !strings.Contains(errOut, "no -emergency") {
		t.Fatalf("approve -dry-run -emergency: %v\n%s", err, errOut)
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
	for name, v := range map[string]map[string]string{"only-a": onlyA, "extra": extra, "empty-b": func() map[string]string {
		m := map[string]string{}
		for k, x := range values {
			m[k] = x
		}
		m["CF_TUNNEL_TOKEN_VMB"] = ""
		return m
	}()} {
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
