package verifier

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/tacyhq/tacy/proto"
)

// testdata/attest-065-kms.json is a real /attest response from a throwaway CVM on dstack-0.6.5 (Phala prod2,
// tdx.small, 2026-11-20; the P0 spike's KMS-fallback run k1), deployed with an app-compose.json in the fallback's
// form: key_provider kms, no deployer env, no pre-launch script (sent as ""), nothing public, only port 8080, an
// ephemeral data disk. Its nonce is the one it echoes. Its compose is the spike's (v0.19.4's images with named
// volumes on the disk, plus a diag service), so it is refused at the fallback's volume rule, after every check before
// it held on a genuine 0.6.5 quote: the boot measurements computed for 0.6.5, the pinned KMS root.
func load065(t *testing.T) (*proto.Attestation, []byte, string, string) {
	t.Helper()
	raw, err := os.ReadFile("../testdata/attest-065-kms.json")
	if err != nil {
		t.Fatal(err)
	}
	var a proto.Attestation
	if err := json.Unmarshal(raw, &a); err != nil {
		t.Fatal(err)
	}
	nonce, _ := hex.DecodeString(a.Nonce)
	var info struct {
		TcbInfo string `json:"tcb_info"`
	}
	json.Unmarshal(a.Info, &info)
	var tcb struct {
		AppCompose string `json:"app_compose"`
	}
	json.Unmarshal([]byte(info.TcbInfo), &tcb)
	return &a, nonce, tcb.AppCompose, attestedCompose(t, &a)
}

// What Phala attests is exactly ReleaseAppCompose's form: jq -cS of what was sent plus tproxy_enabled and the KMS
// root as key_provider_id, no pre_launch_script. So a release's pin is computed before it is deployed.
func TestReleaseAppComposeAsAttested(t *testing.T) {
	_, _, attested, compose := load065(t)
	var ac struct {
		Name string `json:"name"`
	}
	json.Unmarshal([]byte(attested), &ac)
	got, err := appComposeJSON([]byte(compose), nil, true, ac.Name)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte(attested)) {
		t.Fatalf("ReleaseAppCompose differs from what the 0.6.5 CVM attested:\n got %s\nwant %s", clip(got), clip([]byte(attested)))
	}
	// What the deploy sends for it: the same less what Phala adds, with an empty pre-launch script.
	deploy, err := DeployAppCompose(got)
	if err != nil {
		t.Fatal(err)
	}
	var d map[string]any
	json.Unmarshal(deploy, &d)
	if _, ok := d["tproxy_enabled"]; ok || d["key_provider_id"] != nil || d["pre_launch_script"] != "" || d["key_provider"] != "kms" {
		t.Fatalf("deploy form %v", d)
	}
}

func clip(b []byte) string {
	s := string(b)
	if i := strings.Index(s, `"docker_compose_file"`); i >= 0 {
		if j := strings.Index(s[i:], `","`); j > 0 {
			s = s[:i] + `"docker_compose_file":"…` + s[i+j:]
		}
	}
	return s
}

func TestRecorded065Fallback(t *testing.T) {
	a, nonce, attested, compose := load065(t)
	p := Policy{AllowStaleTCB: true, VerifyQuote: offline.VerifyQuote, Compose: []byte(compose), AppCompose: []byte(attested),
		KMSFallback: true, AllowE2EDiag: true}
	res, err := Verify(context.Background(), a, nonce, p)
	if err == nil || !strings.HasPrefix(err.Error(), AppComposeFlagsCheck+": KMS fallback: volume") || res.HPKEPublicKey != nil {
		t.Fatalf("want the volume rule: %v", err)
	}
	for i, c := range res.Checks {
		if c.OK != (i < len(res.Checks)-1) {
			t.Fatalf("check %d %q ok=%v (%s)", i, c.Name, c.OK, c.Detail)
		}
	}
	if res.Facts["OS image"] != "dstack-0.6.5" || res.Facts["boot measurements"] != BootMeasurements[0].Name ||
		res.Facts["KMS root"] != "Phala KMS, root since 2026-11-06" || res.Facts["pre-launch script"] != "none" {
		t.Fatalf("facts %v", res.Facts)
	}
	checkBootRecorded(t, a, &BootMeasurements[0])

	// Without the fallback allowed, the same VM fails at its keys.
	p.KMSFallback = false
	if _, err := Verify(context.Background(), a, nonce, p); err == nil || !strings.Contains(err.Error(), "explicit KMS fallback") {
		t.Fatalf("no fallback: %v", err)
	}
}
