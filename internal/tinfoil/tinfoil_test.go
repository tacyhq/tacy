package tinfoil

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/sigstore/sigstore-go/pkg/root"
)

// testdata/router-release.json: Tinfoil router release v0.0.157 (digest + Sigstore bundle) and Sigstore's trusted
// root, recorded 2026-10-13 with RECORD=1 go test ./internal/tinfoil -run TestRecord.
type recorded struct {
	Repo, Tag, Digest string
	Bundle            json.RawMessage
	TrustedRoot       json.RawMessage
}

func TestRecord(t *testing.T) {
	if os.Getenv("RECORD") == "" {
		t.Skip("set RECORD=1 to refresh testdata")
	}
	ctx := context.Background()
	var rel struct {
		Tag string `json:"tag_name"`
	}
	raw, err := get(ctx, githubProxy+"/repos/"+DefaultRepo+"/releases/latest")
	if err != nil {
		t.Fatal(err)
	}
	json.Unmarshal(raw, &rel)
	hash, _ := get(ctx, githubProxy+"/"+DefaultRepo+"/releases/download/"+rel.Tag+"/tinfoil.hash")
	digest := strings.TrimSpace(string(hash))
	var atts struct {
		Attestations []struct {
			Bundle json.RawMessage `json:"bundle"`
		} `json:"attestations"`
	}
	raw, _ = get(ctx, githubProxy+"/repos/"+DefaultRepo+"/attestations/sha256:"+digest)
	json.Unmarshal(raw, &atts)
	tr, err := sigstoreRoot()
	if err != nil {
		t.Fatal(err)
	}
	trj, _ := tr.(*root.TrustedRoot).MarshalJSON()
	out, _ := json.MarshalIndent(recorded{DefaultRepo, rel.Tag, digest, atts.Attestations[0].Bundle, trj}, "", " ")
	os.WriteFile("testdata/router-release.json", out, 0o644)
}

func loadRelease(t *testing.T) (recorded, root.TrustedMaterial) {
	raw, err := os.ReadFile("testdata/router-release.json")
	if err != nil {
		t.Fatal(err)
	}
	var r recorded
	json.Unmarshal(raw, &r)
	tr, err := root.NewTrustedRootFromJSON(r.TrustedRoot)
	if err != nil {
		t.Fatal(err)
	}
	return r, tr
}

func TestReleaseOffline(t *testing.T) {
	r, tr := loadRelease(t)
	m, tag, err := Release(r.Bundle, r.Digest, r.Repo, tr)
	if err != nil || tag != r.Tag || len(m) != 96 {
		t.Fatalf("%v %s %s", err, tag, m)
	}
	// Another digest, another repo, or a modified bundle must fail.
	if _, _, err := Release(r.Bundle, strings.Repeat("ab", 32), r.Repo, tr); err == nil {
		t.Fatal("wrong digest accepted")
	}
	if _, _, err := Release(r.Bundle, r.Digest, "tinfoilsh/confidential-doc-upload", tr); err == nil {
		t.Fatal("wrong repo accepted")
	}
	var b map[string]any
	json.Unmarshal(r.Bundle, &b)
	env := b["dsseEnvelope"].(map[string]any)
	p := env["payload"].(string)
	i := len(p) / 2
	c := byte('A')
	if p[i] == 'A' {
		c = 'B'
	}
	env["payload"] = p[:i] + string(c) + p[i+1:] // one base64 char of the in-toto statement changed
	bad, _ := json.Marshal(b)
	if _, _, err := Release(bad, r.Digest, r.Repo, tr); err == nil {
		t.Fatal("modified bundle accepted")
	}
}

func TestHostOnly(t *testing.T) {
	h := hostOnly{host: "inference.tinfoil.sh", next: http.DefaultTransport}
	for _, u := range []string{"https://evil.example/v1/chat/completions", "http://inference.tinfoil.sh/x"} {
		req, _ := http.NewRequest("POST", u, nil)
		if _, err := h.RoundTrip(req); err == nil {
			t.Errorf("%s allowed", u)
		}
	}
}

// Live: verify the router now (AMD KDS, GitHub via Tinfoil's proxy, Sigstore TUF). Skipped with -short.
func TestVerifyLive(t *testing.T) {
	if testing.Short() {
		t.Skip("network")
	}
	v, err := Verify(context.Background(), DefaultEnclave, DefaultRepo)
	if err != nil {
		t.Fatal(err)
	}
	if len(v.HPKEKey) != 64 || len(v.Measurement) != 96 {
		t.Fatalf("%+v", v)
	}
	// A different repo's release doesn't match the router's measurement.
	if _, err := Verify(context.Background(), DefaultEnclave, "tinfoilsh/confidential-doc-upload"); err == nil {
		t.Fatal("router verified against another repo's release")
	}
}
