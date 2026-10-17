package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	ehbpidentity "github.com/tinfoilsh/encrypted-http-body-protocol/identity"

	"github.com/tacyhq/tacy/agentclient"
	"github.com/tacyhq/tacy/proto"
)

// The relay sends the run's model in X-Agent-Model so it can charge for it: missing or unknown is refused before
// anything is queued (plaintext 400), and a header that doesn't match the encrypted body is refused after
// decryption (encrypted 400), before any model call.
func TestModelHeader(t *testing.T) {
	a, fm, _ := newTestAgent(t, textSSE("hi"))
	id, _ := ehbpidentity.NewIdentity()
	s := newTestServer(t, a, id, defaultLimits)
	mux := http.NewServeMux()
	mux.Handle("POST /run", s.guard(id.Middleware()(http.HandlerFunc(s.run))))
	srv := httptest.NewServer(mux)
	defer srv.Close()
	conn, _ := agentclient.New(srv.URL, "tok", id.MarshalPublicKey())
	run := func(model string) error {
		return conn.Run(context.Background(), proto.RunRequest{Model: model, Messages: []proto.Message{{Role: "user", Content: "x"}}}, func(proto.Event) {})
	}
	// The header claims the cheap model, the body asks for another one.
	conn.Model = "gpt-oss-120b"
	if err := run("kimi-k3"); err == nil || !strings.Contains(err.Error(), "400") || !strings.Contains(err.Error(), "model_mismatch") {
		t.Fatalf("mismatch: %v", err)
	}
	if len(fm.requests) != 0 {
		t.Fatal("a mismatched run reached the model")
	}
	conn.Model = "gpt-5"
	if err := run("gpt-oss-120b"); err == nil || !strings.Contains(err.Error(), "model_unknown") {
		t.Fatalf("unknown: %v", err)
	}
	// Matching (and the default model, named in the header by the client) works.
	conn.Model = ""
	if err := run(""); err != nil {
		t.Fatalf("default model: %v", err)
	}
	if len(fm.requests) != 1 {
		t.Fatalf("model calls %d", len(fm.requests))
	}
	// No header at all.
	req, _ := http.NewRequest("POST", srv.URL+"/run", strings.NewReader("ciphertext"))
	req.Header.Set("Authorization", "Bearer tok")
	req.Header.Set("Ehbp-Encapsulated-Key", strings.Repeat("ab", 32))
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var body struct{ Error string }
	json.NewDecoder(res.Body).Decode(&body)
	if res.StatusCode != 400 || body.Error != "model_required" {
		t.Fatalf("no header: %d %q", res.StatusCode, body.Error)
	}
}
