package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	ehbpidentity "github.com/tinfoilsh/encrypted-http-body-protocol/identity"

	"github.com/tacyhq/tacy/agentclient"
	"github.com/tacyhq/tacy/vault"
)

// inVault answers secrets ops as gatewayd passes them to vaultd, with a vault in this process.
type inVault struct{ v *vault.Vault }

func (f inVault) Secrets(_ context.Context, c *vault.SecretsCall) *vault.SecretsAnswer {
	switch c.Op {
	case "key":
		return &vault.SecretsAnswer{Key: f.v.SecretsKey()}
	case "status":
		st := f.v.SecretsStatus()
		return &vault.SecretsAnswer{Secrets: &st}
	}
	r, err := f.v.PutSecrets(*c.Push)
	if err != nil {
		return &vault.SecretsAnswer{Error: err.Error()}
	}
	return &vault.SecretsAnswer{Secrets: &r}
}

// pushServer is agentd's front door as main makes it on the CVM: the gate, the push routes, one route behind the
// token and the routes the quick path turns off.
func pushServer(t *testing.T) (*httptest.Server, *server, *vault.Vault, ed25519.PrivateKey, []byte) {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	v, err := vault.New(nil, vault.ChatGrants(""), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := v.EnableSecretsPush(pub); err != nil {
		t.Fatal(err)
	}
	id, err := ehbpidentity.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	s := &server{id: id, needPush: true, vaultSecrets: inVault{v}}
	mux := http.NewServeMux()
	s.secretsRoutes(mux, id)
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok\n") })
	mux.HandleFunc("POST /run", func(w http.ResponseWriter, r *http.Request) {
		if !s.authorized(r) {
			fail(w, 401, "unauthorized")
			return
		}
		io.WriteString(w, "ran")
	})
	for _, p := range []string{"/schedules/list", "/schedules/handoff", "/connections/put", "/spaces/reseal"} {
		mux.HandleFunc("POST "+p, func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "should be off") })
	}
	srv := httptest.NewServer(s.gate(mux, quickPathOff))
	t.Cleanup(srv.Close)
	return srv, s, v, priv, id.MarshalPublicKey()
}

func post(t *testing.T, url, token string) (int, string) {
	t.Helper()
	r, _ := http.NewRequest("POST", url, strings.NewReader("{}"))
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	res, err := http.DefaultClient.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return res.StatusCode, string(b)
}

func errCode(body string) string {
	var e struct {
		Error string `json:"error"`
	}
	json.Unmarshal([]byte(body), &e)
	return e.Error
}

var testKeys = map[string]string{"TINFOIL_API_KEY": "tf-canary-0123456789", "EXA_API_KEY": "exa-canary-0123456789",
	"TAVILY_API_KEY": "tvly-canary-0123456789"}

const testToken = "relay-token-canary-0123456789abcdef"

// Until the Worker's push arrives, /run answers "starting"; after it, the pushed token (and only it) is accepted;
// schedules and connections answer their off codes either way.
func TestSecretsGateAndPush(t *testing.T) {
	srv, s, v, signer, key := pushServer(t)
	if st, body := post(t, srv.URL+"/run", testToken); st != 503 || errCode(body) != "starting" {
		t.Fatalf("/run before the push: %d %s", st, body)
	}
	if ready, err := agentclient.SecretsReady(context.Background(), srv.URL); err != nil || ready {
		t.Fatalf("status before: %v %v", ready, err)
	}
	if res, err := http.Get(srv.URL + "/health"); err != nil || res.StatusCode != 200 {
		t.Fatalf("/health before the push: %v %v", res, err)
	}
	// The key route is EHBP only (the answer must come from the attested key).
	if st, _ := post(t, srv.URL+"/secrets/key", ""); st != 400 {
		t.Fatalf("plaintext /secrets/key: %d", st)
	}
	c, err := agentclient.New(srv.URL, testToken, key)
	if err != nil {
		t.Fatal(err)
	}
	// A push signed by another key is refused; nothing changes.
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := c.PushSecrets(context.Background(), testKeys, testToken, other); !errors.Is(err, agentclient.ErrPushSignature) {
		t.Fatalf("forged push: %v", err)
	}
	if s.push.ready.Load() || len(v.Names()) != 0 {
		t.Fatal("a forged push made the VM ready")
	}
	names, err := c.PushSecrets(context.Background(), testKeys, testToken, signer)
	if err != nil || len(names) != 3 {
		t.Fatalf("push: %v %v", names, err)
	}
	if st, body := post(t, srv.URL+"/run", testToken); st != 200 || body != "ran" {
		t.Fatalf("/run after the push: %d %s", st, body)
	}
	for _, tok := range []string{"", "wrong", testToken + "x"} {
		if st, _ := post(t, srv.URL+"/run", tok); st != 401 {
			t.Fatalf("token %q: %d", tok, st)
		}
	}
	for p, code := range map[string]string{"/schedules/list": "schedules_off", "/schedules/handoff": "schedules_off",
		"/spaces/reseal": "schedules_off", "/connections/put": "connections_off"} {
		if st, body := post(t, srv.URL+p, testToken); st != 503 || errCode(body) != code {
			t.Errorf("%s: %d %s", p, st, body)
		}
	}
	// A vault that restarted (its keys gone) puts agentd back to starting at the next watch.
	s.push.set(&vault.SecretsResult{})
	if st, body := post(t, srv.URL+"/run", testToken); st != 503 || errCode(body) != "starting" {
		t.Fatalf("/run after the vault lost its keys: %d %s", st, body)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	s.watchSecrets(ctx, 0) // one look: the vault still has them here
	if !s.push.ready.Load() {
		t.Fatal("the watch didn't find the vault's keys")
	}
}
