package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	ehbpidentity "github.com/tinfoilsh/encrypted-http-body-protocol/identity"

	"github.com/tacyhq/tacy/agentclient"
	"github.com/tacyhq/tacy/relay"
	"github.com/tacyhq/tacy/vault"
)

// inVault answers secrets ops as gatewayd passes them to vaultd, with a vault in this process.
type inVault struct{ v *vault.Vault }

func (f inVault) Secrets(_ context.Context, c *vault.SecretsCall) *vault.SecretsAnswer {
	if c.Op != "status" {
		return &vault.SecretsAnswer{Error: vault.ErrBadRequest.Error()}
	}
	st := f.v.SecretsStatus()
	return &vault.SecretsAnswer{Secrets: &st}
}

// keysServer is agentd's front door as main makes it on the CVM: the relay's envelopes, the gate, the status route,
// one route that needs the keys, and the routes a VM without sealed state turns off.
func keysServer(t *testing.T) (*httptest.Server, *server, *vault.Vault, []byte) {
	t.Helper()
	v, err := vault.New(nil, vault.ChatGrants(""), nil)
	if err != nil {
		t.Fatal(err)
	}
	id, err := ehbpidentity.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	s := &server{id: id, needKeys: true, vaultSecrets: inVault{v}}
	mux := http.NewServeMux()
	s.secretsRoutes(mux)
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
	srv := httptest.NewServer(s.front(s.gate(mux, quickPathOff), &relay.Server{Key: testRelayPub(), Inner: s.gate(mux, quickPathOff)}))
	t.Cleanup(srv.Close)
	return srv, s, v, id.MarshalPublicKey()
}

// vmClient sends requests as the relay does: each in a signed envelope to the boot's key.
func vmClient(t *testing.T, key []byte) *http.Client {
	k, err := relay.ParseKey(testRelaySeed)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Client{Transport: &relay.Transport{VMKey: key, Key: k}}
}

func postVM(t *testing.T, c *http.Client, url string) (int, string) {
	t.Helper()
	res, err := c.Post(url, "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return res.StatusCode, string(b)
}

var testKeys = map[string]string{"TINFOIL_API_KEY": "tf-canary-0123456789", "EXA_API_KEY": "exa-canary-0123456789",
	"TAVILY_API_KEY": "tvly-canary-0123456789"}

// Until vaultd has the key service's API keys, what needs them answers "starting"; after, it runs; schedules and
// connections answer their off codes on a VM without sealed state either way.
func TestSecretsGate(t *testing.T) {
	srv, s, v, key := keysServer(t)
	c := vmClient(t, key)
	if st, body := postVM(t, c, srv.URL+"/run"); st != 503 || errCode(body) != "starting" {
		t.Fatalf("/run before the keys: %d %s", st, body)
	}
	if ready, err := agentclient.SecretsReady(context.Background(), c, srv.URL); err != nil || ready {
		t.Fatalf("status before: %v %v", ready, err)
	}
	if res, err := http.Get(srv.URL + "/health"); err != nil || res.StatusCode != 200 {
		t.Fatalf("/health before the keys: %v %v", res, err)
	}
	// Outside an envelope nothing but the front door answers, and no route takes secrets at all.
	for _, p := range []string{"/secrets", "/secrets/key", "/secrets/status", "/run"} {
		if res, err := http.Post(srv.URL+p, "application/json", strings.NewReader("{}")); err != nil || res.StatusCode != 404 {
			t.Errorf("plaintext %s: %v", p, res.StatusCode)
		}
	}
	if _, err := v.SetSecrets(testKeys); err != nil { // vaultd's release from the key service
		t.Fatal(err)
	}
	if ready, err := agentclient.SecretsReady(context.Background(), c, srv.URL); err != nil || !ready {
		t.Fatalf("status after: %v %v", ready, err)
	}
	if st, body := postVM(t, c, srv.URL+"/run"); st != 200 || body != "ran" {
		t.Fatalf("/run after the keys: %d %s", st, body)
	}
	for p, code := range map[string]string{"/schedules/list": "schedules_off", "/schedules/handoff": "schedules_off",
		"/spaces/reseal": "schedules_off", "/connections/put": "connections_off"} {
		if st, body := postVM(t, c, srv.URL+p); st != 503 || errCode(body) != code {
			t.Errorf("%s: %d %s", p, st, body)
		}
	}
	// A vault that restarted (its keys gone until its next release) puts agentd back to starting at the next look.
	s.keys.set(&vault.SecretsResult{})
	if st, body := postVM(t, c, srv.URL+"/run"); st != 503 || errCode(body) != "starting" {
		t.Fatalf("/run after the vault lost its keys: %d %s", st, body)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	s.watchSecrets(ctx, 0) // one look: the vault still has them here
	if !s.keys.ready.Load() {
		t.Fatal("the watch didn't find the vault's keys")
	}
}

func errCode(body string) string {
	var e struct {
		Error string `json:"error"`
	}
	json.Unmarshal([]byte(body), &e)
	return e.Error
}
