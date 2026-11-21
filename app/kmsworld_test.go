package main

import (
	"context"
	"crypto/rand"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/tacyhq/tacy/gateway"
	"github.com/tacyhq/tacy/kms"
	"github.com/tacyhq/tacy/kmsvm"
	"github.com/tacyhq/tacy/sealstate"
	"github.com/tacyhq/tacy/unlock"
	"github.com/tacyhq/tacy/vault"
)

// kmsWorld is what a CVM of this release talks to, all in this process and over the production paths: unlockd
// (package unlock, with a development root: the holders' side runs in unlock's own tests) over its unix sockets,
// the chat Worker's sealed-state API (its Go twin, kmsvm.StateAPI) over HTTP, and gatewayd's fixed calls to it over a
// gateway/v0 unix socket (agentd's gate: sealed state and ownership rows only).
type kmsWorld struct {
	seed  []byte
	kmsID string
	state *kmsvm.StateAPI
	gw    *gateway.Client
	dir   string
}

// testKeys are the dev API keys the world's unlockd gives vaultd.
var worldSecrets = map[string]string{"TINFOIL_API_KEY": "tk-dev-tinfoil", "EXA_API_KEY": "exa-dev", "TAVILY_API_KEY": "tvly-dev"}

func newKMSWorld(t *testing.T) *kmsWorld {
	t.Helper()
	seed := make([]byte, kms.MasterSize)
	rand.Read(seed)
	id, err := unlock.DevKMSID(seed)
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := kms.ParseID(id)
	st := &kmsvm.StateAPI{KMSID: pub}
	ss := httptest.NewServer(st)
	t.Cleanup(ss.Close)
	fixed, err := gateway.NewFixed(nil, ss.URL, true)
	if err != nil {
		t.Fatal(err)
	}
	dir := socketDir(t)
	l, err := net.Listen("unix", filepath.Join(dir, "gw.sock"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go (&gateway.Server{Fixed: gateway.FixedGate{D: fixed, Allow: gateway.AgentCalls}}).Serve(l, -1)
	return &kmsWorld{seed: seed, kmsID: id, state: st, gw: &gateway.Client{Path: filepath.Join(dir, "gw.sock")}, dir: dir}
}

// socketDir is a short directory for unix sockets (macOS caps their paths at 104 bytes).
func socketDir(t *testing.T) string {
	d, err := os.MkdirTemp("/tmp", "tacy-kw-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(d) })
	return d
}

// worldKeys are one process's keys from the world's unlockd. Drop is a no-op: there is no lease to free since the
// split-key unlock (the tests' stops keep calling it where a lease went).
type worldKeys struct{ *unlock.Keys }

func (worldKeys) Drop(context.Context) error { return nil }

// release is one process's keys from a fresh unlockd on instance (a boot: unlockd unlocks, then serves its socket).
func (w *kmsWorld) release(t *testing.T, instance string, purposes ...string) worldKeys {
	t.Helper()
	role := unlock.RoleAgent
	if len(purposes) == 1 && purposes[0] == "conn/v1" {
		role = unlock.RoleVault
	}
	pub, _ := kms.ParseID(w.kmsID)
	u, err := unlock.New(unlock.Config{KMSID: pub, Fixed: w.gw, Platform: "local", Evidence: kmsvm.LocalEvidence(instance),
		DevRoot: func() (unlock.Root, unlock.Grant, error) { return unlock.DevRoot(w.seed, worldSecrets) }, Logf: t.Logf})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := u.Run(ctx); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(w.dir, instance+"-"+role+".sock")
	os.Remove(p)
	l, err := net.Listen("unix", p)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go (&unlock.Server{U: u, Logf: t.Logf}).Serve(l, -1, role)
	k, err := (&unlock.Client{Path: p}).Wait(ctx, t.Logf, purposes...)
	if err != nil {
		t.Fatal(err)
	}
	return worldKeys{k}
}

// relayBackend is the sealed-state backend main makes for purpose with -state relay.
func (w *kmsWorld) relayBackend(t *testing.T, k worldKeys, purpose string) *sealstate.Relay {
	t.Helper()
	auth, err := k.StoreAuth(purpose, nil)
	if err != nil {
		t.Fatal(err)
	}
	return &sealstate.Relay{Base: "https://state", Client: gateway.StateHTTP{D: w.gw}, Auth: auth}
}

// bootAgent is agentd's boot with -unlock-socket and -state relay on instance (a fresh CVM: nothing but unlockd and
// the Worker).
func (w *kmsWorld) bootAgent(t *testing.T, instance string) (*booted, worldKeys) {
	t.Helper()
	k := w.release(t, instance, agentPurposes...)
	b, err := bootState(context.Background(), unlockKeys{k.Keys}, w.relayBackend(t, k, PurposeState), nil, "f_chat")
	if err != nil {
		t.Fatal(err)
	}
	return b, k
}

// bootVault is vaultd's boot with -unlock-socket: unlockd's API keys and its sealed connections.
func (w *kmsWorld) bootVault(t *testing.T, instance string) (*vault.Vault, *sealstate.Keeper, worldKeys) {
	t.Helper()
	ctx := context.Background()
	k := w.release(t, instance, "conn/v1")
	v, err := vault.New(nil, vault.ChatGrants(""), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.SetSecrets(k.Secrets); err != nil {
		t.Fatal(err)
	}
	ck, _ := k.Key(ctx, "conn/v1")
	p, keeper, err := vault.SealedConns(ctx, w.relayBackend(t, k, "conn/v1"), ck, k.App, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := v.EnableConns(p); err != nil {
		t.Fatal(err)
	}
	return v, keeper, k
}
