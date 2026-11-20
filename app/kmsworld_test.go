package main

import (
	"context"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/tacyhq/tacy/gateway"
	"github.com/tacyhq/tacy/kms/client"
	"github.com/tacyhq/tacy/kms/kmsdev"
	"github.com/tacyhq/tacy/kmsvm"
	"github.com/tacyhq/tacy/sealstate"
	"github.com/tacyhq/tacy/vault"
)

// kmsWorld is what a CVM of this release talks to, all in this process and over the production paths: a real
// key service (kms/server, development mode: nothing attested) over HTTP, the chat Worker's sealed-state API (its
// Go twin, kmsvm.StateAPI) over HTTP, and gatewayd's fixed calls to both over a gateway/v0 unix socket.
type kmsWorld struct {
	dev   *kmsdev.Dev
	state *kmsvm.StateAPI
	gw    *gateway.Client // agentd's (and, on the CVM, vaultd's ops) socket to gatewayd
}

func newKMSWorld(t *testing.T) *kmsWorld {
	t.Helper()
	dev, err := kmsdev.Start(kmsdev.Options{Secrets: testKeys})
	if err != nil {
		t.Fatal(err)
	}
	ks := dev.HTTP()
	t.Cleanup(ks.Close)
	st := &kmsvm.StateAPI{KMSID: dev.KMSID}
	ss := httptest.NewServer(st)
	t.Cleanup(ss.Close)
	fixed, err := gateway.NewFixed([]string{ks.URL}, ss.URL, true)
	if err != nil {
		t.Fatal(err)
	}
	// The socket lives outside any directory a test checks for files.
	sock := filepath.Join(socketDir(t), "gw.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go (&gateway.Server{Fixed: fixed}).Serve(l, -1)
	return &kmsWorld{dev: dev, state: st, gw: &gateway.Client{Path: sock}}
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

// release is one process's key service release on instance, through gatewayd.
func (w *kmsWorld) release(t *testing.T, instance string, purposes ...string) *kmsvm.Keys {
	t.Helper()
	holder := "agentd"
	if len(purposes) == 1 && purposes[0] == "conn/v1" {
		holder = "vaultd"
	}
	k, err := kmsvm.Boot(context.Background(), kmsvm.Config{KMSID: w.dev.KMSID, Hosts: 1, Platform: "local", Purposes: purposes, Holder: holder,
		Evidence: kmsvm.LocalEvidence(instance), Transport: func(h int) client.Transport { return gateway.KMSTransport{D: w.gw, Host: h} },
		Wait: time.Second, Sleep: func(context.Context, time.Duration) { time.Sleep(20 * time.Millisecond) }, Logf: t.Logf})
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// relayBackend is the sealed-state backend main makes for purpose with -state relay.
func (w *kmsWorld) relayBackend(t *testing.T, k *kmsvm.Keys, purpose string) *sealstate.Relay {
	t.Helper()
	auth, err := k.StoreAuth(purpose)
	if err != nil {
		t.Fatal(err)
	}
	return &sealstate.Relay{Base: "https://state", Client: gateway.StateHTTP{D: w.gw}, Auth: auth}
}

// bootAgent is agentd's boot with -kms-key and -state relay on instance (a fresh CVM: nothing but the key service
// and the Worker).
func (w *kmsWorld) bootAgent(t *testing.T, instance string) (*booted, *kmsvm.Keys) {
	t.Helper()
	k := w.release(t, instance, agentPurposes...)
	b, err := bootState(context.Background(), kmsKeys{k}, w.relayBackend(t, k, PurposeState), k.Register(PurposeState), "f_chat")
	if err != nil {
		t.Fatal(err)
	}
	return b, k
}

// bootVault is vaultd's boot with -kms-key: the key service's secrets and its sealed connections.
func (w *kmsWorld) bootVault(t *testing.T, instance string) (*vault.Vault, *sealstate.Keeper, *kmsvm.Keys) {
	t.Helper()
	ctx := context.Background()
	k := w.release(t, instance, "conn/v1")
	v, err := vault.New(nil, vault.ChatGrants(""), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.SetSecrets(k.Secrets()); err != nil {
		t.Fatal(err)
	}
	ck, _ := k.Key(ctx, "conn/v1")
	p, keeper, err := vault.SealedConns(ctx, w.relayBackend(t, k, "conn/v1"), ck, k.App(), k.Register("conn/v1"))
	if err != nil {
		t.Fatal(err)
	}
	if err := v.EnableConns(p); err != nil {
		t.Fatal(err)
	}
	return v, keeper, k
}
