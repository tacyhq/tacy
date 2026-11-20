package kmsvm_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/tacyhq/tacy/gateway"
	"github.com/tacyhq/tacy/kms"
	"github.com/tacyhq/tacy/kms/client"
	"github.com/tacyhq/tacy/kms/kmsdev"
	"github.com/tacyhq/tacy/kmsvm"
	"github.com/tacyhq/tacy/sealstate"
)

func TestLocalAppComposeMatchesKMSDev(t *testing.T) {
	if kmsvm.LocalAppCompose != kmsdev.LocalVMAppCompose {
		t.Fatal("kmsvm.LocalAppCompose and kmsdev.LocalVMAppCompose differ")
	}
}

// boot is a VM process's release through gatewayd's fixed calls to a development kmsd over HTTP.
func boot(t *testing.T, d *kmsdev.Dev, fx gateway.FixedDoer, instance string, purposes ...string) (*kmsvm.Keys, error) {
	t.Helper()
	holder := "agentd"
	if len(purposes) == 1 && purposes[0] == "conn/v1" {
		holder = "vaultd"
	}
	return kmsvm.Boot(context.Background(), kmsvm.Config{KMSID: d.KMSID, Hosts: 2, Platform: "local", Purposes: purposes, Holder: holder,
		Transport: func(h int) client.Transport { return gateway.KMSTransport{D: fx, Host: h} },
		Evidence:  kmsvm.LocalEvidence(instance), Wait: time.Second, Logf: t.Logf,
		Sleep: func(context.Context, time.Duration) { time.Sleep(20 * time.Millisecond) }})
}

func TestBootThroughGatewayFixedCalls(t *testing.T) {
	d, err := kmsdev.Start(kmsdev.Options{})
	if err != nil {
		t.Fatal(err)
	}
	srv := d.HTTP()
	defer srv.Close()
	// Replica 0 is the primary; replica 1 (a standby, down here) is never asked for releases or leases.
	fx, err := gateway.NewFixed([]string{srv.URL, "http://127.0.0.1:1"}, "", true)
	if err != nil {
		t.Fatal(err)
	}
	agent, err := boot(t, d, fx, "inst-1", "state/v1", "activity-sign/v1", "task-ids/v1")
	if err != nil {
		t.Fatal(err)
	}
	vault, err := boot(t, d, fx, "inst-1", "conn/v1")
	if err != nil {
		t.Fatalf("vaultd's release from the same instance: %v", err)
	}
	// Each process its own lease (L8): agentd's drop below leaves vaultd's alone.
	if agent.Lease().ID == vault.Lease().ID || agent.Lease().Holder != "agentd" || vault.Lease().Holder != "vaultd" {
		t.Fatalf("leases %+v %+v", agent.Lease(), vault.Lease())
	}
	if len(agent.Secrets()) != 0 {
		t.Fatal("agentd's release carries the API keys")
	}
	if _, err := agent.Key(context.Background(), "conn/v1"); err == nil {
		t.Fatal("agentd got vaultd's purpose")
	}
	if s := vault.Secrets(); s["EXA_API_KEY"] != "exa-dev" || len(s) != 3 {
		t.Fatalf("secrets: %v", s)
	}
	// Another instance waits while the lease is held, and gets it once the holder drops it.
	if _, err := boot(t, d, fx, "inst-2", "state/v1"); err == nil || !strings.Contains(err.Error(), "holds") {
		t.Fatalf("a second instance during the lease: %v", err)
	}
	if err := agent.Drop(context.Background()); err != nil {
		t.Fatal(err)
	}
	other, err := boot(t, d, fx, "inst-2", "state/v1")
	if err != nil {
		t.Fatalf("after the drop: %v", err)
	}
	k1, _ := agent.Key(context.Background(), "state/v1")
	k2, _ := other.Key(context.Background(), "state/v1")
	if !bytes.Equal(k1, k2) || other.Lease().Seq != agent.Lease().Seq+1 {
		t.Fatal("a new instance got another state key, or the lease didn't move on")
	}
	if err := vault.RenewOnce(context.Background()); err != nil {
		t.Fatalf("vaultd's lease after agentd dropped its own: %v", err)
	}
}

func TestRegisterAndStoreAuth(t *testing.T) {
	d, err := kmsdev.Start(kmsdev.Options{})
	if err != nil {
		t.Fatal(err)
	}
	fx := fixedHandler{d.Handler()}
	k, err := boot(t, d, fx, "inst-1", "state/v1")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	reg := k.Register("state/v1")
	sk, _ := k.Key(ctx, "state/v1")
	var mem sealstate.Mem
	st, _ := sealstate.New(&mem, sk, k.App())
	st.WithRegister(reg)
	if err := st.Save(ctx, "side", []byte("one")); err != nil {
		t.Fatal(err)
	}
	if err := st.Save(ctx, "side", []byte("two")); err != nil {
		t.Fatal(err)
	}
	if e, err := reg.Generation(ctx, "side"); err != nil || e.Gen != 2 || e.Hash == "" || !e.Stored {
		t.Fatalf("register: %+v %v", e, err)
	}
	old, _ := mem.Get(ctx, "side")
	if err := st.Save(ctx, "side", []byte("three")); err != nil {
		t.Fatal(err)
	}
	// The backend hands back generation 2 (an operator's rollback): a fresh store refuses it.
	var rolled sealstate.Mem
	rolled.Put(ctx, "side", mustSeal(t, sk, k.App(), "side", 1, "x"), 0)
	rolled.Put(ctx, "side", old, 1)
	st2, _ := sealstate.New(&rolled, sk, k.App())
	st2.WithRegister(reg)
	if _, err := st2.Load(ctx, "side"); !errors.Is(err, sealstate.ErrRollback) {
		t.Fatalf("rolled back state: %v", err)
	}
	st3, _ := sealstate.New(&mem, sk, k.App())
	st3.WithRegister(reg)
	if b, err := st3.Load(ctx, "side"); err != nil || string(b) != "three" {
		t.Fatalf("current state: %q %v", b, err)
	}

	auth, err := k.StoreAuth("state/v1")
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest("PUT", "https://chat.example/api/vm/state/side", bytes.NewReader([]byte("blob")))
	req.Header.Set("X-Tacy-Gen", "4")
	req.Header.Set("X-Tacy-Prev-Gen", "3")
	auth(req)
	cb, _ := base64.RawURLEncoding.DecodeString(req.Header.Get("X-Tacy-Cert"))
	var cert kms.StoreCert
	if err := json.Unmarshal(cb, &cert); err != nil || client.CheckStoreCert(cert, d.KMSID) != nil || cert.App != kmsdev.App {
		t.Fatalf("cert: %v", err)
	}
	pub, _ := kms.ParseID(cert.Key)
	a := req.Header.Get("X-Tacy-Auth")
	ts, sig, _ := strings.Cut(strings.TrimPrefix(a, "t="), ",s=")
	sb, _ := base64.RawURLEncoding.DecodeString(sig)
	var at int64
	json.Unmarshal([]byte(ts), &at)
	if !ed25519.Verify(pub, kmsvm.StateMessage("PUT", "side", at, "4", "3", []byte("blob")), sb) {
		t.Fatal("the state request's signature doesn't verify under the certified key")
	}
	if _, err := k.StoreAuth("conn/v1"); err == nil {
		t.Fatal("a store certificate for a purpose not released")
	}
}

func mustSeal(t *testing.T, key []byte, lease, name string, gen uint64, pt string) []byte {
	b, err := sealstate.Seal(key, lease, name, gen, []byte(pt))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// fixedHandler answers kms fixed calls straight from kmsd's handler.
type fixedHandler struct{ h http.Handler }

func (f fixedHandler) Fixed(ctx context.Context, call *gateway.FixedCall) *gateway.FixedAnswer {
	if err := gateway.CheckFixed(call); err != nil {
		return &gateway.FixedAnswer{Error: "bad_call"}
	}
	b, err := client.Handler{H: f.h}.Do(ctx, call.Method, call.Path, call.Body)
	var re *client.RefusedError
	if errors.As(err, &re) {
		eb, _ := json.Marshal(kms.Error{Error: re.Reason})
		return &gateway.FixedAnswer{Status: re.Status, Body: eb}
	}
	return &gateway.FixedAnswer{Status: 200, Body: b}
}
