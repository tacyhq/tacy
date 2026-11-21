package holder

import (
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tacyhq/tacy/kms"
	"github.com/tacyhq/tacy/kms/client"
	"github.com/tacyhq/tacy/kms/split"
	"github.com/tacyhq/tacy/kms/split/glass"
	"github.com/tacyhq/tacy/proto"
	"github.com/tacyhq/tacy/safety"
)

// glassRig: a 2-of-2 rig with vercel down, a relay at the policy's break-glass URL and the admin's break-glass
// holder (M from the rig) serving through it.
type glassRig struct {
	*rig
	relay  *glass.Relay
	srv    *httptest.Server
	bg     *Holder
	served int
	mu     sync.Mutex
}

func newGlassRig(t *testing.T) *glassRig {
	r := newRig(t, twoOfTwo, 2)
	r.pol.BreakGlass = "https://keys-cf.tacy.io/break-glass"
	g := &glassRig{rig: r}
	g.relay = &glass.Relay{Admin: kms.AdminKeys{Keys: []ed25519.PublicKey{r.adminPub}, Threshold: 1}, KMSID: r.kmsID, Now: r.clock,
		Wait: 2 * time.Second}
	g.srv = httptest.NewServer(g.relay)
	t.Cleanup(g.srv.Close)
	cfg := r.config(split.BreakGlassHolder)
	cfg.Shares, cfg.Opener, cfg.Master, cfg.PolicyFloor = nil, nil, r.master, r.pol.Seq
	cfg.PolicyHash = policyHashOf(r.policyEnv()) // the one policy break-glass serves
	cfg.Notify = func(e Event) {
		if e.OK {
			g.mu.Lock()
			g.served++
			g.mu.Unlock()
		}
	}
	bg, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	g.bg = bg
	return g
}

func (g *glassRig) attach(key ed25519.PrivateKey, at time.Time) json.RawMessage {
	b, _ := json.Marshal(glass.BreakGlassAttach{KMSID: g.kmsID, IssuedAt: at})
	env, _ := json.Marshal(safety.Sign(glass.KindBreakGlassAttach, b, key))
	return env
}

// serve runs kmsctl break-glass's loop until it has served one boot (or ctx ends).
func (g *glassRig) serve(ctx context.Context, attach json.RawMessage) chan error {
	done := make(chan error, 1)
	go func() {
		done <- glass.ServeRelay(ctx, client.HTTP{Base: g.srv.URL}, attach, g.bg.Handler(), func() bool {
			g.mu.Lock()
			defer g.mu.Unlock()
			return g.served >= 1
		})
	}()
	return done
}

func (g *glassRig) vercelDown() []split.Holder {
	return g.transports(map[string]func(client.Transport) client.Transport{"vercel": func(client.Transport) client.Transport { return down{} }})
}

// 2-of-2 with a holder down: no unlock from the holders; with the admin attached, break-glass serves one boot.
func TestBreakGlassServesOneBoot(t *testing.T) {
	g := newGlassRig(t)
	// Nobody attached: the relay says so, the VM doesn't unlock.
	cfg := g.unlockConfig(g.vercelDown(), nil)
	cfg.BreakGlass = client.HTTP{Base: g.srv.URL}
	if _, rep, err := split.Unlock(context.Background(), cfg); err == nil || len(rep.Tried) != 2 ||
		!strings.Contains(rep.Tried[1].Err, "admin isn't attached") {
		t.Fatalf("no admin: %v %+v", err, rep)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	done := g.serve(ctx, g.attach(g.admin, g.now))
	time.Sleep(50 * time.Millisecond) // the attach
	cfg.Policy = g.policyEnv()
	m, rep, err := split.Unlock(context.Background(), cfg)
	if err != nil {
		t.Fatalf("break-glass: %v %+v", err, rep)
	}
	g.mustMaster(m)
	if rep.Set != 0 || len(rep.Used) != 1 || rep.Used[0] != split.BreakGlassHolder {
		t.Fatalf("report: %+v", rep)
	}
	if err := <-done; err != nil {
		t.Fatalf("serve: %v", err)
	}
	// One boot only: the holder refuses a second (even if kmsctl kept serving).
	if _, err := g.bg.Unlock(context.Background(), g.breakGlassRequest()); err == nil || !strings.Contains(err.Error(), "already served") {
		t.Fatalf("a second boot: %v", err)
	}
}

func (g *glassRig) breakGlassRequest() split.UnlockRequest {
	ch, _ := g.bg.Challenge()
	hn := []split.HolderNonce{{Holder: split.BreakGlassHolder, Nonce: ch.Nonce}}
	bound, _ := split.Bind(hn)
	att, _, err := client.Attest(context.Background(), g.vm.Evidence, "dstack", bound)
	if err != nil {
		g.t.Fatal(err)
	}
	return split.UnlockRequest{Nonces: hn, Attestation: att, Policy: g.policyEnv(), Set: 0, Release: vmRelease}
}

// The break-glass holder runs every holder check: an unpinned release, a policy without a relay or a request for a
// share set get nothing.
func TestBreakGlassChecks(t *testing.T) {
	g := newGlassRig(t)
	q, info, _ := g.variant(func(m map[string]any) { m["docker_compose_file"] = g.vmCompose; m["public_logs"] = true })
	req := g.breakGlassRequest()
	bound, _ := split.Bind(req.Nonces)
	att, _, err := client.Attest(context.Background(), (&evidence{quote: q, info: info}).Evidence, "dstack", bound)
	if err != nil {
		t.Fatal(err)
	}
	req.Attestation = att
	wantRefused(t, g.bg, req, "isn't a pinned release")

	req = g.breakGlassRequest()
	req.Set = 2
	wantRefused(t, g.bg, req, "set 0 only")

	g.pol.BreakGlass = ""
	wantRefused(t, g.bg, g.breakGlassRequest(), "names a break-glass relay")

	// Only the admin's M, under the break-glass id, and nothing else.
	cfg := g.config(split.BreakGlassHolder)
	cfg.Shares, cfg.Opener = nil, nil
	other := make([]byte, kms.MasterSize)
	rand.Read(other)
	cfg.Master = other
	if _, err := New(cfg); err == nil {
		t.Fatal("break-glass with another M")
	}
	cfg = g.config("cloudflare")
	cfg.Master = g.master
	if _, err := New(cfg); err == nil {
		t.Fatal("a regular holder serving M")
	}
}

// Attaching takes a fresh admin signature for this KMS id; a relay that lies gets nothing past the VM.
func TestBreakGlassRelayAuth(t *testing.T) {
	g := newGlassRig(t)
	ctx := context.Background()
	t2 := client.HTTP{Base: g.srv.URL}
	_, stranger, _ := ed25519.GenerateKey(rand.Reader)
	for name, att := range map[string]json.RawMessage{
		"not the admin": g.attach(stranger, g.now),
		"stale":         g.attach(g.admin, g.now.Add(-time.Hour)),
	} {
		if _, err := t2.Do(ctx, "POST", "/relay/attach", att); err == nil {
			t.Fatalf("%s: attached", name)
		}
	}
	if _, err := t2.Do(ctx, "GET", "/relay/next?session=guess", nil); err == nil {
		t.Fatal("next without a session")
	}

	// A relay that answers with something that isn't M (a forged admin): the VM refuses it.
	cfg := g.unlockConfig(g.vercelDown(), nil)
	cfg.BreakGlass = fakeGlass{g: g}
	if _, rep, err := split.Unlock(ctx, cfg); err == nil || !strings.Contains(rep.Tried[len(rep.Tried)-1].Err, "isn't the epoch's root") {
		t.Fatalf("a forged break-glass: %v %+v", err, rep)
	}
}

// fakeGlass is someone posing as the admin: the real break-glass checks and reply, with another key sealed in
// place of M.
type fakeGlass struct{ g *glassRig }

func (f fakeGlass) Do(ctx context.Context, method, path string, body []byte) ([]byte, error) {
	b, err := client.Handler{H: f.g.bg.Handler()}.Do(ctx, method, path, body)
	if err != nil || path != "/v1/unlock" {
		return b, err
	}
	var rep split.UnlockReply
	var req split.UnlockRequest
	var att proto.Attestation
	json.Unmarshal(b, &rep)
	json.Unmarshal(body, &req)
	json.Unmarshal(req.Attestation, &att)
	kb, _ := hex.DecodeString(att.HPKEPublicKey)
	pub, err := ecdh.X25519().NewPublicKey(kb)
	if err != nil {
		return nil, err
	}
	other := make([]byte, kms.MasterSize)
	rand.Read(other)
	bound, _ := split.Bind(req.Nonces)
	rep.Sealed, _ = kms.Seal(pub, split.LabelBreakGlass, split.ReplyAAD(bound, rep.KMSID, rep.Epoch, 0, rep.Holder, 0, policyHashOf(req.Policy), nil), other)
	return json.Marshal(rep)
}
