package holder

import (
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/tacyhq/tacy/kms"
	"github.com/tacyhq/tacy/kms/client"
	"github.com/tacyhq/tacy/kms/split"
	"github.com/tacyhq/tacy/proto"
	"github.com/tacyhq/tacy/safety"
)

var (
	twoOfTwo   = []string{"cloudflare", "vercel"}
	twoOfThree = []string{"cloudflare", "gcp", "vercel"}
)

// The start (2026-11-20): 2-of-2, the Worker and Vercel.
func TestUnlockTwoOfTwo(t *testing.T) {
	r := newRig(t, twoOfTwo, 2)
	m, rep, err := r.unlock(r.transports(nil), nil)
	if err != nil {
		t.Fatalf("unlock: %v (%v)", err, rep.Outcome)
	}
	r.mustMaster(m)
	m.Drop()
	if _, err := m.Key(vmApp, "f_chat", "state/v1"); err == nil {
		t.Fatal("a dropped master still derives keys")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	var unlocks, pins []Event
	for _, e := range r.events {
		switch e.Kind {
		case "unlock":
			unlocks = append(unlocks, e)
		case "pin":
			pins = append(pins, e)
		}
	}
	if len(unlocks) != 2 || !unlocks[0].OK || unlocks[0].Release != vmRelease || unlocks[0].App != vmApp || unlocks[0].Instance == "" ||
		unlocks[0].Epoch != 1 {
		t.Fatalf("each holder should report one release with its app, release, instance and epoch: %+v", unlocks)
	}
	if len(pins) != 2 {
		t.Fatalf("each holder should report the release pin it first saw: %+v", pins)
	}
}

// Later: 2-of-3 with Google Cloud; any one holder down still unlocks.
func TestHolderDownTwoOfThree(t *testing.T) {
	for _, gone := range twoOfThree {
		t.Run(gone, func(t *testing.T) {
			r := newRig(t, twoOfThree, 2)
			m, rep, err := r.unlock(r.transports(map[string]func(client.Transport) client.Transport{
				gone: func(client.Transport) client.Transport { return down{} }}), nil)
			if err != nil {
				t.Fatalf("unlock with %s down: %v (%v)", gone, err, rep.Outcome)
			}
			r.mustMaster(m)
			if !strings.Contains(rep.Outcome[gone], "connection refused") || len(rep.Used) != 2 {
				t.Fatalf("report: %+v", rep)
			}
		})
	}
}

// 2-of-2 with one holder down, or 2-of-3 with two down: no unlock, and the reason says so.
func TestNotEnoughHolders(t *testing.T) {
	r := newRig(t, twoOfTwo, 2)
	_, rep, err := r.unlock(r.transports(map[string]func(client.Transport) client.Transport{
		"vercel": func(client.Transport) client.Transport { return down{} }}), nil)
	if !errors.Is(err, split.ErrNotEnough) || !strings.Contains(err.Error(), "1 of 2") {
		t.Fatalf("2-of-2 with one down: %v (%v)", err, rep.Outcome)
	}
	r3 := newRig(t, twoOfThree, 2)
	dn := func(client.Transport) client.Transport { return down{} }
	if _, _, err := r3.unlock(r3.transports(map[string]func(client.Transport) client.Transport{"gcp": dn, "vercel": dn}), nil); !errors.Is(err, split.ErrNotEnough) {
		t.Fatalf("2-of-3 with two down: %v", err)
	}
}

// A VM whose app-compose.json isn't a pinned release gets nothing from any holder.
func TestWrongReleaseRefusedByEachHolder(t *testing.T) {
	r := newRig(t, twoOfThree, 2)
	for name, edit := range map[string]func(map[string]any){
		"changed env line": func(m map[string]any) {
			m["docker_compose_file"] = strings.Replace(r.vmCompose, "services:", "services:\n  # one more line", 1)
		},
		"public logs": func(m map[string]any) { m["docker_compose_file"] = r.vmCompose; m["public_logs"] = true },
	} {
		t.Run(name, func(t *testing.T) {
			q, info, _ := r.variant(edit)
			_, rep, err := r.unlock(r.transports(nil), &evidence{quote: q, info: info})
			if !errors.Is(err, split.ErrNotEnough) {
				t.Fatalf("an unpinned release unlocked: %v", err)
			}
			for _, h := range twoOfThree {
				if !strings.Contains(rep.Outcome[h], "isn't a pinned release") {
					t.Fatalf("%s: %q", h, rep.Outcome[h])
				}
				r.assertNoLeak(h+"'s refusal", rep.Outcome[h])
			}
		})
	}
	// A release below the policy's floor, though pinned.
	r.pol.Floor = "v0.20.0"
	_, rep, err := r.unlock(r.transports(nil), nil)
	if err == nil || !strings.Contains(rep.Outcome["cloudflare"], "below the policy floor") {
		t.Fatalf("below the floor: %v %v", err, rep.Outcome)
	}
}

// replayRig makes one good unlock through a recorder at cloudflare and returns the request it carried.
func replayRig(t *testing.T) (*rig, split.UnlockRequest) {
	r := newRig(t, twoOfTwo, 2)
	rec := &recorder{}
	if _, _, err := r.unlock(r.transports(map[string]func(client.Transport) client.Transport{
		"cloudflare": func(n client.Transport) client.Transport { rec.next = n; return rec }}), nil); err != nil {
		t.Fatal(err)
	}
	var req split.UnlockRequest
	if err := kms.Strict(rec.last, &req); err != nil {
		t.Fatal(err)
	}
	return r, req
}

func wantRefused(t *testing.T, h *Holder, req split.UnlockRequest, want string) {
	t.Helper()
	rep, err := h.Unlock(context.Background(), req)
	if err == nil || rep != nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("want a refusal with %q, got %v %v", want, rep, err)
	}
}

func TestReplayRefused(t *testing.T) {
	r, req := replayRig(t)
	cf := r.holders["cloudflare"]
	// The same request again: its nonce is used.
	wantRefused(t, cf, req, "nonce already used")
	// At another instance of the holder (no memory of the use) after the nonce's life.
	r.advance(split.NonceTTL + time.Second)
	wantRefused(t, r.newHolder("cloudflare", nil), req, "nonce expired")
}

// A valid quote replayed with fresh nonces, or with another key put in: report_data binds neither.
func TestReplayedQuoteWithFreshNonceRefused(t *testing.T) {
	r, req := replayRig(t)
	cf := r.holders["cloudflare"]
	ch, _ := cf.Challenge()
	ch2, _ := r.holders["vercel"].Challenge()
	req.Nonces = []split.HolderNonce{{Holder: "cloudflare", Nonce: ch.Nonce}, {Holder: "vercel", Nonce: ch2.Nonce}}
	var att proto.Attestation
	json.Unmarshal(req.Attestation, &att)
	bound, _ := split.Bind(req.Nonces)
	att.Nonce = hex.EncodeToString(bound) // the old quote still binds the old nonces
	mine, _ := ecdh.X25519().GenerateKey(rand.Reader)
	att.HPKEPublicKey = hex.EncodeToString(mine.PublicKey().Bytes())
	req.Attestation, _ = json.Marshal(att)
	wantRefused(t, cf, req, "report_data doesn't bind our nonce and this HPKE key")
}

func TestNonceNotThisHolders(t *testing.T) {
	r, req := replayRig(t)
	cf := r.holders["cloudflare"]
	// Only vercel's nonce: nothing of cloudflare's.
	only := req
	only.Nonces = []split.HolderNonce{req.Nonces[1]}
	wantRefused(t, cf, only, "no nonce of this holder")
	// A nonce cloudflare never issued (random), and vercel's nonce under cloudflare's name.
	forged := req
	b := make([]byte, 32)
	rand.Read(b)
	forged.Nonces = []split.HolderNonce{{Holder: "cloudflare", Nonce: hex.EncodeToString(b)}, req.Nonces[1]}
	wantRefused(t, cf, forged, "wasn't issued by this holder")
	swapped := req
	swapped.Nonces = []split.HolderNonce{{Holder: "cloudflare", Nonce: req.Nonces[1].Nonce}, req.Nonces[1]}
	wantRefused(t, cf, swapped, "wasn't issued by this holder")
	// Unsorted or repeated holders.
	unsorted := req
	unsorted.Nonces = []split.HolderNonce{req.Nonces[1], req.Nonces[0]}
	wantRefused(t, cf, unsorted, "sorted by holder id")
}

// A policy, share set or pin for another KMS id gets nothing.
func TestWrongKMSIDRefused(t *testing.T) {
	r := newRig(t, twoOfTwo, 2)
	other := make([]byte, kms.MasterSize)
	rand.Read(other)
	oid, _ := kms.DeriveID(other)
	otherPub := oid.Public().(ed25519.PublicKey)

	// The VM pins another KMS id: it refuses the policy itself, before asking anyone.
	cfg := r.unlockConfig(r.transports(nil), nil)
	cfg.KMSID = otherPub
	if _, _, err := split.Unlock(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), "another KMS id") {
		t.Fatalf("VM pinned to another id: %v", err)
	}

	// A holder gets a policy naming another KMS id (signed by the admin: a staging policy, say).
	cfgOK := r.unlockConfig(nil, nil)
	req := r.request(cfgOK, nil)
	var pol split.UnlockPolicy = r.pol
	pol.KMSID = kms.IDString(otherPub)
	req.Policy = r.sign(split.KindUnlockPolicy, pol)
	wantRefused(t, r.holders["cloudflare"], req, "another KMS id")

	// A share set signed by another key than the KMS id.
	set, _, err := split.Resplit(other, kms.IDString(otherPub), 1, 2, 2, []split.HolderRecipient{
		{Holder: "cloudflare", Recipient: PublicKeyOf(r.keys["cloudflare"])}, {Holder: "vercel", Recipient: PublicKeyOf(r.keys["vercel"])}},
		r.now, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pol = r.pol
	pol.ShareSets = []split.SignedShareSet{*set} // the rig's epoch certificate doesn't certify its root either
	req = r.request(cfgOK, nil)
	req.Policy = r.sign(split.KindUnlockPolicy, pol)
	wantRefused(t, r.holders["cloudflare"], req, "share set isn't signed by the KMS id")

	// A holder deployed with a share for another KMS id doesn't start.
	otherCfg := r.config("cloudflare")
	otherCfg.KMSID = kms.IDString(otherPub)
	if _, err := New(otherCfg); err == nil {
		t.Fatal("a holder started with another KMS id's share")
	}
}

// request is an unlock request as the VM would send it now (fresh nonces from every holder, the VM's quote).
func (r *rig) request(cfg split.Config, ev *evidence) split.UnlockRequest {
	r.t.Helper()
	if ev == nil {
		ev = r.vm
	}
	var hn []split.HolderNonce
	for _, h := range r.ids {
		ch, err := r.holders[h].Challenge()
		if err != nil {
			r.t.Fatal(err)
		}
		hn = append(hn, split.HolderNonce{Holder: h, Nonce: ch.Nonce})
	}
	bound, _ := split.Bind(hn)
	att, _, err := client.Attest(context.Background(), ev.Evidence, "dstack", bound)
	if err != nil {
		r.t.Fatal(err)
	}
	return split.UnlockRequest{Nonces: hn, Attestation: att, Policy: cfg.Policy, Set: 2, Release: vmRelease}
}

func TestPolicyChecks(t *testing.T) {
	r := newRig(t, twoOfTwo, 2)
	cfg := r.unlockConfig(nil, nil)
	stranger, strangerKey, _ := ed25519.GenerateKey(rand.Reader)
	_ = stranger
	cases := []struct {
		name string
		env  func() json.RawMessage
		want string
	}{
		{"not the admin's key", func() json.RawMessage { return r.sign(split.KindUnlockPolicy, r.pol, strangerKey) }, "admin signatures"},
		{"a kmsd policy's kind", func() json.RawMessage { return r.sign(kms.KindPolicy, r.pol) }, "want a kms-unlock-policy document"},
		{"issued in the future", func() json.RawMessage {
			p := r.pol
			p.IssuedAt = r.now.Add(time.Hour)
			return r.sign(split.KindUnlockPolicy, p)
		}, "issued in the future"},
		{"below the holder's floor", func() json.RawMessage {
			p := r.pol
			p.Seq = 2
			return r.sign(split.KindUnlockPolicy, p)
		}, "below this holder's floor"},
		{"e2e overlays (staging only)", func() json.RawMessage {
			p := r.pol
			p.AllowE2EDiag = true
			return r.sign(split.KindUnlockPolicy, p)
		}, "staging only"},
	}
	h := r.newHolder("cloudflare", func(c *Config) { c.PolicyFloor = 3 })
	r.holders["cloudflare"] = h
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req := r.request(cfg, nil)
			req.Policy = c.env()
			wantRefused(t, h, req, c.want)
		})
	}
}

// Once a holder served policy seq 6, seq 5 (which may still pin a withdrawn release) gets nothing there.
func TestOlderPolicyRefusedAfterNewer(t *testing.T) {
	r := newRig(t, twoOfTwo, 2)
	h := r.holders["cloudflare"]
	cfg := r.unlockConfig(nil, nil)
	newer := r.pol
	newer.Seq = 6
	req := r.request(cfg, nil)
	req.Policy = r.sign(split.KindUnlockPolicy, newer)
	if _, err := h.Unlock(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	wantRefused(t, h, r.request(cfg, nil), "older than this holder's seq 6")
}

// A holder that answers with a wrong share (a bug, or a holder account taken over) is ignored by its commitment;
// with 2-of-3 the other two still unlock.
func TestBadShareIgnored(t *testing.T) {
	r := newRig(t, twoOfThree, 2)
	liar := func(next client.Transport) client.Transport { return &lying{next: next, r: r} }
	m, rep, err := r.unlock(r.transports(map[string]func(client.Transport) client.Transport{"gcp": liar}), nil)
	if err != nil {
		t.Fatalf("unlock with one lying holder: %v (%v)", err, rep.Outcome)
	}
	r.mustMaster(m)
	if !strings.Contains(rep.Outcome["gcp"], "doesn't match its commitment") {
		t.Fatalf("the lie went unnoticed: %v", rep.Outcome)
	}
	// 2-of-2 with one lying: nothing, never a wrong M.
	r2 := newRig(t, twoOfTwo, 2)
	if _, _, err := r2.unlock(r2.transports(map[string]func(client.Transport) client.Transport{
		"vercel": func(n client.Transport) client.Transport { return &lying{next: n, r: r2} }}), nil); !errors.Is(err, split.ErrNotEnough) {
		t.Fatalf("2-of-2 with a lying holder: %v", err)
	}
}

// lying seals random bytes to the VM's attested key in place of the holder's share.
type lying struct {
	next client.Transport
	r    *rig
}

func (l *lying) Do(ctx context.Context, method, path string, body []byte) ([]byte, error) {
	b, err := l.next.Do(ctx, method, path, body)
	if err != nil || path != "/v1/unlock" {
		return b, err
	}
	var req split.UnlockRequest
	var rep split.UnlockReply
	var att proto.Attestation
	json.Unmarshal(body, &req)
	json.Unmarshal(b, &rep)
	json.Unmarshal(req.Attestation, &att)
	kb, _ := hex.DecodeString(att.HPKEPublicKey)
	pub, _ := ecdh.X25519().NewPublicKey(kb)
	bound, _ := split.Bind(req.Nonces)
	junk := make([]byte, kms.MasterSize)
	rand.Read(junk)
	rep.Sealed, _ = kms.Seal(pub, split.LabelReply, split.ReplyAAD(bound, rep.KMSID, rep.Epoch, rep.Set, rep.Holder, rep.Index, policyHashOf(req.Policy), rep.WitnessHead), junk)
	return json.Marshal(rep)
}

// The dstack watchdog restarts the unlock container (no reboot), or the VM restarts: it just unlocks again, with a
// new key and new nonces. Holders restarting (new instances) changes nothing either.
func TestRestartUnlocksAgain(t *testing.T) {
	r := newRig(t, twoOfTwo, 2)
	for i := range 3 {
		m, rep, err := r.unlock(r.transports(nil), nil)
		if err != nil {
			t.Fatalf("unlock %d: %v (%v)", i, err, rep.Outcome)
		}
		r.mustMaster(m)
		m.Drop()
		r.advance(time.Minute)
		for _, h := range r.ids {
			r.holders[h] = r.newHolder(h, nil)
		}
	}
}

// What a provider key or domain change looks like to the holders: a fresh CVM with the same release (another
// instance id, another app id). The holders pin the release, not the provider's ids, so it unlocks the same M.
func TestFreshCVMSameReleaseUnlocks(t *testing.T) {
	r := newRig(t, twoOfTwo, 2)
	_, info, ach := r.variant(func(m map[string]any) { m["docker_compose_file"] = r.vmCompose })
	q := editEvents(t, r.recQuote, map[string]string{"compose-hash": ach,
		"instance-id": strings.Repeat("ab", 20), "app-id": strings.Repeat("cd", 20)})
	m, rep, err := r.unlock(r.transports(nil), &evidence{quote: q, info: info})
	if err != nil {
		t.Fatalf("fresh CVM: %v (%v)", err, rep.Outcome)
	}
	r.mustMaster(m)
	r.mu.Lock()
	last := r.events[len(r.events)-1]
	r.mu.Unlock()
	if last.Instance != strings.Repeat("ab", 20) {
		t.Fatalf("the event should name the new instance: %+v", last)
	}
	// A policy that pins the app id refuses the other app id.
	r.pol.Releases[0].AppID = strings.Repeat("ef", 20)
	if _, rep, err := r.unlock(r.transports(nil), &evidence{quote: q, info: info}); err == nil ||
		!strings.Contains(rep.Outcome["vercel"], "isn't the pinned") {
		t.Fatalf("pinned app id: %v %v", err, rep.Outcome)
	}
}

// Only nonces that check reach the attestation check, and those are rate limited.
func TestRateLimit(t *testing.T) {
	r := newRig(t, twoOfTwo, 2)
	h := r.newHolder("cloudflare", func(c *Config) { c.Rate, c.Burst = 1.0/3600, 2 })
	r.holders["cloudflare"] = h
	cfg := r.unlockConfig(nil, nil)
	for range 2 {
		if _, err := h.Unlock(context.Background(), r.request(cfg, nil)); err != nil {
			t.Fatal(err)
		}
	}
	_, err := h.Unlock(context.Background(), r.request(cfg, nil))
	var rf *Refused
	if !errors.As(err, &rf) || rf.Status != http.StatusTooManyRequests {
		t.Fatalf("third unlock in an hour: %v", err)
	}
}

// Replies carry the share only sealed; refusals and events never carry key material.
func TestNoKeyMaterialOutside(t *testing.T) {
	r := newRig(t, twoOfTwo, 2)
	rec := &recorder{}
	if _, _, err := r.unlock(r.transports(map[string]func(client.Transport) client.Transport{
		"vercel": func(n client.Transport) client.Transport { rec.next = n; return rec }}), nil); err != nil {
		t.Fatal(err)
	}
	cfg := r.unlockConfig(nil, nil)
	b, err := client.Handler{H: r.holders["vercel"].Handler()}.Do(context.Background(), http.MethodPost, "/v1/unlock", mustJSON(r.request(cfg, nil)))
	if err != nil {
		t.Fatal(err)
	}
	r.assertNoLeak("a reply", string(b))
	_, rep, _ := r.unlock(r.transports(nil), &evidence{quote: r.recQuote, info: r.recInfo})
	for h, o := range rep.Outcome {
		r.assertNoLeak(h+"'s refusal", o)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, e := range r.events {
		r.assertNoLeak("an event", e.Reason+e.Instance+e.ComposeHash)
	}
	st, _ := json.Marshal(r.holders["vercel"].Status(context.Background()))
	r.assertNoLeak("status", string(st))
}

func mustJSON(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}

// A holder whose share doesn't match the policy's share set (deployed with an older re-split's share) refuses
// rather than hand out a share that can't combine.
func TestStaleShareRefusedByHolder(t *testing.T) {
	r := newRig(t, twoOfTwo, 2)
	_, newer, err := split.Resplit(r.master, r.kmsID, 1, 2, 2, []split.HolderRecipient{
		{Holder: "cloudflare", Recipient: PublicKeyOf(r.keys["cloudflare"])}, {Holder: "vercel", Recipient: PublicKeyOf(r.keys["vercel"])}},
		r.now, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	h := r.newHolder("cloudflare", func(c *Config) { c.Shares = []split.HolderShare{newer[0]} })
	r.holders["cloudflare"] = h
	wantRefused(t, h, r.request(r.unlockConfig(nil, nil), nil), "doesn't match its commitment")
}

// policyHashOf is split.PolicyHash of a policy envelope's payload.
func policyHashOf(raw json.RawMessage) string {
	var env safety.Envelope
	json.Unmarshal(raw, &env)
	return split.PolicyHash(env.Payload)
}
