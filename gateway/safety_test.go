package gateway

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tacyhq/tacy/guard"
	"github.com/tacyhq/tacy/harness"
	"github.com/tacyhq/tacy/safety"
)

// gatewayd checks the signed documents itself: what agentd sends with a session or pushes is verified against
// gatewayd's own pinned keys, so a forged document from agentd's side counts for nothing, and a stop pushed to
// gatewayd refuses its next request even if agentd didn't cancel the task.
func TestGatewaydChecksDocumentsItself(t *testing.T) {
	_, admin, _ := ed25519.GenerateKey(rand.Reader)
	_, operator, _ := ed25519.GenerateKey(rand.Reader)
	_, stranger, _ := ed25519.GenerateKey(rand.Reader)
	st, err := safety.NewState(safety.Config{Firm: "f_chat", Operator: operator.Public().(ed25519.PublicKey),
		Admins: []ed25519.PublicKey{admin.Public().(ed25519.PublicKey)}, Release: guard.ReleasePolicy("f_chat", "")})
	if err != nil {
		t.Fatal(err)
	}
	g := guard.New(guard.Config{Up: guard.NewPlainUpstream("http://unused", nil), Search: searchN{}, Now: time.Now, Safety: st})
	path := socketPath(t)
	l, err := Listen(path, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	c0 := &conns{Listener: l}
	t.Cleanup(c0.kill)
	var told atomic.Int32
	go (&Server{G: g, Safety: st, OnDocs: func() { told.Add(1) }}).Serve(c0, -1)

	policy := func(key ed25519.PrivateKey, v uint64) safety.Envelope {
		p := guard.ReleasePolicy("f_chat", "")
		p.Version, p.IssuedAt = v, time.Now().UTC()
		b, _ := json.Marshal(p)
		return safety.Sign(safety.KindPolicy, b, key)
	}
	var docs []safety.Envelope
	c := &Client{Path: path, Wait: 5 * time.Second, Docs: func() []safety.Envelope { return docs }}
	ti := &harness.TaskInfo{ID: "t_1", Start: &harness.Start{Tools: guard.ToolDefs("web.search")}}
	search := func(id string) (*harness.ActionResult, error) {
		s := c.Open(ti.ID+id, guard.TaskOptions{Permissions: guard.AllowAll(), Space: "s_chat"}, nil)
		defer s.Close()
		ti := &harness.TaskInfo{ID: ti.ID + id, Start: ti.Start, Journal: func() ([]harness.Record, error) { return nil, nil }}
		return c.Action(harness.WithRequestID(context.Background(), id), ti, id,
			&harness.Action{Name: "web.search", Args: jsontext.Value(`{"query":"x"}`)})
	}
	// agentd's side sends a forged policy with the session: gatewayd has none it trusts, so it refuses.
	docs = []safety.Envelope{policy(stranger, 1)}
	if _, err := search("a1"); err == nil || !strings.Contains(err.Error(), safety.CodePolicyMissing) {
		t.Fatalf("forged policy from agentd: %v", err)
	}
	// A valid one with the session (and a fresh operator list: without one nothing goes out): taken, passed on
	// (OnDocs), and the action runs.
	hb, err := safety.Heartbeat(operator, 0, time.Now().Add(-time.Second), time.Minute, false)
	if err != nil {
		t.Fatal(err)
	}
	docs = []safety.Envelope{hb, policy(admin, 1)}
	if res, err := search("a2"); err != nil || res.Status != harness.ActionDone {
		t.Fatalf("valid policy: %+v %v", res, err)
	}
	if told.Load() != 1 {
		t.Fatalf("OnDocs told %d times", told.Load())
	}
	// A stop pushed on its own connection refuses the next request.
	now := time.Now().UTC()
	b, _ := json.Marshal(&safety.StopList{Type: safety.StopType, Issuer: safety.IssuerOperator, Seq: uint64(now.UnixMilli()), IssuedAt: now,
		ExpiresAt: now.Add(time.Minute), All: true})
	if err := c.PushDocs(context.Background(), []safety.Envelope{safety.Sign(safety.KindStop, b, operator)}); err != nil {
		t.Fatal(err)
	}
	if _, err := search("a3"); err == nil || !strings.Contains(err.Error(), safety.CodeStopped) {
		t.Fatalf("after the stop: %v", err)
	}
}
