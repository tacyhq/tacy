package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	ehbpidentity "github.com/tinfoilsh/encrypted-http-body-protocol/identity"

	"github.com/tacyhq/tacy/agentclient"
	"github.com/tacyhq/tacy/guard"
	"github.com/tacyhq/tacy/proto"
	"github.com/tacyhq/tacy/relay"
)

// testRelaySeed is the tests' relay-auth signing key (an Ed25519 seed, base64url): what the Worker holds.
var testRelaySeed = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))

func testRelayPub() ed25519.PublicKey {
	k, _ := relay.ParseKey(testRelaySeed)
	return k.Public().(ed25519.PublicKey)
}

// asRelay marks r as having come in a signed envelope: for tests that call a handler directly.
func asRelay(r *http.Request) *http.Request { return r.WithContext(relay.WithRelayed(r.Context())) }

// relayed is mux behind agentd's front door (POST /v with the tests' relay key), as main serves it.
func (s *server) relayed(mux http.Handler) http.Handler {
	return s.front(mux, &relay.Server{Key: testRelayPub(), Inner: mux})
}

// gatewayView records what Phala's gateway sees of each request and answer: TLS ends there, so method, path,
// headers and sizes; never more than that.
type gatewayView struct {
	mu   sync.Mutex
	seen []seenRequest
	h    http.Handler
}

type seenRequest struct {
	Method, Path string
	Header       http.Header
	Body         []byte
	Status       int
	RespHeader   http.Header
	Resp         []byte
}

func (g *gatewayView) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	r.Body = io.NopCloser(bytes.NewReader(body))
	rec := httptest.NewRecorder()
	g.h.ServeHTTP(rec, r)
	g.mu.Lock()
	g.seen = append(g.seen, seenRequest{Method: r.Method, Path: r.URL.RequestURI(), Header: r.Header.Clone(), Body: body,
		Status: rec.Code, RespHeader: rec.Header().Clone(), Resp: rec.Body.Bytes()})
	g.mu.Unlock()
	for k, v := range rec.Header() {
		w.Header()[k] = v
	}
	w.WriteHeader(rec.Code)
	w.Write(rec.Body.Bytes())
}

// What the gateway sees (the keys plan §3.4, PX-1): every call the relay makes is POST /v with no X-Agent-* or X-Schedule-*
// header, no token, a 200 and no plaintext. The pricing and fairness headers, the billing witness and every status
// travel inside the envelope, where agentd still checks them.
func TestGatewaySeesOnePath(t *testing.T) {
	a, _, _ := newTestAgent(t, textSSE("the secret answer"), textSSE("again"))
	id, _ := ehbpidentity.NewIdentity()
	s := newTestServer(t, a, id, defaultLimits)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /attest", s.attest)
	mux.Handle("POST /run", s.guard(id.Middleware()(http.HandlerFunc(s.run))))
	s.taskRoutes(mux, id)
	gw := &gatewayView{h: s.relayed(mux)}
	srv := httptest.NewServer(gw)
	defer srv.Close()

	conn, err := agentclient.New(srv.URL, testRelaySeed, id.MarshalPublicKey())
	if err != nil {
		t.Fatal(err)
	}
	conn.User = "0123456789abcdef0123456789abcdef"
	ctx := context.Background()
	var text string
	if err := conn.Run(ctx, proto.RunRequest{Permissions: guard.AllowAll(), Messages: []proto.Message{{Role: "user", Content: "a private question"}}},
		func(e proto.Event) { text += e.Delta }); err != nil || text != "the secret answer" {
		t.Fatalf("run: %v %q", err, text)
	}
	task, err := conn.StartTask(ctx, proto.RunRequest{Permissions: guard.AllowAll(), Messages: []proto.Message{{Role: "user", Content: "a task"}}}, "")
	if err != nil {
		t.Fatal(err)
	}
	// The billing witness still reaches the relay, inside the envelope.
	if task.Billing.Start != "new" || len(task.Billing.Bill) != 32 {
		t.Fatalf("billing witness: %+v", task.Billing)
	}
	// The relay's own plaintext call.
	res, err := conn.Plain().Get(srv.URL + "/tasks/open")
	if err != nil || res.StatusCode != 200 {
		t.Fatalf("tasks/open: %v %v", err, res)
	}
	res.Body.Close()
	// A refusal: its status is inside too.
	bad, _ := agentclient.New(srv.URL, testRelaySeed, id.MarshalPublicKey())
	bad.Model = "not-a-model"
	if err := bad.Run(ctx, proto.RunRequest{Permissions: guard.AllowAll(), Messages: []proto.Message{{Role: "user", Content: "x"}}}, func(proto.Event) {}); err == nil ||
		!strings.Contains(err.Error(), "400") {
		t.Fatalf("refusal: %v", err)
	}

	gw.mu.Lock()
	defer gw.mu.Unlock()
	if len(gw.seen) < 4 {
		t.Fatalf("%d requests seen", len(gw.seen))
	}
	for i, r := range gw.seen {
		if r.Method != "POST" || r.Path != "/v" {
			t.Errorf("request %d: %s %s, want POST /v", i, r.Method, r.Path)
		}
		for k := range r.Header {
			lk := strings.ToLower(k)
			if strings.HasPrefix(lk, "x-agent") || strings.HasPrefix(lk, "x-schedule") || lk == "authorization" || lk == "cookie" {
				t.Errorf("request %d carries %s", i, k)
			}
			if k != "Content-Type" && k != "Ehbp-Encapsulated-Key" && k != "Content-Length" && k != "Accept-Encoding" && k != "User-Agent" &&
				k != "Transfer-Encoding" {
				t.Errorf("request %d: unexpected header %s", i, k)
			}
		}
		for k := range r.RespHeader {
			if lk := strings.ToLower(k); strings.HasPrefix(lk, "x-agent") || strings.HasPrefix(lk, "x-schedule") {
				t.Errorf("answer %d carries %s", i, k)
			}
		}
		if r.Status != 200 {
			t.Errorf("answer %d: status %d visible", i, r.Status)
		}
		for _, leak := range []string{"private question", "secret answer", "X-Agent", "/tasks", "/run", conn.User, "not-a-model", testRelaySeed} {
			if bytes.Contains(r.Body, []byte(leak)) || bytes.Contains(r.Resp, []byte(leak)) {
				t.Errorf("request %d: %q in plaintext", i, leak)
			}
		}
	}
}

// Outside an envelope nothing answers but the attestation, its key and health: no route, a plaintext envelope, a
// request with the old bearer token, and an envelope signed by another key are all refused.
func TestFrontDoor(t *testing.T) {
	a, _, _ := newTestAgent(t, textSSE("x"))
	id, _ := ehbpidentity.NewIdentity()
	s := newTestServer(t, a, id, defaultLimits)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /attest", s.attest)
	mux.Handle("POST /run", s.guard(id.Middleware()(http.HandlerFunc(s.run))))
	s.taskRoutes(mux, id)
	mux.HandleFunc("POST /schedules/handoff", s.scheduleHandoff)
	mux.HandleFunc("POST /notify/pending", s.notifyPending)
	mux.HandleFunc("GET /activity", s.activityOut)
	srv := httptest.NewServer(s.relayed(mux))
	defer srv.Close()

	for _, c := range []struct{ method, path string }{
		{"POST", "/run"}, {"POST", "/tasks"}, {"GET", "/tasks/open"}, {"POST", "/schedules/handoff"}, {"POST", "/notify/pending"},
		{"GET", "/activity?chain=x&after=0"},
	} {
		req, _ := http.NewRequest(c.method, srv.URL+c.path, strings.NewReader(`{"spaces":[]}`))
		req.Header.Set("Authorization", "Bearer tok")
		req.Header.Set("Ehbp-Encapsulated-Key", strings.Repeat("ab", 32))
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		if res.StatusCode != 404 {
			t.Errorf("%s %s outside an envelope: %d", c.method, c.path, res.StatusCode)
		}
	}
	res, err := http.Post(srv.URL+"/v", "application/octet-stream", strings.NewReader("plaintext"))
	if err != nil || res.StatusCode != 400 {
		t.Fatalf("plaintext envelope: %v %d", err, res.StatusCode)
	}
	for _, p := range []string{"/attest?nonce=" + strings.Repeat("ab", 32), "/health", "/.well-known/hpke-keys"} {
		if res, err := http.Get(srv.URL + p); err != nil || res.StatusCode != 200 {
			t.Fatalf("%s: %v %v", p, err, res)
		}
	}
	// Signed by another key: refused inside (the gateway still sees a 200).
	other := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32))
	conn, _ := agentclient.New(srv.URL, other, id.MarshalPublicKey())
	res, err = conn.Plain().Get(srv.URL + "/tasks/open")
	if err != nil || res.StatusCode != 401 {
		t.Fatalf("another key: %v %v", err, res)
	}
	var e struct{ Error string }
	json.NewDecoder(res.Body).Decode(&e)
	if e.Error != "relay_auth" {
		t.Fatalf("another key: %q", e.Error)
	}
}

// A captured envelope sent again is refused (its nonce was used), and so is one outside the time window, or older than
// the operator's signed time allows (a host that sets the VM's clock back).
func TestRelayReplayAndExpiry(t *testing.T) {
	a, _, _ := newTestAgent(t)
	id, _ := ehbpidentity.NewIdentity()
	s := newTestServer(t, a, id, defaultLimits)
	mux := http.NewServeMux()
	s.taskRoutes(mux, id)
	now := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	opTime, opKnown := now, true
	var reached atomic.Int32
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { reached.Add(1); mux.ServeHTTP(w, r) })
	rs := &relay.Server{Key: testRelayPub(), Inner: inner, Now: func() time.Time { return now },
		Trusted: func() (time.Time, bool) { return opTime, opKnown }}
	gw := &gatewayView{h: s.front(inner, rs)}
	srv := httptest.NewServer(gw)
	defer srv.Close()
	key, _ := relay.ParseKey(testRelaySeed)
	signedAt := now
	tr := &relay.Transport{VMKey: id.MarshalPublicKey(), Key: key, Now: func() time.Time { return signedAt }}
	client := &http.Client{Transport: tr}
	get := func() (int, string) {
		res, err := client.Get(srv.URL + "/tasks/open")
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		var e struct{ Error string }
		json.NewDecoder(res.Body).Decode(&e)
		return res.StatusCode, e.Error
	}
	if code, _ := get(); code != 200 {
		t.Fatalf("fresh: %d", code)
	}
	gw.mu.Lock()
	captured := gw.seen[len(gw.seen)-1]
	gw.mu.Unlock()
	if reached.Load() != 1 {
		t.Fatalf("reached %d times", reached.Load())
	}

	// The gateway replays the exact bytes: agentd opens them (the same boot key) and refuses the used nonce; the
	// route isn't reached again. (The refusal is inside the answer, encrypted to a request the replayer can't open.)
	req, _ := http.NewRequest("POST", srv.URL+"/v", bytes.NewReader(captured.Body))
	for k, v := range captured.Header {
		req.Header[k] = v
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil || res.StatusCode != 200 {
		t.Fatalf("replay: %v", err)
	}
	res.Body.Close()
	if reached.Load() != 1 {
		t.Fatal("a replayed envelope reached the route")
	}
	plain := mustSeal(t, key, now)
	if _, _, err := rs.Open(bytes.NewReader(plain)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := rs.Open(bytes.NewReader(plain)); err != relay.ErrReplay {
		t.Fatalf("replay: %v", err)
	}

	// Signed too long ago, or too far ahead.
	for _, at := range []time.Time{now.Add(-relay.Window - time.Second), now.Add(relay.Window + time.Second)} {
		signedAt = at
		if code, msg := get(); code != 409 || msg != "relay_expired" {
			t.Fatalf("signed at %v: %d %q", at, code, msg)
		}
	}
	// The host set the VM's clock back an hour: the envelope matches that clock but is far older than the
	// operator's latest signed time.
	now, opTime = now.Add(-time.Hour), now
	signedAt = now
	if code, msg := get(); code != 409 || msg != "relay_expired" {
		t.Fatalf("clock set back: %d %q", code, msg)
	}
	opKnown = false // no operator time: the clock alone
	if code, _ := get(); code != 200 {
		t.Fatalf("no operator time: %d", code)
	}
}

func mustSeal(t *testing.T, key ed25519.PrivateKey, now time.Time) []byte {
	b, _, err := relay.Seal("GET", "/tasks/open", nil, nil, key, now)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
