package guard

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tacyhq/tacy/harness"
	"github.com/tacyhq/tacy/proto"
	"github.com/tacyhq/tacy/vault"
)

// Keys leased from the vault per call and redacted from responses in every encoding: the vault
// runs as it does in the CVM (its own socket, grants, records), with fake values only.

const fakeKey = "tvly-dev-" + "Zx9Qw8Er7Ty6Ui5Op4As3Df2"

func startVault(t *testing.T, secrets map[string][]byte) (*vault.Client, func() []vault.Record) {
	t.Helper()
	var mu sync.Mutex
	var recs []vault.Record
	v, err := vault.New(secrets, vault.ChatGrants(""), func(r vault.Record) {
		mu.Lock()
		recs = append(recs, r)
		mu.Unlock()
	})
	if err != nil {
		t.Fatal(err)
	}
	dir, err := os.MkdirTemp("", "vt")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	l, err := vault.Listen(filepath.Join(dir, "vault.sock"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go v.Serve(l, -1)
	return &vault.Client{Path: filepath.Join(dir, "vault.sock")}, func() []vault.Record {
		mu.Lock()
		defer mu.Unlock()
		return append([]vault.Record(nil), recs...)
	}
}

// to sends every request to srv, whatever its URL (the provider's real host stays in the URL the lease checks).
type to struct{ srv *httptest.Server }

func (x to) RoundTrip(r *http.Request) (*http.Response, error) {
	u, _ := url.Parse(x.srv.URL)
	r = r.Clone(r.Context())
	r.URL.Scheme, r.URL.Host = u.Scheme, u.Host
	return x.srv.Client().Transport.RoundTrip(r)
}

func TestSearchKeyLeasedPerCallAndRedacted(t *testing.T) {
	vc, records := startVault(t, map[string][]byte{"TAVILY_API_KEY": []byte(fakeKey)})
	var mu sync.Mutex
	var auths []string
	// A provider that echoes the key back: raw in a snippet, base64 in a title, percent-encoded in a URL.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		auths = append(auths, r.Header.Get("Authorization"))
		mu.Unlock()
		k := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		json.NewEncoder(w).Encode(map[string]any{"results": []map[string]string{
			{"title": "echo " + base64.StdEncoding.EncodeToString([]byte(k)), "url": "https://a.example/?k=" + url.QueryEscape(k), "content": "your key is " + k},
		}})
	}))
	defer srv.Close()
	tv := newTavily(VaultLease(vc))
	tv.http = &http.Client{Transport: to{srv}}
	g := New(Config{Up: &plainUpstream{}, Search: tv, Now: time.Now})
	ti := &harness.TaskInfo{ID: "t_lease", Start: &harness.Start{}, Options: []byte(`{"permissions":{"web.search":"always"}}`)}
	for i, id := range []string{"r1", "r2"} {
		ctx := harness.WithRequestID(context.Background(), id)
		res, err := g.Action(ctx, ti, id, &harness.Action{Name: "web.search", Args: []byte(`{"query":"q"}`)})
		if err != nil || res.Status != harness.ActionDone {
			t.Fatalf("call %d: %+v %v", i, res, err)
		}
		out := string(res.Output)
		if strings.Contains(out, fakeKey) || strings.Contains(out, base64.StdEncoding.EncodeToString([]byte(fakeKey))) ||
			strings.Contains(out, url.QueryEscape(fakeKey)) || !strings.Contains(out, "[REDACTED]") {
			t.Fatalf("call %d: the key came back to the brain: %s", i, out)
		}
	}
	if len(auths) != 2 || auths[0] != "Bearer "+fakeKey {
		t.Fatalf("the provider got %d requests", len(auths))
	}
	recs := records()
	if len(recs) != 2 {
		t.Fatalf("records: %+v", recs)
	}
	for i, r := range recs {
		if r.Decision != "released" || r.Secret != "TAVILY_API_KEY" || r.Connector != "web" || r.Host != "api.tavily.com" ||
			r.Task != "t_lease" || r.Action != fmt.Sprintf("r%d", i+1) || r.Lease == "" {
			t.Fatalf("record %d: %+v", i, r)
		}
		if b, _ := json.Marshal(r); strings.Contains(string(b), fakeKey) {
			t.Fatal("a record carries the value")
		}
	}
	if recs[0].Lease == recs[1].Lease {
		t.Fatal("one lease for two calls")
	}
}

// A key the vault doesn't have reads as before the vault ("isn't configured"); a host outside the grant is refused
// and recorded, and the provider never sees a request.
func TestSearchKeyNotReleased(t *testing.T) {
	vc, records := startVault(t, map[string][]byte{"TAVILY_API_KEY": []byte(fakeKey)})
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true }))
	defer srv.Close()
	br := newBrave(VaultLease(vc)) // no Brave key in the vault
	br.http = &http.Client{Transport: to{srv}}
	if _, err := br.Search(context.Background(), "q", 3); err == nil || err.Error() != "web search isn't configured" {
		t.Fatalf("brave without a key: %v", err)
	}
	tv := newTavily(VaultLease(vc))
	tv.base = "https://api.tavily.example/search" // not the granted host
	tv.http = &http.Client{Transport: to{srv}}
	if _, err := tv.Search(context.Background(), "q", 3); err == nil || err.Error() != "search key unavailable" {
		t.Fatalf("other host: %v", err)
	}
	if called {
		t.Fatal("the provider got a request without a released key")
	}
	recs := records()
	if len(recs) != 2 || recs[0].Decision != "denied" || recs[1].Decision != "denied" || recs[1].Reason != vault.ErrHost.Error() {
		t.Fatalf("records: %+v", recs)
	}
}

// keyedUpstream answers with the key it was "called with" echoed in the text (raw and base64, split across
// deltas) and in a tool call's arguments, as a leased response.
type keyedUpstream struct{ key string }

func (u *keyedUpstream) Meta(context.Context) (*proto.Meta, error) { return &proto.Meta{}, nil }
func (u *keyedUpstream) Stream(context.Context, []byte) (io.ReadCloser, error) {
	b64 := base64.StdEncoding.EncodeToString([]byte(u.key))
	half := len(u.key) / 2
	sse := fmt.Sprintf(`data: {"choices":[{"delta":{"content":%q}}]}`+"\n\n", "raw "+u.key+" b64 "+b64+" split "+u.key[:half]) +
		fmt.Sprintf(`data: {"choices":[{"delta":{"content":%q}}]}`+"\n\n", u.key[half:]+" end") +
		fmt.Sprintf(`data: {"choices":[{"delta":{"tool_calls":[{"index":0,"id":"c1","function":{"name":"web_search","arguments":%q}}]},"finish_reason":"tool_calls"}]}`+"\n\n",
			`{"query":"`+u.key+`"}`) + "data: [DONE]\n\n"
	return &leasedBody{ReadCloser: io.NopCloser(strings.NewReader(sse)), key: vault.NewSecret([]byte(u.key), "l_test")}, nil
}

func TestModelCallRedactsTheLeasedKey(t *testing.T) {
	g := New(Config{Up: &keyedUpstream{key: fakeKey}, Now: time.Now})
	var mu sync.Mutex
	var shown strings.Builder
	sess := g.Open("t_model", TaskOptions{}, func(e proto.Event) error {
		mu.Lock()
		defer mu.Unlock()
		shown.WriteString(e.Delta)
		return nil
	})
	defer sess.Close()
	ti := &harness.TaskInfo{ID: "t_model", Start: &harness.Start{Tools: ToolDefs("web.search")}}
	res, err := g.ModelCall(context.Background(), ti, &harness.ModelCall{Model: "gpt-oss-120b", Tools: []string{"web.search"},
		Messages: []harness.Message{{Role: "user", Content: "q"}}})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(res)
	for _, form := range []string{fakeKey, base64.StdEncoding.EncodeToString([]byte(fakeKey))} {
		if strings.Contains(string(b), form) {
			t.Fatalf("the brain got the key: %s", b)
		}
	}
	if !strings.Contains(res.Message.Content, "raw [REDACTED] b64 [REDACTED] split [REDACTED] end") {
		t.Fatalf("content: %q", res.Message.Content)
	}
	mu.Lock()
	defer mu.Unlock()
	if s := shown.String(); !strings.Contains(s, "raw [REDACTED] b64 [REDACTED]") {
		t.Fatalf("people saw %q", s)
	}
}
