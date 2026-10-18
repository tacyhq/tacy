package gateway

import (
	"context"
	"encoding/binary"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tacyhq/tacy/guard"
	"github.com/tacyhq/tacy/harness"
	"github.com/tacyhq/tacy/proto"
)

// gateway/v0 between agentd's client and gatewayd's server over a real unix socket. Parity of the events people see
// runs in ../app (TestParity, mode "gatewayd"), the leak tests there too.

type conns struct {
	net.Listener
	mu sync.Mutex
	cs []net.Conn
}

func (c *conns) Accept() (net.Conn, error) {
	x, err := c.Listener.Accept()
	if err == nil {
		c.mu.Lock()
		c.cs = append(c.cs, x)
		c.mu.Unlock()
	}
	return x, err
}

// kill is gatewayd stopping: the listener and every connection close.
func (c *conns) kill() {
	c.Listener.Close()
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, x := range c.cs {
		x.Close()
	}
}

func socketPath(t *testing.T) string {
	dir, err := os.MkdirTemp("", "gw")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return filepath.Join(dir, "gateway.sock")
}

func serve(t *testing.T, path string, g *guard.Guard) *conns {
	l, err := Listen(path, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	c := &conns{Listener: l}
	t.Cleanup(c.kill)
	go (&Server{G: g}).Serve(c, -1)
	return c
}

type searchN struct{}

func (searchN) Name() string { return "fake" }
func (searchN) Search(_ context.Context, q string, n int) ([]guard.SearchResult, error) {
	return []guard.SearchResult{{Title: "r " + q, URL: "https://a.example/" + q, Snippet: "s"}}, nil
}

func newGuard(up guard.Upstream) *guard.Guard {
	return guard.New(guard.Config{Up: up, Search: searchN{}, Now: time.Now})
}

var task = &harness.TaskInfo{ID: "t_1", Start: &harness.Start{Tools: guard.ToolDefs("web.search")}}

// A gatewayd restart: the session's connection breaks, and the next request goes to the new process, which
// rebuilds the task from the journal the client sends again (citation numbers continue).
func TestReconnectRebuildsFromJournal(t *testing.T) {
	path := socketPath(t)
	first := serve(t, path, newGuard(guard.NewPlainUpstream("http://unused", nil)))
	c := &Client{Path: path, Wait: 5 * time.Second}
	var mu sync.Mutex
	var events []proto.Event
	s := c.Open(task.ID, guard.TaskOptions{Permissions: guard.AllowAll()}, func(e proto.Event) error {
		mu.Lock()
		events = append(events, e)
		mu.Unlock()
		return nil
	})
	defer s.Close()
	var journal []harness.Record
	ti := &harness.TaskInfo{ID: task.ID, Start: task.Start, Journal: func() ([]harness.Record, error) { return journal, nil }}
	act := func(id string) *harness.ActionResult {
		t.Helper()
		ctx := harness.WithRequestID(context.Background(), id)
		req := &harness.Action{Name: "web.search", Args: jsontext.Value(`{"query":"` + id + `"}`)}
		res, err := c.Action(ctx, ti, id, req)
		if err != nil || res.Status != harness.ActionDone {
			t.Fatalf("%s: %+v %v", id, res, err)
		}
		journal = append(journal, harness.Record{ID: id, Kind: harness.TypeAction, Req: mustJSON(req), Done: true, Body: mustJSON(res)})
		return res
	}
	if out := act("a1"); !strings.Contains(string(out.Output), `"n":1`) {
		t.Fatalf("first: %s", out.Output)
	}
	first.kill()
	serve(t, path, newGuard(guard.NewPlainUpstream("http://unused", nil)))
	if out := act("a2"); !strings.Contains(string(out.Output), `"n":2`) {
		t.Fatalf("after the restart the numbering restarted: %s", out.Output)
	}
	mu.Lock()
	defer mu.Unlock()
	results := 0
	for _, e := range events {
		if e.Type == "tool_result" {
			results++
		}
	}
	if results != 2 {
		t.Fatalf("tool_result events relayed: %d", results)
	}
}

func mustJSON(v any) jsontext.Value {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

// A cancelled request stops in gatewayd too (the upstream call ends).
func TestCancelReachesGatewayd(t *testing.T) {
	stopped := make(chan struct{})
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		<-r.Context().Done()
		close(stopped)
	}))
	defer up.Close()
	path := socketPath(t)
	serve(t, path, newGuard(guard.NewPlainUpstream(up.URL, up.Client())))
	c := &Client{Path: path}
	s := c.Open(task.ID, guard.TaskOptions{Permissions: guard.AllowAll()}, func(proto.Event) error { return nil })
	defer s.Close()
	ctx, cancel := context.WithCancel(harness.WithRequestID(context.Background(), "m1"))
	go func() { time.Sleep(200 * time.Millisecond); cancel() }()
	_, err := c.ModelCall(ctx, task, &harness.ModelCall{Model: "gpt-oss-120b", Messages: []harness.Message{{Role: "user", Content: "q"}}})
	if err != context.Canceled {
		t.Fatalf("err %v", err)
	}
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("the upstream call kept running")
	}
}

// Strict decoding: an unknown member, a request before the task frame, a bad version or an oversized length
// close the connection without an answer.
func TestMalformedFramesClose(t *testing.T) {
	path := socketPath(t)
	serve(t, path, newGuard(guard.NewPlainUpstream("http://unused", nil)))
	raw := func(b []byte) []byte {
		h := make([]byte, 4)
		binary.BigEndian.PutUint32(h, uint32(len(b)))
		return append(h, b...)
	}
	open := raw([]byte(`{"t":"open","version":"gateway/v0","task":"t_1"}`))
	for name, send := range map[string][]byte{
		"unknown member":      raw([]byte(`{"t":"open","version":"gateway/v0","task":"t_1","x":1}`)),
		"wrong version":       raw([]byte(`{"t":"open","version":"gateway/v9","task":"t_1"}`)),
		"bad task id":         raw([]byte(`{"t":"open","version":"gateway/v0","task":"../x"}`)),
		"model before task":   append(open, raw([]byte(`{"t":"model","rid":1,"id":"m1","model":{"model":"gpt-oss-120b","messages":[]}}`))...),
		"duplicate name":      append(open, raw([]byte(`{"t":"meta","rid":1,"rid":2}`))...),
		"too long":            {0xff, 0xff, 0xff, 0xff},
		"unknown type":        append(open, raw([]byte(`{"t":"exec","rid":1}`))...),
		"request id 0":        append(open, raw([]byte(`{"t":"meta"}`))...),
		"second task frame":   append(open, append(raw([]byte(`{"t":"task"}`)), raw([]byte(`{"t":"task"}`))...)...),
		"truncated after len": {0, 0, 0, 9, '{'},
	} {
		t.Run(name, func(t *testing.T) {
			nc, err := net.Dial("unix", path)
			if err != nil {
				t.Fatal(err)
			}
			defer nc.Close()
			nc.Write(send)
			if uc, ok := nc.(*net.UnixConn); ok && name == "truncated after len" {
				uc.CloseWrite()
			}
			nc.SetReadDeadline(time.Now().Add(3 * time.Second))
			var f frame
			if err := readFrame(nc, &f); err == nil {
				t.Fatalf("got an answer: %+v", f)
			} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
				t.Fatal("the connection stayed open")
			}
		})
	}
}

// Requests from several goroutines on one session (a step's parallel actions) each get their own result.
func TestParallelRequests(t *testing.T) {
	path := socketPath(t)
	serve(t, path, newGuard(guard.NewPlainUpstream("http://unused", nil)))
	c := &Client{Path: path}
	s := c.Open(task.ID, guard.TaskOptions{Permissions: guard.AllowAll()}, func(proto.Event) error { return nil })
	defer s.Close()
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for i := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			id := fmt.Sprintf("a%d", i)
			res, err := c.Action(harness.WithRequestID(context.Background(), id), task, id,
				&harness.Action{Name: "web.search", Args: jsontext.Value(`{"query":"` + id + `"}`)})
			if err == nil && !strings.Contains(string(res.Output), "r "+id) {
				err = fmt.Errorf("%s got %s", id, res.Output)
			}
			if err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

// What gatewayd saw and did for a request comes back with its result (the activity record's facts): the page's
// host and sizes, nothing of the URL's path.
func TestFactsCrossTheSocket(t *testing.T) {
	page := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("<html><head><title>T</title></head><body><p>" + strings.Repeat("words ", 200) + "</p></body></html>"))
	}))
	defer page.Close()
	path := socketPath(t)
	serve(t, path, guard.New(guard.Config{Up: guard.NewPlainUpstream("http://unused", nil), Search: searchN{}, Fetcher: guard.NewFetcher(true), Now: time.Now}))
	c := &Client{Path: path, Wait: 5 * time.Second}
	s := c.Open("t_f", guard.TaskOptions{Permissions: guard.AllowAll()}, func(proto.Event) error { return nil })
	defer s.Close()
	ti := &harness.TaskInfo{ID: "t_f", Start: &harness.Start{Tools: guard.ToolDefs("web.fetch")}}
	f := &guard.Facts{}
	ctx := guard.WithFacts(harness.WithRequestID(context.Background(), "a1"), f)
	res, err := c.Action(ctx, ti, "a1", &harness.Action{Name: "web.fetch", Args: jsontext.Value(`{"url":"` + page.URL + `/secret/path"}`)})
	if err != nil || res.Status != harness.ActionDone {
		t.Fatalf("%+v %v", res, err)
	}
	d := f.Data()
	if len(d.Hosts) != 1 || d.Hosts[0].Host != "127.0.0.1" || d.Hosts[0].Requests != 1 || d.Hosts[0].BytesIn < 1000 {
		t.Fatalf("facts: %+v", d)
	}
	if b, _ := json.Marshal(d); strings.Contains(string(b), "secret") {
		t.Fatalf("facts hold the path: %s", b)
	}
}

// The quarantined reader in gatewayd: its numbers come back with the action's facts (agentd commits them to the
// budget), the quotes reach the person's stream, and the result agentd's runtime gets has no page text.
func TestReaderAcrossTheSocket(t *testing.T) {
	page := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("<html><head><title>T</title></head><body><p>The quick brown fox jumps over the lazy dog, every single morning.</p></body></html>"))
	}))
	defer page.Close()
	model := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		answer := `{"summary":"A sentence about a fox [Q1].","facts":["A fox jumps."],"entities":[],"dates":[],"amounts":[],` +
			`"source":{"kind":"other","title":"T","publisher":"","published":""},` +
			`"quotes":[{"id":1,"from":2,"to":2,"location":"p","topic":"fox"}],` + // span 1 is the title, 2 the sentence
			`"wording":"","instructions_found":false,"instruction_count":0}`
		b, _ := json.Marshal(answer)
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprintf(w, "data: {\"choices\":[{\"delta\":{\"content\":%s},\"finish_reason\":\"stop\"}]}\n\n", b)
		w.Write([]byte("data: {\"choices\":[],\"usage\":{\"prompt_tokens\":700,\"completion_tokens\":90,\"total_tokens\":790}}\n\ndata: [DONE]\n\n"))
	}))
	defer model.Close()
	path := socketPath(t)
	rc := guard.DefaultReader
	serve(t, path, guard.New(guard.Config{Up: guard.NewPlainUpstream(model.URL, model.Client()), Search: searchN{},
		Fetcher: guard.NewFetcher(true), Reader: &rc, Now: time.Now}))
	c := &Client{Path: path, Wait: 5 * time.Second}
	var mu sync.Mutex
	var quotes []proto.Quote
	s := c.Open("t_r", guard.TaskOptions{Permissions: guard.AllowAll(), Question: "what does the fox do?"}, func(e proto.Event) error {
		mu.Lock()
		quotes = append(quotes, e.Quotes...)
		mu.Unlock()
		return nil
	})
	defer s.Close()
	ti := &harness.TaskInfo{ID: "t_r", Start: &harness.Start{Tools: guard.ToolDefs("web.fetch")}}
	f := &guard.Facts{}
	ctx := guard.WithFacts(harness.WithRequestID(context.Background(), "a1"), f)
	res, err := c.Action(ctx, ti, "a1", &harness.Action{Name: "web.fetch", Args: jsontext.Value(`{"url":"` + page.URL + `/p"}`)})
	if err != nil || res.Status != harness.ActionDone {
		t.Fatalf("%+v %v", res, err)
	}
	if strings.Contains(string(res.Output), "quick brown fox") || !strings.Contains(string(res.Output), `[quote 1]`) {
		t.Fatalf("the brain's result: %s", res.Output)
	}
	d := f.Data()
	if len(d.Reader) != 1 || d.Reader[0].Prompt != 700 || d.Reader[0].Completion != 90 || d.Reader[0].Outcome != "ok" || !d.Reader[0].Sent {
		t.Fatalf("reader facts %+v", d.Reader)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(quotes) != 1 || quotes[0].Text != "The quick brown fox jumps over the lazy dog, every single morning." || quotes[0].Index != 1 {
		t.Fatalf("quotes in the stream %+v", quotes)
	}
	if !c.Untrusted(ti, &harness.Action{Name: "web.fetch"}) || c.Untrusted(ti, &harness.ModelCall{}) {
		t.Fatal("Untrusted")
	}
}

// Permission prompts: the person's grant crosses the socket with its action, and gatewayd checks it itself: without one (or with
// one made with another secret) nothing is searched; with a valid one the person's edit is what goes out.
func TestGrantCrossesTheSocket(t *testing.T) {
	path := socketPath(t)
	var mu sync.Mutex
	var queries []string
	g := guard.New(guard.Config{Up: guard.NewPlainUpstream("http://unused", nil), Search: recSearch{&mu, &queries}, Now: time.Now})
	serve(t, path, g)
	c := &Client{Path: path}
	secret := strings.Repeat("0a", 32)
	s := c.Open(task.ID, guard.TaskOptions{RunSecret: secret}, func(proto.Event) error { return nil })
	defer s.Close()
	ti := &harness.TaskInfo{ID: task.ID, Start: task.Start, Options: []byte(`{"run_secret":"` + secret + `"}`)}
	act := &harness.Action{Name: "web.search", Args: []byte(`{"query":"model q"}`)}
	mk := func(sec string) *guard.Grant {
		gr := &guard.Grant{Task: task.ID, Request: "a1", Kind: "web.search", Decision: guard.DecideOnce, Value: "person q"}
		gr.MAC = guard.GrantMAC(sec, *gr)
		return gr
	}
	for _, gr := range []*guard.Grant{nil, mk(strings.Repeat("0b", 32))} {
		res, err := c.Action(guard.WithGrant(harness.WithRequestID(context.Background(), "a1"), gr), ti, "a1", act)
		if err != nil || res.Status != harness.ActionDenied {
			t.Fatalf("without a valid grant: %+v %v", res, err)
		}
	}
	res, err := c.Action(guard.WithGrant(harness.WithRequestID(context.Background(), "a1"), mk(secret)), ti, "a1", act)
	if err != nil || res.Status != harness.ActionDone {
		t.Fatalf("with the grant: %+v %v", res, err)
	}
	mu.Lock()
	defer mu.Unlock()
	if strings.Join(queries, "|") != "person q" {
		t.Fatalf("searched %q", queries)
	}
}

type recSearch struct {
	mu *sync.Mutex
	q  *[]string
}

func (recSearch) Name() string { return "fake" }
func (r recSearch) Search(_ context.Context, q string, n int) ([]guard.SearchResult, error) {
	r.mu.Lock()
	*r.q = append(*r.q, q)
	r.mu.Unlock()
	return []guard.SearchResult{{Title: "t", URL: "https://a.example/", Snippet: "s"}}, nil
}

// agentd's taint travels with each action: on a tainted task gatewayd won't fetch an address the model composed under
// Always allow (nothing reaches the page); the same request untainted goes.
func TestTaintAcrossTheSocket(t *testing.T) {
	var hits atomic.Int32
	page := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Write([]byte("<html><body><p>ok</p></body></html>"))
	}))
	defer page.Close()
	path := socketPath(t)
	serve(t, path, guard.New(guard.Config{Up: guard.NewPlainUpstream("http://unused", nil), Search: searchN{}, Fetcher: guard.NewFetcher(true), Now: time.Now}))
	c := &Client{Path: path, Wait: 5 * time.Second}
	s := c.Open("t_t", guard.TaskOptions{Permissions: guard.AllowAll()}, func(proto.Event) error { return nil })
	defer s.Close()
	for i, tainted := range []bool{true, false} {
		ti := &harness.TaskInfo{ID: "t_t", Start: &harness.Start{Tools: guard.ToolDefs("web.fetch")}, Tainted: tainted}
		id := fmt.Sprintf("a%d", i)
		res, err := c.Action(harness.WithRequestID(context.Background(), id), ti, id,
			&harness.Action{Name: "web.fetch", Args: jsontext.Value(`{"url":"` + page.URL + `/x?d=secret"}`)})
		if err != nil {
			t.Fatal(err)
		}
		if tainted && (res.Status != harness.ActionDenied || hits.Load() != 0) || !tainted && (res.Status != harness.ActionDone || hits.Load() != 1) {
			t.Fatalf("tainted %v: %+v (hits %d)", tainted, res, hits.Load())
		}
	}
}
