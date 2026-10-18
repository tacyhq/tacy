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
	s := c.Open(task.ID, guard.TaskOptions{}, func(e proto.Event) error {
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
	s := c.Open(task.ID, guard.TaskOptions{}, func(proto.Event) error { return nil })
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
	s := c.Open(task.ID, guard.TaskOptions{}, func(proto.Event) error { return nil })
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
	s := c.Open("t_f", guard.TaskOptions{}, func(proto.Event) error { return nil })
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
