package gateway

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	jsonv1 "encoding/json"
	"encoding/json/jsontext"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tacyhq/tacy/guard"
	"github.com/tacyhq/tacy/harness"
	"github.com/tacyhq/tacy/proto"
)

// gatewayd with the person's image (v0.12.0): the image crosses the socket in the task's options only, gatewayd puts
// it on the person's message in the acting model's request, and nothing else it sends has it: not the search, not
// the page (address, headers or body), not the quarantined reader's model calls. A search for the image's data URL
// is refused before anything is sent.
func TestPersonImageOnlyToTheModelAcrossTheSocket(t *testing.T) {
	raw := make([]byte, 2000)
	rand.Read(raw)
	copy(raw, []byte{0xff, 0xd8, 0xff, 0xe0})
	b64 := base64.StdEncoding.EncodeToString(raw)
	img := proto.ImageURLPrefix + b64
	carries := func(s string) bool {
		if strings.Contains(s, "data:image") || strings.Contains(s, ";base64,") {
			return true
		}
		for i := 16; i+24 <= len(b64); i += 12 {
			if strings.Contains(s, b64[i:i+24]) {
				return true
			}
		}
		return false
	}
	var mu sync.Mutex
	var sent []string // every request that left: pages and searches
	var acting, reader []string
	page := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		h, _ := jsonv1.Marshal(r.Header)
		mu.Lock()
		sent = append(sent, "page "+r.Method+" "+r.URL.String()+" "+string(h)+" "+string(body))
		mu.Unlock()
		w.Write([]byte("<html><head><title>Shop</title></head><body><p>The red espresso machine is in stock at Shop for $499, shipped free.</p></body></html>"))
	}))
	defer page.Close()
	model := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "text/event-stream")
		if strings.Contains(string(body), "You are Tacy's quarantined reader.") {
			mu.Lock()
			reader = append(reader, string(body))
			mu.Unlock()
			answer := `{"summary":"In stock [Q1].","facts":["In stock."],"entities":[],"dates":[],"amounts":[],` +
				`"source":{"kind":"other","title":"Shop","publisher":"","published":""},` +
				`"quotes":[{"id":1,"from":2,"to":2,"location":"p","topic":"stock"}],` +
				`"items":[],"wording":"","instructions_found":false,"instruction_count":0}`
			b, _ := jsonv1.Marshal(answer)
			fmt.Fprintf(w, "data: {\"choices\":[{\"delta\":{\"content\":%s},\"finish_reason\":\"stop\"}]}\n\n", b)
		} else {
			mu.Lock()
			acting = append(acting, string(body))
			mu.Unlock()
			w.Write([]byte(`data: {"choices":[{"delta":{"content":"A red espresso machine."},"finish_reason":"stop"}]}` + "\n\n"))
		}
		w.Write([]byte("data: {\"choices\":[],\"usage\":{\"prompt_tokens\":700,\"completion_tokens\":9,\"total_tokens\":709}}\n\ndata: [DONE]\n\n"))
	}))
	defer model.Close()
	path := socketPath(t)
	rc := guard.DefaultReader
	search := recSearch{&mu, new([]string)}
	serve(t, path, guard.New(guard.Config{Up: guard.NewPlainUpstream(model.URL, model.Client()), Search: search,
		Fetcher: guard.NewFetcher(true), Reader: &rc, Now: time.Now}))
	c := &Client{Path: path, Wait: 5 * time.Second}

	req := proto.RunRequest{Space: "s_test", Model: "kimi-k3", Permissions: guard.AllowAll(),
		Messages: []proto.Message{{Role: "user", Content: "where can I buy this?", Images: []string{img}}}}
	start, opts, err := guard.StartFor(&req, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	optsJSON, _ := jsonv1.Marshal(opts)
	s := c.Open("t_img", opts, func(proto.Event) error { return nil })
	defer s.Close()
	ti := &harness.TaskInfo{ID: "t_img", Start: &start, Options: optsJSON}

	// The acting model's call, as the brain proposes it: its instructions and the task's input (text only).
	msgs := append([]harness.Message{{Role: "system", Content: start.Instructions}}, start.Input...)
	if carries(fmt.Sprint(msgs)) {
		t.Fatal("the brain's messages carry the image")
	}
	ctx := harness.WithRequestID(context.Background(), "m1")
	if _, err := c.ModelCall(ctx, ti, &harness.ModelCall{Model: "kimi-k3", Messages: msgs, Tools: []string{"web.search", "web.fetch"}}); err != nil {
		t.Fatal(err)
	}
	act := func(id, name, args string) *harness.ActionResult {
		t.Helper()
		res, err := c.Action(harness.WithRequestID(context.Background(), id), ti, id, &harness.Action{Name: name, Args: jsontext.Value(args)})
		if err != nil {
			t.Fatalf("%s: %v", id, err)
		}
		return res
	}
	if res := act("a1", "web.search", `{"query":"red espresso machine"}`); res.Status != harness.ActionDone {
		t.Fatalf("search %+v", res)
	}
	if res := act("a2", "web.fetch", `{"url":"`+page.URL+`/p"}`); res.Status != harness.ActionDone {
		t.Fatalf("fetch %+v", res)
	}
	if res := act("a3", "web.search", `{"query":"`+img+`"}`); res.Status != harness.ActionDenied || !strings.Contains(res.Error, "the person's image") {
		t.Fatalf("a search for the image: %+v %s", res, res.Output)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(acting) != 1 || !strings.Contains(acting[0], `"image_url":{"url":"`+img+`"}`) {
		t.Fatalf("the acting model's request lacks the image (%d requests)", len(acting))
	}
	if len(reader) == 0 {
		t.Fatal("the reader never read the page")
	}
	for _, r := range reader {
		if carries(r) {
			t.Fatal("the quarantined reader got the image")
		}
	}
	all := strings.Join(append(sent, *search.q...), "\n")
	if !strings.Contains(all, "red espresso machine") || !strings.Contains(all, "page GET /p") {
		t.Fatalf("outbound %s", all)
	}
	if carries(all) || len(*search.q) != 1 {
		t.Fatalf("the image left the VM: %q", all)
	}
}
