package guard

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tacyhq/tacy/proto"
)

// slowImages serves /img/N?ms=D: a valid PNG after D milliseconds (or until the request ends).
func slowImages(t *testing.T) *httptest.Server {
	t.Helper()
	if pngCache == nil {
		pngCache = pngBytes(t, 300, 450, false)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ms, _ := strconv.Atoi(r.URL.Query().Get("ms"))
		select {
		case <-time.After(time.Duration(ms) * time.Millisecond):
		case <-r.Context().Done():
			return
		}
		w.Header().Set("Content-Type", "image/png")
		w.Write(pngCache)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// delayedImages is a provider whose candidates take the given times to download, in this order.
type delayedImages struct {
	fakeSearch
	base string
	ms   []int
}

func (d *delayedImages) Images(_ context.Context, _ string, n int) ([]ImageCandidate, error) {
	var cs []ImageCandidate
	for i, ms := range d.ms {
		if i == n {
			break
		}
		cs = append(cs, ImageCandidate{URL: fmt.Sprintf("%s/img/%d?ms=%d", d.base, i, ms), Title: fmt.Sprintf("Poster %d", i),
			Source: fmt.Sprintf("https://posters.example/%d", i)})
	}
	return cs, nil
}

func imageRun(t *testing.T, ms []int, count int) ([]proto.Event, map[string]time.Duration) {
	t.Helper()
	srv := slowImages(t)
	a, _, _ := newTestAgent(t, toolCallSSE("c1", "web_images", fmt.Sprintf(`{"query":"posters","count":%d}`, count)), textSSE("Here they are."))
	is := &delayedImages{base: srv.URL, ms: ms}
	a.gates = newToolGates(DefaultLimits)
	a.newTools = func() *Tools { return &Tools{search: is, fetcher: newFetcher(nil)} }
	r := proto.RunRequest{Space: testSpace, Permissions: AllowAll(), Messages: []proto.Message{{Role: "user", Content: "show me posters"}}}
	if err := validate(&r); err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var evs []proto.Event
	at := map[string]time.Duration{}
	t0 := time.Now()
	a.Run(context.Background(), &r, func(e proto.Event) error {
		mu.Lock()
		defer mu.Unlock()
		evs = append(evs, e)
		k := e.Type
		if e.Type == "image" {
			k = fmt.Sprintf("image%d", e.Image.Index)
		}
		if _, ok := at[k]; !ok {
			at[k] = time.Since(t0)
		}
		return nil
	})
	at["returned"] = time.Since(t0)
	time.Sleep(100 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	if evs[len(evs)-1].Type != "done" {
		t.Fatalf("events after done or no done: %s", types(evs))
	}
	return evs, at
}

func imageResult(t *testing.T, evs []proto.Event) (shown, loading int) {
	t.Helper()
	for _, e := range evs {
		if e.Type == "tool_result" {
			var r struct{ Shown, Loading int }
			json.Unmarshal(e.Result, &r)
			return r.Shown, r.Loading
		}
	}
	t.Fatal("no tool_result")
	return
}

// A slow candidate early in the provider's order no longer holds up the answer: once an image is ready, the model
// gets the result imageAnswerWait after the provider answered, with the images ready by then.
func TestImageSearchSlowCandidateDoesntHoldTheAnswer(t *testing.T) {
	evs, at := imageRun(t, []int{0, 6000, 0, 0}, 3)
	if at["tool_result"] > imageAnswerWait+1500*time.Millisecond {
		t.Fatalf("tool_result after %v", at["tool_result"])
	}
	if shown, loading := imageResult(t, evs); shown != 3 || loading != 0 {
		t.Fatalf("shown %d loading %d", shown, loading)
	}
	if at["returned"] > 4*time.Second {
		t.Fatalf("run took %v", at["returned"])
	}
}

// Images that land after the result go to the gallery under the same call, numbered after the shown ones, before
// done; the model's result says they may still appear, and its next step doesn't wait for them.
func TestImageSearchLateImagesReachTheGallery(t *testing.T) {
	evs, at := imageRun(t, []int{0, 2500, 2600}, 3)
	shown, loading := imageResult(t, evs)
	if shown != 1 || loading != 2 {
		t.Fatalf("shown %d loading %d", shown, loading)
	}
	if at["tool_result"] > imageAnswerWait+1500*time.Millisecond || at["text"] > at["image2"] {
		t.Fatalf("the answer waited for the images: %v", at)
	}
	var idx []string
	result := -1
	for i, e := range evs {
		if e.Type == "tool_result" {
			result = i
		}
	}
	for i, e := range evs {
		if e.Type == "image" {
			if e.ID != "c1" || sniffImage(e.Image.Data) != "jpeg" {
				t.Fatalf("image %+v", e)
			}
			idx = append(idx, fmt.Sprint(e.Image.Index, ":", e.Image.Title, ":", i > result))
		}
	}
	if strings.Join(idx, ",") != "1:Poster 0:false,2:Poster 1:true,3:Poster 2:true" {
		t.Fatalf("images %v", idx)
	}
	for _, e := range evs {
		if e.Type == "tool_result" && !strings.Contains(string(e.Result), "may still appear in the gallery") {
			t.Fatalf("result %s", e.Result)
		}
	}
}

// An image that never lands is dropped at the end: the run ends at most imageEndWait after the answer.
func TestImageSearchLateImagesDontHoldTheEnd(t *testing.T) {
	evs, at := imageRun(t, []int{0, 30000}, 2)
	if _, loading := imageResult(t, evs); loading != 1 {
		t.Fatalf("loading %d", loading)
	}
	if d := at["returned"] - at["text"]; d > imageEndWait+time.Second {
		t.Fatalf("done %v after the text", d)
	}
	n := 0
	for _, e := range evs {
		if e.Type == "image" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("%d images", n)
	}
}

// Every download is on the activity record: the action's facts for what finished before the result, the task's
// background facts for what landed after; and late images keep their slots until they land.
func TestImageSearchLateEgressOnTheRecord(t *testing.T) {
	srv := slowImages(t)
	reqFacts, bgFacts := &Facts{}, &Facts{}
	bg, cancel := context.WithCancel(WithFacts(context.Background(), bgFacts))
	defer cancel()
	tl := &Tools{search: &delayedImages{base: srv.URL, ms: []int{0, 2000, 2100}},
		fetcher: &http.Client{Transport: recordTransport{base: http.DefaultTransport}}, bg: bg}
	want := tl.reserveImages(3)
	var out toolOutcome
	imgs, st, tail, err := tl.findImages(WithFacts(context.Background(), reqFacts), "q", want, &out)
	if err != nil || len(imgs) != 1 || tail == nil || tail.slots != 2 || st.tried != 1 {
		t.Fatalf("imgs %d tail %+v st %+v err %v", len(imgs), tail, st, err)
	}
	late := 0
	for range tail.ch {
		late++
	}
	if late != 2 {
		t.Fatalf("late %d", late)
	}
	count := func(f *Facts) int {
		n := 0
		for _, h := range f.Data().Hosts {
			n += h.Requests
		}
		return n
	}
	if r, b := count(reqFacts), count(bgFacts); r != 1 || b != 2 {
		t.Fatalf("action's record %d requests, background %d", r, b)
	}
}

// The task ending stops a tail's downloads and closes it.
func TestImageSearchTailEndsWithTheTask(t *testing.T) {
	srv := slowImages(t)
	bg, cancel := context.WithCancel(context.Background())
	tl := &Tools{search: &delayedImages{base: srv.URL, ms: []int{0, 30000}}, fetcher: newFetcher(nil), bg: bg}
	var out toolOutcome
	_, _, tail, err := tl.findImages(context.Background(), "q", 2, &out)
	if err != nil || tail == nil {
		t.Fatalf("tail %v err %v", tail, err)
	}
	cancel()
	select {
	case _, open := <-tail.ch:
		if open {
			t.Fatal("an image after the task ended")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("tail still open after the task ended")
	}
}

// After a restart, the slots kept for late images stay taken.
func TestJournaledImagesCountLoading(t *testing.T) {
	_, n, _ := journaledOutput("web.images", []byte(`{"shown":1,"loading":2,"images":[{"source":"https://a.example/p"}]}`))
	if n != 3 {
		t.Fatalf("slots %d", n)
	}
}
