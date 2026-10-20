package guard

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/tacyhq/tacy/proto"
)

// Every way a picture fails has its reason: the site refusing, our rules refusing, time, the bytes, the size, the
// network. Never the URL or the host.
func TestImageFailReasons(t *testing.T) {
	if pngCache == nil {
		pngCache = pngBytes(t, 300, 450, false)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/forbidden":
			w.WriteHeader(403)
		case "/limited":
			w.WriteHeader(429)
		case "/gone":
			w.WriteHeader(404)
		case "/broken":
			w.WriteHeader(502)
		case "/html":
			w.Write([]byte("<html>not a picture</html>"))
		case "/tiny":
			w.Write(pngBytes(t, 16, 16, false))
		case "/huge":
			w.Header().Set("Content-Length", fmt.Sprint(maxImageDownload+1))
			w.WriteHeader(200)
		case "/slow":
			select {
			case <-time.After(3 * time.Second):
			case <-r.Context().Done():
			}
		default:
			w.Write(pngCache)
		}
	}))
	defer srv.Close()
	open := newFetcher(func(string, string, syscall.RawConn) error { return nil })
	reason := func(path string, ctx context.Context, client *http.Client) string {
		b, err := downloadImage(ctx, client, srv.URL+path)
		if err == nil {
			_, _, _, err = processImage(ctx, b, nil)
		}
		if err == nil {
			return ""
		}
		return imageFailReason(err)
	}
	bg := context.Background()
	short, cancel := context.WithTimeout(bg, 200*time.Millisecond)
	defer cancel()
	for _, c := range []struct {
		path, want string
		ctx        context.Context
		client     *http.Client
	}{
		{"/ok.png", "", bg, open},
		{"/forbidden", imageBlocked, bg, open},
		{"/limited", imageBlocked, bg, open},
		{"/gone", imageUnreachable, bg, open},
		{"/broken", imageUnreachable, bg, open},
		{"/html", imageFormat, bg, open},
		{"/tiny", imageSize, bg, open},
		{"/huge", imageSize, bg, open},
		{"/slow", imageTimeout, short, open},
		{"/ok.png", imageBlocked, bg, newFetcher(publicOnly)},                   // our address rules
		{"/ok.png?email=jane@example.com", imageBlocked, bg, open},              // personal data in the URL
		{"/ok.png", imageUnreachable, bg, &http.Client{Transport: failingRT{}}}, // DNS, connection, TLS
	} {
		if got := reason(c.path, c.ctx, c.client); got != c.want {
			t.Errorf("%s: %q, want %q", c.path, got, c.want)
		}
	}
	if imageFailReason(context.Canceled) != imageNever {
		t.Error("a download the run's end stopped isn't never_arrived")
	}
}

type failingRT struct{}

func (failingRT) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, fmt.Errorf("dial tcp: lookup img.example: no such host")
}

// Candidates go best caption match first, logos and icons last, and keep the provider's order among equals.
func TestRankCandidates(t *testing.T) {
	list := []ImageCandidate{
		{URL: "https://shop.example/logo.png", Title: "Persol PO3019S"},
		{URL: "https://img.example/a.jpg", Title: "Sunglasses on a beach"},
		{URL: "https://img.example/b.jpg", Title: "Persol 3019 side view"},
		{URL: "https://cdn.example/persol-po3019s-black.jpg", Title: ""},
		{URL: "https://img.example/c.jpg", Title: "Persol PO3019S in Havana"},
	}
	var got []string
	for _, c := range rankCandidates("Persol PO3019S", list) {
		got = append(got, c.URL)
	}
	want := []string{"https://cdn.example/persol-po3019s-black.jpg", "https://img.example/c.jpg", "https://img.example/b.jpg",
		"https://shop.example/logo.png", "https://img.example/a.jpg"}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("order\n got %v\nwant %v", got, want)
	}
	// Nothing to go on: the provider's order.
	same := rankCandidates("", list)
	for i := range list {
		if same[i] != list[i] {
			t.Fatalf("order changed without a query: %v", same)
		}
	}
}

// failingFirst is a provider whose best-named candidates fail (the site refuses, then sends HTML), and a worse-named
// one works: the picture shown is the working one, and the record says why the others didn't make it.
type failingFirst struct {
	fakeSearch
	base string
	mu   sync.Mutex
	asks []int
}

func (f *failingFirst) Images(_ context.Context, _ string, n int) ([]ImageCandidate, error) {
	f.mu.Lock()
	f.asks = append(f.asks, n)
	f.mu.Unlock()
	return []ImageCandidate{
		{URL: f.base + "/other.png", Title: "Some other glasses"},
		{URL: f.base + "/forbidden/persol-po3019s.png", Title: "Persol PO3019S"},
		{URL: f.base + "/html/persol.png", Title: "Persol PO3019S front"},
		{URL: f.base + "/img/persol-3019.png", Title: "Persol 3019"},
	}, nil
}

func TestImageSearchTriesTheNextCandidate(t *testing.T) {
	if pngCache == nil {
		pngCache = pngBytes(t, 300, 450, false)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/forbidden/"):
			w.WriteHeader(403)
		case strings.HasPrefix(r.URL.Path, "/html/"):
			w.Write([]byte("<html>no</html>"))
		default:
			w.Write(pngCache)
		}
	}))
	defer srv.Close()
	is := &failingFirst{base: srv.URL}
	reqFacts := &Facts{}
	tl := &Tools{search: is, fetcher: newFetcher(nil), bg: context.Background()}
	var out toolOutcome
	imgs, st, tail, err := tl.findImages(WithFacts(context.Background(), reqFacts), "Persol PO3019S", 1, &out)
	if err != nil || tail != nil || len(imgs) != 1 {
		t.Fatalf("imgs %d tail %v err %v", len(imgs), tail, err)
	}
	if !strings.HasSuffix(imgs[0].URL, "/img/persol-3019.png") {
		t.Fatalf("shown %s, want the best match that works, not the provider's first", imgs[0].URL)
	}
	if len(is.asks) != 1 || is.asks[0] < minCandidates {
		t.Fatalf("asked the provider for %v candidates", is.asks)
	}
	if st.failed != 2 || st.reasons[imageBlocked] != 1 || st.reasons[imageFormat] != 1 {
		t.Fatalf("stats %+v", st)
	}
	m := toolMetric("image_search", 1, toolOutcome{ran: true, istats: &st, images: imgs}, 5)
	if m.Reasons[imageBlocked] != 1 || m.Reasons[imageFormat] != 1 || m.Failed != 2 || m.Images != 1 {
		t.Fatalf("metric %+v", m)
	}
	if d := reqFacts.Data(); d.Images == nil || d.Images.Failed != 2 || d.Images.Reasons[imageBlocked] != 1 {
		t.Fatalf("record %+v", d.Images)
	}
}

// A late image search's metric waits for its tail: it counts the late images, the late failures, and the slots that
// stayed empty as never_arrived; the empty slots are on the task's background record too.
func TestImageSearchLateMetricCountsNeverArrived(t *testing.T) {
	evs, _ := imageRun(t, []int{0, 30000, 30000}, 3)
	var m *proto.Metric
	for _, e := range evs {
		if e.Type == "metrics" && e.Metrics != nil && e.Metrics.Kind == "images" {
			m = e.Metrics
		}
	}
	if m == nil {
		t.Fatalf("no images metric: %s", types(evs))
	}
	if m.Images != 1 || m.Reasons[imageNever] != 2 {
		t.Fatalf("metric %+v", m)
	}
	b, _ := json.Marshal(m)
	if strings.Contains(string(b), "http") || strings.Contains(string(b), "127.0.0.1") || strings.Contains(string(b), "Poster") {
		t.Fatalf("metric carries content: %s", b)
	}
	// The metric comes after the tool result (it waited for the tail) and before done.
	res, met := -1, -1
	for i, e := range evs {
		if e.Type == "tool_result" {
			res = i
		}
		if e.Type == "metrics" && e.Metrics.Kind == "images" {
			met = i
		}
	}
	if met < res {
		t.Fatalf("metric at %d, result at %d", met, res)
	}
}

func TestLateMetric(t *testing.T) {
	m := &proto.Metric{Kind: "images", Images: 1, Tried: 2, Failed: 1, Reasons: map[string]int{imageBlocked: 1}}
	lateMetric(m, imageStats{tried: 2, failed: 1, bytes: 10, reasons: map[string]int{imageTimeout: 1}}, 1, 1)
	if m.Images != 2 || m.Tried != 4 || m.Failed != 2 || m.Bytes != 10 ||
		m.Reasons[imageBlocked] != 1 || m.Reasons[imageTimeout] != 1 || m.Reasons[imageNever] != 1 {
		t.Fatalf("%+v", m)
	}
	lateMetric(nil, imageStats{}, 0, 3) // no metric: nothing to do
}

// The model gets pictures as "picture" numbers, never "n" (a source's number): citing a picture as [n] cited a
// search result. Its instructions say one number per bracket and only numbers sources gave.
func TestImageResultNumbersArePictures(t *testing.T) {
	a, fm, _, _ := newImageAgent(t, toolCallSSE("c1", "web_images", `{"query":"Arrival poster","count":2}`), textSSE("Here."))
	evs := collect(t, a, proto.RunRequest{Space: testSpace, Permissions: AllowAll(), Messages: []proto.Message{{Role: "user", Content: "posters"}}})
	for _, e := range evs {
		if e.Type == "tool_result" && (!strings.Contains(string(e.Result), `"picture":1`) || strings.Contains(string(e.Result), `"n":`) ||
			!strings.Contains(string(e.Result), "never cite a picture")) {
			t.Fatalf("result %s", e.Result)
		}
	}
	sys := fm.requests[0]["messages"].([]any)[0].(map[string]any)["content"].(string)
	if !strings.Contains(sys, "never [2, 5]") || !strings.Contains(sys, "image search's pictures aren't sources") {
		t.Fatalf("instructions: %s", sys)
	}
}
