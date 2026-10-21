package labexa

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeExa answers every request as Exa would, costing cost a search; it counts what reached it.
type fakeExa struct {
	n    atomic.Int64
	cost string // costDollars.total as JSON; "" leaves costDollars out
	code int
}

func (f *fakeExa) RoundTrip(r *http.Request) (*http.Response, error) {
	f.n.Add(1)
	if r.Body != nil {
		io.ReadAll(r.Body)
	}
	body := `{"results":[{"title":"t","url":"https://example.com/"}]`
	if f.cost != "" {
		body += `,"costDollars":{"total":` + f.cost + `,"search":{"neural":` + f.cost + `}}`
	}
	body += "}"
	code := f.code
	if code == 0 {
		code = 200
	}
	return &http.Response{StatusCode: code, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
}

func search(t *testing.T, tr http.RoundTripper, q string) (*http.Response, error) {
	t.Helper()
	req, _ := http.NewRequest("POST", "https://api.exa.ai/search", strings.NewReader(`{"query":"`+q+`","numResults":5}`))
	req.Header.Set("x-api-key", "lab-key-never-kept")
	return tr.RoundTrip(req)
}

func opts(t *testing.T) Options {
	dir := t.TempDir()
	return Options{CacheDir: filepath.Join(dir, "cache"), Ledger: filepath.Join(dir, "spend.json"), DailyCap: 4, RunCap: 1, Label: "test"}
}

// A search seen before replays at $0; the real cost (costDollars) is what the ledger gets; the key isn't kept.
func TestReplayAndRealCost(t *testing.T) {
	f := &fakeExa{cost: "0.007"}
	o := opts(t)
	tr := New(f, o)
	for i := 0; i < 2; i++ {
		res, err := search(t, tr, "go release")
		if err != nil {
			t.Fatal(err)
		}
		want := map[int]string{0: "live", 1: "replayed"}[i]
		if got := res.Header.Get(HeaderSource); got != want {
			t.Fatalf("search %d: %s, want %s", i, got, want)
		}
		if b, _ := io.ReadAll(res.Body); !strings.Contains(string(b), "example.com") {
			t.Fatalf("search %d: body %q", i, b)
		}
	}
	if f.n.Load() != 1 {
		t.Fatalf("%d searches reached Exa, want 1", f.n.Load())
	}
	s := tr.Stats()
	if s.Live != 1 || s.Replayed != 1 || fmt.Sprintf("%.4f", s.RunUSD) != "0.0070" || fmt.Sprintf("%.4f", s.TodayUSD) != "0.0070" {
		t.Fatalf("stats %+v", s)
	}
	// Another run (process) replays it too, and adds to the same day.
	tr2 := New(f, o)
	search(t, tr2, "go release")
	search(t, tr2, "other")
	if s := tr2.Stats(); s.Live != 1 || s.Replayed != 1 || fmt.Sprintf("%.4f", s.TodayUSD) != "0.0140" {
		t.Fatalf("second run %+v", s)
	}
	filepath.Walk(o.CacheDir, func(p string, _ os.FileInfo, _ error) error {
		if b, _ := os.ReadFile(p); strings.Contains(string(b), "lab-key") {
			t.Fatalf("%s holds the key", p)
		}
		return nil
	})
	// EXA_LAB_LIVE: the cache is skipped.
	o.Live = true
	tr3 := New(f, o)
	if res, _ := search(t, tr3, "go release"); res.Header.Get(HeaderSource) != "live" {
		t.Fatal("live: replayed")
	}
}

// The daily cap: a search that would pass it is refused before it leaves, with ErrCap, once to OnCap.
func TestDailyCap(t *testing.T) {
	f := &fakeExa{cost: "0.007"}
	o := opts(t)
	o.DailyCap = 0.025 // two searches (each reserved at $0.01) fit, the third doesn't
	var heard atomic.Int64
	o.OnCap = func(error) { heard.Add(1) }
	tr := New(f, o)
	for i := 0; i < 3; i++ {
		search(t, tr, fmt.Sprint("q", i))
	}
	_, err := search(t, tr, "q3")
	if !errors.Is(err, ErrCap) || !strings.Contains(err.Error(), "daily cap") {
		t.Fatalf("err %v", err)
	}
	if f.n.Load() != 3 {
		// 0.007 + 0.007 = 0.014; the third reserves 0.024 <= 0.025, so it runs; the fourth would be 0.031.
		t.Fatalf("%d reached Exa, want 3", f.n.Load())
	}
	// A replay still works under the cap.
	if res, err := search(t, tr, "q0"); err != nil || res.Header.Get(HeaderSource) != "replayed" {
		t.Fatalf("replay under the cap: %v", err)
	}
	time.Sleep(50 * time.Millisecond)
	if heard.Load() != 1 || tr.Stats().Capped == "" {
		t.Fatalf("OnCap heard %d, stats %+v", heard.Load(), tr.Stats())
	}
	// Another run the same day is refused at once.
	if _, err := search(t, New(f, o), "q9"); !errors.Is(err, ErrCap) {
		t.Fatalf("second run: %v", err)
	}
}

func TestRunCap(t *testing.T) {
	f := &fakeExa{cost: "0.007"}
	o := opts(t)
	o.RunCap = 0.015
	tr := New(f, o)
	search(t, tr, "a")
	if _, err := search(t, tr, "b"); !errors.Is(err, ErrCap) || !strings.Contains(err.Error(), "run") {
		t.Fatalf("err %v", err)
	}
	// A new run has its own run cap; the day goes on.
	if _, err := search(t, New(f, o), "c"); err != nil {
		t.Fatal(err)
	}
}

// No costDollars: charged at the estimate. An error status: nothing charged, nothing kept.
func TestUnknownCostAndErrors(t *testing.T) {
	o := opts(t)
	tr := New(&fakeExa{}, o)
	search(t, tr, "a")
	if s := tr.Stats(); fmt.Sprintf("%.3f", s.RunUSD) != "0.010" {
		t.Fatalf("no costDollars: %+v", s)
	}
	f := &fakeExa{code: 402}
	tr2 := New(f, o)
	search(t, tr2, "b")
	search(t, tr2, "b")
	if f.n.Load() != 2 || tr2.Stats().RunUSD != 0 {
		t.Fatalf("402: %d calls, %+v", f.n.Load(), tr2.Stats())
	}
}

// Overlapping runs add up in the one ledger (the file lock).
func TestConcurrentLedger(t *testing.T) {
	o := opts(t)
	f := &fakeExa{cost: "0.005"}
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			search(t, New(f, o), fmt.Sprint("c", i))
		}()
	}
	wg.Wait()
	if got := fmt.Sprintf("%.3f", Today(o.Ledger)); got != "0.100" {
		t.Fatalf("today %s, want 0.100", got)
	}
}

// Other hosts pass through untouched.
func TestOtherHosts(t *testing.T) {
	f := &fakeExa{cost: "1"}
	tr := New(f, opts(t))
	req, _ := http.NewRequest("GET", "https://example.com/", nil)
	if _, err := tr.RoundTrip(req); err != nil || tr.Stats().Live != 0 {
		t.Fatalf("%v %+v", err, tr.Stats())
	}
}
