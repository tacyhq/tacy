package main

import (
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tacyhq/tacy/proto"
)

// unpadded is an SSE body without its padding comments (lines of ":" and spaces).
func unpadded(body string) string {
	var b strings.Builder
	for _, ev := range strings.SplitAfter(body, "\n\n") {
		if strings.HasPrefix(ev, ":") && strings.TrimSpace(strings.TrimPrefix(ev, ":")) == "" {
			continue
		}
		b.WriteString(ev)
	}
	return b.String()
}

// A run's stream carries a keepalive right away and whenever nothing else was written for an interval, so the
// chat can tell a quiet run (a slow page) from one whose VM went away. Nothing follows [DONE].
func TestEventStreamKeepalive(t *testing.T) {
	rec := httptest.NewRecorder()
	s := newEventStream(rec, 40*time.Millisecond)
	time.Sleep(130 * time.Millisecond) // quiet: keepalives
	if err := s.emit(proto.Event{Type: "step", Step: 1}); err != nil {
		t.Fatal(err)
	}
	s.done()
	body := rec.Body.String()
	if !strings.HasPrefix(body, keepaliveLine) {
		t.Fatalf("the stream doesn't start with a keepalive: %q", body)
	}
	if n := strings.Count(body, keepaliveLine); n < 3 {
		t.Fatalf("%d keepalives in 130 ms at 40 ms, want at least 3: %q", n, body)
	}
	if !strings.HasSuffix(unpadded(body), "data: {\"type\":\"step\",\"step\":1}\n\ndata: [DONE]\n\n") {
		t.Fatalf("the stream doesn't end with the event and [DONE]: %q", body)
	}
	time.Sleep(100 * time.Millisecond)
	if rec.Body.String() != body {
		t.Fatal("something was written after [DONE]")
	}
	if s.emit(proto.Event{Type: "step", Step: 2}) == nil {
		t.Fatal("an event was accepted after [DONE]")
	}
	s.stop() // the handler's deferred stop after done is fine
}

// Events written often enough leave no room for keepalives (they're only for quiet streams).
func TestEventStreamBusyNoKeepalive(t *testing.T) {
	rec := httptest.NewRecorder()
	s := newEventStream(rec, 80*time.Millisecond)
	for i := range 10 {
		s.emit(proto.Event{Type: "step", Step: i + 1})
		time.Sleep(10 * time.Millisecond)
	}
	s.stop()
	if n := strings.Count(rec.Body.String(), keepaliveLine); n != 1 {
		t.Fatalf("%d keepalives in a busy stream, want only the first", n)
	}
}

// sizes records each Write's size (one EHBP chunk each, behind the EHBP writer).
type sizes struct {
	*httptest.ResponseRecorder
	mu sync.Mutex
	n  []int
	at []time.Time
}

func (s *sizes) Write(b []byte) (int, error) {
	s.mu.Lock()
	s.n, s.at = append(s.n, len(b)), append(s.at, time.Now())
	s.mu.Unlock()
	return s.ResponseRecorder.Write(b)
}

// Padding (the keys plan §3.4): token deltas written one by one go out in batches, at most one per 50 ms, each a multiple
// of 512 bytes, so the carrier sees neither each token's length nor when each came.
func TestEventStreamPaddedBatches(t *testing.T) {
	w := &sizes{ResponseRecorder: httptest.NewRecorder()}
	s := newEventStream(w, time.Minute)
	words := strings.Fields("the answer is a short one but its tokens all differ in length, which the sizes would show")
	for i := range 60 {
		s.emit(proto.Event{Type: "delta", Delta: words[i%len(words)] + " "})
		time.Sleep(2 * time.Millisecond)
	}
	s.done()
	w.mu.Lock()
	defer w.mu.Unlock()
	for i, n := range w.n {
		if n%proto.StreamBucket != 0 {
			t.Fatalf("write %d: %d bytes, not a multiple of %d", i, n, proto.StreamBucket)
		}
	}
	// 60 deltas over about 120 ms (more under load): a handful of batches, not 60 writes.
	if len(w.n) > 8 {
		t.Fatalf("%d writes for 60 deltas: not batched (%v)", len(w.n), w.n)
	}
	for i := 1; i < len(w.n)-1; i++ { // the last one is [DONE], sent at once
		if gap := w.at[i].Sub(w.at[i-1]); gap < proto.StreamBatch-5*time.Millisecond {
			t.Fatalf("batches %d and %d %v apart, want at least %v (%v %v)", i-1, i, gap, proto.StreamBatch, w.n, w.at)
		}
	}
	body := unpadded(w.Body.String())
	if strings.Count(body, `"type":"delta"`) != 60 || !strings.HasSuffix(body, "data: [DONE]\n\n") {
		t.Fatalf("events lost: %q", body)
	}
}

// A whole answer (writeJSON) is padded to its size class and still parses.
func TestWriteJSONPadded(t *testing.T) {
	for _, n := range []int{1, 700, 5000} {
		rec := httptest.NewRecorder()
		writeJSON(rec, 200, map[string]string{"x": strings.Repeat("y", n)})
		if got := rec.Body.Len(); got != proto.PadPow2(got, proto.AnswerMin, proto.AnswerMax) {
			t.Fatalf("n=%d: %d bytes isn't a size class", n, got)
		}
	}
	a, b := httptest.NewRecorder(), httptest.NewRecorder()
	fail(a, 403, "no")
	fail(b, 403, "not_holder: a much longer reason than the other one")
	if a.Body.Len() != b.Body.Len() {
		t.Fatalf("%d != %d", a.Body.Len(), b.Body.Len())
	}
}
