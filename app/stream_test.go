package main

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tacyhq/tacy/proto"
)

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
	if !strings.HasSuffix(body, "data: {\"type\":\"step\",\"step\":1}\n\ndata: [DONE]\n\n") {
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
