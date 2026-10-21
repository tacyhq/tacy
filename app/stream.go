package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/tacyhq/tacy/proto"
)

// keepaliveEvery is how often a run's stream carries a keepalive when nothing else was written. When the VM
// restarts mid-run (an update), nothing closes the browser's connection: Phala's gateway and Cloudflare keep it
// open, silent, until a timeout about 53 s later. With a keepalive every 2 s the chat knows within a few seconds
// (the chat's events.ts: a stream that has carried keepalives and then goes quiet for 6 s is treated as cut).
const keepaliveEvery = 2 * time.Second

// keepaliveLine is an SSE comment: every reader skips it (the chat's events.ts, agentclient, jscheck). It is
// written inside the EHBP-encrypted body like everything else, so only the verified browser sees it, and it says
// nothing but "still here" (one fixed line, sent on a fixed timer whatever the run is doing).
const keepaliveLine = ": keepalive\n\n"

// eventStream writes a run's SSE events (each one encrypted EHBP chunk, flushed) and, between them, a keepalive
// whenever nothing was written for a whole interval. The EHBP writer isn't safe for concurrent use (each chunk
// has a sequence number), so every write holds mu.
type eventStream struct {
	mu      sync.Mutex
	w       io.Writer
	flusher http.Flusher
	last    time.Time
	closed  bool
	quit    chan struct{}
	exited  chan struct{}
	once    sync.Once
}

func newEventStream(w http.ResponseWriter, every time.Duration) *eventStream {
	s := &eventStream{w: w, last: time.Now(), quit: make(chan struct{}), exited: make(chan struct{})}
	s.flusher, _ = w.(http.Flusher)
	s.write(keepaliveLine) // first: tells the reader this stream carries keepalives
	go s.keepalive(every)
	return s
}

func (s *eventStream) keepalive(every time.Duration) {
	defer close(s.exited)
	tick := time.NewTicker(every / 4)
	defer tick.Stop()
	for {
		select {
		case <-s.quit:
			return
		case <-tick.C:
			s.mu.Lock()
			idle := !s.closed && time.Since(s.last) >= every
			s.mu.Unlock()
			if idle && s.write(keepaliveLine) != nil {
				return // the client went away; the run notices through its context
			}
		}
	}
}

func (s *eventStream) write(line string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return io.ErrClosedPipe
	}
	if _, err := io.WriteString(s.w, line); err != nil {
		return err
	}
	if s.flusher != nil {
		s.flusher.Flush()
	}
	s.last = time.Now()
	return nil
}

// emit writes one event.
func (s *eventStream) emit(e proto.Event) error {
	b, _ := json.Marshal(e)
	return s.write(fmt.Sprintf("data: %s\n\n", b))
}

// done ends the stream with [DONE]; nothing is written after it.
// done ends the stream with [DONE]; an error says it couldn't be written (the reader is gone).
func (s *eventStream) done() error {
	s.stop()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return io.ErrClosedPipe
	}
	s.closed = true
	if _, err := io.WriteString(s.w, "data: [DONE]\n\n"); err != nil {
		return err
	}
	if s.flusher != nil {
		s.flusher.Flush()
	}
	return nil
}

// stop ends the keepalives and waits for them to stop writing (the handler must not write after it returns).
func (s *eventStream) stop() {
	s.once.Do(func() { close(s.quit) })
	<-s.exited
}
