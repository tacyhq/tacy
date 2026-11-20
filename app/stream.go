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

// eventStream writes a run's SSE events and, between them, a keepalive whenever nothing was written for a whole
// interval. Writes are batched (proto.StreamBatch: what comes within 50 ms goes out together) and each batch is
// padded to a multiple of proto.StreamBucket bytes (proto.PadSSE): one encrypted EHBP chunk, flushed. What carries
// the stream sees bucket-sized chunks at most every 50 ms, not each token's length (the keys plan §3.4, PX-3). The EHBP
// writer isn't safe for concurrent use (each chunk has a sequence number), so every send holds mu.
type eventStream struct {
	mu      sync.Mutex
	w       io.Writer
	flusher http.Flusher
	batch   time.Duration
	buf     []byte      // written, not yet sent
	timer   *time.Timer // sends buf when it fires; nil: none set
	direct  bool        // stopped: a write goes out at once, from its caller (no timer runs after the handler)
	err     error       // a send failed: the reader is gone
	last    time.Time   // the last write (queued or sent): keepalives are for a quiet stream
	closed  bool
	quit    chan struct{}
	exited  chan struct{}
	once    sync.Once
}

func newEventStream(w http.ResponseWriter, every time.Duration) *eventStream {
	s := &eventStream{w: w, last: time.Now(), batch: proto.StreamBatch, quit: make(chan struct{}), exited: make(chan struct{})}
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

// write queues line for the next batch. An error says an earlier batch couldn't be sent (the reader is gone).
func (s *eventStream) write(line string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return io.ErrClosedPipe
	}
	if s.err != nil {
		return s.err
	}
	s.buf = append(s.buf, line...)
	s.last = time.Now()
	if s.direct {
		return s.sendLocked()
	}
	if s.timer == nil {
		s.timer = time.AfterFunc(s.batch, s.sendBatch)
	}
	return nil
}

// sendBatch is the batch timer: whatever was written since the last batch goes out.
func (s *eventStream) sendBatch() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.timer = nil
	if !s.direct {
		s.sendLocked()
	}
}

// sendLocked sends buf as one padded chunk and flushes it.
func (s *eventStream) sendLocked() error {
	if len(s.buf) == 0 || s.err != nil {
		return s.err
	}
	out := proto.PadSSE(s.buf)
	s.buf = s.buf[:0]
	if _, err := s.w.Write(out); err != nil {
		s.err = err
		return err
	}
	if s.flusher != nil {
		s.flusher.Flush()
	}
	return nil
}

// emit writes one event.
func (s *eventStream) emit(e proto.Event) error {
	b, _ := json.Marshal(e)
	return s.write(fmt.Sprintf("data: %s\n\n", b))
}

// done ends the stream with [DONE], sent at once with whatever is still queued; nothing is written after it. An
// error says it couldn't be written (the reader is gone).
func (s *eventStream) done() error {
	s.halt()
	defer s.mu.Unlock()
	if s.closed {
		return io.ErrClosedPipe
	}
	s.closed = true
	if s.err != nil {
		return s.err
	}
	s.buf = append(s.buf, "data: [DONE]\n\n"...)
	return s.sendLocked() // with what was queued: one chunk
}

// stop ends the keepalives and the batch timer and sends what's queued (the handler must not write after it
// returns: from here a write goes out at once, from its caller).
func (s *eventStream) stop() {
	s.halt()
	defer s.mu.Unlock()
	if !s.closed {
		s.sendLocked()
	}
}

// halt ends the keepalives and the batch timer and returns holding mu; writes go out at once from here.
func (s *eventStream) halt() {
	s.once.Do(func() { close(s.quit) })
	<-s.exited
	s.mu.Lock()
	if s.timer != nil {
		s.timer.Stop()
		s.timer = nil
	}
	s.direct = true
}
