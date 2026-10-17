package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	ehbpidentity "github.com/tinfoilsh/encrypted-http-body-protocol/identity"

	"github.com/tacyhq/tacy/agentclient"
	"github.com/tacyhq/tacy/guard"
	"github.com/tacyhq/tacy/proto"
)

func testLimits() Limits {
	l := defaultLimits
	l.MaxRuns, l.MaxQueue, l.UserRuns, l.UserQueue = 2, 3, 3, 3
	return l
}

func granted(t *ticket) bool {
	select {
	case <-t.ready:
		return true
	default:
		return false
	}
}

func TestSchedulerSlotsAndQueue(t *testing.T) {
	s := newScheduler(testLimits())
	a, _ := s.admit("u1")
	b, _ := s.admit("u2")
	if !granted(a) || !granted(b) || a.runningAtStart != 1 || b.runningAtStart != 2 {
		t.Fatal("first two runs should start at once")
	}
	c, _ := s.admit("u3")
	d, _ := s.admit("u4")
	e, _ := s.admit("u5")
	if granted(c) || c.position() != 1 || d.position() != 2 || e.position() != 3 {
		t.Fatalf("queue positions %d %d %d", c.position(), d.position(), e.position())
	}
	if _, err := s.admit("u6"); !errors.Is(err, errQueueFull) {
		t.Fatalf("full queue: %v", err)
	}
	// Leaving the queue moves the others up; a freed slot goes to the oldest waiting run.
	d.release()
	if e.position() != 2 {
		t.Fatalf("after a queued run left: %d", e.position())
	}
	a.release()
	if !granted(c) || c.position() != 0 || e.position() != 1 || c.runningAtStart != 2 {
		t.Fatal("freed slot didn't go to the oldest queued run")
	}
	a.release() // twice is harmless
	if running, queued := s.stats(); running != 2 || queued != 1 {
		t.Fatalf("stats %d %d", running, queued)
	}
	b.release()
	c.release()
	e.release()
	if running, queued := s.stats(); running != 0 || queued != 0 || len(s.users) != 0 {
		t.Fatalf("not empty after all released: %d %d %v", running, queued, s.users)
	}
}

// One user can't take every slot: past UserRuns their runs queue (and past UserQueue they're refused) while
// other users' runs still start at once, even if they arrived later.
func TestSchedulerPerUserFairness(t *testing.T) {
	l := testLimits()
	l.MaxRuns, l.MaxQueue, l.UserRuns, l.UserQueue = 4, 10, 2, 1
	s := newScheduler(l)
	h1, _ := s.admit("hog")
	h2, _ := s.admit("hog")
	h3, err := s.admit("hog")
	if err != nil || granted(h3) || h3.position() != 1 {
		t.Fatalf("third run of one user should queue: %v", err)
	}
	if _, err := s.admit("hog"); !errors.Is(err, errUserQueueFull) {
		t.Fatalf("per-user queue: %v", err)
	}
	// Two free slots remain for others, though hog's run is queued ahead.
	o1, _ := s.admit("other")
	if !granted(o1) {
		t.Fatal("another user's run should start in a free slot")
	}
	o2, _ := s.admit("other2")
	if !granted(o2) {
		t.Fatal("another user's run should start in a free slot")
	}
	// All four slots busy: a new user queues behind hog's run.
	o3, _ := s.admit("other3")
	if granted(o3) || o3.position() != 2 {
		t.Fatalf("position %d", o3.position())
	}
	// A slot frees from another user: hog is still at its cap, so other3 (behind it) gets it.
	o1.release()
	if granted(h3) || !granted(o3) {
		t.Fatal("capped user's queued run should be skipped, not block others")
	}
	// One of hog's own runs ends: now its queued run fits... once a slot is free.
	h1.release()
	if !granted(h3) {
		t.Fatal("hog's queued run should start when its own run ends")
	}
	for _, x := range []*ticket{h2, h3, o2, o3} {
		x.release()
	}
	if len(s.users) != 0 {
		t.Fatalf("users left: %v", s.users)
	}
}

func TestTicketWait(t *testing.T) {
	l := testLimits()
	l.MaxRuns = 1
	s := newScheduler(l)
	a, _ := s.admit("a")
	if err := a.wait(context.Background(), time.Second, time.Second, func(int) error { t.Fatal("no position for a running ticket"); return nil }); err != nil {
		t.Fatal(err)
	}
	b, _ := s.admit("b")
	c, _ := s.admit("c")
	// c sees position 2, then 1 when b leaves, then starts when a ends.
	var mu sync.Mutex
	var seen []int
	errc := make(chan error, 1)
	go func() {
		errc <- c.wait(context.Background(), 5*time.Second, time.Hour, func(p int) error {
			mu.Lock()
			seen = append(seen, p)
			mu.Unlock()
			return nil
		})
	}()
	time.Sleep(100 * time.Millisecond)
	b.release()
	time.Sleep(700 * time.Millisecond)
	a.release()
	if err := <-errc; err != nil || c.waited < 700*time.Millisecond {
		t.Fatalf("wait: %v, waited %v", err, c.waited)
	}
	mu.Lock()
	if fmt.Sprint(seen) != "[2 1]" {
		t.Fatalf("positions %v", seen)
	}
	mu.Unlock()
	// Timeout: d waits behind c and gives up.
	d, _ := s.admit("d")
	t0 := time.Now()
	if err := d.wait(context.Background(), 200*time.Millisecond, time.Hour, func(int) error { return nil }); !errors.Is(err, errQueueTimeout) || time.Since(t0) > time.Second {
		t.Fatalf("timeout: %v", err)
	}
	d.release()
	c.release()
	if running, queued := s.stats(); running != 0 || queued != 0 {
		t.Fatal("not empty")
	}
}

// blockingModel holds every model request until release is closed.
type blockingModel struct {
	release chan struct{}
	started atomic.Int32
}

func (b *blockingModel) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	io.Copy(io.Discard, r.Body)
	b.started.Add(1)
	<-b.release
	w.Header().Set("Content-Type", "text/event-stream")
	io.WriteString(w, textSSE("answer"))
}

// Over HTTP with EHBP: with the only slot busy, a second run gets encrypted queue events, then runs (with the
// queue metric); a run past the queue gets a plaintext 429 queue_full; one past its user's queue gets
// user_queue_full; a run that waits too long ends with a queue_timeout error event.
func TestQueueOverEHBP(t *testing.T) {
	bm := &blockingModel{release: make(chan struct{})}
	model := httptest.NewServer(bm)
	defer model.Close()
	a, _, _ := newTestAgent(t)
	a.use(guard.NewPlainUpstream(model.URL, model.Client()))
	lim := defaultLimits
	lim.MaxRuns, lim.MaxQueue, lim.UserRuns, lim.UserQueue, lim.QueueTimeout = 1, 2, 1, 1, 3*time.Second
	id, _ := ehbpidentity.NewIdentity()
	s := newTestServer(t, a, id, lim)
	mux := http.NewServeMux()
	mux.Handle("POST /run", s.guard(id.Middleware()(http.HandlerFunc(s.run))))
	srv := httptest.NewServer(mux)
	defer srv.Close()

	run := func(user string, on func(proto.Event)) error {
		conn, _ := agentclient.New(srv.URL, "tok", id.MarshalPublicKey())
		conn.User = user
		return conn.Run(context.Background(), proto.RunRequest{Messages: []proto.Message{{Role: "user", Content: "secret prompt"}}}, on)
	}
	type result struct {
		evs []proto.Event
		err error
	}
	first := make(chan result, 1)
	go func() {
		var evs []proto.Event
		err := run("aaaaaaaaaaaaaaaa", func(e proto.Event) { evs = append(evs, e) })
		first <- result{evs, err}
	}()
	for bm.started.Load() == 0 {
		time.Sleep(10 * time.Millisecond)
	}
	second := make(chan result, 1)
	sawQueue := make(chan struct{})
	go func() {
		var evs []proto.Event
		var once sync.Once
		err := run("bbbbbbbbbbbbbbbb", func(e proto.Event) {
			evs = append(evs, e)
			if e.Type == "queue" {
				once.Do(func() { close(sawQueue) })
			}
		})
		second <- result{evs, err}
	}()
	<-sawQueue
	// The same user as the queued run, past its per-user queue (1): refused.
	if err := run("bbbbbbbbbbbbbbbb", func(proto.Event) {}); err == nil || !strings.Contains(err.Error(), "429") || !strings.Contains(err.Error(), "user_queue_full") {
		t.Fatalf("per-user queue: %v", err)
	}
	// Another user fills the queue (2); the next is refused.
	third := make(chan result, 1)
	go func() {
		var evs []proto.Event
		err := run("cccccccccccccccc", func(e proto.Event) { evs = append(evs, e) })
		third <- result{evs, err}
	}()
	for _, q := s.sched.stats(); q < 2; _, q = s.sched.stats() {
		time.Sleep(10 * time.Millisecond)
	}
	if err := run("dddddddddddddddd", func(proto.Event) {}); err == nil || !strings.Contains(err.Error(), "queue_full") {
		t.Fatalf("full queue: %v", err)
	}
	// A bad tag is refused before anything else.
	if err := run("Not-Hex!", func(proto.Event) {}); err == nil || !strings.Contains(err.Error(), "bad_user_tag") {
		t.Fatalf("bad tag: %v", err)
	}
	time.Sleep(600 * time.Millisecond)
	close(bm.release)
	r1, r2, r3 := <-first, <-second, <-third
	if r1.err != nil || r2.err != nil || r3.err != nil {
		t.Fatalf("runs: %v %v %v", r1.err, r2.err, r3.err)
	}
	if got := types(r2.evs); !strings.HasPrefix(got, "queue,") || !strings.Contains(got, "queue,metrics,meta,step") {
		t.Fatalf("queued run events %s", got)
	}
	if r2.evs[0].Position != 1 {
		t.Fatalf("position %d", r2.evs[0].Position)
	}
	var qm *proto.Metric
	for _, e := range r2.evs {
		if e.Type == "metrics" && e.Metrics.Kind == "queue" {
			qm = e.Metrics
		}
	}
	if qm == nil || qm.Ms < 500 || qm.Running != 1 {
		t.Fatalf("queue metric %+v", qm)
	}
	if got := types(r1.evs); !strings.HasPrefix(got, "metrics,meta") || r1.evs[0].Metrics.Ms > 100 || r1.evs[0].Metrics.Running != 1 {
		t.Fatalf("first run events %s %+v", got, r1.evs[0].Metrics)
	}

	// Queue timeout: hold the slot, the next run gives up with an error event.
	bm2 := &blockingModel{release: make(chan struct{})}
	model2 := httptest.NewServer(bm2)
	defer model2.Close()
	a.use(guard.NewPlainUpstream(model2.URL, model2.Client()))
	s.lim.QueueTimeout = 300 * time.Millisecond
	go run("aaaaaaaaaaaaaaaa", func(proto.Event) {})
	for bm2.started.Load() == 0 {
		time.Sleep(10 * time.Millisecond)
	}
	var evs []proto.Event
	err := run("bbbbbbbbbbbbbbbb", func(e proto.Event) { evs = append(evs, e) })
	close(bm2.release)
	if err != nil || types(evs) != "queue,error" || !strings.HasPrefix(evs[1].Error, "queue_timeout") {
		t.Fatalf("timeout: %v %s %+v", err, types(evs), evs)
	}
}
