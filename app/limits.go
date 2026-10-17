package main

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/tacyhq/tacy/guard"
)

// The run slots and the bounded queue in front of POST /run (guard.Limits: MaxRuns, MaxQueue, QueueTimeout,
// UserRuns, UserQueue). The tool caps are the guard's.

// Limits and defaultLimits are the guard's (one set of flags for both).
type Limits = guard.Limits

var defaultLimits = guard.DefaultLimits

var (
	errQueueFull     = errors.New("queue_full")
	errUserQueueFull = errors.New("user_queue_full")
	errQueueTimeout  = errors.New("queue_timeout")
)

// ---- runs: slots and a bounded FIFO queue -----------------------------------------------------------------

// scheduler admits runs: a free slot right away, else a place in the queue, else a refusal. A queued run starts
// when a slot frees, in arrival order, skipping runs whose user already has UserRuns running (they wait for one
// of their own runs to end, without blocking other users).
type scheduler struct {
	mu      sync.Mutex
	lim     Limits
	running int
	users   map[string]*userRuns
	queue   []*ticket
	now     func() time.Time
}

type userRuns struct{ running, queued int }

// ticket is one admitted run: running (granted) or waiting in the queue.
type ticket struct {
	s        *scheduler
	user     string
	ready    chan struct{} // closed when granted
	granted  bool
	released bool
	enqueued time.Time
	waited   time.Duration // time in the queue (0 when it started at once)
	// RunningAtStart is how many runs were running when this one started, itself included.
	runningAtStart int
}

func newScheduler(lim Limits) *scheduler {
	return &scheduler{lim: lim, users: map[string]*userRuns{}, now: time.Now}
}

// admit returns a ticket (granted, or queued) or errQueueFull / errUserQueueFull.
func (s *scheduler) admit(user string) (*ticket, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	u := s.users[user]
	if u == nil {
		u = &userRuns{}
		s.users[user] = u
	}
	t := &ticket{s: s, user: user, ready: make(chan struct{}), enqueued: s.now()}
	// dispatch runs after every change, so a free slot here means no queued run could take it.
	if s.running < s.lim.MaxRuns && u.running < s.lim.UserRuns {
		s.grant(t, u)
		return t, nil
	}
	var err error
	switch {
	case len(s.queue) >= s.lim.MaxQueue:
		err = errQueueFull
	case u.queued >= s.lim.UserQueue:
		err = errUserQueueFull
	}
	if err != nil {
		s.dropIfIdle(user, u)
		return nil, err
	}
	u.queued++
	s.queue = append(s.queue, t)
	return t, nil
}

func (s *scheduler) grant(t *ticket, u *userRuns) {
	s.running++
	u.running++
	t.granted = true
	t.waited = s.now().Sub(t.enqueued)
	t.runningAtStart = s.running
	close(t.ready)
}

func (s *scheduler) dropIfIdle(user string, u *userRuns) {
	if u.running == 0 && u.queued == 0 {
		delete(s.users, user)
	}
}

// dispatch starts queued runs while slots are free (s.mu held).
func (s *scheduler) dispatch() {
	for i := 0; i < len(s.queue) && s.running < s.lim.MaxRuns; {
		t := s.queue[i]
		u := s.users[t.user]
		if u.running >= s.lim.UserRuns {
			i++
			continue
		}
		s.queue = append(s.queue[:i], s.queue[i+1:]...)
		u.queued--
		s.grant(t, u)
	}
}

// release ends a ticket: frees its slot or leaves the queue. Safe to call more than once.
func (t *ticket) release() {
	s := t.s
	s.mu.Lock()
	defer s.mu.Unlock()
	if t.released {
		return
	}
	t.released = true
	u := s.users[t.user]
	if t.granted {
		s.running--
		u.running--
	} else {
		for i, q := range s.queue {
			if q == t {
				s.queue = append(s.queue[:i], s.queue[i+1:]...)
				break
			}
		}
		u.queued--
	}
	s.dropIfIdle(t.user, u)
	s.dispatch()
}

// position is the ticket's place in the queue (1 = next), or 0 once it runs.
func (t *ticket) position() int {
	t.s.mu.Lock()
	defer t.s.mu.Unlock()
	if t.granted {
		return 0
	}
	for i, q := range t.s.queue {
		if q == t {
			return i + 1
		}
	}
	return 0
}

// wait blocks until the ticket runs. While queued it calls onPosition with the position at once, whenever it
// changes, and every keepalive (so proxies don't close an idle stream). It gives up after timeout
// (errQueueTimeout) or when ctx ends.
func (t *ticket) wait(ctx context.Context, timeout, keepalive time.Duration, onPosition func(int) error) error {
	select {
	case <-t.ready:
		return nil
	default:
	}
	last := t.position()
	if last == 0 {
		<-t.ready
		return nil
	}
	if err := onPosition(last); err != nil {
		return err
	}
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	tick := time.NewTicker(500 * time.Millisecond)
	defer tick.Stop()
	sent := time.Now()
	for {
		select {
		case <-t.ready:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			select {
			case <-t.ready: // granted just now
				return nil
			default:
				return errQueueTimeout
			}
		case <-tick.C:
			p := t.position()
			if p == 0 {
				continue // granted: ready is closed
			}
			if p != last || time.Since(sent) >= keepalive {
				last, sent = p, time.Now()
				if err := onPosition(p); err != nil {
					return err
				}
			}
		}
	}
}

// stats: runs running and queued now.
func (s *scheduler) stats() (running, queued int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.running, len(s.queue)
}
