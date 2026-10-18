package gateway

import (
	"context"
	jsonv1 "encoding/json"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/tacyhq/tacy/guard"
	"github.com/tacyhq/tacy/harness"
	"github.com/tacyhq/tacy/proto"
	"github.com/tacyhq/tacy/safety"
)

// Client is agentd's side: a guard.Gateway whose guard is gatewayd, over its socket. The runtime calls it for the
// brain's requests (harness.Guard); Run opens a session per chat run, whose events it relays to the person.
type Client struct {
	Path string           // gatewayd's socket
	Now  func() time.Time // today's date for the chat's instructions; nil: time.Now
	// Wait is how long a request waits for gatewayd to accept a connection (it restarts in about a second);
	// 0: 20 s.
	Wait time.Duration
	// Docs, when set, are the signed policies and stop lists agentd holds: sent with every session's open, so
	// gatewayd has them before it serves a task (it checks each itself).
	Docs func() []safety.Envelope

	mu       sync.Mutex
	sessions map[string]*session // the tasks Run serves, by id
}

var _ guard.Gateway = (*Client)(nil)
var _ harness.ReplayGuard = (*Client)(nil)

// StartFor checks a chat request and makes the task (guard.StartFor: no gateway round trip).
func (c *Client) StartFor(r *proto.RunRequest) (harness.Start, guard.TaskOptions, error) {
	now := time.Now().UTC()
	if c.Now != nil {
		now = c.Now()
	}
	return guard.StartFor(r, now)
}

// Open starts a session for task id: gatewayd's events for it go to emit. Nothing is sent until its first request.
func (c *Client) Open(id string, opts guard.TaskOptions, emit func(proto.Event) error) guard.Session {
	b, _ := jsonv1.Marshal(opts)
	s := &session{c: c, id: id, opts: b, emit: emit}
	c.mu.Lock()
	if c.sessions == nil {
		c.sessions = map[string]*session{}
	}
	c.sessions[id] = s
	c.mu.Unlock()
	return s
}

// PushDocs passes signed policies and stop lists to gatewayd at once (a stop must reach it within seconds), on a
// connection of their own. gatewayd checks each and passes the ones it takes on to the vault.
func (c *Client) PushDocs(ctx context.Context, docs []safety.Envelope) error {
	var d net.Dialer
	nc, err := d.DialContext(ctx, "unix", c.Path)
	if err != nil {
		return err
	}
	defer nc.Close()
	nc.SetDeadline(time.Now().Add(10 * time.Second))
	if err := writeFrame(nc, &frame{T: tSafety, Version: Version, Docs: docs}); err != nil {
		return err
	}
	var f frame
	if err := readFrame(nc, &f); err != nil {
		return err
	}
	if f.T != tResult || f.Err != nil {
		return errors.New("gateway: documents refused")
	}
	return nil
}

// ReplaySafe: as the guard's (it depends on the request only).
func (c *Client) ReplaySafe(_ *harness.TaskInfo, req any) bool { return guard.ReplaySafe(req) }

// Exec: the chat agent has no hands sandbox (the runtime refuses exec before this).
func (c *Client) Exec(context.Context, *harness.TaskInfo, string, *harness.Exec) (*harness.ExecResult, error) {
	return nil, harness.Errf(harness.CodeNotAllowed, "no hands sandbox")
}

func (c *Client) ModelCall(ctx context.Context, ti *harness.TaskInfo, req *harness.ModelCall) (*harness.ModelResult, error) {
	s, done := c.sessionFor(ti.ID)
	defer done()
	r, err := s.call(ctx, ti, &frame{T: tModel, ID: harness.RequestID(ctx), Model: req, MaxTokens: guard.MaxTokensFrom(ctx)})
	if err != nil {
		return nil, err
	}
	if r.ModelResult == nil {
		return nil, harness.Errf(harness.CodeInternal, "bad result from the gateway")
	}
	return r.ModelResult, nil
}

func (c *Client) Action(ctx context.Context, ti *harness.TaskInfo, id string, req *harness.Action) (*harness.ActionResult, error) {
	s, done := c.sessionFor(ti.ID)
	defer done()
	r, err := s.call(ctx, ti, &frame{T: tAction, ID: id, Action: req})
	if err != nil {
		return nil, err
	}
	if r.ActionResult == nil {
		return nil, harness.Errf(harness.CodeInternal, "bad result from the gateway")
	}
	return r.ActionResult, nil
}

// sessionFor is the session Run opened for the task, or a one-off one (a task Run doesn't serve: nobody sees its
// events), closed by done.
func (c *Client) sessionFor(id string) (*session, func()) {
	c.mu.Lock()
	s := c.sessions[id]
	c.mu.Unlock()
	if s != nil {
		return s, func() {}
	}
	s = &session{c: c, id: id, opts: []byte(`{}`)}
	return s, s.Close
}

var errLost = errors.New("gateway: connection lost")

// session is one task's link to gatewayd. Its connection is made on first use and again after it breaks (a
// gatewayd restart): requests in flight then fail, later ones go to the new process, which rebuilds the task's
// state from the journal the session sends again.
type session struct {
	c    *Client
	id   string
	opts []byte
	emit func(proto.Event) error // nil: nobody watches

	mu     sync.Mutex
	cn     *conn
	closed bool
	step   int // the last step event relayed (End's answer if gatewayd can't give one)
	// background is the task's egress outside any request (site icons), from End's result.
	background guard.FactsData
}

type conn struct {
	nc  net.Conn
	wmu sync.Mutex

	mu      sync.Mutex
	pending map[uint64]chan *frame
	next    uint64
	dead    bool
	task    sync.Mutex // held while the task frame is sent
	taskOK  bool
}

func (s *session) connect(ctx context.Context) (*conn, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, errLost
	}
	if s.cn != nil && !s.cn.isDead() {
		return s.cn, nil
	}
	wait := s.c.Wait
	if wait == 0 {
		wait = 20 * time.Second
	}
	deadline := time.Now().Add(wait)
	var nc net.Conn
	var err error
	for {
		var d net.Dialer
		if nc, err = d.DialContext(ctx, "unix", s.c.Path); err == nil {
			break
		}
		if ctx.Err() != nil || time.Now().After(deadline) {
			return nil, err
		}
		select {
		case <-ctx.Done():
		case <-time.After(200 * time.Millisecond):
		}
	}
	cn := &conn{nc: nc, pending: map[uint64]chan *frame{}}
	var docs []safety.Envelope
	if s.c.Docs != nil {
		docs = s.c.Docs()
	}
	if err := cn.write(&frame{T: tOpen, Version: Version, Task: s.id, Options: s.opts, Docs: docs}); err != nil {
		nc.Close()
		return nil, err
	}
	s.cn = cn
	go s.read(cn)
	return cn, nil
}

func (cn *conn) isDead() bool {
	cn.mu.Lock()
	defer cn.mu.Unlock()
	return cn.dead
}

func (cn *conn) write(f *frame) error {
	cn.wmu.Lock()
	defer cn.wmu.Unlock()
	cn.nc.SetWriteDeadline(time.Now().Add(time.Minute))
	return writeFrame(cn.nc, f)
}

// kill ends the connection: every request waiting on it gets errLost.
func (cn *conn) kill() {
	cn.mu.Lock()
	defer cn.mu.Unlock()
	if cn.dead {
		return
	}
	cn.dead = true
	cn.nc.Close()
	for rid, ch := range cn.pending {
		close(ch)
		delete(cn.pending, rid)
	}
}

// read relays the task's events (in order, before the results they precede) and hands results to their requests.
func (s *session) read(cn *conn) {
	defer cn.kill()
	for {
		var f frame
		if err := readFrame(cn.nc, &f); err != nil {
			return
		}
		switch f.T {
		case tEvent:
			var e proto.Event
			if jsonv1.Unmarshal(f.Event, &e) != nil {
				return
			}
			if e.Type == "step" {
				s.mu.Lock()
				s.step = e.Step
				s.mu.Unlock()
			}
			if s.emit != nil {
				s.emit(e) // a failed write cancels the task (guard.Run's stream); later events are dropped there
			}
		case tResult:
			cn.mu.Lock()
			ch := cn.pending[f.RID]
			delete(cn.pending, f.RID)
			cn.mu.Unlock()
			if ch == nil {
				return
			}
			ch <- &f
		default:
			return
		}
	}
}

// call sends one request and waits for its result. When ctx ends it asks gatewayd to stop and waits a little
// for the result (so the request's events are relayed first), then returns ctx's error. A connection found dead
// before the request went out (gatewayd restarted and the reader hadn't seen it yet) is replaced once; a request
// that was sent is never sent again.
func (s *session) call(ctx context.Context, ti *harness.TaskInfo, f *frame) (*frame, error) {
	unavailable := harness.Errf(harness.CodeInternal, "gateway unavailable")
	var cn *conn
	var ch chan *frame
	for attempt := 0; ; attempt++ {
		var err error
		if cn, err = s.connect(ctx); err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return nil, unavailable
		}
		if ch, err = s.send(cn, ti, f); err == nil {
			break
		}
		cn.kill()
		if attempt == 1 {
			return nil, unavailable
		}
	}
	var r *frame
	select {
	case r = <-ch:
	case <-ctx.Done():
		cn.write(&frame{T: tCancel, RID: f.RID})
		select {
		case r = <-ch:
		case <-time.After(10 * time.Second):
		}
		return nil, ctx.Err()
	}
	if r == nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, harness.Errf(harness.CodeInternal, "gateway connection lost")
	}
	if r.Facts != nil && f.T != tEnd { // what gatewayd did for it goes to the request's activity record
		guard.FactsFrom(ctx).Merge(*r.Facts)
	}
	if r.Err != nil {
		if r.Err.Code == harness.CodeCancelled && ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, r.Err
	}
	return r, nil
}

// send writes the task frame (once per connection) and the request on cn, and returns the channel its result
// comes on. An error means the request didn't go out.
func (s *session) send(cn *conn, ti *harness.TaskInfo, f *frame) (chan *frame, error) {
	if ti != nil {
		cn.task.Lock()
		if !cn.taskOK {
			tf := &frame{T: tTask}
			if ti.Start != nil {
				tf.Tools = ti.Start.Tools
			}
			if ti.Journal != nil {
				if recs, err := ti.Journal(); err == nil {
					tf.Journal = toRecords(recs)
				}
			}
			if err := cn.write(tf); err != nil {
				cn.task.Unlock()
				return nil, err
			}
			cn.taskOK = true
		}
		cn.task.Unlock()
	}
	ch := make(chan *frame, 1)
	cn.mu.Lock()
	if cn.dead {
		cn.mu.Unlock()
		return nil, errLost
	}
	cn.next++
	f.RID = cn.next
	cn.pending[f.RID] = ch
	cn.mu.Unlock()
	if err := cn.write(f); err != nil {
		cn.mu.Lock()
		delete(cn.pending, f.RID)
		cn.mu.Unlock()
		return nil, err
	}
	return ch, nil
}

// Meta asks gatewayd for the verified model upstream.
func (s *session) Meta(ctx context.Context) (*proto.Meta, error) {
	r, err := s.call(ctx, nil, &frame{T: tMeta})
	if err != nil {
		var pe *harness.Error
		if errors.As(err, &pe) && pe.Message != "" {
			return nil, errors.New(pe.Message)
		}
		return nil, err
	}
	if r.Meta == nil {
		return nil, errors.New("no meta from the gateway")
	}
	return r.Meta, nil
}

// End: gatewayd gives the site icons their grace and closes the task; the session closes too.
func (s *session) End() (int, string) {
	defer s.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	r, err := s.call(ctx, nil, &frame{T: tEnd})
	if err != nil {
		s.mu.Lock()
		defer s.mu.Unlock()
		return s.step, "stop"
	}
	if r.Facts != nil {
		s.mu.Lock()
		s.background = *r.Facts
		s.mu.Unlock()
	}
	return r.Step, r.Finish
}

// Background is the task's egress outside any request (site icons), as gatewayd reported it at End.
func (s *session) Background() guard.FactsData {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.background
}

// Close ends the session (gatewayd forgets the task).
func (s *session) Close() {
	s.mu.Lock()
	s.closed = true
	cn := s.cn
	s.mu.Unlock()
	if cn != nil {
		cn.kill()
	}
	s.c.mu.Lock()
	if s.c.sessions[s.id] == s {
		delete(s.c.sessions, s.id)
	}
	s.c.mu.Unlock()
}
