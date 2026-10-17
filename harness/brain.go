package harness

import (
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"net"
	"slices"
	"sync"
	"time"
)

// Client is the brain's side of a connection: the handshake, then the tasks the runtime starts (Accept) and the
// requests each makes (Task). It decodes the runtime's frames as strictly as the runtime decodes the brain's and
// closes the connection on anything unexpected: a brain fails closed too.
type Client struct {
	conn    net.Conn
	hello   Hello
	welcome Welcome
	wmu     sync.Mutex

	mu       sync.Mutex
	tasks    map[string]*Task
	finished map[string]bool
	waiters  map[string]chan reply // by task\x00id; nil once abandoned (its result is dropped)
	starts   []*Task
	notify   chan struct{}
	err      error
	closed   chan struct{}
}

type reply struct {
	body jsontext.Value
	err  *Error
}

// Connect does the handshake on conn. Zero fields of h get defaults (this version, MaxFrame, one task).
func Connect(conn net.Conn, h Hello) (*Client, error) {
	if len(h.Protocols) == 0 {
		h.Protocols = []string{Version}
	}
	if h.MaxFrame == 0 {
		h.MaxFrame = MaxFrame
	}
	if h.MaxTasks == 0 {
		h.MaxTasks = 1
	}
	if err := h.validate(); err != nil {
		return nil, err
	}
	b, err := Encode(&Envelope{Type: TypeHello}, &h)
	if err != nil {
		return nil, err
	}
	conn.SetDeadline(time.Now().Add(HandshakeTimeout))
	if err := WriteFrame(conn, b, MinFrame); err != nil {
		return nil, err
	}
	frame, err := ReadFrame(conn, h.MaxFrame)
	if err != nil {
		return nil, err
	}
	e, body, err := Decode(frame, FromRuntime)
	switch {
	case err != nil:
		return nil, err
	case e.Type == TypeError:
		return nil, e.Error
	case e.Type != TypeWelcome:
		return nil, Errf(CodeProtocol, "expected welcome, got %s", e.Type)
	}
	w := body.(*Welcome)
	if !slices.Contains(h.Protocols, w.Protocol) {
		return nil, Errf(CodeUnsupportedVersion, "runtime chose %s", w.Protocol)
	}
	conn.SetDeadline(time.Time{})
	c := &Client{conn: conn, hello: h, welcome: *w, tasks: map[string]*Task{}, finished: map[string]bool{},
		waiters: map[string]chan reply{}, notify: make(chan struct{}, 1), closed: make(chan struct{})}
	go c.read()
	return c, nil
}

// Welcome is the runtime's handshake answer (its limits).
func (c *Client) Welcome() Welcome { return c.welcome }

// Close closes the connection.
func (c *Client) Close() error {
	c.fail(errors.New("harness: closed"))
	return nil
}

// Closed is closed once the connection is.
func (c *Client) Closed() <-chan struct{} { return c.closed }

// Err is why the connection closed.
func (c *Client) Err() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.err
}

func (c *Client) fail(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.err != nil {
		return
	}
	c.err = err
	close(c.closed)
	c.conn.Close()
}

// Accept returns the next task the runtime started (or resumed).
func (c *Client) Accept(ctx context.Context) (*Task, error) {
	for {
		c.mu.Lock()
		if len(c.starts) > 0 {
			t := c.starts[0]
			c.starts = c.starts[1:]
			c.mu.Unlock()
			return t, nil
		}
		err := c.err
		c.mu.Unlock()
		if err != nil {
			return nil, err
		}
		select {
		case <-c.notify:
		case <-c.closed:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

func (c *Client) send(e *Envelope) error {
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	if len(b) > c.welcome.Limits.MaxFrame {
		return Errf(CodeLimit, "frame of %d bytes over the runtime's max_frame", len(b))
	}
	c.wmu.Lock()
	defer c.wmu.Unlock()
	c.conn.SetWriteDeadline(time.Now().Add(writeTimeout))
	if err := WriteFrame(c.conn, b, c.welcome.Limits.MaxFrame); err != nil {
		c.fail(err)
		return err
	}
	return nil
}

func (c *Client) read() {
	for {
		var e *Envelope
		var body any
		frame, err := ReadFrame(c.conn, c.hello.MaxFrame)
		if err == nil {
			e, body, err = Decode(frame, FromRuntime)
		}
		if err == nil {
			err = c.handle(e, body)
		}
		if err == nil {
			continue
		}
		// A frame we refuse: tell the runtime why (best effort), then close. Not for I/O errors or the runtime's
		// own error message.
		var pe *Error
		if errors.As(err, &pe) && (e == nil || e.Type != TypeError) {
			if b, err := Encode(&Envelope{Type: TypeError, Error: pe}, nil); err == nil {
				c.wmu.Lock()
				c.conn.SetWriteDeadline(time.Now().Add(time.Second))
				WriteFrame(c.conn, b, MinFrame)
				c.wmu.Unlock()
			}
		}
		c.fail(err)
		return
	}
}

func (c *Client) handle(e *Envelope, body any) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	t := c.tasks[e.Task]
	switch b := body.(type) {
	case *Start:
		if t != nil || c.finished[e.Task] || len(c.tasks) >= c.welcome.Limits.MaxTasks {
			return Errf(CodeProtocol, "unexpected start")
		}
		t = &Task{c: c, ID: e.Task, Start: *b, cancelled: make(chan struct{})}
		c.tasks[e.Task] = t
		c.starts = append(c.starts, t)
		select {
		case c.notify <- struct{}{}:
		default:
		}
		return nil
	case *Steer:
		if t == nil {
			return c.lateOrUnknown(e)
		}
		t.mu.Lock()
		defer t.mu.Unlock()
		if b.N <= t.lastN || len(t.steers) >= MaxPendingSteers {
			return Errf(CodeProtocol, "steer out of order")
		}
		t.lastN = b.N
		t.steers = append(t.steers, *b)
		return nil
	case *Cancel:
		if t == nil {
			return c.lateOrUnknown(e)
		}
		t.cancelOnce.Do(func() {
			t.mu.Lock()
			t.reason = b.Reason
			t.mu.Unlock()
			close(t.cancelled)
		})
		return nil
	}
	switch e.Type {
	case TypeError:
		return e.Error
	case TypeResult:
		key := e.Task + "\x00" + e.Re
		ch, ok := c.waiters[key]
		if !ok {
			return Errf(CodeProtocol, "result nobody asked for")
		}
		delete(c.waiters, key)
		if ch != nil {
			ch <- reply{body: e.Body, err: e.Error}
		}
		return nil
	}
	return Errf(CodeProtocol, "%s isn't expected here", e.Type)
}

// lateOrUnknown: steer or cancel for a task this brain already finished is a race, not an error.
func (c *Client) lateOrUnknown(e *Envelope) error {
	if c.finished[e.Task] {
		return nil
	}
	return Errf(CodeProtocol, "%s for an unknown task", e.Type)
}

// Task is one task on the brain side. Its methods may be called from several goroutines.
type Task struct {
	c          *Client
	ID         string
	Start      Start
	mu         sync.Mutex
	steers     []Steer
	lastN      int
	cancelled  chan struct{}
	cancelOnce sync.Once
	reason     string
}

// Steers takes the steering messages received so far, oldest first.
func (t *Task) Steers() []Steer {
	t.mu.Lock()
	defer t.mu.Unlock()
	s := t.steers
	t.steers = nil
	return s
}

// Cancelled is closed when the runtime cancels the task; the brain must then send done (outcome cancelled).
func (t *Task) Cancelled() <-chan struct{} { return t.cancelled }

// CancelReason is the reason cancel gave.
func (t *Task) CancelReason() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.reason
}

// request sends one request and decodes its result into out. A refusal is an *Error.
func (t *Task) request(ctx context.Context, typ, id string, body any, out any) error {
	if !ValidID(id) {
		return errf("bad request id %q", id)
	}
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	c, key := t.c, t.ID+"\x00"+id
	ch := make(chan reply, 1)
	c.mu.Lock()
	if c.err != nil {
		c.mu.Unlock()
		return c.err
	}
	if _, ok := c.waiters[key]; ok {
		c.mu.Unlock()
		return Errf(CodeIDInFlight, "")
	}
	c.waiters[key] = ch
	c.mu.Unlock()
	if err := c.send(&Envelope{Type: typ, Task: t.ID, ID: id, Body: b}); err != nil {
		c.mu.Lock()
		delete(c.waiters, key)
		c.mu.Unlock()
		return err
	}
	select {
	case r := <-ch:
		if r.err != nil {
			return r.err
		}
		if err := DecodeResult(r.body, out); err != nil {
			c.fail(err) // a malformed result: the runtime isn't speaking the protocol
			return err
		}
		return nil
	case <-ctx.Done():
		c.mu.Lock()
		if _, ok := c.waiters[key]; ok {
			c.waiters[key] = nil
		}
		c.mu.Unlock()
		return ctx.Err()
	case <-c.closed:
		return c.Err()
	}
}

// ModelCall asks the model gateway for one completion.
func (t *Task) ModelCall(ctx context.Context, id string, req ModelCall) (*ModelResult, error) {
	var out ModelResult
	if err := t.request(ctx, TypeModelCall, id, &req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Action proposes a typed action. The same id with the same request returns the recorded outcome; it never runs
// twice.
func (t *Task) Action(ctx context.Context, id string, req Action) (*ActionResult, error) {
	var out ActionResult
	if err := t.request(ctx, TypeAction, id, &req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Exec runs a command in the task's hands sandbox.
func (t *Task) Exec(ctx context.Context, id string, req Exec) (*ExecResult, error) {
	var out ExecResult
	if err := t.request(ctx, TypeExec, id, &req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Checkpoint stores the brain's state for this task.
func (t *Task) Checkpoint(ctx context.Context, id string, cp Checkpoint) error {
	return t.request(ctx, TypeCheckpoint, id, &cp, &Empty{})
}

// Status reports progress (no reply).
func (t *Task) Status(st Status) error {
	b, err := json.Marshal(&st)
	if err != nil {
		return err
	}
	return t.c.send(&Envelope{Type: TypeStatus, Task: t.ID, Body: b})
}

// Done ends the task. After it, the task's id is finished on this connection.
func (t *Task) Done(ctx context.Context, id string, d Done) error {
	err := t.request(ctx, TypeDone, id, &d, &Empty{})
	c := t.c
	c.mu.Lock()
	delete(c.tasks, t.ID)
	c.finished[t.ID] = true
	c.mu.Unlock()
	return err
}
