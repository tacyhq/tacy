package gateway

import (
	"context"
	jsonv1 "encoding/json"
	"errors"
	"log"
	"net"
	"os"
	"sync"
	"time"

	"github.com/tacyhq/tacy/guard"
	"github.com/tacyhq/tacy/harness"
	"github.com/tacyhq/tacy/proto"
	"github.com/tacyhq/tacy/safety"
)

// Server is gatewayd's side: it serves task sessions on G, this process's guard (the model gateway and the web
// connector, with keys leased from the vault per call).
type Server struct {
	G *guard.Guard
	// Safety is gatewayd's own verified controls (the guard checks them); documents agentd sends are applied
	// here, and OnDocs is told when something changed (gatewayd passes them on to the vault).
	Safety *safety.State
	OnDocs func()
}

// apply takes signed documents from agentd: each is checked against gatewayd's own pinned keys and floors.
func (s *Server) apply(docs []safety.Envelope) {
	if s.Safety == nil || len(docs) == 0 {
		return
	}
	if _, changed := s.Safety.Apply(docs); changed && s.OnDocs != nil {
		s.OnDocs()
	}
}

// Listen makes gatewayd's socket with mode (0660: agentd connects through the socket's group; Serve checks its
// uid). A stale socket is removed.
func Listen(path string, mode os.FileMode) (net.Listener, error) {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	l, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, mode); err != nil {
		l.Close()
		return nil, err
	}
	return l, nil
}

// Serve accepts sessions on l until it is closed. peerUID is the only uid allowed to connect (agentd's; checked on
// Linux with SO_PEERCRED; -1 skips the check: tests and macOS).
func (s *Server) Serve(l net.Listener, peerUID int) error {
	for {
		c, err := l.Accept()
		if err != nil {
			return err
		}
		if peerUID >= 0 {
			if err := CheckPeer(c, peerUID); err != nil {
				log.Printf("gateway socket: %v", err)
				c.Close()
				continue
			}
		}
		go s.serve(c)
	}
}

// out writes frames to agentd, one at a time.
type out struct {
	mu   sync.Mutex
	c    net.Conn
	dead bool
}

func (o *out) write(f *frame) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.dead {
		return net.ErrClosed
	}
	o.c.SetWriteDeadline(time.Now().Add(time.Minute))
	if err := writeFrame(o.c, f); err != nil {
		o.dead = true
		o.c.Close()
		return err
	}
	return nil
}

func (s *Server) serve(c net.Conn) {
	defer c.Close()
	var open frame
	c.SetReadDeadline(time.Now().Add(30 * time.Second))
	if readFrame(c, &open) != nil || open.Version != Version {
		return
	}
	if open.T == tSafety {
		s.apply(open.Docs)
		c.SetWriteDeadline(time.Now().Add(10 * time.Second))
		writeFrame(c, &frame{T: tResult})
		return
	}
	if open.T != tOpen || !validID(open.Task) {
		return
	}
	s.apply(open.Docs)
	c.SetReadDeadline(time.Time{})
	var opts guard.TaskOptions
	if len(open.Options) > 0 && jsonv1.Unmarshal(open.Options, &opts) != nil {
		return
	}
	w := &out{c: c}
	emit := func(e proto.Event) error {
		b, err := jsonv1.Marshal(e)
		if err != nil {
			return err
		}
		return w.write(&frame{T: tEvent, Event: b})
	}
	sess := s.G.Open(open.Task, opts, emit)
	ti := &harness.TaskInfo{ID: open.Task, Start: &harness.Start{}, Options: open.Options}
	var (
		mu      sync.Mutex
		running = map[uint64]context.CancelFunc{}
		wg      sync.WaitGroup
		haveCtx bool
	)
	defer func() {
		mu.Lock()
		for _, cancel := range running {
			cancel()
		}
		mu.Unlock()
		wg.Wait() // nothing may touch the task after it closes (it would open it again)
		sess.Close()
	}()
	for {
		var f frame
		if err := readFrame(c, &f); err != nil {
			return
		}
		switch f.T {
		case tTask:
			if haveCtx {
				return
			}
			haveCtx = true
			ti.Start = &harness.Start{Tools: f.Tools}
			recs := fromRecords(f.Journal)
			ti.Journal = func() ([]harness.Record, error) { return recs, nil }
			continue
		case tCancel:
			mu.Lock()
			if cancel := running[f.RID]; cancel != nil {
				cancel()
			}
			mu.Unlock()
			continue
		case tMeta, tEnd:
		case tModel, tAction:
			if !haveCtx || f.ID == "" || (f.T == tModel) != (f.Model != nil) || (f.T == tAction) != (f.Action != nil) ||
				f.Grant != nil && f.T != tAction {
				return
			}
		default:
			return
		}
		mu.Lock()
		if f.RID == 0 || running[f.RID] != nil {
			mu.Unlock()
			return
		}
		ctx, cancel := context.WithCancel(context.Background())
		running[f.RID] = cancel
		mu.Unlock()
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() {
				mu.Lock()
				delete(running, f.RID)
				mu.Unlock()
				cancel()
			}()
			res := s.do(ctx, sess, ti, &f)
			res.T, res.RID = tResult, f.RID
			w.write(res)
		}()
	}
}

// do runs one request and makes its result frame.
func (s *Server) do(ctx context.Context, sess guard.Session, ti *harness.TaskInfo, f *frame) *frame {
	var res frame
	var err error
	var facts *guard.Facts // what gatewayd saw and did for a model call or an action (its activity record)
	switch f.T {
	case tMeta:
		res.Meta, err = sess.Meta(ctx)
		if err != nil {
			return &frame{Err: harness.Errf(harness.CodeInternal, "%s", err.Error())}
		}
		return &res
	case tEnd:
		res.Step, res.Finish = sess.End()
		if b, ok := sess.(guard.BackgroundSession); ok {
			if d := b.Background(); len(d.Hosts) > 0 {
				res.Facts = &d
			}
		}
		return &res
	case tModel:
		facts = &guard.Facts{}
		if f.Tainted {
			c := *ti
			c.Tainted = true
			ti = &c
		}
		res.ModelResult, err = s.G.ModelCall(guard.WithFacts(guard.WithMaxTokens(harness.WithRequestID(ctx, f.ID), f.MaxTokens), facts), ti, f.Model)
	case tAction:
		facts = &guard.Facts{}
		if f.Tainted {
			c := *ti
			c.Tainted = true
			ti = &c
		}
		res.ActionResult, err = s.G.Action(guard.WithGrant(guard.WithFacts(harness.WithRequestID(ctx, f.ID), facts), f.Grant), ti, f.ID, f.Action)
	}
	res.Facts = facts.Ptr()
	if err != nil {
		var pe *harness.Error
		switch {
		case ctx.Err() != nil:
			pe = harness.Errf(harness.CodeCancelled, "")
		case errors.As(err, &pe):
		default:
			pe = harness.Errf(harness.CodeInternal, "")
		}
		res = frame{Err: pe, Facts: res.Facts}
	}
	return &res
}
