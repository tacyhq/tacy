package guard

import (
	"cmp"
	"context"
	"sync"
	"time"

	"github.com/tacyhq/tacy/harness"
	"github.com/tacyhq/tacy/proto"
)

// CredWaits is agentd's side of a mail call whose task has no login in the vault (the v1 design §5.4: vaultd
// restarted, or the login was forgotten while the task waited): gatewayd answered the call with MailLoginNeeded
// without sending anything. agentd holds the call, shows need_credential in the task's stream, and when a following
// app sends the login again (POST /tasks/credential) runs the call again. No app within Timeout: the model gets
// the denial. Only POST /tasks tasks (with a run secret: the resend's MAC) wait; nothing else can be asked.
type CredWaits struct {
	// Emit adds an event to a task's stream (Host.Emit). Required.
	Emit func(task string, e proto.Event)
	// Timeout is how long a call waits; 0: DefaultPromptTimeout. Never past the task's deadline less a minute.
	Timeout time.Duration
	// OnWait is told when a wait of a task opens and closes (agentd stops the run's clock meanwhile). nil: nobody.
	OnWait func(task string, open bool)

	mu    sync.Mutex
	waits map[string][]chan struct{} // task -> the calls waiting for its login
}

// Credential decisions in a need_credential event's outcome.
const (
	CredProvided = "provided"
	CredTimedOut = "timed_out"
)

// CanWait: a task of this kind can be asked for its login (a POST /tasks task with a run secret).
func CanWait(ti *harness.TaskInfo) bool {
	o := optionsOf(ti)
	return o.Via == ViaTasks && validRunSecret(o.RunSecret)
}

// Wait holds a call until its task's login is sent again (true) or Timeout, the task's deadline or ctx ends it
// (false). id is the call's request, call its tool call id (the event's id).
func (c *CredWaits) Wait(ctx context.Context, ti *harness.TaskInfo, id, call string) bool {
	d := cmp.Or(c.Timeout, DefaultPromptTimeout)
	if ti.Start != nil && ti.Start.Limits.Deadline != "" {
		if end, err := time.Parse(time.RFC3339, ti.Start.Limits.Deadline); err == nil {
			d = min(d, time.Until(end)-time.Minute)
		}
	}
	if d <= 0 {
		return false
	}
	ch := make(chan struct{})
	c.mu.Lock()
	if c.waits == nil {
		c.waits = map[string][]chan struct{}{}
	}
	c.waits[ti.ID] = append(c.waits[ti.ID], ch)
	c.mu.Unlock()
	if c.OnWait != nil {
		c.OnWait(ti.ID, true)
	}
	need := &proto.CredentialNeed{Task: ti.ID, Request: id, Connection: "email", TimeoutS: int(d.Round(time.Second) / time.Second)}
	c.Emit(ti.ID, proto.Event{Type: "need_credential", ID: cmp.Or(call, id), Credential: need})
	t := time.NewTimer(d)
	defer t.Stop()
	ok := false
	select {
	case <-ch:
		ok = true
	case <-t.C:
	case <-ctx.Done():
	}
	c.drop(ti.ID, ch)
	if c.OnWait != nil {
		c.OnWait(ti.ID, false)
	}
	out := *need
	out.TimeoutS, out.Decision = 0, map[bool]string{true: CredProvided, false: CredTimedOut}[ok]
	c.Emit(ti.ID, proto.Event{Type: "need_credential", ID: cmp.Or(call, id), Credential: &out})
	return ok
}

func (c *CredWaits) drop(task string, ch chan struct{}) {
	c.mu.Lock()
	defer c.mu.Unlock()
	l := c.waits[task]
	for i, x := range l {
		if x == ch {
			c.waits[task] = append(l[:i:i], l[i+1:]...)
			break
		}
	}
	if len(c.waits[task]) == 0 {
		delete(c.waits, task)
	}
}

// Provided wakes the task's waiting calls: its login is in the vault again.
func (c *CredWaits) Provided(task string) {
	c.mu.Lock()
	l := c.waits[task]
	delete(c.waits, task)
	c.mu.Unlock()
	for _, ch := range l {
		close(ch)
	}
}

// Waiting is how many calls of the task wait for its login.
func (c *CredWaits) Waiting(task string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.waits[task])
}
