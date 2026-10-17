// Package brain is our Go agent loop as a harness/v1 brain (docs/20-harness-protocol.md; our own
// loop goes first). It is the loop of the old app/agent.go without anything that needs a key or the network: it runs
// untrusted, in its own sandbox, and its one connection is the runtime's socket. Model calls are model.call, tool
// calls are typed actions, and the runtime streams to people.
//
// Per task, built the Pi way: at every step boundary it folds in steering and checkpoints its
// state, then calls the model; the step's tool calls run as actions, in parallel (results kept in call order),
// until the model answers without tools. The last step offers no tools, so it must answer. Request ids come from
// the step ("s3.c", "s3.m", "s3.a0"), so a brain resumed from a checkpoint asks the same things under the same ids
// and the runtime answers from its journal: no second bill, no repeated side effect.
//
// Kept from the old app/agent.go: the step loop, no tools on the last step, at most 4 tool calls run per step (the rest
// refused), the same refusals told to the model, a tool's result given to the model exactly as the tool returned
// it. Moved to the runtime: the system prompt (start.instructions), the model and its options, max_steps and the
// deadline (start.limits), citation numbers, PII masking, the caps and every event people see.
package brain

import (
	"context"
	"encoding/json"
	jsonv2 "encoding/json/v2"
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"
	"sync"

	"github.com/tacyhq/tacy/harness"
)

// finalNudge asks for the answer when the last step's reply was only a tool call (see loop).
const finalNudge = "You can't call any more tools. Answer my question now from the tool results above, citing them as [n]."

// Version names this brain in hello (logs only).
const Version = "0.1"

const (
	maxCallsPerStep = 4   // tool calls run per step; the model is told the rest were refused (from the old app/agent.go)
	maxParallel     = 4   // actions in flight per task (Limits.RunTools: the runtime's max_inflight), at most the runtime's max_inflight
	maxTasks        = 256 // tasks at once on one connection (one brain per space); the runtime sets fewer
)

// Run serves tasks on conn until ctx ends or the connection closes.
func Run(ctx context.Context, conn net.Conn) error {
	c, err := harness.Connect(conn, harness.Hello{Brain: harness.Info{Name: "tacy-brain", Version: Version}, MaxTasks: maxTasks})
	if err != nil {
		conn.Close()
		return err
	}
	defer c.Close()
	stop := context.AfterFunc(ctx, func() { c.Close() })
	defer stop()
	lim := c.Welcome().Limits
	parallel := max(1, min(maxParallel, lim.MaxInflight))
	for {
		t, err := c.Accept(ctx)
		if err != nil {
			return err
		}
		go func() {
			if d, ok := loop(ctx, t, parallel, maxState(lim)); ok {
				t.Done(ctx, "done", d) // if this fails the connection is gone: the runtime resumes or ends the task
			}
		}()
	}
}

// state is what the checkpoint holds: enough to redo the current step exactly.
type state struct {
	Step     int               `json:"step"`
	Messages []harness.Message `json:"messages"`
}

// maxState is the most checkpoint state the runtime takes: its max_checkpoint, and little enough that the
// checkpoint frame (the state in base64, plus the envelope) fits its max_frame.
func maxState(l harness.Limits) int {
	return max(0, min(l.MaxCheckpoint, (l.MaxFrame-4<<10)/4*3))
}

// errTooLong ends a task whose conversation no longer fits a checkpoint. The protocol caps a conversation by bytes
// only (the checkpoint's max, and the frame's), not by message count.
const errTooLong = "the conversation is too long"

// loop runs one task. ok is false when the connection is gone (nothing more can be sent). A step whose state is
// over maxState fails the task cleanly instead of being refused by the runtime.
func loop(ctx context.Context, t *harness.Task, parallel, maxState int) (harness.Done, bool) {
	// Requests stop as soon as the task is cancelled; done (cancelled) still goes out on ctx.
	rctx, stop := context.WithCancel(ctx)
	defer stop()
	go func() {
		select {
		case <-t.Cancelled():
			stop()
		case <-rctx.Done():
		}
	}()
	var st state
	seq, applied, resumed := 0, 0, false
	if cp := t.Start.Checkpoint; cp != nil {
		if jsonv2.Unmarshal(cp.State, &st) != nil {
			return harness.Done{Outcome: harness.OutcomeFailed, Error: "checkpoint unreadable"}, true
		}
		seq, applied, resumed = cp.Seq, cp.SteerApplied, true
	} else {
		if t.Start.Instructions != "" {
			st.Messages = append(st.Messages, harness.Message{Role: "system", Content: t.Start.Instructions})
		}
		st.Messages = append(st.Messages, t.Start.Input...)
	}
	var tools []string
	for _, tl := range t.Start.Tools {
		tools = append(tools, tl.Name)
	}
	for {
		if cancelled(t) {
			return harness.Done{Outcome: harness.OutcomeCancelled}, true
		}
		if !resumed { // step boundary: steering, then checkpoint
			st.Step++
			if st.Step > t.Start.Limits.MaxSteps {
				return harness.Done{Outcome: harness.OutcomeFailed, Error: "step limit"}, true
			}
			for _, s := range t.Steers() {
				if s.N > applied {
					st.Messages = append(st.Messages, harness.Message{Role: "user", Content: s.Text})
					applied = s.N
				}
			}
			b, err := jsonv2.Marshal(&st)
			if err == nil && len(b) > maxState {
				// The state holds every message, so the step's model call (the messages, unencoded, plus a few KiB)
				// fits a frame whenever the checkpoint does.
				return harness.Done{Outcome: harness.OutcomeFailed, Error: errTooLong}, true
			}
			seq++
			if err == nil {
				err = t.Checkpoint(rctx, fmt.Sprintf("s%d.c", st.Step), harness.Checkpoint{Seq: seq, SteerApplied: applied, State: b})
			}
			if err != nil {
				return ended(t, err)
			}
		}
		resumed = false
		last := st.Step >= t.Start.Limits.MaxSteps
		mc := harness.ModelCall{Model: t.Start.Models[0], Messages: st.Messages}
		if !last {
			mc.Tools = tools
		}
		t.Status(harness.Status{Note: "thinking"})
		res, err := t.ModelCall(rctx, fmt.Sprintf("s%d.m", st.Step), mc)
		if err != nil {
			return ended(t, err)
		}
		if last && len(res.Message.ToolCalls) > 0 && strings.TrimSpace(res.Message.Content) == "" {
			// No tools were offered, yet some models (gpt-oss-120b) still ask for one and write nothing, which ended
			// the run without an answer (8 of 11 live runs of a shopping question, 2026-10-16). Ask once more for
			// the answer, without the unanswerable call. Its own request id, so a resumed brain replays it.
			retry := harness.ModelCall{Model: t.Start.Models[0], Messages: append(slices.Clone(st.Messages), harness.Message{Role: "user", Content: finalNudge})}
			if r2, err := t.ModelCall(rctx, fmt.Sprintf("s%d.m2", st.Step), retry); err == nil && strings.TrimSpace(r2.Message.Content) != "" {
				res = r2
			}
		}
		st.Messages = append(st.Messages, res.Message)
		if len(res.Message.ToolCalls) == 0 || last {
			return harness.Done{Outcome: harness.OutcomeSucceeded, Text: capText(res.Message.Content, harness.MaxDoneText)}, true
		}
		t.Status(harness.Status{Note: "using tools"})
		results, err := runCalls(rctx, t, st.Step, res.Message.ToolCalls, tools, parallel)
		if err != nil {
			return ended(t, err)
		}
		st.Messages = append(st.Messages, results...)
	}
}

// runCalls runs a step's tool calls as actions, at most parallel at once, and returns the tool messages in call
// order. A call it can't run (over the per-step cap, a tool the task doesn't have, arguments that didn't parse)
// is refused here and the model told why, as the old app/agent.go did. Each action carries the model's call id, so the
// runtime shows people its result under that call.
func runCalls(ctx context.Context, t *harness.Task, step int, calls []harness.ToolCall, tools []string, parallel int) ([]harness.Message, error) {
	content := make([]string, len(calls))
	errs := make([]error, len(calls))
	slots := make(chan struct{}, parallel)
	var wg sync.WaitGroup
	for i, c := range calls {
		switch {
		case i >= maxCallsPerStep:
			content[i] = errorContent(fmt.Sprintf("at most %d tool calls per step", maxCallsPerStep))
		case !slices.Contains(tools, c.Name):
			content[i] = errorContent("tool " + c.Name + " isn't available")
		case c.BadArgs:
			content[i] = errorContent("arguments aren't valid JSON")
		default:
			wg.Add(1)
			go func() {
				defer wg.Done()
				select {
				case slots <- struct{}{}:
					defer func() { <-slots }()
				case <-ctx.Done():
					errs[i] = ctx.Err()
					return
				}
				content[i], errs[i] = runAction(ctx, t, fmt.Sprintf("s%d.a%d", step, i), c)
			}()
		}
	}
	wg.Wait()
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	msgs := make([]harness.Message, len(calls))
	for i, c := range calls {
		msgs[i] = harness.Message{Role: "tool", ToolCallID: c.ID, Content: content[i]}
	}
	return msgs, nil
}

// runAction proposes one tool call as an action and returns what the model is told: the tool's own output when it
// ran, else {"error": ...}. A refusal by the runtime (a tool not allowed, an interrupted action) is told to the
// model too; only cancellation and a lost connection stop the task.
func runAction(ctx context.Context, t *harness.Task, id string, c harness.ToolCall) (string, error) {
	ar, err := t.Action(ctx, id, harness.Action{Name: c.Name, Args: c.Args, Call: c.ID})
	var pe *harness.Error
	switch {
	case errors.As(err, &pe) && pe.Code != harness.CodeCancelled:
		return errorContent(errorText(pe)), nil
	case err != nil:
		return "", err
	}
	switch {
	case ar.Status == harness.ActionDone && len(ar.Output) > 0:
		return string(ar.Output), nil
	case ar.Status == harness.ActionDone:
		return `{}`, nil
	case ar.Error != "":
		return errorContent(ar.Error), nil
	}
	return errorContent(ar.Status), nil
}

// errorContent is a tool message for an error, shaped as guard/tools.go's errorOutcome (encoding/json, so the model
// gets the same bytes as before).
func errorContent(msg string) string {
	b, _ := json.Marshal(map[string]string{"error": msg})
	return string(b)
}

func errorText(pe *harness.Error) string {
	if pe.Message == "" {
		return pe.Code
	}
	return pe.Code + ": " + pe.Message
}

func cancelled(t *harness.Task) bool {
	select {
	case <-t.Cancelled():
		return true
	default:
		return false
	}
}

// ended turns a request error into the task's end: cancelled, failed, or (connection gone) nothing to send.
func ended(t *harness.Task, err error) (harness.Done, bool) {
	var pe *harness.Error
	switch {
	case cancelled(t), errors.As(err, &pe) && pe.Code == harness.CodeCancelled:
		return harness.Done{Outcome: harness.OutcomeCancelled}, true
	case errors.As(err, &pe):
		// A model failure arrives as internal with the upstream's message, which people see as the run's error.
		msg := pe.Message
		if pe.Code != harness.CodeInternal || msg == "" {
			msg = errorText(pe)
		}
		return harness.Done{Outcome: harness.OutcomeFailed, Error: capText(msg, harness.MaxErrorText)}, true
	}
	return harness.Done{}, false
}

func capText(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return strings.ToValidUTF8(s[:max], "") // drops a rune cut in half
}
