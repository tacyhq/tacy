// Package refbrain is the reference brain: the smallest harness that passes the conformance suite. One loop per
// task, built the Pi way: at each step boundary it folds in steering, checkpoints, calls the model, then
// proposes the tool calls as actions, until the model answers without tools.
//
// Its request ids come from the step ("s3.c", "s3.m", "s3.a0"), and its checkpoint is taken before the step's
// model call, so a brain resumed from that checkpoint asks the same things under the same ids: the runtime answers
// them from its journal, and an action that already ran is never repeated.
package refbrain

import (
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"net"

	"github.com/tacyhq/tacy/harness"
)

// Run serves tasks on conn until ctx ends or the connection closes.
func Run(ctx context.Context, conn net.Conn) error {
	c, err := harness.Connect(conn, harness.Hello{Brain: harness.Info{Name: "refbrain", Version: "0.1"}, MaxTasks: 4})
	if err != nil {
		conn.Close()
		return err
	}
	defer c.Close()
	stop := context.AfterFunc(ctx, func() { c.Close() })
	defer stop()
	for {
		t, err := c.Accept(ctx)
		if err != nil {
			return err
		}
		go func() {
			if d, ok := loop(ctx, t); ok {
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

// loop runs one task. ok is false when the connection is gone (nothing more can be sent).
func loop(ctx context.Context, t *harness.Task) (harness.Done, bool) {
	var st state
	seq, applied, resumed := 0, 0, false
	if cp := t.Start.Checkpoint; cp != nil {
		if json.Unmarshal(cp.State, &st) != nil {
			return harness.Done{Outcome: harness.OutcomeFailed, Error: "checkpoint unreadable"}, true
		}
		seq, applied, resumed = cp.Seq, cp.SteerApplied, true
	} else {
		st.Messages = append([]harness.Message{{Role: "system", Content: t.Start.Instructions}}, t.Start.Input...)
	}
	var tools []string
	for _, tl := range t.Start.Tools {
		tools = append(tools, tl.Name)
	}
	for {
		select {
		case <-t.Cancelled():
			return harness.Done{Outcome: harness.OutcomeCancelled}, true
		default:
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
			seq++
			b, _ := json.Marshal(&st)
			if err := t.Checkpoint(ctx, fmt.Sprintf("s%d.c", st.Step), harness.Checkpoint{Seq: seq, SteerApplied: applied, State: b}); err != nil {
				return ended(err)
			}
		}
		resumed = false
		t.Status(harness.Status{Note: "thinking"})
		res, err := t.ModelCall(ctx, fmt.Sprintf("s%d.m", st.Step),
			harness.ModelCall{Model: t.Start.Models[0], Messages: st.Messages, Tools: tools})
		if err != nil {
			return ended(err)
		}
		st.Messages = append(st.Messages, res.Message)
		if len(res.Message.ToolCalls) == 0 {
			return harness.Done{Outcome: harness.OutcomeSucceeded, Text: res.Message.Content}, true
		}
		for i, tc := range res.Message.ToolCalls {
			content, err := runTool(ctx, t, fmt.Sprintf("s%d.a%d", st.Step, i), tc)
			if err != nil {
				return ended(err)
			}
			st.Messages = append(st.Messages, harness.Message{Role: "tool", ToolCallID: tc.ID, Content: content})
		}
	}
}

// runTool proposes one tool call as an action (naming the call, as the runtime requires) and returns what the
// model is told. A refusal by the runtime (an
// unknown tool, say) is told to the model too; only cancellation and a lost connection stop the task.
func runTool(ctx context.Context, t *harness.Task, id string, tc harness.ToolCall) (string, error) {
	if tc.BadArgs {
		return `{"error":"the arguments weren't valid JSON"}`, nil
	}
	ar, err := t.Action(ctx, id, harness.Action{Name: tc.Name, Args: tc.Args, Call: tc.ID})
	var pe *harness.Error
	switch {
	case errors.As(err, &pe) && pe.Code != harness.CodeCancelled:
		b, _ := json.Marshal(map[string]string{"error": pe.Code})
		return string(b), nil
	case err != nil:
		return "", err
	}
	out := map[string]any{"status": ar.Status}
	if ar.Output != nil {
		out["output"] = jsontext.Value(ar.Output)
	}
	if ar.Error != "" {
		out["error"] = ar.Error
	}
	b, _ := json.Marshal(out)
	return string(b), nil
}

// ended turns a request error into the task's end: cancelled, failed, or (connection gone) nothing to send.
func ended(err error) (harness.Done, bool) {
	var pe *harness.Error
	switch {
	case errors.As(err, &pe) && pe.Code == harness.CodeCancelled:
		return harness.Done{Outcome: harness.OutcomeCancelled}, true
	case errors.As(err, &pe):
		return harness.Done{Outcome: harness.OutcomeFailed, Error: pe.Code}, true
	}
	return harness.Done{}, false
}
