// Package gateway is gateway/v0 (docs/21-gateway-v0.md section 3): how agentd (the runtime, ../app) reaches
// gatewayd (the model gateway and the connectors, ../cmd/gatewayd), the only process in the CVM with a way out.
// agentd has no network and no keys; for every model call and action the brain asks for, the runtime checks and
// journals it, then sends it here, and gatewayd does it, leasing the key it needs from the vault for that one call.
//
// One unix socket connection per task session. agentd opens it with the task's id and the person's options, sends
// the task's tools and journal once before the first request, then requests (meta, model, action, end; cancel),
// each with its own id; gatewayd answers each with one result and, in between, streams the task's events (what
// people see: the proto.Events the guard emits) in order. A result comes after the events it caused, so agentd
// relays them before the runtime sees the result.
//
// Framing is harness/v1's (a 4-byte big-endian length, then one JSON object) with strict decoding: unknown
// members, duplicate names, a bad length or trailing data close the connection. Internal and unfrozen: only our
// own code speaks it.
package gateway

import (
	"encoding/binary"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"

	"github.com/tacyhq/tacy/guard"
	"github.com/tacyhq/tacy/harness"
	"github.com/tacyhq/tacy/proto"
	"github.com/tacyhq/tacy/safety"
)

// Version names this protocol (internal, unfrozen).
const Version = "gateway/v0"

// MaxFrame bounds one frame: an event with an image (under 1 MiB), a model call with the whole conversation (the
// brain's frames are at most 4 MiB), a journal (model calls without their bodies).
const MaxFrame = 16 << 20

// Frame types.
const (
	tOpen   = "open"   // agentd → gatewayd, first: task, options
	tTask   = "task"   // agentd → gatewayd, once before the first request: tools, journal
	tMeta   = "meta"   // request: the verified model upstream
	tModel  = "model"  // request: a model.call
	tAction = "action" // request: an action
	tEnd    = "end"    // request: the task ended (site icons' grace, steps and finish reason)
	tCancel = "cancel" // agentd → gatewayd: stop request rid
	tEvent  = "event"  // gatewayd → agentd: one of the task's events
	tResult = "result" // gatewayd → agentd: request rid's result
	tSafety = "safety" // agentd → gatewayd, a connection's only frame: signed policies and stop lists (step 6)
)

type frame struct {
	T   string `json:"t"`
	RID uint64 `json:"rid,omitzero"`

	// open
	Task    string         `json:"task,omitzero"`
	Version string         `json:"version,omitzero"`
	Options jsontext.Value `json:"options,omitzero"`
	// open, safety: the signed documents agentd holds; gatewayd checks each itself (step 6)
	Docs []safety.Envelope `json:"docs,omitzero"`
	// task
	Tools   []harness.Tool `json:"tools,omitzero"`
	Journal []record       `json:"journal,omitzero"`
	// model, action
	ID    string             `json:"id,omitzero"` // the harness request id (journal, vault lease records)
	Model *harness.ModelCall `json:"model,omitzero"`
	// model: the output cap agentd reserved budget for (guard.WithMaxTokens; 0: none)
	MaxTokens int64           `json:"max_tokens,omitzero"`
	Action    *harness.Action `json:"action,omitzero"`

	// event
	Event jsontext.Value `json:"event,omitzero"` // a proto.Event as encoding/json writes it
	// result
	ModelResult  *harness.ModelResult  `json:"model_result,omitzero"`
	ActionResult *harness.ActionResult `json:"action_result,omitzero"`
	Meta         *proto.Meta           `json:"meta,omitzero"`
	Step         int                   `json:"step,omitzero"`
	Finish       string                `json:"finish,omitzero"`
	Err          *harness.Error        `json:"error,omitzero"`
	// result of model and action: what gatewayd saw and did for it (hosts, bytes, leases, leak-scan ids); of end:
	// the task's egress outside any request (site icons). Metadata only, for the activity record (docs/24).
	Facts *guard.FactsData `json:"facts,omitzero"`
}

// record is a journal entry as gatewayd needs it to rebuild a task's state (guard/rebuild.go): actions whole, model
// calls without their request and result (only that they finished, and how).
type record struct {
	ID   string         `json:"id"`
	Kind string         `json:"kind"`
	Req  jsontext.Value `json:"req,omitzero"`
	Done bool           `json:"done,omitzero"`
	Body jsontext.Value `json:"body,omitzero"`
	Err  *harness.Error `json:"err,omitzero"`
}

func toRecords(recs []harness.Record) []record {
	out := make([]record, 0, len(recs))
	for _, r := range recs {
		w := record{ID: r.ID, Kind: r.Kind, Done: r.Done, Err: r.Err}
		if r.Kind == harness.TypeAction {
			w.Req, w.Body = r.Req, r.Body
		}
		out = append(out, w)
	}
	return out
}

func fromRecords(recs []record) []harness.Record {
	out := make([]harness.Record, 0, len(recs))
	for _, r := range recs {
		out = append(out, harness.Record{ID: r.ID, Kind: r.Kind, Req: r.Req, Done: r.Done, Body: r.Body, Err: r.Err})
	}
	return out
}

func writeFrame(w io.Writer, f *frame) error {
	b, err := json.Marshal(f)
	if err != nil {
		return err
	}
	if len(b) > MaxFrame {
		return fmt.Errorf("gateway: frame of %d bytes", len(b))
	}
	buf := make([]byte, 4+len(b))
	binary.BigEndian.PutUint32(buf, uint32(len(b)))
	copy(buf[4:], b)
	_, err = w.Write(buf)
	return err
}

var errFrame = errors.New("gateway: bad frame")

func readFrame(r io.Reader, f *frame) error {
	var h [4]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return err
	}
	n := binary.BigEndian.Uint32(h[:])
	if n == 0 || n > MaxFrame {
		return errFrame
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		return err
	}
	*f = frame{}
	if err := json.Unmarshal(b, f, json.RejectUnknownMembers(true)); err != nil {
		return errFrame
	}
	return nil
}

// validID: task ids as the runtime makes them, 1-64 of [A-Za-z0-9._:-], starting with a letter or digit.
func validID(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for i, c := range s {
		alnum := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
		if !alnum && (i == 0 || c != '.' && c != '_' && c != ':' && c != '-') {
			return false
		}
	}
	return true
}
