// Package harness is the harness/v1 protocol (DRAFT, docs/20-harness-protocol.md): how an untrusted agent harness
// (the "brain", in its own sandbox) talks to our trusted Go runtime (the "guard") over a local socket.
//
// The brain only proposes: model calls, typed actions, code to run in the task's hands sandbox, checkpoints of its
// own state. The runtime checks every message, does the work through the guard and records it, keyed by request
// id, so a restarted brain never repeats a side effect. Both sides decode strictly (codec.go) and the runtime
// treats every byte from the brain as hostile.
//
// Standard library only. Part of the attested compose (app/ is the runtime).
package harness

import (
	"encoding/json/jsontext"
	"fmt"
	"strings"
	"time"
)

// Version is the protocol this package speaks. Within a version the schema is frozen: a new field or message type
// is a new version (decoders reject unknown fields).
const Version = "harness/v1"

// Message types. Brain -> runtime: hello, then requests (model.call, action, exec, checkpoint, done; each gets
// exactly one result) and status (no reply). Runtime -> brain: welcome or error, then start, steer, cancel and
// result. error is fatal: the sender closes the connection after it.
const (
	TypeHello      = "hello"
	TypeModelCall  = "model.call"
	TypeAction     = "action"
	TypeExec       = "exec"
	TypeCheckpoint = "checkpoint"
	TypeStatus     = "status"
	TypeDone       = "done"

	TypeWelcome = "welcome"
	TypeStart   = "start"
	TypeSteer   = "steer"
	TypeCancel  = "cancel"
	TypeResult  = "result"
	TypeError   = "error"
)

// Defaults and hard caps. Limits the runtime announces in welcome may be lower, never higher.
const (
	MaxFrame         = 4 << 20 // bytes of one frame's JSON
	MinFrame         = 64 << 10
	MaxDepth         = 64 // nesting of objects and arrays in one frame
	MaxCheckpoint    = 2 << 20
	MaxSteerText     = 64 << 10
	MaxDoneText      = 256 << 10
	MaxNote          = 200
	MaxErrorText     = 1 << 10
	MaxArgs          = 256 << 10
	MaxRawArgs       = 4 << 10 // a tool call's raw_args, the truncation marker included
	MaxToolCalls     = 16
	MaxTools         = 64
	MaxArgv          = 64
	MaxStdin         = 1 << 20
	MaxExecTimeout   = 5 * time.Minute
	MaxPendingSteers = 64
)

// Error codes. bad_frame, unsupported_version and protocol arrive in an error message and end the connection;
// the rest arrive in a result and only fail that request.
const (
	CodeBadFrame           = "bad_frame"           // unreadable or invalid frame: size, JSON, unknown field, field rules
	CodeUnsupportedVersion = "unsupported_version" // hello offered no version the runtime speaks
	CodeProtocol           = "protocol"            // valid frame at the wrong time: before hello, wrong direction, ...
	CodeUnknownTask        = "unknown_task"        // no such task on this connection
	CodeTaskClosed         = "task_closed"         // the task already ended
	CodeCancelled          = "cancelled"           // the task was cancelled; the request didn't (or won't) finish
	CodeIDConflict         = "id_conflict"         // the id was used before with a different body; nothing ran
	CodeIDInFlight         = "id_in_flight"        // the same id is already waiting for its result on this connection
	CodeNotAllowed         = "not_allowed"         // not in the task's model list, tool list, or no hands sandbox
	CodeNotRequested       = "not_requested"       // an action whose call isn't a tool call of the latest model result
	CodeLimit              = "limit"               // a limit was reached (in-flight requests, model calls, size)
	CodeInvalid            = "invalid"             // valid shape, wrong value for the task's state (checkpoint seq)
	CodeInterrupted        = "interrupted"         // the runtime restarted while it ran; it may or may not have happened
	CodeInternal           = "internal"            // the runtime failed; retrying the same id gets the same answer
)

// Error is a protocol error, on the wire (error message, result.error) and as a Go error.
type Error struct {
	Code    string `json:"code"`
	Message string `json:"message,omitzero"`
}

func (e *Error) Error() string {
	if e.Message == "" {
		return "harness: " + e.Code
	}
	return "harness: " + e.Code + ": " + e.Message
}

// Errf makes an *Error.
func Errf(code, format string, args ...any) *Error {
	return &Error{Code: code, Message: capText(fmt.Sprintf(format, args...), MaxErrorText)}
}

// Envelope is one frame. Which fields a type carries is fixed (codec.go, envelopeRules); body is decoded
// separately into the type's struct.
type Envelope struct {
	Type  string         `json:"type"`
	Task  string         `json:"task,omitzero"` // task id (runtime-assigned) for everything but the handshake and error
	ID    string         `json:"id,omitzero"`   // request id (brain-chosen, unique within the task)
	Re    string         `json:"re,omitzero"`   // result: the request id it answers
	Body  jsontext.Value `json:"body,omitzero"`
	Error *Error         `json:"error,omitzero"`
}

// Info names an implementation, for logs and records. Never trusted for decisions.
type Info struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// Hello is the brain's first frame.
type Hello struct {
	Protocols []string `json:"protocols"` // versions it speaks, best first
	Brain     Info     `json:"brain"`
	MaxFrame  int      `json:"max_frame"` // largest frame it accepts (>= MinFrame)
	MaxTasks  int      `json:"max_tasks"` // tasks it runs at once
}

// Limits are what the runtime enforces on this connection, announced in welcome.
type Limits struct {
	MaxFrame      int `json:"max_frame"`       // largest frame the runtime accepts
	MaxTasks      int `json:"max_tasks"`       // tasks started at once (min of both sides)
	MaxInflight   int `json:"max_inflight"`    // requests waiting for a result, per task
	IdleTimeoutMs int `json:"idle_timeout_ms"` // silence with running tasks and nothing in flight = hung brain
	CancelGraceMs int `json:"cancel_grace_ms"` // time to send done after cancel
	MaxCheckpoint int `json:"max_checkpoint"`  // bytes of checkpoint state
}

// DefaultLimits are the runtime's defaults.
var DefaultLimits = Limits{MaxFrame: MaxFrame, MaxTasks: 8, MaxInflight: 8, IdleTimeoutMs: 60_000,
	CancelGraceMs: 10_000, MaxCheckpoint: MaxCheckpoint}

// Welcome is the runtime's answer to hello.
type Welcome struct {
	Protocol string `json:"protocol"` // the version chosen
	Runtime  Info   `json:"runtime"`
	Limits   Limits `json:"limits"`
}

// Start gives the brain a task (first run or resume). The envelope's task field is the task id.
type Start struct {
	Space        string     `json:"space"`
	Parent       string     `json:"parent,omitzero"` // parent task, for a child task
	Attempt      int        `json:"attempt"`         // 1 on the first run, +1 per brain restart
	Agent        AgentRef   `json:"agent"`
	Instructions string     `json:"instructions"`
	Models       []string   `json:"models"` // models the task may call, default first
	Tools        []Tool     `json:"tools"`  // actions the task may propose
	Hands        bool       `json:"hands"`  // whether exec is available (a hands sandbox for this task)
	Input        []Message  `json:"input"`  // what the task was given (the person's request)
	Limits       TaskLimits `json:"limits"`
	// Checkpoint is the latest checkpoint the brain stored for this task, when resuming. The brain continues from
	// it; steering messages after its steer_applied follow the start.
	Checkpoint *Checkpoint `json:"checkpoint,omitzero"`
}

// AgentRef identifies the signed agent definition the task runs.
type AgentRef struct {
	ID      string `json:"id"`
	Version string `json:"version"`
	Digest  string `json:"digest"` // sha256 of the signed definition, hex
}

// Tool is one action the task may propose, described for the model. The runtime gives the model the definitions
// itself (model.call names tools); the brain can't add or change one. The model sees the name as ModelToolName
// gives it (OpenAI-style function names can't hold dots); tool calls in a model.call result carry the action name.
type Tool struct {
	Name        string         `json:"name"` // e.g. "web.search", "mail.send"
	Description string         `json:"description"`
	Parameters  jsontext.Value `json:"parameters"` // JSON Schema object
}

// TaskLimits bound one task. The runtime enforces them; they're here so the brain can plan.
type TaskLimits struct {
	MaxSteps      int    `json:"max_steps"`
	MaxModelCalls int    `json:"max_model_calls"`
	Deadline      string `json:"deadline,omitzero"` // RFC 3339; the runtime cancels the task then
}

// Steer is a message a person sent to a running task. n counts from 1 per task, without gaps.
type Steer struct {
	N    int    `json:"n"`
	Text string `json:"text"`
}

// Cancel asks the brain to stop the task and send done with outcome "cancelled" within the grace period.
type Cancel struct {
	Reason string `json:"reason"` // "person", "deadline", "kill_switch", ...
}

// Message is one model message.
type Message struct {
	Role       string     `json:"role"` // system | user | assistant | tool
	Content    string     `json:"content"`
	ToolCalls  []ToolCall `json:"tool_calls,omitzero"`   // assistant
	ToolCallID string     `json:"tool_call_id,omitzero"` // tool
}

// ToolCall is the model asking for a tool. Args is always a JSON object: when the model's arguments don't parse,
// the runtime sends {} with BadArgs set and the model's own text in RawArgs (CapRawArgs: at most MaxRawArgs bytes,
// cut with RawArgsCut), so the brain can tell the model and the next model call shows the model what it wrote.
type ToolCall struct {
	ID      string         `json:"id"`
	Name    string         `json:"name"`
	Args    jsontext.Value `json:"args"`
	BadArgs bool           `json:"bad_args,omitzero"`
	RawArgs string         `json:"raw_args,omitzero"` // only with BadArgs
}

// RawArgsCut ends raw_args that were cut to MaxRawArgs.
const RawArgsCut = "...[truncated]"

// CapRawArgs is the raw_args for a model's unparsable arguments: valid UTF-8 (invalid bytes become U+FFFD), at most
// MaxRawArgs bytes, ending in RawArgsCut when cut.
func CapRawArgs(s string) string {
	s = strings.ToValidUTF8(s, "\uFFFD")
	if len(s) <= MaxRawArgs {
		return s
	}
	return capText(s, MaxRawArgs-len(RawArgsCut)) + RawArgsCut
}

// ModelCall asks the runtime's model gateway for one completion.
type ModelCall struct {
	Model    string    `json:"model"`
	Messages []Message `json:"messages"`
	Tools    []string  `json:"tools,omitzero"` // names from start.tools offered to the model
	// ReasoningEffort is what the brain asks for. The person's choice for the task caps it: a brain may ask for
	// less, never more; more is clamped to the person's choice, not refused (ModelResult.ReasoningEffort).
	ReasoningEffort string `json:"reasoning_effort,omitzero"`
}

// ModelResult is the assembled completion (the runtime streams to people itself; the brain gets the whole).
type ModelResult struct {
	Message      Message `json:"message"` // role assistant
	FinishReason string  `json:"finish_reason"`
	Usage        Usage   `json:"usage"`
	// ReasoningEffort is the effort the gateway applied ("" for the model's default). Lower than the brain asked
	// for when the person's choice clamped it; the journal keeps it with the result.
	ReasoningEffort string `json:"reasoning_effort,omitzero"`
}

// Usage is token counts.
type Usage struct {
	Prompt     int `json:"prompt"`
	Completion int `json:"completion"`
}

// Action proposes one typed action (a guard connector). The request id is its outbox key: it runs at most once.
type Action struct {
	Name string         `json:"name"`
	Args jsontext.Value `json:"args"` // JSON object, checked by the connector
	// Call is the model tool call this action carries out: the id of a tool call with the same name in the task's
	// latest model.call result. The runtime refuses an action without one (not_requested), so every action traces
	// back to the model asking for it, shows people the result under that call and records the link.
	Call string `json:"call,omitzero"`
}

// Action outcomes. A refusal by policy is an outcome the model should see, not a protocol error.
const (
	ActionDone   = "done"
	ActionFailed = "failed"
	ActionDenied = "denied"
)

// ActionResult is what the guard did. Output is untrusted data (it may come from the web or a firm's systems).
type ActionResult struct {
	Status string         `json:"status"`
	Output jsontext.Value `json:"output,omitzero"`
	Error  string         `json:"error,omitzero"`
}

// Exec runs a command in the task's hands sandbox (no network, no keys).
type Exec struct {
	Argv      []string `json:"argv"`
	Stdin     string   `json:"stdin,omitzero"`
	TimeoutMs int      `json:"timeout_ms,omitzero"` // default 60 s, max MaxExecTimeout
}

// ExecResult is the command's outcome; output is capped by the runtime.
type ExecResult struct {
	Exit      int    `json:"exit"`
	Stdout    string `json:"stdout"`
	Stderr    string `json:"stderr"`
	Truncated bool   `json:"truncated,omitzero"`
	TimedOut  bool   `json:"timed_out,omitzero"`
}

// Checkpoint is the brain's own state, stored by the runtime (encrypted to the space key) and handed back in
// start when the task resumes. Opaque to the runtime.
type Checkpoint struct {
	Seq          int    `json:"seq"`           // 1, 2, ... per task; the runtime refuses anything else
	SteerApplied int    `json:"steer_applied"` // highest steer n already folded into State
	State        []byte `json:"state"`         // base64 in JSON
}

// Status is a progress note for people ("searching the web"). Display-only, untrusted, no reply. (People's steps
// come from the runtime: one per fresh model call.)
type Status struct {
	Note string `json:"note"`
}

// Task outcomes in done.
const (
	OutcomeSucceeded = "succeeded"
	OutcomeFailed    = "failed"
	OutcomeCancelled = "cancelled"
)

// Done ends the task. Text is the answer for people (untrusted, display-only).
type Done struct {
	Outcome string `json:"outcome"`
	Text    string `json:"text,omitzero"`
	Error   string `json:"error,omitzero"`
}

// Empty is the result body of checkpoint and done.
type Empty struct{}

// ---- validation: every body from the other side passes validate() before use ----------------------------------

func (h *Hello) validate() error {
	if len(h.Protocols) == 0 || len(h.Protocols) > 8 {
		return errf("protocols must have 1 to 8 entries")
	}
	for _, p := range h.Protocols {
		if p == "" || len(p) > 32 {
			return errf("bad protocol name")
		}
	}
	if err := h.Brain.validate(); err != nil {
		return err
	}
	if h.MaxFrame < MinFrame || h.MaxFrame > MaxFrame {
		return errf("max_frame must be %d to %d", MinFrame, MaxFrame)
	}
	if h.MaxTasks < 1 || h.MaxTasks > 256 {
		return errf("max_tasks must be 1 to 256")
	}
	return nil
}

func (i *Info) validate() error {
	if !printable(i.Name, 64) || !printable(i.Version, 64) || i.Name == "" {
		return errf("bad name or version")
	}
	return nil
}

func (w *Welcome) validate() error {
	if w.Protocol == "" || len(w.Protocol) > 32 {
		return errf("bad protocol")
	}
	if err := w.Runtime.validate(); err != nil {
		return err
	}
	l := w.Limits
	if l.MaxFrame < MinFrame || l.MaxFrame > MaxFrame || l.MaxTasks < 1 || l.MaxInflight < 1 || l.IdleTimeoutMs < 1 ||
		l.CancelGraceMs < 1 || l.MaxCheckpoint < 1 || l.MaxCheckpoint > MaxCheckpoint {
		return errf("bad limits")
	}
	return nil
}

func (s *Start) validate() error {
	if !ValidID(s.Space) || (s.Parent != "" && !ValidID(s.Parent)) || s.Attempt < 1 {
		return errf("bad space, parent or attempt")
	}
	if !ValidID(s.Agent.ID) || !printable(s.Agent.Version, 64) || !printable(s.Agent.Digest, 128) {
		return errf("bad agent")
	}
	if len(s.Models) == 0 || len(s.Models) > 16 {
		return errf("models must have 1 to 16 entries")
	}
	for _, m := range s.Models {
		if !printable(m, 64) || m == "" {
			return errf("bad model name")
		}
	}
	if len(s.Tools) > MaxTools {
		return errf("too many tools")
	}
	seen := map[string]bool{}
	for _, t := range s.Tools {
		// Two tools the model would see under one name (web.search and web_search) are refused too.
		if !ValidName(t.Name) || seen[ModelToolName(t.Name)] || len(t.Description) > 4096 || t.Parameters.Kind() != '{' {
			return errf("bad tool %q", t.Name)
		}
		seen[ModelToolName(t.Name)] = true
	}
	if err := validMessages(s.Input, 0); err != nil {
		return err
	}
	if s.Limits.MaxSteps < 1 || s.Limits.MaxModelCalls < 1 {
		return errf("bad task limits")
	}
	if s.Limits.Deadline != "" {
		if _, err := time.Parse(time.RFC3339, s.Limits.Deadline); err != nil {
			return errf("bad deadline")
		}
	}
	if s.Checkpoint != nil {
		if err := s.Checkpoint.validate(); err != nil {
			return err
		}
	}
	return nil
}

func (s *Steer) validate() error {
	if s.N < 1 || s.Text == "" || len(s.Text) > MaxSteerText {
		return errf("bad steer")
	}
	return nil
}

func (c *Cancel) validate() error {
	if !printable(c.Reason, 64) {
		return errf("bad reason")
	}
	return nil
}

var roles = map[string]bool{"system": true, "user": true, "assistant": true, "tool": true}

// validMessages checks a message list; min is the fewest messages allowed. There is no count cap: the frame
// (MaxFrame) and checkpoint (MaxCheckpoint) sizes bound a conversation.
func validMessages(ms []Message, min int) error {
	if len(ms) < min {
		return errf("messages must have at least %d entries", min)
	}
	for _, m := range ms {
		if err := m.validate(); err != nil {
			return err
		}
	}
	return nil
}

func (m *Message) validate() error {
	if !roles[m.Role] {
		return errf("bad role")
	}
	if len(m.ToolCalls) > 0 && m.Role != "assistant" || len(m.ToolCalls) > MaxToolCalls {
		return errf("tool_calls only on assistant messages, at most %d", MaxToolCalls)
	}
	if (m.Role == "tool") != (m.ToolCallID != "") || (m.ToolCallID != "" && !printable(m.ToolCallID, 64)) {
		return errf("tool messages need a tool_call_id, others none")
	}
	for _, c := range m.ToolCalls {
		if !printable(c.ID, 64) || c.ID == "" || !printable(c.Name, 64) || c.Name == "" || c.Args.Kind() != '{' ||
			len(c.Args) > MaxArgs || len(c.RawArgs) > MaxRawArgs || (c.RawArgs != "" && !c.BadArgs) {
			return errf("bad tool call")
		}
	}
	return nil
}

func (m *ModelCall) validate() error {
	if m.Model == "" || !printable(m.Model, 64) || !printable(m.ReasoningEffort, 16) {
		return errf("bad model or reasoning_effort")
	}
	if len(m.Tools) > MaxTools {
		return errf("too many tools")
	}
	for _, t := range m.Tools {
		if !ValidName(t) {
			return errf("bad tool name")
		}
	}
	return validMessages(m.Messages, 1)
}

func (m *ModelResult) validate() error {
	if m.Message.Role != "assistant" || !printable(m.FinishReason, 32) || !printable(m.ReasoningEffort, 16) ||
		m.Usage.Prompt < 0 || m.Usage.Completion < 0 {
		return errf("bad model result")
	}
	return m.Message.validate()
}

func (a *Action) validate() error {
	if !ValidName(a.Name) || a.Args.Kind() != '{' || len(a.Args) > MaxArgs {
		return errf("action needs a name and an object of args (at most %d bytes)", MaxArgs)
	}
	if !printable(a.Call, 64) {
		return errf("bad call")
	}
	return nil
}

func (a *ActionResult) validate() error {
	switch a.Status {
	case ActionDone, ActionFailed, ActionDenied:
	default:
		return errf("bad action status")
	}
	if len(a.Error) > MaxErrorText {
		return errf("error too long")
	}
	return nil
}

func (x *Exec) validate() error {
	if len(x.Argv) == 0 || len(x.Argv) > MaxArgv || len(x.Stdin) > MaxStdin || x.TimeoutMs < 0 ||
		time.Duration(x.TimeoutMs)*time.Millisecond > MaxExecTimeout {
		return errf("bad exec: 1 to %d argv entries, stdin at most %d bytes, timeout at most %s", MaxArgv, MaxStdin, MaxExecTimeout)
	}
	for _, a := range x.Argv {
		if len(a) > 4096 || strings.ContainsRune(a, 0) {
			return errf("bad argv entry")
		}
	}
	return nil
}

func (x *ExecResult) validate() error { return nil }

func (c *Checkpoint) validate() error { return c.check(MaxCheckpoint) }

// check is validate with the runtime's own (possibly lower) cap on state.
func (c *Checkpoint) check(max int) error {
	if c.Seq < 1 || c.SteerApplied < 0 || len(c.State) > max {
		return errf("checkpoint needs seq >= 1, steer_applied >= 0, state at most %d bytes", max)
	}
	return nil
}

func (s *Status) validate() error {
	if s.Note == "" || len(s.Note) > MaxNote {
		return errf("status note of 1 to %d bytes", MaxNote)
	}
	return nil
}

func (d *Done) validate() error {
	switch d.Outcome {
	case OutcomeSucceeded, OutcomeFailed, OutcomeCancelled:
	default:
		return errf("bad outcome")
	}
	if len(d.Text) > MaxDoneText || len(d.Error) > MaxErrorText {
		return errf("done text at most %d bytes, error at most %d", MaxDoneText, MaxErrorText)
	}
	return nil
}

func (Empty) validate() error { return nil }

// ValidID reports whether s is a valid task, space or request id: 1-64 of [A-Za-z0-9._:-], starting with a letter
// or digit.
func ValidID(s string) bool {
	if len(s) == 0 || len(s) > 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case i > 0 && (c == '.' || c == '_' || c == ':' || c == '-'):
		default:
			return false
		}
	}
	return true
}

// ValidName reports whether s is a valid action or tool name: lowercase dotted segments, e.g. "mail.send".
func ValidName(s string) bool {
	if len(s) == 0 || len(s) > 64 {
		return false
	}
	for _, seg := range strings.Split(s, ".") {
		if seg == "" || seg[0] < 'a' || seg[0] > 'z' {
			return false
		}
		for i := 0; i < len(seg); i++ {
			c := seg[i]
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_') {
				return false
			}
		}
	}
	return true
}

// ModelToolName is the name the model sees for tool name: dots become underscores ("web.search" -> "web_search"),
// since OpenAI-style function names allow only letters, digits, "_" and "-". Start refuses two tools with the same
// model name, so the runtime maps a model's tool call back to exactly one action name.
func ModelToolName(name string) string { return strings.ReplaceAll(name, ".", "_") }

// printable: at most max bytes, no control characters (labels, names, short fields).
func printable(s string, max int) bool {
	if len(s) > max {
		return false
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

func capText(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return strings.ToValidUTF8(s[:max], "") // drops a rune cut in half
}

func errf(format string, args ...any) *Error { return Errf(CodeBadFrame, format, args...) }
