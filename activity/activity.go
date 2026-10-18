// Package activity is the agent VM's recorder (docs/24-activity-records.md): signed, hash-chained activity
// records of what each agent run did, sealed to whoever may read them, written inside the attested VM.
//
// A record is a small public header plus a sealed body:
//
//   - the header (JSON, kept as the exact bytes that were signed): format version, chain id, sequence number, the
//     previous record's hash, time (seconds), the signing key, the recipient key, the HPKE encapsulated key, and
//     the ciphertext's SHA-256 and length. Nothing else: no run id, space, model, host or kind of event;
//   - the signature: Ed25519 over "tacy-activity/v1\x00" || header, by a key that only exists inside the attested
//     VM (derived from dstack's KMS for this app and firm, see Key);
//   - the body (JSON, Run): sealed with HPKE (RFC 9180 base mode, DHKEM(X25519, HKDF-SHA256), HKDF-SHA256,
//     AES-256-GCM: the suite EHBP uses) to the recipient's X25519 key, with the chain id and sequence number as
//     associated data, so a body can't be moved under another header.
//
// A record's hash is SHA-256("tacy-activity/v1\x00" || header); the next record of the same chain names it in
// prev. A chain is one recipient in one space (ChainID): with space keys every space has one recipient, so a chain
// is a space's history. Anyone holding the records (our servers, an auditor) can check the signatures and the
// links without the recipient's key (VerifyChain); only the recipient can read the bodies (Open). A removed,
// reordered, edited or forged record fails the check.
//
// What a body holds (Run): the run's trigger, agent, the signed controls it started under (policy hashes, stop
// list numbers), the models and tools it was allowed, then each model call and action (kind, name, connector,
// hosts with request counts and byte sizes, outcome, timing), each key lease (secret name, connector, host,
// decision, never a value), the budget it used, why a control stopped it, and its final status. Never content:
// no prompt, answer, search query, URL path, page text or tool argument.
package activity

import (
	"maps"
	"time"
)

// Label prefixes every signed and hashed byte string and names the HPKE context.
const Label = "tacy-activity/v1"

// Version is the header format.
const Version = 1

// BodyType names the body format.
const BodyType = "tacy.activity.run/v1"

// Events a body records. A run has a start and an end record; a run refused before it started has one refused
// record; a run whose process died has its end written as interrupted by the next process.
const (
	EventStart       = "start"
	EventEnd         = "end"
	EventRefused     = "refused"
	EventInterrupted = "interrupted"
)

// Header is a record's public part. It is signed as the exact bytes that travel (Sealed.Header).
type Header struct {
	V      int    `json:"v"`
	Chain  string `json:"chain"`     // ChainID: 32 hex
	Seq    uint64 `json:"seq"`       // 1, 2, ... per chain
	Prev   string `json:"prev"`      // hash of record seq-1 (64 hex); "" for seq 1
	Time   int64  `json:"time"`      // unix seconds
	Key    string `json:"key"`       // signer: "ed25519:<base64>"
	To     string `json:"to"`        // recipient: "x25519:<base64>"
	Enc    string `json:"enc"`       // HPKE encapsulated key, base64
	CTHash string `json:"ct_sha256"` // SHA-256 of the ciphertext, hex
	CTLen  int    `json:"ct_len"`
}

// Sealed is one record as it is stored and sent: base64 of the header bytes, the signature and the ciphertext.
type Sealed struct {
	Header string `json:"header"`
	Sig    string `json:"sig"`
	CT     string `json:"ct"`
}

// Run is a record's body: one event of one run.
type Run struct {
	Type  string `json:"type"`  // BodyType
	Event string `json:"event"` // start | end | refused | interrupted
	Chain string `json:"chain"` // repeated from the header (and bound to it by the AEAD's associated data)
	Seq   uint64 `json:"seq"`
	Run   string `json:"run"` // the task id
	Space string `json:"space"`

	// start and refused
	Agent    *Agent    `json:"agent,omitzero"`
	Trigger  *Trigger  `json:"trigger,omitzero"`
	Controls *Controls `json:"controls,omitzero"`
	Models   []string  `json:"models,omitzero"` // models the run may call
	Tools    []string  `json:"tools,omitzero"`  // actions the run may propose
	Limits   *Limits   `json:"limits,omitzero"`
	Input    *Input    `json:"input,omitzero"`
	Started  time.Time `json:"started,omitzero"`

	// end, refused and interrupted
	Ended  time.Time `json:"ended,omitzero"`
	Status *Status   `json:"status,omitzero"`
	Calls  []Call    `json:"calls,omitzero"`
	Leases []Lease   `json:"leases,omitzero"`
	Usage  *Usage    `json:"usage,omitzero"`
	Steps  int       `json:"steps,omitzero"`
	// Background is egress that belongs to the run but no single call: the sources' site icons.
	Background []Host `json:"background,omitzero"`
	// BackgroundImages: image search pictures that failed or never landed after their call's result (late images).
	BackgroundImages *Images `json:"background_images,omitzero"`
	// StartSeq is the sequence number of the run's start record in this chain (end, interrupted).
	StartSeq uint64 `json:"start_seq,omitzero"`
	// Tainted (end): the run received outside content (web pages, search results), so anything it proposed after that
	// is marked tainted (docs/27 section 5).
	Tainted bool `json:"tainted,omitzero"`
}

// Agent identifies the agent definition the run ran.
type Agent struct {
	ID      string `json:"id"`
	Version string `json:"version"`
	Digest  string `json:"digest"`
}

// Trigger says what started the run.
type Trigger struct {
	Kind string `json:"kind"`          // "chat": a person's browser, through the relay
	Via  string `json:"via,omitempty"` // "relay"
}

// Controls are the signed controls the run started under (the safety documents' hashes and numbers).
type Controls struct {
	Policy        []string `json:"policy,omitzero"`
	ReleasePolicy string   `json:"release_policy,omitzero"`
	OperatorSeq   uint64   `json:"operator_seq,omitzero"`
	FirmSeq       uint64   `json:"firm_seq,omitzero"`
	Fresh         bool     `json:"stop_list_fresh"`
}

// Limits are the run's own limits.
type Limits struct {
	MaxSteps      int    `json:"max_steps,omitzero"`
	MaxModelCalls int    `json:"max_model_calls,omitzero"`
	Deadline      string `json:"deadline,omitzero"`
}

// Input is the size of what the run was given (never the content).
type Input struct {
	Messages int `json:"messages"`
	Bytes    int `json:"bytes"`
}

// Status is how a run ended.
type Status struct {
	State  string `json:"state"`           // succeeded | failed | cancelled | refused | interrupted
	Code   string `json:"code,omitzero"`   // the safety control that ended or refused it (stopped, budget_exceeded, ...)
	Reason string `json:"reason,omitzero"` // a cancel's reason: person, deadline, kill_switch, restart
	Finish string `json:"finish,omitzero"` // the model's last finish reason
	Detail string `json:"detail,omitzero"` // the control's rule, in its own words (never content)
}

// Call is one model call, action or exec the runtime handed to the guard.
type Call struct {
	ID         string `json:"id"`   // the brain's request id (the journal's)
	Kind       string `json:"kind"` // model | action | exec
	Name       string `json:"name"` // the model, or the action (web.search, web.fetch, web.images, ...)
	Connector  string `json:"connector,omitzero"`
	Hosts      []Host `json:"hosts,omitzero"`
	Outcome    string `json:"outcome"`             // ok | failed | denied | refused | cancelled
	Code       string `json:"code,omitzero"`       // a protocol or safety code when it didn't go through
	AtMs       int64  `json:"at_ms"`               // since the run started
	Ms         int64  `json:"ms"`                  // how long it took
	ReqBytes   int    `json:"req_bytes"`           // the request's size as the brain sent it
	RespBytes  int    `json:"resp_bytes"`          // the result's size as the brain got it
	Prompt     int    `json:"prompt,omitzero"`     // model: prompt tokens
	Completion int    `json:"completion,omitzero"` // model: completion tokens
	// Leak-scan decisions on this call: pattern ids only, never the match.
	Blocked  []string `json:"blocked,omitzero"`
	Redacted []string `json:"redacted,omitzero"`
	// Taint (docs/27 section 5): Untrusted, this call's result brought outside content to the agent (a page, search
	// results); Tainted, the run had already received outside content when the agent proposed this call.
	Untrusted bool `json:"untrusted,omitzero"`
	Tainted   bool `json:"tainted,omitzero"`
	// Reader is the quarantined reader's model call for this action (a page or search results read for the agent).
	Reader *Reader `json:"reader,omitzero"`
	// Permission is how the person's permission for an action that sends data out was given: allowed_once,
	// allowed_always, always_setting (not asked: their setting), denied, timed_out, never (not asked: off in their
	// settings), unavailable (the run couldn't ask). Edited: they changed what was sent. Never the value itself.
	Permission string `json:"permission,omitzero"`
	Edited     bool   `json:"edited,omitzero"`
	// Images (web.images): the pictures that didn't make it, by reason. Fixed words and counts only.
	Images *Images `json:"images,omitzero"`
}

// Images counts an image search's pictures that didn't make it, by reason: blocked, timeout, format, size,
// unreachable (a download that failed), never_arrived (a gallery slot that stayed empty when the run ended).
type Images struct {
	Failed  int            `json:"failed"`
	Reasons map[string]int `json:"reasons"`
}

// Clone is a copy (nil for nil).
func (m *Images) Clone() *Images {
	if m == nil {
		return nil
	}
	return &Images{Failed: m.Failed, Reasons: maps.Clone(m.Reasons)}
}

// Add is m with o's counts added (m is changed when not nil; nil when both are).
func (m *Images) Add(o *Images) *Images {
	if o == nil || o.Failed == 0 && len(o.Reasons) == 0 {
		return m
	}
	if m == nil {
		m = &Images{}
	}
	m.Failed += o.Failed
	for r, n := range o.Reasons {
		if m.Reasons == nil {
			m.Reasons = map[string]int{}
		}
		m.Reasons[r] += n
	}
	return m
}

// Reader is one quarantined reader call: numbers and fixed words only.
type Reader struct {
	Model      string `json:"model"`
	Prompt     int    `json:"prompt"`
	Completion int    `json:"completion"`
	Ms         int64  `json:"ms"`
	Outcome    string `json:"outcome"`      // ok | refused | failed
	Why        string `json:"why,omitzero"` // refused: schema, span, tool_call, length, empty; failed: policy, model, timeout; ok: cached
	// Quotes kept and dropped (not found in the source), injections the reader counted, verbatim passages cut.
	Quotes       int `json:"quotes,omitzero"`
	Dropped      int `json:"dropped,omitzero"`
	Instructions int `json:"instructions,omitzero"`
	Verbatim     int `json:"verbatim,omitzero"`
}

// Host is egress to one host: requests made (and refused by the policy before connecting) and bytes each way.
type Host struct {
	Host     string `json:"host"`
	Requests int    `json:"requests"`
	Refused  int    `json:"refused,omitzero"`
	BytesOut int64  `json:"bytes_out"`
	BytesIn  int64  `json:"bytes_in"`
}

// Lease is one key lease the vault decided for a call: names only, never the value.
type Lease struct {
	Call      string `json:"call"` // the call's request id
	Secret    string `json:"secret"`
	Connector string `json:"connector"`
	Host      string `json:"host"`
	Decision  string `json:"decision"` // released | denied
	Reason    string `json:"reason,omitzero"`
	Lease     string `json:"lease,omitzero"`
}

// Usage is the budget the run used.
type Usage struct {
	Tokens     int64 `json:"tokens"`
	ToolCalls  int64 `json:"tool_calls"`
	CostMicros int64 `json:"cost_usd_micros"`
	WallMs     int64 `json:"wall_ms"`
}
