// Package proto is the agent VM's wire format, shared by the service (compiled into the CVM) and its verifiers.
// Standard library only.
package proto

import (
	"crypto/sha512"
	"encoding/json"
)

// Version names this wire format. It is part of the report_data hash, so a quote for another format can't be
// replayed as this one.
const Version = "sealed-agent-vm/v1"

// HPKESuite is the only EHBP suite the service offers (RFC 9180 ids 0x0020/0x0001/0x0002).
const HPKESuite = "DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 / AES-256-GCM"

// ReportData is the 64-byte TDX report_data the service asks dstack to put in its quote:
//
//	sha512("sealed-agent-vm/v1" || 0x00 || nonce (32 bytes) || hpke_public_key (32 bytes, raw X25519))
//
// The nonce is the verifier's fresh random value; the key is this boot's EHBP key. dstack passes 64 bytes through
// unchanged (no prefix or hashing) when given exactly 64.
func ReportData(nonce, hpkePublicKey []byte) []byte {
	h := sha512.New()
	h.Write([]byte(Version))
	h.Write([]byte{0})
	h.Write(nonce)
	h.Write(hpkePublicKey)
	return h.Sum(nil)
}

// Attestation is the GET /attest?nonce=<64 hex> response.
type Attestation struct {
	Version       string `json:"version"`         // Version
	Platform      string `json:"platform"`        // "dstack" (Phala, or dstack on Google Cloud); "local" in dev mode
	Nonce         string `json:"nonce"`           // the verifier's nonce, echoed (hex)
	HPKEPublicKey string `json:"hpke_public_key"` // this boot's EHBP key: raw X25519, hex
	HPKESuite     string `json:"hpke_suite"`
	// Quote is dstack's GetQuote response as returned by the guest agent: {"quote": hex, "event_log": JSON string,
	// "vm_config": JSON string, ...}.
	Quote json.RawMessage `json:"quote,omitempty"`
	// Info is dstack's Info response: {"app_id", "instance_id", "tcb_info": JSON string with "app_compose", ...}.
	Info json.RawMessage `json:"info,omitempty"`
	// Booted is when this process started (RFC 3339, from the CVM's clock; informational).
	Booted string `json:"booted"`
}

// Message is one chat message. Only plain text content: earlier tool calls come back as assistant text.
type Message struct {
	Role    string `json:"role"` // system | user | assistant
	Content string `json:"content"`
}

// DefaultModel is the model a run gets when its request names none.
const DefaultModel = "gpt-oss-120b"

// RunRequest is the (EHBP-encrypted) POST /run body. POST /run also needs the model in plaintext, in the
// X-Agent-Model header; the VM refuses a run whose body names another model.
type RunRequest struct {
	Model           string    `json:"model"`                      // a Tinfoil chat model id; default gpt-oss-120b
	Messages        []Message `json:"messages"`                   // the conversation, oldest first
	ReasoningEffort string    `json:"reasoning_effort,omitempty"` // passed to the model as is (it must accept it)
	Tools           []string  `json:"tools,omitempty"`            // subset of web_search, fetch_page; nil = all
	MaxSteps        int       `json:"max_steps,omitempty"`        // model calls per run; default 6, max 10
	// CacheSecret scopes Tinfoil's prompt cache (user_cache_secret); the chat sends its per-user secret.
	// When empty, a per-boot random secret is used.
	CacheSecret string `json:"cache_secret,omitempty"`
	// RecordTo is the X25519 key the run's activity record is sealed to ("x25519:<base64>", docs/24): the
	// person's own activity key until spaces have keys. Without one the run isn't recorded.
	RecordTo string `json:"record_to,omitempty"`
	// RecordProof shows the sender holds RecordTo's private key (activity.RecordProof, base64): without it the VM
	// refuses a run that names record_to.
	RecordProof []byte `json:"record_proof,omitempty"`
	// RunSecret is this run's answer key for permission prompts (docs/27 section 6): 32 random bytes as 64
	// lowercase hex, made by the person's tab and sent only inside this encrypted body. A grant (POST /tasks/grant)
	// carries an HMAC with it, so only that tab can answer the run's prompts; the relay can't read or forge one.
	// Without it nothing can be asked, so kinds on Ask are refused. Until people have identity keys.
	RunSecret string `json:"run_secret,omitempty"`
	// Permissions are the person's settings per kind of outgoing data: "web.search", "web.fetch",
	// "web.images" -> "ask" | "always" | "never". A kind not named is "ask". A firm's policy may cap them.
	Permissions map[string]string `json:"permissions,omitempty"`
	// FallbackModels are the models the run may switch to when its model is slow or overloaded, in the chat's order
	// (the browser fills them from the plan; the VM never reorders them). The VM keeps only those its signed policy
	// and its own model list allow, not the run's model, no duplicates, at most 5; the others are dropped silently.
	// Used only with AutoFallback.
	FallbackModels []string `json:"fallback_models,omitempty"`
	// AutoFallback: the person chose Auto, so a step whose model is slow (no first token in time) or overloaded is
	// retried once on the first allowed fallback (model_slow, model_switched). False for a hand-picked model: a slow
	// one is waited for, an overloaded one ends the run (code model_overloaded).
	AutoFallback bool `json:"auto_fallback,omitempty"`
}

// Event is one server-sent event in the (EHBP-encrypted) /run response: `data: <json>\n\n`, ending with
// `data: [DONE]`. Types and how they map onto assistant-ui message parts:
//
//	queue        the run waits for a free slot: position (1 = next); repeated when it changes (and every few
//	             seconds), none once the run starts. A run that never gets a slot ends with an error event.
//	meta         first event once the run starts: model, Tinfoil enclave and release that were verified
//	step         a model call starts (step = 1, 2, ...)
//	reasoning    delta of the reasoning trace            -> { type: "reasoning", text }
//	text         delta of the answer                     -> { type: "text", text }
//	tool_call    the model called a tool (args final)    -> { type: "tool-call", toolCallId: id, toolName: name, args }
//	image        image_search: one image it found, fetched and re-encoded in the VM (id = the tool call). Sent
//	             before that call's tool_result, in order (Image)
//	tool_result  the tool's output as the model sees it  -> same part, result: result (+ citations as sources)
//	favicon      a source site's icon, fetched and re-encoded in the VM (Favicon); sent whenever one is ready,
//	             at most one per site and maxIconHosts per run, never before the tool_result that named the site
//	usage        token counts, summed over all steps so far
//	metrics      timing of one model call or tool call that just ended, or of the queue when the run started
//	             (Metric): numbers and fixed names only
//	activity     the run's sealed activity records (Activity), right before done or error
//	permission   a tool call that would send data out of the VM waits for the person: id is the tool call,
//	             permission has the kind and exactly what would go out. Sent again with permission.decision once
//	             it is settled (allowed_once, allowed_always, denied, timed_out, never, unavailable). Never sent
//	             for a kind set to Always allow.
//	model_slow   a model call (step) got no first token in time (20 s, more for big requests), or the provider
//	             answered 503/429 or "overloaded": model, waited_ms, fallback (the model the step switches to; empty
//	             when there is none or the run isn't on Auto). Once per step at most; the provider's own text is never
//	             sent. Without a switch a slow call is still waited for.
//	model_switched  Auto only: the slow or overloaded call was given up and the step runs again, once, on the
//	             fallback: from, to. Later steps of the run go straight to it; it is never switched again.
//	error        a fatal error; the stream ends after it. code says when a safety control ended the run, or
//	             model_overloaded (a hand-picked model was overloaded: the provider's side; error is our own words)
//	done         finish_reason and step count; last event before [DONE]
type Event struct {
	Type      string          `json:"type"`
	Step      int             `json:"step,omitempty"`
	Position  int             `json:"position,omitempty"` // queue: place in the queue, 1 = next
	Delta     string          `json:"delta,omitempty"`
	ID        string          `json:"id,omitempty"`
	Name      string          `json:"name,omitempty"`
	Args      json.RawMessage `json:"args,omitempty"`
	Masked    []string        `json:"masked,omitempty"` // PII kinds replaced before the query left the VM
	Result    json.RawMessage `json:"result,omitempty"`
	Citations []Citation      `json:"citations,omitempty"`
	// Quotes: tool_result of a source the quarantined reader read (docs/27 section 5): the exact passages the
	// answer may cite as [quote N]. The acting model never sees their text; the browser shows it.
	Quotes  []Quote  `json:"quotes,omitempty"`
	Image   *Image   `json:"image,omitempty"`
	Favicon *Favicon `json:"favicon,omitempty"`
	Usage   *Usage   `json:"usage,omitempty"`
	Meta    *Meta    `json:"meta,omitempty"`
	Metrics *Metric  `json:"metrics,omitempty"`
	Error   string   `json:"error,omitempty"`
	Code    string   `json:"code,omitempty"` // error: why a safety control ended the run (stopped, stop_list_stale, policy_missing, policy_denied, budget_exceeded, rate_limited), or model_overloaded
	// Activity: the run's sealed activity records (its start and end, or the one record of a refused run), sent
	// right before done or error. Each is signed by Meta.Activity.Key and sealed to RunRequest.RecordTo.
	Activity     []json.RawMessage `json:"activity,omitempty"`
	FinishReason string            `json:"finish_reason,omitempty"`
	// Permission: a permission prompt or its outcome.
	Permission *Permission `json:"permission,omitempty"`
	// model_slow: the model that was slow or overloaded, how long the call had waited, and the model the step
	// switches to ("" when none). model_switched: from, to.
	Model    string `json:"model,omitempty"`
	WaitedMs int64  `json:"waited_ms,omitempty"`
	Fallback string `json:"fallback,omitempty"`
	From     string `json:"from,omitempty"`
	To       string `json:"to,omitempty"`
}

// Permission is a permission prompt: before data of a kind leaves the VM, the person allows it once, always (that kind,
// this run and their setting), or denies it. Value is exactly what would go out (a search's masked query, a page's
// address); the person may edit it before allowing. Untrusted model output: display only.
type Permission struct {
	Task     string `json:"task"`                // the task (grants name it)
	Request  string `json:"request"`             // the held request (grants name it)
	Kind     string `json:"kind"`                // web.search | web.fetch | web.images
	Value    string `json:"value"`               // what would go out
	Decision string `json:"decision,omitempty"`  // "": waiting; allowed_once | allowed_always | denied | timed_out | never | unavailable
	TimeoutS int    `json:"timeout_s,omitempty"` // waiting: seconds until no answer counts as denied
	Edited   bool   `json:"edited,omitempty"`    // settled: the person changed the value before allowing
	// Reason: why this prompt is shown although the person's setting is Always allow, in words for the person
	// (fixed in the release): a page fetch, after outside content, of an address the model composed.
	Reason string `json:"reason,omitempty"`
}

// Citation is a source a tool returned. Index is the [n] the model is told to cite.
type Citation struct {
	Index   int    `json:"index"`
	Title   string `json:"title"`
	URL     string `json:"url"`
	Snippet string `json:"snippet,omitempty"`
	Age     string `json:"age,omitempty"`
}

// Quote is an exact passage of a source, as the source has it (checked by the guard's code, not the reader's
// word). Untrusted web text: display only.
type Quote struct {
	ID       int    `json:"id"`       // the N of [quote N], per task
	Index    int    `json:"index"`    // the [n] of the source it is from (Citation.Index)
	Location string `json:"location"` // where in the source (the reader's words)
	Topic    string `json:"topic"`    // what it is about (the reader's words)
	Text     string `json:"text"`
}

// Image is one picture image_search shows: a JPEG the VM decoded, scaled to at most 1024 px and re-encoded from
// the pixels (no metadata of the original survives), with where it came from. Title and URLs are untrusted web
// text: display only.
type Image struct {
	Index  int    `json:"index"`            // 1, 2, ... within the call, in the order shown to the model
	Title  string `json:"title"`            // the provider's title or description
	Source string `json:"source,omitempty"` // the page the image is on, when known
	URL    string `json:"url"`              // the original image's URL (never loaded by the browser)
	Type   string `json:"type"`             // "image/jpeg"
	Width  int    `json:"width"`
	Height int    `json:"height"`
	Data   []byte `json:"data"` // the JPEG (base64 in JSON)
}

// Favicon is the icon of a site the run's sources are on: fetched by the VM (never by the browser, which would tell
// the site, or a favicon service, what the user read), decoded and re-encoded from the pixels as a 32x32 PNG, so
// nothing of the original file survives. Display only.
type Favicon struct {
	Host string `json:"host"` // the site: hostname, lowercase, without "www."
	Type string `json:"type"` // "image/png"
	Data []byte `json:"data"` // the PNG (base64 in JSON), 32x32
}

// Usage is token counts as the model reports them.
type Usage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
}

// Meta describes what the run used.
type Meta struct {
	Model          string   `json:"model"`
	TinfoilEnclave string   `json:"tinfoil_enclave"`     // host the model request goes to
	TinfoilRelease string   `json:"tinfoil_release"`     // signed release tag of tinfoilsh/confidential-model-router
	TinfoilMeasure string   `json:"tinfoil_measurement"` // SEV-SNP launch measurement, equal to the release's
	TinfoilHPKEKey string   `json:"tinfoil_hpke_key"`    // key the request was encrypted to
	Tools          []string `json:"tools"`
	// Controls are the signed controls the run started under (docs/23-safety-controls.md).
	Controls *Controls `json:"controls,omitempty"`
	// Activity says where the run's activity record goes (docs/24); nil when it isn't recorded.
	Activity *Activity `json:"activity,omitempty"`
}

// Activity names the key that signs this VM's activity records and the chain the run's records go to. It arrives
// in the meta event, which EHBP authenticates to the attested key: the browser learns the signing key from the
// attested VM itself, and the chain's head before this run (so records our servers keep can be checked for gaps
// and truncation).
type Activity struct {
	Key   string `json:"key"`   // "ed25519:<base64>": the VM's activity signing key (derived in the VM, never leaves it)
	Chain string `json:"chain"` // the chain id (32 hex)
	Seq   uint64 `json:"seq"`   // the chain's last sequence number before this run (0: none)
	Head  string `json:"head"`  // that record's hash ("" when seq is 0)
}

// Controls name the policy and stop lists a run ran under, so the browser can show which policy applied. Hashes
// are of the signed documents (safety.Envelope.Hash); none means the release's own default policy.
type Controls struct {
	Policy        []string `json:"policy,omitempty"`       // signed policy hashes: the firm's, then the space's
	ReleasePolicy string   `json:"release_policy"`         // hash of the release's ceiling policy
	OperatorSeq   uint64   `json:"operator_seq,omitempty"` // newest operator stop list held
	FirmSeq       uint64   `json:"firm_seq,omitempty"`     // newest firm stop list held
	Fresh         bool     `json:"stop_list_fresh"`        // the operator's list is fresh (side effects allowed)
}

// Metric is the timing of one part of a run, sent as a "metrics" event when that part ends (so a run cut short
// still reports what finished). The chat's browser decrypts it and reports the numbers for the admin's
// performance view. Numbers and fixed names only: never content, search queries, URLs or hosts.
type Metric struct {
	// Reasons (images): the failed downloads by why (blocked, timeout, format, size, unreachable), and never_arrived
	// for gallery slots kept for late images that hadn't landed when the run ended. Fixed words and counts only.
	Reasons map[string]int `json:"reasons,omitempty"`

	Kind       string `json:"kind"`                 // "model" (one model call), "search" (web_search), "fetch" (fetch_page), "images" (image_search), "favicons" (the run's site icons), "queue" (the run started), "reader" (the quarantined reader's call for a page or a search)
	Step       int    `json:"step"`                 // the model call this belongs to (1, 2, ...)
	Ms         int64  `json:"ms"`                   // duration in milliseconds (queue: time waiting for a slot, 0 if none)
	FirstMs    int64  `json:"first_ms,omitempty"`   // model: request sent -> first token (reasoning, text or a tool call)
	TextMs     int64  `json:"text_ms,omitempty"`    // model: request sent -> first answer text
	Prompt     int    `json:"prompt,omitempty"`     // model: prompt tokens (cached ones included)
	Cached     int    `json:"cached,omitempty"`     // model: prompt tokens served from Tinfoil's prompt cache
	Completion int    `json:"completion,omitempty"` // model: completion tokens (reasoning included)
	Provider   string `json:"provider,omitempty"`   // search: the provider that ran it (brave | tavily)
	Results    int    `json:"results,omitempty"`    // search: results returned; images: image candidates found; favicons: sites tried
	Images     int    `json:"images,omitempty"`     // images: images shown; favicons: icons sent
	Tried      int    `json:"tried,omitempty"`      // images: downloads tried (failed ones included)
	Failed     int    `json:"failed,omitempty"`     // images: downloads refused or failed (too big, wrong type, HTTP error); favicons: sites without a usable icon
	Bytes      int    `json:"bytes,omitempty"`      // images, favicons: re-encoded bytes sent
	FetchMs    int64  `json:"fetch_ms,omitempty"`   // images: download + decode + encode time, summed over the images tried; favicons: the same over the sites
	WaitMs     int64  `json:"wait_ms,omitempty"`    // search, fetch, images, favicons: time waiting for the per-user and global tool caps (not in ms)
	Running    int    `json:"running,omitempty"`    // queue: runs running on the VM when this one started, itself included
	Model      string `json:"model,omitempty"`      // model: the model this call went to
	Outcome    string `json:"outcome"`              // ok | error | refused (fetch: the URL held personal data) | slow_switched (model: given up as slow or overloaded, the step ran again on the fallback)
}
