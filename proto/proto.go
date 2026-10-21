// Package proto is the agent VM's wire format, shared by the service (compiled into the CVM) and its verifiers.
// Standard library only.
package proto

import (
	"crypto/sha512"
	"encoding/json"
	"time"
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

// Message is one chat message: plain text (earlier tool calls come back as assistant text), and on a person's
// message the pictures they attached.
type Message struct {
	Role    string `json:"role"` // system | user | assistant
	Content string `json:"content"`
	// Images are the person's own pictures with this message (releases since v0.12.0; only on a user message of a
	// chat run): JPEG data URLs ("data:image/jpeg;base64,..."), resized and re-encoded in their browser, which drops
	// EXIF and GPS. At most MaxRunImages per run, each at most MaxImageBytes decoded. They go to the run's model
	// when it can see images, and nowhere else: never into a search, a page fetch, an image search or any other
	// request (guard/images_in.go).
	Images []string `json:"images,omitempty"`
}

// The caps on a run's images (Message.Images). The request's encrypted body is capped too (8 MiB, agentd).
const (
	MaxRunImages  = 4         // per run, over all its messages
	MaxImageBytes = 512 << 10 // one image's JPEG bytes (the chat's own cap per image)
)

// ImageURLPrefix starts every image a run takes: only JPEG, as the chat sends it.
const ImageURLPrefix = "data:image/jpeg;base64,"

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
	// Where and who (keys v2 slice 6, docs/26 section 6; package runauth). Every run names its space and that
	// space's seal public key, with a proof made against this boot's attested key that the sender holds the seal
	// private key (which only the space's holders can open); the run's activity records are sealed to the seal key,
	// so the request can neither choose nor drop their recipient. On a firm's VM the seal key must be the one the
	// space's signed policy names; on the shared chat VM (personal spaces) it comes from the request, proven.
	Space      string `json:"space,omitempty"`       // "s_…"
	SpaceSeal  string `json:"space_seal,omitempty"`  // "x25519:<base64>"
	SpaceProof []byte `json:"space_proof,omitempty"` // runauth.SpaceProof (base64)
	// Identity signs the request (runauth.Digest) with this boot's VM key, Nonce (16 random bytes, 32 lowercase hex)
	// and SignedAt (unix seconds): a request runs at most once per boot. On a firm's VM the identity must be current
	// in the firm key log with IdentityKey; on the shared chat VM it is self-certified.
	Identity    string `json:"identity,omitempty"`     // "i_…"
	IdentityKey string `json:"identity_key,omitempty"` // "ed25519:<base64>"
	Nonce       string `json:"nonce,omitempty"`
	SignedAt    int64  `json:"signed_at,omitempty"`
	IdentitySig []byte `json:"identity_sig,omitempty"` // runauth.Sign (base64)
	// Verified is the agent VM's own note that it checked the above (never read from or written to the wire).
	Verified *Verified `json:"-"`
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
	// Agent names the built-in agent definition the task runs (docs/30-agents-in-chat.md): "a_chat" (the chat, also
	// when absent) or "a_research". The definitions (instructions, tools, limits) are compiled into the release
	// (guard/agents.go); a request only picks one, and an unknown one is refused. Covered by the run signature
	// (runauth) when set. A non-chat agent starts only through POST /tasks and takes one message: the brief.
	Agent string `json:"agent,omitempty"`
	// ChargedModel is the model the relay charged the run at (v0.16.0): its X-Agent-Price-Model header (checked to be
	// the dearest model the run may call, guard.CheckCharge), or X-Agent-Model when there is none (a tab before it). A
	// fallback dearer than it is dropped, so a run never switches to a model it wasn't charged for. Set by agentd
	// from the headers, never read from or written to the wire; "": nothing dropped (in-process tests, scheduled runs).
	ChargedModel string `json:"-"`
}

// SearchRequest is POST /search's body: the plain chat's one web search the person allowed in their tab (docs/29;
// agentd app/search.go, guard/searchtask.go). EHBP-encrypted; strict JSON, nothing else accepted.
type SearchRequest struct {
	// Query is exactly what the person allowed in their tab (the model's query, masked there, or their edit). The
	// VM masks it again (guard.maskPII) before it goes out, as every search.
	Query string `json:"query"`
	// Count is how many results to ask for: 1 to 8, default 5.
	Count int `json:"count,omitzero"`
	// Question is the person's last message (capped), what the reader reads the results for, as in agent mode. It
	// never goes to the search provider. "": the query.
	Question string `json:"question,omitzero"`
	// Decision is how the person allowed it, for the activity record: "once" (Allow once), "always" (Always allow,
	// on this prompt) or "setting" (not asked: their setting for web search is Always allow).
	Decision string `json:"decision"`
	// Edited: the person changed the model's query in the prompt (for the record).
	Edited bool `json:"edited,omitzero"`
	// CacheSecret scopes Tinfoil's prompt cache for the reader's call (RunRequest.CacheSecret).
	CacheSecret string `json:"cache_secret,omitzero"`
	// Where and who, as for a run (RunRequest; keys v2 slice 6, v0.10.0): the space, its seal key and proof, and the
	// identity's signature (runauth.SearchDigest, its own label, so a run's signature can't pass as a search's or
	// the reverse). The search's record is sealed to the seal key; record_to and record_proof are gone.
	Space       string `json:"space,omitzero"`
	SpaceSeal   string `json:"space_seal,omitzero"`
	SpaceProof  []byte `json:"space_proof,omitzero"`
	Identity    string `json:"identity,omitzero"`
	IdentityKey string `json:"identity_key,omitzero"`
	Nonce       string `json:"nonce,omitzero"`
	SignedAt    int64  `json:"signed_at,omitzero"`
	IdentitySig []byte `json:"identity_sig,omitzero"`
	// Verified is the agent VM's own note that it checked the above (never read from or written to the wire).
	Verified *Verified `json:"-"`
}

// PicturesRequest is the body of POST /pictures (v0.8.21): the person turned product photos on after an answer whose
// cards the VM didn't look up (photos weren't on for it). The ticket is the one the run's "pictures"
// event carried; it names, in the VM's memory only, the run's checked reader items its cards named, under the run's
// user tag, for 30 minutes and one use. Nothing else goes out: the tab sends no names.
type PicturesRequest struct {
	Ticket string `json:"ticket"`
	// Where and who, as for a search (runauth.PicturesDigest, its own label; v0.10.0). The ticket is good only in
	// the space its run was in, and the record is sealed to that space's seal key.
	Space       string `json:"space,omitzero"`
	SpaceSeal   string `json:"space_seal,omitzero"`
	SpaceProof  []byte `json:"space_proof,omitzero"`
	Identity    string `json:"identity,omitzero"`
	IdentityKey string `json:"identity_key,omitzero"`
	Nonce       string `json:"nonce,omitzero"`
	SignedAt    int64  `json:"signed_at,omitzero"`
	IdentitySig []byte `json:"identity_sig,omitzero"`
	// Verified: as SearchRequest's.
	Verified *Verified `json:"-"`
}

// Search decisions (SearchRequest.Decision).
const (
	SearchOnce    = "once"
	SearchAlways  = "always"
	SearchSetting = "setting"
)

// Verified is what the agent VM verified about a request's where and who (runauth.Check), and whose budget it
// counts against.
type Verified struct {
	Space    string // the proven space
	Seal     string // its seal public key: the run's activity records are sealed to it
	Identity string // the identity that signed the request
	// Member is whose member budget the run uses: the identity on a firm's VM; on the shared chat VM the relay's
	// daily per-user tag (X-Agent-User), since accounts are free to make and only the relay knows who is who.
	Member string
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
//	             for a kind set to Always allow. Sent once, with its decision only, for an action refused without
//	             asking (never, unavailable, not_from_results: a page address the model composed after reading
//	             the web).
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
	Quotes []Quote `json:"quotes,omitempty"`
	// Pictures: a "pictures" event (v0.8.21), at a run's end: the ticket for its cards' photos the VM didn't look up
	// because pictures weren't allowed yet (POST /pictures, once the person allows them).
	Pictures string   `json:"pictures,omitempty"`
	Image    *Image   `json:"image,omitempty"`
	Favicon  *Favicon `json:"favicon,omitempty"`
	Usage    *Usage   `json:"usage,omitempty"`
	Meta     *Meta    `json:"meta,omitempty"`
	Metrics  *Metric  `json:"metrics,omitempty"`
	Error    string   `json:"error,omitempty"`
	Code     string   `json:"code,omitempty"` // error: why a safety control ended the run (stopped, stop_list_stale, policy_missing, policy_denied, budget_exceeded, rate_limited), or model_overloaded
	// Activity: the run's sealed activity records (its start and end, or the one record of a refused run), sent
	// right before done or error. Each is signed by Meta.Activity.Key and sealed to RunRequest.SpaceSeal.
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
	// Approval: an effect held for a person's approval (approve before send, docs/27 section 4), or what became of it.
	Approval *Approval `json:"approval,omitempty"`
}

// Approval is an effect held for approval: exactly what would happen (Effect, canonical JSON) and its hash, which the
// approver's passkey signs over (with the other fields) in POST /approvals. State says what became of it. Untrusted
// model output inside Effect: display only, and the browser recomputes the hash from what it shows.
type Approval struct {
	ID         string          `json:"id"` // ap_
	Task       string          `json:"task"`
	Request    string          `json:"request"`
	Action     string          `json:"action"`
	Firm       string          `json:"firm"`
	Space      string          `json:"space"`
	Effect     json.RawMessage `json:"effect,omitempty"`
	EffectHash string          `json:"effect_hash"`
	Approvers  []string        `json:"approvers,omitempty"` // i_ ids that may decide
	ExpiresAt  time.Time       `json:"expires_at"`
	// Tainted: the task had read outside content when the action was proposed (docs/27 section 5).
	Tainted bool `json:"tainted,omitempty"`
	// State: "" (waiting), approved, denied, expired, sent, failed, unknown (may or may not have gone out: never
	// sent again by the VM), unavailable (nobody here can approve it: denied without asking).
	State string `json:"state,omitempty"`
}

// Permission is a permission prompt: before data of a kind leaves the VM, the person allows it once, always (that kind,
// this run and their setting), or denies it. Value is exactly what would go out (a search's masked query, a page's
// address); the person may edit it before allowing. Untrusted model output: display only.
type Permission struct {
	Task     string `json:"task"`                // the task (grants name it)
	Request  string `json:"request"`             // the held request (grants name it)
	Kind     string `json:"kind"`                // web.search | web.fetch | web.images
	Value    string `json:"value"`               // what would go out
	Decision string `json:"decision,omitempty"`  // "": waiting; allowed_once | allowed_always | denied | timed_out | never | unavailable | not_from_results
	TimeoutS int    `json:"timeout_s,omitempty"` // waiting: seconds until no answer counts as denied
	Edited   bool   `json:"edited,omitempty"`    // settled: the person changed the value before allowing
	// Reason: why this prompt is shown although the person's setting is Always allow, in words for the person
	// (fixed in the release). v0.8.2 set it for a page fetch, after outside content, of an address the model
	// composed; such a fetch is now refused without a prompt (decision not_from_results), so none sets it.
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
	// File is the name of the person's file a quote is from (a_review's and a_research's files.read, v0.13.0); ""
	// for a web source's. A research task's file quotes have Index 0: they are no web source's.
	File string `json:"file,omitempty"`
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
	// For: a card picture the VM looked up itself (guard/pictures.go, v0.8.18): the item name it searched for, the
	// reader's checked name of one of the run's sources (never the answer's text). The chat puts it on the card that
	// names this item.
	For string `json:"for,omitempty"`
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
	// Agent is the built-in agent the task runs when it isn't the chat ("a_research"); absent for the chat.
	Agent string `json:"agent,omitempty"`
	// Controls are the signed controls the run started under (docs/23-safety-controls.md).
	Controls *Controls `json:"controls,omitempty"`
	// Activity says where the run's activity record goes (docs/24); nil when it isn't recorded.
	Activity *Activity `json:"activity,omitempty"`
	// Keys is the firm key log's head as this VM holds it (keys v2 slice 5); nil on a VM without a key log pin.
	Keys *Keys `json:"keys,omitempty"`
}

// Keys announces the VM's firm key log head (docs/26 section 4) over EHBP: the browser compares it with the log it
// verified itself, so a server showing different people different logs is caught. Genesis is the compose's pin.
type Keys struct {
	Firm    string `json:"firm"`
	Genesis string `json:"genesis"`
	Seq     int64  `json:"seq"`
	Head    string `json:"head"`           // "" while seq is 0 (the genesis entry hasn't arrived)
	Fork    bool   `json:"fork,omitempty"` // the VM saw two valid entries at one position
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
	// Agent is the built-in agent whose task this is, when it isn't the chat ("a_research"; metadata only).
	Agent   string `json:"agent,omitempty"`
	Outcome string `json:"outcome"` // ok | error | refused (fetch: the URL held personal data) | slow_switched (model: given up as slow or overloaded, the step ran again on the fallback)

	// Fallback (search, v0.13.0): the search went to the fallback provider (Tavily, then in Provider) because the
	// primary (Exa) failed on its side, by class: http_401 | http_402 | http_403 | http_429 (after its retry) |
	// http_4xx | http_5xx | timeout | unreachable | bad_response; or breaker_open (Exa skipped after failures in a
	// row). "" when it didn't.
	Fallback string `json:"fallback,omitempty"`
	// Status (search, v0.13.0): a failed search's failure class (the classes above, or refused: the fallback's key or
	// host refused). Fixed words only, never the query or the provider's text.
	Status string `json:"status,omitempty"`
}
