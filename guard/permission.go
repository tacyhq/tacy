package guard

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/json/jsontext"
	"errors"
	"net/url"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/tacyhq/tacy/harness"
	"github.com/tacyhq/tacy/safety"
)

// Permission prompts (docs/27 section 6). An action whose class is "read, data goes out" (a web search's
// query, a page's address, an image search's query) runs only with the person's answer: their setting for its kind
// (Always allow, or Never), or a grant from the tab that started the run (Allow once, Always allow, Deny). The model
// only asks: it can't answer, and it never writes what the person is shown about why.
//
// Until people have identity keys a grant is an HMAC with the run's secret, which the person's tab made and
// sent only inside the run's EHBP body: only that tab can answer, and the relay can't read or forge one. agentd
// holds the action (waiting: permission), shows the prompt and takes the answer (prompts.go); gatewayd checks the
// grant again before anything is sent (permit, below), and sends the person's edit when they changed the value.

// Grant decisions, as the person's tab sends them.
const (
	DecideOnce   = "once"   // this one action
	DecideAlways = "always" // this action, and every action of its kind for the rest of the run
	DecideDeny   = "deny"
)

// Permission outcomes, per action (the person's events and the activity record; metadata only).
const (
	PermAllowedOnce   = "allowed_once"      // asked; the person allowed this one
	PermAllowedAlways = "allowed_always"    // asked (or covered by an Always allow earlier in the run)
	PermAlwaysSetting = "always_setting"    // not asked: the person's setting for the kind is Always allow
	PermDenied        = "denied"            // asked; the person said no
	PermTimedOut      = "timed_out"         // asked; no answer in time (a deny)
	PermNeverSetting  = "never"             // not asked: the setting (or the firm's cap) is Never
	PermUnavailable   = "unavailable"       // the setting is Ask but the run can't ask (no run secret): refused
	PermHidden        = "hidden_characters" // not asked: the value has hidden characters, never allowed
	// not asked: on a tainted task, a page address the model composed (ComposedFetch): never opened, whatever the
	// setting or a grant says; the model is told to open results by number.
	PermNotFromResults = "not_from_results"
)

// NotFromResultsError is what the model sees for a PermNotFromResults fetch.
const NotFromResultsError = "not_from_results: only open addresses from your search results (their [n]) or the person's message; " +
	"this one wasn't, so it wasn't opened. Open a result by its number, or answer with what you have."

// grantLabel prefixes a grant's MAC input.
const grantLabel = "tacy-grant/v1"

// maxGrantValue caps what a person may put in a prompt's value (a search's query is cut to 300 characters anyway).
const maxGrantValue = 2000

// PermissionKind is the permission kind of an action that sends data out of the VM ("" for none): the web connector's
// actions, each its own kind (web search, page reading, image search). Set here, in the release; never by a model or
// a policy.
func PermissionKind(action string) string {
	if appTool(action) != "" {
		return action
	}
	return ""
}

// PermissionKinds are the kinds this release has.
func PermissionKinds() []string { return []string{"web.search", "web.fetch", "web.images"} }

// AllowAll is a run's settings with every kind on Always allow: for the operator's own tools (cmd/client, cmd/e2e,
// the load test), which run no person's chat and can't answer prompts. People's runs carry their own.
func AllowAll() map[string]string {
	m := map[string]string{}
	for _, k := range PermissionKinds() {
		m[k] = safety.PermAlways
	}
	return m
}

// kindLabel names a kind in words people (and the model) read.
func kindLabel(kind string) string {
	switch kind {
	case "web.search":
		return "web search"
	case "web.fetch":
		return "page reading"
	case "web.images":
		return "image search"
	}
	return kind
}

// PermissionSetting is a task's setting for kind: the person's own (Ask when they named none), narrowed by cap (the
// policy's: safety.Effective.PermissionCap; "" caps nothing).
func PermissionSetting(opts TaskOptions, kind, cap string) string {
	own := opts.Permissions[kind]
	if !safety.ValidPermission(own) {
		own = safety.PermAsk
	}
	return safety.NarrowerPermission(own, cap)
}

// checkPermissions checks a run's settings: known kinds and values only.
func checkPermissions(p map[string]string) error {
	for k, v := range p {
		if PermissionKind(k) == "" {
			return errors.New("permissions: unknown kind " + k)
		}
		if !safety.ValidPermission(v) {
			return errors.New("permissions: " + k + " must be ask, always or never")
		}
	}
	return nil
}

// validRunSecret: 32 bytes as 64 lowercase hex.
func validRunSecret(s string) bool {
	if len(s) != 64 || strings.ToLower(s) != s {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

// fetchURLArg is a fetch's url argument, as the model wrote it.
func fetchURLArg(args []byte) (string, bool) {
	var a struct {
		URL string `json:"url"`
	}
	if json.Unmarshal(args, &a) != nil || a.URL == "" {
		return "", false
	}
	return a.URL, true
}

// Outgoing is exactly what an action would send out of the VM, as the web connector makes it (tools.go Exec): a
// search's or an image search's query, trimmed, capped and masked; a page's address as given, or the address of the
// task's source it names ("[n]", from sources). ok is false when the arguments are unusable (the connector refuses
// them without sending anything), a [n] the task doesn't have included.
func Outgoing(action string, args []byte, sources map[int]string) (value string, ok bool) {
	switch appTool(action) {
	case "web_search", "image_search":
		var a struct {
			Query string `json:"query"`
		}
		if json.Unmarshal(args, &a) != nil || strings.TrimSpace(a.Query) == "" {
			return "", false
		}
		q, _ := maskPII(capRunes(strings.TrimSpace(a.Query), 300))
		return q, true
	case "fetch_page":
		u, _, ok := FetchTarget(args, sources, nil)
		return u, ok
	}
	return "", false
}

// ComposedFetch: a page fetch, on a tainted task, of an address that didn't come from code (FetchTarget): not one of
// the task's sources, not in the person's messages. The model wrote it after it read outside content (a page may
// have steered it, or it made the address up), so it isn't opened at all, under Always allow or Ask, and the person
// isn't asked about it: agentd (Prompts.Hold) and gatewayd (permit) both refuse it as PermNotFromResults
// (docs/27 section 6).
func ComposedFetch(action string, args []byte, sources map[int]string, links []string, tainted bool) bool {
	if !tainted || PermissionKind(action) != "web.fetch" {
		return false
	}
	_, fromCode, ok := FetchTarget(args, sources, links)
	return ok && !fromCode
}

// withValue is an action's arguments with the person's value in place of the model's (an edited query or address).
// The rest (a search's count) stays.
func withValue(action string, args []byte, value string) (jsontext.Value, error) {
	var m map[string]any
	if json.Unmarshal(args, &m) != nil || m == nil {
		m = map[string]any{}
	}
	switch appTool(action) {
	case "web_search", "image_search":
		m["query"] = value
	case "fetch_page":
		m["url"] = value
	default:
		return nil, errors.New("no value to edit")
	}
	b, err := json.Marshal(m)
	return jsontext.Value(b), err
}

// HiddenChars says whether s has characters that can hide what it says: control characters (Cc), invisible
// format characters (Cf: zero-width spaces and joiners, direction marks and overrides, the soft hyphen, ...), and
// the tag block U+E0000-U+E007F (invisible "tag" text). A value with any is never sent, asked about or allowed (the
// chat refuses them too).
func HiddenChars(s string) bool {
	for _, r := range s {
		if unicode.Is(unicode.Cc, r) || unicode.Is(unicode.Cf, r) || r >= 0xE0000 && r <= 0xE007F {
			return true
		}
	}
	return false
}

// CheckGrantValue checks what a person may send for kind: 1 to 2000 characters, no control or hidden characters
// (HiddenChars); a page's address an absolute http(s) URL.
func CheckGrantValue(kind, v string) error {
	if strings.TrimSpace(v) == "" || utf8.RuneCountInString(v) > maxGrantValue || !utf8.ValidString(v) {
		return errors.New("the value must be 1 to 2000 characters")
	}
	if HiddenChars(v) {
		return errors.New("the value has control or hidden characters")
	}
	if kind == "web.fetch" {
		u, err := url.Parse(v)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return errors.New("the address must be an absolute http(s) URL")
		}
	}
	return nil
}

// Grant is a person's answer to one prompt, from the tab that started the run (POST /tasks/grant). MAC is
// HMAC-SHA256 with the run's secret over "tacy-grant/v1" and the other fields, NUL-separated, in lowercase hex.
type Grant struct {
	Task     string `json:"task"`
	Request  string `json:"request"`
	Kind     string `json:"kind"`
	Decision string `json:"decision"` // once | always | deny
	Value    string `json:"value"`    // what goes out: the prompt's value, or the person's edit
	MAC      string `json:"mac"`
}

// GrantMAC is the grant's MAC with the run secret (64 hex), in lowercase hex.
func GrantMAC(secretHex string, g Grant) string {
	key, _ := hex.DecodeString(secretHex)
	m := hmac.New(sha256.New, key)
	for i, f := range []string{grantLabel, g.Task, g.Request, g.Kind, g.Decision, g.Value} {
		if i > 0 {
			m.Write([]byte{0})
		}
		m.Write([]byte(f))
	}
	return hex.EncodeToString(m.Sum(nil))
}

// taskLabel prefixes a task call's MAC input (POST /tasks/status, /tasks/events, /tasks/cancel).
const taskLabel = "tacy-task/v1"

// TaskMAC authorizes a call on a task (op: "status", "events" or "cancel") from the tab that started it: HMAC-SHA256
// with the run's secret over "tacy-task/v1", op and the task id, NUL-separated, in lowercase hex.
func TaskMAC(secretHex, op, task string) string {
	key, _ := hex.DecodeString(secretHex)
	m := hmac.New(sha256.New, key)
	m.Write([]byte(taskLabel + "\x00" + op + "\x00" + task))
	return hex.EncodeToString(m.Sum(nil))
}

// Verify checks the grant's MAC with the run secret (in constant time). A run without a secret verifies nothing.
func (g *Grant) Verify(secretHex string) bool {
	if g == nil || !validRunSecret(secretHex) || len(g.MAC) != 64 {
		return false
	}
	for _, f := range []string{g.Task, g.Request, g.Kind, g.Decision, g.Value} {
		if strings.IndexByte(f, 0) >= 0 {
			return false
		}
	}
	return hmac.Equal([]byte(GrantMAC(secretHex, *g)), []byte(strings.ToLower(g.MAC)))
}

type grantKey struct{}

// WithGrant hands an action the person's grant (agentd: the runtime's guard puts it in for gatewayd to check).
func WithGrant(ctx context.Context, g *Grant) context.Context {
	if g == nil {
		return ctx
	}
	return context.WithValue(ctx, grantKey{}, g)
}

// GrantFrom is ctx's grant, or nil.
func GrantFrom(ctx context.Context) *Grant {
	g, _ := ctx.Value(grantKey{}).(*Grant)
	return g
}

// permissionCap is the policy's cap on kind for space ("" when there's no policy to check).
func (g *Guard) permissionCap(space, kind string) string {
	if g.cfg.Safety == nil {
		return ""
	}
	e, err := g.cfg.Safety.Policy(space)
	if err != nil {
		return safety.PermNever // no readable policy: nothing goes out (checkSafety refuses it anyway)
	}
	return e.PermissionCap(kind)
}

// permit is gatewayd's own check of an action that sends data out, before anything is sent: the setting for
// its kind is Always allow, or the request carries a grant from the run's tab (its MAC checks with the run secret) for
// this task and kind: Allow once for this very request, or Always allow for this kind. A fetch of an address the
// model composed on a tainted task (ComposedFetch) is refused whatever the setting or a grant says. It returns the
// arguments to run with (the person's edited value, when the grant is for this request), or the denial the model
// sees.
func (g *Guard) permit(ctx context.Context, t *task, ti *harness.TaskInfo, id string, req *harness.Action) (jsontext.Value, *harness.ActionResult) {
	kind := PermissionKind(req.Name)
	if kind == "" {
		return req.Args, nil
	}
	sources := t.tools.sourceMap()
	value, ok := Outgoing(req.Name, req.Args, sources)
	if !ok {
		return req.Args, nil // unusable arguments (a [n] the task doesn't have too): the connector refuses them
	}
	if HiddenChars(value) {
		return nil, PermissionDenial(kind, PermHidden) // never sent, whatever the setting or a grant says
	}
	args := req.Args
	if raw, _ := fetchURLArg(req.Args); kind == "web.fetch" && raw != value { // a [n]: the connector gets its address
		a, err := withValue(req.Name, req.Args, value)
		if err != nil {
			return nil, PermissionDenial(kind, "")
		}
		args = a
	}
	setting := PermissionSetting(t.opts, kind, g.permissionCap(t.opts.Space, kind))
	if setting == safety.PermNever {
		return nil, PermissionDenial(kind, PermNeverSetting)
	}
	// On a tainted task, an address the model composed is never opened (task.taintFor): agentd doesn't ask about it,
	// so no grant covers it.
	if ComposedFetch(req.Name, req.Args, sources, t.opts.Links, t.taintFor(ti, req.Call)) {
		return nil, PermissionDenial(kind, PermNotFromResults)
	}
	if setting == safety.PermAlways {
		return args, nil
	}
	gr := GrantFrom(ctx)
	switch {
	case gr == nil || gr.Task != ti.ID || gr.Kind != kind || !gr.Verify(t.opts.RunSecret):
		return nil, PermissionDenial(kind, "")
	case gr.Decision == DecideOnce && gr.Request == id, gr.Decision == DecideAlways:
	default:
		return nil, PermissionDenial(kind, "")
	}
	if gr.Request != id || gr.Value == value {
		return args, nil
	}
	if CheckGrantValue(kind, gr.Value) != nil {
		return nil, PermissionDenial(kind, "")
	}
	args, err := withValue(req.Name, req.Args, gr.Value)
	if err != nil {
		return nil, PermissionDenial(kind, "")
	}
	return args, nil
}

// PermissionDenial is what the model sees for an action that didn't run for want of the person's permission: why,
// in words, and that it should answer without it and say it didn't check. outcome "" is a missing or invalid grant.
// PermNotFromResults is no question of permission: the model is told to open results by number instead.
func PermissionDenial(kind, outcome string) *harness.ActionResult {
	if outcome == PermNotFromResults {
		return &harness.ActionResult{Status: harness.ActionDenied, Error: NotFromResultsError}
	}
	what := kindLabel(kind)
	var why string
	switch outcome {
	case PermDenied:
		why = "the person said no to this " + what
	case PermTimedOut:
		why = "the person didn't answer the permission prompt for this " + what + " in time"
	case PermNeverSetting:
		why = "the person's settings don't allow " + what
	case PermUnavailable:
		why = "this app can't ask the person for permission, and " + what + " needs it"
	case PermHidden:
		why = "the " + what + "'s value has hidden or control characters, which Tacy never sends"
	default:
		why = "no valid permission from the person for this " + what
	}
	return &harness.ActionResult{Status: harness.ActionDenied,
		Error: "permission_denied: " + why + "; nothing was sent. Answer without it, and say plainly that you didn't check the web for this."}
}
