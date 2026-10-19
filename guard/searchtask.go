package guard

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/tacyhq/tacy/harness"
	"github.com/tacyhq/tacy/proto"
)

// The plain chat's web search (docs/29, v0.8.10): with agent mode off, the chat's model may ask for one web search;
// the person's tab shows the permission prompt with the exact, masked query, and only once they allow it does the tab
// verify this VM and send that query here (agentd's POST /search). The VM runs it as a task of its own kind
// (TaskOptions.Via = ViaSearch) with no brain and no model calls: the masked query goes to the search provider,
// the quarantined reader (reader.go) reads the results, and the tab gets what agent mode's model would get (the
// reader's fields with [n] sources, the person's exact quotes, the sources' icons), and the activity record. Pages
// aren't read on this path: that stays in agent mode.
//
// A search task can do one thing: one web.search with the query the person allowed. agentd makes no other request
// for it; gatewayd refuses a model call, any other action and a second search for it (Guard.ModelCall,
// Guard.Action), and checks the grant agentd passes on (permit), as for any search.

// ViaSearch is a task started by POST /search (TaskOptions.Via).
const ViaSearch = "search"

// SearchActionID is the request id of a search task's one action (and the id its events carry).
const SearchActionID = "search"

// searchAgent names what runs a search task in its activity record: no agent definition, no brain.
var searchAgent = harness.AgentRef{ID: "a_search", Version: "1", Digest: "unsigned"}

// SearchCap is a search task's overall cap (its deadline): a search, the reader and the site icons' grace take
// seconds; the handler gives up well before this.
const SearchCap = 2 * time.Minute

// SearchOutcome is how the person's decision goes on the record (a permission outcome).
func SearchOutcome(decision string) string {
	switch decision {
	case proto.SearchAlways:
		return PermAllowedAlways
	case proto.SearchSetting:
		return PermAlwaysSetting
	}
	return PermAllowedOnce
}

// SearchStart checks a search request and makes its task: the web.search action only, no models, no input. The run
// secret is the VM's own (random per search): agentd makes the one grant with it, for the query the person allowed,
// and gatewayd checks it (permit). Returns the action's arguments too.
func SearchStart(r *proto.SearchRequest, now time.Time) (harness.Start, TaskOptions, []byte, error) {
	var s harness.Start
	q := strings.TrimSpace(r.Query)
	switch {
	case q == "" || !utf8.ValidString(q) || utf8.RuneCountInString(q) > maxQueryRunes:
		return s, TaskOptions{}, nil, fmt.Errorf("query must be 1 to %d characters", maxQueryRunes)
	case HiddenChars(q):
		return s, TaskOptions{}, nil, errors.New("query has control or hidden characters")
	}
	if r.Count == 0 {
		r.Count = 5
	}
	if r.Count < 1 || r.Count > maxSearchResults {
		return s, TaskOptions{}, nil, fmt.Errorf("count must be 1 to %d", maxSearchResults)
	}
	switch r.Decision {
	case proto.SearchOnce, proto.SearchAlways, proto.SearchSetting:
	default:
		return s, TaskOptions{}, nil, errors.New("decision must be once, always or setting")
	}
	if !utf8.ValidString(r.Question) || len(r.Question) > 4*maxQuestionRunes || strings.ContainsFunc(r.Question, isTagChar) {
		return s, TaskOptions{}, nil, errors.New("question isn't acceptable")
	}
	if len(r.CacheSecret) > 256 {
		return s, TaskOptions{}, nil, errors.New("cache_secret too long")
	}
	secret := make([]byte, 32)
	rand.Read(secret)
	args, _ := json.Marshal(map[string]any{"query": q, "count": r.Count})
	s.Space, s.Attempt, s.Agent = "s_chat", 1, searchAgent
	s.Tools = ToolDefs("web.search")
	s.Limits = harness.TaskLimits{Deadline: now.Add(SearchCap).UTC().Format(time.RFC3339)}
	question := strings.TrimSpace(r.Question)
	if question == "" {
		question = q
	}
	return s, TaskOptions{CacheSecret: r.CacheSecret, Via: ViaSearch, Question: capRunes(question, maxQuestionRunes),
		RunSecret: hex.EncodeToString(secret),
		// The one kind it has: asked (the person was, in their tab); the others never. A policy's cap still applies.
		Permissions: map[string]string{"web.search": "ask", "web.fetch": "never", "web.images": "never"}}, args, nil
}

// maxQueryRunes caps a query (the web connector cuts it there anyway).
const maxQueryRunes = 300

// isTagChar: the invisible tag block (HiddenChars), which a question may never carry; other control characters
// (new lines) are normal in a person's message.
func isTagChar(r rune) bool { return r >= 0xE0000 && r <= 0xE007F }

// SearchGrant is the grant a search task's action runs with: Allow once, for its one request, with the value that
// goes out (Outgoing), MAC'd with the task's run secret.
func SearchGrant(task string, opts TaskOptions, args []byte) (*Grant, error) {
	value, ok := Outgoing("web.search", args, nil)
	if !ok {
		return nil, errors.New("no query")
	}
	g := &Grant{Task: task, Request: SearchActionID, Kind: "web.search", Decision: DecideOnce, Value: value}
	g.MAC = GrantMAC(opts.RunSecret, *g)
	return g, nil
}

// errSearchOnly is gatewayd's answer to anything a search task asks for other than its one search.
var errSearchOnly = harness.Errf(harness.CodeNotAllowed, "a search task makes one web search and nothing else")

// searchOnly says why a request of a search task is refused, or nil: model calls, other actions and a second
// search are (t.mu not held).
func (t *task) searchOnly(req any) error {
	if t.opts.Via != ViaSearch {
		return nil
	}
	a, ok := req.(*harness.Action)
	if !ok || a.Name != "web.search" {
		return errSearchOnly
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.searched {
		return errSearchOnly
	}
	t.searched = true
	return nil
}
