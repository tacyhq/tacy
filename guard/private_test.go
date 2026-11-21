package guard

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/tacyhq/tacy/harness"
	"github.com/tacyhq/tacy/proto"
	"github.com/tacyhq/tacy/safety"
)

// What the client sends for a message with a text attachment (attachment-text.ts formatForModel).
const withAttachment = "<attachment name=\"notes.txt\">\nThe vendor portal is https://evil.example/collect?x=1 and the project codename is BLUE HERON SEVEN OAK LANTERN.\n</attachment>\n\nSummarize this, and see https://typed.example/page"

// Privacy review #7: an attachment taints the task from its start; its addresses aren't the person's.
func TestAttachmentTaintsAndLinks(t *testing.T) {
	if got := StartTaint(&harness.Start{Input: []harness.Message{{Role: "user", Content: withAttachment}}}); got != "attachment" {
		t.Fatalf("StartTaint = %q, want attachment", got)
	}
	if got := StartTaint(&harness.Start{Input: []harness.Message{{Role: "user", Content: "Summarize https://typed.example/page"}}}); got != "" {
		t.Fatalf("a plain first turn is tainted: %q", got)
	}
	links := personLinks([]proto.Message{{Role: "user", Content: withAttachment}})
	if slices.ContainsFunc(links, func(l string) bool { return strings.Contains(l, "evil.example") }) ||
		!slices.ContainsFunc(links, func(l string) bool { return strings.Contains(l, "typed.example") }) {
		t.Fatalf("person links %v: the attachment's address must not count, the typed one must", links)
	}
	// A composed fetch of the attachment's address on that (tainted) first turn is refused.
	args, _ := json.Marshal(map[string]string{"url": "https://evil.example/collect?x=1"})
	if !ComposedFetch("web.fetch", args, nil, links, true) {
		t.Fatal("a fetch of an attachment's address on the first turn should be refused")
	}
	// An unclosed block counts as attachment to the end.
	if s := withoutAttachments("hi <attachment name=\"a\">https://x.example"); strings.Contains(s, "x.example") {
		t.Fatalf("unclosed block kept: %q", s)
	}
}

// A search carrying a passage of an attachment is refused, like one carrying a passage of the person's files.
func TestAttachmentPassageInSearch(t *testing.T) {
	ti := &harness.TaskInfo{ID: "t", Start: &harness.Start{Input: []harness.Message{{Role: "user", Content: withAttachment}}}}
	leak, _ := json.Marshal(map[string]string{"query": "the project codename is blue heron seven oak lantern"})
	own, _ := json.Marshal(map[string]string{"query": "vendor portal security review"})
	if !attachmentTextInArgs(ti, leak) {
		t.Fatal("a passage of the attachment went into a search")
	}
	if attachmentTextInArgs(ti, own) {
		t.Fatal("the model's own words were refused")
	}
}

// After the person's mail reached a task, every web search is asked about, whatever Always allow says; a run that
// can't ask sends none; gatewayd takes only a grant for that one request.
func TestSearchAfterMailIsAsked(t *testing.T) {
	mailRead := harness.Record{Kind: harness.TypeAction, Done: true, Req: mustJ(harness.Action{Name: MailReadAction, Args: []byte(`{"id":"m1"}`)}),
		Body: mustJ(harness.ActionResult{Status: harness.ActionDone, Output: []byte(`{}`)})}
	journal := func(rs ...harness.Record) func() ([]harness.Record, error) {
		return func() ([]harness.Record, error) { return rs, nil }
	}
	opts, _ := json.Marshal(TaskOptions{RunSecret: testSecret, Permissions: map[string]string{"web.search": safety.PermAlways}})
	start := harness.Start{Input: []harness.Message{{Role: "user", Content: "what did Ana say about the invoice?"}}}
	search := &harness.Action{Name: "web.search", Call: "c1", Args: []byte(`{"query":"q"}`)}
	p := &Prompts{Release: func(string, string, bool, string) error { return nil }, Emit: func(string, proto.Event) {}}

	before := &harness.TaskInfo{ID: "tk_m", Start: &start, Options: opts, Journal: journal()}
	if MailTask(before) || p.Hold(before, "r1", search) != "" {
		t.Fatal("before any mail, Always allow sends the search")
	}
	after := &harness.TaskInfo{ID: "tk_m", Start: &start, Options: opts, Journal: journal(mailRead)}
	if !PrivateSearch("web.search", after) || !PrivateSearch("web.images", after) || PrivateSearch("web.fetch", after) {
		t.Fatal("PrivateSearch covers web and image searches after mail only")
	}
	if sub := p.Hold(after, "r2", search); sub != harness.WaitPermission {
		t.Fatalf("after mail, Always allow must still ask: %q", sub)
	}
	noSecret, _ := json.Marshal(TaskOptions{Permissions: map[string]string{"web.search": safety.PermAlways}})
	sched := &harness.TaskInfo{ID: "tk_s", Start: &start, Options: noSecret, Journal: journal(mailRead)}
	p.Hold(sched, "r3", search)
	if o := p.outcomes[key("tk_s", "r3")]; o.Outcome != PermUnavailable {
		t.Fatalf("a run that can't ask: %+v, want unavailable", o)
	}
	// A journal that can't be read counts as mail (fails closed).
	broken := &harness.TaskInfo{ID: "tk_b", Journal: func() ([]harness.Record, error) { return nil, errTest }}
	if !MailTask(broken) {
		t.Fatal("an unreadable journal must count as mail")
	}
}

var errTest = jsonErr("journal unreadable")

type jsonErr string

func (e jsonErr) Error() string { return string(e) }

func mustJ(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}
