package main

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/tacyhq/tacy/guard"
	"github.com/tacyhq/tacy/harness"
	"github.com/tacyhq/tacy/proto"
	"github.com/tacyhq/tacy/safety"
	"github.com/tacyhq/tacy/trigger"
)

// Documents in agent runs (agent feature 5, guard/documents.go) through agentd's full stack: a research task, a web
// (chat) task and a scheduled run put a document in their result. document.create is asked for by name only, never
// held for an approval or a prompt (also on a tainted task, after web content), sends nothing, and its name and format
// come out checked. A policy without the document connector drops the tool at the start.

// A name built to mislead: a path, a right-to-left override that would show "exe.docx" as "xcod.exe", zero-width
// and control characters, a leading dot.
const trickyDocName = "../../.etc/pa​ss\u0007wd‮xcod.exe"

func docCall(id, name, format, content string) [3]string {
	b, _ := json.Marshal(map[string]string{"name": name, "format": format, "content": content})
	return [3]string{id, "document_create", string(b)}
}

// documentEvents are a run's document_create tool_call and tool_result events.
func documentEvents(t *testing.T, evs []proto.Event) (call, result *proto.Event) {
	t.Helper()
	for i := range evs {
		if evs[i].Name != "document_create" {
			continue
		}
		switch evs[i].Type {
		case "tool_call":
			call = &evs[i]
		case "tool_result":
			result = &evs[i]
		}
	}
	return call, result
}

func checkMade(t *testing.T, res *proto.Event, name, format string, chars int) {
	t.Helper()
	if res == nil {
		t.Fatal("no document_create tool_result")
	}
	var r struct {
		Status, Name, Format string
		Chars                int
	}
	if json.Unmarshal(res.Result, &r) != nil || r.Status != "created" || r.Name != name || r.Format != format || r.Chars != chars {
		t.Fatalf("result %s", res.Result)
	}
	if len(res.Args) != 0 {
		t.Fatalf("the tool_result repeats the arguments (%d bytes): the content belongs in the tool_call only", len(res.Args))
	}
}

func noApproval(t *testing.T, evs []proto.Event) {
	t.Helper()
	for _, e := range evs {
		if e.Type == "approval" || e.Type == "permission" && e.Permission != nil && e.Permission.Kind == guard.DocumentAction {
			t.Fatalf("a document was held: %+v", e)
		}
	}
}

// Research asked for a Word report: it searches (the task is tainted from then on), then makes the document. Not held
// for approval (the approval table's class Read: missing there it would be a send, refused on the chat VM, which has
// no approvers), no prompt, the name and format checked, its content in the tool_call event as the model wrote it.
func TestResearchDocument(t *testing.T) {
	content := "# Gullwing Point light\n\n## Summary\nFirst lit in 1871 [1], automated in 1968 [1].\n"
	ae := newAgentEnv(t, nil,
		pCalls([3]string{"c1", "web_search", `{"query":"gullwing point light history"}`}),
		pCalls(docCall("c2", trickyDocName, "Word", content)),
		pText("The report covers when the light was first lit and automated."))
	req := research("Research the Gullwing Point light's history and give me a report as a Word document.")
	req.Tools = []string{"web_search", "fetch_page", "document_create"}
	task, evs := runAgentTask(t, ae.conn(t, tasksUser), req)
	if evs[len(evs)-1].Type != "done" {
		t.Fatalf("run %s: %+v", types(evs), evs[len(evs)-1])
	}
	ae.noAsk()
	noApproval(t, evs)
	var meta *proto.Meta
	for _, e := range evs {
		if e.Type == "meta" {
			meta = e.Meta
		}
	}
	if meta == nil || !slices.Contains(meta.Tools, "document_create") {
		t.Fatalf("meta %+v", meta)
	}
	call, res := documentEvents(t, evs)
	var args map[string]string
	if call == nil || json.Unmarshal(call.Args, &args) != nil || args["content"] != content {
		t.Fatalf("tool_call %+v", call)
	}
	checkMade(t, res, "etc pass wdxcod", "docx", len(content))
	if !strings.Contains(answerText(evs), "The report covers") {
		t.Fatalf("answer %q", answerText(evs))
	}
	// Tainted by the search, and still not held: the document came after web content.
	if st, _ := ae.s.rt.Store.Task(task); st == nil || st.Taint == "" {
		t.Fatalf("task %+v not tainted", st)
	}
	// The model was told what to do with it, in the result it got (and never the note about a search budget).
	if len(ae.model.bodies) < 3 || !strings.Contains(ae.model.bodies[2], "document card is shown") {
		t.Fatal("the model didn't get the document's result")
	}
}

// Research that wasn't asked for documents (an older chat: no tools list) doesn't get the tool; a list naming it
// twice, or a tool research doesn't have, is refused at the door.
func TestResearchDocumentOptIn(t *testing.T) {
	ae := newAgentEnv(t, nil, pText("## Plan\n1. x\n## Summary\nNothing."))
	_, evs := runAgentTask(t, ae.conn(t, tasksUser), research("Research the Gullwing Point light."))
	for _, e := range evs {
		if e.Type == "meta" && slices.Contains(e.Meta.Tools, "document_create") {
			t.Fatalf("default tools %v", e.Meta.Tools)
		}
	}
	c := ae.conn(t, tasksUser)
	req := research("x")
	req.Tools = []string{"web_search", "document_create", "document_create"}
	if _, err := c.StartTask(context.Background(), req, ""); err == nil || !strings.Contains(err.Error(), "twice") {
		t.Fatalf("listed twice: %v", err)
	}
}

// A policy without the document connector (chat-v3, signed before this release): a request that names
// document_create starts without it, and a document the model makes anyway is refused (policy_denied), nothing shown.
func TestDocumentNeedsPolicy(t *testing.T) {
	ae := newAgentEnv(t, func(p *safety.Policy) { delete(p.Connectors, "document") },
		pCalls(docCall("c1", "Report", "docx", "# Report\nText.")),
		pText("Here it is in full: Report. Text."))
	req := research("Research harbor lights; give me a Word doc.")
	req.Tools = []string{"web_search", "fetch_page", "document_create"}
	_, evs := runAgentTask(t, ae.conn(t, tasksUser), req)
	for _, e := range evs {
		if e.Type == "meta" && slices.Contains(e.Meta.Tools, "document_create") {
			t.Fatalf("tools under a policy without documents: %v", e.Meta.Tools)
		}
	}
	if _, res := documentEvents(t, evs); res != nil && strings.Contains(string(res.Result), `"created"`) {
		t.Fatalf("a document was made under a policy without the connector: %s", res.Result)
	}
}

// The web agent (the chat, a_chat) with document_create in its request: a CSV, then a bad format (an executable) and
// one over the cap are refused with words the model can act on; nothing is held.
func TestChatDocument(t *testing.T) {
	big := strings.Repeat("a", guard.MaxDocumentChars+1)
	ae := newAgentEnv(t, nil,
		pCalls(docCall("c1", "Lights.csv", "csv", "name,lit\nGullwing,1871\n"), docCall("c2", "run me", "exe", "MZ"), docCall("c3", "huge", "md", big)),
		pText("Here's the CSV."))
	req := proto.RunRequest{Model: proto.DefaultModel, RunSecret: permSecret,
		Permissions: map[string]string{"web.search": safety.PermAlways, "web.fetch": safety.PermAlways},
		Tools:       []string{"web_search", "fetch_page", "image_search", "document_create"},
		Messages:    []proto.Message{{Role: "user", Content: "Give me a CSV of the light's dates."}}}
	_, evs := runAgentTask(t, ae.conn(t, tasksUser), req)
	if evs[len(evs)-1].Type != "done" {
		t.Fatalf("run %s: %+v", types(evs), evs[len(evs)-1])
	}
	ae.noAsk()
	noApproval(t, evs)
	results := map[string]string{}
	for _, e := range evs {
		if e.Type == "tool_result" && e.Name == "document_create" {
			results[e.ID] = string(e.Result)
		}
	}
	if !strings.Contains(results["c1"], `"name":"Lights","format":"csv"`) || !strings.Contains(results["c2"], "format must be one of docx, pdf, md, txt, csv, html") ||
		!strings.Contains(results["c3"], "over the 50000") {
		t.Fatalf("results %v", results)
	}
}

// A scheduled run whose definition lists document.create puts its document in the sealed result, under a tainted
// task (it read a page first) and with the full approval table wired as on the chat VM: not held, nothing sent but
// the page read, and the document's events kept in the result.
func TestScheduledDocument(t *testing.T) {
	content := "# Digest\n\n1. Nothing new today [1].\n"
	e := newSchedEnv(t, pCalls([3]string{"c1", "fetch_page", `{"url":"https://news.ycombinator.com/"}`}),
		pCalls(docCall("c2", "HN digest.docx", "docx", content)), pText("The digest is in the document."))
	e.wireApprovals()
	d := e.daily(e.me, func(d *trigger.Definition) {
		d.Instructions = "Every morning, read https://news.ycombinator.com/ and send me a digest of the top stories as a Word document."
		d.Tools = []string{"web.fetch", guard.DocumentAction}
	})
	if code, out := e.install(e.me, e.sign(d, e.me.Key)); code != 200 {
		t.Fatalf("install %d %v", code, out)
	}
	e.s.triggerTick(context.Background())
	var task string
	for id := range e.s.tasks().Triggered() {
		task = id
	}
	r := e.waitResult(task)
	if r.State != harness.OutcomeSucceeded {
		t.Fatalf("result %+v", r)
	}
	_, body := e.openResult(e.me, task)
	noApproval(t, body.Events)
	call, res := documentEvents(t, body.Events)
	var args map[string]string
	if call == nil || json.Unmarshal(call.Args, &args) != nil || args["content"] != content {
		t.Fatalf("tool_call %+v", call)
	}
	checkMade(t, res, "HN digest", "docx", len(content))
}

// A sealed result that has to shed events keeps its documents' (dropOldest).
func TestResultKeepsDocuments(t *testing.T) {
	var evs []proto.Event
	evs = append(evs, proto.Event{Type: "tool_call", ID: "d1", Name: "document_create", Args: json.RawMessage(`{"content":"x"}`)},
		proto.Event{Type: "tool_result", ID: "d1", Name: "document_create", Result: json.RawMessage(`{"status":"created"}`)})
	for range 30 {
		evs = append(evs, proto.Event{Type: "text", Delta: "x"})
	}
	out := dropOldest(evs)
	if len(out) != len(evs)-len(evs)/4+2 || out[0].Name != "document_create" || out[1].Name != "document_create" {
		t.Fatalf("kept %d: %+v", len(out), out[:2])
	}
	only := []proto.Event{evs[0], evs[1], evs[0], evs[1]}
	if len(dropOldest(only)) != 3 {
		t.Fatal("a result of documents only never shrinks")
	}
}
