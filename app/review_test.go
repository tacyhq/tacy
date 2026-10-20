package main

import (
	"encoding/json"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/tacyhq/tacy/guard"
	"github.com/tacyhq/tacy/proto"
	"github.com/tacyhq/tacy/safety"
)

// a_review in agentd (docs/30 slice 3): started through POST /tasks with the full stack (signed request, policy,
// budgets, the quarantined reader, activity records), its files read through files_read; nothing goes out; a
// policy without the files connector refuses its reads (a signed policy must list files.list and files.read).

// reviewReader answers a file section's read: its "2. Term" sentence quoted by reference.
func reviewReader(prompt string) string {
	if !strings.Contains(prompt, "one part of a file") {
		return readerAnswer(prompt)
	}
	quotes := []map[string]any{}
	if i := strings.Index(prompt, "2. Term."); i >= 0 {
		ms := regexp.MustCompile(`⟦(\d+)⟧`).FindAllStringSubmatch(prompt[:i], -1)
		n, _ := strconv.Atoi(ms[len(ms)-1][1])
		quotes = append(quotes, map[string]any{"id": 1, "from": n, "to": n, "location": "2. Term", "topic": "term"})
	}
	b, _ := json.Marshal(map[string]any{"summary": "A five-year term [Q1].", "facts": []string{"2. Term: five years [Q1]."}, "entities": []string{},
		"dates": []string{"five years: term"}, "amounts": []string{}, "source": map[string]any{"kind": "legal", "title": "", "publisher": "", "published": ""},
		"quotes": quotes, "wording": "", "instructions_found": false, "instruction_count": 0})
	return string(b)
}

const reviewNDA = "MUTUAL NON-DISCLOSURE AGREEMENT\n\n1. Definitions. Confidential Information means any information disclosed by either party.\n\n" +
	"2. Term. This Agreement lasts five (5) years from the Effective Date.\n\n3. Remedies. KESTREL-CANARY-9 The Recipient pays $250,000 for any breach.\n"

func review() proto.RunRequest {
	msg := "<attachment name=\"nda.txt\">\n" + reviewNDA + "\n</attachment>\n\nTask: Review the NDA\n\nFlag anything one-sided for the Recipient."
	return proto.RunRequest{Agent: guard.AgentReview, Model: proto.DefaultModel, RunSecret: permSecret,
		Permissions: map[string]string{"web.search": safety.PermAlways, "web.fetch": safety.PermAlways, "web.images": safety.PermAlways},
		Messages:    []proto.Message{{Role: "system", Content: "Today is Tuesday, October 20, 2026."}, {Role: "user", Content: msg}}}
}

const reviewAnswer = "## Summary\nA mutual NDA with a five-year term [quote 1].\n\n## Issues\n| # | Severity | Party | Clause | Issue | Cite |\n" +
	"|---|---|---|---|---|---|\n| 1 | Medium | Recipient | 2. Term | Five years is long for an NDA. | [quote 1] |\n\n## Notes\nNone."

func reviewEnv(t *testing.T, edit func(p *safety.Policy), replies ...string) *agentEnv {
	return newAgentEnv(t, edit, replies...)
}

func TestReviewTask(t *testing.T) {
	ae := reviewEnv(t, nil,
		pCalls([3]string{"c1", "files_read", `{}`}, [3]string{"c2", "files_list", `{}`}),
		pText(reviewAnswer))
	_, evs := runAgentTask(t, ae.conn(t, tasksUser), review())
	if evs[len(evs)-1].Type != "done" {
		t.Fatalf("run %s: %+v", types(evs), evs[len(evs)-1])
	}
	ae.noAsk()
	var meta *proto.Meta
	var quotes []proto.Quote
	for _, e := range evs {
		switch {
		case e.Type == "meta":
			meta = e.Meta
		case e.Type == "tool_result" && e.Name == "files_read":
			quotes = append(quotes, e.Quotes...)
		case e.Type == "favicon" || e.Type == "image":
			t.Fatalf("a review fetched %s", e.Type)
		}
	}
	if meta == nil || meta.Agent != guard.AgentReview || !slices.Equal(meta.Tools, []string{"files_list", "files_read"}) {
		t.Fatalf("meta %+v", meta)
	}
	if len(quotes) != 1 || quotes[0].Index != 1 || quotes[0].Text != "2. Term. This Agreement lasts five (5) years from the Effective Date." ||
		!strings.HasPrefix(quotes[0].Location, "nda.txt, part 1 of 1") {
		t.Fatalf("quotes %+v", quotes)
	}
	text := answerText(evs)
	if !strings.Contains(text, "| 1 | Medium | Recipient |") || !strings.Contains(text, "## Sections not reviewed\nNone: all 1 part") {
		t.Fatalf("review %q", text)
	}
	// Nothing went out; the model never got the file's text.
	if ae.search.count() != 0 {
		t.Fatal("a review searched")
	}
	for i, body := range ae.model.bodies {
		if strings.Contains(body, "KESTREL-CANARY-9") {
			t.Fatalf("model call %d has the file's text", i+1)
		}
	}
	runs := openedActivity(t, evs, ae.seal, ae.rec.Signer.Public())
	start, end := runs[0], runs[len(runs)-1]
	if start.Agent == nil || start.Agent.ID != guard.AgentReview || start.Agent.Digest != guard.AgentRef(guard.AgentReview).Digest ||
		start.Limits == nil || start.Limits.MaxSteps != 12 || end.Status.State != "succeeded" {
		t.Fatalf("records: start %+v %+v, end %+v", start.Agent, start.Limits, end.Status)
	}
}

// Under a policy without the files connector (signed before a_review) every files action is policy_denied: the review
// still ends, and the VM says it read nothing.
func TestReviewNeedsFilesPolicy(t *testing.T) {
	ae := reviewEnv(t, func(p *safety.Policy) { delete(p.Connectors, "files") },
		pCalls([3]string{"c1", "files_read", `{}`}), pText("## Summary\nI couldn't read the file."))
	_, evs := runAgentTask(t, ae.conn(t, tasksUser), review())
	denied := false
	for _, e := range evs {
		if e.Type == "tool_result" && strings.Contains(string(e.Result), safety.CodePolicyDenied) {
			denied = true
		}
	}
	if !denied || !strings.Contains(answerText(evs), "- nda.txt: part 1 of 1, from “MUTUAL NON-DISCLOSURE AGREEMENT” (not read") {
		t.Fatalf("denied %v, text %q", denied, answerText(evs))
	}
}
