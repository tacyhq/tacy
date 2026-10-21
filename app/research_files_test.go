package main

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/tacyhq/tacy/guard"
	"github.com/tacyhq/tacy/proto"
	"github.com/tacyhq/tacy/safety"
)

// a_research with the person's files in agentd (v0.13.0): started through POST /tasks with the full stack (signed
// request, policy, budgets, the quarantined reader, activity records); its files read through files_read and
// counted against its $1; a search carrying a passage of a file refused before it reaches the search provider.

func researchWithFiles() proto.RunRequest {
	r := research("")
	msg := "<attachment name=\"nda.txt\">\n" + reviewNDA + "\n</attachment>\n\nTask: NDA terms today\n\nAre five-year NDA terms still usual?"
	r.Messages = []proto.Message{{Role: "system", Content: "Today is Tuesday, October 20, 2026."}, {Role: "user", Content: msg}}
	return r
}

func TestResearchWithFilesTask(t *testing.T) {
	ae := newAgentEnv(t, nil,
		pCalls([3]string{"c1", "files_read", `{}`}),
		pCalls([3]string{"c2", "web_search", `{"query":"This Agreement lasts five (5) years from the Effective Date"}`},
			[3]string{"c3", "web_search", `{"query":"typical NDA term length"}`}),
		pText(researchAnswer))
	_, evs := runAgentTask(t, ae.conn(t, tasksUser), researchWithFiles())
	if evs[len(evs)-1].Type != "done" {
		t.Fatalf("run %s: %+v", types(evs), evs[len(evs)-1])
	}
	ae.noAsk() // "allow for this task": nothing asked, the refused search included
	var meta *proto.Meta
	var quotes []proto.Quote
	for _, e := range evs {
		switch {
		case e.Type == "meta":
			meta = e.Meta
		case e.Type == "tool_result" && e.Name == "files_read":
			quotes = append(quotes, e.Quotes...)
		}
	}
	if meta == nil || meta.Agent != guard.AgentResearch || !slices.Equal(meta.Tools, []string{"web_search", "fetch_page", "files_list", "files_read"}) {
		t.Fatalf("meta %+v", meta)
	}
	if len(quotes) != 1 || quotes[0].Index != 0 || quotes[0].File != "nda.txt" {
		t.Fatalf("quotes %+v", quotes)
	}
	// One search went out, in the model's own words; the passage never reached the provider.
	if ae.search.count() != 1 {
		t.Fatalf("%d searches sent", ae.search.count())
	}
	for i, body := range ae.model.bodies {
		if strings.Contains(body, "KESTREL-CANARY-9") {
			t.Fatalf("model call %d has the file's text", i+1)
		}
	}
	if text := answerText(evs); !strings.Contains(text, "## Parts of your files not read\nNone: all 1 part of the 1 file were read.") {
		t.Fatalf("brief %q", text)
	}
	// The file's read is in the run's budget: its reader calls are in the cost the end record counts.
	runs := openedActivity(t, evs, ae.seal, ae.rec.Signer.Public())
	end := runs[len(runs)-1]
	if end.Status.State != "succeeded" || end.Usage == nil || end.Usage.CostMicros <= 0 || end.Usage.ToolCalls != 3 {
		t.Fatalf("end %+v %+v", end.Status, end.Usage)
	}
}

// File reading counts against research's run budget like a page read: with too little left beyond the reserve for the
// brief, files_read is refused (budget_exceeded) before any reader call, and the task still writes its brief.
func TestResearchFilesBudget(t *testing.T) {
	_, readCost, _ := guard.ReaderReserve("files.read", nil)
	ae := newAgentEnv(t, func(p *safety.Policy) {
		p.Budget.Run = safety.Limits{CostMicros: guard.FinalReserve(guard.AgentResearch) + readCost/2}
	}, pCalls([3]string{"c1", "files_read", `{}`}), pText(researchAnswer))
	_, evs := runAgentTask(t, ae.conn(t, tasksUser), researchWithFiles())
	if !strings.Contains(resultOf(evs, "c1"), safety.CodeBudgetExceeded) || evs[len(evs)-1].Type != "done" {
		t.Fatalf("files_read: %s; end %s", resultOf(evs, "c1"), types(evs))
	}
	if text := answerText(evs); !strings.Contains(text, "- nda.txt: part 1 of 1") {
		t.Fatalf("the VM didn't list the unread part: %q", text)
	}
}

// Under a policy without the files connector research with files is refused at its start; without files it runs.
func TestResearchFilesNeedPolicy(t *testing.T) {
	ae := newAgentEnv(t, func(p *safety.Policy) { delete(p.Connectors, "files") }, pText(researchAnswer))
	c := ae.conn(t, tasksUser)
	if _, err := c.StartTask(context.Background(), researchWithFiles(), ""); err == nil || !strings.Contains(err.Error(), "files connector") {
		t.Fatalf("start with files: %v", err)
	}
	if _, evs := runAgentTask(t, c, research(researchBrief)); evs[len(evs)-1].Type != "done" {
		t.Fatalf("research without files: %s", types(evs))
	}
}
