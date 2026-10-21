package guard

import (
	"context"
	"encoding/json"
	"encoding/json/jsontext"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tacyhq/tacy/harness"
	"github.com/tacyhq/tacy/proto"
)

// a_research with the person's files (v0.13.0): review's intake, the files read inside the VM by the quarantined
// reader, and nothing of them sent out: a search or page read carrying a passage of a file is refused in gatewayd.

const filesBrief = "Task: Check the policy against current rules\n\nWhich of this policy's claims are still current?"

// policyText is a synthetic company policy with a canary in a sentence no query should ever carry.
func policyText() string {
	return "NORTHWIND REMOTE WORK POLICY\n\n" +
		"1. Scope. This policy applies to all employees of Northwind Traders who work from home at least two days a week.\n\n" +
		"2. Equipment. The company reimburses home office equipment up to 500 dollars a year under reference PELICAN-CANARY-3.\n\n" +
		"3. Data. Employees must store customer records only on company laptops encrypted under the 2019 security standard.\n"
}

func researchFilesReq(files ...TaskFile) *proto.RunRequest {
	if len(files) == 0 {
		files = []TaskFile{{Name: "policy.txt", Text: policyText()}}
	}
	return &proto.RunRequest{Agent: AgentResearch, Space: testSpace, Permissions: AllowAll(), Messages: []proto.Message{
		{Role: "system", Content: "Today is Tuesday, October 20, 2026."}, {Role: "user", Content: attach(filesBrief, files...)}}}
}

func TestResearchFilesIntake(t *testing.T) {
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	// A link only in the file isn't one the person gave; the brief's is.
	file := TaskFile{Name: "policy.txt", Text: policyText() + "\nSee https://intranet.northwind.example/policy for details.\n"}
	r := researchFilesReq(file)
	r.Messages[1].Content = attach(filesBrief+" Compare with https://www.ftc.gov/rules.", file)
	s, o, err := StartFor(r, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(o.Files) != 1 || o.Files[0].Text != file.Text || o.Agent != AgentResearch {
		t.Fatalf("files %+v", o.Files)
	}
	msg := s.Input[len(s.Input)-1].Content
	if strings.Contains(msg, "PELICAN-CANARY-3") || !strings.Contains(msg, "Which of this policy's claims are still current?") ||
		!strings.Contains(msg, "Files the person attached (you never see their text: read them with files_read):\n1. policy.txt:") {
		t.Fatalf("the model's message %q", msg)
	}
	var tools []string
	for _, d := range s.Tools {
		tools = append(tools, d.Name)
	}
	if !slices.Contains(tools, "files.read") || !slices.Contains(tools, "web.search") {
		t.Fatalf("tools %v", tools)
	}
	if !slices.Equal(o.Links, []string{"https://www.ftc.gov/rules"}) {
		t.Fatalf("links %v", o.Links)
	}
	if !strings.Contains(s.Instructions, "Read the files first") || !strings.Contains(s.Instructions, "### From your files") ||
		!strings.Contains(s.Instructions, "quotes as [file quote N] references (source 0") || strings.Contains(s.Instructions, "{{") {
		t.Fatalf("instructions %q", s.Instructions)
	}
	// Its file quotes have a marker of their own, in the tool's description too (review's stays [quote N]).
	for _, d := range s.Tools {
		if d.Name == "files.read" && (d.Description != researchFilesReadDesc || !strings.Contains(d.Description, "[file quote N]")) {
			t.Fatalf("files_read's description %q", d.Description)
		}
	}
	if toolDefs["files_read"].Function.Description == researchFilesReadDesc {
		t.Fatal("review's files_read description changed")
	}
	// Without files: no files tools and the prompt as before (no files words), the brief as the message.
	s, o, err = StartFor(researchReq(proto.Message{Role: "user", Content: "Task: x\n\nWhat changed in the 2026 rules?"}), now)
	if err != nil || len(o.Files) != 0 {
		t.Fatalf("no files: %v %+v", err, o.Files)
	}
	for _, d := range s.Tools {
		if strings.HasPrefix(d.Name, "files") {
			t.Fatalf("tool %s without files", d.Name)
		}
	}
	if strings.Contains(s.Instructions, "files") || strings.Contains(s.Instructions, "{{") {
		t.Fatalf("instructions without files %q", s.Instructions)
	}
	// Review's caps hold: six files, a file after the brief, files without files_read.
	six := make([]TaskFile, 6)
	for i := range six {
		six[i] = TaskFile{Name: fmt.Sprintf("f%d.txt", i), Text: "Text."}
	}
	if _, _, err := StartFor(researchFilesReq(six...), now); err == nil || !strings.Contains(err.Error(), "at most 5 files") {
		t.Fatalf("six files: %v", err)
	}
	late := researchFilesReq()
	late.Messages[1].Content = filesBrief + "\n\n" + attach("", TaskFile{Name: "x.txt", Text: "X."})
	if _, _, err := StartFor(late, now); err == nil {
		t.Fatal("a file after the brief was taken")
	}
	noRead := researchFilesReq()
	noRead.Tools = []string{"web_search", "fetch_page"}
	if _, _, err := StartFor(noRead, now); err == nil || !strings.Contains(err.Error(), "files_read") {
		t.Fatalf("files without files_read: %v", err)
	}
	big := researchFilesReq(TaskFile{Name: "big.txt", Text: strings.Repeat("a", maxReviewChars+1)})
	if _, _, err := StartFor(big, now); err == nil {
		t.Fatal("over 1,000,000 characters taken")
	}
}

// The privacy test: a passage of the person's file never leaves the VM in a search or a page read. Whatever the
// permissions or a grant say, an action whose arguments carry six or more of a file's words in a row (any case,
// punctuation, percent-encoding, inside a longer query or a URL) is refused in gatewayd before anything is sent:
// the search provider and the fetcher see nothing. The model's own few words (a public name, a topic) go out as
// any query does, and words the brief has too are the person's own.
func TestResearchFileTextNeverSent(t *testing.T) {
	trap := &egressTrap{}
	fs := &fakeSearch{}
	client := &http.Client{Transport: trap}
	var recMu sync.Mutex
	var records []Egress
	g := New(Config{Up: nil, Search: fs, Fetcher: client, Icons: client, Record: func(e Egress) {
		recMu.Lock()
		records = append(records, e)
		recMu.Unlock()
	}})
	opts, _ := json.Marshal(TaskOptions{Agent: AgentResearch, Permissions: AllowAll(), RunSecret: testSecret,
		Question: filesBrief + " Is home office equipment up to 500 dollars a year still typical?",
		Files:    []TaskFile{{Name: "policy.txt", Text: policyText()}, {Name: "notes.md", Text: "# Notes\n\nOur vendor Contoso Ltd renews the laptop lease every March.\n"}}})
	ti := &harness.TaskInfo{ID: "tk_rf", Start: &harness.Start{}, Options: opts}
	act := func(id, name, args string) *harness.ActionResult {
		t.Helper()
		ctx := WithGrant(harness.WithRequestID(context.Background(), id), &Grant{Task: ti.ID, Kind: name, Decision: DecideAlways, Request: id})
		res, err := g.Action(ctx, ti, id, &harness.Action{Name: name, Call: id, Args: jsontext.Value(args)})
		if err != nil {
			t.Fatal(err)
		}
		return res
	}
	passage := "store customer records only on company laptops encrypted"
	refused := [][2]string{
		{"web.search", `{"query":"Employees must store customer records only on company laptops"}`},
		{"web.search", `{"query":"remote work rules: STORE Customer-Records, only on company laptops!"}`},
		{"web.search", `{"query":"` + strings.ToUpper(passage) + `"}`},
		{"web.search", `{"query":"vendor contoso ltd renews the laptop lease"}`},
		{"web.fetch", `{"url":"https://a.example/search?q=` + url.QueryEscape(passage) + `"}`},
		{"web.fetch", `{"url":"https://a.example/` + strings.ReplaceAll(passage, " ", "-") + `"}`},
		{"web.fetch", `{"url":"https://a.example/p?q=` + strings.ReplaceAll(url.PathEscape(passage), "%20", "%20") + `"}`},
		{"web.search", `{"query":"policy applies to all employees of Northwind Traders who work from home"}`},
	}
	for i, c := range refused {
		res := act(fmt.Sprintf("x%d", i), c[0], c[1])
		if res.Status != harness.ActionDenied || !strings.HasPrefix(res.Error, FileTextDenied+": ") {
			t.Errorf("%s %s: %+v", c[0], c[1], res)
		}
	}
	if len(fs.queries) != 0 || len(trap.reqs) != 0 {
		t.Fatalf("a passage went out: %v %v", fs.queries, trap.reqs)
	}
	var egress []Egress
	for _, e := range records {
		if e.Rule == FileTextDenied {
			egress = append(egress, e)
		}
	}
	if len(egress) != len(refused) {
		t.Fatalf("records %+v", egress)
	}
	// The model's own words go out: a public name and a topic, five of the file's words in a row at most, and a
	// passage the brief has too.
	allowed := []string{
		`{"query":"Northwind Traders remote work policy"}`,
		`{"query":"laptop encryption standard 2026"}`,
		`{"query":"records only on company laptops"}`,
		`{"query":"home office equipment up to 500 dollars a year"}`,
	}
	for i, q := range allowed {
		if res := act(fmt.Sprintf("ok%d", i), "web.search", q); res.Status != harness.ActionDone {
			t.Errorf("%s: %+v", q, res)
		}
	}
	if len(fs.queries) != len(allowed) {
		t.Fatalf("queries %v", fs.queries)
	}
	// A research task without files and a review aren't changed by it.
	ropts, _ := json.Marshal(TaskOptions{Agent: AgentResearch, Permissions: AllowAll(), RunSecret: testSecret})
	rti := &harness.TaskInfo{ID: "tk_r", Start: &harness.Start{}, Options: ropts}
	ctx := WithGrant(harness.WithRequestID(context.Background(), "n1"), &Grant{Task: rti.ID, Kind: "web.search", Decision: DecideAlways, Request: "n1"})
	if res, _ := g.Action(ctx, rti, "n1", &harness.Action{Name: "web.search", Call: "n1", Args: jsontext.Value(`{"query":"` + passage + `"}`)}); res.Status != harness.ActionDone {
		t.Fatalf("research without files: %+v", res)
	}
}

// End to end with the runtime and brain: the agent reads the file through files_read (the research reader's prompt,
// the brief as its question), its quotes have no web source (index 0, the file's name), a search carrying a passage
// is refused and one in the model's own words goes out, the model never gets the file's text, and the VM lists the
// parts not read after the brief.
func TestResearchWithFilesEndToEnd(t *testing.T) {
	brief := "## Plan\n1. Is the 2019 standard current?\n\n## Summary\nThe policy cites the 2019 standard [quote 1]; current guidance differs [1].\n\n## Sources\n### From your files\n- policy.txt: [quote 1]\n### From the web\n[1] github.com, dstack v0.6.1, 1 day ago"
	sm := &splitModel{
		acting: []string{
			toolCallSSE("c1", "files_read", `{}`),
			callsSSE([3]string{"c2", "web_search", `{"query":"store customer records only on company laptops encrypted"}`},
				[3]string{"c3", "web_search", `{"query":"laptop encryption standard 2026"}`}),
			textSSE(brief)},
		reader: func(prompt string) string {
			if strings.Contains(prompt, "Kind: search results") {
				return answerJSON(t, nil)
			}
			return answerJSON(t, func(m map[string]any) {
				m["summary"] = "The policy requires encrypted company laptops under a 2019 standard [Q1]."
				m["facts"] = []string{"Data: records only on encrypted company laptops [Q1]."}
				m["quotes"] = []map[string]any{{"id": 1, "from": 4, "to": 4, "location": "3. Data", "topic": "encryption rule"}}
			})
		},
	}
	e := newReviewE2E(t, sm)
	evs := e.review(t, researchFilesReq())
	if evs[len(evs)-1].Type != "done" {
		t.Fatalf("ended %+v", evs[len(evs)-1])
	}
	var quotes []proto.Quote
	results := map[string]string{}
	for _, ev := range evs {
		if ev.Type == "tool_result" {
			results[ev.ID] = string(ev.Result)
			if ev.Name == "files_read" {
				quotes = append(quotes, ev.Quotes...)
			}
		}
	}
	if len(quotes) != 1 || quotes[0].Index != 0 || quotes[0].File != "policy.txt" || !strings.HasPrefix(quotes[0].Location, "policy.txt, part 1 of 1") {
		t.Fatalf("file quotes %+v", quotes)
	}
	// The model gets them as [file quote N], everywhere in the part's fields; never as a web quote's [quote N].
	var read filesReadOut
	if err := json.Unmarshal([]byte(results["c1"]), &read); err != nil || len(read.Parts) != 1 || read.Parts[0].Read == nil {
		t.Fatalf("files_read %s", results["c1"])
	}
	if v := read.Parts[0].Read; v.Quotes[0].Cite != "[file quote 1]" || !strings.HasSuffix(v.Summary, "[file quote 1].") ||
		!strings.HasSuffix(v.Facts[0], "[file quote 1].") || strings.Contains(results["c1"], "[quote 1]") || read.Note != researchReadNote {
		t.Fatalf("files_read %s", results["c1"])
	}
	if !slices.Equal(e.fs.queries, []string{"laptop encryption standard 2026"}) {
		t.Fatalf("searches sent %v", e.fs.queries)
	}
	for i, req := range sm.actReqs {
		if strings.Contains(string(req), "PELICAN-CANARY-3") || strings.Contains(string(req), "reimburses home office equipment") {
			t.Fatalf("the acting model's call %d has the file's text", i+1)
		}
	}
	if !strings.Contains(string(sm.actReqs[2]), FileTextDenied) {
		t.Fatal("the model wasn't told its search was refused")
	}
	// The file's part was read with the research reader's prompt, the brief its question.
	var filePrompt string
	for _, r := range sm.readReqs {
		msgs := r["messages"].([]any)
		if p := msgs[1].(map[string]any)["content"].(string); strings.Contains(p, "policy.txt, part 1 of 1") {
			filePrompt = p
			if sys := msgs[0].(map[string]any)["content"].(string); strings.Contains(sys, "attached for review") {
				t.Fatal("research read its file with review's prompt")
			}
		}
	}
	if !strings.Contains(filePrompt, "attached to their research brief") || !strings.Contains(filePrompt, "Which of this policy's claims") {
		t.Fatalf("file prompt %q", filePrompt)
	}
	if text := eventText(evs); !strings.HasSuffix(text, "## Parts of your files not read\nNone: all 1 part of the 1 file were read.\n") {
		t.Fatalf("text %q", text)
	}
}

// Research reads at most researchFileParts parts of the files: past it, files_read reads nothing (file_cap), and the
// VM lists the parts it didn't read with why.
func TestResearchFilePartsCap(t *testing.T) {
	var big strings.Builder
	for i := range researchFileParts + 8 {
		fmt.Fprintf(&big, "%d. Clause %d\n%s\n\n", i+1, i+1, strings.Repeat(fmt.Sprintf("Clause %d text runs on. ", i+1), 150))
	}
	file := TaskFile{Name: "big.txt", Text: big.String()}
	n := len(splitSections(file.Text, researchDef.PartRunes))
	if n <= researchFileParts {
		t.Fatalf("only %d parts", n)
	}
	call := func(i int) [3]string { return [3]string{fmt.Sprintf("c%d", i), "files_read", `{}`} }
	var mu sync.Mutex
	reads := 0
	sm := &splitModel{
		acting: []string{callsSSE(call(1), call(2), call(3)), callsSSE(call(4), call(5), call(6)), textSSE("## Summary\nDone.")},
		reader: func(string) string {
			mu.Lock()
			reads++
			mu.Unlock()
			return answerJSON(t, nil)
		},
	}
	e := newReviewE2E(t, sm)
	evs := e.review(t, researchFilesReq(file))
	if reads != researchFileParts {
		t.Fatalf("%d parts read (cap %d)", reads, researchFileParts)
	}
	capped := false
	for _, ev := range evs {
		if ev.Type == "tool_result" && ev.Name == "files_read" && strings.Contains(string(ev.Result), FileCapDenied) {
			capped = true
		}
	}
	text := eventText(evs)
	if !capped || !strings.Contains(text, fmt.Sprintf("- big.txt: parts %d-%d of %d", researchFileParts+1, n, n)) ||
		!strings.Contains(text, fmt.Sprintf("(not read: past the %d parts this task reads)", researchFileParts)) {
		t.Fatalf("capped %v, text %q", capped, text)
	}
}

// The reader's budget for one files.read (agentd reserves it from research's $1 before the read; ReaderReserve):
// small enough that a research task can read its files and still search.
func TestResearchFilesReserve(t *testing.T) {
	_, cost, ok := ReaderReserve("files.read", nil)
	if !ok || cost <= 0 || cost > researchDef.Run.CostMicros/4 {
		t.Fatalf("files.read reserve $%.3f of research's $%.2f", float64(cost)/1e6, float64(researchDef.Run.CostMicros)/1e6)
	}
	t.Logf("files.read reserves $%.3f", float64(cost)/1e6)
}

// A research part that starts inside a clause names the headings it's under (the reader took the CSA's "3. Privacy &
// Security" item "1. Personal Data", cut into the next part, for section 1); one at a top-level heading names none.
func TestOuterHeadings(t *testing.T) {
	text := "# Cloud Service Agreement\n\n1. Service\n    1. Access and Use.  Customer may use it.\n\n3. Privacy & Security\n    1. Personal Data.  Before submitting Personal Data, sign a DPA.\n        a. More detail.\n    2. Prohibited Data.  None.\n\n4. Payment & Taxes\n    1. Fees.  In dollars.\nA line that runs on.\n"
	at := func(s string) int { return strings.Index(text, s) }
	for _, c := range []struct{ start, want string }{
		{"    1. Personal Data", "Cloud Service Agreement > 3. Privacy & Security"},
		{"        a. More", "Cloud Service Agreement > 3. Privacy & Security > 1. Personal Data. Before submitting Personal Data, sign a DPA."},
		{"4. Payment", "Cloud Service Agreement"},
		{"A line that runs on", "Cloud Service Agreement > 4. Payment & Taxes > 1. Fees. In dollars."},
		{"# Cloud", ""},
	} {
		if got := outerHeadings(text, at(c.start)); got != c.want {
			t.Errorf("at %q: %q, want %q", c.start, got, c.want)
		}
	}
	if got := outerHeadings("1. A\n"+strings.Repeat("    ", 0)+"   2. "+strings.Repeat("x", 200)+"\n      a. b\n", 0); got != "" {
		t.Errorf("at the start: %q", got)
	}
}

// A research file part's sentence saying the part lacks something carries no quote (lab round 3): a quote can't show
// an absence. A rule's own "not" or "no" keeps its quote.
func TestAbsenceUncited(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"No liability cap, security obligations or switching terms appear in this section [quote 15].",
			"No liability cap, security obligations or switching terms appear in this section."},
		{"This part does not mention Rule 10b5-1 plans [quote 3]. Blackouts end on the third trading day [quote 4].",
			"This part does not mention Rule 10b5-1 plans. Blackouts end on the third trading day [quote 4]."},
		{"It contains no blackout period [quote 2][quote 5]; pre-clearance is in Part III [quote 6].",
			"It contains no blackout period; pre-clearance is in Part III [quote 6]."},
		{"The excerpt says nothing about cooling-off periods [quote 9].", "The excerpt says nothing about cooling-off periods."},
		{"The Customer may not resell or reverse engineer the Product [quote 3].", ""},
		{"Customer has no right to a refund except on termination for breach [quote 5].", ""},
		{"Pre-clearance is not required for trades under an Approved 10b5-1 Plan [quote 48].", ""},
		{"8.4: nothing limits liability for gross negligence, willful misconduct or fraud [quote 26].", ""},
		{"Section 8.2 does not apply to breaches of Section 10 [quote 24].", ""},
	} {
		want := c.want
		if want == "" {
			want = c.in
		}
		v := &readView{Summary: c.in, Facts: []string{c.in}, Wording: c.in}
		absenceUncited(v)
		if v.Summary != want || v.Facts[0] != want || v.Wording != want {
			t.Errorf("absenceUncited(%q)\n got %q\nwant %q", c.in, v.Facts[0], want)
		}
	}
}
