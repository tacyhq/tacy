package guard

import (
	"context"
	"encoding/json"
	"encoding/json/jsontext"
	"slices"
	"strings"
	"time"

	"github.com/tacyhq/tacy/harness"
	"github.com/tacyhq/tacy/proto"
)

// The web connector: actions web.search, web.fetch and web.images, each running tools.go's tool of that kind
// (PII masking, public-only fetching, the tool caps, re-encoded images). The guard routes an action by name to its
// connector (docs/20, "Connectors"); this is the only one so far.
var webTools = []struct{ action, app string }{
	{"web.search", "web_search"},
	{"web.fetch", "fetch_page"},
	{"web.images", "image_search"},
}

// appTool is the tools.go tool an action runs ("" for none). Its name is also what the chat's events carry
// (tool_call, tool_result), until the chat knows the action names.
func appTool(action string) string {
	for _, w := range webTools {
		if w.action == action {
			return w.app
		}
	}
	return ""
}

// webAction is the action for a tools.go tool name ("" for none).
func webAction(app string) string {
	for _, w := range webTools {
		if w.app == app {
			return w.action
		}
	}
	return ""
}

// eventName is the tool name people's events carry for an action.
func eventName(action string) string {
	if a := appTool(action); a != "" {
		return a
	}
	return action
}

// Action runs one of the brain's actions through its connector. It shows people the result (images, tool_result,
// site icons, metrics) under the model tool call the action carries out, and returns what the model sees: done
// with the tool's JSON; denied when policy refused it (a URL with personal data); failed with the tool's error.
func (g *Guard) Action(ctx context.Context, ti *harness.TaskInfo, id string, req *harness.Action) (*harness.ActionResult, error) {
	app := appTool(req.Name)
	if app == "" {
		return nil, harness.Errf(harness.CodeNotAllowed, "no connector runs %s", req.Name)
	}
	ctx = withTask(ctx, ti.ID)
	t := g.task(ti)
	ctx = withSpace(ctx, t.opts.Space)
	if err := g.checkSafety(t.opts.Space, req); err != nil {
		if d, ok := deniedResult(err); ok {
			g.record(Egress{Task: ti.ID, Action: id, Op: req.Name, Decision: "denied", Rule: "policy"})
			return d, nil
		}
		return nil, err
	}
	// Permission prompts: nothing goes out without the person's answer (permission.go): their setting, or a valid grant from
	// their tab; an edited value replaces the model's.
	args, denied := g.permit(ctx, t, ti, id, req)
	if denied != nil {
		g.record(Egress{Task: ti.ID, Action: id, Op: req.Name, Decision: "denied", Rule: "permission"})
		return denied, nil
	}
	if g.cfg.Safety != nil {
		ctx = withHostFilter(ctx, g.fetchFilter(t.opts.Space))
	}
	call := t.claim(req.Call, id, app, args)
	defer t.markReturned() // its result, whatever it is, reaches the brain: outside content for the next model call
	step := t.currentStep()
	t1 := time.Now()
	var p pending
	var shown json.RawMessage
	// The brain's arguments are scanned before anything is sent: a credential pattern, in any encoding, blocks the
	// action (denied), like a URL with personal data.
	if ids := outboundLeak(args); ids != nil {
		g.record(Egress{Task: ti.ID, Action: id, Op: req.Name, Decision: "denied", Rule: "leak_scan", Patterns: ids})
		FactsFrom(ctx).leak(true, ids)
		provider := ""
		if app != "fetch_page" {
			provider = t.tools.search.Name()
		}
		p, shown = pending{out: leakRefused(ids, provider)}, json.RawMessage(args)
	} else {
		p, shown = t.tools.Exec(ctx, app, json.RawMessage(args))
	}
	ms := max(0, time.Since(t1)-p.out.wait).Milliseconds()
	if ctx.Err() != nil {
		return nil, ctx.Err() // cancelled: the runtime answers "cancelled"
	}
	// The quarantined reader (reader.go) reads the page or the results before anything is numbered, in parallel
	// with the step's other calls; the model then gets its fields, never the text.
	if d := g.readerDoc(ctx, ti.ID, id, req.Name, &p); d != nil {
		p.read = g.read(ctx, t, step, d)
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
	}
	// Citation numbers go in the order calls finish (decided): the runtime can't see the brain's
	// steps. The model and people see the same numbers, and a replay gets the journaled ones.
	// The lock is held until the result is shown, so people see the numbers in order even when calls finish
	// together.
	t.numbering.Lock()
	out := t.tools.Finish(p)
	// What came back is redacted before the brain (and people) see it.
	if ids := redactOutcome(&out); len(ids) > 0 {
		g.record(Egress{Task: ti.ID, Action: id, Op: req.Name, Decision: "redacted", Rule: "leak_scan", Patterns: ids})
		FactsFrom(ctx).leak(false, ids)
	}
	t.tools.citedUnder(out.citations, call) // a card about one of these sources gets its picture there (cardpics.go)
	if !json.Valid(shown) {
		shown = json.RawMessage(`null`)
	}
	// From the old app/agent.go runCalls: the call's images first, then its result, then its sites' icons and its metric.
	for i, im := range out.images {
		t.emit(proto.Event{Type: "image", ID: call, Image: &proto.Image{Index: i + 1, Title: im.Title, Source: im.Source,
			URL: im.URL, Type: "image/jpeg", Width: im.Width, Height: im.Height, Data: im.JPEG}})
	}
	t.emit(proto.Event{Type: "tool_result", ID: call, Name: app, Args: shown, Masked: out.masked,
		Result: json.RawMessage(out.content), Citations: out.citations, Quotes: out.quotes})
	t.numbering.Unlock()
	t.icons.add(sourceURLs(out)...)
	m := toolMetric(app, step, out, ms)
	if out.tail != nil {
		// Its metric waits for the late images: it then counts what landed, what failed and the slots never filled.
		g.lateImages(t, id, call, len(out.images), out.tail, m)
	} else if m != nil {
		t.emit(proto.Event{Type: "metrics", Metrics: m})
	}
	return actionResult(out), nil
}

// lateImages shows the images of an image search that land after its result (findImages returned early): each
// is redacted like the others (its title; on the record as pattern ids), sent as the call's next "image" event and
// its site's icon fetched; the slots it didn't use go back. The end of the run waits for them at most imageEndWait
// (localSession.End); once the task ends, its downloads stop and nothing more is emitted. m, the call's metrics
// event, is sent when the tail ends, with the late images and failures added, and every slot that stayed empty
// counted as never_arrived (also on the task's background record).
func (g *Guard) lateImages(t *task, action, call string, shown int, tail *imageTail, m *proto.Metric) {
	t.lateMu.Lock()
	if t.ctx.Err() != nil { // the task ended: its downloads stop on their own (nobody shows them)
		t.lateMu.Unlock()
		lateMetric(m, imageStats{}, 0, tail.slots)
		t.background.imageNever(tail.slots)
		if m != nil {
			t.emit(proto.Event{Type: "metrics", Metrics: m})
		}
		return
	}
	t.late.Add(1)
	t.lateMu.Unlock()
	go func() {
		defer t.late.Done()
		used, bytes := 0, 0
		for im := range tail.ch {
			out := toolOutcome{images: []shownImage{im}}
			if ids := redactOutcome(&out); len(ids) > 0 {
				g.record(Egress{Task: t.id, Action: action, Op: "web.images", Decision: "redacted", Rule: "leak_scan", Patterns: ids})
				t.background.leak(false, ids)
			}
			im = out.images[0]
			used++
			bytes += len(im.JPEG)
			t.emit(proto.Event{Type: "image", ID: call, Image: &proto.Image{Index: shown + used, Title: im.Title, Source: im.Source,
				URL: im.URL, Type: "image/jpeg", Width: im.Width, Height: im.Height, Data: im.JPEG}})
			t.icons.add(sourceURLs(out)...)
		}
		t.tools.returnImages(tail.slots - used)
		// Every download is over (ch is closed after the last): tail.st is final.
		st := tail.st
		st.bytes = bytes
		lateMetric(m, st, used, tail.slots-used)
		t.background.imageCounts(used, tail.st.reasons)
		t.background.imageNever(tail.slots - used)
		if m != nil {
			t.emit(proto.Event{Type: "metrics", Metrics: m})
		}
	}()
}

// lateMetric adds an image search's tail to its metric: the images that landed after the result, the downloads
// that finished then (tried, failed and why) and the slots that stayed empty (never_arrived).
func lateMetric(m *proto.Metric, st imageStats, landed, empty int) {
	if m == nil {
		return
	}
	m.Images += landed
	m.Tried += st.tried
	m.Failed += st.failed
	m.FetchMs += st.fetchMs
	m.Bytes += st.bytes
	for r, n := range st.reasons {
		m.Reasons = addReason(m.Reasons, r, n)
	}
	if empty > 0 {
		m.Reasons = addReason(m.Reasons, imageNever, empty)
	}
}

func addReason(m map[string]int, reason string, n int) map[string]int {
	if n <= 0 {
		return m
	}
	if m == nil {
		m = map[string]int{}
	}
	m[reason] += n
	return m
}

// readerDoc is what the reader reads for an action's outcome: a fetched page, or a search's results (titles and
// snippets), with credentials redacted as they would be from what the brain sees. nil: nothing for the reader
// (the reader is off, the tool failed, no results, an image search).
func (g *Guard) readerDoc(ctx context.Context, task, id, action string, p *pending) *readerDoc {
	if g.cfg.Reader == nil || p.out.content != "" {
		return nil
	}
	var ids []string
	add := func(s string) string {
		r, found := redactForReader(s)
		ids = append(ids, found...)
		return r
	}
	var d *readerDoc
	switch {
	case p.page != nil:
		d = &readerDoc{kind: "page", title: add(p.page.title), url: p.page.final, text: add(p.page.text)}
	case len(p.results) > 0:
		d = &readerDoc{kind: "search"}
		for _, r := range p.results {
			d.results = append(d.results, SearchResult{Title: add(r.Title), Snippet: add(r.Snippet)})
		}
	default:
		return nil
	}
	if len(ids) > 0 {
		slices.Sort(ids)
		ids = slices.Compact(ids)
		g.record(Egress{Task: task, Action: id, Op: action, Decision: "redacted", Rule: "leak_scan", Patterns: ids})
		FactsFrom(ctx).leak(false, ids)
	}
	return d
}

// actionResult is the protocol's view of a tool outcome. A tool that failed answers {"error": ...} (errorOutcome);
// the brain gives the model that same JSON back from the error text.
func actionResult(out toolOutcome) *harness.ActionResult {
	var e struct {
		Error *string `json:"error"`
	}
	if strings.HasPrefix(out.content, `{"error":`) && json.Unmarshal([]byte(out.content), &e) == nil && e.Error != nil {
		st := harness.ActionFailed
		if out.failed == "refused" {
			st = harness.ActionDenied
		}
		msg := *e.Error
		if len(msg) > harness.MaxErrorText {
			msg = strings.ToValidUTF8(msg[:harness.MaxErrorText], "")
		}
		return &harness.ActionResult{Status: st, Error: msg}
	}
	return &harness.ActionResult{Status: harness.ActionDone, Output: jsontext.Value(out.content)}
}

// claim finds the model tool call an action carries out (req.Call: the runtime checked it names a call of the
// latest model result) and returns the id people see its result under. An action whose call people weren't shown
// (its model result came before a runtime restart, or another action took it) is shown under its request id, with
// a tool_call of its own.
func (t *task) claim(call, id, app string, args jsontext.Value) string {
	t.mu.Lock()
	for i := range t.open {
		if c := &t.open[i]; call != "" && c.id == call && !c.claimed {
			c.claimed = true
			t.mu.Unlock()
			return call
		}
	}
	t.mu.Unlock()
	t.emit(proto.Event{Type: "tool_call", ID: id, Name: app, Args: json.RawMessage(args)})
	return id
}

// toolMetric is the metrics event for a tool call that ran (nil for one refused before running: bad arguments).
// Kind, step, duration, provider, result count and outcome only: not the query, the URL or its host.
// As the old app/agent.go had it.
func toolMetric(name string, step int, out toolOutcome, ms int64) *proto.Metric {
	if !out.ran {
		return nil
	}
	m := &proto.Metric{Step: step, Ms: ms, WaitMs: out.wait.Milliseconds(), Outcome: "ok"}
	if out.failed != "" {
		m.Outcome = out.failed
	}
	switch name {
	case "web_search":
		m.Kind, m.Provider = "search", out.provider
		if out.failed == "" {
			m.Results = len(out.citations)
		}
	case "fetch_page":
		m.Kind = "fetch"
	case "image_search":
		m.Kind, m.Provider = "images", out.provider
		if st := out.istats; st != nil {
			m.Results, m.Tried, m.Failed, m.Bytes, m.FetchMs = st.candidates, st.tried, st.failed, st.bytes, st.fetchMs
			for r, n := range st.reasons {
				m.Reasons = addReason(m.Reasons, r, n)
			}
		}
		m.Images = len(out.images)
	default:
		return nil
	}
	return m
}
