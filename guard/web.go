package guard

import (
	"context"
	"encoding/json"
	"encoding/json/jsontext"
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
	if g.cfg.Safety != nil {
		ctx = withHostFilter(ctx, g.fetchFilter(t.opts.Space))
	}
	call := t.claim(req.Call, id, app, req.Args)
	step := t.currentStep()
	t1 := time.Now()
	var p pending
	var shown json.RawMessage
	// The brain's arguments are scanned before anything is sent: a credential pattern, in any encoding, blocks the
	// action (denied), like a URL with personal data.
	if ids := outboundLeak(req.Args); ids != nil {
		g.record(Egress{Task: ti.ID, Action: id, Op: req.Name, Decision: "denied", Rule: "leak_scan", Patterns: ids})
		FactsFrom(ctx).leak(true, ids)
		provider := ""
		if app != "fetch_page" {
			provider = t.tools.search.Name()
		}
		p, shown = pending{out: leakRefused(ids, provider)}, json.RawMessage(req.Args)
	} else {
		p, shown = t.tools.Exec(ctx, app, json.RawMessage(req.Args))
	}
	ms := max(0, time.Since(t1)-p.out.wait).Milliseconds()
	if ctx.Err() != nil {
		return nil, ctx.Err() // cancelled: the runtime answers "cancelled"
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
	if !json.Valid(shown) {
		shown = json.RawMessage(`null`)
	}
	// From the old app/agent.go runCalls: the call's images first, then its result, then its sites' icons and its metric.
	for i, im := range out.images {
		t.emit(proto.Event{Type: "image", ID: call, Image: &proto.Image{Index: i + 1, Title: im.Title, Source: im.Source,
			URL: im.URL, Type: "image/jpeg", Width: im.Width, Height: im.Height, Data: im.JPEG}})
	}
	t.emit(proto.Event{Type: "tool_result", ID: call, Name: app, Args: shown, Masked: out.masked,
		Result: json.RawMessage(out.content), Citations: out.citations})
	t.numbering.Unlock()
	t.icons.add(sourceURLs(out)...)
	if m := toolMetric(app, step, out, ms); m != nil {
		t.emit(proto.Event{Type: "metrics", Metrics: m})
	}
	return actionResult(out), nil
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
		}
		m.Images = len(out.images)
	default:
		return nil
	}
	return m
}
