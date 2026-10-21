package guard

import (
	"cmp"
	"context"
	"encoding/json"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"errors"
	"fmt"
	"math/rand/v2"
	"slices"
	"time"

	"github.com/tacyhq/tacy/harness"
	"github.com/tacyhq/tacy/proto"
	"github.com/tacyhq/tacy/safety"
	"github.com/tacyhq/tacy/vault"
)

// ModelCall is the model gateway: one streamed completion from the verified upstream for a brain's model.call.
// People see the step as it comes (step, reasoning and text deltas, usage, metrics, the tool calls), as the old
// loop sent them; the brain gets the assembled message. Tool names are mapped both ways (the model sees
// harness.ModelToolName, the brain action names), and tool calls are checked so the result always passes the
// brain's strict decoder.
func (g *Guard) ModelCall(ctx context.Context, ti *harness.TaskInfo, req *harness.ModelCall) (*harness.ModelResult, error) {
	ctx = withTask(ctx, ti.ID) // the vault records the key's lease under the task and this request
	t := g.task(ti)
	if err := t.searchOnly(req); err != nil { // a plain chat's search task calls no model (searchtask.go)
		return nil, err
	}
	ctx = withSpace(ctx, t.opts.Space)
	if err := g.checkSafety(t.opts.Space, req); err != nil {
		return nil, err
	}
	efforts, ok := models[req.Model]
	if !ok {
		return nil, harness.Errf(harness.CodeNotAllowed, "model %s isn't available", req.Model)
	}
	if req.ReasoningEffort != "" && !slices.Contains(efforts, req.ReasoningEffort) {
		return nil, harness.Errf(harness.CodeNotAllowed, "model %s doesn't accept reasoning_effort %q", req.Model, req.ReasoningEffort)
	}
	effort := clampEffort(efforts, t.opts.ReasoningEffort, req.ReasoningEffort)
	// Every tool of the task, by the name the model sees (earlier messages may name tools this call doesn't
	// offer: the last step offers none).
	toAction := map[string]string{}
	var defs []toolDef
	for _, tl := range ti.Start.Tools {
		name := harness.ModelToolName(tl.Name)
		toAction[name] = tl.Name
		if slices.Contains(req.Tools, tl.Name) {
			defs = append(defs, def(name, tl.Description, string(tl.Parameters)))
		}
	}
	g.answered(t, req.Messages)
	t.mu.Lock()
	t.outside = t.outside || t.returned || ti.Tainted
	t.step++
	step := t.step
	t.mu.Unlock()
	t.emit(proto.Event{Type: "step", Step: step})

	// The model it goes to: the one the task switched to after a slow call, if it did (fallback.go), with the
	// effort that model accepts; and the fallback this call may switch to.
	model, fallback := g.route(t, req.Model, PricedFrom(ctx))
	if model != req.Model {
		effort = effortFor(model, effort)
	}
	// The request as the old app/agent.go built it.
	build := func(model, effort string) []byte {
		msgs := toModel(req.Messages)
		withImages(msgs, req.Messages, t.opts.Images, SeesImages(model)) // the person's images: to the model only (images_in.go)
		body := map[string]any{"model": model, "messages": msgs, "stream": true,
			"stream_options": map[string]any{"include_usage": true}}
		if secret := cmp.Or(t.opts.CacheSecret, g.cfg.CacheSecret); secret != "" {
			body["user_cache_secret"] = secret
		}
		if effort != "" {
			body["reasoning_effort"] = effort
		}
		if len(defs) > 0 {
			body["tools"] = defs
			body["parallel_tool_calls"] = true // all six models accept it (checked 2026-10-14)
		}
		raw, _ := json.Marshal(body)
		return raw
	}
	raw := build(model, effort)
	t0 := time.Now()
	failed := func(err error) (*harness.ModelResult, error) {
		t.emit(proto.Event{Type: "metrics", Metrics: &proto.Metric{Kind: "model", Step: step, Model: model, Ms: msSince(t0), Outcome: "error"}})
		if ctx.Err() != nil {
			return nil, ctx.Err() // cancelled: the runtime answers "cancelled"
		}
		var pe *harness.Error
		if errors.As(err, &pe) {
			return nil, pe // model_overloaded: our words, never the provider's
		}
		return nil, harness.Errf(harness.CodeInternal, "%v", err)
	}
	// The key this call was made with never comes back out, in any encoding: each delta people see, and the
	// whole message the brain gets (a key split across deltas is caught there). Model output isn't pattern-scanned
	// (docs/21 section 2: the model is attested and the answer is the point).
	maxOut, outBytes := MaxTokensFrom(ctx), int64(0)
	onDelta := func(kind, delta string, leased []*vault.Secret) error {
		// The output cap agentd reserved budget for (step 6): counted from the bytes streamed back (about 3 per
		// token, on the high side), so a call can't run past its budget even if the upstream would.
		if outBytes += int64(len(delta)); maxOut > 0 && outBytes/3 > maxOut {
			return fmt.Errorf("%s: the model's answer passed the %d tokens reserved for it", safety.CodeBudgetExceeded, maxOut)
		}
		if kind == "tool_call" {
			return nil // counted only: the calls are shown once complete (tool_call events below)
		}
		if leased != nil {
			delta = string(exactRedact([]byte(delta), leased))
		}
		t.emit(proto.Event{Type: kind, Delta: delta})
		switch kind {
		case "text":
			g.cardText(t, delta) // an items block that closes: its cards' pictures from their sources (cardpics.go)
		case "reasoning":
			g.watchMentions(t, delta) // the items it names: their lookups start now (pictures.go)
		}
		return nil // a person who went away cancels the task (Run); the model call itself finishes
	}
	t.cards.reset()
	said := false // model_slow, once per model a step tries
	a := g.try(ctx, t, step, model, raw, fallback, &said, onDelta)
	// For the activity record: one request to the model's host (the key's lease names it), the request's bytes
	// before EHBP encryption and the answer's as it streamed back (text, reasoning and tool calls' names and
	// arguments).
	FactsFrom(ctx).model(int64(len(raw)), outBytes)
	// Overloaded before any token: the same call again after a short jittered wait (fallback.go overloadWait), each
	// try on the record as given up (outcome overloaded, no tokens).
	again := func() {
		for i := 0; a.abandon == "overloaded" && i < overloadRetries(fallback); i++ {
			FactsFrom(ctx).abandoned(ModelAttempt{Model: model, Outcome: a.abandon, Ms: msSince(t0)})
			base := cmp.Or(g.cfg.OverloadWait, DefaultOverloadWait)
			wait := time.NewTimer(overloadWait(base, i, overloadedAsk(a.err), fallback != "", rand.Float64()))
			select {
			case <-ctx.Done():
				wait.Stop()
				a = attempt{err: ctx.Err()}
				return
			case <-wait.C:
			}
			t0, outBytes = time.Now(), 0
			t.cards.reset()
			a = g.try(ctx, t, step, model, raw, fallback, &said, onDelta)
			FactsFrom(ctx).model(int64(len(raw)), outBytes)
		}
	}
	again()
	if a.abandon != "" && fallback != "" {
		// Given up as slow or overloaded (Auto): on the record as such, with its time and no tokens; the metric says
		// slow_switched (the chat counts it toward its model_slow alert). The step runs again, once, on the
		// fallback, which the task's later calls go straight to; that one is never switched again.
		ms := msSince(t0)
		FactsFrom(ctx).abandoned(ModelAttempt{Model: model, Outcome: a.abandon, Ms: ms})
		t.emit(proto.Event{Type: "metrics", Metrics: &proto.Metric{Kind: "model", Step: step, Model: model, Ms: ms, Outcome: "slow_switched"}})
		t.mu.Lock()
		t.switched = fallback
		t.mu.Unlock()
		t.emit(proto.Event{Type: "model_switched", Step: step, From: model, To: fallback})
		model, fallback, effort = fallback, "", effortFor(fallback, effort)
		raw, t0, outBytes = build(model, effort), time.Now(), 0
		t.cards.reset()
		said = false
		a = g.try(ctx, t, step, model, raw, "", &said, onDelta)
		FactsFrom(ctx).model(int64(len(raw)), outBytes)
		again()
	}
	if a.abandon == "overloaded" { // tried again and still overloaded, with no fallback left: our words, never the provider's
		a = attempt{err: overloadedError(model)}
	}
	FactsFrom(ctx).used(model)
	if a.err != nil {
		return failed(a.err)
	}
	g.cardTextDone(t)
	res := a.res
	m := &proto.Metric{Kind: "model", Step: step, Model: model, Ms: msSince(t0), Outcome: "ok"}
	if !res.firstAt.IsZero() {
		m.FirstMs = res.firstAt.Sub(t0).Milliseconds()
	}
	if !res.textAt.IsZero() {
		m.TextMs = res.textAt.Sub(t0).Milliseconds()
	}
	out := &harness.ModelResult{Message: harness.Message{Role: "assistant", Content: res.text}, FinishReason: "stop",
		ReasoningEffort: effort} // journaled with the result: a clamp is on record
	if label(res.finish, 32) {
		out.FinishReason = res.finish
	}
	if res.usage != nil {
		t.mu.Lock()
		t.usage.PromptTokens += res.usage.PromptTokens
		t.usage.CompletionTokens += res.usage.CompletionTokens
		t.usage.TotalTokens += res.usage.TotalTokens
		u := t.usage
		t.mu.Unlock()
		t.emit(proto.Event{Type: "usage", Step: step, Usage: &u})
		m.Prompt, m.Cached, m.Completion = res.usage.PromptTokens, min(res.cached, res.usage.PromptTokens), res.usage.CompletionTokens
		out.Usage = harness.Usage{Prompt: max(0, res.usage.PromptTokens), Completion: max(0, res.usage.CompletionTokens)}
	}
	t.emit(proto.Event{Type: "metrics", Metrics: m})

	var open []openCall
	for i, c := range res.calls {
		if i == harness.MaxToolCalls {
			break // the brain runs at most 4 per step anyway
		}
		tc := checkCall(i, c, toAction)
		out.Message.ToolCalls = append(out.Message.ToolCalls, tc)
		if len(defs) == 0 {
			continue // a call on a step offered no tools isn't shown (app/: the last step's calls are ignored)
		}
		shown := json.RawMessage(c.Function.Arguments)
		resultArgs := shown // the old loop (app/agent.go): a refused call's tool_result has the arguments, or null if they aren't JSON
		if !json.Valid(shown) {
			shown, _ = json.Marshal(capRunes(c.Function.Arguments, 500))
			resultArgs = json.RawMessage(`null`)
		}
		name := eventName(tc.Name)
		shown = t.shownArgs(tc.Name, shown)
		if json.Valid(resultArgs) && string(resultArgs) != "null" {
			resultArgs = shown
		}
		t.emit(proto.Event{Type: "tool_call", ID: tc.ID, Name: name, Args: shown})
		open = append(open, openCall{id: tc.ID, name: name, args: resultArgs})
	}
	t.mu.Lock()
	t.finish, t.open = out.FinishReason, open
	t.mu.Unlock()
	return out, nil
}

// clampEffort is the reasoning effort the gateway applies. The person's choice for the task caps the brain's: a
// brain may ask for a lower level, never a higher one; a higher one is clamped to the person's choice, not
// refused. levels are the model's accepted values, lowest first (models), and asked is one of them or "". When
// the person chose none the model's default applies whatever the brain asks: its level isn't known, so no level
// is known to be lower.
func clampEffort(levels []string, person, asked string) string {
	if person == "" || asked == "" {
		return person
	}
	if slices.Index(levels, asked) < slices.Index(levels, person) {
		return asked
	}
	return person
}

// toModel turns the brain's messages into the upstream's (OpenAI chat format), tools named as the model sees them.
// A call whose arguments didn't parse goes back as the model wrote it (raw_args, capped), as the old loop (app/agent.go) sent it,
// so the model sees what it wrote.
func toModel(ms []harness.Message) []map[string]any {
	out := make([]map[string]any, 0, len(ms))
	for _, m := range ms {
		o := map[string]any{"role": m.Role, "content": m.Content}
		if m.Role == "tool" {
			o["tool_call_id"] = m.ToolCallID
		}
		if len(m.ToolCalls) > 0 {
			calls := make([]toolCall, len(m.ToolCalls))
			for i, c := range m.ToolCalls {
				calls[i].ID, calls[i].Type = c.ID, "function"
				calls[i].Function.Name, calls[i].Function.Arguments = harness.ModelToolName(c.Name), string(c.Args)
				if c.BadArgs {
					calls[i].Function.Arguments = c.RawArgs
				}
			}
			o["tool_calls"] = calls
			if m.Content == "" {
				o["content"] = nil
			}
		}
		out = append(out, o)
	}
	return out
}

// checkCall turns one of the model's tool calls into the protocol's: the action name (a name no tool has stays
// as the model wrote it), an id and arguments the brain's strict decoder accepts. Arguments that aren't one JSON
// object strict JSON takes (duplicate names, invalid UTF-8, too deep, too big) become {} with BadArgs and the
// model's text in RawArgs (at most 4 KiB, marked when cut), so the brain can tell the model and the next model
// call shows it what it wrote.
func checkCall(i int, c toolCall, toAction map[string]string) harness.ToolCall {
	tc := harness.ToolCall{ID: c.ID, Name: c.Function.Name}
	if !label(tc.ID, 64) {
		tc.ID = fmt.Sprintf("call_%d", i+1)
	}
	if a, ok := toAction[tc.Name]; ok {
		tc.Name = a
	} else if !label(tc.Name, 64) {
		tc.Name = "unknown"
	}
	args := jsontext.Value(c.Function.Arguments).Clone()
	var v map[string]any
	if len(args) <= harness.MaxArgs && args.Kind() == '{' && jsonv2.Unmarshal(args, &v) == nil && depth(v) <= 32 &&
		args.Compact() == nil {
		tc.Args = args
	} else {
		tc.Args, tc.BadArgs, tc.RawArgs = jsontext.Value(`{}`), true, harness.CapRawArgs(c.Function.Arguments)
	}
	return tc
}

// depth is how deeply v nests objects and arrays.
func depth(v any) int {
	d := 0
	switch x := v.(type) {
	case map[string]any:
		for _, e := range x {
			d = max(d, depth(e))
		}
		return d + 1
	case []any:
		for _, e := range x {
			d = max(d, depth(e))
		}
		return d + 1
	}
	return 0
}

// maxShownResult caps a tool_result taken from the brain's own messages (a refusal is a few dozen bytes; a hostile
// brain could send megabytes into the person's stream).
const maxShownResult = 16 << 10

// answered shows people the result of each tool call the brain answered without an action (one it refused: an
// unknown tool, bad arguments, over the per-step cap; or one the runtime refused), from the tool messages of its
// next model call: the result as the model sees it, which is what tool_result is. Untrusted, display only.
func (g *Guard) answered(t *task, msgs []harness.Message) {
	t.mu.Lock()
	open := t.open
	t.open = nil
	t.mu.Unlock()
	for _, c := range open {
		if c.claimed {
			continue
		}
		for i := len(msgs) - 1; i >= 0; i-- {
			if m := msgs[i]; m.Role == "tool" && m.ToolCallID == c.id {
				res := json.RawMessage(m.Content)
				if len(res) > maxShownResult || !json.Valid(res) {
					res, _ = json.Marshal(capRunes(m.Content, maxShownResult/4))
				}
				t.emit(proto.Event{Type: "tool_result", ID: c.id, Name: c.name, Args: c.args, Result: res})
				break
			}
		}
	}
}
