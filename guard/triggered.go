package guard

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/tacyhq/tacy/approval"
	"github.com/tacyhq/tacy/harness"
	"github.com/tacyhq/tacy/proto"
	"github.com/tacyhq/tacy/trigger"
)

// Unattended tasks (docs/27 section 3): a schedule or an inbound event starts a task from its signed
// agent definition, on its sponsor's authority and budget. Nobody is there to answer a permission prompt, so a kind the
// sponsor didn't set to always is denied; anything that needs approval waits (waiting: approval) until the sponsor
// approves it with their passkey in the chat. A task an event started is tainted from its start: the event came
// from outside, so every change it proposes needs the sponsor's approval too.

// TriggerCap is an unattended task's overall cap, waits included: long enough for its sponsor to answer an
// approval (approval.DefaultTTL) and for its running time (RunTimeout, counted only while it works).
var TriggerCap = approval.DefaultTTL + 30*time.Minute

// MaxTriggeredOpen caps the open tasks one agent may have: a schedule whose tasks all wait for approval can't pile up.
const MaxTriggeredOpen = 4

// unattendedNote is added to a definition's instructions (fixed in the release; the model can't change it).
const unattendedNote = `
This task runs unattended for its sponsor; nobody reads your messages while it runs. Anything that sends or changes something waits for the sponsor's approval in the Tacy app. If an action comes back denied (approval_denied or permission_denied), don't try it another way: finish and say what wasn't done. Your last message is what the sponsor gets: link each source in it by citing its number, like [3], which the app shows as a link to the source. Say only what the sources you read say, nothing from your own knowledge; when a source gave little, write less rather than fill it in.`

// ErrUnknownTool: a definition names a tool this release doesn't have.
var ErrUnknownTool = errors.New("the definition names a tool this release doesn't have")

// TriggeredStart makes the start and options of a fired task (StartTriggered).
func TriggeredStart(f trigger.Fire, firm string, now time.Time) (harness.Start, TaskOptions, error) {
	d := f.Def
	var s harness.Start
	var web, sink []string
	for _, t := range d.Tools {
		switch {
		case appTool(t) != "":
			web = append(web, t)
		case t == "sink.post" || t == "sink.put":
			sink = append(sink, t)
		default:
			return s, TaskOptions{}, fmt.Errorf("%w: %s", ErrUnknownTool, t)
		}
	}
	for _, m := range d.Models {
		if !KnownModel(m) {
			return s, TaskOptions{}, fmt.Errorf("the definition names a model this release doesn't have: %s", m)
		}
	}
	note := ""
	switch {
	case f.Trigger.IsDaily():
		// The person's own date and time (their zone): what "today" means for the run.
		loc, _ := time.LoadLocation(f.Trigger.Zone)
		if loc == nil {
			loc = time.UTC
		}
		note = fmt.Sprintf("Scheduled run: every day at %s (%s). Today is %s; it is %s there now.", f.Trigger.Daily, f.Trigger.Zone,
			f.At.In(loc).Format("Monday, January 2, 2006"), f.At.In(loc).Format("15:04"))
	case f.Trigger.Kind == trigger.Schedule:
		note = fmt.Sprintf("Scheduled run: trigger %s, slot %d, fired %s.", f.Trigger.ID, f.Slot, f.At.UTC().Format(time.RFC3339))
	case f.Trigger.Kind == trigger.Event:
		note = fmt.Sprintf("Event run: trigger %s, delivery %s", f.Trigger.ID, f.Delivery)
		if f.Ref != "" {
			note += ", ref " + f.Ref
		}
		note += fmt.Sprintf(", received %s.", f.At.UTC().Format(time.RFC3339))
	default:
		return s, TaskOptions{}, errors.New("unknown trigger kind")
	}
	s = harness.Start{Space: d.Space, Attempt: 1,
		Agent:        harness.AgentRef{ID: d.Agent, Version: strconv.FormatUint(d.Version, 10), Digest: f.Digest},
		Instructions: strings.TrimSpace(d.Instructions) + "\n" + unattendedNote, Models: d.Models,
		Tools: append(ToolDefs(web...), SinkToolDefs(sink...)...),
		Input: []harness.Message{{Role: "user", Content: note}},
		Limits: harness.TaskLimits{MaxSteps: min(d.Steps(), scheduledDef.Steps), MaxModelCalls: min(d.Steps(), scheduledDef.Steps) + 1,
			Deadline: now.Add(TriggerCap).UTC().Format(time.RFC3339)}}
	perms := map[string]string{}
	for _, k := range PermissionKinds() {
		if v, ok := d.Allow[k]; ok {
			perms[k] = v
		}
	}
	// The addresses the definition's instructions name are the sponsor's own, as a chat message's are the person's
	// (ComposedFetch); a page read comes with its links as numbered sources (links.go), so a digest of a page can
	// open and link what it lists without the model ever writing an address (docs/30 "Scheduled tasks", decision 9).
	// Its activity records are sealed to the definition's seal key (the space's chain; docs/27 section 12 decision 14),
	// with the sponsor as the member who started it; its budget is the schedule's own bucket (ScheduleMember), its
	// run budget a_scheduled's (decision 8: $0.25, 20 steps).
	opts := TaskOptions{User: d.Sponsor, Space: d.Space, Via: ViaTrigger, Firm: firm, Question: capRunes(d.Instructions, maxQuestionRunes),
		RecordTo: d.Seal, Identity: d.Sponsor, Member: ScheduleMember(d.Agent), DefVersion: d.Version, TriggerKind: f.Trigger.Kind,
		Slot: f.Slot, Due: f.Due,
		Permissions: maps.Clone(perms), Approvers: []string{d.Sponsor}, Agent: AgentScheduled, DefAgent: d.Agent, Digest: f.Digest, Trigger: f.Trigger.ID,
		Sponsor: d.Sponsor, NotAfter: d.NotAfter, Links: personLinks([]proto.Message{{Role: "user", Content: d.Instructions}}),
		PageLinks: slices.Contains(web, "web.fetch")}
	// The run uses the definition's first model; the others it lists (signed by the sponsor, each allowed by the
	// policy at install) are its fallbacks, in order: an overloaded or slow step switches to the first still allowed,
	// as a chat run on Auto does (fallback.go). One model: none.
	if fb := fallbackModels(d.Models[0], d.Models[1:]); len(fb) > 0 {
		opts.AutoFallback, opts.Fallbacks = true, fb
	}
	return s, opts, nil
}

// ScheduleMember is the budget bucket (safety.Ledger's member) of an agent definition's unattended runs: each
// schedule counts against a day budget of its own, not against a person's chat.
func ScheduleMember(agent string) string { return "schedule:" + agent }

// StartTriggered starts a fired task under its derived id (a repeat finds the first: existed). Tainted from its start
// when an event started it. At most MaxTriggeredOpen open tasks per agent (ErrTooMany).
func (h *Host) StartTriggered(ctx context.Context, f trigger.Fire, firm string) (existed bool, err error) {
	h.init()
	start, opts, err := TriggeredStart(f, firm, time.Now())
	if err != nil {
		return false, err
	}
	l := &hosted{id: f.Task, user: opts.User, via: ViaTrigger, start: start, opts: opts, changed: make(chan struct{}), st: h.RT.Store}
	h.mu.Lock()
	if h.live[f.Task] != nil {
		h.mu.Unlock()
		return true, nil
	}
	if st, err := h.RT.Store.Task(f.Task); err != nil || st != nil {
		h.mu.Unlock()
		return err == nil, err
	}
	open := 0
	for _, x := range h.live {
		if x.via == ViaTrigger && x.opts.DefAgent == opts.DefAgent && !x.isEnded() {
			open++
		}
	}
	if open >= MaxTriggeredOpen {
		h.mu.Unlock()
		return false, ErrTooMany
	}
	h.live[f.Task] = l
	h.mu.Unlock()
	taint := ""
	if f.Trigger.Kind == trigger.Event {
		taint = "event"
	}
	var tools []string
	for _, t := range start.Tools {
		tools = append(tools, t.Name)
	}
	existed, err = h.launch(ctx, l, start.Models[0], tools, taint)
	if err != nil {
		h.drop(l)
	}
	return existed, err
}

// Triggered is the open unattended tasks this process serves, with their options (agentd checks their sponsors).
func (h *Host) Triggered() map[string]TaskOptions {
	h.init()
	h.mu.Lock()
	defer h.mu.Unlock()
	out := map[string]TaskOptions{}
	for id, l := range h.live {
		if l.via == ViaTrigger && !l.isEnded() {
			out[id] = l.opts
		}
	}
	return out
}
