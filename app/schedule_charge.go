package main

import (
	"fmt"
	"net/http"
	"slices"
	"time"

	"github.com/tacyhq/tacy/safety"
	"github.com/tacyhq/tacy/trigger"
)

// What the relay charges a person's schedule (v0.16.0; decided 2026-10-21, "charge up front", the server
// learning nothing new about the schedule). A scheduled run fires on this VM's clock and the relay never hears of it,
// so the relay charges each active schedule an expected cost per UTC day on the person's own budget. It learns only
// prices, from one plaintext header on the install (or renewal) call, which this VM recomputes from the signed
// definition before installing (as X-Agent-Kind on a task start), and it stops charging when a stop or remove names
// the schedule (X-Schedule-Agent, checked against the signed call). Nothing is told at run time.
//
//	X-Schedule-Charge: v1 <agent> daily=<µ$> once=<µ$> until=<YYYY-MM-DD>
//
// agent: the schedule's random id (a_…), so a later stop or remove can name it. daily: one run's expected cost times
// its recurring runs a week, over 7, rounded up (a daily trigger runs 7 times a week, a weekday trigger on its days).
// once: its one-time runs' cost together. until: its not_after's UTC date. A run's expected cost is scheduleRunCost:
// how many runs, which models, whether it may search and whether it reads stored files are folded into the two
// prices, never sent. A mismatch is 400
// charge_mismatch (inside the encrypted answer); a call that matches says so in a plaintext answer header,
// X-Schedule-Priced: 1 (an older VM never does, and the relay then charges one run a day at the $0.25 cap).
//
// The price table is the chat's too (the chat's src/shared/schedule-charge.ts scheduleRunCost); both are tested against the
// same vectors (schedule_charge_test.go, test/unit/agent-charge.test.ts).
const (
	scheduleChargeHeader = "X-Schedule-Charge"
	scheduleAgentHeader  = "X-Schedule-Agent"
	schedulePricedHeader = "X-Schedule-Priced"
)

// A scheduled run's typical cost on scheduleMeasuredModel, µ$: the acting model's share (scaled to the schedule's
// dearest model by scheduleWeight) and the reader's and searches' share (fixed). cmd/digestlab measured a page-read
// digest at $0.070 a run (2026-10-20); one that may search adds up to 6 searches with the reader. Never past the run
// budget (scheduledDef: $0.25).
const (
	scheduleMeasuredModel = "deepseek-v4-1-flash"
	scheduleReadModel     = 30_000
	scheduleReadFixed     = 40_000
	scheduleSearchModel   = 50_000
	scheduleSearchFixed   = 100_000
	scheduleRunCap        = 250_000
	// A definition with stored files (v0.17.0) adds the quarantined reader on its files and the acting model
	// reading what it found. An estimate from the scheduled run's cap of 24 parts (about 96,000 characters; at most
	// about $0.08 of reader calls), not yet measured on real scheduled runs: re-measure with cmd/digestlab once a
	// digest with files runs there.
	scheduleFilesModel = 10_000
	scheduleFilesFixed = 40_000
	// A definition that reads the sponsor's email (v0.19.0, CONNECTIONS.md "Scheduled tasks": any mail tool allowed
	// always) adds the quarantined reader on the mail it opens (at most 6 searches' headers and 12 messages) and the
	// acting model reading what it found: the same estimate as stored files, on top of them.
	scheduleMailModel = 10_000
	scheduleMailFixed = 40_000
)

// scheduleMailActions are the tools that count as reading email.
var scheduleMailActions = []string{"mail.search", "mail.read", "mail.folders"}

// scheduleWeight is a model's price for a typical step (2,048 prompt and 1,500 completion tokens), in whole units of
// the price table: what a schedule's model share is scaled by.
func scheduleWeight(model string) int64 {
	in, out := safety.PricePerM(model)
	return 2048*in + 1500*out
}

// scheduleRunCost is one run's expected cost on model (the dearest the schedule names), µ$, in integers: whether it
// may search, whether it reads stored files (files), and whether it reads email (mail).
func scheduleRunCost(model string, search, files, mail bool) int64 {
	share, fixed := int64(scheduleReadModel), int64(scheduleReadFixed)
	if search {
		share, fixed = scheduleSearchModel, scheduleSearchFixed
	}
	if files {
		share, fixed = share+scheduleFilesModel, fixed+scheduleFilesFixed
	}
	if mail {
		share, fixed = share+scheduleMailModel, fixed+scheduleMailFixed
	}
	w, base := scheduleWeight(model), scheduleWeight(scheduleMeasuredModel)
	return min(scheduleRunCap, fixed+(share*w+base-1)/base)
}

// scheduleCharge is the X-Schedule-Charge value d's install must carry.
func scheduleCharge(d *trigger.Definition) string {
	week, once := int64(0), int64(0)
	for _, t := range d.Triggers {
		switch {
		case t.At != "":
			once++
		case t.Daily != "" && len(t.Days) > 0:
			week += int64(len(t.Days))
		case t.Daily != "":
			week += 7
		case t.Every != "": // not on personal spaces; priced by its slots in a week, at least one
			if p := t.Period(); p > 0 {
				week += max(1, int64((7*24*time.Hour+p-1)/p))
			}
		}
	}
	model := ""
	for _, m := range d.Models {
		if model == "" || safety.PriceRank(m) > safety.PriceRank(model) {
			model = m
		}
	}
	search := slices.Contains(d.Tools, "web.search") && d.Allow["web.search"] == "always"
	mail := slices.ContainsFunc(scheduleMailActions, func(a string) bool { return slices.Contains(d.Tools, a) && d.Allow[a] == "always" })
	run := scheduleRunCost(model, search, len(d.Files) > 0, mail)
	return fmt.Sprintf("v1 %s daily=%d once=%d until=%s", d.Agent, (run*week+6)/7, run*once, d.NotAfter.UTC().Format(time.DateOnly))
}

// checkScheduleCharge: an install's X-Schedule-Charge, when sent, is what d says ("" and true when none was sent).
func checkScheduleCharge(r *http.Request, d *trigger.Definition, decoded bool) (sent, ok bool) {
	h := r.Header.Get(scheduleChargeHeader)
	if h == "" {
		return false, true
	}
	return true, decoded && h == scheduleCharge(d)
}
