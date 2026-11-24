package main

import (
	"fmt"
	"net/http"
	"slices"
	"time"

	"github.com/tacyhq/tacy/safety"
	"github.com/tacyhq/tacy/trigger"
)

// What the relay charges a person's schedule (v0.16.0, "charge up front", the server
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
// prices, never sent. A header that matches none of the tables this release accepts (scheduleTables) is 400
// charge_mismatch (inside the encrypted answer); a call that matches says so in a plaintext answer header,
// X-Schedule-Priced: 1 (an older VM never does, and the relay then charges one run a day at the run budget's cap:
// $0.40 since this release, $0.25 before).
//
// The price tables are the chat's too (packages/client-core shared/schedule-charge.ts); both are tested against the
// same vectors (schedule_charge_test.go and the chat's own test).
const (
	scheduleChargeHeader = "X-Schedule-Charge"
	scheduleAgentHeader  = "X-Schedule-Agent"
	schedulePricedHeader = "X-Schedule-Priced"
)

// A price table for one scheduled run, µ$: per kind of run, the acting model's share on scheduleMeasuredModel (scaled
// to the schedule's dearest model by scheduleWeight) and the reader's and searches' share (fixed); stored files and
// email add theirs on top; cap is the most one run is priced at. The chat's tables are the same
// (packages/client-core shared/schedule-charge.ts SCHEDULE_PRICES_V1, SCHEDULE_PRICES_V2).
//
//   - read: cmd/digestlab measured a page-read digest at $0.070 a run (2026-10-20), and $0.065 to $0.089 at this
//     release's limits (2026-11-23): $0.07.
//   - files (v0.17.0): the quarantined reader on its files and the acting model reading what it found. An
//     estimate from the scheduled run's cap of 24 parts (about 96,000 characters; at most about $0.08 of reader
//     calls), not yet measured on real scheduled runs: re-measure with cmd/digestlab once a digest with files runs there.
//   - mail (v0.19.0, the connections contract "Scheduled tasks": any mail tool allowed always): the quarantined reader
//     on the mail it opens and the acting model reading what it found: the same estimate as stored files, on top.
type scheduleTable struct {
	readModel, readFixed, searchModel, searchFixed, filesModel, filesFixed, mailModel, mailFixed, cap int64
}

const scheduleMeasuredModel = "deepseek-v4-1-flash"

var (
	// schedulePricesV1 is v0.16.0 to v0.22.0's (at most 6 searches and $0.25 a run; one that may search $0.15): what
	// every shipped client sends, so this release accepts it beside V2. Drop it once the clients send V2 and no VM
	// they reach is older than this release (the no-downtime plan row 77).
	schedulePricesV1 = scheduleTable{readModel: 30_000, readFixed: 40_000, searchModel: 50_000, searchFixed: 100_000,
		filesModel: 10_000, filesFixed: 40_000, mailModel: 10_000, mailFixed: 40_000, cap: 250_000}
	// schedulePricesV2 is this release's (15 searches and $0.40 a run, guard/agents.go scheduledDef): one that may
	// search $0.235. cmd/digestlab news (2026-11-23, 4 news digests on deepseek-v4-1-flash) measured $0.22 to $0.25 a
	// run, about $0.06 of it the acting model's and the rest the reader's and the searches'. Its cap is the run budget.
	schedulePricesV2 = scheduleTable{readModel: 30_000, readFixed: 40_000, searchModel: 60_000, searchFixed: 175_000,
		filesModel: 10_000, filesFixed: 40_000, mailModel: 10_000, mailFixed: 40_000, cap: 400_000}
	// schedulePrices is the table scheduleCharge prices by; scheduleTables are all an install's header may match.
	schedulePrices = schedulePricesV2
	scheduleTables = []scheduleTable{schedulePricesV2, schedulePricesV1}
)

// scheduleMailActions are the tools that count as reading email.
var scheduleMailActions = []string{"mail.search", "mail.read", "mail.folders"}

// scheduleWeight is a model's price for a typical step (2,048 prompt and 1,500 completion tokens), in whole units of
// the price table: what a schedule's model share is scaled by.
func scheduleWeight(model string) int64 {
	in, out := safety.PricePerM(model)
	return 2048*in + 1500*out
}

// scheduleRunCost is one run's expected cost on model (the dearest the schedule names), µ$, in integers, on this
// release's table: whether it may search, whether it reads stored files (files), and whether it reads email (mail).
func scheduleRunCost(model string, search, files, mail bool) int64 {
	return schedulePrices.runCost(model, search, files, mail)
}

func (p scheduleTable) runCost(model string, search, files, mail bool) int64 {
	share, fixed := p.readModel, p.readFixed
	if search {
		share, fixed = p.searchModel, p.searchFixed
	}
	if files {
		share, fixed = share+p.filesModel, fixed+p.filesFixed
	}
	if mail {
		share, fixed = share+p.mailModel, fixed+p.mailFixed
	}
	w, base := scheduleWeight(model), scheduleWeight(scheduleMeasuredModel)
	return min(p.cap, fixed+(share*w+base-1)/base)
}

// scheduleCharge is the X-Schedule-Charge value of d's install on this release's table.
func scheduleCharge(d *trigger.Definition) string { return scheduleChargeOn(d, schedulePrices) }

// scheduleChargeOn is the X-Schedule-Charge value of d's install on table p.
func scheduleChargeOn(d *trigger.Definition, p scheduleTable) string {
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
	run := p.runCost(model, search, len(d.Files) > 0, mail)
	return fmt.Sprintf("v1 %s daily=%d once=%d until=%s", d.Agent, (run*week+6)/7, run*once, d.NotAfter.UTC().Format(time.DateOnly))
}

// checkScheduleCharge: an install's X-Schedule-Charge, when sent, is what d says on one of the tables this release
// accepts ("" and true when none was sent). Either is a price the chat computed from the same signed definition: V1 is
// what shipped clients send, V2 what they send once they switch (add, switch, remove; the no-downtime plan row 77).
func checkScheduleCharge(r *http.Request, d *trigger.Definition, decoded bool) (sent, ok bool) {
	h := r.Header.Get(scheduleChargeHeader)
	if h == "" {
		return false, true
	}
	if !decoded {
		return true, false
	}
	for _, p := range scheduleTables {
		if h == scheduleChargeOn(d, p) {
			return true, true
		}
	}
	return true, false
}
