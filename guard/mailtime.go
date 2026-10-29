package guard

import (
	"errors"
	"strings"
	"time"

	"github.com/tacyhq/tacy/imapro"
	"github.com/tacyhq/tacy/proto"
)

// Mail times in the person's time zone (2026-10-29): an 8:00 AM "overnight mail" schedule got each
// message's time in UTC ("received 13:03" for 6:03 AM) and took "since 6 PM yesterday" as 6 PM UTC. Now:
//   - the task knows the person's zone (TaskOptions.Zone): a schedule's own (its trigger's zone), or the chat's time
//     note, a system message in exactly the form dateNote takes ("Today is Thursday, October 29, 2026. The time is
//     8:00 AM in America/Los_Angeles."), the zone checked against the embedded tzdata;
//   - mail_search and mail_read show each message's arrival time (INTERNALDATE; the Date header when the server gives
//     none) in that zone, labelled with it ("Thu, Oct 29, 2026, 6:03 AM PDT");
//   - mail_search's since and before are the person's local dates, or dates with a time ("2026-10-28 18:00"). IMAP
//     SEARCH compares days only, in the server's own zone, so the server is asked for a day more on each side and
//     the candidates are filtered by their exact arrival time here.
// No zone (a tab before the chat sends its time note): UTC, and the result says the person's zone is unknown.

// zoneFromNotes is the person's IANA zone from the chat's time note among a request's system messages (the last
// one that is exactly such a note: dateNoteOK), or "".
func zoneFromNotes(ms []proto.Message) string {
	z := ""
	for _, m := range ms {
		if m.Role != "system" {
			continue
		}
		s := strings.TrimSpace(m.Content)
		if !dateNoteOK(s) {
			continue
		}
		if sub := dateNote.FindStringSubmatch(s); sub != nil && sub[1] != "" {
			z = sub[1]
		}
	}
	return z
}

// validZone is z when it is an IANA zone this build knows (not "Local"), else "".
func validZone(z string) string {
	if z == "" || z == "Local" || len(z) > 64 {
		return ""
	}
	if _, err := time.LoadLocation(z); err != nil {
		return ""
	}
	return z
}

// mailLoc is the task's time zone for mail: the person's, or UTC when it isn't known (known false).
func (t *task) mailLoc() (loc *time.Location, known bool) {
	if z := validZone(t.opts.Zone); z != "" {
		if l, err := time.LoadLocation(z); err == nil {
			return l, true
		}
	}
	return time.UTC, false
}

// mailZoneNote is what a mail result says about its times.
func mailZoneNote(loc *time.Location, known bool) string {
	if !known {
		return "Times are UTC: the person's time zone is unknown. since and before are taken as UTC."
	}
	return "Times are the person's local time (" + loc.String() + "). since and before are taken in it too."
}

// mailTimeText is t in loc for the model: "Thu, Oct 29, 2026, 6:03 AM PDT" (a zone without an abbreviation:
// "UTC-03").
func mailTimeText(t time.Time, loc *time.Location) string {
	l := t.In(loc)
	abbr, _ := l.Zone()
	if abbr == "" || abbr[0] == '+' || abbr[0] == '-' {
		abbr = "UTC" + l.Format("-07:00")
		abbr = strings.TrimSuffix(abbr, ":00")
	}
	return l.Format("Mon, Jan 2, 2006, 3:04 PM") + " " + abbr
}

// mailWhen is when a message arrived: the server's INTERNALDATE, else its Date header.
func mailWhen(internal, header time.Time) time.Time {
	if !internal.IsZero() {
		return internal
	}
	return header
}

// localTime is a since or before as the model wrote it: a local date, or a date and a time.
type localTime struct {
	y       int
	m       time.Month
	d       int
	hh, mm  int
	hasTime bool
}

func (l localTime) zero() bool { return l.y == 0 }

// in is the instant l names in loc.
func (l localTime) in(loc *time.Location) time.Time {
	return time.Date(l.y, l.m, l.d, l.hh, l.mm, 0, 0, loc)
}

func (l localTime) String() string {
	t := time.Date(l.y, l.m, l.d, l.hh, l.mm, 0, 0, time.UTC)
	if l.hasTime {
		return t.Format("2006-01-02 15:04")
	}
	return t.Format("2006-01-02")
}

var errMailWhen = errors.New(`since and before are the person's local dates, YYYY-MM-DD, or a date and a time, "YYYY-MM-DD HH:MM" (24-hour)`)

// parseLocalTime reads "YYYY-MM-DD", "YYYY-MM-DD HH:MM" or "YYYY-MM-DDTHH:MM" (seconds allowed and dropped).
func parseLocalTime(s string) (localTime, error) {
	s = strings.TrimSpace(s)
	for _, f := range []struct {
		layout  string
		hasTime bool
	}{{"2006-01-02", false}, {"2006-01-02 15:04", true}, {"2006-01-02T15:04", true}, {"2006-01-02 15:04:05", true}, {"2006-01-02T15:04:05", true}} {
		if t, err := time.Parse(f.layout, s); err == nil {
			return localTime{y: t.Year(), m: t.Month(), d: t.Day(), hh: t.Hour(), mm: t.Minute(), hasTime: f.hasTime}, nil
		}
	}
	return localTime{}, errMailWhen
}

// window is a search's since and before as instants in loc (zero: open).
func (s *mailSearch) window(loc *time.Location) (since, before time.Time) {
	if !s.since.zero() {
		since = s.since.in(loc)
	}
	if !s.before.zero() {
		before = s.before.in(loc)
	}
	return since, before
}

// serverDays is what the server is asked for, by day (its SEARCH SINCE and BEFORE): the window widened by a day on
// each side, so a message inside it is among the candidates whatever the server's zone (UTC-12 to UTC+14).
func serverDays(since, before time.Time) (time.Time, time.Time) {
	day := func(t time.Time, add int) time.Time {
		u := t.UTC()
		return time.Date(u.Year(), u.Month(), u.Day()+add, 0, 0, 0, 0, time.UTC)
	}
	var s, b time.Time
	if !since.IsZero() {
		s = day(since, -1)
	}
	if !before.IsZero() {
		b = day(before, 2)
	}
	return s, b
}

// inWindow: at is on or after since and before before (zero bounds are open). A message with no time is kept.
func inWindow(at, since, before time.Time) bool {
	if at.IsZero() {
		return true
	}
	return (since.IsZero() || !at.Before(since)) && (before.IsZero() || at.Before(before))
}

// maxTimedCandidates bounds the candidates a timed search checks one by one (their INTERNALDATE, a few dozen bytes
// each); a search with more checks its newest so many, and says the count is at least that.
const (
	maxTimedCandidates = 5000
	timedBatch         = 500
)

// filterByTime keeps the candidates (ascending UIDs) that arrived inside the window, by their INTERNALDATE. capped:
// there were more than maxTimedCandidates, so only the newest were checked.
func filterByTime(cl *imapro.Client, uids []uint32, since, before time.Time) (kept []uint32, capped bool, err error) {
	if len(uids) > maxTimedCandidates {
		uids, capped = uids[len(uids)-maxTimedCandidates:], true
	}
	when := map[uint32]time.Time{}
	for i := 0; i < len(uids); i += timedBatch {
		fs, err := cl.FetchDates(uids[i:min(i+timedBatch, len(uids))])
		if err != nil {
			return nil, false, err
		}
		for _, f := range fs {
			when[f.UID] = f.Internal
		}
	}
	for _, u := range uids {
		if inWindow(when[u], since, before) {
			kept = append(kept, u)
		}
	}
	return kept, capped, nil
}
