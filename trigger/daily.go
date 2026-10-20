package trigger

import (
	"errors"
	"regexp"
	"strconv"
	"time"
)

// Daily schedules (docs/30 "Scheduled tasks", decisions 1 and 2): one slot a day, at a wall-clock time in an IANA
// zone. A slot is a local date, numbered by its days since 1970-01-01, so a slot can't fire twice whatever the
// zone's offset does. Its instant is the first one whose wall clock in the zone reads the time on that date:
//   - a time the spring-forward change skips (02:30 when clocks jump from 02:00 to 03:00) fires at the change
//     (03:00 local), as cron does;
//   - a time the fall-back change repeats (01:30 twice) fires at its first occurrence, once.
//
// The zones come from the Go release's tzdata, embedded in agentd (import time/tzdata), so the VM image needs no
// zoneinfo files and the rules are fixed by the attested build.

var dailyRe = regexp.MustCompile(`^([01][0-9]|2[0-3]):([0-5][0-9])$`)

// daily parses the trigger's time and zone.
func (t *Trigger) daily() (hh, mm int, loc *time.Location, err error) {
	m := dailyRe.FindStringSubmatch(t.Daily)
	if m == nil {
		return 0, 0, nil, errors.New("daily must be HH:MM (00:00 to 23:59)")
	}
	if t.Zone == "" || t.Zone == "Local" || len(t.Zone) > 64 {
		return 0, 0, nil, errors.New("zone must be an IANA time zone name")
	}
	loc, err = time.LoadLocation(t.Zone)
	if err != nil {
		return 0, 0, nil, errors.New("zone must be an IANA time zone name")
	}
	hh, _ = strconv.Atoi(m[1])
	mm, _ = strconv.Atoi(m[2])
	return hh, mm, loc, nil
}

// IsDaily: a daily schedule trigger.
func (t *Trigger) IsDaily() bool { return t.Kind == Schedule && t.Daily != "" }

// dayNumber is a civil date's days since 1970-01-01.
func dayNumber(y int, m time.Month, d int) int64 {
	return time.Date(y, m, d, 0, 0, 0, 0, time.UTC).Unix() / 86400
}

// DayOf is the local date ("YYYY-MM-DD") a daily slot names.
func DayOf(slot int64) string { return time.Unix(slot*86400, 0).UTC().Format(time.DateOnly) }

// dailyAt is the instant of hh:mm on the date y-m-d (normalized, so d may be 0 or 32) in loc.
func dailyAt(hh, mm int, loc *time.Location, y int, m time.Month, d int) time.Time {
	day := time.Date(y, m, d, 12, 0, 0, 0, time.UTC) // normalize the date
	y, m, d = day.Date()
	want := time.Date(y, m, d, hh, mm, 0, 0, time.UTC) // the wall clock, as if it were UTC
	// The offsets that apply on that date (a zone changes at most once or twice a day).
	var offs []int
	for _, h := range []int{0, 6, 12, 18, 23} {
		_, off := time.Date(y, m, d, h, 59, 0, 0, loc).Zone()
		offs = append(offs, off)
	}
	_, off := time.Date(y, m, d+1, 0, 30, 0, 0, loc).Zone()
	offs = append(offs, off)
	var best time.Time
	var before time.Time // a candidate whose wall clock reads earlier than wanted: the time is in a gap
	for _, o := range offs {
		u := want.Add(-time.Duration(o) * time.Second)
		lt := u.In(loc)
		w := time.Date(lt.Year(), lt.Month(), lt.Day(), lt.Hour(), lt.Minute(), lt.Second(), 0, time.UTC)
		switch {
		case w.Equal(want):
			if best.IsZero() || u.Before(best) {
				best = u
			}
		case w.Before(want):
			if before.IsZero() || u.After(before) {
				before = u
			}
		}
	}
	if !best.IsZero() {
		return best
	}
	if !before.IsZero() { // skipped by a spring-forward change: the change itself (the end of the zone before it)
		_, end := before.In(loc).ZoneBounds()
		if !end.IsZero() {
			return end
		}
	}
	return time.Date(y, m, d, hh, mm, 0, 0, loc) // not reached for real zones
}

// DailySlot is the latest slot of a daily trigger at or before t, and its instant.
func (t *Trigger) DailySlot(at time.Time) (int64, time.Time) {
	hh, mm, loc, err := t.daily()
	if err != nil {
		return -1, time.Time{}
	}
	y, m, d := at.In(loc).Date()
	inst := dailyAt(hh, mm, loc, y, m, d)
	if inst.After(at) {
		d--
		inst = dailyAt(hh, mm, loc, y, m, d)
	}
	n := time.Date(y, m, d, 12, 0, 0, 0, time.UTC)
	return dayNumber(n.Date()), inst
}

// NextRun is the next instant after t a daily trigger fires at (zero for other triggers).
func (t *Trigger) NextRun(at time.Time) time.Time {
	hh, mm, loc, err := t.daily()
	if err != nil {
		return time.Time{}
	}
	y, m, d := at.In(loc).Date()
	for i := 0; i < 3; i++ {
		if inst := dailyAt(hh, mm, loc, y, m, d+i); inst.After(at) {
			return inst
		}
	}
	return time.Time{}
}

// SlotAt is a daily slot's instant (the slot's local date at the trigger's time).
func (t *Trigger) SlotAt(slot int64) time.Time {
	hh, mm, loc, err := t.daily()
	if err != nil {
		return time.Time{}
	}
	y, m, d := time.Unix(slot*86400, 0).UTC().Date()
	return dailyAt(hh, mm, loc, y, m, d)
}
