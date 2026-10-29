package guard

import (
	"regexp"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Quotes that carry the point (2026-10-29): on a real Gmail account a Google security alert's
// answer quoted the account's own address, "[image: Google]" alt text and the "you received this email because…"
// footer. The mail reader's prompt (readerMailSystem) now asks for passages that state what the message says or asks
// and names the boilerplate to skip. Behind it, code trims what is surely boilerplate off a mail quote's first and
// last lines and sentences (image alt text, a bare address or web address, "view in browser", unsubscribe, privacy, copyright and
// "this email was sent to" lines, and a greeting, heading or sign-off of a few words next to the passage), and drops
// a quote that is nothing else. Only which exact passage of the message is shown changes; nothing is added.

var (
	mailAltRe  = regexp.MustCompile(`^(?:\[image:[^\]]{0,200}\]\s*)+$`)
	mailAddrRe = regexp.MustCompile(`^[<(]?[A-Za-z0-9._%+'-]{1,64}@[A-Za-z0-9.-]{1,190}\.[A-Za-z]{2,24}[>)]?[.,;:]?$`)
	mailURLRe  = regexp.MustCompile(`^<?https?://\S+>?$`)
	mailViewRe = regexp.MustCompile(`(?i)^(?:having trouble viewing this (?:e-?mail|message)\??.*|(?:view|read|open)(?: this| the)?(?: e-?mail| message| newsletter)?(?: in (?:your |a |the )?browser| online| on the web)\.?)$`)
	// mailFooterRe: a footer's own words, wherever they are in the sentence; mailFooterWeakRe words a footer has but
	// a message's point may too ("we updated our privacy policy"): only in a short sentence with no number.
	mailFooterRe = regexp.MustCompile(`(?i)(unsubscribe|all rights reserved|©|\(c\) 20[0-9]{2}|` +
		`you (?:received|are receiving|'re receiving|’re receiving) this|this (?:e-?mail|message|notice) was sent to|sent to [^\s@]+@|` +
		`(?:please )?do not reply to this|don't reply to this|confidentiality notice)`)
	mailFooterWeakRe = regexp.MustCompile(`(?i)(manage (?:your )?(?:email )?preferences|privacy (?:policy|notice|practices)|intended recipient)`)
)

// mailBoilerplate: a sentence or line of a message's text that is surely boilerplate, never the point.
func mailBoilerplate(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return true
	}
	if mailAltRe.MatchString(s) || mailAddrRe.MatchString(s) || mailURLRe.MatchString(s) || mailViewRe.MatchString(s) || mailFooterRe.MatchString(s) {
		return true
	}
	return mailFooterWeakRe.MatchString(s) && !hasFigure(s) && len(strings.Fields(s)) <= 15
}

func hasFigure(s string) bool {
	return strings.ContainsFunc(s, func(r rune) bool { return unicode.IsDigit(r) || r == '$' || r == '€' || r == '£' })
}

// mailFringe: a span of a few words with no number, a greeting, heading, button or sign-off ("Hi there,", "Check
// activity", "Best,"): trimmed only next to the passage it heads or ends, never a quote's only span.
func mailFringe(s string) bool {
	s = strings.TrimSpace(s)
	return !hasFigure(s) && len(strings.Fields(s)) <= 3
}

// trimMailQuote narrows a mail quote, s[start:end] of its segment s, to the passage without boilerplate at either
// end, by line and sentence (spans join short lines, so "[image: Google]" and the heading after it are one span);
// ok false when nothing is left. The result is still s's own words, a part of the passage the reader named.
func trimMailQuote(s string, start, end int) (int, int, bool) {
	type line struct {
		a, b int
		// whole: a whole line of the message, not a sentence of one: only those may be fringe (a "Due Friday."
		// ending a paragraph stays).
		whole bool
	}
	var ls []line
	piece := func(a, b int) {
		if strings.TrimSpace(s[a:b]) != "" {
			whole := (a == 0 || s[a-1] == '\n') && (b == len(s) || s[b] == '\n')
			ls = append(ls, line{a, b, whole})
		}
	}
	for a := start; a < end; {
		b := strings.IndexByte(s[a:end], '\n')
		if b < 0 {
			b = end
		} else {
			b += a
		}
		// Sentences, as splitSpans cuts them (a break before a lowercase letter isn't one).
		from := a
		for _, m := range sentenceBreak.FindAllStringIndex(s[a:b], -1) {
			at := a + m[1]
			if r, _ := utf8.DecodeRuneInString(s[at:]); unicode.IsLower(r) {
				continue
			}
			piece(from, at)
			from = at
		}
		piece(from, b)
		a = b + 1
	}
	text := func(l line) string { return s[l.a:l.b] }
	fringe := func(l line) bool { return l.whole && mailFringe(text(l)) }
	n := len(ls)
	for len(ls) > 0 && mailBoilerplate(text(ls[0])) {
		ls = ls[1:]
	}
	for len(ls) > 0 && mailBoilerplate(text(ls[len(ls)-1])) {
		ls = ls[:len(ls)-1]
	}
	// Nothing left, or only a button or heading that was beside the boilerplate ("Check activity" over a footer).
	if len(ls) == 0 || len(ls) < n && !slices.ContainsFunc(ls, func(l line) bool { return !fringe(l) }) {
		return 0, 0, false
	}
	for len(ls) > 1 && fringe(ls[0]) {
		ls = ls[1:]
	}
	for len(ls) > 1 && fringe(ls[len(ls)-1]) {
		ls = ls[:len(ls)-1]
	}
	a, b := ls[0].a, ls[len(ls)-1].b
	for a < b && isSpace(s[a]) {
		a++
	}
	for b > a && isSpace(s[b-1]) {
		b--
	}
	return a, b, true
}
