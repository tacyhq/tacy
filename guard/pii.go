package guard

import (
	"regexp"
	"strings"
)

// PII masking for text that leaves the VM (search queries, fetched URLs). It catches the obvious, structured
// kinds only; names and free-text details can't be caught by patterns, so the system prompt also tells the model
// to keep queries generic. Order matters: longer, more specific patterns run first.
var piiPatterns = []struct {
	kind string
	re   *regexp.Regexp
}{
	{"url-credentials", regexp.MustCompile(`(?i)\b[a-z][a-z0-9+.\-]*://[^/\s:@]+:[^/\s@]+@`)},
	{"email", regexp.MustCompile(`(?i)[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}`)},
	{"iban", regexp.MustCompile(`\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{4}){2,7}(?:[ ]?[A-Z0-9]{1,4})?\b`)},
	{"ssn", regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`)},
	// 13-19 digits, optionally grouped by spaces or dashes: payment cards and similar account numbers.
	{"card", regexp.MustCompile(`\b(?:\d[ \-]?){12,18}\d\b`)},
	// Phone numbers: optional (+)country code, optional (area), groups separated by space/dot/dash; at least 7 digits.
	{"phone", regexp.MustCompile(`(?:\+?\d{1,3}[ .\-]?)?(?:\(\d{1,4}\)[ .\-]?)?\b\d{2,4}[ .\-]\d{2,4}[ .\-]?\d{2,5}\b`)},
	{"ip", regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)},
	// Any remaining run of 7+ digits (account, customer, case or ID numbers). Years and short counts survive.
	{"number", regexp.MustCompile(`\b\d{7,}\b`)},
}

var dateLike = regexp.MustCompile(`^\d{4}[-./]\d{1,2}[-./]\d{1,2}\z|^\d{1,2}[-./]\d{1,2}[-./]\d{4}\z`)

// Prices and years next to each other look like a phone number to the phone pattern ("under $1000 2026",
// "$1,299 2025", "500 2026", "2025-2026", "1000-1500"). These say a phone match is really such numbers.
var (
	// Right before the match: a currency sign ("$1000 2026", "$1,299 2025"), or the thousands of the same number
	// ("1,299 2025": "1,"; not "…0134," in a list of phones).
	pricePrefix = regexp.MustCompile(`(?:[$€£¥₹] ?(?:\d{1,3},)*|(?:^|[^\d.,])\d{1,3},)\z`)
	// Exactly two numbers (the first may have decimals: "999.99 2026"), split by spaces or one dash.
	twoNumbers = regexp.MustCompile(`^(\d+(?:[.,]\d+)?)(?: +|-)(\d+)\z`)
	year       = regexp.MustCompile(`^(?:19|20)\d\d\z`)
	// A 3-digit group, not round: shaped like a phone exchange ("555 2026" stays a phone).
	exchange = regexp.MustCompile(`^[1-9]\d[1-9]\z`)
	// The pattern's optional country code can start inside a word: "4 " of "rav4 2025 2026" is no country code.
	glued    = regexp.MustCompile(`[A-Za-z0-9]\z`)
	gluedTip = regexp.MustCompile(`^\d{1,3}[ .\-]?`)
)

// notPhone: a phone-pattern match that is a price, a year or a range, not a phone number. A real number keeps a
// country code, an area code or three groups ("+1 415-555-0134", "(415) 555-0134", "020 7946 0958"), or is a
// local "555-0134" / "555 2026", and stays masked.
func notPhone(m, before string) bool {
	if pricePrefix.MatchString(before) {
		return true
	}
	if glued.MatchString(before) {
		m = gluedTip.ReplaceAllLiteralString(m, "")
	}
	g := twoNumbers.FindStringSubmatch(m)
	if g == nil {
		return false
	}
	a, b := g[1], g[2]
	// A number, then a year: "1000 2026", "500 2026", "999.99 2026", "2025 2026", "2025-2026".
	if year.MatchString(b) && !exchange.MatchString(a) {
		return true
	}
	// A range of round numbers: "1000-1500", "800 1200".
	return strings.HasSuffix(a, "00") && strings.HasSuffix(b, "00")
}

// maskPII replaces obvious personal data with [kind] placeholders and returns the kinds it found.
func maskPII(s string) (string, []string) {
	var kinds []string
	for _, p := range piiPatterns {
		locs := p.re.FindAllStringIndex(s, -1)
		if locs == nil {
			continue
		}
		var b strings.Builder
		last := 0
		for _, l := range locs {
			m := s[l[0]:l[1]]
			// A phone pattern also matches dates like 2026-10-13 or versions like 1.2.3 (7+ digits needed), and
			// prices and years.
			if p.kind == "phone" && (digits(m) < 7 || dateLike.MatchString(m) || notPhone(m, s[:l[0]])) {
				continue
			}
			if p.kind == "card" && digits(m) < 13 {
				continue
			}
			b.WriteString(s[last:l[0]])
			b.WriteString("[" + p.kind + "]")
			last = l[1]
		}
		b.WriteString(s[last:])
		s = b.String()
		if strings.Contains(s, "["+p.kind+"]") {
			kinds = append(kinds, p.kind)
		}
	}
	return s, kinds
}

func digits(s string) int {
	n := 0
	for _, r := range s {
		if r >= '0' && r <= '9' {
			n++
		}
	}
	return n
}
