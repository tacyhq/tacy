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

// maskPII replaces obvious personal data with [kind] placeholders and returns the kinds it found.
func maskPII(s string) (string, []string) {
	var kinds []string
	for _, p := range piiPatterns {
		if !p.re.MatchString(s) {
			continue
		}
		s = p.re.ReplaceAllStringFunc(s, func(m string) string {
			// A phone pattern also matches dates like 2026-10-13 or versions like 1.2.3; require 7+ digits.
			if p.kind == "phone" && (digits(m) < 7 || dateLike.MatchString(m)) {
				return m
			}
			if p.kind == "card" && digits(m) < 13 {
				return m
			}
			return "[" + p.kind + "]"
		})
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
