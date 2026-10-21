package guard

import (
	"regexp"
	"slices"
	"strings"
	"unicode"

	"golang.org/x/text/unicode/norm"
)

// PII masking for text that leaves the VM (search queries, fetched URLs). It catches the structured kinds and the
// ones a label names ("DOB 14.03.1987", "passport X12345678", "policy number 9A-4471-22B"); a private person's name
// or a health detail looks like any other words to a pattern, so the system prompt also tells the model to keep
// queries generic, and the person sees the query first (Ask). Order matters: longer, more specific patterns run
// first. Graded by the chat's PII scorecard (guard/piiscore_test.go).
//
// Text is masked as written and once more with lookalike characters folded (foldText: fullwidth and other scripts'
// digits, Unicode dashes and spaces, invisible characters, %40 and friends, "+" between words); when the folded
// one leaves fewer digits or masks more, it is what goes out (piiScan).

// piiRule is one pattern. group > 0 masks only that submatch (the label before it stays: "DOB [dob]"). check, when
// set, decides a candidate [a, b) of s and may move it (a label rule's token starts where the label ends); ok false
// leaves it for later rules. when, when set, says whether the rule runs on s at all.
type piiRule struct {
	kind  string
	re    *regexp.Regexp
	group int
	check func(s string, a, b int) (int, int, bool)
	when  func(s string) bool
}

// piiHit is one masked span: its kind and the text it replaced.
type piiHit struct{ kind, text string }

const (
	// A month name, English, German, French, Spanish (a date of birth written out).
	monthName = `(?:jan(?:uary)?|feb(?:ruary)?|mar(?:ch)?|apr(?:il)?|may|june?|july?|aug(?:ust)?|sep(?:t(?:ember)?)?|oct(?:ober)?|nov(?:ember)?|dec(?:ember)?|januar|februar|märz|maerz|mai|juni|juli|oktober|dezember|janvier|février|fevrier|mars|avril|juin|juillet|août|aout|septembre|octobre|novembre|décembre|decembre|enero|febrero|marzo|abril|mayo|junio|julio|agosto|septiembre|octubre|noviembre|diciembre)\.?`
	// A full date: day, month and year in any common order.
	fullDate = `(\d{1,2}[./\-]\d{1,2}[./\-](?:\d{4}|\d{2})|\d{4}[./\-]\d{1,2}[./\-]\d{1,2}|\d{1,2}(?:st|nd|rd|th)?\.?\s+(?:of\s+)?` + monthName + `,?\s+\d{4}|` + monthName + `\s+\d{1,2}(?:st|nd|rd|th)?,?\s+\d{4})`
	// What may follow a label before the value: spaces, a colon, "#", "=" (a URL's query), a dash.
	labelSep = `[\s:#=.\-]*`
	// A capitalized word of a street's name, in any script.
	capWord = `[A-ZÄÖÜÅØÆÁÉÍÓÚÀÈÌÒÙÂÊÎÔÛÃÕÇ][\p{L}'\-]*`
)

var (
	hasAddress = func(s string) bool { return strings.Contains(s, "[address]") }

	piiRules = []piiRule{
		{kind: "url-credentials", re: regexp.MustCompile(`(?i)\b[a-z][a-z0-9+.\-]*://[^/\s:@]+:[^/\s@]+@`)},
		// Letters of any script on both sides ("josé.garcía@correo.es", "anna@müller.de").
		{kind: "email", re: regexp.MustCompile(`(?i)[\p{L}\p{N}._%+\-]+@[\p{L}\p{N}.\-]+\.\p{L}{2,}`)},
		// Spelled out: "john.reyes at gmail dot com", "j.reyes[at]example[dot]com", "jane . doe @ example . com".
		{kind: "email", re: regexp.MustCompile(`(?i)[\p{L}\p{N}_%+\-]+(?:(?:\s*(?:\.|\(dot\)|\[dot\]|\{dot\}|<dot>)\s*|\s+dot\s+)[\p{L}\p{N}_%+\-]+)*(\s*(?:@|\(at\)|\[at\]|\{at\}|<at>)\s*|\s+at\s+)[\p{L}\p{N}\-]+(?:(?:\s*(?:\.|\(dot\)|\[dot\]|\{dot\}|<dot>)\s*|\s+dot\s+)[\p{L}\p{N}\-]+)+`), check: spelledEmail},
		// Checked (ibanLen): a registry country, its length and mod-97; any case.
		{kind: "iban", re: regexp.MustCompile(`(?i)\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{4}){2,7}(?:[ ]?[A-Z0-9]{1,4})?\b`), check: ibanCheck},
		// A full date after a birth label; the label stays.
		{kind: "dob", re: regexp.MustCompile(`(?i)(?:\b(?:dob|d\.o\.b|date\s+of\s+birth|birth\s*date|birthday|born(?:\s+on)?|geboren(?:\s+am)?|geburtsdatum|date\s+de\s+naissance|fecha\s+de\s+nacimiento|data\s+di\s+nascita|nato\s+il|nata\s+il)\b|\bnée?\s+le\b)` + labelSep + fullDate + `\b`), group: 1},
		{kind: "ssn", re: regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b|\b\d{3} \d{2} \d{4}\b|\b\d{3}\.\d{2}\.\d{4}\b`)},
		// National IDs by their shape: UK National Insurance, Brazil's CPF, Italy's codice fiscale, Spain's DNI and
		// NIE, India's PAN.
		{kind: "national-id", re: regexp.MustCompile(`\b[A-Z]{2} ?\d{2} ?\d{2} ?\d{2} ?[A-D]\b|\b\d{3}\.\d{3}\.\d{3}-\d{2}\b|\b[A-Z]{6}\d{2}[A-EHLMPR-T]\d{2}[A-Z]\d{3}[A-Z]\b|\b\d{8}[A-HJ-NP-TV-Z]\b|\b[XYZ]\d{7}[A-HJ-NP-TV-Z]\b|\b[A-Z]{3}[ABCFGHJLPT][A-Z]\d{4}[A-Z]\b`)},
		// 13-19 digits grouped by spaces, dots or dashes that pass the Luhn check (an EAN-13 barcode isn't one).
		// Other such runs fall through to the number rules.
		{kind: "card", re: cardRun, check: cardCheck},
		{kind: "number", re: cardRun, check: longRunCheck},
		// A value right after a label that names it ("passport X12345678", "SIN 046 454 286", "plate B-MK 4321",
		// "policy number 9A-4471-22B"): the label stays.
		{kind: "national-id", re: regexp.MustCompile(`(?:\b(?i:passport(?:\s+(?:no\.?|number|#))?|driver'?s?\s+licen[cs]e(?:\s+(?:no\.?|number|#))?|licen[cs]e\s+(?:no\.?|number|#)|national\s+insurance(?:\s+(?:no\.?|number))?|ni\s+(?:no\.?|number)|nino|ssn|social\s+security(?:\s+(?:no\.?|number))?|nhs\s+(?:no\.?|number)|medicare(?:\s+(?:no\.?|number|card))?|medicaid(?:\s+(?:id|no\.?|number))?|aadhaar(?:\s+(?:no\.?|number))?|cpf|dni|nie|nif|codice\s+fiscale|steuer-?id|steuer-?identifikationsnummer|(?:personal)?ausweis(?:nummer)?|tax\s+(?:id|file\s+number)|id\s+(?:no\.?|number|card))|\b(?:PAN|SIN|TIN|EIN|ITIN|BSN|PPS|TFN|DL))\b` + labelSep), check: labelToken(4)},
		{kind: "plate", re: regexp.MustCompile(`(?i)\b(?:licen[cs]e\s+plate|number\s+plate|plate|registration(?:\s+(?:no\.?|number))?|reg(?:\.|\s+(?:no\.?|number))|kennzeichen|nummernschild|matr[ií]cula|immatriculation|plaque|targa)\b` + labelSep), check: plateToken},
		{kind: "account", re: regexp.MustCompile(`(?i)\b(?:account(?:\s+(?:no\.?|number|num|#))?|acct\.?(?:\s*(?:no\.?|number|#))?|a/c(?:\s+no\.?)?|routing(?:\s+(?:no\.?|number|#))?|sort\s+code|(?:member(?:ship)?|policy|claim|case|customer|client|patient|subscriber|tracking|loan|contract|student|employee|reference|ref|booking|reservation|confirmation)\s+(?:id|no\.?|number|num|#)|mrn|medical\s+record(?:\s+(?:no\.?|number|#))?)\b` + labelSep), check: labelToken(4)},
		{kind: "account", re: regexp.MustCompile(`(?i)\b(?:booking\s+(?:reference|ref|code)|confirmation\s+code|reservation\s+code|record\s+locator|pnr)\b` + labelSep), check: bookingCode},
		// Phone numbers. With a country code: any grouping, a trunk "(0)" ("+33 1 23 45 67 89", "+44 (0)20 7946 0958").
		{kind: "phone", re: regexp.MustCompile(`\+\d{1,3}(?:[ .\-]?\((?:0|\d{1,4})\))?(?:[ .\-]?\d{1,5}){1,6}\b`), check: intlPhone},
		// French national numbers in pairs ("06 12 34 56 78").
		{kind: "phone", re: regexp.MustCompile(`\b0[1-9](?:[ .\-]?\d{2}){4}\b`)},
		// Spelled out, 7+ digits as words ("two zero two five five five zero one four seven").
		{kind: "phone", re: regexp.MustCompile(`(?i)\b(?:zero|oh|one|two|three|four|five|six|seven|eight|nine)(?:[\s,.\-]+(?:zero|oh|one|two|three|four|five|six|seven|eight|nine)){6,}\b`)},
		// Optional (+)country code, optional (area), groups separated by space/dot/dash; at least 7 digits.
		{kind: "phone", re: regexp.MustCompile(`(?:\+?\d{1,3}[ .\-]?)?(?:\(\d{1,4}\)[ .\-]?)?\b\d{2,5}[ .\-]\d{2,4}[ .\-]?\d{2,5}\b`), check: phoneCheck},
		{kind: "ip", re: regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`), check: ipCheck},
		// Street addresses. English: a house number, the street's capitalized name, its kind ("17B Harlow Street",
		// "350 W 5th Ave").
		{kind: "address", re: regexp.MustCompile(`\b(\d{1,5}[A-Za-z]?)\s+((?:(?:N|S|E|W|NE|NW|SE|SW|North|South|East|West)\.?\s+)?(?:` + capWord + `|\d{1,3}(?:st|nd|rd|th))(?:\s+` + capWord + `){0,3})\s+(?:(?i:street|avenue|road|boulevard|lane|drive|court|terrace|close|crescent|parkway|highway|square|place|circle|gardens|grove|mews)|St|Ave|Rd|Blvd|Ln|Dr|Ct|Pkwy|Hwy|Sq|Way|Pl|Cir)\b\.?`), check: addressCheck},
		// Lowercase ("1428 elm street"): a 3-5 digit house number and a full street word only.
		{kind: "address", re: regexp.MustCompile(`(?i)\b(\d{3,5}[a-z]?)\s+((?:[a-z][\p{L}'\-]*\s+){1,3})(?:street|avenue|road|lane|boulevard|terrace)\b`), check: addressCheck},
		// German, Dutch, Nordic: the name and its kind in one word, then the number ("Hauptstraße 5").
		{kind: "address", re: regexp.MustCompile(`\b[A-ZÄÖÜÅØÆ][\p{L}\-]*(?:straße|strasse|str\.|weg|allee|platz|gasse|damm|ufer|straat|laan|gracht|plein|steeg|gatan|gata|vej|veien|vegen|gade)\s+(\d{1,4})[a-z]?\b`), check: notYearGroup},
		// French: number, kind, name ("12 rue des Lilas").
		{kind: "address", re: regexp.MustCompile(`\b(\d{1,4})(?:\s?(?:bis|ter))?,?\s+(?:[Rr]ue|[Aa]venue|[Bb]oulevard|[Bb]d|[Pp]lace|[Aa]llée|[Cc]hemin|[Ii]mpasse|[Qq]uai|[Rr]oute)\s+(?:(?:de|du|des|la|le|les)\s+|l'|d'){0,2}` + capWord + `(?:\s+` + capWord + `){0,2}`), check: notYearGroup},
		// Spanish, Italian, Portuguese: kind, name, number ("Calle Mayor 10", "Via Roma 15").
		{kind: "address", re: regexp.MustCompile(`\b(?:Calle|C/|Avenida|Avda\.?|Paseo|Plaza|Carrer|Via|Viale|Piazza|Piazzale|Corso|Largo|Rua|Travessa)\s+(?:(?:de|del|la|las|los|el|di|della|delle|dei|degli|do|da|dos|das)\s+){0,2}` + capWord + `(?:\s+` + capWord + `){0,2},?\s+(?:n\.?\s*º?\s*)?(\d{1,4})\b`), check: notYearGroup},
		// Next to an address: the flat and a UK postcode.
		{kind: "address", re: regexp.MustCompile(`(?i)\b(?:apartment|apt\.?|flat|unit|suite|ste\.?|appartement|wohnung)\s*#?\s*[a-z]?\d{1,4}[a-z]?\b`), when: hasAddress},
		{kind: "address", re: regexp.MustCompile(`\b[A-Z]{1,2}\d[A-Z\d]? ?\d[A-Z]{2}\b`), when: hasAddress},
		// Any remaining run of 7+ digits (account, customer, case or ID numbers). Years and short counts survive.
		{kind: "number", re: regexp.MustCompile(`\b\d{7,}\b`), check: numberCheck},
		// An identifier mixing letters and many digits ("1Z999AA10123456784", "2024-CV-004417"); not hex (hashes,
		// UUIDs) and not a public code (CVE-2024-3094).
		{kind: "number", re: regexp.MustCompile(`\b[A-Za-z0-9]+(?:-[A-Za-z0-9]+)*\b`), check: identifierCheck},
		// Digits in 3+ groups, 9+ in all ("4 1 5 5 5 5 0 1 3 4", "1 85 05 78 006 084"): a number spaced out.
		{kind: "number", re: regexp.MustCompile(`\b\d{1,4}(?:[ .\-]\d{1,4}){2,}\b`), check: digitGroupsCheck},
	}

	cardRun  = regexp.MustCompile(`\b(?:\d[ .\-]?){12,18}\d\b`)
	dateLike = regexp.MustCompile(`^\d{4}[-./]\d{1,2}[-./]\d{1,2}\z|^\d{1,2}[-./]\d{1,2}[-./]\d{4}\z`)
	// A public code's name right before the number, or earlier in the same code: CVE-2024-3094, ISBN 978-0-306-…,
	// HS code 8471.30.0100, KB5031354, patent US 11234567, build 26100.4652.
	publicCode   = regexp.MustCompile(`(?i)\b(?:CVE|GHSA|CWE|KB|RFC|ISO|IEC|ISBN(?:-1[03])?|ISSN|EAN(?:-13)?|UPC|GTIN|ASIN|DOI|PMID|PMCID|arXiv|(?:HS|HTS)(?:\s+code)?|build|version|patent(?:\s+(?:no\.?|number))?(?:\s+(?:US|EP|WO))?)[\s:#.\-]*[0-9A-Za-z.\-/]*\z`)
	patentTail   = regexp.MustCompile(`^\s?[AB]\d\b`)
	fractionHead = regexp.MustCompile(`(?:^|[^\d.])\d\.\z`)
	uuidHead     = regexp.MustCompile(`(?i)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-\z`)
	patentHead   = regexp.MustCompile(`\b(?:US|EP|WO)\s*\z`)
)

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
	// One decimal point and nothing else, 9 digits at most: a paper id or a build (arXiv 2310.06825, 26100.4652),
	// not a phone (415.5550134).
	decimal = regexp.MustCompile(`^\d{1,5}\.\d{1,5}\z`)
	// Thousands grouping of a round amount ("1 000 000", "8.100.000.000").
	roundThousands = regexp.MustCompile(`^\d{1,3}(?:[ .,]\d{3})*[ .,]000\z`)
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

// maskPII replaces personal data with [kind] placeholders and returns the kinds it found.
func maskPII(s string) (string, []string) {
	out, hits, _ := piiScan(s)
	var kinds []string
	for _, h := range hits {
		if !slices.Contains(kinds, h.kind) {
			kinds = append(kinds, h.kind)
		}
	}
	return out, kinds
}

// piiScan masks s as written and with lookalikes folded, and keeps the one that leaves fewer digits, then the one
// that masked more (the text as written on a tie). all is both passes' hits (what a page address is refused for).
func piiScan(s string) (out string, hits, all []piiHit) {
	out, hits = maskOnce(s)
	f := foldText(s)
	if f == s {
		return out, hits, hits
	}
	out2, hits2 := maskOnce(f)
	all = append(slices.Clip(hits), hits2...)
	if d1, d2 := digits(foldText(out)), digits(out2); d2 < d1 || d2 == d1 && len(hits2) > len(hits) {
		return out2, hits2, all
	}
	return out, hits, all
}

func maskOnce(s string) (string, []piiHit) {
	var hits []piiHit
	for _, r := range piiRules {
		if r.when != nil && !r.when(s) {
			continue
		}
		locs := r.re.FindAllStringSubmatchIndex(s, -1)
		if locs == nil {
			continue
		}
		var b strings.Builder
		last := 0
		for _, l := range locs {
			a, e := l[0], l[1]
			if r.group > 0 {
				if a, e = l[2*r.group], l[2*r.group+1]; a < 0 {
					continue
				}
			}
			if r.check != nil {
				var ok bool
				if a, e, ok = r.check(s, a, e); !ok {
					continue
				}
			}
			if a < last || e <= a {
				continue
			}
			b.WriteString(s[last:a])
			b.WriteString("[" + r.kind + "]")
			hits = append(hits, piiHit{r.kind, s[a:e]})
			last = e
		}
		b.WriteString(s[last:])
		s = b.String()
	}
	return s, hits
}

// urlPersonalData is the personal data in a page address the model wrote (fetch_page refuses it): the
// unambiguous kinds, and a phone number only in a phone's own shape (a country code, an area code in parentheses,
// or 3-3-4 digits): long numbers, dates and IPs are normal in URLs (article ids; private IPs are refused by the
// dialer anyway).
func urlPersonalData(u string) []string {
	_, _, hits := piiScan(u)
	var kinds []string
	for _, h := range hits {
		switch h.kind {
		case "email", "ssn", "card", "iban", "url-credentials", "national-id", "dob", "address":
		case "phone":
			if !strongPhone.MatchString(h.text) {
				continue
			}
		default:
			continue
		}
		if !slices.Contains(kinds, h.kind) {
			kinds = append(kinds, h.kind)
		}
	}
	return kinds
}

var strongPhone = regexp.MustCompile(`[+(]|^(?:\d{1,3}[ .\-])?\d{3}[ .\-]\d{3}[ .\-]\d{4}\z`)

func digits(s string) int {
	n := 0
	for _, r := range s {
		if r >= '0' && r <= '9' {
			n++
		}
	}
	return n
}

func letters(s string) int {
	n := 0
	for _, r := range s {
		if unicode.IsLetter(r) {
			n++
		}
	}
	return n
}

// ---- checks -----------------------------------------------------------------------------------------

func phoneCheck(s string, a, b int) (int, int, bool) {
	m := s[a:b]
	// A phone pattern also matches dates like 2026-10-13 or versions like 1.2.3 (7+ digits needed), prices and years,
	// a paper id or a build (one decimal point), public codes and round thousands.
	if digits(m) < 7 || dateLike.MatchString(m) || notPhone(m, s[:a]) || decimal.MatchString(m) || publicCode.MatchString(s[:a]) || roundThousands.MatchString(m) {
		return 0, 0, false
	}
	return a, b, true
}

func intlPhone(s string, a, b int) (int, int, bool) {
	if digits(s[a:b]) < 8 || publicCode.MatchString(s[:a]) {
		return 0, 0, false
	}
	return a, b, true
}

func cardCheck(s string, a, b int) (int, int, bool) {
	var d []byte
	for i := a; i < b; i++ {
		if c := s[i]; c >= '0' && c <= '9' {
			d = append(d, c)
		}
	}
	if len(d) < 13 || !luhn(d) || len(d) == 13 && ean13(d) || publicCode.MatchString(s[:a]) {
		return 0, 0, false
	}
	return a, b, true
}

// longRunCheck: the 13-19 digits a card's pattern found that aren't a card (an account number grouped like one),
// unless a public code (ISBN 978-0-306-40615-7).
func longRunCheck(s string, a, b int) (int, int, bool) {
	if digits(s[a:b]) < 13 || publicCode.MatchString(s[:a]) {
		return 0, 0, false
	}
	return a, b, true
}

// luhn: the payment card check digit (ISO/IEC 7812).
func luhn(d []byte) bool {
	sum := 0
	for i := len(d) - 1; i >= 0; i-- {
		n := int(d[i] - '0')
		if (len(d)-1-i)%2 == 1 {
			if n *= 2; n > 9 {
				n -= 9
			}
		}
		sum += n
	}
	return sum%10 == 0
}

// ean13: a 13-digit barcode's check digit (EAN-13, ISBN-13).
func ean13(d []byte) bool {
	sum := 0
	for i, c := range d {
		w := 1
		if i%2 == 1 {
			w = 3
		}
		sum += w * int(c-'0')
	}
	return sum%10 == 0
}

func ibanCheck(s string, a, b int) (int, int, bool) {
	// An IBAN is masked only when it is one: a registry country, that country's length and the mod-97 check
	// (v0.10.1: the Samsung dishwasher "DW90F89P0USR" went out as "[iban]"). It ends at that length.
	n := ibanLen(strings.ToUpper(s[a:b]))
	if n == 0 {
		return 0, 0, false
	}
	return a, a + n, true
}

func ipCheck(s string, a, b int) (int, int, bool) {
	if publicIP(s[a:b]) {
		return a, b, true
	}
	return 0, 0, false
}

// publicIP: not a private, loopback or link-local address and not a well-known public resolver: those say nothing
// about who is asking ("192.168.1.1 router login", "8.8.8.8 vs 1.1.1.1").
func publicIP(ip string) bool {
	var o [4]int
	for i, p := range strings.Split(ip, ".") {
		for _, c := range p {
			o[i] = o[i]*10 + int(c-'0')
		}
	}
	switch {
	case o[0] == 10, o[0] == 127, o[0] == 0, o[0] == 192 && o[1] == 168, o[0] == 172 && o[1] >= 16 && o[1] <= 31, o[0] == 169 && o[1] == 254:
		return false
	}
	switch ip {
	case "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9", "149.112.112.112", "208.67.222.222", "208.67.220.220":
		return false
	}
	return true
}

// Words that start a phrase, not a street's name ("top 10 Wall Street banks", "5 best street food markets",
// "1954 Supreme Court ruling").
var notStreetName = map[string]bool{
	"best": true, "top": true, "great": true, "good": true, "cheap": true, "free": true, "famous": true, "popular": true,
	"favorite": true, "favourite": true, "new": true, "old": true, "mile": true, "miles": true, "km": true, "day": true,
	"days": true, "hour": true, "hours": true, "year": true, "years": true, "step": true, "steps": true, "way": true,
	"ways": true, "the": true, "a": true, "an": true, "and": true, "or": true, "of": true, "in": true, "on": true,
	"at": true, "for": true, "to": true, "with": true, "gb": true, "tb": true, "supreme": true, "federal": true,
	"district": true, "appeals": true,
}

var (
	wordBefore = regexp.MustCompile(`(?i)\b(top|best|the)\s+\z`)
	// A year in place of a house number: "2026 Supreme Court term", "Spring 2026".
	yearNumber = regexp.MustCompile(`^(?:19|20)\d\d[A-Za-z]?\z`)
)

func addressCheck(s string, a, b int) (int, int, bool) {
	m := s[a:b]
	num := m[:strings.IndexFunc(m, unicode.IsSpace)]
	if yearNumber.MatchString(num) || wordBefore.MatchString(s[:a]) || pricePrefix.MatchString(s[:a]) {
		return 0, 0, false
	}
	for _, w := range strings.Fields(m)[1:] {
		if notStreetName[strings.ToLower(w)] {
			return 0, 0, false
		}
	}
	return a, b, true
}

// notYearGroup: the house number (the pattern's group 1) isn't a year.
func notYearGroup(s string, a, b int) (int, int, bool) {
	for _, d := range digitRun.FindAllString(s[a:b], -1) {
		if year.MatchString(d) {
			return 0, 0, false
		}
	}
	return a, b, true
}

func numberCheck(s string, a, b int) (int, int, bool) {
	m := s[a:b]
	switch {
	case publicCode.MatchString(s[:a]), pricePrefix.MatchString(s[:a]):
		return 0, 0, false
	case len(strings.TrimRight(m, "0")) <= 3: // round, 4+ zeros: "1000000 yen"
		return 0, 0, false
	case patentHead.MatchString(s[:a]) && patentTail.MatchString(s[b:]): // "US 11234567 B2"
		return 0, 0, false
	case fractionHead.MatchString(s[:a]), uuidHead.MatchString(s[:a]): // "3.1415926535", a UUID's last group
		return 0, 0, false
	}
	return a, b, true
}

var hexChunk = regexp.MustCompile(`^[0-9a-fA-F]+\z`)

func identifierCheck(s string, a, b int) (int, int, bool) {
	m := s[a:b]
	chunks := strings.Split(m, "-")
	d, years := digits(m), true // only years and words ("2024-2025-season") isn't an identifier
	for _, c := range chunks {
		years = years && (digits(c) == 0 || year.MatchString(c))
	}
	if letters(m) == 0 || years || d < 8 || len(chunks) == 1 && d < 10 || publicCode.MatchString(s[:a]) || publicCode.MatchString(chunks[0]) {
		return 0, 0, false
	}
	hex := true
	for _, c := range chunks {
		hex = hex && hexChunk.MatchString(c)
	}
	if hex {
		return 0, 0, false
	}
	return a, b, true
}

var (
	ipShape    = regexp.MustCompile(`^\d{1,3}(?:\.\d{1,3}){3}\z`)
	dotsOnly   = regexp.MustCompile(`^\d+(?:\.\d+){3,}\z`)
	yearsOnly  = regexp.MustCompile(`^(?:19|20)\d\d(?:[ .\-](?:19|20)\d\d)+\z`)
	datePrefix = regexp.MustCompile(`^(?:\d{4}[-./]\d{1,2}[-./]\d{1,2}|\d{1,2}[-./]\d{1,2}[-./]\d{4})(?:[ .\-]|\z)`)
	digitRun   = regexp.MustCompile(`\d+`)
)

func digitGroupsCheck(s string, a, b int) (int, int, bool) {
	m := s[a:b]
	if digits(m) < 9 || ipShape.MatchString(m) || dotsOnly.MatchString(m) || yearsOnly.MatchString(m) || datePrefix.MatchString(m) ||
		roundThousands.MatchString(m) || notPhone(m, s[:a]) || publicCode.MatchString(s[:a]) {
		return 0, 0, false
	}
	return a, b, true
}

// spelledEmail: a spelled-out address is one when it ends in a top-level domain and, with a plain " at ", has a
// dot, digit or underscore before it or a mail provider after it ("jdoe at gmail dot com"; not "deals at amazon
// dot com").
func spelledEmail(s string, a, b int) (int, int, bool) {
	m := strings.ToLower(s[a:b])
	parts := spelledDot.Split(m, -1)
	tld := strings.TrimSpace(parts[len(parts)-1])
	if !commonTLD[tld] && !(len(tld) == 2 && letters(tld) == 2) {
		return 0, 0, false
	}
	at := plainAt.FindStringIndex(m)
	if at == nil {
		return a, b, true
	}
	local, domain := m[:at[0]], m[at[1]:]
	if strings.ContainsAny(local, "._0123456789") || mailProvider[strings.TrimSpace(spelledDot.Split(domain, 2)[0])] {
		return a, b, true
	}
	return 0, 0, false
}

var (
	spelledDot   = regexp.MustCompile(`\s*(?:\.|\(dot\)|\[dot\]|\{dot\}|<dot>)\s*|\s+dot\s+`)
	plainAt      = regexp.MustCompile(`\s+at\s+`)
	commonTLD    = map[string]bool{"com": true, "org": true, "net": true, "edu": true, "gov": true, "mil": true, "info": true, "biz": true, "app": true, "dev": true, "mail": true}
	mailProvider = map[string]bool{"gmail": true, "googlemail": true, "yahoo": true, "hotmail": true, "outlook": true, "live": true, "icloud": true, "me": true, "aol": true, "proton": true, "protonmail": true, "pm": true, "gmx": true, "web": true, "yandex": true, "mail": true, "zoho": true, "fastmail": true, "hey": true, "example": true}
)

// labelToken is a label rule's check: the value right after the label (labelToken scans it), with at least
// minDigits digits and either a letter or one more digit ("passport X12345678", "SIN 046 454 286"; not
// "policy 2024").
func labelToken(minDigits int) func(s string, a, b int) (int, int, bool) {
	return func(s string, _, b int) (int, int, bool) {
		e, d, l := scanToken(s, b)
		if e <= b || d < minDigits || d == minDigits && l == 0 {
			return 0, 0, false
		}
		return b, e, true
	}
}

var bookingRe = regexp.MustCompile(`^[A-Z0-9]{5,8}\b`)

// bookingCode: an airline or hotel booking code (5-8 capitals and digits, both) opens the booking.
func bookingCode(s string, _, b int) (int, int, bool) {
	m := bookingRe.FindString(s[b:])
	if m == "" || digits(m) == 0 || letters(m) == 0 {
		return 0, 0, false
	}
	return b, b + len(m), true
}

// plateToken: a plate has letters and digits ("7ABC123", "B-MK 4321"; not "hot plate 1500W").
func plateToken(s string, _, b int) (int, int, bool) {
	e, d, l := scanToken(s, b)
	if e <= b || d < 2 || l < 2 || e-b < 5 {
		return 0, 0, false
	}
	return b, e, true
}

// scanToken reads an ID-like value from i: alphanumeric chunks joined by single spaces, dots, dashes or slashes,
// each with a digit or short and uppercase ("B", "MK", "CV"; lowercase after a dash or slash: "23-cv-01234"), ending with a chunk that has a digit. It returns
// where it ends and its digits and letters.
func scanToken(s string, i int) (end, nd, nl int) {
	end = i
	j := i
	for n := 0; n < 8 && j < len(s); n++ {
		k := j
		for k < len(s) && (s[k] >= '0' && s[k] <= '9' || s[k] >= 'A' && s[k] <= 'Z' || s[k] >= 'a' && s[k] <= 'z') {
			k++
		}
		c := s[j:k]
		if c == "" {
			break
		}
		cd := digits(c)
		joined := j > i && (s[j-1] == '-' || s[j-1] == '/')
		if cd == 0 && (len(c) > 4 || strings.ToUpper(c) != c && !joined) {
			break
		}
		if cd > 0 {
			end = k
		}
		if k < len(s) && k+1 < len(s) && strings.IndexByte(" .-/", s[k]) >= 0 && s[k+1] != ' ' {
			j = k + 1
			continue
		}
		break
	}
	tok := s[i:end]
	return end, digits(tok), letters(tok)
}

// ---- folding ----------------------------------------------------------------------------------------

var pctSep = regexp.MustCompile(`%(?:40|2[0BbDdEe]|28|29|5[BbDd])`)

// confusables: Cyrillic and Greek letters that look like Latin ones, folded only inside a Latin word ("jаne" with
// a Cyrillic а); a Cyrillic or Greek word stays as it is.
var confusables = map[rune]rune{
	'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'х': 'x', 'у': 'y', 'і': 'i', 'ј': 'j', 'ѕ': 's', 'ԁ': 'd',
	'ӏ': 'l', 'һ': 'h', 'ԛ': 'q', 'ԝ': 'w', 'А': 'A', 'В': 'B', 'Е': 'E', 'К': 'K', 'М': 'M', 'Н': 'H', 'О': 'O',
	'Р': 'P', 'С': 'C', 'Т': 'T', 'Х': 'X', 'ο': 'o', 'α': 'a', 'ρ': 'p', 'ε': 'e', 'ι': 'i', 'κ': 'k', 'ν': 'v',
	'τ': 't', 'υ': 'u', 'Α': 'A', 'Β': 'B', 'Ε': 'E', 'Ζ': 'Z', 'Η': 'H', 'Ι': 'I', 'Κ': 'K', 'Μ': 'M', 'Ν': 'N',
	'Ο': 'O', 'Ρ': 'P', 'Τ': 'T', 'Χ': 'X', 'Υ': 'Y',
}

// foldText is s with what hides personal data from the patterns undone: %40 and other encoded separators,
// compatibility forms (NFKC: fullwidth "＠" and digits, ligatures), Unicode dashes and spaces as ASCII, invisible
// characters dropped, other scripts' digits as ASCII digits, "+" between words as a space (a URL's query), and
// lookalike letters inside Latin words.
func foldText(s string) string {
	s = pctSep.ReplaceAllStringFunc(s, func(m string) string {
		switch strings.ToUpper(m) {
		case "%40":
			return "@"
		case "%2B":
			return "+"
		case "%2D":
			return "-"
		case "%2E":
			return "."
		case "%20":
			return " "
		case "%28":
			return "("
		case "%29":
			return ")"
		case "%5B":
			return "["
		case "%5D":
			return "]"
		}
		return m
	})
	rs := []rune(norm.NFKC.String(s))
	latin := func(i int) bool { return i >= 0 && i < len(rs) && rs[i] < unicode.MaxASCII && unicode.IsLetter(rs[i]) }
	alnum := func(i int) bool {
		return i >= 0 && i < len(rs) && (unicode.IsLetter(rs[i]) || unicode.IsDigit(rs[i]))
	}
	var b strings.Builder
	for i, r := range rs {
		switch {
		case r == '\n' || r == '\t' || r == '\r':
			b.WriteRune(r)
		case unicode.Is(unicode.Cf, r) || unicode.Is(unicode.Cc, r):
		case strings.ContainsRune("‐‑‒–—―−﹘﹣－", r):
			b.WriteByte('-')
		case unicode.Is(unicode.Zs, r):
			b.WriteByte(' ')
		case r > unicode.MaxASCII && unicode.Is(unicode.Nd, r):
			b.WriteRune('0' + digitValue(r))
		case r == '+' && alnum(i-1) && alnum(i+1):
			b.WriteByte(' ')
		default:
			if c, ok := confusables[r]; ok && (latin(i-1) || latin(i+1)) {
				r = c
			}
			b.WriteRune(r)
		}
	}
	return b.String()
}

// digitValue: a decimal digit's value in its script (the digits of a script are 10 code points in a row).
func digitValue(r rune) rune {
	z := r
	for z > 0 && unicode.Is(unicode.Nd, z-1) {
		z--
	}
	return (r - z) % 10
}

// ---- IBAN -------------------------------------------------------------------------------------------

// ibanLengths are the IBAN registry's countries and the length of their IBANs (SWIFT IBAN registry).
var ibanLengths = map[string]int{
	"AD": 24, "AE": 23, "AL": 28, "AT": 20, "AZ": 28, "BA": 20, "BE": 16, "BG": 22, "BH": 22, "BI": 27, "BR": 29,
	"BY": 28, "CH": 21, "CR": 22, "CY": 28, "CZ": 24, "DE": 22, "DJ": 27, "DK": 18, "DO": 28, "EE": 20, "EG": 29,
	"ES": 24, "FI": 18, "FK": 18, "FO": 18, "FR": 27, "GB": 22, "GE": 22, "GI": 23, "GL": 18, "GR": 27, "GT": 28,
	"HN": 28, "HR": 21, "HU": 28, "IE": 22, "IL": 23, "IQ": 23, "IS": 26, "IT": 27, "JO": 30, "KW": 30, "KZ": 20,
	"LB": 28, "LC": 32, "LI": 21, "LT": 20, "LU": 20, "LV": 21, "LY": 25, "MC": 27, "MD": 24, "ME": 22, "MK": 19,
	"MN": 20, "MR": 27, "MT": 31, "MU": 30, "NI": 28, "NL": 18, "NO": 15, "OM": 23, "PK": 24, "PL": 28, "PS": 29,
	"PT": 25, "QA": 29, "RO": 24, "RS": 22, "RU": 33, "SA": 24, "SC": 31, "SD": 18, "SE": 24, "SI": 19, "SK": 24,
	"SM": 27, "SO": 23, "ST": 25, "SV": 28, "TL": 23, "TN": 24, "TR": 26, "UA": 29, "VA": 22, "VG": 24, "XK": 20,
	"YE": 30,
}

// ibanLen is the length in bytes of the IBAN that the iban pattern's match m starts with, or 0 when it isn't one:
// its country is in the registry, it has that country's length (spaces aside; the match may run on into the next
// group, so the IBAN ends there, at a space or the match's end) and passes the ISO 13616 mod-97 check.
func ibanLen(m string) int {
	if len(m) < 4 {
		return 0
	}
	want, ok := ibanLengths[m[:2]]
	if !ok {
		return 0
	}
	compact := make([]byte, 0, want)
	end := -1
	for i := 0; i < len(m); i++ {
		if m[i] == ' ' {
			continue
		}
		compact = append(compact, m[i])
		if len(compact) == want {
			end = i + 1
			break
		}
	}
	if end < 0 || end < len(m) && m[end] != ' ' || !ibanChecksum(compact) {
		return 0
	}
	return end
}

// ibanChecksum: the country and check digits moved to the end, letters as 10-35, the number mod 97 is 1.
func ibanChecksum(iban []byte) bool {
	r := 0
	for _, c := range append(append([]byte{}, iban[4:]...), iban[:4]...) {
		switch {
		case c >= '0' && c <= '9':
			r = (r*10 + int(c-'0')) % 97
		case c >= 'A' && c <= 'Z':
			r = (r*100 + int(c-'A') + 10) % 97
		default:
			return false
		}
	}
	return r == 1
}
