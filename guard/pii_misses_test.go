package guard

import (
	"slices"
	"testing"
)

// The PII misses (2026-10-21; graded by the chat's PII scorecard, these are a sample of its
// cases): national phone formats, IDs by shape or label, dates of birth, street addresses, accounts, lookalike and
// invisible characters, encodings; and what must survive.
func TestMaskPIIMisses(t *testing.T) {
	cases := []struct {
		in, want string
		kinds    []string
	}{
		// Phones the old pattern missed or cut.
		{"07700 900123 missed call", "[phone] missed call", []string{"phone"}},
		{"+91 98765 43210 courier", "[phone] courier", []string{"phone"}},
		{"+33 1 23 45 67 89 rappel", "[phone] rappel", []string{"phone"}},
		{"+44 (0)20 7946 0958 callback", "[phone] callback", []string{"phone"}},
		{"06 12 34 56 78 numéro inconnu", "[phone] numéro inconnu", []string{"phone"}},
		{"who owns two zero two five five five zero one four seven", "who owns [phone]", []string{"phone"}},
		// Lookalikes, invisible characters, encodings: folded, then masked (the folded text goes out).
		{"415‐555‐0134 missed call", "[phone] missed call", []string{"phone"}},
		{"+44 20 7946 0958 caller id", "[phone] caller id", []string{"phone"}},
		{"４１５-５５５-０１３４ who", "[phone] who", []string{"phone"}},
		{"415-555​-0134 scam", "[phone] scam", []string{"phone"}},
		{"415+555+0134 owner lookup", "[phone] owner lookup", []string{"phone"}},
		{"4 1 5 5 5 5 0 1 3 4 who called", "[number] who called", []string{"number"}},
		{"jane.doe@exa​mple.com login", "[email] login", []string{"email"}},
		{"jane.doe%40example.com unsubscribe", "[email] unsubscribe", []string{"email"}},
		{"jane.doe＠example.com recovery", "[email] recovery", []string{"email"}},
		{"SSN 219–09–9999 credit freeze", "SSN [ssn] credit freeze", []string{"ssn"}},
		{"4111 1111 1111 1111 chargeback", "[card] chargeback", []string{"card"}},
		// Emails: other scripts, spelled out.
		{"josé.garcía@correo.es reclamación", "[email] reclamación", []string{"email"}},
		{"anna.k@müller-example.de Rechnung", "[email] Rechnung", []string{"email"}},
		{"john.reyes at gmail dot com contact", "[email] contact", []string{"email"}},
		{"j.reyes[at]example[dot]com phishing", "[email] phishing", []string{"email"}},
		{"jdoe at gmail dot com hacked", "[email] hacked", []string{"email"}},
		// IDs by shape, and by the label before them (the label stays).
		{"National Insurance number QQ 12 34 56 C lost", "National Insurance number [national-id] lost", []string{"national-id"}},
		{"DNI 12345678Z renovación", "DNI [national-id] renovación", []string{"national-id"}},
		{"PAN ABCPE1234F status", "PAN [national-id] status", []string{"national-id"}},
		{"codice fiscale RSSMRA85T10A562S verifica", "codice fiscale [national-id] verifica", []string{"national-id"}},
		{"passport X12345678 visa appointment", "passport [national-id] visa appointment", []string{"national-id"}},
		{"SIN 046 454 286 lost card", "SIN [national-id] lost card", []string{"national-id"}},
		{"driver's license D1234567 suspended", "driver's license [national-id] suspended", []string{"national-id"}},
		{"verify SSN 219099999 employer", "verify SSN [national-id] employer", []string{"national-id"}},
		{"policy number 9A-4471-22B claim denied", "policy number [account] claim denied", []string{"account"}},
		{"case no. 23-cv-01234 settlement", "case no. [account] settlement", []string{"account"}},
		{"member ID XJH123456789 coverage", "member ID [account] coverage", []string{"account"}},
		{"booking reference XK7P2Q change fee", "booking reference [account] change fee", []string{"account"}},
		{"license plate 7ABC123 parking ticket", "license plate [plate] parking ticket", []string{"plate"}},
		{"car towed plate B-MK 4321 Berlin", "car towed plate [plate] Berlin", []string{"plate"}},
		{"eviction case 2024-CV-004417 court date", "eviction case [number] court date", []string{"number"}},
		{"1Z999AA10123456784 where is my package", "[number] where is my package", []string{"number"}},
		// Dates of birth after a label.
		{"date of birth 03/14/1987 life insurance", "date of birth [dob] life insurance", []string{"dob"}},
		{"DOB 1987-03-14 passport form", "DOB [dob] passport form", []string{"dob"}},
		{"geboren 14.03.1987 Rente", "geboren [dob] Rente", []string{"dob"}},
		{"born March 14, 1987 birth chart", "born [dob] birth chart", []string{"dob"}},
		// Street addresses, and the flat and postcode next to one.
		{"noise complaint 1428 Elm Street Springfield IL", "noise complaint [address] Springfield IL", []string{"address"}},
		{"parking permit 14 Wexford Road London SW12 8HP", "parking permit [address] London [address]", []string{"address"}},
		{"350 W 5th Ave Apt 12B noise", "[address] [address] noise", []string{"address"}},
		{"1428 elm street springfield", "[address] springfield", []string{"address"}},
		{"Hausverwaltung Musterstraße 12 Berlin", "Hausverwaltung [address] Berlin", []string{"address"}},
		{"hausse de loyer 4 rue des Lilas 75011 Paris", "hausse de loyer [address] 75011 Paris", []string{"address"}},
		{"Calle Mayor 10 Madrid", "[address] Madrid", []string{"address"}},
		// A card's length but not a card (no Luhn): masked as a number, so a page address with one isn't refused.
		{"account 1234 5678 9012 3456", "account [number]", []string{"number"}},
		{"ref 1234 5678 9012 3456 x", "ref [number] x", []string{"number"}},
	}
	for _, c := range cases {
		if got, kinds := maskPII(c.in); got != c.want || !slices.Equal(kinds, c.kinds) {
			t.Errorf("maskPII(%q) = %q %v, want %q %v", c.in, got, kinds, c.want, c.kinds)
		}
	}

	keep := []string{
		"CVE-2024-3094 xz backdoor details",
		"CVE-2021-44228 log4shell patch",
		"arxiv 2310.06825 paper summary",
		"Windows 11 build 26100.4652 known issues",
		"Chrome 141.0.7390.54 security fixes",
		"ISBN 978-0-306-40615-7 edition",
		"EAN 4006381333931 product",
		"UPC 012345678905 product lookup",
		"patent US 11234567 B2 claims",
		"HS code 8471.30.0100 import duty",
		"DOI 10.1038/s41586-021-03819-2 alphafold",
		"1000000 yen to dollars",
		"salaire 1 000 000 euros impôts",
		"192.168.1.1 router admin login",
		"8.8.8.8 vs 1.1.1.1 DNS speed",
		"Top 10 Wall Street banks 2026",
		"5 best street food markets in Bangkok",
		"Main Street USA Disneyland opening hours",
		"born in 1987 how old am I in 2026",
		"famous people born on March 14",
		"commit 3f2a9c81b7d04e5f6a7b8c9d0e1f2a3b4c5d6e7f revert",
		"uuid 123e4567-e89b-12d3-a456-426614174000 format",
		"pi to 10 digits 3.1415926535",
		"Python 3.12.4 vs 3.13.0 performance",
		"concert 18/10/2026 19:30 Wembley tickets",
		"Sony WH-1000XM5 vs XM6 battery life",
		"deals at amazon dot com",
		"Route 66 road trip 10 days itinerary",
		"2026 Supreme Court term cases",
		"512 gb ssd drive price",
		"hot plate 1500W review",
		"privacy policy 2024 update",
		"order #48213 not shipped yet",
	}
	for _, q := range keep {
		if got, kinds := maskPII(q); got != q || kinds != nil {
			t.Errorf("maskPII(%q) = %q %v, want unchanged", q, got, kinds)
		}
	}
}

// A page address the model wrote is refused for the unambiguous kinds, after decoding (%40, %20, "+"); a phone only
// in a phone's own shape. Article ids, dates, product and paper numbers aren't refused.
func TestURLPersonalData(t *testing.T) {
	refused := map[string]string{
		"https://example.com/unsubscribe?email=jane.doe@example.com":           "email",
		"https://example.com/unsubscribe?email=jane.doe%40example.com":         "email",
		"https://www.whitepages.com/phone/1-415-555-0134":                      "phone",
		"https://www.google.com/search?q=415+555+0134":                         "phone",
		"https://example.com/contact?phone=%2B44%207700%20900123":              "phone",
		"https://example.com/verify?ssn=219099999":                             "national-id",
		"https://www.google.com/maps/search/742+Evergreen+Terrace+Springfield": "address",
		"https://example.com/quote?dob=1987-03-14&zip=62704":                   "dob",
		"https://pay.example.com/?card=4111111111111111":                       "card",
		"https://example.com/pay?iban=DE89370400440532013000":                  "iban",
	}
	for u, kind := range refused {
		if got := urlPersonalData(u); !slices.Contains(got, kind) {
			t.Errorf("urlPersonalData(%q) = %v, want %s", u, got, kind)
		}
	}
	for _, u := range []string{
		"https://www.bbc.com/news/world-us-canada-68012345",
		"https://github.com/golang/go/issues/67890",
		"https://arxiv.org/abs/2310.06825",
		"https://en.wikipedia.org/wiki/1600_Pennsylvania_Avenue",
		"https://news.ycombinator.com/item?id=41234567",
		"https://www.nytimes.com/2026/10/18/technology/ai-chips.html",
		"https://nvd.nist.gov/vuln/detail/CVE-2024-3094",
		"https://isbnsearch.org/isbn/9780306406157",
		"https://www.example-shop.de/p/4006381333931",
		"https://www.ebay.com/itm/256789012345",
	} {
		if got := urlPersonalData(u); got != nil {
			t.Errorf("urlPersonalData(%q) = %v, want none", u, got)
		}
	}
}
