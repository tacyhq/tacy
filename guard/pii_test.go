package guard

import (
	"slices"
	"testing"
)

// Prices, years and ranges next to each other are not phone numbers ("best espresso machine under $1000 2026" went
// out as "under $[phone]"); real phone numbers stay masked. TestMaskPII (agent_test.go) has the other kinds.
func TestMaskPIIPricesAndYears(t *testing.T) {
	keep := []string{
		"best espresso machine under $1000 2026",
		"$1,299 2025",
		"laptop 1,299 2025",
		"under 500 2026",
		"$999.99 2026 model",
		"999.99 2026 model",
		"1000 2026",
		"2025 2026 comparison",
		"rav4 2025 2026 comparison",
		"ps5 1000 2026",
		"nba 2025-2026 season",
		"4k 120hz 2026 tv under 800",
		"iphone 17 256 gb 2026 price",
		"gaming laptop 1000-1500",
		"top 100 2026",
		"rtx 5090 2026 price",
		"€1.299 2025",
		"£800 1200 budget",
	}
	for _, q := range keep {
		if got, kinds := maskPII(q); got != q || kinds != nil {
			t.Errorf("maskPII(%q) = %q %v, want unchanged", q, got, kinds)
		}
	}
	phones := []struct{ in, want string }{
		{"+1 415-555-0134", "[phone]"},
		{"415 555 0134", "[phone]"},
		{"(415) 555-0134", "[phone]"},
		{"415-555-2026", "[phone]"},
		{"020 7946 0958", "[phone]"},
		{"+44 20 7946 0958", "[phone]"},
		{"call 555-0134 today", "call [phone] today"},
		{"phone 555 0147 call log", "phone [phone] call log"},
		{"555 2026 who called", "[phone] who called"},
		{"312.555.0198 debt collector", "[phone] debt collector"},
		{"555-0134,415-555-0199", "[phone],[phone]"},
		{"rav4 415-555-0134", "rav[phone]"},
		{"under $1000 2026 or call 415-555-0134", "under $1000 2026 or call [phone]"},
	}
	for _, c := range phones {
		if got, kinds := maskPII(c.in); got != c.want || !slices.Equal(kinds, []string{"phone"}) {
			t.Errorf("maskPII(%q) = %q %v, want %q [phone]", c.in, got, kinds, c.want)
		}
	}
}

// An IBAN is masked only when it is one (registry country, its length, mod-97): long model numbers in an image
// query stay (v0.10.1: "Samsung DW90F89P0USR" went out as "Samsung [iban]").
func TestMaskPIIIBANChecked(t *testing.T) {
	masked := []struct{ in, want string }{
		{"IBAN DE89 3704 0044 0532 0130 00", "IBAN [iban]"},
		{"pay DE89370400440532013000 today", "pay [iban] today"},
		{"GB82 WEST 1234 5698 7654 32", "[iban]"},
		{"GB82WEST12345698765432 RENT", "[iban] RENT"},
		{"FR14 2004 1010 0505 0001 3M02 606", "[iban]"},
		{"NL91ABNA0417164300", "[iban]"},
		{"NO9386011117947", "[iban]"},
		{"BE68539007547034 invoice", "[iban] invoice"},
	}
	for _, c := range masked {
		if got, kinds := maskPII(c.in); got != c.want || !slices.Equal(kinds, []string{"iban"}) {
			t.Errorf("maskPII(%q) = %q %v, want %q [iban]", c.in, got, kinds, c.want)
		}
	}
	keep := []string{
		"Samsung DW90F89P0USR dishwasher",
		"DW90F89P0USR",
		"Samsung QN65S90DAEXZA",
		"LG OLED65C4PUA 65 inch",
		"GB00WEST12345698765432", // a GB shape, wrong check digits
		"DE89WEST12345698765432", // DE's length, wrong check
		"NL91ABNA041716430",      // one short
	}
	for _, q := range keep {
		if got, kinds := maskPII(q); got != q || kinds != nil {
			t.Errorf("maskPII(%q) = %q %v, want unchanged", q, got, kinds)
		}
	}
}
