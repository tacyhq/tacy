package guard

import (
	"strings"
	"testing"
)

func TestTrimMailQuote(t *testing.T) {
	// A Google security alert (2026-10-28), as its text part has it.
	s := strings.Join([]string{
		"[image: Google]",
		"A new sign-in on Mac",
		"you@example.com",
		"We noticed a new sign-in to your Google Account on a Mac device. If this was you, you don't need to do anything.",
		"Check activity",
		"https://myaccount.google.example/notifications",
		"You received this email to let you know about important changes to your Google Account and services.",
		"© 2026 Google LLC, 1600 Amphitheatre Parkway, Mountain View, CA 94043, USA",
		"Total due: $40.00",
	}, "\n")
	pass := func(first, last string) (int, int) {
		a := strings.Index(s, first)
		b := strings.Index(s, last) + len(last)
		if a < 0 || b < a {
			t.Fatalf("no %q..%q", first, last)
		}
		return a, b
	}
	for _, c := range []struct{ first, last, want string }{
		{"[image: Google]", "A new sign-in on Mac", "A new sign-in on Mac"},
		{"you@example.com", "don't need to do anything.", "We noticed a new sign-in to your Google Account on a Mac device. If this was you, you don't need to do anything."},
		{"Check activity", "and services.", ""},
		{"[image: Google]", "Mountain View, CA 94043, USA", "A new sign-in on Mac\nyou@example.com\nWe noticed a new sign-in to your Google Account on a Mac device. If this was you, you don't need to do anything."},
		{"We noticed", "Check activity", "We noticed a new sign-in to your Google Account on a Mac device. If this was you, you don't need to do anything."},
		// A short line with a number stays; one short line alone stays.
		{"© 2026", "Total due: $40.00", "Total due: $40.00"},
		{"Check activity", "Check activity", "Check activity"},
		// Part of a line: as given.
		{"If this was you", "anything.", "If this was you, you don't need to do anything."},
	} {
		a, b := pass(c.first, c.last)
		x, y, ok := trimMailQuote(s, a, b)
		got := ""
		if ok {
			got = s[x:y]
		}
		if got != c.want {
			t.Errorf("%q..%q: got %q, want %q", c.first, c.last, got, c.want)
		}
	}
	// By sentence: a footer sentence ending the passage's line goes; a short last sentence of the point stays.
	p := "Your package was left at the front door. Please confirm by replying. Due Friday. This email was sent to you@example.com. © 2026 Keyshop."
	if a, b, ok := trimMailQuote(p, 0, len(p)); !ok || p[a:b] != "Your package was left at the front door. Please confirm by replying. Due Friday." {
		t.Errorf("by sentence: %q", p[a:b])
	}
	for _, s := range []string{"View this email in your browser", "View in browser", "Having trouble viewing this email? View it online.",
		"Unsubscribe | Manage preferences | Privacy policy", "This email was sent to you@example.com.", "<you@example.com>",
		"[image: Facebook] [image: Instagram] [image: LinkedIn]", "Please do not reply to this message.", "https://example.com/x?y=1"} {
		if !mailBoilerplate(s) {
			t.Errorf("not boilerplate: %q", s)
		}
	}
	for _, s := range []string{"Your payment of $182.44 was sent.", "Please send the signed W-9 by Monday.", "Reply to bob@client.example by Friday.",
		"Preorder now for $249. Ships November 12.", "A new sign-in on Mac",
		"We updated our privacy policy; the changes take effect on December 1, 2026.",
		"Your recovery email was changed, and the privacy settings of your account now show your phone number to everyone who visits your profile page."} {
		if mailBoilerplate(s) {
			t.Errorf("boilerplate: %q", s)
		}
	}
}
