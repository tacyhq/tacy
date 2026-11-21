package safety

import (
	"crypto/ed25519"
	"testing"
	"time"
)

// The optional fields added before anything uses them (pre-mortem 2026-11-20): a list with them validates and
// round-trips; a bad one is refused.
func TestTrustListOptionalFields(t *testing.T) {
	l := sampleList(9)
	l.TCBGrace = &TCBGrace{Until: l.IssuedAt.Add(7 * 24 * time.Hour), Statuses: []string{"OutOfDate"}, MinTCBDate: "2025-01-01"}
	l.Platforms = []string{"dstack"}
	l.NextAdminKeys = []string{KeyString(make(ed25519.PublicKey, 32))}
	if err := l.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, edit := range map[string]func(*TrustList){
		"a revoked grace":     func(l *TrustList) { l.TCBGrace.Statuses = []string{"Revoked"} },
		"a grace too long":    func(l *TrustList) { l.TCBGrace.Until = l.IssuedAt.Add(MaxTCBGrace + time.Hour) },
		"a bad min date":      func(l *TrustList) { l.TCBGrace.MinTCBDate = "last year" },
		"a bad next key":      func(l *TrustList) { l.NextAdminKeys = []string{"ed25519:nope"} },
		"a bad platform name": func(l *TrustList) { l.Platforms = []string{"Dstack Cloud!"} },
	} {
		c := l
		g := *l.TCBGrace
		c.TCBGrace = &g
		edit(&c)
		if err := c.Validate(); err == nil {
			t.Fatalf("%s: validated", name)
		}
	}
	g := l.TCBGrace
	now := l.IssuedAt.Add(time.Hour)
	if err := g.Allows("OutOfDate", "UpToDate", "2025-06-01T00:00:00Z", 0, now); err != nil {
		t.Fatal(err)
	}
	if err := g.Allows("Revoked", "UpToDate", "2025-06-01T00:00:00Z", 0, now); err == nil {
		t.Fatal("Revoked passed a grace")
	}
	if err := g.Allows("OutOfDate", "UpToDate", "2025-06-01T00:00:00Z", 0, g.Until); err == nil {
		t.Fatal("passed after the grace ended")
	}
}
