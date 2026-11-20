package safety

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json/v2"
	"strings"
	"testing"
	"time"
)

func trustKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, k, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

var tlNow = time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)

func sampleList(seq uint64) TrustList {
	return TrustList{Type: TrustListType, Seq: seq, IssuedAt: tlNow.Add(-time.Hour), Expires: tlNow.Add(30 * 24 * time.Hour),
		OSImages:  map[string]string{strings.Repeat("ab", 32): "dstack-0.6.6"},
		PreLaunch: map[string]string{strings.Repeat("cd", 32): "Tacy pre-launch v1"},
		KMSIDs:    map[string]string{KeyString(make(ed25519.PublicKey, 32)): "Tacy KMS (test)"},
		BootMeasurements: []TrustBoot{{Name: "dstack-0.6.6, tdx.small", OSImage: strings.Repeat("ab", 32), MRTD: strings.Repeat("01", 48),
			RTMR0: strings.Repeat("02", 48), RTMR1: strings.Repeat("03", 48), RTMR2: strings.Repeat("04", 48), Source: "computed (test)"}},
		VMReleaseFloor: "v0.20.0"}
}

func signList(t *testing.T, l TrustList, keys ...ed25519.PrivateKey) Envelope {
	t.Helper()
	b, err := json.Marshal(l)
	if err != nil {
		t.Fatal(err)
	}
	return Sign(KindTrustList, b, keys...)
}

func TestTrustList(t *testing.T) {
	admin, other := trustKey(t), trustKey(t)
	pinned := []ed25519.PublicKey{admin.Public().(ed25519.PublicKey)}
	e := signList(t, sampleList(7), admin)
	l, err := VerifyTrustList(&e, pinned, 1, 7, tlNow)
	if err != nil || l.Seq != 7 || l.OSImages[strings.Repeat("ab", 32)] != "dstack-0.6.6" || l.VMReleaseFloor != "v0.20.0" {
		t.Fatalf("%v %+v", err, l)
	}
	refused := func(name string, e Envelope, keys []ed25519.PublicKey, threshold int, minSeq uint64, now time.Time, want string) {
		t.Helper()
		if _, err := VerifyTrustList(&e, keys, threshold, minSeq, now); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v", name, err)
		}
	}
	refused("an older list than one taken", e, pinned, 1, 8, tlNow, "older than list 8")
	refused("expired", e, pinned, 1, 0, tlNow.Add(31*24*time.Hour), "expired")
	refused("issued in the future", e, pinned, 1, 0, tlNow.Add(-2*time.Hour), "future")
	refused("another signer", signList(t, sampleList(7), other), pinned, 1, 0, tlNow, "signed by 0")
	refused("below the threshold", e, append(pinned, other.Public().(ed25519.PublicKey)), 2, 0, tlNow, "needs 2")
	refused("no keys pinned", e, nil, 1, 0, tlNow, "no signing keys")
	policy := Sign(KindPolicy, e.Payload, admin) // the same bytes signed as another kind
	policy.Kind = KindTrustList
	refused("a signature for another kind", policy, pinned, 1, 0, tlNow, "signed by 0")
	wrongKind := e
	wrongKind.Kind = KindPolicy
	refused("another kind", wrongKind, pinned, 1, 0, tlNow, "kind")
	unknown := Sign(KindTrustList, []byte(`{"type":"tacy.trust-list/v1","seq":1,"issued_at":"2026-11-20T00:00:00Z","expires":"2026-12-20T00:00:00Z","extra":1}`), admin)
	refused("an unknown member", unknown, pinned, 1, 0, tlNow, "unknown")

	for _, c := range []struct {
		name string
		edit func(l *TrustList)
	}{
		{"type", func(l *TrustList) { l.Type = "x" }},
		{"seq 0", func(l *TrustList) { l.Seq = 0 }},
		{"no expiry", func(l *TrustList) { l.Expires = time.Time{} }},
		{"over 400 days", func(l *TrustList) { l.Expires = l.IssuedAt.Add(401 * 24 * time.Hour) }},
		{"OS image hash", func(l *TrustList) { l.OSImages = map[string]string{"AB": "x"} }},
		{"pre-launch hash", func(l *TrustList) { l.PreLaunch = map[string]string{"zz": "x"} }},
		{"KMS id", func(l *TrustList) { l.KMSIDs = map[string]string{"ed25519:nope": "x"} }},
		{"register", func(l *TrustList) { l.BootMeasurements[0].RTMR2 = "00" }},
		{"no source", func(l *TrustList) { l.BootMeasurements[0].Source = "" }},
		{"floor", func(l *TrustList) { l.VMReleaseFloor = "0.20" }},
	} {
		l := sampleList(1)
		c.edit(&l)
		if err := l.Validate(); err == nil {
			t.Errorf("%s: accepted", c.name)
		}
	}
}
