package safety

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json/jsontext"
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
		VMReleaseFloor: "v0.20.0",
		Releases: []TrustRelease{{Version: "v0.21.0", Commit: strings.Repeat("e5", 20), ComposeSHA256: strings.Repeat("ef", 32),
			Bundle: []byte(`{"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json"}`)}}}
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
	if len(l.Releases) != 1 || l.Releases[0].Version != "v0.21.0" || l.Releases[0].Bundle.Kind() != '{' {
		t.Fatalf("releases %+v", l.Releases)
	}
	unknownRel := Sign(KindTrustList, []byte(`{"type":"tacy.trust-list/v1","seq":1,"issued_at":"2026-11-20T00:00:00Z","expires":"2026-12-20T00:00:00Z",`+
		`"releases":[{"version":"v0.21.0","commit":"`+strings.Repeat("e", 40)+`","compose_sha256":"`+strings.Repeat("a", 64)+`","bundle":{},"app":1}]}`), admin)
	refused("a release's unknown member", unknownRel, pinned, 1, 0, tlNow, "unknown")
	// Larger than other documents (bundles), up to MaxTrustListPayload.
	if e := signList(t, bigList(7), admin); len(e.Payload) <= MaxEnvelope {
		t.Fatal("not larger than MaxEnvelope")
	} else if _, err := VerifyTrustList(&e, pinned, 1, 0, tlNow); err != nil {
		t.Fatalf("a list over MaxEnvelope: %v", err)
	}
	over := e
	over.Payload = make([]byte, MaxTrustListPayload+1)
	refused("over MaxTrustListPayload", over, pinned, 1, 0, tlNow, "size")

	for _, c := range []struct {
		name string
		edit func(l *TrustList)
	}{
		{"type", func(l *TrustList) { l.Type = "x" }},
		{"seq 0", func(l *TrustList) { l.Seq = 0 }},
		{"no issued_at", func(l *TrustList) { l.IssuedAt = time.Time{} }},
		{"an expiry before issued_at", func(l *TrustList) { l.Expires = l.IssuedAt.Add(-time.Hour) }},
		{"over 400 days", func(l *TrustList) { l.Expires = l.IssuedAt.Add(401 * 24 * time.Hour) }},
		{"OS image hash", func(l *TrustList) { l.OSImages = map[string]string{"AB": "x"} }},
		{"pre-launch hash", func(l *TrustList) { l.PreLaunch = map[string]string{"zz": "x"} }},
		{"KMS id", func(l *TrustList) { l.KMSIDs = map[string]string{"ed25519:nope": "x"} }},
		{"register", func(l *TrustList) { l.BootMeasurements[0].RTMR2 = "00" }},
		{"no source", func(l *TrustList) { l.BootMeasurements[0].Source = "" }},
		{"floor", func(l *TrustList) { l.VMReleaseFloor = "0.20" }},
		{"release version", func(l *TrustList) { l.Releases[0].Version = "0.21.0" }},
		{"release commit", func(l *TrustList) { l.Releases[0].Commit = "E512" }},
		{"release compose", func(l *TrustList) { l.Releases[0].ComposeSHA256 = strings.Repeat("EF", 32) }},
		{"release twice", func(l *TrustList) { l.Releases = append(l.Releases, l.Releases[0]) }},
		{"no bundle", func(l *TrustList) { l.Releases[0].Bundle = nil }},
		{"bundle not an object", func(l *TrustList) { l.Releases[0].Bundle = []byte(`["x"]`) }},
		{"bundle not JSON", func(l *TrustList) { l.Releases[0].Bundle = []byte(`{"x":`) }},
		{"bundle too large", func(l *TrustList) {
			l.Releases[0].Bundle = []byte(`{"x":"` + strings.Repeat("x", MaxTrustBundle) + `"}`)
		}},
		{"too many releases", func(l *TrustList) {
			for i := range MaxTrustReleases {
				r := l.Releases[0]
				r.Version = "v1.0." + string(rune('0'+i))
				l.Releases = append(l.Releases, r)
			}
		}},
	} {
		l := sampleList(1)
		c.edit(&l)
		if err := l.Validate(); err == nil {
			t.Errorf("%s: accepted", c.name)
		}
	}
}

// bigList is a list over MaxEnvelope (two releases with 20 KiB bundles), within MaxTrustListPayload.
func bigList(seq uint64) TrustList {
	l := sampleList(seq)
	l.Releases[0].Bundle = []byte(`{"x":"` + strings.Repeat("x", 20<<10) + `"}`)
	r := l.Releases[0]
	r.Version = "v0.21.1"
	l.Releases = append(l.Releases, r)
	return l
}

func TestDecodeTrustList(t *testing.T) {
	admin := trustKey(t)
	e := signList(t, bigList(3), admin)
	b, _ := json.Marshal(e)
	got, err := DecodeTrustList(b)
	if err != nil || got.Hash() != e.Hash() {
		t.Fatalf("%v", err)
	}
	// DecodeEnvelopes (the other documents' bound) refuses it; a trust list is one envelope, not an array.
	if _, err := DecodeEnvelopes(b); err == nil {
		t.Fatal("DecodeEnvelopes took a trust list over MaxEnvelope")
	}
	for name, in := range map[string][]byte{
		"empty":          nil,
		"an array":       append(append([]byte("["), b...), ']'),
		"unknown member": []byte(`{"kind":"trust-list","payload":"e30=","sigs":[],"x":1}`),
		"oversize":       []byte(`{"kind":"` + strings.Repeat("x", 2*MaxTrustListPayload) + `"}`),
		"trailing data":  append(append([]byte{}, b...), []byte(" {}")...),
	} {
		if _, err := DecodeTrustList(in); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// No expiry: a list without one holds until a newer seq replaces it; one that names an expiry still
// stops counting then.
func TestTrustListNoExpiry(t *testing.T) {
	admin := trustKey(t)
	pinned := []ed25519.PublicKey{admin.Public().(ed25519.PublicKey)}
	l := sampleList(6)
	l.Expires = time.Time{}
	e := signList(t, l, admin)
	if got, err := VerifyTrustList(&e, pinned, 1, 6, tlNow.Add(5*365*24*time.Hour)); err != nil || got.Seq != 6 {
		t.Fatalf("a list with no expiry, five years on: %v", err)
	}
	if _, err := VerifyTrustList(&e, pinned, 1, 7, tlNow); err == nil || !strings.Contains(err.Error(), "older") {
		t.Fatalf("withdrawn by a newer seq: %v", err)
	}
}

// The fields a later VM release may need, defined before any VM depends on them (clients ship first): revoked
// releases, extra services, dstack KMS roots, a TCB grace window, a release's platform, admin keys for the next lists.
func TestTrustListLaterFields(t *testing.T) {
	admin, next := trustKey(t), trustKey(t)
	pinned := []ed25519.PublicKey{admin.Public().(ed25519.PublicKey)}
	nextKey := KeyString(next.Public().(ed25519.PublicKey))
	good := sampleList(4)
	good.RevokedReleases = []string{"v0.20.0"}
	good.Services = []string{"unlockd", "holder_probe"}
	good.KMSRoots = map[string]string{strings.Repeat("3059", 40): "dstack KMS (another provider)"}
	good.TCBGrace = &TCBGrace{Until: tlNow.Add(10 * 24 * time.Hour), Statuses: []string{"OutOfDate", "ConfigurationNeeded"},
		MinTCBDate: "2026-08-01"}
	good.Releases[0].Platform = "dstack"
	good.NextAdminKeys = []string{nextKey}
	good.StartTicketKeys = []string{KeyString(trustKey(t).Public().(ed25519.PublicKey))}
	good.RollbackWitness = &TrustWitness{Head: strings.Repeat("ab", 32), Seq: 9}
	good.Optional = map[string]jsontext.Value{"later_thing": jsontext.Value(`{"x":[1,2]}`)}
	e := signList(t, good, admin)
	l, err := VerifyTrustList(&e, pinned, 1, 0, tlNow)
	if err != nil || l.RevokedReleases[0] != "v0.20.0" || len(l.Services) != 2 || l.TCBGrace == nil || l.Releases[0].Platform != "dstack" ||
		l.RollbackWitness.Seq != 9 || len(l.StartTicketKeys) != 1 || len(l.Optional) != 1 {
		t.Fatalf("%v %+v", err, l)
	}
	if keys, th := NextAdminKeys(l, pinned, 1); len(keys) != 1 || !keys[0].Equal(next.Public()) || th != 1 {
		t.Fatalf("next keys %v %d", keys, th)
	}
	if keys, _ := NextAdminKeys(&TrustList{}, pinned, 1); !keys[0].Equal(admin.Public()) {
		t.Fatal("a list naming no keys changed them")
	}
	for name, edit := range map[string]func(l *TrustList){
		"a bad revoked version":   func(l *TrustList) { l.RevokedReleases = []string{"0.20.0"} },
		"a revoked version twice": func(l *TrustList) { l.RevokedReleases = []string{"v0.20.0", "v0.20.0"} },
		"listed and revoked":      func(l *TrustList) { l.RevokedReleases = []string{"v0.21.0"} },
		"a bad service name":      func(l *TrustList) { l.Services = []string{"Bad Name"} },
		"a service twice":         func(l *TrustList) { l.Services = []string{"x", "x"} },
		"a bad KMS root":          func(l *TrustList) { l.KMSRoots = map[string]string{"zz": "x"} },
		"a TCB grace over 30 days": func(l *TrustList) {
			l.TCBGrace = &TCBGrace{Until: l.IssuedAt.Add(31 * 24 * time.Hour), Statuses: []string{"OutOfDate"}}
		},
		"a TCB grace before issued": func(l *TrustList) {
			l.TCBGrace = &TCBGrace{Until: l.IssuedAt.Add(-time.Minute), Statuses: []string{"OutOfDate"}}
		},
		"a TCB grace for Revoked": func(l *TrustList) {
			l.TCBGrace = &TCBGrace{Until: l.IssuedAt.Add(time.Hour), Statuses: []string{"OutOfDate", "Revoked"}}
		},
		"a TCB grace with no status": func(l *TrustList) { l.TCBGrace = &TCBGrace{Until: l.IssuedAt.Add(time.Hour)} },
		"a TCB grace for UpToDate": func(l *TrustList) {
			l.TCBGrace = &TCBGrace{Until: l.IssuedAt.Add(time.Hour), Statuses: []string{"UpToDate"}}
		},
		"a witness without a head": func(l *TrustList) { l.RollbackWitness = &TrustWitness{Seq: 1} },
		"a bad start-ticket key":   func(l *TrustList) { l.StartTicketKeys = []string{"x"} },
		"a bad optional name":      func(l *TrustList) { l.Optional = map[string]jsontext.Value{"Bad Name": jsontext.Value(`1`)} },
		"a bad platform":           func(l *TrustList) { l.Releases[0].Platform = "SEV SNP" },
		"a bad admin key":          func(l *TrustList) { l.NextAdminKeys = []string{"ed25519:nope"} },
		"an admin key twice":       func(l *TrustList) { l.NextAdminKeys = []string{nextKey, nextKey} },
		"nine admin keys": func(l *TrustList) {
			l.NextAdminKeys = nil
			for range 9 {
				l.NextAdminKeys = append(l.NextAdminKeys, KeyString(trustKey(t).Public().(ed25519.PublicKey)))
			}
		},
	} {
		l := sampleList(4)
		edit(&l)
		e := signList(t, l, admin)
		if _, err := VerifyTrustList(&e, pinned, 1, 0, tlNow); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// Strict as before: a member this build doesn't know refuses the whole list.
	raw, _ := json.Marshal(sampleList(5))
	unknown := Sign(KindTrustList, append(raw[:len(raw)-1], []byte(`,"later_field":1}`)...), admin)
	if _, err := VerifyTrustList(&unknown, pinned, 1, 0, tlNow); err == nil {
		t.Fatal("an unknown member was accepted")
	}
}

// A rotation link: signed by the keys before it, names the next keys, after the link before it. A chain decodes as
// rotations then the list; one envelope is a chain of none.
func TestTrustListChain(t *testing.T) {
	admin, next := trustKey(t), trustKey(t)
	pinned := []ed25519.PublicKey{admin.Public().(ed25519.PublicKey)}
	rot := sampleList(3)
	rot.NextAdminKeys = []string{KeyString(next.Public().(ed25519.PublicKey))}
	re := signList(t, rot, admin)
	if l, err := VerifyTrustListLink(&re, pinned, 1, 2, tlNow.Add(365*24*time.Hour)); err != nil || l.Seq != 3 {
		t.Fatalf("a rotation past its expiry still links: %v", err)
	}
	if _, err := VerifyTrustListLink(&re, pinned, 1, 3, tlNow); err == nil || !strings.Contains(err.Error(), "isn't after") {
		t.Fatalf("not after the link before: %v", err)
	}
	plain := signList(t, sampleList(4), admin)
	if _, err := VerifyTrustListLink(&plain, pinned, 1, 0, tlNow); err == nil || !strings.Contains(err.Error(), "names no next admin keys") {
		t.Fatalf("a list naming no keys as a link: %v", err)
	}
	other := signList(t, rot, next)
	if _, err := VerifyTrustListLink(&other, pinned, 1, 0, tlNow); err == nil {
		t.Fatal("a link signed by a key that isn't the current one")
	}
	rb, _ := json.Marshal(re)
	pb, _ := json.Marshal(plain)
	links, list, err := DecodeTrustListChain([]byte("[" + string(rb) + "," + string(pb) + "]"))
	if err != nil || len(links) != 1 || list.Hash() != plain.Hash() {
		t.Fatalf("%v %d", err, len(links))
	}
	if links, list, err := DecodeTrustListChain(pb); err != nil || links != nil || list.Hash() != plain.Hash() {
		t.Fatalf("one envelope: %v", err)
	}
	ten := "[" + strings.TrimSuffix(strings.Repeat(string(pb)+",", 10), ",") + "]"
	for name, in := range map[string]string{"empty": "[]", "too long": ten, "not envelopes": `[1]`, "trailing": "[" + string(pb) + "] x"} {
		if _, _, err := DecodeTrustListChain([]byte(in)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
