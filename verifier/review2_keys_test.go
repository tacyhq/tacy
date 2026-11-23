package verifier

import (
	"crypto/ed25519"
	"crypto/rand"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/tacyhq/tacy/safety"
)

// The second keys review (a research note), client side. Each test failed before its
// fix (the review's proof tests, made binding).

// H1: a version leaving revoked_releases is an addition: it stays revoked at this verifier for safety.TrustDelay
// from when it first saw it left out (item unrevoke:vX), shown as pending; revoked again, at once; left out again,
// it waits a full day again. The emergency override (pinned KMS id) may expedite the un-revocation.
func TestReview2UnrevokeWaits(t *testing.T) {
	admin := testAdmin(t)
	var s TrustState
	i := s.Take(signedList(t, admin, safety.TrustList{Seq: 5, RevokedReleases: []string{"v0.21.0"}}), 0, listNow)
	if !i.OK {
		t.Fatal(i.Error)
	}
	if p, _ := s.Apply(Policy{}, listNow); !p.Revoked("v0.21.0") {
		t.Fatal("setup: not revoked")
	}
	at := listNow.Add(time.Minute)
	i = s.TakeSeen(signedList(t, admin, safety.TrustList{Seq: 6}), 5, at, []byte(i.Seen))
	if !i.OK {
		t.Fatal(i.Error)
	}
	if p, _ := s.Apply(Policy{}, at); !p.Revoked("v0.21.0") {
		t.Fatal("an admin-key list un-revoked v0.21.0 at once (no delay)")
	}
	unrevoke := "unrevoke:v0.21.0"
	if !slices.Contains(i.RevokedReleases, "v0.21.0") || !slices.ContainsFunc(i.Pending, func(p safety.TrustPending) bool {
		return p.Item == unrevoke && p.From.Equal(at.Add(safety.TrustDelay))
	}) {
		t.Fatalf("the un-revocation should be pending for 24 h and the release still reported revoked: %+v", i)
	}
	if p, _ := s.Apply(Policy{}, at.Add(safety.TrustDelay-time.Second)); !p.Revoked("v0.21.0") {
		t.Fatal("un-revoked before 24 h")
	}
	if p, info := s.Apply(Policy{}, at.Add(safety.TrustDelay)); p.Revoked("v0.21.0") || slices.Contains(info.RevokedReleases, "v0.21.0") {
		t.Fatal("still revoked 24 h after the un-revocation was first seen")
	}
	// The record a day later: the un-revocation holds in the next list too.
	later := at.Add(safety.TrustDelay)
	j := s.TakeSeen(signedList(t, admin, safety.TrustList{Seq: 7}), 6, later, []byte(i.Seen))
	if p, _ := s.Apply(Policy{}, later); !j.OK || p.Revoked("v0.21.0") {
		t.Fatalf("a ripe un-revocation lost in the next list: %+v", j)
	}
	// Revoked again: at once. Left out again: waits a full day again.
	j = s.TakeSeen(signedList(t, admin, safety.TrustList{Seq: 8, RevokedReleases: []string{"v0.21.0"}}), 7, later, []byte(j.Seen))
	if p, _ := s.Apply(Policy{}, later); !p.Revoked("v0.21.0") {
		t.Fatal("a revocation listed again didn't apply at once")
	}
	again := later.Add(time.Hour)
	j = s.TakeSeen(signedList(t, admin, safety.TrustList{Seq: 9}), 8, again, []byte(j.Seen))
	if p, _ := s.Apply(Policy{}, again.Add(safety.TrustDelay-time.Minute)); !p.Revoked("v0.21.0") {
		t.Fatal("a second un-revocation didn't wait a full day")
	}
	// A list older than the record can't un-revoke either (a fallback to a kept list): the revocation stays.
	var old TrustState
	k := old.TakeSeen(signedList(t, admin, safety.TrustList{Seq: 4}), 0, again, []byte(j.Seen))
	if p, _ := old.Apply(Policy{}, again); !k.OK || !p.Revoked("v0.21.0") {
		t.Fatalf("an older list un-revoked at once: %+v", k)
	}
}

// H1: the emergency override can expedite an un-revocation (and only one this verifier keeps).
func TestReview2UnrevokeEmergency(t *testing.T) {
	admin := testAdmin(t)
	_, kmsPriv, _ := ed25519.GenerateKey(rand.Reader)
	old := trustKMSID
	trustKMSID = kmsPriv.Public().(ed25519.PublicKey)
	t.Cleanup(func() { trustKMSID = old })

	var s TrustState
	i := s.Take(signedList(t, admin, safety.TrustList{Seq: 5, RevokedReleases: []string{"v0.21.0", "v0.21.1"}}), 0, listNow)
	l := safety.TrustList{Type: safety.TrustListType, Seq: 6, IssuedAt: listNow.Add(-time.Hour)}
	em, err := safety.SignTrustEmergency(kmsPriv, safety.TrustEmergency{ListSeq: 6, Items: []string{"unrevoke:v0.21.0"}, Reason: "revoked by mistake", IssuedAt: listNow})
	if err != nil {
		t.Fatal(err)
	}
	if err := l.SetEmergency(em); err != nil {
		t.Fatal(err)
	}
	at := listNow.Add(time.Minute)
	i = s.TakeSeen(signedList(t, admin, l), 5, at, []byte(i.Seen))
	p, _ := s.Apply(Policy{}, at)
	if !i.OK || p.Revoked("v0.21.0") || !p.Revoked("v0.21.1") {
		t.Fatalf("the override should un-revoke v0.21.0 at once and only it: %+v", i)
	}
	// An override naming an un-revocation of a version the list still revokes: refused whole.
	bad := safety.TrustList{Type: safety.TrustListType, Seq: 7, IssuedAt: listNow.Add(-time.Hour), RevokedReleases: []string{"v0.21.1"}}
	em, _ = safety.SignTrustEmergency(kmsPriv, safety.TrustEmergency{ListSeq: 7, Items: []string{"unrevoke:v0.21.1"}, Reason: "x", IssuedAt: listNow})
	bad.SetEmergency(em)
	var r TrustState
	if j := r.Take(signedList(t, admin, bad), 0, listNow); j.OK {
		t.Fatal("an override un-revoking a version the list revokes was taken")
	}
}

// M1: a seq above 2^53-1 (what JavaScript can't keep exactly) or more than MaxTrustSeqJump above the highest taken
// is refused, so a device's record is never wiped by a list it can't store.
func TestReview2HugeSeqRefused(t *testing.T) {
	admin := testAdmin(t)
	for name, c := range map[string]struct{ seq, min uint64 }{
		"2^60":         {1 << 60, 3},
		"2^53":         {1 << 53, 1<<53 - 10},
		"a jump":       {3 + review2Jump + 1, 3},
		"a fresh jump": {TrustListFloorSeq + review2Jump + 1, 0},
	} {
		var s TrustState
		if i := s.Take(signedList(t, admin, safety.TrustList{Seq: c.seq}), c.min, listNow); i.OK {
			t.Errorf("%s: seq %d taken over %d", name, c.seq, c.min)
		}
	}
	var s TrustState
	if i := s.Take(signedList(t, admin, safety.TrustList{Seq: 3 + review2Jump}), 3, listNow); !i.OK {
		t.Errorf("a jump of exactly MaxTrustSeqJump: %s", i.Error)
	}
	// The jump counts from the record's own seq too (the caller's minSeq lost).
	i := s.Take(signedList(t, admin, safety.TrustList{Seq: 2000}), 1900, listNow)
	if !i.OK {
		t.Fatal(i.Error)
	}
	var s2 TrustState
	if j := s2.TakeSeen(signedList(t, admin, safety.TrustList{Seq: 2000 + review2Jump + 1}), 0, listNow, []byte(i.Seen)); j.OK {
		t.Error("a jump over the record's seq taken with no minSeq")
	}
	// A record whose seq is out of range keeps its revocations and items (it isn't reset to accept anything).
	rec := `{"seq":1152921504606846976,"items":{},"revoked_machines":["` + strings.Repeat("a", 64) + `"],"revoked_releases":["v0.21.0"]}`
	got := safety.ParseTrustSeen([]byte(rec))
	if len(got.RevokedMachines) != 1 || !strings.Contains(string(got.Marshal()), `"v0.21.0"`) || got.Seq > 1<<53-1 {
		t.Fatalf("an out-of-range record lost its revocations: %+v", got)
	}
}

// L1: a Google machine certificate doesn't count at a client while platform dstack-gcp is still pending.
func TestReview2GoogleCertWaitsForPlatform(t *testing.T) {
	admin, kms := testAdmin(t), testKMS(t)
	c5 := signCert(t, kms, phalaDoc(prod5PPID, "phala prod5", listNow.Add(-48*time.Hour)))
	g := safety.MachineDoc{Type: safety.MachineType, Platform: safety.PlatformDstack, Host: safety.MachineHostGoogle,
		Mode: safety.MachineModePPID, PPID: strings.Repeat("ab", 16), FMSPC: "00906ed50000", Label: "gcp host", IssuedAt: listNow.Add(-48 * time.Hour)}
	gc := signCert(t, kms, g)
	l := listWithMachines(t, 5, []safety.SignedMachineCert{c5, gc}, nil)
	l.Platforms = []string{"dstack", PlatformDstackGCP}
	var s TrustState
	i := s.Take(signedList(t, admin, l), 0, listNow)
	if !i.OK {
		t.Fatal(i.Error)
	}
	p, _ := s.Apply(Policy{}, listNow)
	if _, err := p.Machines.Match(g.PPID, g.FMSPC); err == nil {
		t.Fatal("the Google certificate matched while dstack-gcp is pending")
	}
	if _, err := p.Machines.Match(prod5PPID, phalaFMSPC); err != nil {
		t.Fatalf("prod5 should still match: %v", err)
	}
	if slices.Contains(i.Machines, "gcp host") {
		t.Fatalf("the Google machine is reported in force: %v", i.Machines)
	}
	p, _ = s.Apply(Policy{}, listNow.Add(safety.TrustDelay))
	if _, err := p.Machines.Match(g.PPID, g.FMSPC); err != nil {
		t.Fatalf("the Google certificate once dstack-gcp counts: %v", err)
	}
}

// L4: a record whose items can't be kept (oversized) or whose member is unreadable keeps its revocations: they are
// read on their own, outside the item map.
func TestReview2SeenResetKeepsRevocations(t *testing.T) {
	h := strings.Repeat("b", 64)
	var items strings.Builder
	items.WriteString(`{`)
	for n := range safety.MaxTrustSeen + 1 {
		if n > 0 {
			items.WriteString(",")
		}
		items.WriteString(`"os:` + strings.Repeat("0", 60) + string(rune('a'+n%26)) + strings.Repeat("1", 3) + `` + itoa(n) + `":{"first":"2026-11-20T00:00:00Z"}`)
	}
	items.WriteString(`}`)
	for name, rec := range map[string]string{
		"oversized items": `{"seq":5,"items":` + items.String() + `,"revoked_machines":["` + h + `"],"revoked_releases":["v0.21.0"]}`,
		"bad items":       `{"seq":5,"items":{"x":{"first":"not a time"}},"revoked_machines":["` + h + `"],"revoked_releases":["v0.21.0"]}`,
	} {
		got := safety.ParseTrustSeen([]byte(rec))
		if !slices.Contains(got.RevokedMachines, h) || !strings.Contains(string(got.Marshal()), `"v0.21.0"`) {
			t.Errorf("%s: revocations lost: %+v", name, got)
		}
		if len(got.Items) != 0 {
			t.Errorf("%s: items kept from a bad record: %d", name, len(got.Items))
		}
	}
}

// review2Jump is safety.MaxTrustSeqJump (a literal, so the test builds on the code before the fix).
const review2Jump = 1000

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for ; n > 0; n /= 10 {
		b = append([]byte{byte('0' + n%10)}, b...)
	}
	return string(b)
}
