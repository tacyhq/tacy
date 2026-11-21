package verifier

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/tacyhq/tacy/safety"
)

// The 24 h delay at clients (safety/trustdelay.go): what a signed list adds counts at a verifier only once that
// verifier has seen it listed for safety.TrustDelay; a withdrawal applies at once and an item listed again waits
// again; Google Cloud (dstack-gcp) waits like any addition; a lowered floor keeps the old one for the delay; the
// emergency override (the pinned KMS id's signature) expedites only the items it names, and a bad one refuses the list.
func TestTrustDelay(t *testing.T) {
	admin := testAdmin(t)
	id := kmsKey(t)
	rc := bootWith(t, composeWithKMS(t, `"-kms-key", "`+id+`", "-kms-url", "https://kms.tacy.io", `), false, nil, keyEvent(false))
	passes := func(s *TrustState, at time.Time) error {
		p, info := s.Apply(rc.p, at)
		if info != nil && !info.OK {
			t.Fatalf("list refused at use: %s", info.Error)
		}
		p.Now = rc.p.Now
		_, err := Verify(context.Background(), rc.a, rc.nonce, p)
		return err
	}
	list := func(seq uint64, l safety.TrustList) []byte {
		l.Seq = seq
		return signedList(t, admin, l)
	}
	withID := safety.TrustList{KMSIDs: map[string]string{id: "Tacy KMS (test)"}}

	var s TrustState
	info := s.Take(list(5, withID), 0, listNow)
	if !info.OK || info.KMSIDs != 1 || len(info.Pending) != 1 || info.Pending[0].Item != safety.TrustItemKMSID+id ||
		!info.Pending[0].From.Equal(listNow.Add(safety.TrustDelay)) || info.Seen == "" {
		t.Fatalf("a new KMS id should be taken and pending for 24 h: %+v", info)
	}
	if err := passes(&s, listNow); err == nil || !strings.HasPrefix(err.Error(), "Tacy KMS:") {
		t.Fatalf("a KMS id listed a moment ago counted: %v", err)
	}
	if err := passes(&s, listNow.Add(safety.TrustDelay-time.Minute)); err == nil {
		t.Fatal("a KMS id listed 23 h 59 min ago counted")
	}
	if err := passes(&s, listNow.Add(safety.TrustDelay)); err != nil {
		t.Fatalf("a KMS id listed 24 h ago: %v", err)
	}
	seen := info.Seen

	// The device keeps the record; a new list a day later that still names it: counts.
	later := listNow.Add(safety.TrustDelay)
	var s2 TrustState
	if i := s2.TakeSeen(list(6, withID), 5, later, []byte(seen)); !i.OK || len(i.Pending) != 0 {
		t.Fatalf("a kept record: %+v", i)
	} else {
		seen = i.Seen
	}
	if err := passes(&s2, later); err != nil {
		t.Fatalf("kept record, still listed: %v", err)
	}
	// Withdrawn: at once.
	if i := s2.TakeSeen(list(7, safety.TrustList{}), 6, later, []byte(seen)); !i.OK {
		t.Fatal(i.Error)
	} else {
		seen = i.Seen
	}
	if err := passes(&s2, later); err == nil {
		t.Fatal("a withdrawn KMS id still counted")
	}
	// Listed again an hour later: waits a full day again.
	again := later.Add(time.Hour)
	if i := s2.TakeSeen(list(8, withID), 7, again, []byte(seen)); !i.OK || len(i.Pending) != 1 {
		t.Fatalf("listed again: %+v", i)
	} else {
		seen = i.Seen
	}
	if err := passes(&s2, again.Add(safety.TrustDelay-time.Minute)); err == nil {
		t.Fatal("an item withdrawn and listed again counted before a new day")
	}
	if err := passes(&s2, again.Add(safety.TrustDelay)); err != nil {
		t.Fatalf("listed again, a day on: %v", err)
	}

	// A record the device can't read: everything waits (never counts at once).
	var s3 TrustState
	if i := s3.TakeSeen(list(9, withID), 0, again, []byte("{not json")); !i.OK || len(i.Pending) != 1 {
		t.Fatalf("an unreadable record: %+v", i)
	}
}

// dstack-gcp is an addition like any other: Google Cloud's sets come on only a day after a client first saw the
// platform listed, and off at once when a list drops it.
func TestTrustDelayGCP(t *testing.T) {
	admin := testAdmin(t)
	gcpOn := func(p Policy) bool {
		for h := range GCPImages {
			if _, ok := p.ProdImages[h]; ok {
				return true
			}
		}
		return false
	}
	var s TrustState
	env := signedList(t, admin, safety.TrustList{Seq: 3, Platforms: []string{"dstack", PlatformDstackGCP}})
	info := s.Take(env, 0, listNow)
	if !info.OK || len(info.Pending) != 1 || info.Pending[0].Item != safety.TrustItemPlatform+PlatformDstackGCP {
		t.Fatalf("dstack-gcp should be pending: %+v", info)
	}
	if p, _ := s.Apply(Policy{}, listNow); gcpOn(p) {
		t.Fatal("Google Cloud's sets on at once")
	}
	if p, _ := s.Apply(Policy{}, listNow.Add(safety.TrustDelay)); !gcpOn(p) {
		t.Fatal("Google Cloud's sets still off a day later")
	}
	off := s.TakeSeen(signedList(t, admin, safety.TrustList{Seq: 4, Platforms: []string{"dstack"}}), 3, listNow.Add(safety.TrustDelay), []byte(info.Seen))
	if p, _ := s.Apply(Policy{}, listNow.Add(safety.TrustDelay)); !off.OK || gcpOn(p) {
		t.Fatalf("dropped dstack-gcp still on: %+v", off)
	}
}

// Releases, boot sets, OS images, services, pre-launch scripts, KMS roots and a TCB grace wait too; a release entry
// reaches the client's bundle lookup (ReleaseEntries) only once it counts; a boot set waits with its OS image.
func TestTrustDelayEveryAddition(t *testing.T) {
	admin := testAdmin(t)
	img := strings.Repeat("c", 64)
	l := safety.TrustList{Seq: 2,
		OSImages:         map[string]string{img: "dstack-0.6.9 (test)"},
		BootMeasurements: []safety.TrustBoot{{Name: "0.6.9", OSImage: img, MRTD: strings.Repeat("1", 96), RTMR0: strings.Repeat("2", 96), RTMR1: strings.Repeat("3", 96), RTMR2: strings.Repeat("4", 96), Source: "test"}},
		PreLaunch:        map[string]string{strings.Repeat("d", 64): "pre (test)"},
		KMSRoots:         map[string]string{strings.Repeat("e", 64): "root (test)"},
		Services:         []string{"holderprobe"},
		Releases:         []safety.TrustRelease{trustRelease("v0.30.0", strings.Repeat("a", 64), fakeBundle(5))},
		TCBGrace:         &safety.TCBGrace{Until: listNow.Add(7 * 24 * time.Hour), Statuses: []string{"OutOfDate"}},
	}
	env := signedList(t, admin, l)
	var s TrustState
	info := s.Take(env, 0, listNow)
	if !info.OK || len(info.ReleaseEntries) != 0 || len(info.Pending) != 7 {
		t.Fatalf("every addition should wait: %+v", info)
	}
	p, _ := s.Apply(Policy{}, listNow)
	if _, ok := p.ProdImages[img]; ok || len(p.Boot) != len(BootMeasurements) || p.PreLaunch[strings.Repeat("d", 64)] != "" ||
		p.KMSRoots[strings.Repeat("e", 64)] != "" || slices.Contains(p.Services, "holderprobe") || len(p.Releases) != 0 || p.AllowStaleTCB {
		t.Fatalf("pending additions applied: %+v", p)
	}
	day := listNow.Add(safety.TrustDelay)
	again := s.TakeSeen(env, 0, day, []byte(info.Seen))
	if len(again.ReleaseEntries) != 1 || len(again.Pending) != 0 {
		t.Fatalf("a day later: %+v", again)
	}
	q, _ := s.Apply(Policy{}, day)
	if _, ok := q.ProdImages[img]; !ok || len(q.Boot) != len(BootMeasurements)+1 || !slices.Contains(q.Services, "holderprobe") || len(q.Releases) != 1 ||
		!q.AllowStaleTCB {
		t.Fatalf("a day later, not applied: %+v", q)
	}

	// The boot set counts but its OS image was withdrawn and listed again: the set waits with it.
	seen := safety.ParseTrustSeen([]byte(again.Seen))
	st := seen.Items[safety.TrustItemOS+img]
	st.First = day
	seen.Items[safety.TrustItemOS+img] = st
	var b TrustState
	b.TakeSeen(env, 0, day, seen.Marshal())
	if r, _ := b.Apply(Policy{}, day); len(r.Boot) != len(BootMeasurements) {
		t.Fatal("a boot set counted while its OS image waits")
	}
}

// A lowered vm_release_floor keeps the old floor in force for the delay; a raise applies at once.
func TestTrustDelayFloor(t *testing.T) {
	admin := testAdmin(t)
	var s TrustState
	i := ripen(t, &s, signedList(t, admin, safety.TrustList{Seq: 2, VMReleaseFloor: "v0.22.0"}), 0)
	if p, _ := s.Apply(Policy{}, listNow); p.ReleaseFloor != "v0.22.0" {
		t.Fatalf("floor: %q", p.ReleaseFloor)
	}
	low := s.TakeSeen(signedList(t, admin, safety.TrustList{Seq: 3, VMReleaseFloor: "v0.21.0"}), 2, listNow, []byte(i.Seen))
	if p, _ := s.Apply(Policy{}, listNow.Add(safety.TrustDelay-time.Minute)); p.ReleaseFloor != "v0.22.0" || len(low.Pending) != 1 {
		t.Fatalf("a lowered floor applied at once: %q %+v", p.ReleaseFloor, low.Pending)
	}
	if p, _ := s.Apply(Policy{}, listNow.Add(safety.TrustDelay)); p.ReleaseFloor != "v0.21.0" {
		t.Fatalf("a lowered floor, a day later: %q", p.ReleaseFloor)
	}
	s.TakeSeen(signedList(t, admin, safety.TrustList{Seq: 4, VMReleaseFloor: "v0.23.0"}), 3, listNow, []byte(low.Seen))
	if p, _ := s.Apply(Policy{}, listNow); p.ReleaseFloor != "v0.23.0" {
		t.Fatalf("a raised floor didn't apply at once: %q", p.ReleaseFloor)
	}
}

// The emergency override, as the holders take it (kms/split emergency.go): signed by the build's pinned KMS id, for
// this list's seq, naming items this list adds; those count at once (and stay counted in later lists), the others
// still wait. Signed by any other key (a KMS id the list itself adds included), for another seq, or naming an item
// the list doesn't add: the whole list is refused.
func TestTrustDelayEmergency(t *testing.T) {
	admin := testAdmin(t)
	_, kmsPriv, _ := ed25519.GenerateKey(rand.Reader)
	old := trustKMSID
	trustKMSID = kmsPriv.Public().(ed25519.PublicKey)
	t.Cleanup(func() { trustKMSID = old })

	fix := trustRelease("v0.30.1", strings.Repeat("a", 64), fakeBundle(5))
	other := strings.Repeat("c", 64)
	base := safety.TrustList{Type: safety.TrustListType, Seq: 6, IssuedAt: listNow.Add(-time.Hour), Releases: []safety.TrustRelease{fix},
		OSImages: map[string]string{other: "dstack-0.6.9 (test)"}}
	withEm := func(signer ed25519.PrivateKey, seq uint64, items ...string) []byte {
		l := base
		l.Optional = nil
		em, err := safety.SignTrustEmergency(signer, safety.TrustEmergency{ListSeq: seq, Items: items, Reason: "CVE fix", IssuedAt: listNow})
		if err != nil {
			t.Fatal(err)
		}
		if err := l.SetEmergency(em); err != nil {
			t.Fatal(err)
		}
		return signedList(t, admin, l)
	}
	item := safety.TrustReleaseItem(fix)

	var s TrustState
	info := s.Take(withEm(kmsPriv, 6, item), 0, listNow)
	if !info.OK || info.Emergency != "CVE fix" || len(info.ReleaseEntries) != 1 || len(info.Pending) != 1 || info.Pending[0].Item != safety.TrustItemOS+other {
		t.Fatalf("the override should expedite the fix only: %+v", info)
	}
	if p, _ := s.Apply(Policy{}, listNow); len(p.Releases) != 1 {
		t.Fatal("the expedited release isn't in force")
	}
	// The next list (no override) keeps the fix counted.
	base.Seq = 7
	next := s.TakeSeen(signedList(t, admin, base), 6, listNow.Add(time.Hour), []byte(info.Seen))
	if len(next.ReleaseEntries) != 1 {
		t.Fatalf("the expedited release waits again in the next list: %+v", next)
	}
	base.Seq = 6

	_, stranger, _ := ed25519.GenerateKey(rand.Reader)
	for name, env := range map[string][]byte{
		"signed by another key":        withEm(stranger, 6, item),
		"for another list":             withEm(kmsPriv, 5, item),
		"naming an item not in it":     withEm(kmsPriv, 6, safety.TrustItemOS+strings.Repeat("f", 64)),
		"naming an item not in it (2)": withEm(kmsPriv, 6, "release:"+strings.Repeat("0", 64)),
	} {
		var r TrustState
		if i := r.Take(env, 0, listNow); i.OK {
			t.Errorf("%s: taken", name)
		}
	}
	// A KMS id the list adds can't sign an override: only the build's pinned one.
	var added TrustState
	l := base
	_, listed, _ := ed25519.GenerateKey(rand.Reader)
	l.KMSIDs = map[string]string{safety.KeyString(listed.Public().(ed25519.PublicKey)): "added (test)"}
	em, _ := safety.SignTrustEmergency(listed, safety.TrustEmergency{ListSeq: 6, Items: []string{item}, Reason: "x", IssuedAt: listNow})
	l.SetEmergency(em)
	if i := added.Take(signedList(t, admin, l), 0, listNow); i.OK {
		t.Fatal("an override signed by a KMS id the list adds was taken")
	}
	// No pinned KMS id: no override verifies.
	trustKMSID = nil
	var none TrustState
	if i := none.Take(withEm(kmsPriv, 6, item), 0, listNow); i.OK {
		t.Fatal("an override taken with no pinned KMS id")
	}
}
