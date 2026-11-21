package safety

import (
	"crypto/ed25519"
	"slices"
	"strings"
	"testing"
	"time"
)

// The overlap's end (overlapend.go) is an optional member: a build without this file parses the same struct (the
// member lands in Optional, which it never reads), so it takes the list as before, with the same items. It adds no
// item (nothing waits 24 h), and a verifier's record keeps it for good.
func TestOverlapEndedMember(t *testing.T) {
	k := trustKey(t)
	plain := sampleList(5)
	ended := sampleList(5)
	ended.SetOverlapEnded()
	if plain.OverlapEnded() || !ended.OverlapEnded() || (*TrustList)(nil).OverlapEnded() {
		t.Fatal("OverlapEnded")
	}
	e := signList(t, ended, k)
	got, err := VerifyTrustList(&e, []ed25519.PublicKey{k.Public().(ed25519.PublicKey)}, 1, 0, tlNow)
	if err != nil || !got.OverlapEnded() {
		t.Fatalf("verify: %v", err)
	}
	// Older builds: the member is only an optional one, and the list's items (what a verifier applies) are the same.
	if len(got.Optional) != 1 || string(got.Optional[TrustOverlapEndedMember]) != "true" || !slices.Equal(TrustItems(got), TrustItems(&plain)) {
		t.Fatalf("optional %v, items differ", got.Optional)
	}

	// Anything but true is refused whole: a list can't turn an ending off.
	for _, v := range []string{"false", `"true"`, "1", "null"} {
		bad := sampleList(6)
		bad.SetOverlapEnded()
		bad.Optional[TrustOverlapEndedMember] = []byte(v)
		if err := bad.Validate(); err == nil || !strings.Contains(err.Error(), "overlap_ended must be true") {
			t.Fatalf("overlap_ended %s: %v", v, err)
		}
	}

	// The record: set from the list, at once (InForce has it the same instant), kept by every later Observe, read back
	// on its own (a record whose items can't be read keeps it), and put into the list in force of a list without it.
	s := TrustSeen{}.Observe(got, nil, tlNow)
	if !s.OverlapEnded {
		t.Fatal("not recorded")
	}
	in, pending := s.InForce(got, tlNow)
	if !in.OverlapEnded() || slices.ContainsFunc(pending, func(p TrustPending) bool { return strings.Contains(p.Item, "overlap") }) {
		t.Fatalf("in force: %v %v", in.OverlapEnded(), pending)
	}
	later := sampleList(7)
	s2 := ParseTrustSeen(s.Marshal()).Observe(&later, nil, tlNow.Add(time.Hour))
	if !s2.OverlapEnded {
		t.Fatal("a later list without it turned it off")
	}
	if in, _ := s2.InForce(&later, tlNow.Add(time.Hour)); !in.OverlapEnded() || later.OverlapEnded() {
		t.Fatal("the list in force lost the end (or InForce changed the list)")
	}
	older := sampleList(1)
	if !s2.Observe(&older, nil, tlNow).OverlapEnded {
		t.Fatal("an older list turned it off")
	}
	if !ParseTrustSeen([]byte(`{"seq":"bad","items":7,"overlap_ended":true}`)).OverlapEnded {
		t.Fatal("an unreadable record's end lost")
	}
	if ParseTrustSeen([]byte(`{"seq":1,"items":{}}`)).OverlapEnded {
		t.Fatal("ended without the member")
	}
}
