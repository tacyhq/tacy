package main

import (
	"bytes"
	"crypto/rand"
	"encoding/json/jsontext"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/tacyhq/tacy/kms/split"
	"github.com/tacyhq/tacy/kms/split/splitdev"
	"github.com/tacyhq/tacy/safety"
)

// epochTwo is a re-split of d's master to epoch 2 (share set 2, both holders) and its epoch certificate.
func epochTwo(t *testing.T, d *splitdev.Dev) (split.SignedShareSet, split.SignedEpochCert) {
	t.Helper()
	var rs []split.HolderRecipient
	for _, h := range d.Holders {
		rs = append(rs, split.HolderRecipient{Holder: h, Recipient: split.RecipientString(d.Keys[h].PublicKey())})
	}
	ss, _, err := split.Resplit(d.Master, d.KMSID, 2, 3, 2, rs, time.Now().Add(-time.Minute), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	c, err := epochCert(d.Master, d.KMSID, 2, "agent-vm", "f_chat", time.Now().Add(-time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	return *ss, *c
}

// The epoch rules of -min-unlock-epoch (review M1, M2): checked against the policy served now (the base, the one VMs
// unlocked with) as well as the one signed, and, whatever else a run changes, no share set below the list's retired
// epoch is ever signed. The base trust list's own map is never changed.
func TestMinUnlockEpochShareSets(t *testing.T) {
	d, err := splitdev.New([]string{"cloudflare", "vercel"}, 2, time.Now().Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	set2, cert2 := epochTwo(t, d)
	e1 := d.Policy // epoch 1, its epoch-1 set
	overlap := d.Policy
	overlap.Epoch, overlap.ShareSets, overlap.EpochCerts = 2, []split.SignedShareSet{set2, d.Policy.ShareSets[0]}, []split.SignedEpochCert{cert2, d.Policy.EpochCerts[0]}
	moved := d.Policy
	moved.Epoch, moved.ShareSets, moved.EpochCerts = 2, []split.SignedShareSet{set2}, []split.SignedEpochCert{cert2}
	for _, p := range []split.UnlockPolicy{overlap, moved} {
		if err := checkUnlockPolicy(&p); err != nil {
			t.Fatalf("fixture: %v", err)
		}
	}
	list := func(min uint32) *safety.TrustList {
		l := &safety.TrustList{Type: safety.TrustListType, Seq: 3, IssuedAt: time.Now().Add(-time.Hour)}
		if min > 0 {
			l.SetMinUnlockEpoch(min)
		}
		return l
	}
	var w bytes.Buffer
	for _, c := range []struct {
		name     string
		base, np split.UnlockPolicy
		want     string
	}{
		{"the overlap signed", overlap, overlap, "share set 2 is of epoch 1"},
		{"the epoch-2 set brought in by this run (M2: no VM proves epoch 2 yet)", e1, moved, "policy seq 1's share set"},
		{"the served policy still in the overlap (M2)", overlap, moved, "is of epoch 1"},
	} {
		ntl := *list(1)
		if err := raiseMinUnlockEpoch(&c.base, &c.np, &ntl, 2, &w); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v (want %q)", c.name, err, c.want)
		}
	}
	// The served policy and the signed one both past epoch 1: raised, the base list's map untouched.
	tl := list(1)
	before := maps.Clone(tl.Optional)
	ntl := *tl
	if err := raiseMinUnlockEpoch(&moved, &moved, &ntl, 2, &w); err != nil {
		t.Fatal(err)
	}
	if e, _ := ntl.MinUnlockEpoch(); e != 2 || !strings.Contains(w.String(), "every Google VM must have restarted since policy seq") {
		t.Fatalf("raised to %d; notice %q", e, w.String())
	}
	if !maps.EqualFunc(before, tl.Optional, func(a, b jsontext.Value) bool { return bytes.Equal(a, b) }) {
		t.Fatal("the trust base changed")
	}
	// M1: once epoch 1 is retired, no run may sign a policy with an epoch-1 set again (a share-set "rollback").
	if err := epochFloorHolds(&overlap, list(2)); err == nil || !strings.Contains(err.Error(), "retired") {
		t.Fatalf("an epoch-1 set under min_unlock_epoch 2: %v", err)
	}
	if err := epochFloorHolds(&moved, list(2)); err != nil {
		t.Fatal(err)
	}
	if err := epochFloorHolds(&e1, list(0)); err != nil {
		t.Fatal(err)
	}
}

// The review's CLI refusals: -min-unlock-epoch with -share-set or past uint32, the trust list's changes on the
// override-only path (L2), a version pinned already (L3, and with -remove in the same run: I5), one compose under two
// versions (L4), a policy-only -release whose app-compose doesn't embed its compose (I4), a lenient R.json (I1); and
// M1 through the CLI: a share-set change under a list that retired its epoch.
func TestApproveReviewRefusals(t *testing.T) {
	f := newApproveFixture(t)
	tl := f.approve[slices.Index(f.approve, "-trust-base")+1]
	base := []string{"approve", "-base", f.base, "-trust-base", tl}
	relB, trB, eB := slotBuild(t, f.dir, "b", "v1.0.0")
	set := filepath.Join(f.dir, "share-set-1.json")

	// A policy already pinning v1.0.0 (slot b's build), and a list that lists it.
	ws, _, _ := f.dryRun(t, "ws-pinned.json")
	var doc dryRunDoc
	readJSON(ws, &doc)
	pinned := writeJSONFile(t, filepath.Join(f.dir, "U-pinned.json"), doc.UnlockPolicy)
	listedB := writeJSONFile(t, filepath.Join(f.dir, "T-b.json"), safety.TrustList{Type: safety.TrustListType, Seq: 3, IssuedAt: time.Now().Add(-time.Hour), Releases: []safety.TrustRelease{eB}})
	sameCompose := writeJSONFile(t, filepath.Join(f.dir, "R-same.json"), safety.TrustRelease{Version: "v1.0.9", Commit: eB.Commit, ComposeSHA256: eB.ComposeSHA256, Bundle: eB.Bundle})
	lenient := filepath.Join(f.dir, "R-lenient.json")
	writeFileT(t, lenient, `{"version":"v1.0.0","commit":"`+eB.Commit+`","compose_sha256":"`+eB.ComposeSHA256+`","bundle":{},"extra":1}`)
	noEmbed := filepath.Join(f.dir, "ac-noembed.json")
	writeFileT(t, noEmbed, `{"name":"agent-vm","docker_compose_file":"services: {other: {}}\n"}`)
	retired := writeJSONFile(t, filepath.Join(f.dir, "T-retired.json"), func() safety.TrustList {
		l := safety.TrustList{Type: safety.TrustListType, Seq: 3, IssuedAt: time.Now().Add(-time.Hour)}
		l.SetMinUnlockEpoch(2)
		return l
	}())
	for _, c := range []struct {
		name string
		args []string
		want string
	}{
		{"-min-unlock-epoch with -share-set", append(slices.Clone(base), "-min-unlock-epoch", "1", "-share-set", set), "retire an epoch in its own approval"},
		{"-min-unlock-epoch past uint32", append(slices.Clone(base), "-min-unlock-epoch", "4294967297"), "isn't an epoch"},
		{"a trust entry on the override-only path", append(slices.Clone(base), "-emergency", "x", "-emergency-item", "other", "-trust-release", trB), "signs the policy's override alone"},
		{"-min-unlock-epoch on the override-only path", append(append(slices.Clone(base), "-emergency", "x", "-emergency-item", "other", "-min-unlock-epoch", "1"), servedPolicy(t, f)...), "signs the policy's override alone"},
		// re-review L-a: each clause of the override-only refusal on its own
		{"-trust-release on the override-only path, no trust base", []string{"approve", "-base", f.base, "-emergency", "x", "-emergency-item", "other", "-trust-release", trB}, "signs the policy's override alone"},
		{"-trust-base alone on the override-only path", []string{"approve", "-base", f.base, "-trust-base", tl, "-emergency", "x", "-emergency-item", "other"}, "signs the policy's override alone"},
		// re-review M1', L-b
		{"a share-set change without the trust list (its retired epochs unknown)", []string{"approve", "-base", f.base, "-share-set", set}, "-share-set and -epoch-cert need -trust-base"},
		{"-epoch-cert dropped on the machine/overlap path", append(slices.Clone(base), "-end-overlap", "-epoch-cert", filepath.Join(f.dir, "epoch-cert-1.json")), "-epoch-cert goes with the -share-set"},
		{"a version pinned already", []string{"approve", "-base", pinned, "-trust-base", tl, "-release", strings.Replace(relB, "v1.0.0", "v1.0.0", 1), "-trust-release", trB}, "is pinned already"},
		{"a pinned version removed and re-added", []string{"approve", "-base", pinned, "-remove", "v1.0.0", "-release", relB}, "is pinned already"},
		{"one compose under two versions", []string{"approve", "-base", f.base, "-trust-base", listedB, "-release", strings.Replace(relB, "v1.0.0", "v1.0.9", 1), "-trust-release", sameCompose}, "listed already as v1.0.0"},
		{"a policy-only -release whose app-compose doesn't embed its compose", []string{"approve", "-base", f.base, "-release", "app=agent-vm,version=v1.0.0,app-compose=" + noEmbed + ",compose=" + filepath.Join(f.dir, "slot-b", "compose.yaml")}, "doesn't embed its compose"},
		{"an R.json with an unknown member", append(slices.Clone(base), "-release", relB, "-trust-release", lenient), "R-lenient.json"},
		{"a share-set change under a list that retired its epoch", []string{"approve", "-base", f.base, "-trust-base", retired, "-share-set", set}, "which the trust list retired"},
	} {
		if out, errOut, err := kmsctl(t, append(c.args, "-dry-run")...); err == nil || !strings.Contains(errOut, c.want) {
			t.Errorf("%s: %v (want %q)\n%s%s", c.name, err, c.want, out, errOut)
		}
	}
}

func writeFileT(t *testing.T, path, s string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(s), 0o644); err != nil {
		t.Fatal(err)
	}
}
