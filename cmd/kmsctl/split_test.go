package main

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/tacyhq/tacy/kms"
	"github.com/tacyhq/tacy/kms/client"
	"github.com/tacyhq/tacy/kms/passshare"
	"github.com/tacyhq/tacy/kms/split"
	"github.com/tacyhq/tacy/kms/split/holder"
	"github.com/tacyhq/tacy/kms/split/splitdev"
	"github.com/tacyhq/tacy/safety"
)

// devGenesis writes a genesis's three passphrase shares (2 of 3) of a fresh M into dir, as kmsctl genesis does, and
// stubs the passphrase prompt with their passphrases.
func devGenesis(t *testing.T, dir string) ([]byte, ed25519.PublicKey) {
	t.Helper()
	passParams = passshare.Params{Time: 1, MemLog2: 6, Threads: 1}
	t.Cleanup(func() { passParams = passshare.Default })
	m := make([]byte, kms.MasterSize)
	rand.Read(m)
	id, _ := kms.DeriveID(m)
	pub := id.Public().(ed25519.PublicKey)
	idStr := kms.IDString(pub)
	parts, err := kms.Split(m, 3, 2, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	passes := map[string]string{}
	for _, p := range parts {
		k, _ := ecdh.P256().GenerateKey(rand.Reader)
		box, err := kms.Seal(k.PublicKey(), kms.LabelShare, kms.ShareAAD(idStr, p.X, 1), p.Y)
		if err != nil {
			t.Fatal(err)
		}
		sh := kms.SealedShare{Recipient: kms.RecipientString(k.PublicKey()), Index: p.X, Epoch: 1, KMSID: idStr, Sealed: box}
		pass := fmt.Sprintf("dev passphrase for share %d, long enough", p.X)
		ps, err := passshare.New([]byte(pass), k, sh, passParams)
		if err != nil {
			t.Fatal(err)
		}
		os.WriteFile(filepath.Join(dir, fmt.Sprintf("share-%d.pass.txt", p.X)), []byte(passshare.Armor(ps)), 0o600)
		passes[fmt.Sprintf("share %d", p.X)] = pass
	}
	readPassphrase = func(prompt string) ([]byte, error) {
		for label, p := range passes {
			if strings.Contains(prompt, label) {
				return []byte(p), nil
			}
		}
		return nil, fmt.Errorf("no passphrase for %q", prompt)
	}
	return m, pub
}

// The ceremony: two passphrase shares rebuild M, a re-split to the holders' keys writes only public and sealed files,
// and each holder's file opens with its key and combines back to the same M.
func TestResplitCeremony(t *testing.T) {
	dir := t.TempDir()
	m, pub := devGenesis(t, dir)
	got, err := combineShares([]string{filepath.Join(dir, "share-3.pass.txt"), filepath.Join(dir, "share-1.pass.txt")}, []string{"pass", "pass"})
	if err != nil || !bytes.Equal(got, m) {
		t.Fatalf("two passphrase shares: %v", err)
	}
	if _, err := combineShares([]string{filepath.Join(dir, "share-1.pass.txt"), filepath.Join(dir, "share-1.pass.txt")}, []string{"pass", "pass"}); err == nil {
		t.Fatal("one share given twice combined")
	}
	keys := map[string]*ecdh.PrivateKey{}
	var recips []split.HolderRecipient
	for _, h := range []string{"cloudflare", "vercel"} {
		priv, rcp, err := holderKeygen("x25519")
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := base64.StdEncoding.DecodeString(priv)
		k, _ := ecdh.X25519().NewPrivateKey(raw)
		if split.RecipientString(k.PublicKey()) != rcp {
			t.Fatal("holder-keygen's recipient isn't its key's")
		}
		keys[h] = k
		recips = append(recips, split.HolderRecipient{Holder: h, Recipient: rcp})
	}
	out := filepath.Join(dir, "set-2")
	if err := resplit(got, kms.IDString(pub), 1, 2, 2, recips, "agent-vm", "f_chat", time.Now(), out); err != nil {
		t.Fatal(err)
	}
	if err := resplit(got, kms.IDString(pub), 1, 2, 2, recips, "agent-vm", "f_chat", time.Now(), out); err == nil {
		t.Fatal("resplit wrote into an existing folder")
	}
	if err := resplit(got, kms.IDString(pub), 1, 1, 2, recips, "agent-vm", "f_chat", time.Now(), filepath.Join(dir, "set-1")); err == nil {
		t.Fatal("set 1 is the genesis's")
	}
	files, _ := os.ReadDir(out)
	if len(files) != 4 {
		t.Fatalf("resplit wrote %d files, want the share set, the epoch certificate and two holder shares", len(files))
	}
	var ec split.SignedEpochCert
	readJSON(filepath.Join(out, "epoch-cert-1.json"), &ec)
	cert, err := ec.Open(pub)
	if err != nil || cert.Signers["activity-sign/v1"] == "" {
		t.Fatalf("epoch certificate: %v %+v", err, cert)
	}
	var ss split.SignedShareSet
	readJSON(filepath.Join(out, "share-set-2.json"), &ss)
	set, err := ss.Open(pub)
	if err != nil || set.Threshold != 2 {
		t.Fatalf("share set: %v", err)
	}
	var parts []kms.Share
	for h, k := range keys {
		var hs split.HolderShare
		readJSON(filepath.Join(out, "holder-"+h+"-set-2.json"), &hs)
		y, err := split.OpenHolderShare(k, hs)
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range files {
			b, _ := os.ReadFile(filepath.Join(out, f.Name()))
			for _, enc := range []string{base64.StdEncoding.EncodeToString(y), base64.StdEncoding.EncodeToString(m)} {
				if strings.Contains(string(b), enc) {
					t.Fatalf("%s carries a share or M in the clear", f.Name())
				}
			}
		}
		parts = append(parts, kms.Share{X: hs.Index, Y: y})
	}
	back, _ := kms.Combine(parts)
	r1, _ := split.EpochRoot(m, 1)
	if !bytes.Equal(back, r1) || bytes.Equal(back, m) {
		t.Fatal("the holders' shares must rebuild R_1, never M")
	}
	for _, f := range files {
		b, _ := os.ReadFile(filepath.Join(out, f.Name()))
		if strings.Contains(string(b), base64.StdEncoding.EncodeToString(r1)) {
			t.Fatalf("%s carries R_1 in the clear", f.Name())
		}
	}
	// secrets-seal: under R_1, opened by R_1 only.
	sealed, err := secretsSeal(m, kms.IDString(pub), 1, 2, map[string]string{"EXA_API_KEY": "exa-test"})
	if err != nil {
		t.Fatal(err)
	}
	if b, err := split.OpenSecrets(r1, kms.IDString(pub), 1, sealed); err != nil || b.Values["EXA_API_KEY"] != "exa-test" || b.Seq != 2 {
		t.Fatalf("secrets: %v", err)
	}
}

// approve: the next policy and trust list change together and are signed; a holder takes the policy.
func TestApprove(t *testing.T) {
	now := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	d, err := splitdev.New([]string{"cloudflare", "vercel"}, 2, now.Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	d.AddRelease("v0.21.0", strings.Repeat("a", 64), "")
	dir := t.TempDir()
	ac, cy := filepath.Join(dir, "app-compose.json"), filepath.Join(dir, "compose.yaml")
	os.WriteFile(ac, []byte(`{"name":"agent-vm"}`), 0o644)
	os.WriteFile(cy, []byte("services: {}\n"), 0o644)
	tl := &safety.TrustList{Type: safety.TrustListType, Seq: 3, IssuedAt: now.Add(-24 * time.Hour), Expires: now.Add(89 * 24 * time.Hour),
		Releases: []safety.TrustRelease{{Version: "v0.21.0", Commit: strings.Repeat("1", 40), ComposeSHA256: strings.Repeat("2", 64), Bundle: []byte(`{}`)}}}
	entry := &safety.TrustRelease{Version: "v0.22.0", Commit: strings.Repeat("3", 40), ComposeSHA256: fileSHA256(cy), Bundle: []byte(`{}`)}
	add := releaseSpec{App: splitdev.App, Version: "v0.22.0", AppCompose: ac, Compose: cy}

	grace, err := parseTCBGrace("until=2026-11-27T00:00:00Z,statuses=OutOfDate+ConfigurationNeeded,min-tcb-date=2025-01-01")
	if err != nil {
		t.Fatal(err)
	}
	np, ntl, err := approve(d.Policy, tl, []releaseSpec{add}, []string{"v0.21.0"}, entry, nil, nil, grace, now)
	if err != nil {
		t.Fatal(err)
	}
	if np.Seq != d.Policy.Seq+1 || len(np.Releases) != 1 || np.Releases[0].Version != "v0.22.0" || np.Releases[0].AppComposeSHA256 != fileSHA256(ac) {
		t.Fatalf("policy: %+v", np.Releases)
	}
	if ntl.Seq != 4 || len(ntl.Releases) != 1 || ntl.Releases[0].Version != "v0.22.0" || !ntl.Expires.IsZero() {
		t.Fatalf("trust list: %+v", ntl)
	}
	if len(d.Policy.Releases) != 1 || d.Policy.Releases[0].Version != "v0.21.0" {
		t.Fatal("approve changed its input")
	}
	if !slices.Contains(ntl.RevokedReleases, "v0.21.0") {
		t.Fatalf("the withdrawn release should be revoked in the trust list too: %v", ntl.RevokedReleases)
	}
	if np.TCBGrace == nil || ntl.TCBGrace == nil || ntl.TCBGrace.Until != np.TCBGrace.Until || len(ntl.TCBGrace.Statuses) != 2 {
		t.Fatal("the grace should be in both documents")
	}
	if _, err := parseTCBGrace("until=2026-11-27T00:00:00Z,statuses=Revoked"); err == nil {
		if _, _, err := approve(d.Policy, nil, nil, nil, nil, nil, nil, &safety.TCBGrace{Until: now.Add(time.Hour), Statuses: []string{"Revoked"}}, now); err == nil {
			t.Fatal("a grace for Revoked")
		}
	}
	// Refusals: nothing to do, an unknown removal, a trust entry for another release or another compose.
	if _, _, err := approve(d.Policy, nil, nil, nil, nil, nil, nil, nil, now); err == nil {
		t.Fatal("approve with nothing to change")
	}
	if _, _, err := approve(d.Policy, nil, nil, []string{"v9.9.9"}, nil, nil, nil, nil, now); err == nil {
		t.Fatal("removed a release that isn't pinned")
	}
	other := *entry
	other.ComposeSHA256 = strings.Repeat("4", 64)
	if _, _, err := approve(d.Policy, tl, []releaseSpec{add}, nil, &other, nil, nil, nil, now); err == nil {
		t.Fatal("a trust entry for another compose")
	}
	if _, _, err := approve(d.Policy, tl, []releaseSpec{add}, nil, nil, nil, nil, nil, now); err == nil {
		t.Fatal("a release added to the trust list without its entry")
	}

	// Signed and written; a holder takes the new policy and refuses the old one from then on.
	out := filepath.Join(dir, "approved")
	_, trustKey, _ := ed25519.GenerateKey(rand.Reader)
	if err := writeApproved(out, np, ntl, []ed25519.PrivateKey{d.Admin}, []ed25519.PrivateKey{trustKey}); err != nil {
		t.Fatal(err)
	}
	if err := writeApproved(out, np, ntl, []ed25519.PrivateKey{d.Admin}, []ed25519.PrivateKey{trustKey}); err == nil {
		t.Fatal("approve wrote into an existing folder")
	}
	pol := readFile(filepath.Join(out, fmt.Sprintf("unlock-policy-%d.signed.json", np.Seq)))
	var tenv safety.Envelope
	readJSON(filepath.Join(out, "trust-list-4.signed.json"), &tenv)
	if _, err := safety.VerifyTrustList(&tenv, []ed25519.PublicKey{trustKey.Public().(ed25519.PublicKey)}, 1, 4, now); err != nil {
		t.Fatalf("trust list: %v", err)
	}
	hc := d.HolderConfig("vercel")
	hc.Now = func() time.Time { return now }
	h, err := holder.New(hc)
	if err != nil {
		t.Fatal(err)
	}
	if seq, err := h.PushPolicy(context.Background(), pol); err != nil || seq != np.Seq {
		t.Fatalf("holder push: %d %v", seq, err)
	}
	old, _ := d.SignPolicy()
	if _, err := h.PushPolicy(context.Background(), old); err == nil {
		t.Fatal("the holder took the older policy after the newer")
	}
}

// unlock-policy from a base: holders, share sets and the break-glass relay replaced, checked as a whole.
func TestUnlockPolicyBuild(t *testing.T) {
	now := time.Now().UTC()
	d, _ := splitdev.New([]string{"cloudflare", "vercel"}, 2, now)
	dir := t.TempDir()
	base := filepath.Join(dir, "base.json")
	b, _ := json.Marshal(d.Policy)
	os.WriteFile(base, b, 0o644)
	set := filepath.Join(dir, "share-set-2.json")
	sb, _ := json.Marshal(d.Set)
	os.WriteFile(set, sb, 0o644)
	p, err := unlockPolicy(base, "", "", 7, "v0.21.0", "cloudflare=https://keys-cf.tacy.io,vercel=https://keys-v.tacy.io", []string{set}, nil,
		"https://keys-cf.tacy.io/break-glass", now, kms.AdminKeys{})
	if err != nil {
		t.Fatal(err)
	}
	if p.Seq != 7 || p.Floor != "v0.21.0" || len(p.Holders) != 2 || p.Holders[1].URL != "https://keys-v.tacy.io" || p.BreakGlass == "" {
		t.Fatalf("policy: %+v", p)
	}
	if _, err := unlockPolicy(base, "", "", 7, "", "cloudflare=http://insecure", nil, nil, "", now, kms.AdminKeys{}); err == nil {
		t.Fatal("a plain-http holder URL")
	}
}

// split-dev writes the staging files into a new folder only, the dev secrets 0600.
func TestSplitDevFiles(t *testing.T) {
	d, err := splitdev.New([]string{"cloudflare", "vercel"}, 2, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "staging")
	if err := writeSplitDev(d, out); err != nil {
		t.Fatal(err)
	}
	if err := writeSplitDev(d, out); err == nil {
		t.Fatal("wrote into an existing folder")
	}
	k, err := readHolderKey(filepath.Join(out, "dev-holder-vercel.key"))
	if err != nil || !k.Equal(d.Keys["vercel"]) {
		t.Fatalf("holder key: %v", err)
	}
	st, _ := os.Stat(filepath.Join(out, "dev-master.key"))
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("dev-master.key is %v", st.Mode().Perm())
	}
}

// holder-push's first step: the Worker takes the policy and a VM's fetch returns its seq, or nothing is pushed.
func TestPushWorkerFirst(t *testing.T) {
	d, _ := splitdev.New([]string{"cloudflare", "vercel"}, 2, time.Now())
	env, _ := d.SignPolicy()
	var served []byte
	stale := false
	w := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		if r.URL.Path != unlockPolicyPath {
			rw.WriteHeader(http.StatusNotFound)
			return
		}
		if r.Method == "POST" {
			b, _ := io.ReadAll(r.Body)
			if !stale {
				served = b
			}
			rw.Write([]byte("{}"))
			return
		}
		rw.Write(served)
	}))
	defer w.Close()
	if err := pushWorker(context.Background(), client.HTTP{Base: w.URL}, env, d.Policy.Seq); err != nil {
		t.Fatal(err)
	}
	stale = true // a Worker that keeps serving the old policy
	d.Policy.Seq++
	newer, _ := d.SignPolicy()
	if err := pushWorker(context.Background(), client.HTTP{Base: w.URL}, newer, d.Policy.Seq); err == nil || !strings.Contains(err.Error(), "returns policy seq 1, not 2") {
		t.Fatalf("a Worker that didn't take it: %v", err)
	}
}

// approve -emergency: the override names the new seq and the added release, signed by the KMS id (M from the
// shares); a later approve drops it.
func TestApproveEmergency(t *testing.T) {
	now := time.Now().UTC()
	d, _ := splitdev.New([]string{"cloudflare", "vercel"}, 2, now.Add(-time.Hour))
	dir := t.TempDir()
	ac := filepath.Join(dir, "app-compose.json")
	os.WriteFile(ac, []byte(`{"name":"agent-vm","fix":true}`), 0o644)
	add := releaseSpec{App: splitdev.App, Version: "v0.22.1", AppCompose: ac}
	np, _, err := approve(d.Policy, nil, []releaseSpec{add}, nil, nil, nil, nil, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := attachEmergency(np, d.Master, []releaseSpec{add}, nil, "CVE fix", now); err != nil {
		t.Fatal(err)
	}
	em, err := np.Emergency.Open(d.IDPub, np)
	if err != nil || em.PolicySeq != np.Seq || len(em.Items) != 1 || !strings.HasPrefix(em.Items[0], split.ItemRelease) {
		t.Fatalf("override: %v %+v", err, em)
	}
	other := make([]byte, kms.MasterSize)
	rand.Read(other)
	if err := attachEmergency(np, other, []releaseSpec{add}, nil, "x", now); err == nil {
		t.Fatal("an override from another M")
	}
	next, _, err := approve(*np, nil, nil, []string{"v0.22.1"}, nil, nil, nil, nil, now)
	if err != nil || next.Emergency != nil {
		t.Fatalf("the next approve should drop the override: %v", err)
	}
}

// approve -emergency -emergency-item: a fresh holder has seen every item of its first policy for less than 24 h, not
// only the release, so the override may name others: "other" is the catch-all item (OtherItem), which every VM relies
// on. An item the new policy doesn't have is refused here, before anything is signed.
func TestApproveEmergencyItems(t *testing.T) {
	now := time.Now().UTC()
	d, _ := splitdev.New([]string{"cloudflare", "vercel"}, 2, now.Add(-time.Hour))
	dir := t.TempDir()
	ac := filepath.Join(dir, "app-compose.json")
	os.WriteFile(ac, []byte(`{"name":"agent-vm","first":true}`), 0o644)
	add := releaseSpec{App: splitdev.App, Version: "v0.22.1", AppCompose: ac}
	np, _, err := approve(d.Policy, nil, []releaseSpec{add}, nil, nil, nil, nil, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := attachEmergency(np, d.Master, []releaseSpec{add}, []string{"other", "other"}, "first deploy", now); err != nil {
		t.Fatal(err)
	}
	em, err := np.Emergency.Open(d.IDPub, np)
	if err != nil || len(em.Items) != 2 || em.Items[0] != split.OtherItem(np) || !strings.HasPrefix(em.Items[1], split.ItemRelease) {
		t.Fatalf("override: %v %+v", err, em)
	}
	// Only the catch-all, no release added: allowed (an expedited change to the other fields).
	np2, _, _ := approve(d.Policy, nil, []releaseSpec{add}, nil, nil, nil, nil, nil, now)
	if err := attachEmergency(np2, d.Master, nil, []string{"other"}, "x", now); err != nil {
		t.Fatal(err)
	}
	if err := attachEmergency(np2, d.Master, nil, []string{split.ItemOS + "deadbeef"}, "x", now); err == nil || !strings.Contains(err.Error(), "isn't an item") {
		t.Fatalf("an item the policy doesn't have: %v", err)
	}
	if err := attachEmergency(np2, d.Master, nil, nil, "x", now); err == nil {
		t.Fatal("an override naming nothing")
	}
	// A release pinned earlier, normally: the next seq with the override alone, naming it by version.
	if !expediteOnly("fix", []string{"release:v0.22.1"}, nil, nil, nil, nil) || expediteOnly("fix", nil, nil, nil, nil, nil) ||
		expediteOnly("", []string{"other"}, nil, nil, nil, nil) || expediteOnly("fix", []string{"other"}, []releaseSpec{add}, nil, nil, nil) {
		t.Fatal("expediteOnly")
	}
	np3, err := nextSeq(*np2, now)
	if err != nil || np3.Seq != np2.Seq+1 || np3.Emergency != nil || len(np3.Releases) != len(np2.Releases) {
		t.Fatalf("nextSeq: %v", err)
	}
	if err := attachEmergency(np3, d.Master, nil, []string{"release:v0.22.1"}, "pinned earlier", now); err != nil {
		t.Fatal(err)
	}
	em3, err := np3.Emergency.Open(d.IDPub, np3)
	if err != nil || len(em3.Items) != 1 || em3.Items[0] != split.ReleaseItem(np3.Releases[len(np3.Releases)-1]) {
		t.Fatalf("%v %+v", err, em3)
	}
	if err := attachEmergency(np3, d.Master, nil, []string{"release:v9.9.9"}, "x", now); err == nil {
		t.Fatal("a version that isn't pinned")
	}
}

// Review M2: from kms.KMSFallbackRemoveBy on, kmsctl signs no policy that still has the KMS fallback (approve, and
// through checkUnlockPolicy unlock-policy and sign); before it, and without the flag after it, nothing changes.
func TestApproveKMSFallbackRemovalDate(t *testing.T) {
	for _, c := range []struct {
		name     string
		at       time.Time
		fallback bool
		ok       bool
	}{
		{"before the date, flag on", kms.KMSFallbackRemoveBy.Add(-time.Hour), true, true},
		{"on the date, flag on", kms.KMSFallbackRemoveBy, true, false},
		{"after the date, flag on", kms.KMSFallbackRemoveBy.Add(24 * time.Hour), true, false},
		{"after the date, flag off", kms.KMSFallbackRemoveBy.Add(24 * time.Hour), false, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			d, err := splitdev.New([]string{"cloudflare", "vercel"}, 2, c.at.Add(-time.Hour))
			if err != nil {
				t.Fatal(err)
			}
			d.Policy.KMSFallback = c.fallback
			ac := filepath.Join(t.TempDir(), "app-compose.json")
			os.WriteFile(ac, []byte(`{"name":"agent-vm"}`), 0o644)
			_, _, err = approve(d.Policy, nil, []releaseSpec{{App: splitdev.App, Version: "v0.22.0", AppCompose: ac}}, nil, nil, nil, nil, nil, c.at)
			if c.ok && err != nil {
				t.Fatal(err)
			}
			if !c.ok && (err == nil || !strings.Contains(err.Error(), "kms_fallback is still on")) {
				t.Fatalf("approved: %v", err)
			}
		})
	}
}

// approve -emergency with a trust list: the clients' override (the trust list's optional "emergency" member) names
// the trust-list entry of the release added, signed by the KMS id M derives; it opens only for that list and only
// against that KMS id; the next approve drops it (a stale one would make clients refuse the whole list).
func TestApproveTrustEmergency(t *testing.T) {
	now := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	d, err := splitdev.New([]string{"cloudflare", "vercel"}, 2, now.Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	ac, cy := filepath.Join(dir, "app-compose.json"), filepath.Join(dir, "compose.yaml")
	os.WriteFile(ac, []byte(`{"name":"agent-vm","fix":true}`), 0o644)
	os.WriteFile(cy, []byte("services: {}\n"), 0o644)
	tl := &safety.TrustList{Type: safety.TrustListType, Seq: 3, IssuedAt: now.Add(-24 * time.Hour),
		OSImages: map[string]string{strings.Repeat("c", 64): "dstack-0.6.9 (test)"}}
	entry := &safety.TrustRelease{Version: "v0.22.1", Commit: strings.Repeat("3", 40), ComposeSHA256: fileSHA256(cy), Bundle: []byte(`{}`)}
	add := releaseSpec{App: splitdev.App, Version: "v0.22.1", AppCompose: ac, Compose: cy}
	np, ntl, err := approve(d.Policy, tl, []releaseSpec{add}, nil, entry, nil, nil, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := attachEmergency(np, d.Master, []releaseSpec{add}, nil, "CVE fix", now); err != nil {
		t.Fatal(err)
	}
	if err := attachTrustEmergency(ntl, d.Master, np.KMSID, []releaseSpec{add}, nil, "CVE fix", now); err != nil {
		t.Fatal(err)
	}
	em, err := ntl.OpenEmergency(d.IDPub)
	if err != nil || em.ListSeq != ntl.Seq || len(em.Items) != 1 || em.Items[0] != safety.TrustReleaseItem(*entry) || em.Reason != "CVE fix" {
		t.Fatalf("trust override: %v %+v", err, em)
	}
	_, stranger, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := ntl.OpenEmergency(stranger.Public().(ed25519.PublicKey)); err == nil {
		t.Fatal("the override opened against another KMS id")
	}
	// The policy's override doesn't open as the trust list's (separate labels).
	pe := safety.TrustList(*ntl)
	pe.Optional = maps.Clone(ntl.Optional)
	pol, _ := json.Marshal(np.Emergency)
	pe.Optional[safety.TrustEmergencyMember] = pol
	if _, err := pe.OpenEmergency(d.IDPub); err == nil {
		t.Fatal("the unlock policy's override opened as the trust list's")
	}
	// Another M: refused.
	other := make([]byte, kms.MasterSize)
	rand.Read(other)
	if err := attachTrustEmergency(ntl, other, np.KMSID, []releaseSpec{add}, nil, "x", now); err == nil {
		t.Fatal("a trust override from another M")
	}
	// The next approve drops it.
	_, ntl2, err := approve(*np, ntl, nil, []string{"v0.22.1"}, nil, nil, nil, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := ntl2.Optional[safety.TrustEmergencyMember]; ok {
		t.Fatal("the next trust list kept the override")
	}
	if _, ok := ntl.Optional[safety.TrustEmergencyMember]; !ok {
		t.Fatal("approve changed its input")
	}
}

// secrets-push: the sealed bundle in a kms-unlock-secrets envelope the kms-admin key signed, at the route unlockd
// fetches it from; anything but a sealed bundle is refused before it leaves.
func TestSecretsEnvelope(t *testing.T) {
	_, k, _ := ed25519.GenerateKey(rand.Reader)
	sealed := append([]byte("TACYSECRETS1"), make([]byte, 40)...)
	raw, err := secretsEnvelope(sealed, []ed25519.PrivateKey{k})
	if err != nil {
		t.Fatal(err)
	}
	var env safety.Envelope
	if err := json.Unmarshal(raw, &env); err != nil || env.Kind != KindUnlockSecrets {
		t.Fatalf("envelope: %v %+v", err, env)
	}
	var p struct {
		Sealed []byte `json:"sealed"`
	}
	if err := (kms.AdminKeys{Keys: []ed25519.PublicKey{k.Public().(ed25519.PublicKey)}, Threshold: 1}).Open(&env, KindUnlockSecrets, &p); err != nil || !bytes.Equal(p.Sealed, sealed) {
		t.Fatalf("open: %v", err)
	}
	if _, err := secretsEnvelope([]byte(`{"EXA_API_KEY":"plain"}`), []ed25519.PrivateKey{k}); err == nil {
		t.Fatal("a plain file pushed as a sealed bundle")
	}
	if unlockSecretsPath != "/api/vm/unlock-secrets" {
		t.Fatal(unlockSecretsPath)
	}
}
