package verifier

import (
	"context"
	"crypto/sha256"
	"strings"
	"testing"
	"time"

	"github.com/tacyhq/tacy/internal/tdx"
	"github.com/tacyhq/tacy/release"
	"github.com/tacyhq/tacy/release/releasetest"
)

// Release mode in a Fix B build (KMSFallback off, as the browser's, the apps' and the chat Worker's WebAssembly): the
// recorded v0.20.0 VM (testdata/attest-r0200.json, overlap_test.go) passes with a bundle for its compose signed as
// v0.20.0, by its exact pins; the same compose signed as another version, the same compose under another app-compose
// (r0200-inplace), or a KMS-mode Fix B compose are refused. The overlap needs a signed trust list in force (overlap.go):
// with none, the same bundle and quote are refused. The bundles are the test signer's (releasetest), so only the
// signature's root differs from production's.
func TestReleaseModeOverlap(t *testing.T) {
	s, err := releasetest.New()
	if err != nil {
		t.Fatal(err)
	}
	sign := func(t *testing.T, compose, version string) []byte {
		t.Helper()
		sum := sha256.Sum256([]byte(compose))
		b, err := s.Bundle(releasetest.Options{Version: version, Subjects: map[string][]byte{release.Subject: sum[:]}})
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	bare := func(r r0200Rec, bundle []byte) Policy {
		return Policy{VerifyQuote: r.vq, Bundle: bundle, Release: release.Policy{Trusted: s.Trusted()}, Now: r0200Now}
	}
	policy := func(r r0200Rec, bundle []byte) Policy { return listed(t, bare(r, bundle), r0200Now) }

	r := loadR0200(t, "r0200", r0200Now)
	// No trust list in force (a fresh install, a list withheld or refused): refused, fail closed.
	if _, err := Verify(context.Background(), r.a, r.nonce, bare(r, sign(t, r.compose, "v0.20.0"))); err == nil || !strings.HasPrefix(err.Error(), KMSCheck+": ") ||
		!strings.Contains(err.Error(), "only while a signed trust list is in force") {
		t.Fatalf("release mode, no list: %v", err)
	}
	r = loadR0200(t, "r0200", r0200Now)
	res, err := Verify(context.Background(), r.a, r.nonce, policy(r, sign(t, r.compose, "v0.20.0")))
	if err != nil {
		t.Fatal(err)
	}
	if res.Facts["release"] != "v0.20.0" || res.Facts["key mode"] != KeyProviderKMS || !strings.HasPrefix(res.Facts[KMSOverlapFact], "v0.20.0 ") ||
		res.Facts["app-compose sha256"] != KMSOverlapReleases[0].AppComposeSHA256 {
		t.Fatalf("facts %v", res.Facts)
	}
	for _, c := range res.Checks {
		if !c.OK {
			t.Fatalf("check %q failed", c.Name)
		}
	}

	// Without the overlap entry: refused at the key check, as the vm-v1 verifier did.
	saved := KMSOverlapReleases
	KMSOverlapReleases = nil
	r = loadR0200(t, "r0200", r0200Now)
	_, err = Verify(context.Background(), r.a, r.nonce, policy(r, sign(t, r.compose, "v0.20.0")))
	KMSOverlapReleases = saved
	if err == nil || !strings.HasPrefix(err.Error(), KMSCheck+": ") || !strings.Contains(err.Error(), "accepted only as a pinned KMS overlap release") {
		t.Fatalf("no overlap: %v", err)
	}

	cases := []struct {
		name, check, want string
		run               func(t *testing.T) (r0200Rec, Policy)
	}{
		{"the overlap compose signed as another version", "docker compose is a signed release", "the overlap pins v0.20.0", func(t *testing.T) (r0200Rec, Policy) {
			r := loadR0200(t, "r0200", r0200Now)
			return r, policy(r, sign(t, r.compose, "v0.21.0"))
		}},
		{"the overlap compose under another KMS app-compose", AppComposeCheck, "deployer may set env", func(t *testing.T) (r0200Rec, Policy) {
			r := loadR0200(t, "r0200-inplace", time.Date(2026, 11, 20, 3, 1, 51, 0, time.UTC))
			return r, policy(r, sign(t, r.compose, "v0.20.0"))
		}},
		{"the overlap release on the removal date", KMSCheck, "accepted only until 2027-01-15", func(t *testing.T) (r0200Rec, Policy) {
			r := loadR0200(t, "r0200", r0200Now)
			p := policy(r, sign(t, r.compose, "v0.20.0"))
			p.Now = KMSOverlapUntil
			return r, p
		}},
		{"a key-releasing verifier in release mode", KMSCheck, "allowed only in the explicit KMS fallback", func(t *testing.T) (r0200Rec, Policy) {
			r := loadR0200(t, "r0200", r0200Now)
			p := policy(r, sign(t, r.compose, "v0.20.0"))
			p.KeyRelease = true
			return r, p
		}},
		{"the Fix B compose in the KMS mode, signed", KMSCheck, `key provider "kms", want none`, func(t *testing.T) (r0200Rec, Policy) {
			compose := composeYAML(t)
			kmsForm, err := appComposeJSON(compose, []byte(MemoryRootScript), true, AppComposeName)
			if err != nil {
				t.Fatal(err)
			}
			r := loadR0200(t, "r0200", r0200Now)
			setAppComposeRaw(t, r.a, kmsForm)
			rt := recompose(t, r.a, kmsForm)
			rd := agentLabel(t, r.a, r.nonce, true)
			p := policy(r, sign(t, string(compose), "v1.0.0"))
			p.VerifyQuote, p.AllowStaleTCB = changeQuote(func(q *tdx.Quote) { q.Rtmrs[3], q.ReportData = rt, rd }), true
			return r, p
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r, p := c.run(t)
			res, err := Verify(context.Background(), r.a, r.nonce, p)
			if err == nil || !strings.HasPrefix(err.Error(), c.check) || !strings.Contains(err.Error(), c.want) || res.HPKEPublicKey != nil {
				t.Fatalf("want %s (%s): %v", c.check, c.want, err)
			}
		})
	}
}
