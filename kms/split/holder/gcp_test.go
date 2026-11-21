package holder

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/tacyhq/tacy/kms"
	"github.com/tacyhq/tacy/kms/server"
	"github.com/tacyhq/tacy/verifier"
)

// The Google Cloud fallback is off unless the signed unlock policy names dstack-gcp beside dstack (vm-v1; it replaced
// branch cfd-google's staging-only HOLDER_GCP=1): the holder's check gets GCP only then, and a VM that passed by a
// Google Cloud set relies on the policy's dstack-gcp item, so it unlocks only once that item is past the pin delay.
// The recorded quote is Phala's, so a Google Cloud match is simulated by the fact the verifier sets for one.
func TestGCPOnlyBySignedPolicy(t *testing.T) {
	r := newRig(t, twoOfTwo, 2)
	var sawGCP []bool
	gcpQuote := false
	plat := func(ctx context.Context, att json.RawMessage, bound []byte, pol *kms.Policy, o server.CheckOptions) (*server.Attested, error) {
		sawGCP = append(sawGCP, o.GCP)
		a, err := Dstack(ctx, att, bound, pol, o)
		if err == nil && gcpQuote {
			a.Facts[verifier.FactPlatformSet] = verifier.PlatformDstackGCP
		}
		return a, err
	}
	for _, h := range r.ids {
		r.holders[h] = r.newHolder(h, func(c *Config) {
			c.NoPinDelay = false
			c.Platforms = map[string]Platform{"dstack": plat}
		})
	}
	unlockOK := func(what string) {
		t.Helper()
		if _, rep, err := r.unlock(r.transports(nil), nil); err != nil {
			t.Fatalf("%s: %v %v", what, err, rep.Outcome)
		}
	}
	refused := func(what, want string) {
		t.Helper()
		if _, rep, err := r.unlock(r.transports(nil), nil); err == nil || !strings.Contains(rep.Outcome["cloudflare"], want) {
			t.Fatalf("%s: %v %v (want %q)", what, err, rep.Outcome, want)
		}
	}
	gcpAsked := func() bool {
		defer func() { sawGCP = nil }()
		for _, g := range sawGCP {
			if g {
				return true
			}
		}
		return false
	}

	// A policy naming only dstack: GCP is never asked for, and a Google Cloud match isn't in the policy at all.
	r.pol.Platforms = []string{"dstack"}
	refused("the new release", "was first allowed here at")
	r.advance(24*time.Hour + time.Minute)
	unlockOK("Phala, dstack only")
	if gcpAsked() {
		t.Fatal("GCP asked for under a policy without dstack-gcp")
	}
	gcpQuote = true
	refused("a Google Cloud set under a dstack-only policy", "platform:"+verifier.PlatformDstackGCP+" isn't in this holder's record")
	gcpQuote = false

	// The admin signs dstack-gcp in: Phala unlocks at once (nothing it relies on changed); Google waits 24 h.
	r.pol.Seq++
	r.pol.Platforms = []string{"dstack", verifier.PlatformDstackGCP}
	unlockOK("Phala after dstack-gcp was added")
	if !gcpAsked() {
		t.Fatal("GCP not asked for under a policy naming dstack-gcp")
	}
	gcpQuote = true
	refused("Google Cloud within the pin delay", "first allowed here at")
	r.advance(24*time.Hour + time.Minute)
	unlockOK("Google Cloud after the pin delay")
	if !gcpAsked() {
		t.Fatal("GCP not asked for on the Google Cloud unlock")
	}

	// Withdrawn by a newer policy: at once.
	r.pol.Seq++
	r.pol.Platforms = []string{"dstack"}
	refused("Google Cloud after the withdrawal", "isn't in this holder's record")
	gcpQuote = false
	unlockOK("Phala after the withdrawal")
	if gcpAsked() {
		t.Fatal("GCP asked for after dstack-gcp was withdrawn")
	}
}
