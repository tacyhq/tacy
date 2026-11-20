package verifier

import (
	"context"
	"crypto/sha256"
	"strings"
	"testing"

	"github.com/tacyhq/tacy/release"
	"github.com/tacyhq/tacy/release/releasetest"
)

// Release mode pins the whole app-compose.json too: the one a release of the attested docker compose is deployed
// with (ReleaseAppCompose in the policy's key mode), while the bundle proves that docker compose is a signed release.
// So a VM whose CVM settings differ from the release's in any byte is refused, even with a genuinely signed compose.
// The VMs are the 0.6.4 recording made consistent with each app-compose.json (bootWith, appcompose_test.go).
func TestReleaseModeAppComposePin(t *testing.T) {
	compose := fallbackCompose(t)
	sum := sha256.Sum256(compose)
	s, err := releasetest.New()
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := s.Bundle(releasetest.Options{Version: "v0.20.0", Subjects: map[string][]byte{release.Subject: sum[:]}})
	if err != nil {
		t.Fatal(err)
	}
	// boot is a VM booted with attested(the release's app-compose.json), checked in release mode (no Compose, no
	// AppCompose: both come from the signed docker compose).
	boot := func(t *testing.T, attested func([]byte) []byte) releaseCase {
		rc := bootWith(t, compose, true, attested, keyEvent(true))
		rc.p.Compose, rc.p.AppCompose = nil, nil
		rc.p.Bundle, rc.p.Release = bundle, release.Policy{Trusted: s.Trusted()}
		return rc
	}

	rc := boot(t, nil)
	res, err := Verify(context.Background(), rc.a, rc.nonce, rc.p)
	if err != nil {
		t.Fatal(err)
	}
	ok := map[string]bool{}
	for _, c := range res.Checks {
		ok[c.Name] = c.OK
	}
	if res.Facts["release"] != "v0.20.0" || !ok[AppComposePinCheck] || !ok[AppComposeFlagsCheck] || res.Facts["key mode"] != KeyProviderKMS {
		t.Fatalf("release mode: %v %v", res.Checks, res.Facts)
	}
	want, _ := ReleaseAppCompose(compose, nil, true)
	if h := sha256.Sum256(want); res.Facts["app-compose sha256"] != strings.ToLower(hexOf(h[:])) {
		t.Fatalf("app-compose sha256 %s", res.Facts["app-compose sha256"])
	}

	for _, c := range []struct {
		name, check, want string
		edit              func([]byte) []byte
		policy            func(p *Policy)
	}{
		{"re-encoded (same settings)", AppComposePinCheck, "the release pins", edited(func(map[string]any) {}), nil},
		{"one trailing space", AppComposePinCheck, "the release pins", func(b []byte) []byte { return append(append([]byte{}, b...), ' ') }, nil},
		{"another app name", AppComposePinCheck, "the release pins", edited(func(ac map[string]any) { ac["name"] = "tacy-agent-vm-2" }), nil},
		{"storage_discard on", AppComposePinCheck, "the release pins", edited(func(ac map[string]any) { ac["storage_discard"] = true }), nil},
		{"a second port", AppComposeFlagsCheck, "want only 8080", edited(func(ac map[string]any) {
			ac["port_policy"] = map[string]any{"ports": []map[string]any{{"port": 8080, "pp": false}, {"port": 8082, "pp": false}}, "restrict_mode": true}
		}), nil},
		{"public logs", AppComposeCheck, "public_logs", edited(func(ac map[string]any) { ac["public_logs"] = true }), nil},
		{"a deployer env", AppComposeCheck, "allowed_envs must be empty", edited(func(ac map[string]any) { ac["allowed_envs"] = []string{"TINFOIL_API_KEY"} }), nil},
		{"swap", AppComposeFlagsCheck, "swap_size", edited(func(ac map[string]any) { ac["swap_size"] = "4G" }), nil},
		{"no ephemeral disk", AppComposeFlagsCheck, "ephemeral_data_disk", edited(func(ac map[string]any) { delete(ac, "requirements") }), nil},
		{"policy without the KMS fallback", KMSCheck, "", nil, func(p *Policy) { p.KMSFallback = false }},
		{"a caller's own pin is used as is", AppComposePinCheck, "the release pins", nil, func(p *Policy) {
			p.AppCompose = edited(func(ac map[string]any) { ac["name"] = "other" })(want)
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			rc := boot(t, c.edit)
			if c.policy != nil {
				c.policy(&rc.p)
			}
			res, err := Verify(context.Background(), rc.a, rc.nonce, rc.p)
			if err == nil || !strings.HasPrefix(err.Error(), c.check+": ") || !strings.Contains(err.Error(), c.want) || res.HPKEPublicKey != nil {
				t.Fatalf("%v", err)
			}
		})
	}

	// A signed release whose compose keeps data on the disk (a release from before the memory-only VM) has no
	// release app-compose.json in the KMS fallback: refused.
	disk := diskCompose(t)
	dsum := sha256.Sum256(disk)
	dbundle, err := s.Bundle(releasetest.Options{Version: "v0.20.0", Subjects: map[string][]byte{release.Subject: dsum[:]}})
	if err != nil {
		t.Fatal(err)
	}
	drc := bootWith(t, disk, false, nil, keyEvent(false))
	drc.p.Compose, drc.p.AppCompose, drc.p.KMSFallback = nil, nil, true
	drc.p.Bundle, drc.p.Release = dbundle, release.Policy{Trusted: s.Trusted()}
	if _, err := Verify(context.Background(), drc.a, drc.nonce, drc.p); err == nil || !strings.Contains(err.Error(), "no release app-compose.json") {
		t.Fatalf("disk compose: %v", err)
	}
}

func hexOf(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 2*len(b))
	for i, x := range b {
		out[2*i], out[2*i+1] = digits[x>>4], digits[x&15]
	}
	return string(out)
}
