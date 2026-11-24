package main

import (
	"slices"
	"testing"
	"time"

	"github.com/tacyhq/tacy/kms/split"
	"github.com/tacyhq/tacy/kms/split/splitdev"
	"github.com/tacyhq/tacy/safety"
	"github.com/tacyhq/tacy/verifier"
)

// approve -add-platform/-remove-platform: dstack-gcp on in both documents (with registry certificates valid beside
// it), off again (the registry certificates leave with it); nothing else accepted.
func TestChangePlatforms(t *testing.T) {
	d, err := splitdev.New([]string{"cloudflare"}, 1, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	p := d.Policy
	tl := &safety.TrustList{}
	if err := changePlatforms(&p, tl, []string{verifier.PlatformDstackGCP}, nil); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(p.Platforms, []string{"dstack", "dstack-gcp"}) || !slices.Equal(tl.Platforms, []string{"dstack", "dstack-gcp"}) {
		t.Fatalf("%v %v", p.Platforms, tl.Platforms)
	}
	doc := safety.MachineDoc{Type: safety.MachineType, KMSID: d.KMSID, Platform: safety.PlatformDstack, Host: "google",
		Mode: safety.MachineModeRegistry, FMSPC: "00806f050000", ProjectNumber: "635557987033", Label: "gcp c3 test", IssuedAt: time.Now().UTC()}
	c, err := split.NewMachineCert(d.Master, d.KMSID, doc)
	if err != nil {
		t.Fatal(err)
	}
	n := len(p.MachineCerts)
	p.MachineCerts = append(p.MachineCerts, *c)
	if err := changePlatforms(&p, tl, nil, []string{verifier.PlatformDstackGCP}); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(p.Platforms, []string{"dstack"}) || len(p.MachineCerts) != n {
		t.Fatalf("after removal: %v, %d certificates", p.Platforms, len(p.MachineCerts))
	}
	for _, bad := range [][2][]string{{{"dstack"}, nil}, {nil, {"dstack"}}, {{"dstack-aws"}, nil}, {{"dstack-gcp"}, {"dstack-gcp"}}} {
		q := d.Policy
		if err := changePlatforms(&q, nil, bad[0], bad[1]); err == nil {
			t.Errorf("%v passed", bad)
		}
	}
}
