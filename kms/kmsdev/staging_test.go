package kmsdev

import (
	"strings"
	"testing"

	"github.com/tacyhq/tacy/kms"
)

// A policy that lets e2e overlays in (their diag service) is a staging key service's only: a key service started
// without -staging (server.Config.Staging) refuses it, so a production policy can never carry it.
func TestAllowE2EDiagStagingOnly(t *testing.T) {
	d, err := Start(Options{})
	if err != nil {
		t.Fatal(err)
	}
	p := d.Policy
	p.Seq, p.AllowE2EDiag = p.Seq+1, true
	if _, err := d.Server.SetPolicy(ptr(d.Sign(kms.KindPolicy, p))); err == nil || !strings.Contains(err.Error(), "staging") {
		t.Fatalf("a production key service took allow_e2e_diag: %v", err)
	}
	p.AllowE2EDiag = false
	if _, err := d.Server.SetPolicy(ptr(d.Sign(kms.KindPolicy, p))); err != nil {
		t.Fatalf("the same policy without it: %v", err)
	}
}

func ptr[T any](v T) *T { return &v }
