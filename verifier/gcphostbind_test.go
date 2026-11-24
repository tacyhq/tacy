package verifier

import (
	"context"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/tacyhq/tacy/internal/tdx"
	"github.com/tacyhq/tacy/safety"
)

type registryStub struct{ asked int }

func (r *registryStub) Get(string) (map[string][]string, []byte, error) {
	r.asked++
	return nil, []byte(`{"timestamp":"2026-11-20T21:53:55Z","zone":"us-central1-a"}`), nil
}

// gcp-host review M1: a quote on a Phala boot set from a machine that only a Google certificate (registry mode here)
// allows is refused at the machine check: the host can't boot a Phala-shaped chain on a registry-listed machine and
// pass with no Google check and no dstack-gcp item for the holders' delay. Nothing is fetched from Google's registry.
// (The reviewer's probe passed the machine check before the fix: "gcp c3 (registry) …; host Google".)
func TestGoogleCertRefusedOnPhalaBoot(t *testing.T) {
	c := recordedCollateral(t)
	a, nonce, attested, compose := loadNone(t, "attest-065-none.json")
	const project, instance, zone = "635557987033", "4815162342", "us-central1-a"
	digest := sha512.Sum384([]byte(fmt.Sprintf(`{"instanceId":%s,"numericalProjectId":%s,"zone":"%s"}`, instance, project, zone)))
	googlePPID := "074d04cd17d469b6f0ebf06230e536b0"
	full := func(ctx context.Context, b []byte) (*tdx.Quote, error) {
		q, err := tdx.VerifyWith(ctx, b, tdx.Options{Getter: c, Now: collateralNow})
		if q != nil {
			q.PPID, q.FMSPC, q.MrOwner = googlePPID, "00806f050000", hex.EncodeToString(digest[:])
		}
		return q, err
	}
	var info map[string]any
	json.Unmarshal(a.Info, &info)
	info["gce_instance_id"], info["gce_zone"] = instance, zone
	a.Info, _ = json.Marshal(info)
	for name, doc := range map[string]safety.MachineDoc{
		"registry": {Type: safety.MachineType, Platform: "dstack", Host: safety.MachineHostGoogle, Mode: safety.MachineModeRegistry,
			FMSPC: "00806f050000", ProjectNumber: project, Label: "gcp c3 (registry)"},
		"one Google host": {Type: safety.MachineType, Platform: "dstack", Host: safety.MachineHostGoogle, Mode: safety.MachineModePPID,
			PPID: googlePPID, FMSPC: "00806f050000", Label: "gcp one host"},
	} {
		h, _ := safety.MachineDocHash(doc)
		g := &registryStub{}
		for _, gcp := range []bool{false, true} {
			p := Policy{AllowStaleTCB: true, Compose: []byte(compose), AppCompose: []byte(attested), VerifyQuote: full, GoogleGetter: g,
				Machines: &safety.MachineSet{Machines: []safety.Machine{{Doc: doc, Hash: h, Source: "test"}}, Revoked: map[string]bool{}}}
			if gcp {
				p = p.WithGCP()
			}
			res, err := Verify(context.Background(), a, nonce, p)
			if err == nil || !strings.Contains(err.Error(), "machine") || res.Facts[FactMachine] != "" || res.Facts[FactMachineHost] != "" || g.asked != 0 {
				t.Fatalf("%s (WithGCP %v): %v, machine %q, host %q, %d registry fetches", name, gcp, err, res.Facts[FactMachine], res.Facts[FactMachineHost], g.asked)
			}
		}
	}
}

// The mirror: a genuine Google Cloud quote whose PPID only a Phala certificate names is refused at the machine check;
// with its Google certificate it passes and says host google (what the holders' dstack-gcp item keys on).
func TestPhalaCertRefusedOnGCPBoot(t *testing.T) {
	name := gcpRecordings[0]
	a, nonce, p, _ := gcpPolicy(t, name)
	set := gcpMachines(t)
	res, err := Verify(context.Background(), a, nonce, p)
	if err != nil || res.Facts[FactMachineHost] != safety.MachineHostGoogle {
		t.Fatalf("Google certificate: %v, host %q", err, res.Facts[FactMachineHost])
	}
	phala := &safety.MachineSet{Revoked: map[string]bool{}}
	for _, m := range set.Machines {
		m.Doc.Host = safety.MachineHostPhala
		phala.Machines = append(phala.Machines, m)
	}
	p.Machines = phala
	res, err = Verify(context.Background(), a, nonce, p)
	if err == nil || !strings.Contains(err.Error(), "on a Google Cloud boot set") || res.Facts[FactMachine] != "" {
		t.Fatalf("Phala certificate on a Google boot: %v", err)
	}
}
