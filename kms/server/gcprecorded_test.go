package server

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/tacyhq/tacy/internal/gcetcb"
	"github.com/tacyhq/tacy/internal/tdx"
	"github.com/tacyhq/tacy/kms"
	"github.com/tacyhq/tacy/proto"
	"github.com/tacyhq/tacy/safety"
	"github.com/tacyhq/tacy/verifier"
)

// The key holders' own check (holder.Dstack is VerifyVM) on genuine Google Cloud quotes, one per pinned shape:
// c3-standard-4 and c4-standard-2 (dstack 0.6.6, key provider none; recorded 2026-11-21, testdata gcp-066-*). With
// GCP on (a holder sets it only when the signed unlock policy names dstack-gcp) and a machine certificate for the
// quote's platform, the quote passes and is reported as the shape's Google set; with GCP off, or without the
// machine, it is refused. The recordings are a small test app, not the agent VM, so RequireUnlockd is off here (the
// agent VM's unlockd rule is the same on both hosts: verifier TestRecordedGCP and the throwaway unlocks of the Google
// pilot run it on a real release).
func TestHolderCheckGoogleRecorded(t *testing.T) {
	collateral := gcpRecordedCollateral(t)
	now := time.Date(2026, 11, 21, 5, 24, 52, 0, time.UTC)
	for _, c := range []struct{ file, set string }{
		{"gcp-066-c3-us-central1-a.json", "c3-standard-4"},
		{"gcp-066-c4-us-central1-f.json", "c4-standard-2"},
	} {
		t.Run(c.set, func(t *testing.T) {
			raw, err := os.ReadFile("../../testdata/" + c.file)
			if err != nil {
				t.Fatal(err)
			}
			var a proto.Attestation
			if err := json.Unmarshal(raw, &a); err != nil {
				t.Fatal(err)
			}
			nonce, _ := hex.DecodeString(a.Nonce)
			appCompose, err := kms.AppCompose(a.Info)
			if err != nil {
				t.Fatal(err)
			}
			dc, err := kms.DockerCompose(appCompose)
			if err != nil {
				t.Fatal(err)
			}
			ac, d := sha256.Sum256(appCompose), sha256.Sum256([]byte(dc))
			pol := &kms.Policy{Releases: []kms.ReleasePin{{App: "agent-vm", Version: "v0.99.0", AppComposeSHA256: hex.EncodeToString(ac[:]),
				ComposeSHA256: hex.EncodeToString(d[:])}}}
			q, err := tdx.Parse(gcpRawQuote(t, &a))
			if err != nil {
				t.Fatal(err)
			}
			machines := &safety.MachineSet{Revoked: map[string]bool{}, Machines: []safety.Machine{{Doc: safety.MachineDoc{
				Type: safety.MachineType, Platform: "dstack", Host: safety.MachineHostGoogle, Mode: safety.MachineModePPID, PPID: q.PPID,
				FMSPC: q.FMSPC, Label: "gcp " + c.set}, Hash: strings.Repeat("0", 64), Source: "test"}}}
			google := &recordedGoogle{}
			o := CheckOptions{Now: now, GCP: true, GoogleGetter: google, Machines: machines,
				VerifyQuote: func(ctx context.Context, b []byte) (*tdx.Quote, error) {
					return tdx.VerifyWith(ctx, b, tdx.Options{Getter: collateral, Now: now})
				}}
			// The recordings' test app has no instance-id event, which the holder's one-instance lease needs: so the
			// furthest a recording gets is that last rule, after every attestation check, the release pin and the
			// attested app-compose held. An agent VM has the event (the Google pilot's 2-of-2 unlocks, c3 and c4).
			_, err = VerifyVM(context.Background(), raw, nonce, pol, o)
			if err == nil || err.Error() != "no instance-id event (the lease needs one)" || google.calls != 1 {
				t.Fatalf("GCP on: %v (%d Google fetches), want only the lease's instance-id rule", err, google.calls)
			}
			// What the verifier itself reports for it under the holder's policy: the shape's Google set.
			vp := verifier.Policy{Compose: []byte(dc), AppComposeSHA256: []string{pol.Releases[0].AppComposeSHA256}, KMSIDs: map[string]string{},
				VerifyQuote: o.VerifyQuote, Now: now, KeyRelease: true, Machines: machines}.WithGCP()
			vp.GoogleGetter = &recordedGoogle{}
			res, err := verifier.Verify(context.Background(), &a, nonce, vp)
			if err != nil || res.Facts[verifier.FactPlatformSet] != verifier.PlatformDstackGCP || !strings.Contains(res.Facts["boot measurements"], c.set) {
				t.Fatalf("verifier: %v, result %+v", err, res)
			}

			off := o
			off.GCP = false
			if _, err := VerifyVM(context.Background(), raw, nonce, pol, off); err == nil || !strings.Contains(err.Error(), "match no pinned set") {
				t.Fatalf("GCP off (a policy without dstack-gcp): %v", err)
			}
			none := o
			none.Machines = &safety.MachineSet{Revoked: map[string]bool{}}
			if _, err := VerifyVM(context.Background(), raw, nonce, pol, none); err == nil || !strings.Contains(err.Error(), "attestation: machine") {
				t.Fatalf("no machine certificate: %v", err)
			}
			other := *pol
			other.Releases = []kms.ReleasePin{{App: "agent-vm", Version: "v0.99.0", AppComposeSHA256: strings.Repeat("ab", 32)}}
			if _, err := VerifyVM(context.Background(), raw, nonce, &other, o); err == nil {
				t.Fatal("an app-compose the policy doesn't pin: accepted")
			}
		})
	}
}

type gcpCollateralFile map[string]struct {
	Header map[string][]string `json:"header"`
	Body   string              `json:"body"`
}

func (c gcpCollateralFile) Get(url string) (map[string][]string, []byte, error) {
	r, ok := c[url]
	if !ok {
		return nil, nil, fmt.Errorf("not recorded: %s", url)
	}
	b, err := base64.StdEncoding.DecodeString(r.Body)
	return r.Header, b, err
}

func gcpRecordedCollateral(t *testing.T) gcpCollateralFile {
	t.Helper()
	raw, err := os.ReadFile("../../testdata/intel-collateral-gcp-20261121.json")
	if err != nil {
		t.Fatal(err)
	}
	var c gcpCollateralFile
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatal(err)
	}
	return c
}

// recordedGoogle serves Google's recorded firmware endorsements (internal/gcetcb testdata) by URL, counting calls.
type recordedGoogle struct{ calls int }

func (g *recordedGoogle) Get(url string) (map[string][]string, []byte, error) {
	g.calls++
	name, ok := strings.CutPrefix(url, gcetcb.URLPrefix)
	if !ok {
		return nil, nil, errors.New("not Google's bucket: " + url)
	}
	b, err := os.ReadFile("../../internal/gcetcb/testdata/" + name)
	if err != nil {
		return nil, nil, errors.New("failed to retrieve " + url + ", status code received 404")
	}
	return nil, b, nil
}

func gcpRawQuote(t *testing.T, a *proto.Attestation) []byte {
	t.Helper()
	var q struct {
		Quote string `json:"quote"`
	}
	json.Unmarshal(a.Quote, &q)
	b, err := hex.DecodeString(q.Quote)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
