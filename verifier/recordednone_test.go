package verifier

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/tacyhq/tacy/internal/tdx"
	"github.com/tacyhq/tacy/proto"
)

// Fix B on real quotes. testdata/attest-065-none.json and attest-065-none-restart.json are dstack GetQuote and Info
// answers of two throwaway CVMs on dstack-0.6.5 (Phala prod2, tdx.small, 2026-11-21, the disk-key experiments'
// round 1 and round 2), deployed with key_provider none, kms_enabled false, gateway_enabled false, an ephemeral data
// disk and pre_launch_script "" (a research note). The second was taken after
// a Phala restart (a new boot: a new disk key and instance id). The report_data is proto.ReportData of the nonce and
// key recorded with them. Their composes are the experiment's (a diag and a curl probe, not ours, and no ulimits).
//
// In none mode dstack measures no os-image-hash (it comes only from a KMS's answer): the verifier takes the OS image
// from the pinned boot set the measurements match.

var noneRecordings = []string{"attest-065-none.json", "attest-065-none-restart.json"}

func loadNone(t *testing.T, name string) (*proto.Attestation, []byte, string, string) {
	t.Helper()
	raw, err := os.ReadFile("../testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	var a proto.Attestation
	if err := json.Unmarshal(raw, &a); err != nil {
		t.Fatal(err)
	}
	nonce, _ := hex.DecodeString(a.Nonce)
	var info struct {
		TcbInfo string `json:"tcb_info"`
	}
	json.Unmarshal(a.Info, &info)
	var tcb struct {
		AppCompose string `json:"app_compose"`
	}
	json.Unmarshal([]byte(info.TcbInfo), &tcb)
	return &a, nonce, tcb.AppCompose, attestedCompose(t, &a)
}

// collateral20261121 serves the Intel PCS answers recorded 2026-11-21 (testdata/intel-collateral-20261121.json,
// also internal/tdx's), and collateralNow is when they were fetched.
type collateral20261121 map[string]struct {
	Header map[string][]string `json:"header"`
	Body   string              `json:"body"`
}

var collateralNow = time.Date(2026, 11, 21, 0, 27, 0, 0, time.UTC)

func (c collateral20261121) Get(url string) (map[string][]string, []byte, error) {
	e, ok := c[url]
	if !ok {
		return nil, nil, errors.New("not recorded: " + url)
	}
	b, err := base64.StdEncoding.DecodeString(e.Body)
	return e.Header, b, err
}

func recordedCollateral(t *testing.T) collateral20261121 {
	t.Helper()
	raw, err := os.ReadFile("../testdata/intel-collateral-20261121.json")
	if err != nil {
		t.Fatal(err)
	}
	var c collateral20261121
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatal(err)
	}
	return c
}

// quoteCheck verifies the quote with Intel's recorded collateral when it covers the host's FMSPC (the full chain,
// CRLs and TCB levels), else parses it offline; it says which.
func quoteCheck(t *testing.T, raw []byte) (func(context.Context, []byte) (*tdx.Quote, error), bool) {
	t.Helper()
	c := recordedCollateral(t)
	full := func(ctx context.Context, b []byte) (*tdx.Quote, error) {
		return tdx.VerifyWith(ctx, b, tdx.Options{Getter: c, Now: collateralNow})
	}
	if _, err := full(context.Background(), raw); err == nil {
		return full, true
	} else if !strings.Contains(err.Error(), "not recorded") {
		t.Fatalf("the recorded quote fails Intel's checks: %v", err)
	}
	return offline.VerifyQuote, false
}

func rawQuote(t *testing.T, a *proto.Attestation) []byte {
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

// The genuine none-mode quotes, as they are: genuine Intel quote, UpToDate, report_data, the event log replay, the OS
// image from the boot set (no os-image-hash event), the 0.6.5 tdx.small boot set, keys made in the VM with the disk
// encrypted, the experiment's app-compose (its own pin): then the Fix B rule the experiment's compose doesn't meet,
// ulimits core 0. Before the change they stopped at the OS image.
func TestRecorded065None(t *testing.T) {
	for _, name := range noneRecordings {
		t.Run(name, func(t *testing.T) {
			a, nonce, attested, compose := loadNone(t, name)
			vq, full := quoteCheck(t, rawQuote(t, a))
			t.Logf("Intel chain and TCB verified with the recorded collateral: %v", full)
			p := Policy{VerifyQuote: vq, AllowStaleTCB: !full, Compose: []byte(compose), AppCompose: []byte(attested)}
			res, err := Verify(context.Background(), a, nonce, p)
			if err == nil || !strings.HasPrefix(err.Error(), AppComposeFlagsCheck+": ") || !strings.Contains(err.Error(), "ulimits core 0") {
				t.Fatalf("want the core-dump rule last: %v", err)
			}
			for i, c := range res.Checks {
				if c.OK != (i < len(res.Checks)-1) {
					t.Fatalf("check %d %q ok=%v (%s)", i, c.Name, c.OK, c.Detail)
				}
			}
			if res.Facts["OS image"] != "dstack-0.6.5" || res.Facts["OS image hash"] != BootMeasurements[0].OSImage ||
				res.Facts["boot measurements"] != BootMeasurements[0].Name || res.Facts["keys"] != "made inside the VM at boot (key provider none)" ||
				res.Facts["key provider"] != `{"name":"none","id":""}` || res.Facts["pre-launch script"] != "none" {
				t.Fatalf("facts %v", res.Facts)
			}
			if full && !strings.HasPrefix(res.Facts["TCB"], "UpToDate") {
				t.Fatalf("TCB %q", res.Facts["TCB"])
			}
			// Review L4: in none mode the check's name says the label comes from the boot set, not an attested event.
			n := 0
			for _, c := range res.Checks {
				if strings.HasPrefix(c.Name, "production dstack OS image") {
					n++
					if c.Name != OSImageBootCheck || !strings.Contains(c.Detail, "from the pinned boot set") {
						t.Fatalf("OS image check %q: %q", c.Name, c.Detail)
					}
				}
			}
			if n != 1 {
				t.Fatalf("%d OS image checks", n)
			}
		})
	}
}

// The same genuine quotes running the release's Fix B app-compose (compose.yaml with its pinned app-compose.json:
// the compose-hash event and RTMR3 made consistent, the agentd label as unlockd makes it): every check passes. The
// boot measurements, the missing os-image-hash and the key-provider and storage events are the real ones.
func TestRecorded065NoneRelease(t *testing.T) {
	compose := composeYAML(t)
	release, err := ReleaseAppCompose(compose, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range noneRecordings {
		t.Run(name, func(t *testing.T) {
			a, nonce, _, _ := loadNone(t, name)
			setAppComposeRaw(t, a, release)
			rtmr3 := recompose(t, a, release)
			rd := agentLabel(t, a, nonce, HasUnlockd(string(compose)))
			p := Policy{AllowStaleTCB: true, Compose: compose, AppCompose: release, VerifyQuote: changeQuote(func(q *tdx.Quote) {
				q.Rtmrs[3] = rtmr3
				if rd != nil {
					q.ReportData = rd
				}
			})}
			res, err := Verify(context.Background(), a, nonce, p)
			if err != nil {
				t.Fatal(err)
			}
			if res.Facts["OS image"] != "dstack-0.6.5" || res.Facts["key mode"] != KeyProviderNone || res.Facts["pre-launch script"] != "none" {
				t.Fatalf("facts %v", res.Facts)
			}
			last := res.Checks[len(res.Checks)-1]
			if last.Name != UnlockdCheck || !last.OK || !strings.Contains(last.Detail, "key made in the VM") {
				t.Fatalf("last check %+v", last)
			}

			// A tampered compose (one byte in agentd's command) with the release's app-compose pinned: refused.
			bad := []byte(strings.Replace(string(release), `-relay-auth-key`, `-relay-auth-kez`, 1))
			if string(bad) == string(release) {
				t.Fatal("the tamper didn't apply")
			}
			a2, nonce2, _, _ := loadNone(t, name)
			setAppComposeRaw(t, a2, bad)
			rt2 := recompose(t, a2, bad)
			rd2 := agentLabel(t, a2, nonce2, true)
			p2 := p
			p2.VerifyQuote = changeQuote(func(q *tdx.Quote) { q.Rtmrs[3], q.ReportData = rt2, rd2 })
			if _, err := Verify(context.Background(), a2, nonce2, p2); err == nil || !strings.HasPrefix(err.Error(), AppComposePinCheck) {
				t.Fatalf("tampered compose: %v", err)
			}
		})
	}
}

// What the none-mode OS image rule refuses, on the genuine none quote with only the edit made consistent.
func TestNoneOSImageRule(t *testing.T) {
	ev := func(name, payload string) tdx.Event {
		return tdx.Event{IMR: 3, EventType: 0x08000001, Event: name, EventPayload: hex.EncodeToString([]byte(payload))}
	}
	insertBefore := func(evs []tdx.Event, before string, e tdx.Event) []tdx.Event {
		for i := range evs {
			if evs[i].IMR == 3 && evs[i].Event == before {
				return append(evs[:i], append([]tdx.Event{e}, evs[i:]...)...)
			}
		}
		t.Fatalf("no %s event", before)
		return nil
	}
	devImage := strings.Repeat("d", 64)
	cases := []struct {
		name, check, want string
		edit              func([]tdx.Event) []tdx.Event
		quote             func(q *tdx.Quote)
	}{
		{"os-image-hash after system-ready", "event log replays", "after system-ready", func(e []tdx.Event) []tdx.Event {
			return append(e, tdx.Event{IMR: 3, EventType: 0x08000001, Event: "os-image-hash", EventPayload: BootMeasurements[0].OSImage})
		}, nil},
		{"a dev image's os-image-hash at boot", "production dstack OS image", "isn't a known production image", func(e []tdx.Event) []tdx.Event {
			return insertBefore(e, "system-ready", tdx.Event{IMR: 3, EventType: 0x08000001, Event: "os-image-hash", EventPayload: devImage})
		}, nil},
		{"KMS keys without os-image-hash", "production dstack OS image", "isn't a known production image", func(e []tdx.Event) []tdx.Event {
			for i := range e {
				if e[i].Event == "key-provider" {
					e[i] = ev("key-provider", `{"name":"kms","id":"`+strings.Repeat("ab", 8)+`"}`)
				}
			}
			return e
		}, nil},
		{"another kernel", "production dstack OS image", "no os-image-hash event (key provider none) and MRTD/RTMR0-2", nil,
			func(q *tdx.Quote) { q.Rtmrs[1][0] ^= 1 }},
		{"disk not encrypted", KMSCheck, "storage-encrypted", func(e []tdx.Event) []tdx.Event {
			for i := range e {
				if e[i].Event == "storage-encrypted" {
					e[i] = ev("storage-encrypted", "0")
				}
			}
			return e
		}, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a, nonce, attested, compose := loadNone(t, noneRecordings[0])
			p := Policy{AllowStaleTCB: true, VerifyQuote: offline.VerifyQuote, Compose: []byte(compose), AppCompose: []byte(attested)}
			if c.edit != nil {
				p.VerifyQuote = forge(t, a, c.edit)
			}
			if c.quote != nil {
				inner := p.VerifyQuote
				p.VerifyQuote = func(ctx context.Context, raw []byte) (*tdx.Quote, error) {
					q, err := inner(ctx, raw)
					if err == nil {
						c.quote(q)
					}
					return q, err
				}
			}
			_, err := Verify(context.Background(), a, nonce, p)
			if err == nil || !strings.HasPrefix(err.Error(), c.check) || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("want %s (%s): %v", c.check, c.want, err)
			}
		})
	}
}

// A release that declares Fix B (its pinned app-compose.json has key_provider none) refuses a VM whose keys come
// from Phala's KMS, even where the policy would allow the KMS fallback: the genuine 0.6.5 KMS-mode quote.
func TestNoneReleaseRefusesKMS(t *testing.T) {
	release, err := ReleaseAppCompose(composeYAML(t), nil, false)
	if err != nil {
		t.Fatal(err)
	}
	a, nonce, _, compose := load065(t)
	for _, fallback := range []bool{false, true} {
		p := Policy{AllowStaleTCB: true, VerifyQuote: offline.VerifyQuote, Compose: []byte(compose), AppCompose: release,
			KMSFallback: fallback, AllowE2EDiag: true}
		_, err := Verify(context.Background(), a, nonce, p)
		if err == nil || !strings.HasPrefix(err.Error(), KMSCheck+": ") || !strings.Contains(err.Error(), `key provider "kms", want none`) {
			t.Fatalf("fallback allowed %v: %v", fallback, err)
		}
	}
}
