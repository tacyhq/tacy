package verifier

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/tacyhq/tacy/internal/gcetcb"
	"github.com/tacyhq/tacy/internal/tdx"
	"github.com/tacyhq/tacy/proto"
	"github.com/tacyhq/tacy/safety"
)

// Google Cloud on real quotes. testdata/gcp-066-c3-us-central1-{a,b,c}.json are /attest answers (proto.Attestation:
// dstack's quote with report_data = proto.ReportData(nonce, key), dstack's Info) of three fresh throwaway VMs in
// project sealowl, one per zone, 2026-11-21 03:33-03:40Z (a research note, "Many-cycle
// runs", cycles a01, b01, c01): c3-standard-4 TDX; gcp-066-c3-us-east1-c.json, gcp-066-c4-us-east4-c-1.json and
// gcp-066-c4-us-central1-f.json are G3's (the third run, 04:49-05:09Z: c3-standard-4 in a second region,
// c4-standard-2 in the two zones that had stock). All:
// dstack 0.6.6 booted from its UKI on Google's firmware, key provider none, an ephemeral data disk, the throwaway
// attest app (app A, not the agent VM). Intel's answers for both platforms' FMSPCs were recorded at gcpCollateralNow (testdata/intel-collateral-gcp-20261121.json); Google's endorsements
// are internal/gcetcb/testdata's, as Google's bucket served them the same day. gcp-066-c3s8-us-central1-a.json,
// gcp-066-c3s8-us-east1-c.json (c3-standard-8) and gcp-066-c3s22-us-central1-a.json (c3-standard-22) are the same app
// on bigger C3 shapes in project tacy-test, 2026-11-23; the same Intel answers and Google endorsement verify them.

var gcpRecordings = []string{"gcp-066-c3-us-central1-a.json", "gcp-066-c3-us-central1-b.json", "gcp-066-c3-us-central1-c.json",
	"gcp-066-c3-us-east1-c.json", "gcp-066-c4-us-east4-c-1.json", "gcp-066-c4-us-central1-f.json",
	"gcp-066-c3s8-us-central1-a.json", "gcp-066-c3s8-us-east1-c.json", "gcp-066-c3s22-us-central1-a.json"}

// gcpSetOf is the GCP set a recording's name says it is (c3-standard-4, c4-standard-2, c3-standard-8, c3-standard-22).
func gcpSetOf(name string) BootMeasurement {
	shape := "c3-standard-4"
	switch {
	case strings.Contains(name, "-c4-"):
		shape = "c4-standard-2"
	case strings.Contains(name, "-c3s8-"):
		shape = "c3-standard-8"
	case strings.Contains(name, "-c3s22-"):
		shape = "c3-standard-22"
	}
	for _, b := range GCPBootMeasurements {
		if strings.Contains(b.Name, " "+shape+" ") {
			return b
		}
	}
	panic("no GCP set for " + shape)
}

var gcpCollateralNow = time.Date(2026, 11, 21, 5, 24, 52, 0, time.UTC)

const (
	mrtdGoogleNov = "f21e6b48743fe14c2d090078ca1197f09ae4c99438677f2c79901ef80e2aeefe2f9a7eb6e3eb3b5047c4f1511731e5d3"
	mrtdGoogleOct = "c1ee9c16e3afc506cfe042c5b846a368528f3b37618eafb27469bc114cf914e9222c91618470e7f2b28ac360968270a5"
)

// googleFiles serves Google's recorded endorsements by URL (or serve for every URL, or fail with err), counting calls.
type googleFiles struct {
	serve []byte
	err   error
	calls int
}

func (g *googleFiles) Get(url string) (map[string][]string, []byte, error) {
	g.calls++
	if g.err != nil {
		return nil, nil, g.err
	}
	if g.serve != nil {
		return nil, g.serve, nil
	}
	name, ok := strings.CutPrefix(url, gcetcb.URLPrefix)
	if !ok {
		return nil, nil, errors.New("not Google's bucket: " + url)
	}
	b, err := os.ReadFile("../internal/gcetcb/testdata/" + name)
	if err != nil {
		return nil, nil, errors.New("failed to retrieve " + url + ", status code received 404")
	}
	return nil, b, nil
}

func googleEndorsement(t *testing.T, mrtd string) []byte {
	t.Helper()
	b, err := os.ReadFile("../internal/gcetcb/testdata/" + mrtd + ".binarypb")
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func gcpCollateral(t *testing.T) collateral20261121 {
	t.Helper()
	raw, err := os.ReadFile("../testdata/intel-collateral-gcp-20261121.json")
	if err != nil {
		t.Fatal(err)
	}
	var c collateral20261121
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatal(err)
	}
	return c
}

// gcpPolicy is the policy for a recording as it is: Intel's chain and TCB with the recorded collateral, the
// recording's own compose and app-compose as the pins, Google's endorsements from the recorded files, WithGCP.
func gcpPolicy(t *testing.T, name string) (*proto.Attestation, []byte, Policy, *googleFiles) {
	t.Helper()
	a, nonce, attested, compose := loadNone(t, name)
	c := gcpCollateral(t)
	g := &googleFiles{}
	p := Policy{Compose: []byte(compose), AppCompose: []byte(attested), GoogleGetter: g, Now: gcpCollateralNow,
		VerifyQuote: func(ctx context.Context, b []byte) (*tdx.Quote, error) {
			return tdx.VerifyWith(ctx, b, tdx.Options{Getter: c, Now: gcpCollateralNow})
		}, Machines: gcpMachines(t)}
	return a, nonce, p.WithGCP(), g
}

func countCheck(res *Result, name string) int {
	n := 0
	for _, c := range res.Checks {
		if c.Name == name {
			n++
		}
	}
	return n
}

// The genuine GCP quotes pass every check with WithGCP: Intel's chain and TCB UpToDate, report_data, the RTMR3
// replay and compose hash, Google's signed endorsement of the MRTD, the dstack UKI in RTMR1, the c3-standard-4 set
// (RTMR0-2), keys made in the VM with the disk encrypted, and the none-mode app-compose rules (the throwaway app's
// app-compose is its own pin). One endorsement fetch per verification.
func TestRecordedGCP(t *testing.T) {
	for _, name := range gcpRecordings {
		t.Run(name, func(t *testing.T) {
			a, nonce, p, g := gcpPolicy(t, name)
			res, err := Verify(context.Background(), a, nonce, p)
			if err != nil {
				t.Fatal(err)
			}
			if countCheck(res, GCPBootCheck) != 1 || len(res.Checks) != 22 || g.calls != 1 {
				t.Fatalf("%d GCP checks, %d checks, %d fetches", countCheck(res, GCPBootCheck), len(res.Checks), g.calls)
			}
			f := res.Facts
			if !strings.HasPrefix(f["boot chain"], "Google's TDX firmware and the dstack UKI") || f["boot measurements"] != gcpSetOf(name).Name ||
				f["OS image"] != "dstack-0.6.6 (GCP UKI)" || f["MRTD"] != mrtdGoogleNov || f["key mode"] != KeyProviderNone ||
				f["keys"] != "made inside the VM at boot (key provider none)" || !strings.HasPrefix(f["TCB"], "UpToDate") ||
				!strings.Contains(f["firmware"], "SVN 2, built 2026-07-31, cl 957008435") {
				t.Fatalf("facts %v", f)
			}
			for _, c := range res.Checks {
				if c.Name == GCPBootCheck && !strings.Contains(c.Detail, "UKI 440fa6cac8d3fc19… in RTMR1") {
					t.Fatalf("detail %q", c.Detail)
				}
			}
		})
	}
}

// The pinned set is what the recordings' firmware logs replay to, RTMR1's boot applications hold the UKI, and the
// recordings' MRTD is the set's pinned Google build.
func TestGCPSetIsTheRecordings(t *testing.T) {
	for _, name := range gcpRecordings {
		s := gcpSetOf(name)
		a, _, _, _ := loadNone(t, name)
		q, err := tdx.Parse(rawQuote(t, a))
		if err != nil {
			t.Fatal(err)
		}
		var ql struct {
			EventLog json.RawMessage `json:"event_log"`
		}
		json.Unmarshal(a.Quote, &ql)
		ev, err := tdx.ParseEventLog(ql.EventLog)
		if err != nil {
			t.Fatal(err)
		}
		apps, err := tdx.ReplayFirmware(q, ev)
		if err != nil {
			t.Fatal(err)
		}
		if hex.EncodeToString(q.MrTd) != mrtdGoogleNov || !slices.Contains(s.GoogleMRTDs, mrtdGoogleNov) || hex.EncodeToString(q.Rtmrs[0]) != s.RTMR0 ||
			hex.EncodeToString(q.Rtmrs[1]) != s.RTMR1 || hex.EncodeToString(q.Rtmrs[2]) != s.RTMR2 || !slices.Contains(apps, s.UKI) {
			t.Fatalf("%s: the recording isn't the pinned set (apps %v)", name, apps)
		}
	}
	// The shapes share the firmware and the UKI: only RTMR0 differs, and no two shapes share one.
	c3 := GCPBootMeasurements[0]
	rtmr0 := map[string]string{}
	for _, s := range GCPBootMeasurements {
		if s.RTMR1 != c3.RTMR1 || s.RTMR2 != c3.RTMR2 || s.UKI != c3.UKI || s.OSImage != c3.OSImage || s.MRTD != c3.MRTD ||
			s.MinFirmwareSVN != c3.MinFirmwareSVN || !slices.Equal(s.GoogleMRTDs, c3.GoogleMRTDs) {
			t.Fatalf("%s should differ from %s in RTMR0 only", s.Name, c3.Name)
		}
		if other, ok := rtmr0[s.RTMR0]; ok {
			t.Fatalf("%s and %s share RTMR0", s.Name, other)
		}
		rtmr0[s.RTMR0] = s.Name
	}
	for h := range GCPImages {
		if _, ok := ProdImages[h]; ok {
			t.Fatal("a GCP image is a default (Phala) image")
		}
	}
}

// Without WithGCP (every verifier today) a GCP quote is refused as before, at the OS image: no pinned set; and
// Google's bucket isn't asked.
func TestGCPNotByDefault(t *testing.T) {
	a, nonce, attested, compose := loadNone(t, gcpRecordings[0])
	g := &googleFiles{}
	p := Policy{AllowStaleTCB: true, VerifyQuote: offline.VerifyQuote, Compose: []byte(compose), AppCompose: []byte(attested), GoogleGetter: g,
		Machines: gcpMachines(t)}
	res, err := Verify(context.Background(), a, nonce, p)
	if err == nil || !strings.HasPrefix(err.Error(), OSImageBootCheck) || !strings.Contains(err.Error(), "match no pinned set") ||
		g.calls != 0 || countCheck(res, GCPBootCheck) != 0 {
		t.Fatalf("%v (%d fetches)", err, g.calls)
	}
}

// Phala's behaviour is unchanged with WithGCP: the same checks, details, facts and errors on Phala's genuine
// quotes (a full pass, the KMS fallback, a none-mode refusal), and Google's bucket is never asked.
func TestPhalaUnchangedWithGCP(t *testing.T) {
	type run struct {
		name string
		mk   func(t *testing.T) (*proto.Attestation, []byte, Policy)
	}
	compose := composeYAML(t)
	release, err := ReleaseAppCompose(compose, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	var runs []run
	for _, name := range noneRecordings {
		runs = append(runs, run{"release on " + name, func(t *testing.T) (*proto.Attestation, []byte, Policy) {
			a, nonce, _, _ := loadNone(t, name)
			setAppComposeRaw(t, a, release)
			rtmr3 := recompose(t, a, release)
			rd := agentLabel(t, a, nonce, HasUnlockd(string(compose)))
			return a, nonce, Policy{AllowStaleTCB: true, Compose: compose, AppCompose: release, VerifyQuote: changeQuote(func(q *tdx.Quote) {
				q.Rtmrs[3] = rtmr3
				if rd != nil {
					q.ReportData = rd
				}
			})}
		}}, run{"as recorded " + name, func(t *testing.T) (*proto.Attestation, []byte, Policy) {
			a, nonce, attested, compose := loadNone(t, name)
			vq, _ := quoteCheck(t, rawQuote(t, a))
			return a, nonce, Policy{VerifyQuote: vq, Now: collateralNow, Compose: []byte(compose), AppCompose: []byte(attested)}
		}})
	}
	runs = append(runs, run{"KMS fallback 0.6.5", func(t *testing.T) (*proto.Attestation, []byte, Policy) {
		a, nonce, attested, compose := load065(t)
		return a, nonce, Policy{AllowStaleTCB: true, VerifyQuote: offline.VerifyQuote, Compose: []byte(compose),
			AppCompose: []byte(attested), KMSFallback: true, AllowE2EDiag: true}
	}}, run{"retired 0.6.1 (offline policy)", func(t *testing.T) (*proto.Attestation, []byte, Policy) {
		a, nonce, compose := load061(t)
		p := offline
		p.Compose = compose
		return a, nonce, p
	}})
	for _, r := range runs {
		t.Run(r.name, func(t *testing.T) {
			a, nonce, p := r.mk(t)
			want, wantErr := Verify(context.Background(), a, nonce, p)
			a2, nonce2, p2 := r.mk(t)
			g := &googleFiles{}
			p2.GoogleGetter = g
			got, gotErr := Verify(context.Background(), a2, nonce2, p2.WithGCP())
			if !reflect.DeepEqual(want.Checks, got.Checks) || !reflect.DeepEqual(want.Facts, got.Facts) || g.calls != 0 ||
				(wantErr == nil) != (gotErr == nil) || (wantErr != nil && wantErr.Error() != gotErr.Error()) {
				t.Fatalf("differs with WithGCP (%d fetches):\n%v\n%v", g.calls, wantErr, gotErr)
			}
			t.Logf("%d checks, err %v", len(got.Checks), gotErr)
		})
	}
}

// A Phala quote under Google Cloud pins only: refused at the OS image (it matches no set; the closest, the GCP one,
// differs in every register), with nothing fetched.
func TestPhalaQuoteUnderGCPPins(t *testing.T) {
	a, nonce, attested, compose := loadNone(t, noneRecordings[0])
	g := &googleFiles{}
	p := Policy{AllowStaleTCB: true, VerifyQuote: offline.VerifyQuote, Compose: []byte(compose), AppCompose: []byte(attested),
		Boot: GCPBootMeasurements, ProdImages: GCPImages, GoogleGetter: g}
	_, err := Verify(context.Background(), a, nonce, p)
	if err == nil || !strings.HasPrefix(err.Error(), OSImageBootCheck) ||
		!strings.Contains(err.Error(), "closest is "+GCPBootMeasurements[0].Name+", which differs in RTMR0, RTMR1, RTMR2") || g.calls != 0 {
		t.Fatalf("%v (%d fetches)", err, g.calls)
	}
}

// What the GCP rules refuse, on a genuine GCP quote with only the named change (the quote parsed offline, so its
// edits can be made consistent).
func TestGCPRefusals(t *testing.T) {
	setWith := func(edit func(*BootMeasurement)) []BootMeasurement {
		s := GCPBootMeasurements[0]
		edit(&s)
		return append(slices.Clone(BootMeasurements), s)
	}
	editFirmwareLog := func(a *proto.Attestation) {
		var q map[string]any
		json.Unmarshal(a.Quote, &q)
		ev, _ := tdx.ParseEventLog(json.RawMessage(mustJSON(q["event_log"])))
		for i := range ev {
			if ev[i].IMR == 1 && ev[i].EventType == 0x80000006 { // the GPT event
				ev[i].Digest = strings.Repeat("00", 48)
			}
		}
		b, _ := json.Marshal(ev)
		q["event_log"] = string(b)
		a.Quote, _ = json.Marshal(q)
	}
	// The genuine MRTD with one bit changed (another firmware, as the "quote" edit below makes it).
	otherMRTD, _ := hex.DecodeString(mrtdGoogleNov)
	otherMRTD[5] ^= 1
	pinOther := setWith(func(s *BootMeasurement) {
		s.GoogleMRTDs = append(slices.Clone(s.GoogleMRTDs), hex.EncodeToString(otherMRTD))
	})
	keyEv := func(payload string) tdx.Event {
		return tdx.Event{IMR: 3, EventType: 0x08000001, Event: "key-provider", EventPayload: hex.EncodeToString([]byte(payload))}
	}
	cases := []struct {
		name, check, want string
		quote             func(*tdx.Quote)
		events            func([]tdx.Event) []tdx.Event
		att               func(*proto.Attestation)
		boot              []BootMeasurement
		google            *googleFiles
		fetches           int
	}{
		{name: "an MRTD neither pinned nor endorsed (other firmware)", check: GCPBootCheck,
			want: "isn't a Google firmware build we reviewed", quote: func(q *tdx.Quote) { q.MrTd[5] ^= 1 }},
		{name: "an MRTD we pinned but Google never endorsed (the endorsement stays required)", check: GCPBootCheck,
			want: "no Google endorsement for MRTD", quote: func(q *tdx.Quote) { q.MrTd[5] ^= 1 }, boot: pinOther, fetches: 1},
		{name: "a genuine endorsement of another firmware build served for this MRTD", check: GCPBootCheck,
			want: "doesn't list MRTD f21e6b48", fetches: 1},
		{name: "an endorsement with its signature changed", check: GCPBootCheck, want: "endorsement signature", fetches: 1},
		{name: "Google's bucket unreachable", check: GCPBootCheck, want: "no Google endorsement", google: &googleFiles{err: errors.New("dial tcp: i/o timeout")}, fetches: 1},
		{name: "firmware SVN below the set's minimum", check: GCPBootCheck, want: "has SVN 2, " + GCPBootMeasurements[0].Name + " needs at least 3",
			boot: setWith(func(s *BootMeasurement) { s.MinFirmwareSVN = 3 }), fetches: 1},
		{name: "another UKI in RTMR1's boot applications", check: GCPBootCheck, want: "RTMR1's boot applications don't include",
			boot: setWith(func(s *BootMeasurement) { s.UKI = strings.Repeat("ab", 48) })},
		{name: "a firmware log that doesn't replay to RTMR1", check: GCPBootCheck, want: "firmware event log: RTMR1 replay", att: editFirmwareLog},
		{name: "keys from a KMS on Google Cloud", check: GCPBootCheck, want: "needs key provider none", events: func(e []tdx.Event) []tdx.Event {
			for i := range e {
				if e[i].Event == "key-provider" {
					e[i] = keyEv(`{"name":"kms","id":"` + strings.Repeat("ab", 8) + `"}`)
				}
			}
			return e
		}},
		{name: "an os-image-hash event at boot", check: GCPBootCheck, want: "needs key provider none", events: func(e []tdx.Event) []tdx.Event {
			for i := range e {
				if e[i].IMR == 3 && e[i].Event == "system-ready" {
					oh := tdx.Event{IMR: 3, EventType: 0x08000001, Event: "os-image-hash", EventPayload: GCPBootMeasurements[0].OSImage}
					return append(e[:i], append([]tdx.Event{oh}, e[i:]...)...)
				}
			}
			t.Fatal("no system-ready")
			return nil
		}},
		{name: "another kernel or UKI (RTMR1)", check: OSImageBootCheck, want: "which differs in RTMR1 (another OS image?)",
			quote: func(q *tdx.Quote) { q.Rtmrs[1][0] ^= 1 }},
		{name: "another machine shape or firmware configuration (RTMR0)", check: OSImageBootCheck,
			want: "which differs in RTMR0 (another machine shape, or a Google firmware update?)", quote: func(q *tdx.Quote) { q.Rtmrs[0][0] ^= 1 }},
		{name: "another command line or initramfs (RTMR2)", check: OSImageBootCheck, want: "which differs in RTMR2",
			quote: func(q *tdx.Quote) { q.Rtmrs[2][0] ^= 1 }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a, nonce, attested, compose := loadNone(t, gcpRecordings[0])
			g := c.google
			switch {
			case g != nil:
			case strings.Contains(c.name, "another firmware build served"):
				g = &googleFiles{serve: googleEndorsement(t, mrtdGoogleOct)}
			case strings.Contains(c.name, "signature changed"):
				b := googleEndorsement(t, mrtdGoogleNov)
				b[len(b)-20] ^= 1 // inside the signature, the message's last field
				g = &googleFiles{serve: b}
			default:
				g = &googleFiles{}
			}
			if c.att != nil {
				c.att(a)
			}
			vq := offline.VerifyQuote
			if c.events != nil {
				vq = forge(t, a, c.events)
			}
			if c.quote != nil {
				inner := vq
				vq = func(ctx context.Context, raw []byte) (*tdx.Quote, error) {
					q, err := inner(ctx, raw)
					if err == nil {
						c.quote(q)
					}
					return q, err
				}
			}
			p := Policy{AllowStaleTCB: true, VerifyQuote: vq, Compose: []byte(compose), AppCompose: []byte(attested),
				GoogleGetter: g, Now: gcpCollateralNow, Machines: gcpMachines(t)}.WithGCP()
			if c.boot != nil {
				p.Boot = c.boot
			}
			res, err := Verify(context.Background(), a, nonce, p)
			if err == nil || !strings.HasPrefix(err.Error(), c.check+": ") || !strings.Contains(err.Error(), c.want) || res.HPKEPublicKey != nil {
				t.Fatalf("want %s (%s): %v", c.check, c.want, err)
			}
			if g.calls != c.fetches {
				t.Fatalf("%d fetches, want %d", g.calls, c.fetches)
			}
		})
	}
}

// The none-mode app-compose rules hold on Google Cloud too: the genuine GCP quote with its app-compose's
// ephemeral_data_disk requirement removed (the edit made consistent: RTMR3, and the edited file as the pin) is
// refused at the flags check, after the GCP boot chain passed.
func TestGCPNoneComposeRules(t *testing.T) {
	a, nonce, attested, compose := loadNone(t, gcpRecordings[0])
	var ac map[string]any
	if err := json.Unmarshal([]byte(attested), &ac); err != nil {
		t.Fatal(err)
	}
	req, _ := ac["requirements"].(map[string]any)
	if req["ephemeral_data_disk"] != true {
		t.Fatalf("requirements %v", ac["requirements"])
	}
	delete(req, "ephemeral_data_disk")
	edited, _ := json.Marshal(ac)
	setAppComposeRaw(t, a, edited)
	rtmr3 := recompose(t, a, edited)
	g := &googleFiles{}
	p := Policy{AllowStaleTCB: true, Compose: []byte(compose), AppCompose: edited, GoogleGetter: g, Now: gcpCollateralNow, Machines: gcpMachines(t),
		VerifyQuote: changeQuote(func(q *tdx.Quote) { q.Rtmrs[3] = rtmr3 })}.WithGCP()
	res, err := Verify(context.Background(), a, nonce, p)
	if err == nil || !strings.HasPrefix(err.Error(), AppComposeFlagsCheck+": ") || !strings.Contains(err.Error(), "ephemeral") ||
		countCheck(res, GCPBootCheck) != 1 || g.calls != 1 {
		t.Fatalf("%v", err)
	}
}

// Google's older firmware is still endorsed, but a genuine quote on it doesn't pass: an earlier dstack 0.6.1 test quote of
// 2026-10-13 (testdata/gcp-061-poc2-20261013.json) carries MRTD c1ee9c16…, which Google's signed
// endorsement lists (SVN 2, like today's build), so the endorsement alone would accept a downgrade to it. It isn't
// one of the sets' GoogleMRTDs (TestGCPEndorsedButUnpinnedMRTD), and the pinned RTMR0 refuses it too: that firmware measures another configuration firmware volume (and other ACPI tables). Nothing is
// fetched, since no GCP set's RTMR0-2 match.
func TestGCPOlderFirmwareRefused(t *testing.T) {
	raw, err := os.ReadFile("../testdata/gcp-061-poc2-20261013.json")
	if err != nil {
		t.Fatal(err)
	}
	var rec struct {
		Quote    string          `json:"quote"`
		EventLog json.RawMessage `json:"event_log"`
	}
	if err := json.Unmarshal(raw, &rec); err != nil {
		t.Fatal(err)
	}
	b, _ := hex.DecodeString(rec.Quote)
	q, err := tdx.Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	ev, err := tdx.ParseEventLog(rec.EventLog)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tdx.ReplayFirmware(q, ev); err != nil || hex.EncodeToString(q.MrTd) != mrtdGoogleOct {
		t.Fatalf("the 2026-10-13 quote: %v", err)
	}
	if _, _, err := gcetcb.Check(context.Background(), &googleFiles{}, q.MrTd, gcpCollateralNow); err != nil {
		t.Fatalf("Google's endorsement of the older firmware: %v", err)
	}
	g := &googleFiles{}
	sets := Policy{}.WithGCP().Boot
	out, set, _, err := gcpBoot(context.Background(), q, ev, sets, []byte(`{"name":"none","id":""}`), false, g, gcpCollateralNow)
	if set != nil || err != nil || g.calls != 0 || !reflect.DeepEqual(out, sets) {
		t.Fatalf("gcpBoot: %v %v (%d fetches)", set, err, g.calls)
	}
	if _, err := matchBoot(q, GCPBootMeasurements[0].OSImage, out); err == nil || !strings.Contains(err.Error(), "RTMR0") {
		t.Fatalf("matchBoot: %v", err)
	}
	// RTMR0's configuration firmware volume event (EV_EFI_PLATFORM_FIRMWARE_BLOB2) differs between the two builds.
	cfv := func(ev []tdx.Event) string {
		for _, e := range ev {
			if e.IMR == 0 && e.EventType == 0x8000000a {
				return e.Digest
			}
		}
		return ""
	}
	a, _, _, _ := loadNone(t, gcpRecordings[0])
	var ql struct {
		EventLog json.RawMessage `json:"event_log"`
	}
	json.Unmarshal(a.Quote, &ql)
	now, _ := tdx.ParseEventLog(ql.EventLog)
	if cfv(ev) == "" || cfv(now) == "" || cfv(ev) == cfv(now) {
		t.Fatalf("CFV events %q %q", cfv(ev), cfv(now))
	}
}

// The recorded collateral is what Intel served (a sanity check that the file isn't edited by hand).
func TestGCPCollateralRecorded(t *testing.T) {
	c := gcpCollateral(t)
	for url, e := range c {
		if _, err := base64.StdEncoding.DecodeString(e.Body); err != nil || !strings.Contains(url, "intel.com") {
			t.Fatalf("%s: %v", url, err)
		}
	}
	if len(c) != 5 { // both platforms' TCB info (c3 and c4), QE identity, PCK CRL, root CA CRL
		t.Fatalf("%d URLs", len(c))
	}
}

// Every GCP set is complete: a non-zero SVN floor, a 96-hex UKI, the placeholder MRTD, at least one pinned 96-hex
// Google MRTD (review H1), 96-hex RTMR0-2 and an image GCPImages names (review L5: a set left at zero values would
// accept any SVN).
func TestGCPSetsComplete(t *testing.T) {
	hex96 := func(s string) bool {
		b, err := hex.DecodeString(s)
		return err == nil && len(b) == 48 && strings.ToLower(s) == s
	}
	for _, s := range GCPBootMeasurements {
		if s.MinFirmwareSVN == 0 || !hex96(s.UKI) || s.MRTD != MRTDGoogleEndorsed || !hex96(s.RTMR0) || !hex96(s.RTMR1) ||
			!hex96(s.RTMR2) || GCPImages[s.OSImage] == "" || s.Name == "" || s.Source == "" || len(s.GoogleMRTDs) == 0 {
			t.Fatalf("incomplete set %+v", s)
		}
		for _, m := range s.GoogleMRTDs {
			if !hex96(m) {
				t.Fatalf("%s: pinned MRTD %q isn't 96 lowercase hex", s.Name, m)
			}
		}
	}
}

// A signed trust list can't carry the placeholder MRTD (its registers must be 96 hex characters), so it can't add a
// GCP set; and a trust list applied before or after WithGCP leaves the GCP recordings passing and Phala's as they
// were (WithTrustList keeps every set it was given).
func TestGCPAndTrustLists(t *testing.T) {
	admin := testAdmin(t)
	s := GCPBootMeasurements[0]
	bad := safety.TrustList{Seq: 1, OSImages: map[string]string{s.OSImage: "dstack-0.6.6 (GCP UKI)"},
		BootMeasurements: []safety.TrustBoot{{Name: "gcp", OSImage: s.OSImage, MRTD: MRTDGoogleEndorsed, RTMR0: s.RTMR0,
			RTMR1: s.RTMR1, RTMR2: s.RTMR2, Source: "t"}}}
	if _, err := ParseTrustList(signedList(t, admin, bad), 0, listNow); err == nil || !strings.Contains(err.Error(), "48 bytes of lowercase hex") {
		t.Fatalf("a trust list with the placeholder MRTD: %v", err)
	}
	list, err := ParseTrustList(signedList(t, admin, safety.TrustList{Seq: 2}), 0, listNow)
	if err != nil {
		t.Fatal(err)
	}
	for _, order := range []string{"trust list then WithGCP", "WithGCP then trust list"} {
		t.Run(order, func(t *testing.T) {
			a, nonce, p, g := gcpPolicy(t, gcpRecordings[0])
			base := Policy{Compose: p.Compose, AppCompose: p.AppCompose, GoogleGetter: g, Now: p.Now, VerifyQuote: p.VerifyQuote, Machines: p.Machines}
			var q Policy
			if order == "trust list then WithGCP" {
				q, err = base.WithTrustList(list)
				q = q.WithGCP()
			} else {
				q, err = base.WithGCP().WithTrustList(list)
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Verify(context.Background(), a, nonce, q); err != nil || g.calls != 1 {
				t.Fatalf("%v (%d fetches)", err, g.calls)
			}
		})
	}
}

// Another shape's RTMR0, on genuine quotes: a c4-standard-2 VM with only the c3-standard-4 set pinned, and a
// c3-standard-4 VM with only the c4 set, are refused at the OS image (RTMR0 differs), with nothing fetched.
func TestGCPOtherShapeRefused(t *testing.T) {
	for _, c := range []struct {
		rec  string
		only BootMeasurement
	}{{"gcp-066-c4-us-east4-c-1.json", GCPBootMeasurements[0]}, {"gcp-066-c3-us-east1-c.json", GCPBootMeasurements[1]},
		// The bigger C3 shapes: each refused with only c3-standard-4's set, or only the other's.
		{"gcp-066-c3s8-us-central1-a.json", GCPBootMeasurements[0]}, {"gcp-066-c3s22-us-central1-a.json", GCPBootMeasurements[0]},
		{"gcp-066-c3s8-us-east1-c.json", gcpSetOf("gcp-066-c3s22-")}, {"gcp-066-c3s22-us-central1-a.json", gcpSetOf("gcp-066-c3s8-")},
		// And c3-standard-4 refused with only a bigger set.
		{"gcp-066-c3-us-central1-a.json", gcpSetOf("gcp-066-c3s8-")}} {
		a, nonce, p, g := gcpPolicy(t, c.rec)
		p.Boot = append(slices.Clone(BootMeasurements), c.only)
		_, err := Verify(context.Background(), a, nonce, p)
		if err == nil || !strings.HasPrefix(err.Error(), OSImageBootCheck) || g.calls != 0 ||
			!strings.Contains(err.Error(), "closest is "+c.only.Name+", which differs in RTMR0 (another machine shape, or a Google firmware update?)") {
			t.Fatalf("%s: %v (%d fetches)", c.rec, err, g.calls)
		}
	}
}

// Review H1: an MRTD Google endorses but we haven't reviewed is refused. The genuine c3 quote with its MRTD swapped
// for Google's October build (c1ee9c16…: genuinely endorsed, SVN 2, the set's floor) and every other register as
// pinned would pass on the endorsement alone; the set's GoogleMRTDs (the builds we reviewed) refuse it, before any
// fetch.
func TestGCPEndorsedButUnpinnedMRTD(t *testing.T) {
	oct, _ := hex.DecodeString(mrtdGoogleOct)
	if fw, _, err := gcetcb.Check(context.Background(), &googleFiles{}, oct, gcpCollateralNow); err != nil || fw.SVN < GCPBootMeasurements[0].MinFirmwareSVN {
		t.Fatalf("the October build should be endorsed at the set's SVN floor: %v", err)
	}
	a, nonce, attested, compose := loadNone(t, gcpRecordings[0])
	g := &googleFiles{}
	p := Policy{AllowStaleTCB: true, Compose: []byte(compose), AppCompose: []byte(attested), GoogleGetter: g, Now: gcpCollateralNow, Machines: gcpMachines(t),
		VerifyQuote: changeQuote(func(q *tdx.Quote) { q.MrTd = slices.Clone(oct) })}.WithGCP()
	res, err := Verify(context.Background(), a, nonce, p)
	want := "MRTD c1ee9c16e3afc506… isn't a Google firmware build we reviewed for " + GCPBootMeasurements[0].Name +
		" (pinned: f21e6b48743fe14c…); Google's endorsement alone isn't enough"
	if err == nil || !strings.HasPrefix(err.Error(), GCPBootCheck+": ") || !strings.Contains(err.Error(), want) ||
		res.HPKEPublicKey != nil || g.calls != 0 {
		t.Fatalf("want %q, no fetch: %v (%d fetches)", want, err, g.calls)
	}
}

// vm-v1 (2026-11-21: the Google fallback ready to run, off): a client turns the Google Cloud sets on only
// through a signed trust list naming dstack-gcp, with no app update. A list without it, or no list, refuses a
// genuine GCP quote and asks Google nothing; with it the same quote passes, and its facts name the platform set
// (what a holder requires the policy's dstack-gcp item for).
func TestGCPOnlyBySignedTrustList(t *testing.T) {
	admin := testAdmin(t)
	a, nonce, p, _ := gcpPolicy(t, gcpRecordings[0])
	for _, c := range []struct {
		name      string
		platforms []string
		ok        bool
	}{{"no platforms", nil, false}, {"dstack only", []string{"dstack"}, false}, {"dstack and dstack-gcp", []string{"dstack", PlatformDstackGCP}, true}} {
		t.Run(c.name, func(t *testing.T) {
			list, err := ParseTrustList(signedList(t, admin, safety.TrustList{Seq: 3, Platforms: c.platforms}), 0, listNow)
			if err != nil {
				t.Fatal(err)
			}
			g := &googleFiles{}
			base := Policy{Compose: p.Compose, AppCompose: p.AppCompose, GoogleGetter: g, Now: p.Now, VerifyQuote: p.VerifyQuote, Machines: p.Machines}
			q, err := base.WithTrustList(list)
			if err != nil {
				t.Fatal(err)
			}
			res, err := Verify(context.Background(), a, nonce, q)
			if c.ok != (err == nil) {
				t.Fatalf("ok %v: %v", c.ok, err)
			}
			if !c.ok {
				if g.calls != 0 {
					t.Fatalf("Google asked %d times with the fallback off", g.calls)
				}
				return
			}
			if g.calls != 1 || res.Facts[FactPlatformSet] != PlatformDstackGCP {
				t.Fatalf("%d fetches, facts %v", g.calls, res.Facts)
			}
		})
	}
	// Phala quotes: TestPhalaUnchangedWithGCP (the same facts, so no platform set, and no fetch).
}
