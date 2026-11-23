package verifier

import (
	"context"
	"strings"
	"testing"

	"github.com/tacyhq/tacy/internal/tdx"
)

// The Phala shapes: tdx.small, tdx.medium and tdx.large are one image on three VM sizes, so their sets
// differ only in RTMR0, and a quote is labelled with the set its registers match, never the first one.

func phalaSet(t *testing.T, shape string) BootMeasurement {
	t.Helper()
	for _, b := range BootMeasurements {
		if strings.Contains(b.Name, "(Phala "+shape+",") {
			return b
		}
	}
	t.Fatalf("no %s set", shape)
	return BootMeasurement{}
}

func TestPhalaShapeSets(t *testing.T) {
	small, medium, large := phalaSet(t, "tdx.small"), phalaSet(t, "tdx.medium"), phalaSet(t, "tdx.large")
	for _, b := range []BootMeasurement{medium, large} {
		if b.OSImage != small.OSImage || b.MRTD != small.MRTD || b.RTMR1 != small.RTMR1 || b.RTMR2 != small.RTMR2 {
			t.Errorf("%s differs from tdx.small's set in more than RTMR0", b.Name)
		}
		if b.RTMR0 == small.RTMR0 || len(b.RTMR0) != 96 || GCPShaped(b) != "" || retiredBoot(b.RTMR1, b.RTMR2) != "" {
			t.Errorf("%s: RTMR0 %s", b.Name, b.RTMR0)
		}
		if !strings.Contains(b.Source, "dstack-mr") {
			t.Errorf("%s: source %q", b.Name, b.Source)
		}
	}
	if medium.RTMR0 == large.RTMR0 {
		t.Fatal("tdx.medium and tdx.large share RTMR0")
	}
}

// The genuine tdx.small quote (key provider none, the release's app-compose made consistent) with only its RTMR0
// changed: each shape's RTMR0 passes as that shape's set; anything else, or a shape's RTMR0 beside another image's
// kernel or Google's firmware, is refused at the boot measurements.
func TestPhalaShapeRTMR0(t *testing.T) {
	compose := composeYAML(t)
	release, err := ReleaseAppCompose(compose, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	medium, large := phalaSet(t, "tdx.medium"), phalaSet(t, "tdx.large")
	retired := RetiredBootMeasurements[len(RetiredBootMeasurements)-1] // 0.6.4
	flipped := mustHex(t, medium.RTMR0)
	flipped[47] ^= 1
	run := func(t *testing.T, edit func(q *tdx.Quote)) (*Result, error) {
		t.Helper()
		a, nonce, _, _ := loadNone(t, noneRecordings[0])
		setAppComposeRaw(t, a, release)
		rtmr3 := recompose(t, a, release)
		rd := agentLabel(t, a, nonce, HasUnlockd(string(compose)))
		p := Policy{AllowStaleTCB: true, Compose: compose, AppCompose: release, VerifyQuote: changeQuote(func(q *tdx.Quote) {
			q.Rtmrs[3] = rtmr3
			if rd != nil {
				q.ReportData = rd
			}
			edit(q)
		})}
		return Verify(context.Background(), a, nonce, p)
	}
	for _, s := range []BootMeasurement{phalaSet(t, "tdx.small"), medium, large} {
		t.Run(s.Name, func(t *testing.T) {
			res, err := run(t, func(q *tdx.Quote) { q.Rtmrs[0] = mustHex(t, s.RTMR0) })
			if err != nil {
				t.Fatal(err)
			}
			if res.Facts["boot measurements"] != s.Name || res.Facts["OS image"] != "dstack-0.6.5" || res.Facts["RTMR0"] != s.RTMR0 {
				t.Fatalf("facts %v", res.Facts)
			}
		})
	}
	for name, c := range map[string]struct {
		edit func(q *tdx.Quote)
		want string
	}{
		"tdx.medium's RTMR0 one bit off": {func(q *tdx.Quote) { q.Rtmrs[0] = flipped }, "differs in RTMR0 (another VM size or VM configuration?)"},
		"tdx.large's RTMR0 with 0.6.4's kernel and command line": {func(q *tdx.Quote) {
			q.Rtmrs[0], q.Rtmrs[1], q.Rtmrs[2] = mustHex(t, large.RTMR0), mustHex(t, retired.RTMR1), mustHex(t, retired.RTMR2)
		}, "match no pinned set"},
		"tdx.medium's RTMR0 on 0.5.9's firmware": {func(q *tdx.Quote) {
			q.Rtmrs[0], q.MrTd = mustHex(t, medium.RTMR0), mustHex(t, RetiredBootMeasurements[0].MRTD)
		}, "match no pinned set"},
		"Google c3-standard-4's RTMR0 on Phala's firmware": {func(q *tdx.Quote) {
			q.Rtmrs[0] = mustHex(t, GCPBootMeasurements[0].RTMR0)
		}, "differs in RTMR0"},
		"tdx.large's RTMR0 in RTMR1 and RTMR0 swapped": {func(q *tdx.Quote) {
			q.Rtmrs[0], q.Rtmrs[1] = q.Rtmrs[1], mustHex(t, large.RTMR0)
		}, "match no pinned set"},
	} {
		t.Run(name, func(t *testing.T) {
			res, err := run(t, c.edit)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("want %q: %v", c.want, err)
			}
			if res != nil && res.Facts["boot measurements"] != "" {
				t.Fatalf("labelled %q", res.Facts["boot measurements"])
			}
		})
	}
}

// A policy with its own boot sets (a signed key-service policy's, or a client's trust list replacing nothing) gets
// only those: the built-in bigger shapes aren't added behind its back.
func TestPhalaShapeOwnSets(t *testing.T) {
	compose := composeYAML(t)
	release, err := ReleaseAppCompose(compose, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	a, nonce, _, _ := loadNone(t, noneRecordings[0])
	setAppComposeRaw(t, a, release)
	rtmr3 := recompose(t, a, release)
	rd := agentLabel(t, a, nonce, HasUnlockd(string(compose)))
	medium := phalaSet(t, "tdx.medium")
	p := Policy{AllowStaleTCB: true, Compose: compose, AppCompose: release, Boot: []BootMeasurement{phalaSet(t, "tdx.small")},
		VerifyQuote: changeQuote(func(q *tdx.Quote) {
			q.Rtmrs[3], q.Rtmrs[0] = rtmr3, mustHex(t, medium.RTMR0)
			if rd != nil {
				q.ReportData = rd
			}
		})}
	if _, err := Verify(context.Background(), a, nonce, p); err == nil || !strings.Contains(err.Error(), "differs in RTMR0") {
		t.Fatalf("a tdx.medium quote under a tdx.small-only policy: %v", err)
	}
}
