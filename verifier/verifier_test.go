package verifier

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/tacyhq/tacy/internal/tdx"
	"github.com/tacyhq/tacy/proto"
	"github.com/tacyhq/tacy/release"
	"github.com/tacyhq/tacy/release/releasetest"
)

// offline parses the quote without Intel's chain, so the remaining checks can run without network. It also accepts
// the retired images and sets (dstack-0.5.9 and older); TestRetiredImagesRefused shows the default policy refuses
// them.
var offline = Policy{AllowStaleTCB: true, VerifyQuote: func(_ context.Context, raw []byte) (*tdx.Quote, error) { return tdx.Parse(raw) },
	ProdImages: allImages(), Boot: allSets()}

func allImages() map[string]string {
	m := map[string]string{}
	for k, v := range ProdImages {
		m[k] = v
	}
	for k, v := range RetiredImages {
		m[k] = v
	}
	return m
}

func allSets() []BootMeasurement {
	return append(append([]BootMeasurement{}, BootMeasurements...), RetiredBootMeasurements...)
}

// Since 2026-10-17 only dstack-0.6.1 is accepted: a VM on a retired image fails the image check by default.
func TestRetiredImagesRefused(t *testing.T) {
	a, nonce, compose := load061(t)
	p := Policy{AllowStaleTCB: true, VerifyQuote: offline.VerifyQuote, Compose: compose,
		ProdImages: RetiredImages, Boot: RetiredBootMeasurements}
	if _, err := Verify(context.Background(), a, nonce, p); err == nil || !strings.Contains(err.Error(), "isn't a known production image") {
		t.Fatalf("an image outside the policy accepted: %v", err)
	}
	for h := range RetiredImages {
		if _, ok := ProdImages[h]; ok {
			t.Fatalf("retired image %s still accepted", h)
		}
	}
	if len(ProdImages) != 1 || ProdImages["ec43cb8c5e04b6bb6c53b33b16076a01d83d01f7f4b703f2f78a0d947d6247e6"] != "dstack-0.6.1" ||
		len(BootMeasurements) != 1 {
		t.Fatalf("accepted images %v, %d sets", ProdImages, len(BootMeasurements))
	}
}

// The pinned set is what the recorded VM booted with: the registers in its quote and in the tcb_info dstack reports
// next to it (unsigned, only a cross-check here).
func TestBootMeasurementsRecorded(t *testing.T) {
	a, _, _ := load061(t)
	checkBootRecorded(t, a, &BootMeasurements[0])
	for _, s := range allSets() {
		for _, h := range []string{s.MRTD, s.RTMR0, s.RTMR1, s.RTMR2} {
			if d, err := hex.DecodeString(h); err != nil || len(d) != 48 {
				t.Errorf("%s: bad register %q", s.Name, h)
			}
		}
		if d, err := hex.DecodeString(s.OSImage); err != nil || len(d) != 32 || s.Source == "" {
			t.Errorf("%s: bad OS image or no source", s.Name)
		}
		if _, ok := allImages()[s.OSImage]; !ok {
			t.Errorf("%s: OS image not in ProdImages or RetiredImages", s.Name)
		}
	}
}

// checkBootRecorded: a's quote matches want, and so does the tcb_info dstack reports next to it.
func checkBootRecorded(t *testing.T, a *proto.Attestation, want *BootMeasurement) {
	t.Helper()
	var q struct{ Quote string }
	json.Unmarshal(a.Quote, &q)
	raw, _ := hex.DecodeString(q.Quote)
	quote, err := tdx.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	m, err := matchBoot(quote, want.OSImage, allSets())
	if err != nil || m.Name != want.Name {
		t.Fatal(m, err)
	}
	var info struct {
		TcbInfo json.RawMessage `json:"tcb_info"`
	}
	json.Unmarshal(a.Info, &info)
	var tcbStr string
	if json.Unmarshal(info.TcbInfo, &tcbStr) == nil {
		info.TcbInfo = []byte(tcbStr)
	}
	var tcb map[string]any
	json.Unmarshal(info.TcbInfo, &tcb)
	if tcb["mrtd"] != want.MRTD || tcb["rtmr0"] != want.RTMR0 || tcb["rtmr1"] != want.RTMR1 || tcb["rtmr2"] != want.RTMR2 ||
		tcb["os_image_hash"] != want.OSImage {
		t.Fatalf("tcb_info %v", tcb)
	}
}

// testdata/attest-061.json is a real /attest response from a throwaway CVM on dstack-0.6.1 (Phala prod5,
// tdx.small, 2026-10-17), running an earlier compose (sha256 88eee3e3…, which it carries itself).
func load061(t *testing.T) (*proto.Attestation, []byte, []byte) {
	t.Helper()
	raw, err := os.ReadFile("../testdata/attest-061.json")
	if err != nil {
		t.Fatal(err)
	}
	var a proto.Attestation
	if err := json.Unmarshal(raw, &a); err != nil {
		t.Fatal(err)
	}
	n, _ := os.ReadFile("../testdata/attest-061.nonce")
	nonce, _ := hex.DecodeString(strings.TrimSpace(string(n)))
	return &a, nonce, []byte(attestedCompose(t, &a))
}

// attestedCompose is the docker compose in a's app-compose.json (unverified; Verify checks it against the quote).
func attestedCompose(t *testing.T, a *proto.Attestation) string {
	t.Helper()
	var info struct {
		TcbInfo json.RawMessage `json:"tcb_info"`
	}
	json.Unmarshal(a.Info, &info)
	var tcbStr string
	if json.Unmarshal(info.TcbInfo, &tcbStr) == nil {
		info.TcbInfo = []byte(tcbStr)
	}
	var tcb struct {
		AppCompose string `json:"app_compose"`
	}
	var ac struct {
		DockerComposeFile string `json:"docker_compose_file"`
	}
	if json.Unmarshal(info.TcbInfo, &tcb) != nil || json.Unmarshal([]byte(tcb.AppCompose), &ac) != nil {
		t.Fatal("no app compose")
	}
	return ac.DockerComposeFile
}

func TestRecorded061Offline(t *testing.T) {
	a, nonce, compose := load061(t)
	p := offline
	p.Compose = compose
	res, err := Verify(context.Background(), a, nonce, p)
	onlyImagesFailed(t, res, err)
	if res.Facts["OS image"] != "dstack-0.6.1" || res.Facts["boot measurements"] != BootMeasurements[0].Name ||
		res.Facts["pre-launch script"] != "Phala pre-launch script v0.0.20" || res.Facts["brain binary sha256"] == "" {
		t.Fatalf("facts %v", res.Facts)
	}
	checkBootRecorded(t, a, &BootMeasurements[0])
}

// dstack 0.5.5+ runs app-compose's init_script as root before dockerd; any non-empty one is refused. The test
// stands in for a VM that really booted with one: the compose-hash event and RTMR3 are made consistent with the
// edited app-compose.json, so only the init_script rule can fail.
func TestInitScriptRefused(t *testing.T) {
	for _, v := range []any{"echo hi", []string{"", "id"}, 42} {
		a, nonce, compose := load061(t)
		appCompose := withAppCompose(t, a, func(ac map[string]any) { ac["init_script"] = v })
		p := offline
		p.Compose = compose
		rtmr3 := recompose(t, a, appCompose)
		p.VerifyQuote = changeQuote(func(q *tdx.Quote) { q.Rtmrs[3] = rtmr3 })
		_, err := Verify(context.Background(), a, nonce, p)
		if err == nil || !strings.Contains(err.Error(), "init_script") {
			t.Fatalf("init_script %v: %v", v, err)
		}
	}
	for _, v := range []any{nil, "", []string{}, []string{""}} {
		a, nonce, compose := load061(t)
		appCompose := withAppCompose(t, a, func(ac map[string]any) { ac["init_script"] = v })
		p := offline
		p.Compose = compose
		rtmr3 := recompose(t, a, appCompose)
		p.VerifyQuote = changeQuote(func(q *tdx.Quote) { q.Rtmrs[3] = rtmr3 })
		res, err := Verify(context.Background(), a, nonce, p)
		onlyImagesFailed(t, res, err)
	}
}

// recompose sets a's compose-hash event to sha256(appCompose) and returns the RTMR3 the edited log replays to.
func recompose(t *testing.T, a *proto.Attestation, appCompose []byte) []byte {
	t.Helper()
	var q map[string]any
	json.Unmarshal(a.Quote, &q)
	ev, err := tdx.ParseEventLog(json.RawMessage(mustJSON(q["event_log"])))
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(appCompose)
	for i := range ev {
		if ev[i].IMR == 3 && ev[i].Event == "compose-hash" {
			ev[i].EventPayload, ev[i].Digest = hex.EncodeToString(h[:]), ""
		}
	}
	rt, err := tdx.ReplayRTMR3(ev)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(ev)
	q["event_log"] = string(b)
	a.Quote, _ = json.Marshal(q)
	return rt.RTMR3
}

func mustJSON(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}

// withAppCompose edits the app-compose.json in a's info and returns its new bytes.
func withAppCompose(t *testing.T, a *proto.Attestation, edit func(map[string]any)) []byte {
	t.Helper()
	var info map[string]any
	if json.Unmarshal(a.Info, &info) != nil {
		t.Fatal("info")
	}
	tcbRaw, _ := info["tcb_info"].(string)
	var tcb map[string]any
	json.Unmarshal([]byte(tcbRaw), &tcb)
	var ac map[string]any
	json.Unmarshal([]byte(tcb["app_compose"].(string)), &ac)
	edit(ac)
	appCompose, _ := json.Marshal(ac)
	tcb["app_compose"] = string(appCompose)
	b, _ := json.Marshal(tcb)
	info["tcb_info"] = string(b)
	a.Info, _ = json.Marshal(info)
	return appCompose
}

// changeQuote returns a quote verifier that parses (offline) and then changes the quote.
func changeQuote(f func(q *tdx.Quote)) func(context.Context, []byte) (*tdx.Quote, error) {
	return func(_ context.Context, raw []byte) (*tdx.Quote, error) {
		q, err := tdx.Parse(raw)
		if err == nil {
			f(q)
		}
		return q, err
	}
}

// The full check, with Intel's signature chain and PCS collateral (network). Skipped with -short.
func TestRecordedOnline(t *testing.T) {
	if testing.Short() {
		t.Skip("needs Intel PCS")
	}
	a, nonce, compose := load061(t)
	res, err := Verify(context.Background(), a, nonce, Policy{Compose: compose})
	onlyImagesFailed(t, res, err)
}

// onlyImagesFailed: the recordings run composes that built the binaries on the VM, from before the OCI images.
// Every check passes except the last, the image rule, and no key is returned.
func onlyImagesFailed(t *testing.T, res *Result, err error) {
	t.Helper()
	if err == nil || !strings.HasPrefix(err.Error(), ImagesCheck+": ") || res.HPKEPublicKey != nil {
		t.Fatalf("want only the image rule to fail: %v", err)
	}
	for i, c := range res.Checks {
		if c.OK != (i < len(res.Checks)-1) {
			t.Fatalf("check %d %q ok=%v (%s)", i, c.Name, c.OK, c.Detail)
		}
	}
	if !strings.Contains(err.Error(), `golang:1.27.2-alpine@sha256:f92b6ef800e499660581efdabdf25d9d817a9d124eaf900924f0504e7e27e12d" isn't name@sha256`) {
		t.Fatalf("refused for another reason: %v", err)
	}
}

// A VM running an image compose (this folder's compose.yaml, put into the 0.6.1 recording with its compose-hash
// event and RTMR3 made consistent) passes every check, and its images are facts.
func TestImageComposeOffline(t *testing.T) {
	a, nonce, _ := load061(t)
	compose, err := os.ReadFile("../compose.yaml")
	if err != nil {
		t.Fatal(err)
	}
	appCompose := withAppCompose(t, a, func(ac map[string]any) { ac["docker_compose_file"] = string(compose) })
	rtmr3 := recompose(t, a, appCompose)
	p := offline
	p.Compose = compose
	p.VerifyQuote = changeQuote(func(q *tdx.Quote) { q.Rtmrs[3] = rtmr3 })
	res, err := Verify(context.Background(), a, nonce, p)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Checks) != 16 || res.Checks[15].Name != ImagesCheck || hex.EncodeToString(res.HPKEPublicKey) != a.HPKEPublicKey {
		t.Fatalf("%d checks, last %q", len(res.Checks), res.Checks[len(res.Checks)-1].Name)
	}
	for _, svc := range []string{"setup", "agentd", "runner", "agentvm", "vaultd"} {
		if !strings.HasPrefix(res.Facts["image "+svc], "ghcr.io/tacyhq/tacy/") || !strings.Contains(res.Facts["image "+svc], "@sha256:") {
			t.Errorf("image %s: %q", svc, res.Facts["image "+svc])
		}
	}
	// The brain in gVisor (since v0.4.0): the runner's image is pinned like the others, and its sandbox is a fact.
	if !strings.HasPrefix(res.Facts["image runner"], "ghcr.io/tacyhq/tacy/runnerd@sha256:") || res.Facts["image brain"] != "" ||
		!strings.HasSuffix(res.Facts["brain sandbox"], "(systrap, rootless runsc), no network") || len(res.Facts["gvisor runsc sha256"]) != 64 ||
		!strings.Contains(res.Checks[15].Detail, "the brain in gVisor "+res.Facts["gvisor release"]) {
		t.Errorf("runner facts %v, detail %q", res.Facts, res.Checks[15].Detail)
	}
	// The same VM with one image's digest swapped for a tag: compose-hash and RTMR3 consistent again, and refused
	// by the image rule even with that compose expected.
	i := strings.Index(string(compose), "\n    image: ")
	if r := strings.Index(string(compose), "\n  runner:\n    image: "); r > 0 {
		i = r + len("\n  runner:") // the runner's image (runnerd and gVisor) is the one swapped
	}
	j := i + strings.Index(string(compose[i:]), "@sha256:")
	tagged := string(compose[:j]) + ":latest" + string(compose[j+len("@sha256:")+64:])
	appCompose = withAppCompose(t, a, func(ac map[string]any) { ac["docker_compose_file"] = tagged })
	rtmr3 = recompose(t, a, appCompose)
	p.Compose = []byte(tagged)
	res, err = Verify(context.Background(), a, nonce, p)
	if err == nil || !strings.Contains(err.Error(), "isn't name@sha256") || res.HPKEPublicKey != nil {
		t.Fatalf("tagged image accepted: %v", err)
	}
}

func flip(b []byte) []byte {
	c := append([]byte{}, b...)
	c[len(c)-1] ^= 1
	return c
}

func otherKey() string {
	k, _ := ecdh.X25519().GenerateKey(rand.Reader)
	return hex.EncodeToString(k.PublicKey().Bytes())
}

func TestTamper(t *testing.T) {
	cases := []struct {
		name, want string
		edit       func(a *proto.Attestation, nonce *[]byte, p *Policy)
	}{
		{"another HPKE key (key binding)", "report_data", func(a *proto.Attestation, _ *[]byte, _ *Policy) {
			a.HPKEPublicKey = otherKey()
		}},
		{"another nonce (replayed quote)", "nonce", func(a *proto.Attestation, n *[]byte, _ *Policy) {
			*n = make([]byte, 32)
			a.Nonce = hex.EncodeToString(*n)
		}},
		{"response for a different nonce", "echoes a different nonce", func(_ *proto.Attestation, n *[]byte, _ *Policy) {
			*n = make([]byte, 32)
		}},
		{"modified compose (one byte)", "compose differs", func(_ *proto.Attestation, _ *[]byte, p *Policy) {
			c := append([]byte{}, p.Compose...)
			c[len(c)/2] ^= 1
			p.Compose = c
		}},
		{"modified app-compose.json in the info", "compose-hash", func(a *proto.Attestation, _ *[]byte, _ *Policy) {
			a.Info = json.RawMessage(strings.Replace(string(a.Info), "agentvm", "agentvn", 1))
		}},
		{"dev OS image", "production image", func(_ *proto.Attestation, _ *[]byte, p *Policy) {
			p.ProdImages = map[string]string{}
		}},
		{"edited event log", "RTMR3", func(a *proto.Attestation, _ *[]byte, _ *Policy) {
			var q map[string]any
			json.Unmarshal(a.Quote, &q)
			var ev []map[string]any
			json.Unmarshal([]byte(q["event_log"].(string)), &ev)
			for _, e := range ev {
				if e["event"] == "compose-hash" {
					e["event_payload"] = strings.Repeat("0", 64)
					e["digest"] = ""
				}
			}
			b, _ := json.Marshal(ev)
			q["event_log"] = string(b)
			a.Quote, _ = json.Marshal(q)
		}},
		{"other firmware (MRTD)", "differs in MRTD (another OS image?)", func(_ *proto.Attestation, _ *[]byte, p *Policy) {
			p.VerifyQuote = changeQuote(func(q *tdx.Quote) { q.MrTd = flip(q.MrTd) })
		}},
		{"other VM size (RTMR0)", "differs in RTMR0 (another VM size", func(_ *proto.Attestation, _ *[]byte, p *Policy) {
			p.VerifyQuote = changeQuote(func(q *tdx.Quote) { q.Rtmrs[0] = flip(q.Rtmrs[0]) })
		}},
		{"other kernel (RTMR1)", "differs in RTMR1", func(_ *proto.Attestation, _ *[]byte, p *Policy) {
			p.VerifyQuote = changeQuote(func(q *tdx.Quote) { q.Rtmrs[1] = flip(q.Rtmrs[1]) })
		}},
		{"other initramfs, command line or root filesystem (RTMR2)", "differs in RTMR2", func(_ *proto.Attestation, _ *[]byte, p *Policy) {
			p.VerifyQuote = changeQuote(func(q *tdx.Quote) { q.Rtmrs[2] = flip(q.Rtmrs[2]) })
		}},
		{"pinned set is for another OS image", "event log reports OS image", func(_ *proto.Attestation, _ *[]byte, p *Policy) {
			b := BootMeasurements[0] // the recording's (dstack-0.6.1)
			b.OSImage = strings.Repeat("ab", 32)
			p.Boot = []BootMeasurement{b}
		}},
		{"no pinned sets", "no pinned boot measurements", func(_ *proto.Attestation, _ *[]byte, p *Policy) {
			p.Boot = []BootMeasurement{}
		}},
		{"unreviewed pre-launch script", "pre-launch script", func(_ *proto.Attestation, _ *[]byte, p *Policy) {
			p.PreLaunch = map[string]string{"00": "other"}
		}},
		{"platform local without the dev flag", "platform", func(a *proto.Attestation, _ *[]byte, _ *Policy) {
			a.Platform = "local"
		}},
		{"other wire format", "format", func(a *proto.Attestation, _ *[]byte, _ *Policy) {
			a.Version = "sealed-agent-vm/v0"
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a, nonce, compose := load061(t)
			p := offline
			p.Compose = compose
			c.edit(a, &nonce, &p)
			res, err := Verify(context.Background(), a, nonce, p)
			if err == nil {
				t.Fatal("tampered attestation accepted")
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Fatalf("failed for another reason: %v", err)
			}
			if res.HPKEPublicKey != nil {
				t.Fatal("a key was returned despite the failure")
			}
		})
	}
}

// load061Images is the 0.6.1 recording running this repo's compose.yaml (images by digest): its app-compose.json
// carries that compose, and the compose-hash event and RTMR3 are made consistent with it (offline only).
func load061Images(t *testing.T) (*proto.Attestation, []byte, []byte, func(context.Context, []byte) (*tdx.Quote, error)) {
	t.Helper()
	a, nonce, _ := load061(t)
	compose, err := os.ReadFile("../compose.yaml")
	if err != nil {
		t.Fatal(err)
	}
	appCompose := withAppCompose(t, a, func(ac map[string]any) { ac["docker_compose_file"] = string(compose) })
	rtmr3 := recompose(t, a, appCompose)
	return a, nonce, compose, changeQuote(func(q *tdx.Quote) { q.Rtmrs[3] = rtmr3 })
}

// Release mode: a VM running this repo's compose.yaml, released by a throwaway Sigstore that stands in for GitHub
// Actions + Sigstore's public-good instance.
func TestRelease(t *testing.T) {
	a, nonce, compose, vq := load061Images(t)
	sum := sha256.Sum256(compose)
	s, err := releasetest.New()
	if err != nil {
		t.Fatal(err)
	}
	signed := func(o releasetest.Options) []byte {
		if o.Subjects == nil {
			o.Subjects = map[string][]byte{release.Subject: sum[:]}
		}
		b, err := s.Bundle(o)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	policy := func(b []byte) Policy {
		p := offline
		p.VerifyQuote = vq
		p.Bundle = b
		p.Release = release.Policy{Trusted: s.Trusted()}
		return p
	}
	res, err := Verify(context.Background(), a, nonce, policy(signed(releasetest.Options{Version: "v0.3.1"})))
	if err != nil {
		t.Fatal(err)
	}
	if res.Facts["release"] != "v0.3.1" || res.Facts["docker compose sha256"] != hex.EncodeToString(sum[:]) || res.HPKEPublicKey == nil ||
		len(res.Checks) != 16 || res.Checks[15].Name != ImagesCheck || !strings.HasPrefix(res.Facts["image agentd"], "ghcr.io/tacyhq/tacy/agentd@sha256:") {
		t.Fatalf("facts %v", res.Facts)
	}
	// A signed release whose compose builds on the VM (the recording's own, as before v0.2.0): the signature holds,
	// the image rule refuses it.
	{
		a, nonce, old := load061(t)
		osum := sha256.Sum256(old)
		p := policy(signed(releasetest.Options{Version: "v0.3.1", Subjects: map[string][]byte{release.Subject: osum[:]}}))
		p.VerifyQuote = offline.VerifyQuote
		res, err := Verify(context.Background(), a, nonce, p)
		if err == nil || !strings.HasPrefix(err.Error(), ImagesCheck) || res.HPKEPublicKey != nil || res.Facts["release"] != "v0.3.1" {
			t.Fatalf("a release that builds on the VM: %v", err)
		}
	}

	other := sha256.Sum256([]byte("another compose"))
	cases := []struct {
		name, want string
		p          Policy
	}{
		{"no bundle", "no release bundle", policy(nil)},
		{"bundle for another compose", "artifact", policy(signed(releasetest.Options{Subjects: map[string][]byte{release.Subject: other[:]}}))},
		{"built from a branch", "certificate identity", policy(signed(releasetest.Options{Ref: "refs/heads/main"}))},
		{"another repo", "certificate identity", policy(signed(releasetest.Options{Repo: "someone/tacy"}))},
		{"older than the minimum", "rollback", func() Policy {
			p := policy(signed(releasetest.Options{Version: "v0.3.1"}))
			p.Release.MinVersion = "v0.4.0"
			return p
		}()},
		{"older than the newest the client has seen", "newest this client has seen", func() Policy {
			p := policy(signed(releasetest.Options{Version: "v0.3.1"}))
			p.Release.LastSeen = "v0.3.2"
			return p
		}()},
		{"not in the transparency log", "transparency log", policy(signed(releasetest.Options{NoTlog: true}))},
		{"production root (test bundle isn't Sigstore's)", "log", func() Policy {
			p := policy(signed(releasetest.Options{}))
			p.Release.Trusted = nil
			return p
		}()},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a, nonce, _, _ := load061Images(t)
			res, err := Verify(context.Background(), a, nonce, c.p)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("want %q, got %v", c.want, err)
			}
			if res.HPKEPublicKey != nil {
				t.Fatal("a key was returned despite the failure")
			}
		})
	}
}

func TestDockerCompose(t *testing.T) {
	a, _, compose := load061(t)
	dc, err := DockerCompose(a)
	if err != nil || dc != string(compose) {
		t.Fatalf("%v (%d bytes)", err, len(dc))
	}
}
