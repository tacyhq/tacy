// Package verifier checks an agent VM's attestation (proto.Attestation) before anything is sent to it:
//
//   - genuine Intel TDX quote: Intel signature chain, PCS collateral, revocation, debug off, TCB status
//   - report_data = proto.ReportData(our nonce, the HPKE key in the response): the key requests get encrypted to
//     was generated inside this TD for this boot
//   - dstack's event log replays to RTMR3, and its compose-hash event equals sha256(app-compose.json)
//   - the OS image (os-image-hash event) is a production dstack image, not a dev one (dev allows debug access)
//   - the boot measurements (MRTD, RTMR0-2: firmware, its configuration and the VM shape, kernel, command line
//     with the root filesystem hash, initramfs) are one of the pinned sets (BootMeasurements), for that OS image
//   - the VM's keys are made inside it at boot (key provider none), or in the explicit KMS fallback come from a
//     pinned dstack KMS root (KMSRoots, the attested key-provider event): never keys a provider can derive at will
//   - app-compose.json: a reviewed pre-launch script, the docker-compose runner, no deployer env
//   - app-compose.json is exactly the release's, after a check of each setting on its own (appcompose.go: no
//     deployer env, no swap, nothing public, only port 8080, secure time, ephemeral data disk). In release mode the
//     pin is ReleaseAppCompose of the docker compose the VM runs, so it is the signed release's app-compose.json
//     exactly; in the older exact mode it is Policy.AppCompose
//   - the Tacy KMS the compose names (-kms-key) is a pinned one (KMSIDs or a signed trust list)
//   - a signed trust list (trustlist.go, Policy.WithTrustList) may add OS images, boot sets, pre-launch scripts, KMS
//     ids and signed VM releases to the built-in ones, never remove one, and may raise the release floor
//   - the docker compose the VM runs (which names every image by digest) is a signed release: a Sigstore bundle
//     from this repo's release workflow on a version tag, in Sigstore's public log, for exactly
//     sha256(docker compose), at least release.MinVersion (package release) and the trust list's floor. The bundle
//     is Policy.Bundle, or, when none is given, one a trust list's release names for that compose (Policy.Releases)
//   - the docker compose pins every container to an image digest (name@sha256, no tag, no build:, extends: or
//     include:), so the compose hash covers exactly the code that runs (ComposeImages)
//
// The older mode, Policy.Compose, instead requires one exact compose.yaml given by the caller. It stays until every
// client passes release bundles, then goes.
//
// It is a library so the same code can run in Go programs and, compiled to WebAssembly, in the browser.
package verifier

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/google/go-tdx-guest/verify/trust"

	"github.com/tacyhq/tacy/internal/tdx"
	"github.com/tacyhq/tacy/proto"
	"github.com/tacyhq/tacy/release"
	"github.com/tacyhq/tacy/safety"
)

// ProdImages are Phala's non-dev dstack OS images we accept, by os-image-hash (phala os-images). This label check
// comes first for a clear error on a dev image; what binds the image is BootMeasurements (MRTD, RTMR0-2), which
// also has to list the image. Only 0.6.5 since 2026-11-20 (Phala moved the live CVM to it, with its KMS's new root,
// off 0.6.4; 0.6.4 had replaced 0.6.1 on 2026-11-15 for GHSA-c79w-3x5w-gmm5).
var ProdImages = map[string]string{
	"4771a29e03e93f0e2d5e37174cd8bb1112942c9689deb36b16c5df9e183d8623": "dstack-0.6.5",
}

// RetiredImages were accepted once and are refused now (RetiredBootMeasurements has their sets): 0.5.8, 0.5.9 and
// 0.6.0 since 2026-10-17, 0.6.1 since 2026-11-15 (GHSA-c79w-3x5w-gmm5), 0.6.4 since 2026-11-20 (the live CVM's disk
// moved to the KMS's new root, which only a 0.6.5 guest migrates to).
var RetiredImages = map[string]string{
	"feff3645893ad910d4f0e06d8f553cf80a7c9fede2ce0698fa63116283260366": "dstack-0.6.4",
	"ec43cb8c5e04b6bb6c53b33b16076a01d83d01f7f4b703f2f78a0d947d6247e6": "dstack-0.6.1",
	"bd369a8c2f9edb2b52dad48ac8e0b32dde5f1337c423a506b48d07403a7d8033": "dstack-0.5.9",
	"6427f4f5ded88b72d326bd973e581c1689c5080c6444a0cf90fec7d9e4c8b92a": "dstack-0.5.8",
	"8409e2a24ea8325f3ea45d7c50622c952a8a4a961ffc139f5d9a81c4e47bd744": "dstack-0.6.0",
}

// KMSRoots are the dstack KMS roots a VM may take its keys from, by key-provider id: the KMS root CA's public key
// (P-256 SubjectPublicKeyInfo, DER, hex) that the guest checked the KMS's answer against and measured into RTMR3
// ("key-provider" event) before it used the keys. Every key the VM has (disk, encrypted env, dstack GetKey) derives
// from that root, so a VM served by another root, such as Phala's root from before its 2026-11-06 rotation (retired
// with the rotation), is refused. Since the app-compose pin, only for the
// explicit KMS fallback (Policy.KMSFallback, appcompose.go): a release makes its keys in the VM (key_provider none).
var KMSRoots = map[string]string{
	"3059301306072a8648ce3d020106082a8648ce3d03010703420004e8e325a477b0bf22800dc927a46c68638938d283fe73d1f9028eeac7028193f3470122193875f598b7addc503e534712ab437b4120776bbac32ddf8897f844ee": "Phala KMS, root since 2026-11-06",
}

// RetiredKMSRoots were accepted once and are refused now: Phala's KMS root before its 2026-11-06 rotation (the live
// CVM's until 2026-11-20).
var RetiredKMSRoots = map[string]string{
	"3059301306072a8648ce3d020106082a8648ce3d030107034200048844eb42ccdf8c52fd4f174f362fcb9bbd19c45fd48f1edec2d8f1ca23536ec1a74021b4cee610c074f8294d431b2b7fee2c39e5333fdaf0a4522d43fb159d9f": "Phala KMS, root until 2026-11-06",
}

// KMSCheck is the name of the key-provider check (the chat maps its "keys made inside the VM" prefix to "kms").
const KMSCheck = "keys made inside the VM, or in the KMS fallback from a pinned dstack KMS root (attested key-provider event)"

// PreLaunchScripts are Phala pre-launch scripts we accept, by sha256. Phala adds this script to app-compose.json
// (so the compose hash covers it) and dstack runs it as root before the containers start, so it must be pinned as
// strictly as the compose: v0.0.20 does registry login, image prune/pull, root password and SSH keys from
// user_config. Reviewed 2026-10-13; a new version must be read before it is added here.
//
// None since the app-compose pin (2026-11-20): a release runs no pre-launch script (it sends pre_launch_script "", so
// Phala adds none of its own), and any script fails. A signed trust list can add a reviewed one.
var PreLaunchScripts = map[string]string{}

// RetiredPreLaunchScripts were accepted once: Phala's v0.0.20 (registry login, image prune/pull, root password and
// SSH keys from user_config), from 2026-10-13 until the app-compose pin. Kept for tests on older recordings.
var RetiredPreLaunchScripts = map[string]string{
	"982181610f70be9087b1c69b36b719b47b82d37fcef8acc9289ed3bb3095ffe8": "Phala pre-launch script v0.0.20",
}

// AppComposeCheck is the check of app-compose.json's other settings. The chat names a failure by its "app-compose:"
// prefix (the chat's verifier-core.ts), so the rest of the name may grow.
const AppComposeCheck = "app-compose: reviewed pre-launch script, no init script, docker-compose runner, no deployer env, container logs not public"

// Envs were the environment variable names a CVM could receive from the deployer (Phala's encrypted env), accepted
// only for recordings from before app-compose pinning (tests). Now allowed_envs must be empty: secrets reach the VM
// sealed to its attested key, never through a provider's env.
var Envs = []string{"TINFOIL_API_KEY", "BRAVE_SEARCH_API_KEY", "TAVILY_API_KEY", "EXA_API_KEY", "SEARCH_PROVIDER", "AGENT_VM_TOKEN"}

// Policy is what the verifier requires.
type Policy struct {
	// Bundle is the Sigstore bundle (JSON) that proves the VM's docker compose is a signed release (see package
	// release; GitHub serves it at release.AttestationsURL for the compose's sha256). Unless Compose is set, it is
	// required, or one of Releases' bundles for the attested compose (ReleaseBundles) must verify.
	Bundle []byte
	// Release is what the signed release must satisfy; the zero value is the pinned production policy.
	Release release.Policy
	// Compose, if set, switches to the older exact mode: the VM must run exactly this compose.yaml, and Bundle is
	// ignored. Deprecated: kept until every client passes release bundles.
	Compose []byte
	// AppCompose is the release's app-compose.json (ReleaseAppCompose); the CVM's must be these bytes. In release
	// mode, when neither it nor AppComposeSHA256 is set, it is ReleaseAppCompose of the attested docker compose (in
	// the KMSFallback mode), which the bundle then proves is a signed release.
	AppCompose []byte
	// AppComposeSHA256 are pinned app-compose.json hashes (hex), accepted besides AppCompose's: kmsd pins its releases
	// by hash (its admin-signed policy). The key mode is then read from the attested file.
	AppComposeSHA256 []string
	Port             int               // the only port the gateway may forward (port_policy); 0 = AppPort (8080)
	Services         []string          // the services a docker compose may have; nil = ReleaseServices (the agent VM's)
	KMSFallback      bool              // accept a release whose app-compose takes keys from a pinned KMS root (not "none")
	ProdImages       map[string]string // allowed os-image-hash values; nil = ProdImages
	AllowStaleTCB    bool              // accept a TCB status other than UpToDate
	SkipAttestation  bool              // development only: accept platform "local" with no quote
	AllowE2EDiag     bool              // test tools only: accept the e2e overlay's diag service (ComposeImagesE2E)
	PreLaunch        map[string]string // allowed pre-launch script sha256s; nil = PreLaunchScripts
	Boot             []BootMeasurement // allowed MRTD/RTMR0-2 sets; nil = BootMeasurements
	KMSRoots         map[string]string // allowed key-provider ids (KMS root CA keys); nil = KMSRoots
	KMSIDs           map[string]string // allowed Tacy KMS ids a compose may name (-kms-key); nil = KMSIDs
	// ReleaseFloor (vX.Y.Z) is the oldest signed VM release the release mode accepts on top of Release's minimum
	// (a trust list's vm_release_floor); unused by the exact mode.
	ReleaseFloor string
	// Releases are signed VM releases (a trust list's releases, MergeReleases) whose bundles a release-mode verifier
	// may look up for the attested compose (ReleaseBundles), each verified as a built-in one; the release mode tries
	// them when Bundle is empty. Unused by the exact mode.
	Releases []safety.TrustRelease
	// VerifyQuote checks a raw quote; nil = tdx.VerifyWith(Getter, Now) (needs Intel PCS). Tests replace it.
	VerifyQuote func(ctx context.Context, raw []byte) (*tdx.Quote, error)
	// Getter fetches Intel PCS collateral; nil = net/http straight to Intel. The browser (WebAssembly) build passes
	// one that goes through the chat's same-origin relay; Intel's signatures on the collateral are still checked.
	Getter trust.HTTPSGetter
	// Now is when certificates and collateral must be valid; zero = now. Only tests set it (recorded collateral).
	Now time.Time
	// legacy (tests only) checks recordings from before app-compose pinning: keys from a pinned KMS root, the old
	// env names, and no per-flag or pin checks, so the older recordings still exercise every other check.
	legacy bool
	// trust is the signed trust list WithTrustList added (its values are in the fields above), for the facts.
	trust *safety.TrustList
}

// Check is one verification step.
type Check struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail,omitempty"`
}

// Result is what a successful verification established.
type Result struct {
	HPKEPublicKey []byte            `json:"-"`
	Facts         map[string]string `json:"facts"`
	Checks        []Check           `json:"checks"`
}

func (r *Result) add(name string, err error, detail string) bool {
	c := Check{Name: name, OK: err == nil, Detail: detail}
	if err != nil {
		c.Detail = err.Error()
	}
	r.Checks = append(r.Checks, c)
	return c.OK
}

// Failed lists the failed checks.
func (r *Result) Failed() []Check {
	var f []Check
	for _, c := range r.Checks {
		if !c.OK {
			f = append(f, c)
		}
	}
	return f
}

// binaryPin is the service's binary hash in the compose: agentd's since the gateway/vault split, the single
// agentvm binary's before.
var binaryPin = regexp.MustCompile(`(?:AGENTD|AGENTVM)_SHA256=([0-9a-f]{64})`)

// brainPin is the brain's binary hash in the compose (its own container, harness/v1).
var brainPin = regexp.MustCompile(`BRAIN_SHA256=([0-9a-f]{64})`)

// gatewayPin and vaultPin are gatewayd's and vaultd's (their own containers since the split; absent before).
var (
	gatewayPin = regexp.MustCompile(`GATEWAYD_SHA256=([0-9a-f]{64})`)
	vaultPin   = regexp.MustCompile(`VAULTD_SHA256=([0-9a-f]{64})`)
)

// Verify checks att against nonce and policy. It returns an error (and the checks so far) on the first failure
// that makes later checks meaningless; on success, Result.HPKEPublicKey is the key to encrypt to.
func Verify(ctx context.Context, att *proto.Attestation, nonce []byte, p Policy) (*Result, error) {
	r := &Result{Facts: map[string]string{}}
	if p.trust != nil {
		r.Facts["trust list"] = fmt.Sprintf("signed list %d, expires %s", p.trust.Seq, p.trust.Expires.UTC().Format(time.RFC3339))
	} else {
		r.Facts["trust list"] = "none: only the values this verifier was built with"
	}
	failed := func() (*Result, error) {
		f := r.Failed()
		return r, fmt.Errorf("%s: %s", f[0].Name, f[0].Detail)
	}
	var err error
	if att.Version != proto.Version {
		err = fmt.Errorf("version %q, want %q", att.Version, proto.Version)
	}
	if !r.add("attestation format", err, att.Version) {
		return failed()
	}
	err = nil
	if att.Nonce != hex.EncodeToString(nonce) {
		err = errors.New("the response echoes a different nonce")
	}
	if !r.add("response is for our nonce", err, short(att.Nonce)) {
		return failed()
	}
	key, err := hex.DecodeString(att.HPKEPublicKey)
	if err == nil && len(key) != 32 {
		err = fmt.Errorf("HPKE key is %d bytes, want 32 (X25519)", len(key))
	}
	if err == nil && att.HPKESuite != proto.HPKESuite {
		err = fmt.Errorf("HPKE suite %q", att.HPKESuite)
	}
	if !r.add("HPKE key is X25519 with the expected suite", err, short(att.HPKEPublicKey)) {
		return failed()
	}
	r.Facts["hpke public key"] = att.HPKEPublicKey
	r.Facts["booted"] = att.Booted

	if att.Platform == "local" && p.SkipAttestation {
		r.add("attestation SKIPPED (development: platform local)", nil, "nothing about this server is verified")
		r.HPKEPublicKey = key
		return r, nil
	}
	err = nil
	if att.Platform != "dstack" {
		err = fmt.Errorf("platform %q, want dstack", att.Platform)
	}
	if !r.add("platform is dstack", err, att.Platform) {
		return failed()
	}

	var q struct {
		Quote    string          `json:"quote"`
		EventLog json.RawMessage `json:"event_log"`
	}
	if err := json.Unmarshal(att.Quote, &q); err != nil || q.Quote == "" {
		r.add("parse quote", fmt.Errorf("no quote in the response"), "")
		return failed()
	}
	raw, err := hex.DecodeString(q.Quote)
	if !r.add("parse quote", err, fmt.Sprintf("%d bytes", len(raw))) {
		return failed()
	}
	vq := p.VerifyQuote
	if vq == nil {
		vq = func(ctx context.Context, raw []byte) (*tdx.Quote, error) {
			return tdx.VerifyWith(ctx, raw, tdx.Options{Getter: p.Getter, Now: p.Now})
		}
	}
	quote, err := vq(ctx, raw)
	if quote != nil {
		r.Facts["TCB"] = quote.TcbStatus + " (QE " + quote.QeStatus + ", TCB date " + quote.TcbDate + ")"
		r.Facts["MRTD"] = hex.EncodeToString(quote.MrTd)
		for i := 0; i < 4; i++ {
			r.Facts[fmt.Sprintf("RTMR%d", i)] = hex.EncodeToString(quote.Rtmrs[i])
		}
	}
	if !r.add("genuine Intel TDX quote (signature chain, collateral, revocation, debug off)", err, "") {
		return failed()
	}
	err = nil
	if quote.Debug {
		err = errors.New("TD debug attribute set")
	} else if quote.TcbStatus != "UpToDate" && !p.AllowStaleTCB {
		err = fmt.Errorf("TCB status %s", quote.TcbStatus)
	}
	if !r.add("TCB up to date, debug off", err, quote.TcbStatus) {
		return failed()
	}
	err = nil
	if !bytes.Equal(quote.ReportData, proto.ReportData(nonce, key)) {
		err = errors.New("report_data doesn't bind our nonce and this HPKE key")
	}
	if !r.add("quote binds our nonce and the HPKE key (report_data)", err,
		`sha512("`+proto.Version+`" || 0x00 || nonce || hpke_key)`) {
		return failed()
	}

	var info struct {
		AppID   string          `json:"app_id"`
		TcbInfo json.RawMessage `json:"tcb_info"`
	}
	json.Unmarshal(att.Info, &info)
	var tcbStr string
	if json.Unmarshal(info.TcbInfo, &tcbStr) == nil {
		info.TcbInfo = []byte(tcbStr)
	}
	var tcb struct {
		AppCompose string `json:"app_compose"`
	}
	json.Unmarshal(info.TcbInfo, &tcb)
	ev, err := tdx.ParseEventLog(q.EventLog)
	if !r.add("parse event log", err, fmt.Sprintf("%d events", len(ev))) {
		return failed()
	}
	rt, err := tdx.CheckApp(quote, ev, []byte(tcb.AppCompose))
	if !r.add("event log replays to RTMR3; compose-hash event = sha256(app-compose.json)", err, "") {
		return failed()
	}
	// Attested (the replay equals the quote's RTMR3): the app id and this instance's id (kmsd's one-instance lease).
	r.Facts["app id"] = strings.ToLower(rt.Values["app-id"])
	r.Facts["instance id"] = strings.ToLower(rt.Values["instance-id"])
	r.Facts["compose hash"] = rt.Values["compose-hash"]
	kp, _ := hex.DecodeString(rt.Values["key-provider"])
	r.Facts["key provider"] = string(kp)

	images := p.ProdImages
	if images == nil {
		images = ProdImages
	}
	osHash := rt.Values["os-image-hash"]
	r.Facts["OS image hash"] = osHash
	name, ok := images[osHash]
	err = nil
	if !ok {
		err = fmt.Errorf("OS image %s isn't a known production image (dev images allow debug access)", short(osHash))
	}
	if !r.add("production dstack OS image (attested os-image-hash)", err, name) {
		return failed()
	}
	r.Facts["OS image"] = name

	sets := p.Boot
	if sets == nil {
		sets = BootMeasurements
	}
	bm, err := matchBoot(quote, osHash, sets)
	detail := ""
	if bm != nil {
		detail = bm.Name
		r.Facts["boot measurements"] = bm.Name
	}
	if !r.add("boot measurements (MRTD, RTMR0-2) are a pinned set: firmware, kernel, initramfs, root filesystem, VM size",
		err, detail) {
		return failed()
	}

	ac, err := parseAppCompose([]byte(tcb.AppCompose))
	if !r.add("parse app-compose.json", err, "") {
		return failed()
	}
	roots := p.KMSRoots
	if roots == nil {
		roots = KMSRoots
	}
	// The key mode is the release's (its pinned app-compose.json), as far as the policy allows it.
	mode, pinErr := KeyProviderKMS, error(nil)
	if !p.legacy {
		// Release mode: the pin is the app-compose.json a release of the attested docker compose is deployed with
		// (ReleaseAppCompose: this verifier's own settings, in the policy's key mode). The bundle check below proves
		// that docker compose is a signed release, so the whole app-compose.json is that release's, byte for byte.
		var releasePinErr error
		if p.Compose == nil && len(p.AppCompose) == 0 && len(p.AppComposeSHA256) == 0 {
			p.AppCompose, releasePinErr = ReleaseAppCompose([]byte(ac.DockerComposeFile), nil, p.KMSFallback)
		}
		var pinned *appCompose
		pinnedBytes := p.AppCompose
		if len(pinnedBytes) == 0 && len(p.AppComposeSHA256) > 0 {
			pinnedBytes = []byte(tcb.AppCompose) // pinned by hash: the pin check below decides whether it's one
		}
		if releasePinErr != nil {
			pinErr = fmt.Errorf("no release app-compose.json for this docker compose: %w", releasePinErr)
		} else if len(pinnedBytes) == 0 {
			pinErr = errors.New("no pinned app-compose.json (the release's) to check against")
		} else if pinned, pinErr = parseAppCompose(pinnedBytes); pinErr == nil {
			mode, pinErr = pinnedMode(pinned, p.KMSFallback)
		} else {
			pinErr = fmt.Errorf("the pinned app-compose.json doesn't parse: %w", pinErr)
		}
	}

	// The keys' source, measured by the guest (dstack-util) as the key-provider event {"name":…, "id":…}: "none" with
	// no id (a seed made inside the TD at boot), or in the KMS fallback "kms" with the KMS root CA key as its id.
	var provider struct {
		Name string `json:"name"`
		ID   string `json:"id"`
	}
	err = pinErr
	keysDetail := ""
	if err == nil && json.Unmarshal(kp, &provider) != nil {
		err = errors.New("no key-provider event (or not JSON)")
	}
	id := strings.ToLower(provider.ID)
	switch {
	case err != nil:
	case mode == KeyProviderNone:
		if provider.Name != KeyProviderNone || provider.ID != "" {
			err = fmt.Errorf("key provider %q, want none (keys made inside the VM at boot, never a provider's)", provider.Name)
		} else {
			keysDetail = "made inside the VM at boot (key provider none)"
			r.Facts["keys"] = keysDetail
		}
	case provider.Name != KeyProviderKMS:
		err = fmt.Errorf("key provider %q, want a dstack KMS", provider.Name)
	case roots[id] == "":
		err = fmt.Errorf("KMS root %s isn't a pinned one", short(id))
		if old, ok := RetiredKMSRoots[id]; ok {
			err = fmt.Errorf("KMS root %s is retired (%s)", short(id), old)
		}
	case !p.legacy && !strings.EqualFold(ac.KeyProviderID, id):
		err = fmt.Errorf("KMS root %s isn't the app-compose's key_provider_id", short(id))
	default:
		keysDetail = roots[id]
		r.Facts["KMS root"] = keysDetail
		r.Facts["keys"] = "from a pinned KMS root (fallback): " + keysDetail
	}
	if !r.add(KMSCheck, err, keysDetail) {
		return failed()
	}

	// Everything else in app-compose.json that changes what runs: the pre-launch script (root, before the
	// containers), the runner, and which deployer-supplied variables can reach the containers.
	pre := p.PreLaunch
	if pre == nil {
		pre = PreLaunchScripts
	}
	preName := "none"
	err = nil
	if ac.PreLaunchScript != nil && *ac.PreLaunchScript != "" {
		sum := sha256.Sum256([]byte(*ac.PreLaunchScript))
		var ok bool
		if preName, ok = pre[hex.EncodeToString(sum[:])]; !ok {
			err = fmt.Errorf("pre-launch script %s isn't a reviewed one", short(hex.EncodeToString(sum[:])))
		}
	}
	// init_script (dstack 0.5.5+, a string or up to five strings since 0.6.0) runs as root before dockerd on every
	// boot. We use none, so any is refused (Phala's dashboard could otherwise add one and still pass).
	if err == nil && !emptyInitScript(ac.InitScript) {
		err = errors.New("app-compose has an init_script (runs as root before the containers); we use none")
	}
	if err == nil && ac.Runner != "docker-compose" {
		err = fmt.Errorf("runner %q", ac.Runner)
	}
	if err == nil && !p.legacy {
		err = emptyEnvs(ac.AllowedEnvs)
	}
	for _, e := range ac.AllowedEnvs {
		if err == nil && p.legacy && !slices.Contains(Envs, e) {
			err = fmt.Errorf("deployer may set env %s", e)
		}
	}
	// public_logs publishes the containers' stdout and stderr on the host's dashboard and log API: an error message
	// or a stray print could carry what a person sent. Ours log no content, but nothing here could prove that of
	// every line, so a CVM with public logs fails (v0.16.0; before, it was only recorded as a fact).
	if err == nil && ac.PublicLogs {
		err = errors.New("app-compose has public_logs on (the containers' logs are published)")
	}
	r.Facts["public logs"] = fmt.Sprint(ac.PublicLogs) // also when the check fails: what it saw
	r.Facts["pre-launch script"] = preName
	if !r.add(AppComposeCheck, err, fmt.Sprintf("%s; envs %v; public logs %v", preName, ac.AllowedEnvs, ac.PublicLogs)) {
		return failed()
	}
	if !p.legacy {
		// Each flag on its own first, so a failure names it; then the whole file against the release's pin.
		port := p.Port
		if port == 0 {
			port = AppPort
		}
		ports := []int{port}
		err = nil
		if p.AllowE2EDiag {
			// Test tools only: the e2e overlay's diag service publishes its own port too (E2EAppCompose).
			var extra []int
			extra, err = E2EDiagPorts(ac.DockerComposeFile)
			ports = append(ports, extra...)
		}
		if err == nil {
			err = ac.checkFlags(mode, roots, ports)
		}
		detail := fmt.Sprintf("key provider %s; no swap; nothing public; only port %d; secure time", mode, port)
		if mode == KeyProviderNone {
			detail += "; ephemeral data disk"
		} else {
			detail += "; nothing on the disk (memory volumes only)"
		}
		r.Facts["key mode"] = mode
		if !r.add(AppComposeFlagsCheck, err, detail) {
			return failed()
		}
		sum := sha256.Sum256([]byte(tcb.AppCompose))
		got := hex.EncodeToString(sum[:])
		var pins []string
		if len(p.AppCompose) > 0 {
			w := sha256.Sum256(p.AppCompose)
			pins = append(pins, hex.EncodeToString(w[:]))
		}
		for _, h := range p.AppComposeSHA256 {
			pins = append(pins, strings.ToLower(h))
		}
		err = nil
		if !slices.Contains(pins, got) {
			want := make([]string, len(pins))
			for i, h := range pins {
				want[i] = short(h)
			}
			err = fmt.Errorf("app-compose.json sha256 %s, the release pins %s", short(got), strings.Join(want, " or "))
		}
		r.Facts["app-compose sha256"] = got
		if !r.add(AppComposePinCheck, err, "sha256 "+short(got)) {
			return failed()
		}
	}
	pin := ""
	if m := binaryPin.FindStringSubmatch(ac.DockerComposeFile); m != nil {
		pin = m[1]
		r.Facts["service binary sha256"] = pin
	}
	if m := brainPin.FindStringSubmatch(ac.DockerComposeFile); m != nil {
		r.Facts["brain binary sha256"] = m[1]
	}
	if m := gatewayPin.FindStringSubmatch(ac.DockerComposeFile); m != nil {
		r.Facts["gateway binary sha256"] = m[1]
	}
	if m := vaultPin.FindStringSubmatch(ac.DockerComposeFile); m != nil {
		r.Facts["vault binary sha256"] = m[1]
	}
	sum := sha256.Sum256([]byte(ac.DockerComposeFile))
	r.Facts["docker compose sha256"] = hex.EncodeToString(sum[:])
	if p.Compose != nil {
		err = nil
		if strings.TrimSpace(ac.DockerComposeFile) != strings.TrimSpace(string(p.Compose)) {
			err = errors.New("the CVM's docker compose differs from ours")
		}
		if err == nil && len(p.Compose) == 0 {
			err = errors.New("no expected compose given")
		}
		h := sha256.Sum256(p.Compose)
		detail := ""
		if pin != "" {
			detail = ", binary " + short(pin)
		}
		if !r.add("runs exactly our compose.yaml", err, "compose.yaml sha256 "+short(hex.EncodeToString(h[:]))+detail) {
			return failed()
		}
	} else {
		// A signed trust list's floor raises the minimum version, never lowers it.
		rp, floorErr := p.Release, error(nil)
		if p.ReleaseFloor != "" {
			floor, ferr := release.ParseVersion(p.ReleaseFloor)
			min, merr := release.ParseVersion(rp.Minimum())
			switch {
			case ferr != nil:
				floorErr = fmt.Errorf("release floor: %w", ferr)
			case merr != nil:
				floorErr = merr
			case min.Less(floor):
				rp.MinVersion = p.ReleaseFloor
			}
		}
		var rel *release.Release
		err = errors.New("no release bundle given")
		if floorErr != nil {
			err = floorErr
		} else if len(p.Bundle) > 0 {
			rel, err = release.Verify(p.Bundle, sum[:], rp)
		} else {
			// No bundle given: a signed trust list's release for this compose, each checked as a given one would be.
			for _, b := range p.ReleaseBundles(hex.EncodeToString(sum[:])) {
				r, e := release.Verify(b, sum[:], rp)
				if e == nil {
					rel, err = r, nil
					break
				}
				err = fmt.Errorf("the trust list's release for this compose: %w", e)
			}
		}
		detail := ""
		if rel != nil {
			detail = rel.Version + " (commit " + short(rel.Commit) + "), compose sha256 " + short(rel.ComposeSHA256)
			if pin != "" {
				detail += ", binary " + short(pin)
			}
			r.Facts["release"] = rel.Version
			r.Facts["release commit"] = rel.Commit
			r.Facts["release signer"] = rel.Identity
			r.Facts["release run"] = rel.RunURL
			r.Facts["release logged"] = rel.SignedAt.Format(time.RFC3339)
			r.Facts["release log index"] = fmt.Sprint(rel.LogIndex)
		}
		if !r.add("docker compose is a signed release ("+rp.Identity()+"vX.Y.Z, in Sigstore's public log, version >= "+rp.Minimum()+")",
			err, detail) {
			return failed()
		}
	}
	if !r.checkKMSID(ac.DockerComposeFile, cmpOr(p.KMSIDs, KMSIDs)) {
		return failed()
	}
	if !r.checkImages(ac.DockerComposeFile, p.AllowE2EDiag, p.Services) {
		return failed()
	}
	r.HPKEPublicKey = key
	return r, nil
}

// emptyInitScript: app-compose's init_script is absent, null, "" or a list of only "".
func emptyInitScript(raw json.RawMessage) bool {
	if len(raw) == 0 || string(raw) == "null" {
		return true
	}
	var one string
	if json.Unmarshal(raw, &one) == nil {
		return one == ""
	}
	var list []string
	if json.Unmarshal(raw, &list) != nil {
		return false
	}
	for _, s := range list {
		if s != "" {
			return false
		}
	}
	return true
}

func short(s string) string {
	if len(s) > 16 {
		return s[:16] + "…"
	}
	return s
}

// DockerCompose returns the docker compose in att's app-compose.json, unverified: only to look up its release
// bundle (release.AttestationsURL of its sha256) before calling Verify, which hashes the attested copy itself.
func DockerCompose(att *proto.Attestation) (string, error) {
	var info struct {
		TcbInfo json.RawMessage `json:"tcb_info"`
	}
	if err := json.Unmarshal(att.Info, &info); err != nil {
		return "", fmt.Errorf("attestation info: %w", err)
	}
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
	if json.Unmarshal(info.TcbInfo, &tcb) != nil || json.Unmarshal([]byte(tcb.AppCompose), &ac) != nil || ac.DockerComposeFile == "" {
		return "", errors.New("no docker compose in the attestation")
	}
	return ac.DockerComposeFile, nil
}
