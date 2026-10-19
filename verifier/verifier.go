// Package verifier checks an agent VM's attestation (proto.Attestation) before anything is sent to it:
//
//   - genuine Intel TDX quote: Intel signature chain, PCS collateral, revocation, debug off, TCB status
//   - report_data = proto.ReportData(our nonce, the HPKE key in the response): the key requests get encrypted to
//     was generated inside this TD for this boot
//   - dstack's event log replays to RTMR3, and its compose-hash event equals sha256(app-compose.json)
//   - the OS image (os-image-hash event) is a production dstack image, not a dev one (dev allows debug access)
//   - the boot measurements (MRTD, RTMR0-2: firmware, its configuration and the VM shape, kernel, command line
//     with the root filesystem hash, initramfs) are one of the pinned sets (BootMeasurements), for that OS image
//   - app-compose.json: a reviewed pre-launch script, the docker-compose runner, expected env names only
//   - the docker compose the VM runs (which names every image by digest) is a signed release: a Sigstore bundle
//     from this repo's release workflow on a version tag, in Sigstore's public log, for exactly
//     sha256(docker compose), at least release.MinVersion (package release)
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
)

// ProdImages are Phala's non-dev dstack OS images we accept, by os-image-hash (phala os-images). This label check
// comes first for a clear error on a dev image; what binds the image is BootMeasurements (MRTD, RTMR0-2), which
// also has to list the image. Only 0.6.1 since 2026-10-17 (the live CVM moved to it with the gateway/vault
// release; RetiredImages are the ones dropped then).
var ProdImages = map[string]string{
	"ec43cb8c5e04b6bb6c53b33b16076a01d83d01f7f4b703f2f78a0d947d6247e6": "dstack-0.6.1",
}

// RetiredImages were accepted before 2026-10-17 and are refused now (RetiredBootMeasurements has their sets).
var RetiredImages = map[string]string{
	"bd369a8c2f9edb2b52dad48ac8e0b32dde5f1337c423a506b48d07403a7d8033": "dstack-0.5.9",
	"6427f4f5ded88b72d326bd973e581c1689c5080c6444a0cf90fec7d9e4c8b92a": "dstack-0.5.8",
	"8409e2a24ea8325f3ea45d7c50622c952a8a4a961ffc139f5d9a81c4e47bd744": "dstack-0.6.0",
}

// PreLaunchScripts are Phala pre-launch scripts we accept, by sha256. Phala adds this script to app-compose.json
// (so the compose hash covers it) and dstack runs it as root before the containers start, so it must be pinned as
// strictly as the compose: v0.0.20 does registry login, image prune/pull, root password and SSH keys from
// user_config. Reviewed 2026-10-13; a new version must be read before it is added here.
var PreLaunchScripts = map[string]string{
	"982181610f70be9087b1c69b36b719b47b82d37fcef8acc9289ed3bb3095ffe8": "Phala pre-launch script v0.0.20",
}

// Envs are the only environment variable names the CVM may receive from the deployer (encrypted env).
var Envs = []string{"TINFOIL_API_KEY", "BRAVE_SEARCH_API_KEY", "TAVILY_API_KEY", "EXA_API_KEY", "SEARCH_PROVIDER", "AGENT_VM_TOKEN"}

// Policy is what the verifier requires.
type Policy struct {
	// Bundle is the Sigstore bundle (JSON) that proves the VM's docker compose is a signed release (see package
	// release; GitHub serves it at release.AttestationsURL for the compose's sha256). Required unless Compose is set.
	Bundle []byte
	// Release is what the signed release must satisfy; the zero value is the pinned production policy.
	Release release.Policy
	// Compose, if set, switches to the older exact mode: the VM must run exactly this compose.yaml, and Bundle is
	// ignored. Deprecated: kept until every client passes release bundles.
	Compose         []byte
	ProdImages      map[string]string // allowed os-image-hash values; nil = ProdImages
	AllowStaleTCB   bool              // accept a TCB status other than UpToDate
	SkipAttestation bool              // development only: accept platform "local" with no quote
	AllowE2EDiag    bool              // test tools only: accept the e2e overlay's diag service (ComposeImagesE2E)
	PreLaunch       map[string]string // allowed pre-launch script sha256s; nil = PreLaunchScripts
	Boot            []BootMeasurement // allowed MRTD/RTMR0-2 sets; nil = BootMeasurements
	// VerifyQuote checks a raw quote; nil = tdx.VerifyWith(Getter, Now) (needs Intel PCS). Tests replace it.
	VerifyQuote func(ctx context.Context, raw []byte) (*tdx.Quote, error)
	// Getter fetches Intel PCS collateral; nil = net/http straight to Intel. The browser (WebAssembly) build passes
	// one that goes through the chat's same-origin relay; Intel's signatures on the collateral are still checked.
	Getter trust.HTTPSGetter
	// Now is when certificates and collateral must be valid; zero = now. Only tests set it (recorded collateral).
	Now time.Time
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
	r.Facts["app id"] = rt.Values["app-id"]
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

	var ac struct {
		DockerComposeFile string          `json:"docker_compose_file"`
		PreLaunchScript   *string         `json:"pre_launch_script"`
		InitScript        json.RawMessage `json:"init_script"`
		Runner            string          `json:"runner"`
		AllowedEnvs       []string        `json:"allowed_envs"`
		PublicLogs        bool            `json:"public_logs"`
		KMSEnabled        bool            `json:"kms_enabled"`
	}
	err = json.Unmarshal([]byte(tcb.AppCompose), &ac)
	if !r.add("parse app-compose.json", err, "") {
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
	for _, e := range ac.AllowedEnvs {
		if err == nil && !slices.Contains(Envs, e) {
			err = fmt.Errorf("deployer may set env %s", e)
		}
	}
	if !r.add("app-compose: reviewed pre-launch script, no init script, docker-compose runner, expected env names only", err,
		fmt.Sprintf("%s; envs %v", preName, ac.AllowedEnvs)) {
		return failed()
	}
	r.Facts["public logs"] = fmt.Sprint(ac.PublicLogs)
	r.Facts["pre-launch script"] = preName
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
		var rel *release.Release
		err = errors.New("no release bundle given")
		if len(p.Bundle) > 0 {
			rel, err = release.Verify(p.Bundle, sum[:], p.Release)
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
		if !r.add("docker compose is a signed release ("+p.Release.Identity()+"vX.Y.Z, in Sigstore's public log, version >= "+p.Release.Minimum()+")",
			err, detail) {
			return failed()
		}
	}
	if !r.checkImages(ac.DockerComposeFile, p.AllowE2EDiag) {
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
