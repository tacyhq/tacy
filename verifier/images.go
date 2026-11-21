package verifier

import (
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"
)

// digestRef is the only image reference a service may have: a full repository name (registry and at least one
// path component), then @sha256: and 64 hex digits. No tag (a tag can be moved; a digest names exactly one image),
// no variable (compose would interpolate it from the deployer's env).
var digestRef = regexp.MustCompile(`^[a-z0-9]+(?:[._-][a-z0-9]+)*(?::[0-9]+)?(?:/[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*)+@sha256:[0-9a-f]{64}$`)

// ReleaseServices are the services a release's compose may have: the setup step, agentd, the brain's runner,
// gatewayd (named agentvm), vaultd and unlockd (the split-key unlock; listed before any release has
// it, so clients accept that release without a rebuild). Anything else is code the release doesn't describe, unless
// a signed trust list names it (services).
//
// The tunnel runs in-container (cloudflared is gatewayd's child in agentvm, since 2026-11-21), so the
// confined variant's seventh service (cftunnel, branch vm-fix-b-cloudflared) isn't listed: a compose with it is
// refused unless a signed trust list names it.
var ReleaseServices = []string{"setup", "agentd", "runner", "agentvm", "vaultd", "unlockd"}

// E2EDiagService is the end-to-end test's diag service (cmd/e2e overlay): accepted only by ComposeImagesE2E, with
// its pid namespace (it kills processes to check crashes). Never in a release.
const E2EDiagService = "e2ediag"

// ComposeImages checks the docker compose a VM runs pins every container to an image digest, so the attested
// compose hash covers exactly the code that runs: one YAML document; only the release's services
// (ReleaseServices); every service has an image that is name@sha256:<64 hex> with no tag; no service has build:
// (code built on the VM from a context the hash doesn't cover) or extends:, and there is no top-level include: (both
// pull in another file); no service has more than its own container (servicePrivileges: not privileged, no host
// namespaces such as pid: host, which would let it see and signal every process of the VM, no added capabilities
// but setup's, no devices, no unconfined security options but the runner's seccomp, no configs or secrets); no
// command sets the e2e test's model faults (E2EModelFaultFlag). It returns each service's image.
// E2EModelFaultFlag is gatewayd's test-only flag for fake slow and overloaded models: accepted only by
// ComposeImagesE2E.
const E2EModelFaultFlag = "e2e-model-fault"

// E2EDiagFlag is gatewayd's test-only flag that puts the e2e overlay's diag service on the tunnel's ingress
// (gateway/cftunnel.DiagFlag: /e2e/diag/ to the diag's kill and disk-scan script; the release gate through the
// tunnel, the v1 design §7.4): accepted only by ComposeImagesE2E (Policy.AllowE2EDiag), which no production client,
// holder or policy sets.
const E2EDiagFlag = "e2e-diag"

func ComposeImages(compose string) (map[string]string, error) {
	return composeImages(compose, diagNone, nil)
}

// ComposeImagesE2E is ComposeImages that also accepts the e2e overlay's diag service with the bounded privileges of
// E2EDiagException (test tools and staging key services only, never the browser's verifier).
func ComposeImagesE2E(compose string) (map[string]string, error) {
	return composeImages(compose, diagE2E, nil)
}

// ComposeImagesE2ERoot is ComposeImagesE2E whose diag service may also have E2EDiagRootException (cmd/e2e fixb's
// push diag on a throwaway with no holders and no key service; Policy.AllowE2EDiagRoot).
func ComposeImagesE2ERoot(compose string) (map[string]string, error) {
	return composeImages(compose, diagRoot, nil)
}

// ComposeImagesFor is ComposeImages for another release's services (the key service's compose: kmsd).
func ComposeImagesFor(compose string, services []string) (map[string]string, error) {
	return composeImages(compose, diagNone, services)
}

// diagLevel is what the e2e diag service (E2EDiagService) may be: absent (every release, every production
// verifier), the e2e overlay's (E2EDiagException), or fixb's push diag (E2EDiagRootException).
type diagLevel int

const (
	diagNone diagLevel = iota
	diagE2E
	diagRoot
)

// The two named exceptions for the e2e diag service. Nothing else in a compose may have any of these privileges.
const (
	// E2EDiagException (Policy.AllowE2EDiag: test tools, a staging key service, staging holders): the httpd diag of
	// cmd/e2e overlay. Its pid namespace is the host's or the runner's (it kills processes for the crash checks), it
	// drops every capability and adds back at most KILL, DAC_READ_SEARCH and SYS_PTRACE, no-new-privileges, the
	// host's root read-only at /host (the plaintext-disk scan). No host network, no devices, no other security_opt.
	E2EDiagException = "e2e diag: pid host or service:runner; cap_drop ALL, cap_add KILL, DAC_READ_SEARCH, SYS_PTRACE at most"
	// E2EDiagRootException (Policy.AllowE2EDiagRoot too: cmd/e2e fixb only): the push diag of a Fix B throwaway
	// (cmd/e2epush), root in the host's pid and network namespaces with every capability, seccomp unconfined and
	// block-device cgroup rules (it enters PID 1's namespaces for docker, cryptsetup and zfs, and flips ciphertext on
	// the raw disk). No signed policy can grant it: a key service's and a holder's verifier never set it.
	E2EDiagRootException = "e2e push diag (fixb): pid and network host, cap_add ALL, seccomp unconfined, device cgroup rules"
)

// RunnerService is the brain's sandbox service (runnerd): gVisor needs seccomp unconfined in it.
const RunnerService = "runner"

// setupCaps are what setup may add back after cap_drop ALL: it makes the socket directories for each uid.
var setupCaps = []string{"CHOWN", "DAC_OVERRIDE", "FOWNER"}

// e2eDiagCaps are what E2EDiagException's diag may add back after cap_drop ALL.
var e2eDiagCaps = []string{"KILL", "DAC_READ_SEARCH", "SYS_PTRACE"}

// GatewaydService is gatewayd's service (it carries the VM's only network).
const GatewaydService = "agentvm"

// TunnelUIDFlag is gatewayd's flag for cloudflared's uid (review H1, 2026-11-21): with it, gatewayd's container starts
// as root with only SETUID and SETGID (GatewaydLaunchException), gatewayd's launcher (cmd/gatewayd/launcher.go)
// starts gatewayd itself as its own uid with no capabilities and cloudflared as this uid, and keeps the two
// capabilities only to start cloudflared again. A gatewayd without the launcher refuses the flag (an unknown flag
// stops it), so a compose that names it runs no gatewayd as root.
const TunnelUIDFlag = "tunnel-uid"

// GatewaydLaunchException is the one exception for gatewayd's container: user 0:0 and cap_add SETUID, SETGID at
// most after cap_drop ALL, no-new-privileges, only with -tunnel-uid in its command (and never with the confined
// variant's -tunnel-confined).
const GatewaydLaunchException = "gatewayd's launcher: user 0:0, cap_drop ALL, cap_add SETUID, SETGID at most, only with -tunnel-uid"

// gatewaydLaunchCaps are what GatewaydLaunchException's container may add back after cap_drop ALL.
var gatewaydLaunchCaps = []string{"SETUID", "SETGID"}

// DevFlags are flags of development and spike composes only (review L1): -dev-fixed-http turns off the holder-domain
// and admin-key checks for http:// fixed hosts; -tunnel-spike-routes adds test routes to the tunnel's ingress;
// -tunnel-confined is the confined spike variant's. A production verifier refuses a compose whose any command has
// one (the e2e levels accept them, as E2EModelFaultFlag).
var DevFlags = []string{"dev-fixed-http", "tunnel-spike-routes", "tunnel-confined"}

// ListenFlag is gatewayd's published-port flag: in a release with unlockd (v1: the tunnel is the only way in) a
// production verifier refuses it, and any published port but the e2e diag's (review L1). Older releases (the KMS
// ones, live before v1) publish 8080 and stay accepted, so clients keep verifying them.
const ListenFlag = "listen"

// commandArgs is a service's command and entrypoint as strings (a YAML list or a string, split on spaces).
func commandArgs(svc map[string]any) []string {
	var out []string
	for _, k := range []string{"entrypoint", "command"} {
		switch v := svc[k].(type) {
		case string:
			out = append(out, strings.Fields(v)...)
		case []any:
			for _, e := range v {
				out = append(out, fmt.Sprint(e))
			}
		}
	}
	return out
}

// hasFlag says whether args set flag name (-name, --name, -name=…, --name=…; Go's flag package takes all four).
func hasFlag(args []string, name string) bool {
	for _, a := range args {
		a = strings.TrimPrefix(strings.TrimPrefix(a, "-"), "-")
		if a == name || strings.HasPrefix(a, name+"=") {
			return true
		}
	}
	return false
}

// gatewaydLaunch: service n is gatewayd's container with GatewaydLaunchException's privileges (user 0:0, launch caps).
func gatewaydLaunch(n string, svc map[string]any) bool {
	args := commandArgs(svc)
	return n == GatewaydService && capsWithin(svc, gatewaydLaunchCaps) && hasFlag(args, TunnelUIDFlag) &&
		!hasFlag(args, "tunnel-confined")
}

// strs is a YAML list of strings (nil if v isn't one).
func strs(v any) ([]string, bool) {
	l, ok := v.([]any)
	if !ok {
		return nil, false
	}
	out := make([]string, 0, len(l))
	for _, e := range l {
		s, ok := e.(string)
		if !ok {
			return nil, false
		}
		out = append(out, s)
	}
	return out, true
}

// capsWithin: svc drops every capability and adds back only some of allowed.
func capsWithin(svc map[string]any, allowed []string) bool {
	drop, ok1 := strs(svc["cap_drop"])
	add, ok2 := strs(svc["cap_add"])
	if !ok1 || !ok2 || !slices.Equal(drop, []string{"ALL"}) {
		return false
	}
	for _, c := range add {
		if !slices.Contains(allowed, strings.TrimPrefix(strings.ToUpper(c), "CAP_")) {
			return false
		}
	}
	return true
}

// servicePrivileges refuses what would give service n more than its own container: host namespaces, added
// capabilities, devices, unconfined security options, another container's volumes, and configs or secrets (which
// can bind a host file). The release's own exceptions are named: setup's capabilities (setupCaps) and the runner's
// seccomp unconfined (gVisor). The e2e diag service's are E2EDiagException and E2EDiagRootException, by level.
func servicePrivileges(n string, svc map[string]any, level diagLevel) error {
	diag := n == E2EDiagService
	root := diag && level == diagRoot
	if p, ok := svc["privileged"]; ok && p != false {
		return fmt.Errorf("service %s is privileged", n)
	}
	if pid, ok := svc["pid"]; ok {
		switch {
		case root && pid == "host":
		case diag && level >= diagE2E && (pid == "host" || pid == "service:"+RunnerService):
		default:
			return fmt.Errorf("service %s sets pid: %v (it would share a process namespace)", n, pid)
		}
	}
	if nm, ok := svc["network_mode"]; ok {
		switch {
		case nm == "none" || nm == "bridge" || nm == "default":
		case root && nm == "host":
		default:
			return fmt.Errorf("service %s sets network_mode: %v (only none or its own network)", n, nm)
		}
	}
	for _, k := range []string{"ipc", "uts", "userns_mode", "cgroup", "cgroup_parent", "devices", "volumes_from", "configs", "secrets",
		"sysctls", "runtime", "isolation"} {
		if _, ok := svc[k]; ok {
			return fmt.Errorf("service %s sets %s: (host namespaces, devices, another container's volumes or host files)", n, k)
		}
	}
	if _, ok := svc["device_cgroup_rules"]; ok && !root {
		return fmt.Errorf("service %s sets device_cgroup_rules: (access to the VM's devices)", n)
	}
	if _, ok := svc["cap_add"]; ok {
		switch {
		case root:
		case diag && level >= diagE2E && capsWithin(svc, e2eDiagCaps):
		case n == SetupService && capsWithin(svc, setupCaps):
		case gatewaydLaunch(n, svc):
		default:
			return fmt.Errorf("service %s adds capabilities %v (only setup's %s, after cap_drop ALL)", n, svc["cap_add"], strings.Join(setupCaps, ", "))
		}
	}
	if u, ok := svc["user"]; ok && n == GatewaydService {
		if uid, _, _ := strings.Cut(fmt.Sprint(u), ":"); (uid == "0" || uid == "root") && !gatewaydLaunch(n, svc) {
			return fmt.Errorf("service %s runs as root without the launcher (%s)", n, GatewaydLaunchException)
		}
	}
	if gatewaydLaunch(n, svc) && !noNewPrivileges(svc) {
		return fmt.Errorf("service %s: the launcher's capabilities need no-new-privileges", n)
	}
	if so, ok := svc["security_opt"]; ok {
		opts, ok := strs(so)
		if !ok {
			return fmt.Errorf("service %s's security_opt isn't a list of strings", n)
		}
		for _, o := range opts {
			switch {
			case o == "no-new-privileges:true" || o == "no-new-privileges=true" || o == "no-new-privileges":
			case o == "seccomp:unconfined" && (n == RunnerService || root):
			default:
				return fmt.Errorf("service %s sets security_opt %q (only no-new-privileges; seccomp unconfined for the runner's gVisor)", n, o)
			}
		}
	}
	return nil
}

// noNewPrivileges: svc's security_opt has no-new-privileges.
func noNewPrivileges(svc map[string]any) bool {
	opts, _ := strs(svc["security_opt"])
	return slices.ContainsFunc(opts, func(o string) bool {
		return o == "no-new-privileges:true" || o == "no-new-privileges=true" || o == "no-new-privileges"
	})
}

func composeImages(compose string, level diagLevel, allowed []string) (map[string]string, error) {
	e2e := level >= diagE2E
	if allowed == nil {
		allowed = ReleaseServices
	}
	dec := yaml.NewDecoder(strings.NewReader(compose))
	var doc map[string]any
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("docker compose isn't YAML: %w", err)
	}
	var more any
	if err := dec.Decode(&more); !errors.Is(err, io.EOF) {
		return nil, errors.New("docker compose has more than one YAML document")
	}
	if _, ok := doc["include"]; ok {
		return nil, errors.New("docker compose has include: (another file's services)")
	}
	for _, k := range []string{"configs", "secrets"} {
		if _, ok := doc[k]; ok {
			return nil, fmt.Errorf("docker compose has top-level %s: (a file: entry binds a host file into a container)", k)
		}
	}
	services, ok := doc["services"].(map[string]any)
	if !ok || len(services) == 0 {
		return nil, errors.New("docker compose has no services")
	}
	names := make([]string, 0, len(services))
	for n := range services {
		names = append(names, n)
	}
	sort.Strings(names)
	images := map[string]string{}
	for _, n := range names {
		svc, ok := services[n].(map[string]any)
		if !ok {
			return nil, fmt.Errorf("service %s isn't a mapping", n)
		}
		diag := e2e && n == E2EDiagService
		if !slices.Contains(allowed, n) && !diag {
			return nil, fmt.Errorf("service %s isn't one of the release's (%s)", n, strings.Join(allowed, ", "))
		}
		if err := servicePrivileges(n, svc, level); err != nil {
			return nil, err
		}
		// The e2e test's fake slow and overloaded models (gatewayd -e2e-model-fault): the e2e overlay's only.
		if !e2e && strings.Contains(fmt.Sprint(svc["command"], svc["entrypoint"]), E2EModelFaultFlag) {
			return nil, fmt.Errorf("service %s sets %s (an e2e test's fake slow models)", n, E2EModelFaultFlag)
		}
		// Development and spike flags, and in a release with unlockd a published port or -listen (review L1).
		if !e2e {
			args := commandArgs(svc)
			for _, f := range DevFlags {
				if hasFlag(args, f) {
					return nil, fmt.Errorf("service %s sets -%s (development composes only)", n, f)
				}
			}
			if _, ok := services[UnlockdService]; ok {
				if _, ok := svc["ports"]; ok {
					return nil, fmt.Errorf("service %s publishes ports (a release with unlockd has no way in but the tunnel)", n)
				}
				if n == GatewaydService && hasFlag(args, ListenFlag) {
					return nil, fmt.Errorf("service %s sets -%s (a release with unlockd has no way in but the tunnel)", n, ListenFlag)
				}
			}
		}
		// The e2e diag route on the tunnel (gatewayd -e2e-diag): the e2e overlay's only. Matched anywhere in the
		// command, environment and entrypoint, as -e2e-diag, --e2e-diag or -e2e-diag=…
		if !e2e && strings.Contains(fmt.Sprint(svc["command"], svc["entrypoint"], svc["environment"]), E2EDiagFlag) {
			return nil, fmt.Errorf("service %s sets %s (the e2e test's diag route on the tunnel)", n, E2EDiagFlag)
		}
		for _, k := range []string{"build", "extends"} {
			if _, ok := svc[k]; ok {
				return nil, fmt.Errorf("service %s has %s: (code the compose hash doesn't cover)", n, k)
			}
		}
		img, ok := svc["image"].(string)
		if !ok {
			return nil, fmt.Errorf("service %s has no image", n)
		}
		if !digestRef.MatchString(img) {
			return nil, fmt.Errorf("service %s's image %q isn't name@sha256:<digest> without a tag", n, img)
		}
		images[n] = img
	}
	// A release with unlockd (the v1 line), to a production verifier: exactly cmd/compose's shape (review 2, M1).
	if _, ok := services[UnlockdService]; ok && level == diagNone {
		var extra []string
		for _, n := range allowed {
			if !slices.Contains(ReleaseServices, n) {
				extra = append(extra, n)
			}
		}
		if err := releaseShapeWith(compose, extra); err != nil {
			return nil, err
		}
	}
	return images, nil
}

// ImagesCheck is the name of the check ComposeImages backs (the last one).
// The name stays as the browser's tests pin it; the check also covers the services, privileged and pid (above).
const ImagesCheck = "docker compose pins every image by digest (no tag, no build, extends or include)"

// SandboxFacts reads, from a compose whose brain runs in gVisor (since v0.4.0, docs/22: the "runner" service, runnerd),
// what the Security panel shows about the brain's sandbox: "brain sandbox" ("gVisor <release> (<platform>, rootless
// runsc), no network"), "gvisor release", "gvisor runsc sha256" and "brain binary sha256", from runnerd's
// arguments. runnerd refuses to start unless the release and runsc's hash are the ones built into it and the brain
// in its image has that hash, and the image is pinned by digest, so these describe what runs. Facts only: an older
// compose (the brain in its own container) has none, and nothing here passes or fails a check.
func SandboxFacts(compose string) map[string]string {
	var doc struct {
		Services map[string]struct {
			NetworkMode string   `yaml:"network_mode"`
			Command     []string `yaml:"command"`
		} `yaml:"services"`
	}
	facts := map[string]string{}
	if yaml.Unmarshal([]byte(compose), &doc) != nil {
		return facts
	}
	runner, ok := doc.Services["runner"]
	if !ok {
		return facts
	}
	arg, rootless := map[string]string{}, false
	for i, a := range runner.Command {
		if a == "-rootless" || a == "-rootless=true" {
			rootless = true
		} else if strings.HasPrefix(a, "-") && i+1 < len(runner.Command) && !strings.HasPrefix(runner.Command[i+1], "-") {
			arg[a] = runner.Command[i+1]
		}
	}
	hex64 := regexp.MustCompile(`^[0-9a-f]{64}$`)
	rel, platform := arg["-gvisor-release"], arg["-platform"]
	if !regexp.MustCompile(`^[0-9]{8}\.[0-9]+$`).MatchString(rel) || !regexp.MustCompile(`^[a-z]+$`).MatchString(platform) {
		return facts
	}
	facts["gvisor release"] = rel
	sb := "gVisor " + rel + " (" + platform
	if rootless {
		sb += ", rootless runsc"
	}
	sb += ")"
	if runner.NetworkMode == "none" {
		sb += ", no network"
	}
	facts["brain sandbox"] = sb
	if hex64.MatchString(arg["-runsc-sha256"]) {
		facts["gvisor runsc sha256"] = arg["-runsc-sha256"]
	}
	if hex64.MatchString(arg["-brain-sha256"]) {
		facts["brain binary sha256"] = arg["-brain-sha256"]
	}
	return facts
}

// checkImages runs ComposeImages on the attested compose, records each service's image as the fact
// "image <service>" and the brain's sandbox (SandboxFacts), and adds the check.
func (r *Result) checkImages(compose string, level diagLevel, services []string) bool {
	images, err := composeImages(compose, level, services)
	for svc, img := range images {
		r.Facts["image "+svc] = img
	}
	if err == nil {
		for k, v := range SandboxFacts(compose) {
			r.Facts[k] = v
		}
	}
	detail := ""
	if err == nil {
		detail = fmt.Sprintf("%d services, each name@sha256", len(images))
		if rel := r.Facts["gvisor release"]; rel != "" {
			detail += "; the brain in gVisor " + rel + " from the runner's image"
		}
	}
	return r.add(ImagesCheck, err, detail)
}
