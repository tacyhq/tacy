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
// gatewayd (named agentvm) and vaultd. Anything else is code the release doesn't describe.
var ReleaseServices = []string{"setup", "agentd", "runner", "agentvm", "vaultd"}

// E2EDiagService is the end-to-end test's diag service (cmd/e2e overlay): accepted only by ComposeImagesE2E, with
// its pid namespace (it kills processes to check crashes). Never in a release.
const E2EDiagService = "e2ediag"

// ComposeImages checks the docker compose a VM runs pins every container to an image digest, so the attested
// compose hash covers exactly the code that runs: one YAML document; only the release's services
// (ReleaseServices); every service has an image that is name@sha256:<64 hex> with no tag; no service has build:
// (code built on the VM from a context the hash doesn't cover) or extends:, and there is no top-level include: (both
// pull in another file); no service is privileged or shares a pid namespace (pid: host would let it see and
// signal every process of the VM); no command sets the e2e test's model faults (E2EModelFaultFlag). It returns
// each service's image.
// E2EModelFaultFlag is gatewayd's test-only flag for fake slow and overloaded models: accepted only by
// ComposeImagesE2E.
const E2EModelFaultFlag = "e2e-model-fault"

func ComposeImages(compose string) (map[string]string, error) { return composeImages(compose, false) }

// ComposeImagesE2E is ComposeImages that also accepts the e2e overlay's diag service with its pid setting (test
// tools only, never the browser's verifier).
func ComposeImagesE2E(compose string) (map[string]string, error) { return composeImages(compose, true) }

func composeImages(compose string, e2e bool) (map[string]string, error) {
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
		if !slices.Contains(ReleaseServices, n) && !diag {
			return nil, fmt.Errorf("service %s isn't one of the release's (%s)", n, strings.Join(ReleaseServices, ", "))
		}
		if p, ok := svc["privileged"]; ok && p != false {
			return nil, fmt.Errorf("service %s is privileged", n)
		}
		if _, ok := svc["pid"]; ok && !diag {
			return nil, fmt.Errorf("service %s sets pid: (it would share a process namespace)", n)
		}
		// The e2e test's fake slow and overloaded models (gatewayd -e2e-model-fault): the e2e overlay's only.
		if !e2e && strings.Contains(fmt.Sprint(svc["command"], svc["entrypoint"]), E2EModelFaultFlag) {
			return nil, fmt.Errorf("service %s sets %s (an e2e test's fake slow models)", n, E2EModelFaultFlag)
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
func (r *Result) checkImages(compose string, e2e bool) bool {
	images, err := composeImages(compose, e2e)
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
