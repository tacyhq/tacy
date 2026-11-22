package verifier

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"
)

// The VM's keys, and what protects its disk, must never be a provider's ("Keys: never a provider's"). So
// each release pins its exact app-compose.json (the dstack manifest Phala deploys: the docker compose plus every
// setting of the CVM), and the verifier requires sha256(the attested app-compose.json) == sha256(the pinned one).
// That covers every flag at once; the per-flag checks below run first so a failure says which flag is wrong.
//
// Two key modes, chosen by the release (the pinned app-compose.json) and allowed by the policy:
//
//   - KeyProviderNone (the default): key_provider "none". dstack makes a random seed inside the TD at each boot and
//     derives the disk key from it; nothing is asked of a KMS, so no provider holds or can derive it. The data disk
//     is reformatted at every boot (requirements.ephemeral_data_disk, manifest_version "3" so a guest that doesn't
//     know requirements fails closed). Fix B (2026-11-21): no provider gateway (gateway_enabled and tproxy_enabled
//     off: the VM dials out), no pre-launch script, and ulimits core 0 on every service (a crash would otherwise
//     write a process's memory into its writable layer on the disk).
//   - KeyProviderKMS (Policy.KMSFallback only, if Phala refuses "none"): key_provider "kms" with key_provider_id
//     pinned to a KMSRoots root, so the guest itself refuses another root. The disk is then under a key Phala's KMS
//     derives, so the VM must keep nothing on it: the docker compose has no volume that isn't memory (tmpfs).
//
// In both: no deployer-supplied env (allowed_envs empty: secrets come sealed to the attested VM, never through
// Phala's encrypted env), no swap (swap is a zvol or file on the data disk), the guest's logs, sysinfo and tcbinfo
// not public, the gateway forwarding only port 8080 (restrict_mode), the guest's clock from a secure source.

// Key modes (app-compose.json key_provider).
const (
	KeyProviderNone = "none"
	KeyProviderKMS  = "kms"
)

// AppPort is the only port the gateway may forward to the VM (gatewayd's listener).
const AppPort = 8080

// AppComposeName is the app name in the release's app-compose.json.
const AppComposeName = "tacy-agent-vm"

// The app-compose checks. Their names start with "app-compose:" (the chat maps that prefix to its failure code).
const (
	AppComposeFlagsCheck = "app-compose: no swap, sysinfo and tcbinfo not public, only port 8080, secure time, keys per mode " +
		"(key_provider none with an ephemeral data disk, or the pinned-KMS fallback with nothing on disk)"
	AppComposePinCheck = "app-compose: exactly the release's app-compose.json (sha256 pinned)"
)

// appCompose is what the verifier reads of an app-compose.json (dstack-types AppCompose, 0.6.5).
type appCompose struct {
	ManifestVersion         json.RawMessage `json:"manifest_version"`
	Name                    string          `json:"name"`
	Features                []string        `json:"features"` // deprecated in dstack; "tproxy-net" turns the gateway on
	DockerComposeFile       string          `json:"docker_compose_file"`
	PreLaunchScript         *string         `json:"pre_launch_script"`
	InitScript              json.RawMessage `json:"init_script"`
	Runner                  string          `json:"runner"`
	AllowedEnvs             []string        `json:"allowed_envs"`
	PublicLogs              bool            `json:"public_logs"`
	PublicSysinfo           bool            `json:"public_sysinfo"`
	PublicTcbinfo           *bool           `json:"public_tcbinfo"` // dstack's default is true
	KMSEnabled              bool            `json:"kms_enabled"`
	GatewayEnabled          *bool           `json:"gateway_enabled"`
	TproxyEnabled           *bool           `json:"tproxy_enabled"`
	LocalKeyProviderEnabled bool            `json:"local_key_provider_enabled"`
	KeyProvider             *string         `json:"key_provider"`
	KeyProviderID           string          `json:"key_provider_id"`
	SecureTime              *bool           `json:"secure_time"` // dstack 0.6.5's default is true; we require it written
	SwapSize                json.RawMessage `json:"swap_size"`
	StorageFS               *string         `json:"storage_fs"`      // the data disk's filesystem; overrides the kernel command line
	StorageDiscard          *bool           `json:"storage_discard"` // dstack's default is true (TRIM to the host)
	PortPolicy              *struct {
		Ports []struct {
			Port int  `json:"port"`
			PP   bool `json:"pp"`
		} `json:"ports"`
		RestrictMode bool `json:"restrict_mode"`
	} `json:"port_policy"`
	Requirements *struct {
		EphemeralDataDisk bool `json:"ephemeral_data_disk"`
	} `json:"requirements"`
}

func parseAppCompose(b []byte) (*appCompose, error) {
	var ac appCompose
	if err := json.Unmarshal(b, &ac); err != nil {
		return nil, err
	}
	return &ac, nil
}

// keyMode is the app-compose's key provider as dstack resolves it (key_provider, else kms_enabled, else local, else none).
func (ac *appCompose) keyMode() string {
	if ac.KeyProvider != nil {
		return *ac.KeyProvider
	}
	if ac.KMSEnabled {
		return KeyProviderKMS
	}
	if ac.LocalKeyProviderEnabled {
		return "local"
	}
	return KeyProviderNone
}

// zeroSize: swap_size absent, 0, or a size string of zero ("0", "0G").
var zeroSize = regexp.MustCompile(`^"0+\s*[A-Za-z]*"$`)

// StorageFS is the data disk's filesystem every release asks for (app-compose storage_fs). ZFS keeps a checksum of
// each block in its parent, up to the uberblock in memory, so a block the host randomizes or rolls back (aes-xts has
// no integrity) reads as an error, never as other data. On ext4 a sector rolled back to an earlier ciphertext of
// the same boot would read back as that earlier plaintext.
const StorageFS = "zfs"

// checkFlags checks the settings of an app-compose.json for key mode mode (KeyProviderNone or KeyProviderKMS).
// The gateway may forward exactly ports: a release's is the app port alone; only the e2e test's overlay adds its
// diag service's (E2EAppCompose). allowDiscard accepts storage_discard true (Policy.AllowStorageDiscard; nothing
// sets it). The error names the first flag that's wrong.
func (ac *appCompose) checkFlags(mode string, kmsRoots map[string]string, ports []int, allowDiscard bool) error {
	if len(ports) == 0 {
		return errors.New("no port to check port_policy against")
	}
	port := ports[0]
	if string(ac.ManifestVersion) != `"3"` {
		return fmt.Errorf("manifest_version %s, want \"3\" (older guests ignore requirements instead of failing closed)", ac.ManifestVersion)
	}
	// dstack-types 0.6.5: gateway_enabled() is gateway_enabled || features contains "tproxy-net". The list is
	// deprecated and a release writes it empty, so any entry is refused, not only the ones known to turn something on.
	if len(ac.Features) > 0 {
		return fmt.Errorf("features %q, want none (deprecated; \"tproxy-net\" turns the provider gateway on)", ac.Features)
	}
	if ac.StorageFS == nil || *ac.StorageFS != StorageFS {
		got := "unset (the kernel command line's)"
		if ac.StorageFS != nil {
			got = strconv.Quote(*ac.StorageFS)
		}
		return fmt.Errorf("storage_fs %s, want %q (its block checksums turn a host's rollback of the disk into a read error)", got, StorageFS)
	}
	if (ac.StorageDiscard == nil || *ac.StorageDiscard) && !allowDiscard {
		return errors.New("storage_discard is on or unset (dstack's default is on), want off (TRIM shows the host which blocks are free)")
	}
	if got := ac.keyMode(); got != mode {
		return fmt.Errorf("key_provider %q, want %q", got, mode)
	}
	if ac.LocalKeyProviderEnabled {
		return errors.New("local_key_provider_enabled is on, want off")
	}
	switch mode {
	case KeyProviderNone:
		if ac.KMSEnabled {
			return errors.New("kms_enabled is on, want off (keys made in the VM, key_provider none)")
		}
		if ac.KeyProviderID != "" {
			return errors.New("key_provider_id is set with key_provider none")
		}
		// Fix B: no provider gateway (its TLS and app registration need the provider's KMS; the VM dials out
		// instead), so nothing of the provider's sits in front of the VM either.
		if ac.GatewayEnabled == nil || *ac.GatewayEnabled {
			return errors.New("gateway_enabled is on or unset, want off with key_provider none (no provider gateway)")
		}
		if ac.TproxyEnabled != nil && *ac.TproxyEnabled {
			return errors.New("tproxy_enabled is on, want off with key_provider none")
		}
		// No pre-launch script: the disk's key is the TD's, so the images need not be moved into memory, and the
		// deploy always sends "" (without it Phala inserts its own script, which runs as root).
		if ac.PreLaunchScript != nil && *ac.PreLaunchScript != "" {
			return errors.New("a pre-launch script with key_provider none, want none (sent as \"\")")
		}
		if err := coreDumpsOff(ac.DockerComposeFile); err != nil {
			return err
		}
		// The disk's key is the TD's here, but the VM still keeps nothing there (v0.20.0's rule, kept: what a
		// container writes to a volume would outlive the container's restarts in this boot).
		if err := noDiskVolumesMode(ac.DockerComposeFile, KeyProviderNone); err != nil {
			return err
		}
	case KeyProviderKMS:
		if !ac.KMSEnabled {
			return errors.New("kms_enabled is off with key_provider kms")
		}
		if kmsRoots[strings.ToLower(ac.KeyProviderID)] == "" {
			return fmt.Errorf("key_provider_id %s isn't a pinned KMS root (the guest must refuse any other)", short(ac.KeyProviderID))
		}
		if err := noDiskVolumesMode(ac.DockerComposeFile, KeyProviderKMS); err != nil {
			return fmt.Errorf("KMS fallback: %w", err)
		}
	default:
		return fmt.Errorf("key mode %q", mode)
	}
	if ac.Requirements == nil || !ac.Requirements.EphemeralDataDisk {
		return errors.New("requirements.ephemeral_data_disk is off, want on (a fresh data disk at every boot)")
	}
	if len(ac.SwapSize) != 0 && string(ac.SwapSize) != "0" && string(ac.SwapSize) != "null" && !zeroSize.Match(ac.SwapSize) {
		return fmt.Errorf("swap_size is %s, want 0 (swap is on the data disk)", ac.SwapSize)
	}
	if ac.PublicLogs {
		return errors.New("public_logs is on, want off")
	}
	if ac.PublicSysinfo {
		return errors.New("public_sysinfo is on, want off")
	}
	if ac.PublicTcbinfo == nil || *ac.PublicTcbinfo {
		return errors.New("public_tcbinfo is on (dstack's default when absent), want off")
	}
	if ac.PortPolicy == nil || !ac.PortPolicy.RestrictMode {
		return fmt.Errorf("port_policy.restrict_mode is off, want on (the gateway forwards only port %d)", port)
	}
	ok := len(ac.PortPolicy.Ports) == len(ports)
	for i := 0; ok && i < len(ports); i++ {
		ok = ac.PortPolicy.Ports[i].Port == ports[i] && !ac.PortPolicy.Ports[i].PP
	}
	if !ok {
		want := make([]string, len(ports))
		for i, p := range ports {
			want[i] = strconv.Itoa(p)
		}
		return fmt.Errorf("port_policy.ports %v, want only %s (no PROXY protocol)", ac.PortPolicy.Ports, strings.Join(want, ", "))
	}
	if ac.SecureTime == nil || !*ac.SecureTime {
		return errors.New("secure_time is off or unset, want on")
	}
	return nil
}

// coreDumpsOff: every service sets ulimits core 0 (soft and hard). dstack's core_pattern is "core", a file in the
// crashing process's working directory, and dockerd and containerd run with an unlimited core limit, so a crash
// would write the process's memory (keys, what people sent) into its container's writable layer on the data disk.
func coreDumpsOff(compose string) error {
	var doc struct {
		Services map[string]struct {
			Ulimits map[string]any `yaml:"ulimits"`
		} `yaml:"services"`
	}
	if err := yaml.Unmarshal([]byte(compose), &doc); err != nil {
		return fmt.Errorf("docker compose isn't YAML: %w", err)
	}
	if len(doc.Services) == 0 {
		return errors.New("docker compose has no services")
	}
	for _, n := range slices.Sorted(maps.Keys(doc.Services)) {
		zero := false
		switch c := doc.Services[n].Ulimits["core"].(type) {
		case int:
			zero = c == 0
		case map[string]any:
			soft, ok1 := c["soft"].(int)
			hard, ok2 := c["hard"].(int)
			zero = ok1 && ok2 && soft == 0 && hard == 0
		}
		if !zero {
			return fmt.Errorf("service %s doesn't set ulimits core 0 (a crash would dump its memory to the disk)", n)
		}
	}
	return nil
}

// noDiskVolumes: the docker compose keeps nothing on the data disk. Every top-level volume is memory (driver_opts
// type tmpfs), and a service mounts only those, tmpfs, or dstack's socket (/var/run/dstack.sock, for quotes). The
// e2e test's diag service may also bind the host's root read-only (its plaintext-disk scan reads the disk, writes
// nothing): only an e2e verification takes a compose with that service at all (ComposeImagesE2E). The KMS
// fallback's rule (noDiskVolumesMode for mode KeyProviderKMS).
func noDiskVolumes(compose string) error { return noDiskVolumesMode(compose, KeyProviderKMS) }

// noDiskVolumesMode is noDiskVolumes for a key mode: with key_provider none, setup may also bind the unlock cache
// directory (host /run, tmpfs) to give it to unlockd's uid (UnlockdRules).
func noDiskVolumesMode(compose, mode string) error {
	var doc struct {
		Services map[string]struct {
			Volumes []any `yaml:"volumes"`
		} `yaml:"services"`
		Volumes map[string]any `yaml:"volumes"`
	}
	if err := yaml.Unmarshal([]byte(compose), &doc); err != nil {
		return fmt.Errorf("docker compose isn't YAML: %w", err)
	}
	mem := map[string]bool{}
	names := make([]string, 0, len(doc.Volumes))
	for n := range doc.Volumes {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		v, _ := doc.Volumes[n].(map[string]any)
		opts, _ := v["driver_opts"].(map[string]any)
		dev, hasDev := opts["device"]
		if d, ok := v["driver"]; (ok && d != "local") || opts["type"] != "tmpfs" || (hasDev && dev != "tmpfs") || v["external"] != nil {
			return fmt.Errorf("volume %s isn't memory (driver_opts type tmpfs): it would be on the provider-keyed disk", n)
		}
		mem[n] = true
	}
	svcs := make([]string, 0, len(doc.Services))
	for n := range doc.Services {
		svcs = append(svcs, n)
	}
	sort.Strings(svcs)
	for _, s := range svcs {
		for _, v := range doc.Services[s].Volumes {
			src, typ, ro := "", "volume", false
			switch m := v.(type) {
			case string:
				var rest string
				src, rest, _ = strings.Cut(m, ":")
				if strings.HasPrefix(src, "/") || strings.HasPrefix(src, ".") {
					typ = "bind"
				}
				if _, opts, ok := strings.Cut(rest, ":"); ok {
					ro = slices.Contains(strings.Split(opts, ","), "ro")
				}
			case map[string]any:
				typ, _ = m["type"].(string)
				src, _ = m["source"].(string)
				ro, _ = m["read_only"].(bool)
			}
			switch {
			case typ == "tmpfs":
			case typ == "bind" && src == "/var/run/dstack.sock":
			case typ == "bind" && src == UnlockCacheDir && s == UnlockdService: // a host tmpfs (TD memory): UnlockdRules
			case typ == "bind" && src == UnlockCacheDir && s == SetupService && mode == KeyProviderNone:
			case typ == "bind" && src == TasksDir && (s == AgentdService || s == SetupService) && mode == KeyProviderNone: // TasksRules
			case typ == "volume" && mem[src]:
			case s == E2EDiagService && typ == "bind" && src == "/" && ro:
			default:
				return fmt.Errorf("service %s mounts %v, which isn't memory or dstack's socket", s, v)
			}
		}
	}
	return TasksRules(compose, mode) // agentd's task queue tmpfs: agentd's alone, made for its uid only
}

// ReleaseAppCompose is the app-compose.json a release's CVM attests: compose and preLaunch (a reviewed pre-launch
// script; nil for none, today's) with the settings above, as Phala stores it: compact JSON with sorted keys (jq -cS)
// of what DeployAppCompose sends, plus what Phala adds (tproxy_enabled; key_provider_id, the KMS root, in KMS mode),
// less an empty pre_launch_script (sent so that Phala adds none of its own). The 0.6.5 spike (2026-11-20) attested
// exactly these bytes (TestReleaseAppComposeAsAttested). kmsFallback picks KeyProviderKMS with the one pinned KMS
// root; otherwise KeyProviderNone. cmd/compose writes it as app-compose.json, the file the verifier pins.
func ReleaseAppCompose(compose, preLaunch []byte, kmsFallback bool) ([]byte, error) {
	out, err := appComposeJSON(compose, preLaunch, kmsFallback, AppComposeName)
	if err != nil {
		return nil, err
	}
	// The release's own rules hold for what it deploys.
	parsed, err := parseAppCompose(out)
	if err != nil {
		return nil, err
	}
	mode := KeyProviderNone
	if kmsFallback {
		mode = KeyProviderKMS
	}
	if err := parsed.checkFlags(mode, KMSRoots, []int{AppPort}, false); err != nil {
		return nil, fmt.Errorf("release app-compose: %w", err)
	}
	return out, nil
}

// E2EAppCompose is ReleaseAppCompose for the end-to-end test's overlay of a release compose (cmd/e2e overlay, on
// throwaway CVMs only): the same settings, but port_policy also lets the gateway forward the diag service's
// published ports (E2EDiagPorts), as ComposeImagesE2E lets that service in. For a compose with no diag service it
// is exactly ReleaseAppCompose. Never a release's: the browser's verifier never allows the diag service, so it
// checks AppPort alone.
func E2EAppCompose(compose, preLaunch []byte, kmsFallback bool) ([]byte, error) {
	extra, err := E2EDiagPorts(string(compose))
	if err != nil {
		return nil, err
	}
	if len(extra) == 0 {
		return ReleaseAppCompose(compose, preLaunch, kmsFallback)
	}
	ports := append([]int{AppPort}, extra...)
	out, err := appComposeJSONPorts(compose, preLaunch, kmsFallback, AppComposeName, ports)
	if err != nil {
		return nil, err
	}
	parsed, err := parseAppCompose(out)
	if err != nil {
		return nil, err
	}
	mode := KeyProviderNone
	if kmsFallback {
		mode = KeyProviderKMS
	}
	if err := parsed.checkFlags(mode, KMSRoots, ports, false); err != nil {
		return nil, fmt.Errorf("e2e app-compose: %w", err)
	}
	return out, nil
}

// E2EDiagPorts are the ports the e2e overlay's diag service (E2EDiagService) publishes, in order; none when the
// compose has no such service. Each is published on the port it listens on ("N:N") and isn't AppPort.
func E2EDiagPorts(compose string) ([]int, error) {
	var doc struct {
		Services map[string]struct {
			Ports []any `yaml:"ports"`
		} `yaml:"services"`
	}
	if err := yaml.Unmarshal([]byte(compose), &doc); err != nil {
		return nil, fmt.Errorf("docker compose isn't YAML: %w", err)
	}
	svc, ok := doc.Services[E2EDiagService]
	if !ok {
		return nil, nil
	}
	var ports []int
	for _, p := range svc.Ports {
		s, _ := p.(string)
		host, cont, found := strings.Cut(s, ":")
		n, err := strconv.Atoi(host)
		if !found || err != nil || host != cont || n <= 0 || n > 65535 || n == AppPort || slices.Contains(ports, n) {
			return nil, fmt.Errorf("the %s service publishes %v (want \"N:N\", not %d)", E2EDiagService, p, AppPort)
		}
		ports = append(ports, n)
	}
	return ports, nil
}

// appComposeJSON is ReleaseAppCompose's file for an app name, without the check of its rules.
func appComposeJSON(compose, preLaunch []byte, kmsFallback bool, name string) ([]byte, error) {
	return appComposeJSONPorts(compose, preLaunch, kmsFallback, name, []int{AppPort})
}

// appComposeJSONPorts is appComposeJSON with the ports the gateway may forward.
func appComposeJSONPorts(compose, preLaunch []byte, kmsFallback bool, name string, ports []int) ([]byte, error) {
	pp := make([]map[string]any, len(ports))
	for i, p := range ports {
		pp[i] = map[string]any{"port": p, "pp": false}
	}
	ac := map[string]any{
		"manifest_version":           "3",
		"name":                       name,
		"runner":                     "docker-compose",
		"docker_compose_file":        string(compose),
		"features":                   []string{},
		"init_script":                []string{},
		"gateway_enabled":            true,
		"tproxy_enabled":             true,
		"allowed_envs":               []string{},
		"public_logs":                false,
		"public_sysinfo":             false,
		"public_tcbinfo":             false,
		"local_key_provider_enabled": false,
		"no_instance_id":             false,
		"secure_time":                true,
		"storage_fs":                 "zfs",
		"storage_discard":            false,
		"swap_size":                  "0",
		"port_policy":                map[string]any{"ports": pp, "restrict_mode": true},
		"requirements":               map[string]any{"ephemeral_data_disk": true},
	}
	if len(preLaunch) > 0 {
		ac["pre_launch_script"] = string(preLaunch)
	}
	if kmsFallback {
		if len(KMSRoots) != 1 {
			return nil, fmt.Errorf("the KMS fallback needs exactly one pinned KMS root, have %d", len(KMSRoots))
		}
		for root := range KMSRoots {
			if _, err := hex.DecodeString(root); err != nil {
				return nil, fmt.Errorf("KMS root %s isn't hex", short(root))
			}
			ac["key_provider_id"] = root
		}
		ac["key_provider"], ac["kms_enabled"] = KeyProviderKMS, true
	} else {
		// Fix B: no provider gateway (Phala stores tproxy_enabled false with it).
		ac["key_provider"], ac["kms_enabled"] = KeyProviderNone, false
		ac["gateway_enabled"], ac["tproxy_enabled"] = false, false
	}
	return compactSorted(ac)
}

// DeployAppCompose is what a release sends Phala for the pinned app-compose.json: without what Phala adds itself
// (tproxy_enabled, which it refuses from us, and key_provider_id), and with pre_launch_script "" when there is none
// (without the field Phala injects its own script). Phala stores jq -cS of it plus its additions: the pinned bytes.
func DeployAppCompose(pinned []byte) ([]byte, error) {
	var ac map[string]any
	if err := json.Unmarshal(pinned, &ac); err != nil {
		return nil, err
	}
	delete(ac, "tproxy_enabled")
	delete(ac, "key_provider_id")
	if _, ok := ac["pre_launch_script"]; !ok {
		ac["pre_launch_script"] = ""
	}
	return compactSorted(ac)
}

// compactSorted is v as jq -cS writes it: compact, keys sorted, no HTML escaping.
func compactSorted(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

// pinnedMode is the key mode the pinned app-compose.json asks for, if the policy allows it.
func pinnedMode(pinned *appCompose, fallback bool) (string, error) {
	switch m := pinned.keyMode(); {
	case m == KeyProviderNone:
		return m, nil
	case m == KeyProviderKMS && fallback:
		return m, nil
	case m == KeyProviderKMS:
		return "", errors.New("the release's app-compose.json takes keys from a KMS, allowed only in the explicit KMS fallback")
	default:
		return "", fmt.Errorf("the release's app-compose.json has key provider %q", m)
	}
}

// emptyEnvs: allowed_envs is empty (nothing reaches the containers through the deployer's encrypted env).
func emptyEnvs(envs []string) error {
	if len(envs) == 0 {
		return nil
	}
	return fmt.Errorf("deployer may set env %s (allowed_envs must be empty: secrets come sealed to the verified VM)",
		strings.Join(slices.Sorted(slices.Values(envs)), ", "))
}
