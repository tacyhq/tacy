package verifier

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/tacyhq/tacy/proto"
)

// The split-key unlock's rules (the keys plan §11.2), for a release whose compose has the unlockd service:
//
//   - Binaries only from TD memory (privacy audit finding 1; the pre-mortem's go-live gate). The quote measures the
//     compose (image digests), not the bytes Docker unpacks; on the KMS fallback those sit on a disk under the
//     provider's key, and dstack's watchdog restarts the containers about hourly from them, so an edited binary
//     there would run and get the keys. A check by code that itself sits on that disk proves nothing. So the
//     release's app-compose carries MemoryRootScript as its pre-launch script (measured: the attested compose hash
//     covers it; dstack runs it as root before the containers): it puts Docker's and containerd's data roots on
//     tmpfs in TD memory before anything is pulled, and refuses to go on otherwise. Images are then pulled by digest
//     into memory and never touch the disk. This is the compose marker split-key holders require (MemoryRoot) before
//     they seal a share to a key_provider kms VM.
//   - unlockd alone holds dstack's socket (only it can make a quote) and the host tmpfs its keys survive container
//     restarts in (UnlockCacheDir); it has no network, no port, no capability and isn't root.
//   - agentd's attestation (made by unlockd for it) carries proto.VersionAgent's report_data, never an unlock's.
//
// With key_provider none (Fix B) the data disk is under a key made inside the TD at boot, which no provider holds:
// an edited byte there decrypts to garbage that ZFS's checksums refuse, never to a binary of someone's choosing. So
// that mode needs no memory-root script (and has none: the deploy sends ""). unlockd then runs with
// -key-mode none (it doesn't wait for the script's marker), and the one-shot setup container, root and without a
// network, makes the cache directory for unlockd's uid in the host's /run (tmpfs) instead of the script. In the KMS
// fallback neither is allowed.

// UnlockdService is the split-key unlock's service.
const UnlockdService = "unlockd"

// UnlockCacheDir is the host tmpfs (TD memory) unlockd keeps its derived keys in across container restarts, made by
// MemoryRootScript for unlockd's uid only.
const UnlockCacheDir = "/run/tacy-unlock"

// UnlockdUID is unlockd's uid (cmd/compose).
const UnlockdUID = "10005"

// UnlockdKeyModeFlag is unlockd's flag for the VM's key mode: "-key-mode none" with key_provider none (no
// memory-root marker to wait for), absent in the KMS fallback.
const UnlockdKeyModeFlag = "-key-mode"

// SetupService is the one-shot setup container: with key_provider none it alone besides unlockd mounts the unlock
// cache directory, to give it to unlockd's uid.
const SetupService = "setup"

// MemoryRootScript is the release's pre-launch script (phala/pre-launch-memory-root-v1.sh; TestMemoryRootScriptFile
// keeps the two the same). Reviewed with the release; any change is a new script with a new name.
const MemoryRootScript = `#!/bin/bash
# Tacy pre-launch v1: every container image in TD memory, never on the provider-keyed disk (the keys plan §11.2).
# dstack runs this as root before docker compose up, on every start of the app (a boot, and the guest agent
# watchdog's restarts). It prints no secret: there is none on this VM before unlockd runs.
set -euo pipefail
fail() { echo "tacy pre-launch: $*" >&2; exit 1; }
ondisk() { [ "$(stat -f -c %T "$1")" != tmpfs ]; }
[ "$(stat -f -c %T /run)" = tmpfs ] || fail "/run isn't tmpfs"
droot=$(docker info -f '{{.DockerRootDir}}' 2>/dev/null || echo /var/lib/docker)
croot=/var/lib/containerd
if ondisk "$droot" || { [ -d "$croot" ] && ondisk "$croot"; }; then
  echo "tacy pre-launch: moving the image stores into memory"
  systemctl stop docker.socket docker.service 2>/dev/null || true
  systemctl stop containerd.service 2>/dev/null || true
  for d in "$droot" "$croot"; do
    mkdir -p "$d"
    if ondisk "$d"; then mount -t tmpfs -o size=4g,mode=0711 tmpfs "$d"; fi
  done
  systemctl start containerd.service 2>/dev/null || true
  systemctl start docker.service
fi
for d in "$droot" "$croot"; do
  [ ! -d "$d" ] || ! ondisk "$d" || fail "$d is still on a disk"
done
[ "$(docker info -f '{{.DockerRootDir}}')" = "$droot" ] || fail "docker's data root moved"
install -d -m 0700 -o 10005 -g 10005 /run/tacy-unlock
printf 'boot=%s docker=%s containerd=%s fs=tmpfs\n' "$(cat /proc/sys/kernel/random/boot_id)" "$droot" "$croot" > /run/tacy-unlock/memory-root
chmod 0444 /run/tacy-unlock/memory-root
echo "tacy pre-launch: image stores in memory"
`

// MemoryRootScripts are the reviewed memory-root pre-launch scripts, by sha256.
var MemoryRootScripts = map[string]string{sha256hex(MemoryRootScript): "Tacy memory-root pre-launch v1"}

func init() {
	for k, v := range MemoryRootScripts {
		PreLaunchScripts[k] = v
	}
}

func sha256hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// MemoryRoot is the compose marker holders require of an agent VM with key_provider kms before they seal a share:
// its app-compose's pre-launch script is a reviewed memory-root one (nil or "": none, refused).
func MemoryRoot(preLaunch *string) error {
	if preLaunch == nil || *preLaunch == "" {
		return errors.New("no memory-root pre-launch script: the images would be unpacked onto the provider-keyed disk")
	}
	if _, ok := MemoryRootScripts[sha256hex(*preLaunch)]; !ok {
		return errors.New("the pre-launch script isn't a reviewed memory-root one")
	}
	return nil
}

// UnlockdCheck is the name of the unlockd check.
const UnlockdCheck = "split-key unlock: images in TD memory, only unlockd makes quotes, agentd attests under its own label"

// HasUnlockd says whether a docker compose has the unlockd service.
func HasUnlockd(compose string) bool {
	var doc struct {
		Services map[string]any `yaml:"services"`
	}
	if yaml.Unmarshal([]byte(compose), &doc) != nil {
		return false
	}
	_, ok := doc.Services[UnlockdService]
	return ok
}

// UnlockdRules checks a compose with unlockd (nil when it has none) for key mode mode (KeyProviderNone or
// KeyProviderKMS): unlockd isolated, the only one with dstack's socket and the unlock cache (with key_provider none
// the setup container may mount the cache directory too, to give it to unlockd's uid); in the KMS fallback the
// memory-root pre-launch script, with key_provider none no script and unlockd's -key-mode none.
func UnlockdRules(compose string, preLaunch *string, mode string) error {
	var doc struct {
		Services map[string]struct {
			Command     []string `yaml:"command"`
			NetworkMode string   `yaml:"network_mode"`
			Ports       []any    `yaml:"ports"`
			User        string   `yaml:"user"`
			ReadOnly    bool     `yaml:"read_only"`
			CapDrop     []string `yaml:"cap_drop"`
			CapAdd      []string `yaml:"cap_add"`
			Volumes     []any    `yaml:"volumes"`
			Privileged  bool     `yaml:"privileged"`
		} `yaml:"services"`
	}
	if err := yaml.Unmarshal([]byte(compose), &doc); err != nil {
		return fmt.Errorf("docker compose isn't YAML: %w", err)
	}
	u, ok := doc.Services[UnlockdService]
	if !ok {
		return nil
	}
	if u.NetworkMode != "none" || len(u.Ports) > 0 {
		return errors.New("unlockd has a network or a port")
	}
	if uid, _, _ := strings.Cut(u.User, ":"); uid != UnlockdUID || !u.ReadOnly || !slices.Equal(u.CapDrop, []string{"ALL"}) || len(u.CapAdd) > 0 || u.Privileged {
		return errors.New("unlockd isn't its own uid, read-only, without capabilities")
	}
	for name, s := range doc.Services {
		for _, v := range s.Volumes {
			src := ""
			switch m := v.(type) {
			case string:
				src, _, _ = strings.Cut(m, ":")
			case map[string]any:
				src, _ = m["source"].(string)
			}
			if name == UnlockdService {
				continue
			}
			if src == UnlockCacheDir && name == SetupService && mode == KeyProviderNone {
				continue // setup makes it for unlockd's uid (no pre-launch script in this mode)
			}
			if src == "/var/run/dstack.sock" || src == UnlockCacheDir || strings.HasPrefix(src, UnlockCacheDir+"/") {
				return fmt.Errorf("service %s mounts %s: only unlockd may (it alone makes quotes and keeps the keys)", name, src)
			}
		}
	}
	if err := TasksRules(compose, mode); err != nil { // agentd's task queue: the same kind of host tmpfs, agentd's alone
		return err
	}
	keyMode := ""
	for i, a := range u.Command {
		if a == UnlockdKeyModeFlag && i+1 < len(u.Command) {
			keyMode = u.Command[i+1]
		} else if strings.HasPrefix(a, UnlockdKeyModeFlag+"=") {
			keyMode = strings.TrimPrefix(a, UnlockdKeyModeFlag+"=")
		}
	}
	switch mode {
	case KeyProviderNone:
		if keyMode != KeyProviderNone {
			return errors.New("key_provider none: unlockd must run with -key-mode none")
		}
		if preLaunch != nil && *preLaunch != "" {
			return errors.New("key_provider none: no pre-launch script (the disk's key is the TD's)")
		}
		return nil
	case KeyProviderKMS:
		if keyMode != "" {
			return fmt.Errorf("the KMS fallback: unlockd must not set %s (it must wait for the memory-root marker)", UnlockdKeyModeFlag)
		}
		return MemoryRoot(preLaunch)
	default:
		return fmt.Errorf("key mode %q", mode)
	}
}

// checkUnlockd runs UnlockdRules and, outside a key release, requires agentd's attestation label.
func (r *Result) checkUnlockd(compose string, preLaunch *string, mode, version string, keyRelease bool) bool {
	if !HasUnlockd(compose) {
		if version == proto.VersionAgent {
			return r.add(UnlockdCheck, errors.New("an agentd attestation label from a release without unlockd"), "")
		}
		return true
	}
	err := UnlockdRules(compose, preLaunch, mode)
	if err == nil && !keyRelease && version != proto.VersionAgent {
		err = errors.New("agentd's attestation isn't under its own label (proto.VersionAgent)")
	}
	if err == nil && keyRelease && version == proto.VersionAgent {
		err = errors.New("an agentd attestation can't ask for keys")
	}
	detail := "unlockd alone has dstack's socket; Docker's data root in TD memory (memory-root pre-launch v1)"
	if mode == KeyProviderNone {
		detail = "unlockd alone has dstack's socket; the disk under the key made in the VM (no pre-launch script)"
	}
	return r.add(UnlockdCheck, err, detail)
}
