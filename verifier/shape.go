package verifier

import (
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"
)

// The release's exact shape (review 2, M1 and L2, 2026-11-21). A release with unlockd (the v1 line: every release a
// holder unlocks) must be the compose cmd/compose writes, key by key and argument by argument: every service's image
// (its own binary's repository, by digest), user, groups, network (none for everyone but gatewayd, which has its own
// bridge network and no networks: key), environment (gatewayd's HOME=/tmp, nobody else any), volumes and their modes,
// tmpfs mounts, capabilities, security options, limits and command line. A command is the generator's flags in its
// order, each value either the generator's constant (paths, uids, -tunnel-uid 10006, -unlock-domain tacy.io) or of
// its form (keys, hashes, https URLs); no other flag, no flag twice, no -flag=value form, no positional argument. An
// unknown key anywhere (an environment variable such as SSL_CERT_FILE, GODEBUG or HTTPS_PROXY, networks:, ports:,
// extra_hosts:, an x- extension, a top-level name:) is refused, and so are YAML anchors, aliases, merge keys and
// explicit tags (docker compose's !reset and !override included), so what the verifier reads is what compose runs.
// The trust roots each process pins must be the same in each (the firm, the operator key, the key log), and the KMS
// id and the unlock admin keys the same in gatewayd and unlockd.
//
// The denylist (servicePrivileges, UnlockdRules, TasksRules) stays as well, and alone covers the releases before
// unlockd (v0.20.0 and older, live before v1) and the e2e levels (their overlays change logging, add the diag
// service and keep -listen). A change to cmd/compose's output is a change here first, in a client and holder build
// that ships before the VM release (the no-downtime plan rows 10 and 29). A signed trust list may still name an extra service,
// but not in a release with unlockd: its shape is these six.

// ReleaseShapeCheck names the check (it is part of ImagesCheck's result).
const ReleaseShapeCheck = "a release with unlockd is exactly cmd/compose's shape"

// UnlockDomain is the only domain the holders may be on (gatewayd's -unlock-domain; cmd/compose's unlockDomain).
const UnlockDomain = "tacy.io"

// AccessTeam is the Cloudflare Zero Trust team whose Access app cloudflared checks the JWT of (gatewayd's
// -cloudflared-access <team>,<aud>; cmd/compose's releaseAccessTeam): pinned by value, so a release can only name an
// Access app of our own account (its certs at https://<team>.cloudflareaccess.com/cdn-cgi/access/certs). The audience
// is taken by form (a staging release names its own app in the same team) but never the all-zero placeholder, which
// no Access app has.
const AccessTeam = "baldcactus"

// val is a scalar the shape takes by form, not by value: ok says whether s is of the form; same, when set, names a
// value that must be equal wherever it appears (part picks the compared piece; nil: all of it).
type val struct {
	what string
	ok   func(s string) bool
	same string
	part func(s string) string
}

func re(p string) func(string) bool { return regexp.MustCompile(p).MatchString }

var (
	isKey  = re(`^ed25519:[A-Za-z0-9+/]{43}=$`)
	isKeys = func(s string) bool {
		return len(s) <= 16*53 && re(`^ed25519:[A-Za-z0-9+/]{43}=(,ed25519:[A-Za-z0-9+/]{43}=)*$`)(s)
	}
	isHex64    = re(`^[0-9a-f]{64}$`)
	isHexList  = func(s string) bool { return len(s) <= 32*65 && re(`^[0-9a-f]{64}(,[0-9a-f]{64})*$`)(s) }
	isHTTPS    = re(`^https://[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+(/[A-Za-z0-9._~/-]*)?$`)
	isFirm     = re(`^f_[A-Za-z0-9_-]{1,60}$`)
	isCount    = re(`^[1-9][0-9]{0,8}$`)
	isDoT      = re(`^[a-z0-9]([a-z0-9.-]*[a-z0-9])?@[0-9.]{7,15}:[0-9]{1,5}(,[0-9.]{7,15}:[0-9]{1,5}){0,3}$`)
	isKeyNames = re(`^[A-Z][A-Z0-9_]{0,63}(,[A-Z][A-Z0-9_]{0,63}){0,15}$`)
	isProvider = re(`^(exa|tavily|brave)$`)
	isGVisor   = re(`^[0-9]{8}\.[0-9]+$`)
	isTunnel   = re(`^CF_TUNNEL_TOKEN_VM[AB]$`)
	isAccess   = func(s string) bool { // gateway/cftunnel.ParseAccess's <team>,<aud>: our team, a real audience
		team, aud, ok := strings.Cut(s, ",")
		return ok && team == AccessTeam && isHex64(aud) && aud != strings.Repeat("0", 64)
	}
)

func key(same string) val                        { return val{what: "an ed25519 key", ok: isKey, same: same} }
func keys(same string) val                       { return val{what: "ed25519 keys", ok: isKeys, same: same} }
func hex64(same string) val                      { return val{what: "a sha256", ok: isHex64, same: same} }
func https() val                                 { return val{what: "an https URL", ok: isHTTPS} }
func count(same string) val                      { return val{what: "a count", ok: isCount, same: same} }
func form(what string, ok func(string) bool) val { return val{what: what, ok: ok} }

// image is service img's image: its own repository (any registry: a throwaway's names a scratch one) by digest, the
// same registry for every service.
func image(img string) val {
	return val{what: "the " + img + " image by digest", same: "registry",
		ok: func(s string) bool {
			repo, _, ok := strings.Cut(s, "@sha256:")
			return ok && digestRef.MatchString(s) && strings.HasSuffix(repo, "/"+img)
		},
		part: func(s string) string { return strings.TrimSuffix(s[:strings.Index(s, "@")], img) }}
}

func list(a ...any) []any { return a }

// trustShape is the trust-root flags every guard process gets (cmd/compose trustArgs, the key log form).
func trustShape() []any {
	return list("-firm", val{what: "a firm id", ok: isFirm, same: "firm"}, "-personal-spaces", "-operator-key", key("operator-key"),
		"-keylog-genesis", hex64("keylog-genesis"), "-keylog-carry", val{what: "sha256s", ok: isHexList, same: "keylog-carry"})
}

// serviceShape is a long-running service's common keys (cmd/compose's service()).
func serviceShape(img, user string, network bool, opts ...string) map[string]any {
	sec := list("no-new-privileges:true")
	for _, o := range opts {
		sec = append(sec, o)
	}
	m := map[string]any{
		"image":        image(img),
		"entrypoint":   list("/tacy/" + img),
		"restart":      "unless-stopped",
		"logging":      map[string]any{"driver": "none"},
		"ulimits":      map[string]any{"core": 0},
		"depends_on":   map[string]any{"setup": map[string]any{"condition": "service_completed_successfully"}},
		"user":         user,
		"read_only":    true,
		"cap_drop":     list("ALL"),
		"security_opt": sec,
	}
	if !network {
		m["network_mode"] = "none"
	}
	return m
}

func cat(parts ...[]any) []any {
	var out []any
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// releaseShape is the compose cmd/compose writes for a release, keysInVM (key_provider none: the task queue and
// unlockd's cache made by setup, unlockd -key-mode none) or the KMS fallback.
func releaseShape(keysInVM bool) map[string]any {
	setupVolumes := list("agentsock:/run/tacy/agent", "vaultsock:/run/tacy/vault", "runnersock:/run/tacy/runner", "opssock:/run/tacy/ops",
		"unlockagent:/run/tacy/unlock", "unlockvault:/run/tacy/unlockv", "unlockgw:/run/tacy/unlockgw")
	setupDirs := list("-dir", "/run/tacy/agent=10003:10001:0770", "-dir", "/run/tacy/vault=10002:10001:0750",
		"-dir", "/run/tacy/runner=10004:10003:0750", "-dir", "/run/tacy/ops=10001:10001:0750", "-dir", "/run/tacy/unlock=10005:10005:0750",
		"-dir", "/run/tacy/unlockv=10005:10005:0750", "-dir", "/run/tacy/unlockgw=10001:10001:0750")
	agentdVolumes := list("runnersock:/run/tacy/runner", "agentsock:/run/tacy/agent", "unlockagent:/run/tacy/unlock")
	agentdArgs := cat(list("-runner-socket", "/run/tacy/runner/runner.sock", "-gateway-socket", "/run/tacy/agent/gateway.sock",
		"-listen-unix", "/run/tacy/agent/http.sock", "-listen-uid", "10001", "-listen-gid", "10001", "-mem-limit-mib", count(""),
		"-relay-auth-key", key(""), "-unlock-socket", "/run/tacy/unlock/agentd.sock", "-state", "relay"), trustShape())
	unlockdArgs := list("-kms-key", key("kms-key"), "-unlock-admin-keys", keys("unlock-admin-keys"), "-unlock-admin-threshold",
		count("unlock-admin-threshold"), "-min-epoch", count(""), "-gateway-socket", "/run/tacy/unlockgw/gateway.sock",
		"-agent-socket", "/run/tacy/unlock/agentd.sock", "-agent-uid", "10003", "-vault-socket", "/run/tacy/unlockv/vaultd.sock",
		"-vault-uid", "10002", "-cache-dir", UnlockCacheDir)
	if keysInVM {
		setupVolumes = append(setupVolumes, UnlockCacheDir+":"+UnlockCacheDir, TasksDir+":"+TasksDir)
		setupDirs = append(setupDirs, "-dir", UnlockCacheDir+"=10005:10005:0700", "-dir", TasksDir+"=10003:10003:0700")
		agentdVolumes = append(agentdVolumes, TasksDir+":"+TasksDir)
		agentdArgs = append(agentdArgs, "-tasks-dir", TasksDir)
		unlockdArgs = append(unlockdArgs, UnlockdKeyModeFlag, KeyProviderNone)
	}

	setup := map[string]any{
		"image":        image("setup"),
		"entrypoint":   list("/tacy/setup"),
		"network_mode": "none",
		"restart":      "no",
		"logging":      map[string]any{"driver": "none"},
		"ulimits":      map[string]any{"core": 0},
		"user":         "0:0",
		"read_only":    true,
		"cap_drop":     list("ALL"),
		"cap_add":      list("CHOWN", "DAC_OVERRIDE", "FOWNER"),
		"security_opt": list("no-new-privileges:true"),
		"volumes":      setupVolumes,
		"command":      setupDirs,
	}

	agentd := serviceShape("agentd", "10003:10003", false)
	agentd["group_add"] = list("10001", "10005")
	agentd["volumes"] = agentdVolumes
	agentd["command"] = agentdArgs

	runner := serviceShape("runnerd", "10004:10003", false, "seccomp:unconfined")
	runner["mem_limit"], runner["memswap_limit"], runner["pids_limit"] = "640m", "640m", 512
	runner["tmpfs"] = list("/run/runner:exec,size=64m,mode=0700,uid=10004,gid=10003", "/tmp:size=16m")
	runner["volumes"] = list("runnersock:/run/tacy/runner")
	runner["command"] = list("-socket", "/run/tacy/runner/runner.sock", "-agent-uid", "10003", "-gvisor", "/tacy/gvisor",
		"-gvisor-release", form("a gVisor release", isGVisor), "-runsc-sha256", hex64(""), "-brain", "/tacy/brain", "-brain-sha256", hex64(""),
		"-dir", "/run/runner", "-platform", "systrap", "-rootless")

	// gatewayd: its launcher (GatewaydLaunchException) as root with SETUID and SETGID only, its own bridge network,
	// HOME=/tmp and nothing else in its environment, no published port and no -listen, cloudflared as 10006, the Access
	// app as a pin (-cloudflared-access: the launcher writes cloudflared's config from it; no config file in the
	// image; the team by value, AccessTeam), never the e2e diag route (-e2e-diag: not in the shape, so refused).
	gw := serviceShape("gatewayd", "0:0", true)
	gw["cap_add"] = list("SETGID", "SETUID")
	gw["tmpfs"] = list("/tmp:mode=0700,uid=10001,gid=10001", "/run/tunnel:size=1m,mode=0750,uid=10001,gid=10006")
	gw["volumes"] = list("agentsock:/run/tacy/agent", "vaultsock:/run/tacy/vault", "opssock:/run/tacy/ops", "unlockgw:/run/tacy/unlockgw")
	gw["environment"] = map[string]any{"HOME": "/tmp"}
	gw["command"] = cat(list("-socket", "/run/tacy/agent/gateway.sock", "-agent-uid", "10003", "-vault-socket", "/run/tacy/vault/vault.sock",
		"-forward", "/run/tacy/agent/http.sock", "-search-provider", form("a search provider", isProvider),
		"-expected-keys", form("key names", isKeyNames), "-state-url", https(), "-ops-socket", "/run/tacy/ops/gateway.sock",
		"-vault-uid", "10002", "-kms-key", key("kms-key"), "-unlock-domain", UnlockDomain, "-unlock-admin-keys", keys("unlock-admin-keys"),
		"-unlock-admin-threshold", count("unlock-admin-threshold"), "-unlock-socket", "/run/tacy/unlockgw/gateway.sock", "-unlockd-uid", "10005"),
		trustShape(),
		list("-safety-url", https(), "-keylog-url", https(), "-dns-tls", form("a DNS-over-TLS resolver", isDoT),
			"-"+TunnelUIDFlag, "10006", "-cloudflared", "/tacy/cloudflared", "-cloudflared-sha256", hex64(""),
			"-cloudflared-access", form("an Access app ("+AccessTeam+",aud)", isAccess), "-tunnel-secret", form("a tunnel token's name", isTunnel)))

	vaultd := serviceShape("vaultd", "10002:10001", false)
	vaultd["group_add"] = list("10005")
	vaultd["volumes"] = list("vaultsock:/run/tacy/vault", "opssock:/run/tacy/ops", "unlockvault:/run/tacy/unlockv")
	vaultd["command"] = cat(list("-socket", "/run/tacy/vault/vault.sock", "-gateway-uid", "10001", "-group-mode",
		"-unlock-socket", "/run/tacy/unlockv/vaultd.sock", "-ops-socket", "/run/tacy/ops/gateway.sock"), trustShape())

	unlockd := serviceShape("unlockd", "10005:10005", false)
	unlockd["group_add"] = list("10001")
	unlockd["volumes"] = list("/var/run/dstack.sock:/var/run/dstack.sock", UnlockCacheDir+":"+UnlockCacheDir,
		"unlockagent:/run/tacy/unlock", "unlockvault:/run/tacy/unlockv", "unlockgw:/run/tacy/unlockgw")
	unlockd["command"] = unlockdArgs

	tmpfsVol := func(uid, gid, mode string) map[string]any {
		return map[string]any{"driver_opts": map[string]any{"type": "tmpfs", "device": "tmpfs",
			"o": "size=1m,uid=" + uid + ",gid=" + gid + ",mode=" + mode}}
	}
	return map[string]any{
		"services": map[string]any{"setup": setup, "agentd": agentd, "runner": runner, GatewaydService: gw, "vaultd": vaultd, UnlockdService: unlockd},
		"volumes": map[string]any{
			"runnersock":  tmpfsVol("10004", "10003", "0750"),
			"agentsock":   tmpfsVol("10003", "10001", "0770"),
			"vaultsock":   tmpfsVol("10002", "10001", "0750"),
			"opssock":     tmpfsVol("10001", "10001", "0750"),
			"unlockagent": tmpfsVol("10005", "10005", "0750"),
			"unlockvault": tmpfsVol("10005", "10005", "0750"),
			"unlockgw":    tmpfsVol("10001", "10001", "0750"),
		},
	}
}

// plainYAML refuses what makes a YAML file mean more than its plain tree: anchors, aliases, merge keys and explicit
// tags (compose's !reset and !override among them), and any type but strings, integers, booleans, maps and lists.
func plainYAML(n *yaml.Node, path string) error {
	if n.Anchor != "" || n.Kind == yaml.AliasNode {
		return fmt.Errorf("%s: a YAML anchor or alias", path)
	}
	if n.Style&yaml.TaggedStyle != 0 {
		return fmt.Errorf("%s: an explicit YAML tag (%s)", path, n.Tag)
	}
	switch n.Kind {
	case yaml.DocumentNode, yaml.SequenceNode:
		for i, c := range n.Content {
			if err := plainYAML(c, fmt.Sprintf("%s[%d]", path, i)); err != nil {
				return err
			}
		}
	case yaml.MappingNode:
		for i := 0; i+1 < len(n.Content); i += 2 {
			k := n.Content[i]
			if k.Kind != yaml.ScalarNode || k.Tag != "!!str" || k.Value == "<<" {
				return fmt.Errorf("%s: a key that isn't a plain string (%q)", path, k.Value)
			}
			if err := plainYAML(k, path); err != nil {
				return err
			}
			if err := plainYAML(n.Content[i+1], path+"."+k.Value); err != nil {
				return err
			}
		}
	case yaml.ScalarNode:
		switch n.Tag {
		case "!!str", "!!int", "!!bool":
		default:
			return fmt.Errorf("%s: a %s value", path, n.Tag)
		}
	}
	return nil
}

// ReleaseShape checks compose (a release with unlockd) is exactly the shape cmd/compose writes (releaseShape), in
// its key_provider none form or its KMS fallback form (chosen by unlockd's -key-mode; the other parts must agree).
func ReleaseShape(compose string) error { return releaseShapeWith(compose, nil) }

// releaseShapeWith is ReleaseShape where services named in extra (a signed trust list's, Policy.Services) may also be
// there; they get the denylist only (servicePrivileges), the release's six still their exact shape.
func releaseShapeWith(compose string, extra []string) error {
	var root yaml.Node
	if err := yaml.Unmarshal([]byte(compose), &root); err != nil {
		return fmt.Errorf("docker compose isn't YAML: %w", err)
	}
	if err := plainYAML(&root, "compose"); err != nil {
		return fmt.Errorf("release shape: %w", err)
	}
	var doc map[string]any
	if err := yaml.Unmarshal([]byte(compose), &doc); err != nil {
		return fmt.Errorf("docker compose isn't YAML: %w", err)
	}
	keysInVM := false
	if s, ok := doc["services"].(map[string]any); ok {
		if u, ok := s[UnlockdService].(map[string]any); ok {
			if c, ok := u["command"].([]any); ok {
				keysInVM = slices.Contains(c, any(UnlockdKeyModeFlag))
			}
		}
	}
	if s, ok := doc["services"].(map[string]any); ok && len(extra) > 0 {
		own := map[string]any{}
		for k, v := range s {
			if !slices.Contains(extra, k) || slices.Contains(ReleaseServices, k) {
				own[k] = v
			}
		}
		doc["services"] = own
	}
	seen := map[string]string{}
	if err := matchShape("compose", releaseShape(keysInVM), doc, seen); err != nil {
		return fmt.Errorf("release shape: %w", err)
	}
	return nil
}

// matchShape matches got against want (a map: exactly its keys; a list: exactly its items in order; a val: a string
// of its form; else the same value of the same type).
func matchShape(path string, want, got any, seen map[string]string) error {
	switch w := want.(type) {
	case map[string]any:
		g, ok := got.(map[string]any)
		if !ok {
			return fmt.Errorf("%s isn't a mapping", path)
		}
		var extra []string
		for k := range g {
			if _, ok := w[k]; !ok {
				extra = append(extra, k)
			}
		}
		if len(extra) > 0 {
			sort.Strings(extra)
			return fmt.Errorf("%s has %s, which the release's shape doesn't", path, strings.Join(extra, ", "))
		}
		ks := make([]string, 0, len(w))
		for k := range w {
			ks = append(ks, k)
		}
		sort.Strings(ks)
		for _, k := range ks {
			v, ok := g[k]
			if !ok {
				return fmt.Errorf("%s has no %s", path, k)
			}
			if err := matchShape(path+"."+k, w[k], v, seen); err != nil {
				return err
			}
		}
		return nil
	case []any:
		g, ok := got.([]any)
		if !ok {
			return fmt.Errorf("%s isn't a list", path)
		}
		for i := 0; i < len(w) || i < len(g); i++ {
			switch {
			case i >= len(g):
				return fmt.Errorf("%s ends at item %d: the release's shape has %v next", path, i, describe(w[i]))
			case i >= len(w):
				return fmt.Errorf("%s has an item the release's shape doesn't: %q", path, fmt.Sprint(g[i]))
			}
			if err := matchShape(fmt.Sprintf("%s[%d]", path, i), w[i], g[i], seen); err != nil {
				return err
			}
		}
		return nil
	case val:
		s, ok := got.(string)
		if !ok || !w.ok(s) {
			return fmt.Errorf("%s isn't %s", path, w.what)
		}
		if w.same != "" {
			p := s
			if w.part != nil {
				p = w.part(s)
			}
			if prev, ok := seen[w.same]; ok && prev != p {
				return fmt.Errorf("%s: its %s differs from another service's", path, w.same)
			}
			seen[w.same] = p
		}
		return nil
	default:
		if fmt.Sprintf("%T", want) != fmt.Sprintf("%T", got) || want != got {
			return fmt.Errorf("%s is %q, the release's shape has %q", path, fmt.Sprint(got), fmt.Sprint(want))
		}
		return nil
	}
}

func describe(w any) string {
	if v, ok := w.(val); ok {
		return v.what
	}
	return fmt.Sprintf("%q", fmt.Sprint(w))
}
