package verifier

import (
	"strings"
	"testing"
)

// Review 2, M1 and L2 (a research note): a release with unlockd must be exactly the shape
// cmd/compose writes, service by service (ReleaseShape). The review's probe composes (its vprobe/main.go and
// main2.go, cases A to G) passed ComposeImages, UnlockdRules and TasksRules before; each must now be refused by
// ComposeImages, the check every production verifier (clients, holders, the key service) runs.

// edit is compose with old replaced by new once (the test fails if old isn't there).
// slotToken is the tunnel secret the committed compose's gatewayd leases (its slot's: a release on either slot).
func slotToken(t *testing.T, compose string) string {
	t.Helper()
	a, b := strings.Contains(compose, `"-tunnel-secret", "CF_TUNNEL_TOKEN_VM`+"A"+`"]`), strings.Contains(compose, `"-tunnel-secret", "CF_TUNNEL_TOKEN_VM`+"B"+`"]`)
	switch {
	case a && !b:
		return "CF_TUNNEL_TOKEN_VM" + "A"
	case b && !a:
		return "CF_TUNNEL_TOKEN_VM" + "B"
	}
	t.Fatal("compose.yaml leases no single tunnel slot")
	return ""
}

func edit(t *testing.T, compose, old, new string) string {
	t.Helper()
	if !strings.Contains(compose, old) {
		t.Fatalf("compose has no %q", old)
	}
	return strings.Replace(compose, old, new, 1)
}

// inService is compose with old replaced by new once inside service svc's section.
func inService(t *testing.T, compose, svc, old, new string) string {
	t.Helper()
	i := strings.Index(compose, "\n  "+svc+":\n")
	if i < 0 {
		t.Fatalf("no service %s", svc)
	}
	j := len(compose)
	for _, next := range []string{"\n  setup:", "\n  agentd:", "\n  runner:", "\n  agentvm:", "\n  vaultd:", "\n  unlockd:", "\nvolumes:"} {
		if m := strings.Index(compose[i+1:], next); m >= 0 && i+1+m < j {
			j = i + 1 + m
		}
	}
	sec := compose[i:j]
	if !strings.Contains(sec, old) {
		t.Fatalf("service %s has no %q", svc, old)
	}
	return compose[:i] + strings.Replace(sec, old, new, 1) + compose[j:]
}

// refusedEverywhere: a production verifier refuses compose (ComposeImages), and so does the release-shape check alone.
func refusedEverywhere(t *testing.T, name, compose string) {
	t.Helper()
	if _, err := ComposeImages(compose); err == nil {
		t.Errorf("%s: accepted by ComposeImages", name)
	} else {
		t.Logf("%s: %v", name, err)
	}
}

// The review's probes, verbatim in effect (vprobe/main.go A to F, main2.go G).
func TestReviewProbeComposesRefused(t *testing.T) {
	base := string(composeYAML(t))
	tok := slotToken(t, base)
	if _, err := ComposeImages(base); err != nil {
		t.Fatalf("the release compose: %v", err)
	}
	hostnet := "networks:\n  hostnet:\n    external: true\n    name: host\n"
	// A: agentd on the host network via networks:, TCP listener (no -listen-unix).
	a := inService(t, base, "agentd", "    network_mode: none\n", "    networks: [hostnet]\n")
	a = edit(t, a, `"-listen-unix", "/run/tacy/agent/http.sock", `, "") + hostnet
	// B: agentvm on the host network.
	b := edit(t, base, "    entrypoint: [\"/tacy/gatewayd\"]\n    restart: unless-stopped", "    entrypoint: [\"/tacy/gatewayd\"]\n    networks: [hostnet]\n    restart: unless-stopped") + hostnet
	// C: tunnel-uid = agentd's, gatewayd-uid = vaultd's.
	c := edit(t, base, `"-tunnel-uid", "10006"`, `"-tunnel-uid", "10003", "-gatewayd-uid", "10002"`)
	// D: vaultd with the default network (a second network_mode key: also a duplicate).
	d := edit(t, base, "  vaultd:\n    image:", "  vaultd:\n    network_mode: bridge\n    image:")
	// E: setup makes the vault directory 0777 and the runner runs as gatewayd's uid.
	e := edit(t, base, "/run/tacy/vault=10002:10001:0750", "/run/tacy/vault=10002:10001:0777")
	e = edit(t, e, `user: "10004:10003"`, `user: "10001:10001"`)
	// F: agentvm with the launcher's capabilities but no user (the image's default).
	f := edit(t, base, "    user: \"0:0\"\n    read_only: true\n    cap_drop: [ALL]\n    cap_add: [SETGID, SETUID]", "    read_only: true\n    cap_drop: [ALL]\n    cap_add: [SETGID, SETUID]")
	// G: agentvm with SSL_CERT_FILE=/proc/self/cmdline and a PEM CA as an extra argument.
	g := edit(t, base, "    environment:\n      HOME: /tmp\n", "    environment:\n      HOME: /tmp\n      SSL_CERT_FILE: /proc/self/cmdline\n")
	g = edit(t, g, `"-tunnel-secret", "`+tok+`"]`, `"-tunnel-secret", "`+tok+`", "\n-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----\n"]`)
	for name, comp := range map[string]string{
		"A agentd host network + TCP :8080":        a,
		"B agentvm host network":                   b,
		"C tunnel-uid 10003, gatewayd-uid 10002":   c,
		"D vaultd network_mode bridge":             d,
		"E vault dir 0777, runner as 10001":        e,
		"F agentvm without user:":                  f,
		"G agentvm SSL_CERT_FILE + PEM argument":   g,
		"G1 SSL_CERT_FILE alone":                   edit(t, base, "      HOME: /tmp\n", "      HOME: /tmp\n      SSL_CERT_FILE: /proc/self/cmdline\n"),
		"G2 a PEM argument alone":                  edit(t, base, `"-tunnel-secret", "`+tok+`"]`, `"-tunnel-secret", "`+tok+`", "x"]`),
		"A1 agentd without -listen-unix":           edit(t, base, `"-listen-unix", "/run/tacy/agent/http.sock", `, ""),
		"A2 networks: on agentd":                   inService(t, base, "agentd", "    network_mode: none\n", "    network_mode: none\n    networks: [hostnet]\n") + hostnet,
		"A3 top-level networks: alone":             base + hostnet,
		"C1 -tunnel-uid 10004":                     edit(t, base, `"-tunnel-uid", "10006"`, `"-tunnel-uid", "10004"`),
		"C2 -gatewayd-uid 10001 (not the release)": edit(t, base, `"-tunnel-uid", "10006"`, `"-tunnel-uid", "10006", "-gatewayd-uid", "10001"`),
	} {
		if comp == base {
			t.Fatalf("%s: the edit didn't apply", name)
		}
		refusedEverywhere(t, name, comp)
	}
}

// The review's missing test 1: environment beyond the template, networks, a service off network_mode none, agentd
// without -listen-unix, positional arguments, other user or cap_drop values, setup's -dir modes, wrong uids, and the
// YAML forms (anchors, merge keys, tags, extension keys) that could make what a verifier reads differ from what
// docker compose runs.
func TestReleaseShapeAllowlist(t *testing.T) {
	base := string(composeYAML(t))
	env := func(kv string) string { return edit(t, base, "      HOME: /tmp\n", "      HOME: /tmp\n      "+kv+"\n") }
	cases := map[string]string{
		"GODEBUG":                    env("GODEBUG: x509sha1=1"),
		"HTTPS_PROXY":                env("HTTPS_PROXY: http://10.0.0.1:3128"),
		"SSL_CERT_DIR":               env("SSL_CERT_DIR: /tmp"),
		"HOME elsewhere":             edit(t, base, "      HOME: /tmp\n", "      HOME: /run/tunnel\n"),
		"environment on agentd":      inService(t, base, "agentd", "    group_add:", "    environment:\n      GODEBUG: x\n    group_add:"),
		"env_file":                   inService(t, base, "vaultd", "    group_add:", "    env_file: [x.env]\n    group_add:"),
		"agentd network bridge":      inService(t, base, "agentd", "    network_mode: none\n", "    network_mode: bridge\n"),
		"unlockd network default":    inService(t, base, "unlockd", "    network_mode: none\n", "    network_mode: default\n"),
		"agentvm network_mode none":  edit(t, base, "    entrypoint: [\"/tacy/gatewayd\"]\n", "    entrypoint: [\"/tacy/gatewayd\"]\n    network_mode: none\n"),
		"agentvm network_mode host":  edit(t, base, "    entrypoint: [\"/tacy/gatewayd\"]\n", "    entrypoint: [\"/tacy/gatewayd\"]\n    network_mode: host\n"),
		"positional on agentd":       edit(t, base, `"-tasks-dir", "/run/tacy-tasks"]`, `"-tasks-dir", "/run/tacy-tasks", "extra"]`),
		"unknown flag on vaultd":     edit(t, base, `"-group-mode",`, `"-group-mode", "-dev-fixed-http",`),
		"flag=value form":            edit(t, base, `"-tunnel-uid", "10006"`, `"-tunnel-uid=10006"`),
		"a flag twice":               edit(t, base, `"-tunnel-uid", "10006"`, `"-tunnel-uid", "10006", "-tunnel-uid", "10006"`),
		"agentd -addr":               edit(t, base, `"-tasks-dir", "/run/tacy-tasks"]`, `"-tasks-dir", "/run/tacy-tasks", "-addr", ":8080"]`),
		"agentd -platform local":     edit(t, base, `"-tasks-dir", "/run/tacy-tasks"]`, `"-tasks-dir", "/run/tacy-tasks", "-platform", "local"]`),
		"agentd -state memory":       edit(t, base, `"-state", "relay"`, `"-state", "memory"`),
		"agentd -listen-uid 0":       edit(t, base, `"-listen-uid", "10001"`, `"-listen-uid", "0"`),
		"agentd user root":           edit(t, base, `user: "10003:10003"`, `user: "0:0"`),
		"vaultd user 10001":          edit(t, base, `user: "10002:10001"`, `user: "10001:10001"`),
		"unlockd extra group":        inService(t, base, "unlockd", `group_add: ["10001"]`, `group_add: ["10001", "10002"]`),
		"agentd cap_drop none":       inService(t, base, "agentd", "    cap_drop: [ALL]\n", "    cap_drop: [NET_RAW]\n"),
		"agentd read_only false":     inService(t, base, "agentd", "    read_only: true\n", "    read_only: false\n"),
		"agentd no no-new-privs":     inService(t, base, "agentd", `security_opt: ["no-new-privileges:true"]`, `security_opt: []`),
		"agentd restart":             inService(t, base, "agentd", "    restart: unless-stopped\n", "    restart: always\n"),
		"agentd logging json-file":   inService(t, base, "agentd", "      driver: none\n", "      driver: json-file\n"),
		"agentd core dumps":          inService(t, base, "agentd", "      core: 0\n", "      core: -1\n"),
		"agentd shm_size":            inService(t, base, "agentd", "    read_only: true\n", "    read_only: true\n    shm_size: 1g\n"),
		"agentd tmpfs":               inService(t, base, "agentd", "    read_only: true\n", "    read_only: true\n    tmpfs: [/tmp]\n"),
		"agentd extra_hosts":         inService(t, base, "agentd", "    read_only: true\n", "    read_only: true\n    extra_hosts: [\"chat.tacy.io:10.0.0.1\"]\n"),
		"agentd working_dir":         inService(t, base, "agentd", "    read_only: true\n", "    read_only: true\n    working_dir: /run\n"),
		"agentd volume rw elsewhere": inService(t, base, "agentd", "      - agentsock:/run/tacy/agent\n", "      - agentsock:/run/tacy/agent\n      - vaultsock:/run/tacy/vault\n"),
		"agentd volume :ro removed":  inService(t, base, "agentd", "      - runnersock:/run/tacy/runner\n", "      - runnersock:/run/tacy/runner:rw\n"),
		"agentvm extra tmpfs":        edit(t, base, `"/run/tunnel:size=1m,mode=0750,uid=10001,gid=10006"]`, `"/run/tunnel:size=1m,mode=0777,uid=10001,gid=10006"]`),
		"agentvm cap_add more":       edit(t, base, "cap_add: [SETGID, SETUID]", "cap_add: [SETGID, SETUID, NET_BIND_SERVICE]"),
		"agentvm entrypoint":         edit(t, base, `entrypoint: ["/tacy/gatewayd"]`, `entrypoint: ["/tacy/gatewayd", "-listen", ":8080"]`),
		"agentvm image of agentd":    edit(t, base, "image: ghcr.io/tacyhq/tacy/gatewayd@", "image: ghcr.io/tacyhq/tacy/agentd@"),
		"setup vault 0777":           edit(t, base, "/run/tacy/vault=10002:10001:0750", "/run/tacy/vault=10002:10001:0777"),
		"setup agent dir other gid":  edit(t, base, "/run/tacy/agent=10003:10001:0770", "/run/tacy/agent=10003:10006:0770"),
		"setup an extra dir":         edit(t, base, `"-dir", "/run/tacy-tasks=10003:10003:0700"]`, `"-dir", "/run/tacy-tasks=10003:10003:0700", "-dir", "/run/x=0:0:0777"]`),
		"setup cap_add more":         edit(t, base, "cap_add: [CHOWN, DAC_OVERRIDE, FOWNER]", "cap_add: [CHOWN, DAC_OVERRIDE, FOWNER, SYS_ADMIN]"),
		"volume mode 0777":           edit(t, base, `o: "size=1m,uid=10002,gid=10001,mode=0750"`, `o: "size=1m,uid=10002,gid=10001,mode=0777"`),
		"volume on the disk":         edit(t, base, "  vaultsock:\n    driver_opts:\n      type: tmpfs\n      device: tmpfs\n      o: \"size=1m,uid=10002,gid=10001,mode=0750\"\n", "  vaultsock:\n"),
		"an extra volume":            base + "  extra:\n    driver_opts:\n      type: tmpfs\n      device: tmpfs\n      o: \"size=1m\"\n",
		"unlock-domain elsewhere":    edit(t, base, `"-unlock-domain", "tacy.io"`, `"-unlock-domain", "evil.example"`),
		"state-url http":             edit(t, base, `"-state-url", "https://chat.tacy.io"`, `"-state-url", "http://chat.tacy.io"`),
		"dns-tls off":                edit(t, base, `"-dns-tls", "dns.quad9.net@9.9.9.9:853,149.112.112.112:853", `, ""),
		"kms-key differs":            edit(t, base, `"-kms-key", "ed25519:1LPZHjHaCjYvuibeGa0PcuFHEIadIxsp8x9EbNNMmEg=", "-unlock-admin-keys"`, `"-kms-key", "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "-unlock-admin-keys"`),
		"trust roots differ":         edit(t, base, `"-socket", "/run/tacy/vault/vault.sock", "-gateway-uid", "10001", "-group-mode", "-unlock-socket", "/run/tacy/unlockv/vaultd.sock", "-ops-socket", "/run/tacy/ops/gateway.sock", "-firm", "f_chat"`, `"-socket", "/run/tacy/vault/vault.sock", "-gateway-uid", "10001", "-group-mode", "-unlock-socket", "/run/tacy/unlockv/vaultd.sock", "-ops-socket", "/run/tacy/ops/gateway.sock", "-firm", "f_other"`),
		"a variable":                 edit(t, base, `"-firm", "f_chat"`, `"-firm", "${FIRM}"`),
		"x- extension key":           "x-tacy: 1\n" + base,
		"top-level name":             "name: tacy\n" + base,
		"an anchor":                  edit(t, base, "    read_only: true\n", "    read_only: &ro true\n"),
		"a custom tag":               inService(t, base, "agentd", "    read_only: true\n", "    read_only: !!bool true\n"),
		"a !reset tag":               inService(t, base, "agentd", "    group_add: [\"10001\", \"10005\"]\n", "    group_add: !reset [\"10001\", \"10005\"]\n"),
		"a merge key":                strings.Replace(edit(t, base, "services:\n", "x-a: &a\n  privileged: false\nservices:\n"), "  agentd:\n    image:", "  agentd:\n    <<: *a\n    image:", 1),
	}
	for name, comp := range cases {
		if comp == base {
			t.Fatalf("%s: the edit didn't apply", name)
		}
		refusedEverywhere(t, name, comp)
	}
}

// The generator's own forms pass: compose.yaml (key_provider none) and its KMS fallback form; the KMS form's
// own shape (no task queue, no -key-mode) is the only one it may have (no mixing).
func TestReleaseShapeAcceptsTheGenerator(t *testing.T) {
	base := string(composeYAML(t))
	if err := ReleaseShape(base); err != nil {
		t.Fatalf("compose.yaml: %v", err)
	}
	kms := string(fallbackCompose(t))
	if err := ReleaseShape(kms); err != nil {
		t.Fatalf("the KMS fallback form: %v", err)
	}
	if _, err := ComposeImages(kms); err != nil {
		t.Fatalf("the KMS fallback form, ComposeImages: %v", err)
	}
	// Half of each: the task queue without unlockd's -key-mode none, and the reverse.
	mixed := edit(t, base, `, "-key-mode", "none"`, "")
	refusedEverywhere(t, "task queue with the KMS fallback's unlockd", mixed)
	mixed2 := edit(t, kms, `"-cache-dir", "/run/tacy-unlock"]`, `"-cache-dir", "/run/tacy-unlock", "-key-mode", "none"]`)
	refusedEverywhere(t, "unlockd -key-mode none without the task queue", mixed2)
	// The e2e levels (test tools, staging holders) don't run the shape check: their overlays change the compose.
	if _, err := ComposeImagesE2E(edit(t, base, "      driver: none\n", "      driver: json-file\n")); err != nil {
		t.Fatalf("the e2e level: %v", err)
	}
}

// The Access pin (vm-v1-gate2; by value since the production app, 2026-11-22): the release names its Access app on
// gatewayd's command line (-cloudflared-access <team>,<aud>), which must be AccessTeam,AccessAUD exactly. Another app
// of our team, another team, the placeholders, the config-file form, a malformed pin, the pin twice and the e2e diag
// route (-e2e-diag, the e2e overlay's only) are each refused.
func TestShapeAccessPinAndDiagFlag(t *testing.T) {
	base := string(composeYAML(t))
	tok := slotToken(t, base)
	if _, err := ComposeImages(base); err != nil {
		t.Fatalf("the release compose: %v", err)
	}
	if AccessTeam != "baldcactus" || AccessAUD != "4b3edae68fd8b0f6913601a52763b6ab048dcf3981a9d5669efec249530bb00b" {
		t.Fatalf("AccessTeam, AccessAUD %q, %q: not the production Access app (tacy-agent-vm)", AccessTeam, AccessAUD)
	}
	pin := `"-cloudflared-access", "baldcactus,4b3edae68fd8b0f6913601a52763b6ab048dcf3981a9d5669efec249530bb00b"`
	if err := ReleaseShape(base); err != nil {
		t.Fatalf("the release compose, the release shape: %v", err)
	}
	aud := "4b3edae68fd8b0f6913601a52763b6ab048dcf3981a9d5669efec249530bb00b"
	for name, comp := range map[string]string{
		"another app of our team":         edit(t, base, pin, `"-cloudflared-access", "baldcactus,`+strings.Repeat("ab", 32)+`"`),
		"another team":                    edit(t, base, pin, `"-cloudflared-access", "kikosh,`+aud+`"`),
		"another team, our team's prefix": edit(t, base, pin, `"-cloudflared-access", "baldcactus-x,`+aud+`"`),
		"another team, a suffix of ours":  edit(t, base, pin, `"-cloudflared-access", "xbaldcactus,`+aud+`"`),
		"our team in capitals":            edit(t, base, pin, `"-cloudflared-access", "BALDCACTUS,`+aud+`"`),
		"our team, the zero audience":     edit(t, base, pin, `"-cloudflared-access", "baldcactus,`+strings.Repeat("0", 64)+`"`),
		"the placeholders":                edit(t, base, pin, `"-cloudflared-access", "unpinned,`+strings.Repeat("0", 64)+`"`),
		"an upper-case audience":          edit(t, base, pin, `"-cloudflared-access", "baldcactus,`+strings.ToUpper(aud)+`"`),
		"a second comma":                  edit(t, base, pin, `"-cloudflared-access", "baldcactus,`+aud+`,x"`),
		"the config-file form":            edit(t, base, pin, `"-cloudflared-config", "/tacy/cloudflared.yml"`),
		"a short audience":                edit(t, base, pin, `"-cloudflared-access", "baldcactus,0000"`),
		"no team":                         edit(t, base, pin, `"-cloudflared-access", ",`+aud+`"`),
		"the pin twice":                   edit(t, base, pin, pin+", "+pin),
		"the e2e diag route": edit(t, base, `"-tunnel-secret", "`+tok+`"]`,
			`"-tunnel-secret", "`+tok+`", "-`+E2EDiagFlag+`", "http://e2ediag:8082"]`),
		"the diag route, --flag": edit(t, base, `"-tunnel-secret", "`+tok+`"]`,
			`"-tunnel-secret", "`+tok+`", "--`+E2EDiagFlag+`", "http://e2ediag:8082"]`),
		"the diag route, =value": edit(t, base, `"-tunnel-secret", "`+tok+`"]`,
			`"-tunnel-secret", "`+tok+`", "-`+E2EDiagFlag+`=http://e2ediag:8082"]`),
		"the diag route in place of a pin": edit(t, base, pin, `"-`+E2EDiagFlag+`", "http://e2ediag:8082"`),
		"the diag flag in the environment": edit(t, base, "    environment:\n      HOME: /tmp\n",
			"    environment:\n      HOME: /tmp\n      GATEWAYD_ARGS: -"+E2EDiagFlag+"=http://e2ediag:8082\n"),
	} {
		refusedEverywhere(t, name, comp)
		if err := ReleaseShape(comp); err == nil {
			t.Errorf("%s: the release shape took it", name)
		}
	}
}
