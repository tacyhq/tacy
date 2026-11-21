package verifier

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/tacyhq/tacy/internal/tdx"
	"github.com/tacyhq/tacy/proto"
)

// Golden tests for the app-compose pin ("Keys: never a provider's"). Each stands in for a VM that really
// booted with the app-compose.json under test: the 0.6.4 recording (a genuine quote, prod5, 2026-11-15) with its
// app-compose.json, compose-hash event, key-provider event and RTMR3 made consistent with the edit, so only the rule
// under test can fail. The docker compose is this folder's compose.yaml (images by digest), as in
// TestImageComposeOffline.

// kmsComposeOf is a key_provider none compose (Fix B, this folder's compose.yaml since vm-fix-b) in the KMS
// fallback's form, as go run ./cmd/compose -kms-fallback writes it: setup doesn't mount the unlock cache (the
// memory-root script makes it) and unlockd runs without -key-mode none. A compose already in that form is returned
// as it is.
func kmsComposeOf(t *testing.T, b []byte) []byte {
	t.Helper()
	c := string(b)
	if !strings.Contains(c, `, "-key-mode", "none"`) {
		return b
	}
	// The task queue's tmpfs (TasksRules) is key_provider none's too: setup's and agentd's mounts, setup's -dir and
	// agentd's -tasks-dir go with it.
	for _, cut := range []string{"      - " + TasksDir + ":" + TasksDir + "\n", "      - " + TasksDir + ":" + TasksDir + "\n",
		`, "-dir", "` + TasksDir + `=10003:10003:0700"`, `, "-tasks-dir", "` + TasksDir + `"`} {
		c = strings.Replace(c, cut, "", 1) // absent before the task queue's tmpfs (older recorded composes)
	}
	for _, cut := range []string{"      - " + UnlockCacheDir + ":" + UnlockCacheDir + "\n", `, "-dir", "` + UnlockCacheDir + `=10005:10005:0700"`,
		`, "-key-mode", "none"`} {
		if !strings.Contains(c, cut) {
			t.Fatalf("compose.yaml has no %q", cut)
		}
		c = strings.Replace(c, cut, "", 1) // setup's cache mount comes first (unlockd keeps its own)
	}
	return []byte(c)
}

// fallbackCompose is compose.yaml in the KMS fallback's form: every named volume in memory (tmpfs), what the KMS
// fallback must run.
func fallbackCompose(t *testing.T) []byte {
	t.Helper()
	compose := kmsComposeOf(t, composeYAML(t))
	if err := noDiskVolumes(string(compose)); err != nil {
		t.Fatalf("compose.yaml: %v", err)
	}
	return compose
}

// diskCompose is compose.yaml with its volumes on the data disk (as before the memory-only VM).
func diskCompose(t *testing.T) []byte {
	t.Helper()
	// Every top-level volume with its driver_opts dropped (whatever their form).
	c := string(kmsComposeOf(t, composeYAML(t)))
	i := strings.LastIndex(c, "\nvolumes:\n")
	if i < 0 || !strings.Contains(c[i:], "type: tmpfs") {
		t.Fatal("compose.yaml's volumes aren't the expected tmpfs ones")
	}
	out := c[:i] + "\nvolumes:\n"
	for _, ln := range strings.Split(c[i+len("\nvolumes:\n"):], "\n") {
		if strings.HasPrefix(ln, "  ") && !strings.HasPrefix(ln, "   ") && strings.HasSuffix(ln, ":") {
			out += ln + "\n"
		}
	}
	return []byte(out)
}

// releaseCase is a VM booted with attested as its app-compose.json, verified against the release made of compose.
type releaseCase struct {
	a       *proto.Attestation
	nonce   []byte
	p       Policy
	release []byte
	rd      []byte // the agentd label's report_data (a release with unlockd), or nil
}

// keyEvent is the key-provider event dstack measures for a mode: {"name":"none","id":""} or the KMS root's.
func keyEvent(fallback bool) []byte {
	if !fallback {
		return []byte(`{"name":"none","id":""}`)
	}
	for root := range KMSRoots {
		return []byte(`{"name":"kms","id":"` + root + `"}`)
	}
	return nil
}

// bootWith makes the 0.6.4 recording a VM that booted with attested as its app-compose.json and event as its
// key-provider event, and returns the policy pinning release (compose, the pinned pre-launch script, the mode).
func bootWith(t *testing.T, compose []byte, fallback bool, attested func(release []byte) []byte, event []byte) releaseCase {
	t.Helper()
	var pre []byte // a release without unlockd, or with key_provider none, runs no pre-launch script
	unlockd := HasUnlockd(string(compose))
	if unlockd && fallback { // the split-key unlock's in the KMS fallback: the memory-root script
		pre = []byte(MemoryRootScript)
	}
	release, err := ReleaseAppCompose(compose, pre, fallback)
	if err != nil {
		t.Fatal(err)
	}
	a, nonce, _ := load064(t)
	ac := release
	if attested != nil {
		ac = attested(release)
	}
	setAppComposeRaw(t, a, ac)
	recompose(t, a, ac)
	rtmr3 := setEvent(t, a, "key-provider", event)
	rd := agentLabel(t, a, nonce, unlockd)
	p := Policy{AllowStaleTCB: true, ProdImages: allImages(), Boot: allSets(), Compose: compose, AppCompose: release,
		KMSFallback: fallback, VerifyQuote: changeQuote(func(q *tdx.Quote) {
			q.Rtmrs[3] = rtmr3
			if rd != nil {
				q.ReportData = rd
			}
		})}
	return releaseCase{a: a, nonce: nonce, p: p, release: release, rd: rd}
}

// agentLabel makes a an agentd attestation of a release with unlockd (proto.VersionAgent) and returns the
// report_data its quote must carry; nil (no change) without unlockd.
func agentLabel(t *testing.T, a *proto.Attestation, nonce []byte, unlockd bool) []byte {
	t.Helper()
	if !unlockd {
		return nil
	}
	key, err := hex.DecodeString(a.HPKEPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	a.Version = proto.VersionAgent
	return proto.AgentReportData(nonce, key)
}

// setAppComposeRaw puts exactly raw in a's info as its app-compose.json (withAppCompose re-encodes it).
func setAppComposeRaw(t *testing.T, a *proto.Attestation, raw []byte) {
	t.Helper()
	var info map[string]any
	if json.Unmarshal(a.Info, &info) != nil {
		t.Fatal("info")
	}
	tcbRaw, _ := info["tcb_info"].(string)
	var tcb map[string]any
	json.Unmarshal([]byte(tcbRaw), &tcb)
	tcb["app_compose"] = string(raw)
	b, _ := json.Marshal(tcb)
	info["tcb_info"] = string(b)
	a.Info, _ = json.Marshal(info)
}

// edited is release with edit applied (re-encoded, so it is another file even when edit changes nothing).
func edited(edit func(ac map[string]any)) func([]byte) []byte {
	return func(release []byte) []byte {
		var ac map[string]any
		if err := json.Unmarshal(release, &ac); err != nil {
			panic(err)
		}
		edit(ac)
		b, err := json.Marshal(ac)
		if err != nil {
			panic(err)
		}
		return b
	}
}

func composeYAML(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile("../compose.yaml")
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// The release's own app-compose.json, keys made in the VM: every check passes, the last three new ones included.
func TestReleaseAppCompose(t *testing.T) {
	c := bootWith(t, composeYAML(t), false, nil, keyEvent(false))
	res, err := Verify(context.Background(), c.a, c.nonce, c.p)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Checks) != 21 || hex.EncodeToString(res.HPKEPublicKey) != c.a.HPKEPublicKey {
		t.Fatalf("%d checks", len(res.Checks))
	}
	names := map[string]bool{}
	for _, ch := range res.Checks {
		names[ch.Name] = ch.OK
	}
	if !names[KMSCheck] || !names[AppComposeCheck] || !names[AppComposeFlagsCheck] || !names[AppComposePinCheck] {
		t.Fatalf("checks %v", res.Checks)
	}
	if res.Facts["keys"] != "made inside the VM at boot (key provider none)" || res.Facts["key mode"] != KeyProviderNone ||
		res.Facts["KMS root"] != "" || len(res.Facts["app-compose sha256"]) != 64 {
		t.Fatalf("facts %v", res.Facts)
	}
	// What the release writes: every setting the rules name, and no deployer env.
	var ac map[string]any
	json.Unmarshal(c.release, &ac)
	for k, want := range map[string]string{"key_provider": `"none"`, "kms_enabled": "false", "local_key_provider_enabled": "false",
		"allowed_envs": "[]", "swap_size": `"0"`, "gateway_enabled": "false", "tproxy_enabled": "false", "features": "[]", "init_script": "[]", "public_logs": "false", "public_sysinfo": "false", "public_tcbinfo": "false",
		"secure_time": "true", "manifest_version": `"3"`, "requirements": `{"ephemeral_data_disk":true}`,
		"port_policy": `{"ports":[{"port":8080,"pp":false}],"restrict_mode":true}`} {
		if got := string(mustJSON(ac[k])); got != want {
			t.Errorf("%s = %s, want %s", k, got, want)
		}
	}
}

// Any app-compose.json other than the release's fails, and for each setting the rules name, the failure says which.
func TestAppComposeFlags(t *testing.T) {
	cases := []struct {
		name, check, want string
		edit              func(ac map[string]any)
	}{
		{"deployer env", AppComposeCheck, "allowed_envs must be empty", func(ac map[string]any) { ac["allowed_envs"] = []string{"EXA_API_KEY"} }},
		{"public logs", AppComposeCheck, "public_logs", func(ac map[string]any) { ac["public_logs"] = true }},
		{"swap (size string)", AppComposeFlagsCheck, "swap_size", func(ac map[string]any) { ac["swap_size"] = "1G" }},
		{"swap (bytes)", AppComposeFlagsCheck, "swap_size", func(ac map[string]any) { ac["swap_size"] = 1 << 30 }},
		{"public sysinfo", AppComposeFlagsCheck, "public_sysinfo", func(ac map[string]any) { ac["public_sysinfo"] = true }},
		{"public tcbinfo", AppComposeFlagsCheck, "public_tcbinfo", func(ac map[string]any) { ac["public_tcbinfo"] = true }},
		{"public tcbinfo by default", AppComposeFlagsCheck, "public_tcbinfo", func(ac map[string]any) { delete(ac, "public_tcbinfo") }},
		{"all ports forwarded", AppComposeFlagsCheck, "restrict_mode", func(ac map[string]any) {
			ac["port_policy"] = map[string]any{"ports": []any{map[string]any{"port": 8080}}, "restrict_mode": false}
		}},
		{"no port policy", AppComposeFlagsCheck, "restrict_mode", func(ac map[string]any) { delete(ac, "port_policy") }},
		{"another port (the guest agent's)", AppComposeFlagsCheck, "port_policy.ports", func(ac map[string]any) {
			ac["port_policy"] = map[string]any{"ports": []any{map[string]any{"port": 8080}, map[string]any{"port": 8090}}, "restrict_mode": true}
		}},
		{"PROXY protocol", AppComposeFlagsCheck, "port_policy.ports", func(ac map[string]any) {
			ac["port_policy"] = map[string]any{"ports": []any{map[string]any{"port": 8080, "pp": true}}, "restrict_mode": true}
		}},
		{"host clock", AppComposeFlagsCheck, "secure_time", func(ac map[string]any) { ac["secure_time"] = false }},
		{"secure time unset", AppComposeFlagsCheck, "secure_time", func(ac map[string]any) { delete(ac, "secure_time") }},
		{"persistent data disk", AppComposeFlagsCheck, "ephemeral_data_disk", func(ac map[string]any) {
			ac["requirements"] = map[string]any{"ephemeral_data_disk": false}
		}},
		{"no requirements", AppComposeFlagsCheck, "ephemeral_data_disk", func(ac map[string]any) { delete(ac, "requirements") }},
		{"KMS on", AppComposeFlagsCheck, "kms_enabled", func(ac map[string]any) { ac["kms_enabled"] = true }},
		{"local key provider", AppComposeFlagsCheck, "local_key_provider_enabled", func(ac map[string]any) { ac["local_key_provider_enabled"] = true }},
		{"key provider kms", AppComposeFlagsCheck, `key_provider "kms", want "none"`, func(ac map[string]any) { ac["key_provider"] = "kms" }},
		{"key provider id", AppComposeFlagsCheck, "key_provider_id is set", func(ac map[string]any) { ac["key_provider_id"] = strings.Repeat("ab", 32) }},
		{"manifest version 2", AppComposeFlagsCheck, "manifest_version", func(ac map[string]any) { ac["manifest_version"] = 2 }},
		// Fix B: no provider gateway, no pre-launch script, no core dumps.
		{"provider gateway", AppComposeFlagsCheck, "gateway_enabled", func(ac map[string]any) { ac["gateway_enabled"] = true }},
		{"gateway unset", AppComposeFlagsCheck, "gateway_enabled", func(ac map[string]any) { delete(ac, "gateway_enabled") }},
		{"tproxy", AppComposeFlagsCheck, "tproxy_enabled", func(ac map[string]any) { ac["tproxy_enabled"] = true }},
		{"a pre-launch script", AppComposeFlagsCheck, "a pre-launch script with key_provider none", func(ac map[string]any) {
			ac["pre_launch_script"] = MemoryRootScript
		}},
		{"core dumps", AppComposeFlagsCheck, "ulimits core 0", func(ac map[string]any) {
			ac["docker_compose_file"] = strings.Replace(ac["docker_compose_file"].(string), "    ulimits:\n      core: 0\n", "", 1)
		}},
		{"core dumps soft only", AppComposeFlagsCheck, "ulimits core 0", func(ac map[string]any) {
			ac["docker_compose_file"] = strings.Replace(ac["docker_compose_file"].(string), "    ulimits:\n      core: 0\n",
				"    ulimits:\n      core:\n        soft: 0\n        hard: 1024\n", 1)
		}},
		// Review L1 (2026-11-21): dstack's own semantics, not only the flags' names. gateway_enabled() is
		// gateway_enabled || features contains "tproxy-net"; storage_fs and storage_discard (default on) are the disk's.
		{"tproxy-net feature", AppComposeFlagsCheck, "features", func(ac map[string]any) { ac["features"] = []string{"tproxy-net"} }},
		{"kms feature", AppComposeFlagsCheck, "features", func(ac map[string]any) { ac["features"] = []string{"kms"} }},
		{"any feature", AppComposeFlagsCheck, "features", func(ac map[string]any) { ac["features"] = []string{"x"} }},
		{"ext4", AppComposeFlagsCheck, `storage_fs "ext4", want "zfs"`, func(ac map[string]any) { ac["storage_fs"] = "ext4" }},
		{"storage_fs unset", AppComposeFlagsCheck, "storage_fs unset", func(ac map[string]any) { delete(ac, "storage_fs") }},
		{"storage discard", AppComposeFlagsCheck, "storage_discard", func(ac map[string]any) { ac["storage_discard"] = true }},
		{"storage discard unset (dstack's default is on)", AppComposeFlagsCheck, "storage_discard", func(ac map[string]any) { delete(ac, "storage_discard") }},
		// The same settings, written another way, or a setting no rule names: only the pin sees it.
		{"key provider implied", AppComposePinCheck, "the release pins", func(ac map[string]any) { delete(ac, "key_provider") }},
		{"another name", AppComposePinCheck, "the release pins", func(ac map[string]any) { ac["name"] = "other" }},
		{"verity volumes", AppComposePinCheck, "the release pins", func(ac map[string]any) {
			ac["verity_volumes"] = []any{map[string]any{"source": "x.img", "verity_root": strings.Repeat("00", 32), "target": "/data"}}
		}},
		{"re-encoded only", AppComposePinCheck, "the release pins", func(map[string]any) {}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rc := bootWith(t, composeYAML(t), false, edited(c.edit), keyEvent(false))
			res, err := Verify(context.Background(), rc.a, rc.nonce, rc.p)
			if err == nil || res.HPKEPublicKey != nil {
				t.Fatalf("accepted: %v", err)
			}
			if !strings.HasPrefix(err.Error(), c.check+": ") || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("failed for another reason: %v", err)
			}
			if last := res.Checks[len(res.Checks)-1]; last.OK || last.Name != c.check {
				t.Fatalf("last check %+v", last)
			}
		})
	}
	// storage_discard only where a policy allows it explicitly (nothing does): then only the pin refuses it.
	rc := bootWith(t, composeYAML(t), false, edited(func(ac map[string]any) { ac["storage_discard"] = true }), keyEvent(false))
	rc.p.AllowStorageDiscard = true
	if _, err := Verify(context.Background(), rc.a, rc.nonce, rc.p); err == nil || !strings.HasPrefix(err.Error(), AppComposePinCheck) {
		t.Fatalf("discard allowed: %v", err)
	}
	// One byte of whitespace is another file.
	rc = bootWith(t, composeYAML(t), false, func(r []byte) []byte { return append(append([]byte{}, r...), ' ') }, keyEvent(false))
	if _, err := Verify(context.Background(), rc.a, rc.nonce, rc.p); err == nil || !strings.HasPrefix(err.Error(), AppComposePinCheck) {
		t.Fatalf("trailing space: %v", err)
	}
}

// The keys check follows the release's mode: in "none" a KMS's keys fail, without a pin nothing passes.
func TestKeysMode(t *testing.T) {
	compose := composeYAML(t)
	for _, c := range []struct {
		name  string
		event []byte
		edit  func(p *Policy)
		want  string
	}{
		{"keys from a KMS (the event)", keyEvent(true), nil, `key provider "kms", want none`},
		{"none with an id", []byte(`{"name":"none","id":"ab"}`), nil, "want none"},
		{"no key-provider event JSON", []byte("x"), nil, "no key-provider event"},
		{"no pinned app-compose", keyEvent(false), func(p *Policy) { p.AppCompose = nil }, "no pinned app-compose.json"},
		{"pinned app-compose isn't JSON", keyEvent(false), func(p *Policy) { p.AppCompose = []byte("{") }, "doesn't parse"},
	} {
		t.Run(c.name, func(t *testing.T) {
			rc := bootWith(t, compose, false, nil, c.event)
			if c.edit != nil {
				c.edit(&rc.p)
			}
			res, err := Verify(context.Background(), rc.a, rc.nonce, rc.p)
			if err == nil || !strings.HasPrefix(err.Error(), KMSCheck+": ") || !strings.Contains(err.Error(), c.want) || res.HPKEPublicKey != nil {
				t.Fatalf("%v", err)
			}
		})
	}
}

// The KMS fallback (only if Phala refuses "none"): keys from the pinned root, named in the app-compose too, and
// nothing on the provider-keyed disk. Refused unless the policy allows the fallback.
func TestKMSFallback(t *testing.T) {
	compose := fallbackCompose(t)
	rc := bootWith(t, compose, true, nil, keyEvent(true))
	res, err := Verify(context.Background(), rc.a, rc.nonce, rc.p)
	if err != nil || res.Facts["key mode"] != KeyProviderKMS || !strings.HasPrefix(res.Facts["keys"], "from a pinned KMS root") {
		t.Fatalf("fallback: %v %v", err, res.Facts)
	}

	rc.p.KMSFallback = false
	if _, err := Verify(context.Background(), rc.a, rc.nonce, rc.p); err == nil || !strings.Contains(err.Error(), "explicit KMS fallback") {
		t.Fatalf("fallback without the policy: %v", err)
	}

	// Volumes on the disk Phala's KMS keys: no fallback release can be made of such a compose.
	if _, err := ReleaseAppCompose(diskCompose(t), nil, true); err == nil || !strings.Contains(err.Error(), "isn't memory") {
		t.Fatalf("fallback with disk volumes: %v", err)
	}

	var otherRoot string
	for root := range KMSRoots {
		otherRoot = root[:len(root)-2] + "00"
	}
	for _, c := range []struct {
		name, check, want string
		edit              func(ac map[string]any)
		event             []byte
		policy            func(p *Policy)
	}{
		{"KMS off", AppComposeFlagsCheck, "kms_enabled is off", func(ac map[string]any) { ac["kms_enabled"] = false }, nil, nil},
		{"another KMS root (app-compose and keys)", KMSCheck, "isn't a pinned one", func(ac map[string]any) { ac["key_provider_id"] = otherRoot },
			[]byte(`{"name":"kms","id":"` + otherRoot + `"}`), nil},
		{"app-compose names another root than the keys came from", KMSCheck, "isn't the app-compose's key_provider_id",
			func(ac map[string]any) { ac["key_provider_id"] = otherRoot }, nil, nil},
		{"a disk volume", AppComposeFlagsCheck, "KMS fallback: volume", func(ac map[string]any) {
			ac["docker_compose_file"] = ac["docker_compose_file"].(string) + "  disk:\n"
		}, nil, nil},
		{"keys from another root than the app-compose names", KMSCheck, "isn't the app-compose's key_provider_id", nil,
			[]byte(`{"name":"kms","id":"` + otherRoot + `"}`), func(p *Policy) {
				p.KMSRoots = map[string]string{otherRoot: "x"}
				for root := range KMSRoots {
					p.KMSRoots[root] = "y"
				}
			}},
		{"keys made in the VM", KMSCheck, "want a dstack KMS", nil, keyEvent(false), nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			ev := c.event
			if ev == nil {
				ev = keyEvent(true)
			}
			var att func([]byte) []byte
			if c.edit != nil {
				att = edited(c.edit)
			}
			rc := bootWith(t, compose, true, att, ev)
			if c.policy != nil {
				c.policy(&rc.p)
			}
			res, err := Verify(context.Background(), rc.a, rc.nonce, rc.p)
			if err == nil || !strings.HasPrefix(err.Error(), c.check+": ") || !strings.Contains(err.Error(), c.want) || res.HPKEPublicKey != nil {
				t.Fatalf("%v", err)
			}
		})
	}
	// The flag rule on its own (what a release is built against): key_provider_id must be a pinned root.
	ac, _ := parseAppCompose(rc.release)
	ac.KeyProviderID = otherRoot
	if err := ac.checkFlags(KeyProviderKMS, KMSRoots, []int{AppPort}, false); err == nil || !strings.Contains(err.Error(), "isn't a pinned KMS root") {
		t.Fatalf("unpinned key_provider_id: %v", err)
	}
}

func TestNoDiskVolumes(t *testing.T) {
	ok := []string{
		"services:\n  a:\n    image: x\n",
		"services:\n  a:\n    volumes: [\"/var/run/dstack.sock:/var/run/dstack.sock\", \"m:/m\"]\n    tmpfs: [/tmp]\nvolumes:\n  m:\n    driver_opts: {type: tmpfs, device: tmpfs}\n",
		"services:\n  a:\n    volumes:\n      - {type: tmpfs, target: /t}\n      - {type: volume, source: m, target: /m}\nvolumes:\n  m:\n    driver: local\n    driver_opts: {type: tmpfs, device: tmpfs}\n",
		// The e2e diag service reads the host's root for its plaintext-disk scan (read-only).
		"services:\n  e2ediag:\n    volumes: [\"/:/host:ro,rslave\"]\n",
		"services:\n  e2ediag:\n    volumes:\n      - {type: bind, source: /, target: /host, read_only: true}\n",
	}
	bad := []string{
		"services:\n  a:\n    volumes: [\"d:/d\"]\nvolumes:\n  d:\n",
		"services:\n  a:\n    volumes: [\"d:/d\"]\n",
		"services:\n  a:\n    volumes: [\"/data:/data\"]\n",
		"services:\n  a:\n    volumes: [\"./x:/x\"]\n",
		"services:\n  a:\n    volumes:\n      - {type: bind, source: /etc, target: /e}\n",
		"volumes:\n  m:\n    external: true\n    driver_opts: {type: tmpfs, device: tmpfs}\nservices: {}\n",
		"volumes:\n  m:\n    driver: other\n    driver_opts: {type: tmpfs, device: tmpfs}\nservices: {}\n",
		"services:\n  e2ediag:\n    volumes: [\"/:/host\"]\n",
		"services:\n  e2ediag:\n    volumes: [\"/:/host:rslave\"]\n",
		"services:\n  e2ediag:\n    volumes: [\"/var:/host:ro\"]\n",
		"services:\n  agentd:\n    volumes: [\"/:/host:ro\"]\n",
	}
	for _, c := range ok {
		if err := noDiskVolumes(c); err != nil {
			t.Errorf("%q: %v", c, err)
		}
	}
	for _, c := range bad {
		if err := noDiskVolumes(c); err == nil {
			t.Errorf("%q accepted", c)
		}
	}
}
