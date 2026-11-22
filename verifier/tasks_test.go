package verifier

import (
	"strings"
	"testing"
)

// withMount is compose with line added to service svc's volumes.
func withMount(t *testing.T, compose, svc, line string) string {
	t.Helper()
	i := strings.Index(compose, "\n  "+svc+":\n")
	if i < 0 {
		t.Fatalf("no service %s", svc)
	}
	j := strings.Index(compose[i:], "    volumes:\n")
	if j < 0 {
		t.Fatalf("service %s has no volumes", svc)
	}
	at := i + j + len("    volumes:\n")
	return compose[:at] + "      - " + line + "\n" + compose[at:]
}

// TestOnlyAgentdMountsTasksTmpfs (V1-DESIGN §6.2, §6.5): the release (key_provider none) has agentd's task queue in
// the host tmpfs setup makes for agentd alone, and every check takes it; any other service that mounts it, a path in
// it or a parent of it, the KMS fallback with it, or setup making it for anyone but agentd, is refused, by the
// client's and the holders' rules alike (UnlockdRules runs TasksRules).
func TestOnlyAgentdMountsTasksTmpfs(t *testing.T) {
	rel := string(composeYAML(t))
	none := ""
	if !strings.Contains(rel, `"-tasks-dir", "`+TasksDir+`"`) {
		t.Fatal("the release compose has no -tasks-dir")
	}
	if err := TasksRules(rel, KeyProviderNone); err != nil {
		t.Fatalf("the release: %v", err)
	}
	if err := UnlockdRules(rel, &none, KeyProviderNone); err != nil {
		t.Fatalf("the release, unlockd's rules: %v", err)
	}
	if _, err := ReleaseAppCompose([]byte(rel), nil, false); err != nil {
		t.Fatalf("the release's app-compose: %v", err)
	}
	refused := func(what, compose, mode string) {
		t.Helper()
		if err := TasksRules(compose, mode); err == nil {
			t.Errorf("%s: TasksRules took it", what)
		}
		if mode == KeyProviderNone {
			if err := UnlockdRules(compose, &none, mode); err == nil {
				t.Errorf("%s: UnlockdRules took it", what)
			}
			if _, err := ReleaseAppCompose([]byte(compose), nil, false); err == nil {
				t.Errorf("%s: the app-compose rules took it", what)
			}
		}
	}
	for _, svc := range []string{"agentvm", "vaultd", "runner", UnlockdService} {
		refused(svc+" mounts it", withMount(t, rel, svc, TasksDir+":"+TasksDir), KeyProviderNone)
		refused(svc+" mounts it elsewhere", withMount(t, rel, svc, TasksDir+":/data"), KeyProviderNone)
		refused(svc+" mounts the queue file", withMount(t, rel, svc, TasksDir+"/queue.db:/q.db"), KeyProviderNone)
		refused(svc+" mounts /run", withMount(t, rel, svc, "/run:/hostrun"), KeyProviderNone)
	}
	refused("agentd mounts it at another path", strings.Replace(rel, "      - "+TasksDir+":"+TasksDir+"\n    command: [\"-runner-socket\"",
		"      - "+TasksDir+":/data\n    command: [\"-runner-socket\"", 1), KeyProviderNone)
	refused("the KMS fallback with it", rel, KeyProviderKMS)
	for _, bad := range []string{TasksDir + "=10003:10003:0750", TasksDir + "=10001:10003:0700", TasksDir + "=10003:10001:0700"} {
		refused("setup makes "+bad, strings.Replace(rel, TasksDir+"=10003:10003:0700", bad, 1), KeyProviderNone)
	}
	refused("setup doesn't make it", strings.Replace(rel, `, "-dir", "`+TasksDir+`=10003:10003:0700"`, "", 1), KeyProviderNone)
	refused("agentd isn't its uid", strings.Replace(rel, `user: "10003:10003"`, `user: "10001:10003"`, 1), KeyProviderNone)
	// Without the task queue's tmpfs at all (the KMS fallback's form): nothing to check.
	if err := TasksRules(string(kmsComposeOf(t, []byte(rel))), KeyProviderKMS); err != nil {
		t.Errorf("the KMS fallback's form: %v", err)
	}
}
