package verifier

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// overlayOf is compose with an e2e diag service publishing ports (as cmd/e2e overlay writes it).
func overlayOf(t *testing.T, compose []byte, ports ...string) []byte {
	t.Helper()
	c := string(compose)
	i := strings.LastIndex(c, "\nvolumes:\n")
	if i < 0 {
		t.Fatal("compose.yaml has no top-level volumes")
	}
	diag := "\n  " + E2EDiagService + ":\n    image: docker.io/library/busybox@sha256:" + strings.Repeat("ab", 32) +
		"\n    pid: \"host\"\n    tmpfs: [\"/www:exec,mode=0755\"]\n    ports:"
	for _, p := range ports {
		diag += "\n      - \"" + p + "\""
	}
	return []byte(c[:i] + diag + c[i:])
}

// The e2e overlay's app-compose: its diag port goes through port_policy next to 8080, only for test tools
// (AllowE2EDiag); a release's stays 8080 only, and a compose without the diag service gets exactly the release's.
func TestE2EAppCompose(t *testing.T) {
	compose := fallbackCompose(t)
	rel, err := ReleaseAppCompose(compose, nil, true)
	if err != nil {
		t.Fatal(err)
	}
	if same, err := E2EAppCompose(compose, nil, true); err != nil || string(same) != string(rel) {
		t.Fatalf("no diag service: %v, same %v", err, string(same) == string(rel))
	}
	overlay := overlayOf(t, compose, "8082:8082")
	e2e, err := E2EAppCompose(overlay, nil, true)
	if err != nil {
		t.Fatal(err)
	}
	var ac map[string]any
	json.Unmarshal(e2e, &ac)
	if got := string(mustJSON(ac["port_policy"])); got != `{"ports":[{"port":8080,"pp":false},{"port":8082,"pp":false}],"restrict_mode":true}` {
		t.Fatalf("port_policy %s", got)
	}
	// What the release itself makes of the overlay compose keeps 8080 only.
	relOverlay, err := ReleaseAppCompose(overlay, nil, true)
	if err != nil {
		t.Fatal(err)
	}
	ac = nil
	json.Unmarshal(relOverlay, &ac)
	if got := string(mustJSON(ac["port_policy"])); got != `{"ports":[{"port":8080,"pp":false}],"restrict_mode":true}` {
		t.Fatalf("release port_policy %s", got)
	}

	// A throwaway booted with the e2e app-compose passes for the test tools only.
	rc := bootWith(t, overlay, true, func([]byte) []byte { return e2e }, keyEvent(true))
	rc.p.AppCompose, rc.p.AllowE2EDiag = e2e, true
	if _, err := Verify(context.Background(), rc.a, rc.nonce, rc.p); err != nil {
		t.Fatalf("e2e overlay: %v", err)
	}
	rc.p.AllowE2EDiag = false
	if _, err := Verify(context.Background(), rc.a, rc.nonce, rc.p); err == nil || !strings.HasPrefix(err.Error(), AppComposeFlagsCheck+": ") ||
		!strings.Contains(err.Error(), "want only 8080 (no PROXY") {
		t.Fatalf("without AllowE2EDiag: %v", err)
	}
	// Against the release's pin (8080 only), the e2e app-compose is another file.
	rc.p.AppCompose, rc.p.AllowE2EDiag = relOverlay, true
	if _, err := Verify(context.Background(), rc.a, rc.nonce, rc.p); err == nil || !strings.HasPrefix(err.Error(), AppComposePinCheck+": ") {
		t.Fatalf("e2e app-compose against the release pin: %v", err)
	}
	// The release compose with the extra port opened is refused even with AllowE2EDiag: no diag service, no port.
	open := edited(func(ac map[string]any) {
		ac["port_policy"] = map[string]any{"ports": []map[string]any{{"port": 8080, "pp": false}, {"port": 8082, "pp": false}}, "restrict_mode": true}
	})
	rc = bootWith(t, compose, true, open, keyEvent(true))
	rc.p.AllowE2EDiag = true
	if _, err := Verify(context.Background(), rc.a, rc.nonce, rc.p); err == nil || !strings.HasPrefix(err.Error(), AppComposeFlagsCheck+": ") {
		t.Fatalf("extra port without a diag service: %v", err)
	}

	for _, bad := range [][]string{{"8080:8080"}, {"9000:8082"}, {"8082"}, {"8082:8082", "8082:8082"}} {
		if _, err := E2EAppCompose(overlayOf(t, compose, bad...), nil, true); err == nil {
			t.Errorf("diag ports %v accepted", bad)
		}
	}
}
