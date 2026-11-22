package verifier

import (
	"context"
	"encoding/hex"
	"os"
	"strings"
	"testing"

	"github.com/tacyhq/tacy/internal/tdx"
	"github.com/tacyhq/tacy/proto"
)

// The pre-launch script the release ships is the reviewed one, byte for byte.
func TestMemoryRootScriptFile(t *testing.T) {
	b, err := os.ReadFile("../phala/pre-launch-memory-root-v1.sh")
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != MemoryRootScript {
		t.Fatal("phala/pre-launch-memory-root-v1.sh isn't verifier.MemoryRootScript")
	}
	if _, ok := PreLaunchScripts[sha256hex(MemoryRootScript)]; !ok {
		t.Fatal("the memory-root script isn't a reviewed pre-launch script")
	}
	s := MemoryRootScript
	if MemoryRoot(&s) != nil || MemoryRoot(nil) == nil {
		t.Fatal("MemoryRoot")
	}
	other := s + "# edited\n"
	if MemoryRoot(&other) == nil {
		t.Fatal("an edited script passed as the memory-root one")
	}
}

// The compose rules for unlockd (UnlockdRules): only unlockd mounts dstack's socket and the unlock cache, it has no
// network, port, capability or root, and the memory-root script is there.
func TestUnlockdRules(t *testing.T) {
	compose := string(kmsComposeOf(t, composeYAML(t)))
	script := MemoryRootScript
	if !HasUnlockd(compose) {
		t.Fatal("compose.yaml has no unlockd")
	}
	if err := UnlockdRules(compose, &script, KeyProviderKMS); err != nil {
		t.Fatalf("compose.yaml: %v", err)
	}
	if err := UnlockdRules(compose, nil, KeyProviderKMS); err == nil {
		t.Fatal("no memory-root script accepted")
	}
	svc := func(name string) (int, int) {
		i := strings.Index(compose, "\n  "+name+":\n")
		j := strings.Index(compose[i+1:], "\n  ")
		for j >= 0 && strings.HasPrefix(compose[i+1+j+3:], " ") {
			k := strings.Index(compose[i+1+j+1:], "\n  ")
			if k < 0 {
				break
			}
			j += k + 1
		}
		return i, i + 1 + j
	}
	bad := map[string]string{}
	// agentd mounts dstack's socket again (it could make its own quotes).
	bad["dstack socket on agentd"] = strings.Replace(compose, "      - runnersock:/run/tacy/runner\n      - agentsock:/run/tacy/agent\n",
		"      - /var/run/dstack.sock:/var/run/dstack.sock\n      - runnersock:/run/tacy/runner\n      - agentsock:/run/tacy/agent\n", 1)
	// unlockd with a network.
	i, j := svc("unlockd")
	u := compose[i:j]
	bad["unlockd with a network"] = compose[:i] + strings.Replace(u, "    network_mode: none\n", "", 1) + compose[j:]
	bad["unlockd as root"] = compose[:i] + strings.Replace(u, `user: "10005:10005"`, `user: "0:0"`, 1) + compose[j:]
	bad["unlockd with a capability"] = compose[:i] + strings.Replace(u, "    cap_drop: [ALL]\n", "    cap_drop: [ALL]\n    cap_add: [SYS_ADMIN]\n", 1) + compose[j:]
	bad["the unlock cache on vaultd"] = strings.Replace(compose, "      - vaultsock:/run/tacy/vault\n",
		"      - /run/tacy-unlock:/run/tacy-unlock\n      - vaultsock:/run/tacy/vault\n", 1)
	for what, c := range bad {
		if c == compose {
			t.Fatalf("%s: the edit didn't apply", what)
		}
		if err := UnlockdRules(c, &script, KeyProviderKMS); err == nil {
			t.Errorf("%s accepted", what)
		}
	}
	if err := noDiskVolumes(bad["the unlock cache on vaultd"]); err == nil {
		t.Error("the unlock cache bound into vaultd passed noDiskVolumes")
	}
}

// Labels: a browser takes agentd's attestation of a release with unlockd only under proto.VersionAgent, and a key
// release (kmsd, a holder) only under proto.Version: so no quote unlockd makes for agentd can ask for a share, and
// no unlock attestation passes as agentd's.
func TestUnlockdLabels(t *testing.T) {
	c := bootWith(t, composeYAML(t), false, nil, keyEvent(false))
	if c.rd == nil || c.a.Version != proto.VersionAgent {
		t.Fatal("bootWith didn't make an agentd attestation")
	}
	if _, err := Verify(context.Background(), c.a, c.nonce, c.p); err != nil {
		t.Fatalf("agentd's attestation in a browser: %v", err)
	}
	// The same quote, presented to a key release: refused.
	kr := c.p
	kr.KeyRelease = true
	if _, err := Verify(context.Background(), c.a, c.nonce, kr); err == nil {
		t.Fatal("an agentd attestation passed a key release")
	}
	// An unlock attestation (proto.Version's report_data) presented to a browser: refused.
	b := bootWith(t, composeYAML(t), false, nil, keyEvent(false))
	b.a.Version = proto.Version
	rtmr := b.p.VerifyQuote
	b.p.VerifyQuote = func(ctx context.Context, raw []byte) (*tdx.Quote, error) {
		q, err := rtmr(ctx, raw)
		if err == nil {
			key := mustHex(t, b.a.HPKEPublicKey)
			q.ReportData = proto.ReportData(b.nonce, key)
		}
		return q, err
	}
	if _, err := Verify(context.Background(), b.a, b.nonce, b.p); err == nil || !strings.Contains(err.Error(), "own label") {
		t.Fatalf("an unlock attestation in a browser: %v", err)
	}
	// ...and to a key release: the label is right there (the holders' own check).
	b.p.KeyRelease = true
	if _, err := Verify(context.Background(), b.a, b.nonce, b.p); err != nil {
		t.Fatalf("an unlock attestation at a key release: %v", err)
	}
	// A quote v5 (Intel's TD 1.5 report) is refused, not misread (drill 7.2).
	if _, err := tdx.Parse(append([]byte{5, 0}, make([]byte, 1000)...)); err == nil {
		t.Fatal("a v5 quote parsed as v4")
	}
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
