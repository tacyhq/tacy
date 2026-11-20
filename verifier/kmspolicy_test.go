package verifier

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/tacyhq/tacy/internal/tdx"
)

// What kmsd (the Tacy key service) needs of Verify for its own replicas and the VMs it serves: app-compose pins by
// hash (its admin-signed policy), another port and another service set (its compose runs kmsd on 8000), and the
// attested instance and app ids as facts (its one-instance lease). The key service runs in the KMS fallback too.
func TestKMSServicePolicy(t *testing.T) {
	compose := "services:\n  kmsd:\n    image: ghcr.io/tacyhq/tacy/kmsd@sha256:" + strings.Repeat("ab", 32) +
		"\n    ports: [\"8000:8000\"]\n    volumes: [\"/var/run/dstack.sock:/var/run/dstack.sock\"]\n    logging: {driver: none}\n"
	raw, err := appComposeJSON([]byte(compose), nil, true, "tacy-kms")
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	json.Unmarshal(raw, &m)
	m["port_policy"] = map[string]any{"ports": []any{map[string]any{"port": 8000, "pp": false}}, "restrict_mode": true}
	ac, _ := compactSorted(m)
	sum := sha256.Sum256(ac)

	a, nonce, _ := load064(t)
	setAppComposeRaw(t, a, ac)
	recompose(t, a, ac)
	rtmr3 := setEvent(t, a, "key-provider", keyEvent(true))
	policy := func() Policy {
		return Policy{AllowStaleTCB: true, ProdImages: allImages(), Boot: allSets(), Compose: []byte(compose),
			AppComposeSHA256: []string{strings.ToUpper(hex.EncodeToString(sum[:]))}, KMSFallback: true, Port: 8000,
			Services: []string{"kmsd"}, VerifyQuote: changeQuote(func(q *tdx.Quote) { q.Rtmrs[3] = rtmr3 })}
	}
	res, err := Verify(context.Background(), a, nonce, policy())
	if err != nil {
		t.Fatalf("key service compose: %v", err)
	}
	if len(res.Facts["instance id"]) != 40 || len(res.Facts["app id"]) != 40 || res.Facts["image kmsd"] == "" ||
		res.Facts["app-compose sha256"] != hex.EncodeToString(sum[:]) {
		t.Fatalf("facts %v", res.Facts)
	}

	for _, c := range []struct {
		name, check, want string
		edit              func(p *Policy)
	}{
		{"the agent VM's services", ImagesCheck, "isn't one of the release's", func(p *Policy) { p.Services = nil }},
		{"the agent VM's port", AppComposeFlagsCheck, "want only 8080", func(p *Policy) { p.Port = 0 }},
		{"another pinned hash", AppComposePinCheck, "the release pins", func(p *Policy) { p.AppComposeSHA256 = []string{strings.Repeat("0", 64)} }},
		{"no pin at all", KMSCheck, "no pinned app-compose.json", func(p *Policy) { p.AppComposeSHA256 = nil }},
		{"no fallback", KMSCheck, "explicit KMS fallback", func(p *Policy) { p.KMSFallback = false }},
	} {
		p := policy()
		c.edit(&p)
		res, err := Verify(context.Background(), a, nonce, p)
		if err == nil || !strings.HasPrefix(err.Error(), c.check+": ") || !strings.Contains(err.Error(), c.want) || res.HPKEPublicKey != nil {
			t.Errorf("%s: %v", c.name, err)
		}
	}
}
