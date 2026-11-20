package agentclient

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/tacyhq/tacy/vault"
)

// ErrPushSignature is a push the VM refused for its signature (another signer is pinned).
var ErrPushSignature = errors.New("agentclient: the VM refused the push's signature")

// SecretsReady asks GET /secrets/status whether the VM has its keys this boot.
func SecretsReady(ctx context.Context, base string) (bool, error) {
	r, _ := http.NewRequestWithContext(ctx, "GET", strings.TrimSuffix(base, "/")+"/secrets/status", nil)
	res, err := plain.Do(r)
	if err != nil {
		return false, err
	}
	defer res.Body.Close()
	var st struct {
		Ready bool `json:"ready"`
	}
	if res.StatusCode != 200 || json.NewDecoder(io.LimitReader(res.Body, 4096)).Decode(&st) != nil {
		return false, fmt.Errorf("/secrets/status: HTTP %d", res.StatusCode)
	}
	return st.Ready, nil
}

// PushSecrets does what the chat Worker does after it verified the VM (vault/secrets.go): it asks the attested key
// (EHBP, so the answer is the attested VM's) for vaultd's secrets key, seals the keys and the run token to it, signs
// the box with signer and posts it. c must be a connection to a verified attestation's key. It returns the names
// the vault took.
func (c *Conn) PushSecrets(ctx context.Context, secrets map[string]string, token string, signer ed25519.PrivateKey) ([]string, error) {
	r, _ := http.NewRequestWithContext(ctx, "POST", c.Base+"/secrets/key", bytes.NewReader([]byte("{}")))
	r.Header.Set("Content-Type", "application/json")
	res, err := c.http.Do(r)
	if err != nil {
		return nil, err
	}
	b, _ := io.ReadAll(io.LimitReader(res.Body, 4096))
	res.Body.Close()
	var k struct {
		Key string `json:"key"`
	}
	if res.StatusCode != 200 || json.Unmarshal(b, &k) != nil || k.Key == "" {
		return nil, fmt.Errorf("/secrets/key: HTTP %d: %s", res.StatusCode, strings.TrimSpace(string(b)))
	}
	p, err := vault.SealSecrets(k.Key, time.Now().Unix(), secrets, token, func(m []byte) []byte { return ed25519.Sign(signer, m) })
	if err != nil {
		return nil, err
	}
	body, _ := json.Marshal(p)
	r, _ = http.NewRequestWithContext(ctx, "POST", c.Base+"/secrets", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	res, err = plain.Do(r)
	if err != nil {
		return nil, err
	}
	b, _ = io.ReadAll(io.LimitReader(res.Body, 4096))
	res.Body.Close()
	if res.StatusCode == 403 {
		return nil, ErrPushSignature
	}
	var out struct {
		Names []string `json:"names"`
	}
	if res.StatusCode != 200 || json.Unmarshal(b, &out) != nil {
		return nil, fmt.Errorf("/secrets: HTTP %d: %s", res.StatusCode, strings.TrimSpace(string(b)))
	}
	return out.Names, nil
}
