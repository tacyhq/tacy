package agentclient

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// SecretsReady asks GET /secrets/status whether the VM's vaultd has its API keys from the key service this boot. c
// must send the request in a relay envelope (relay.Transport), like every route.
func SecretsReady(ctx context.Context, c *http.Client, base string) (bool, error) {
	r, _ := http.NewRequestWithContext(ctx, "GET", strings.TrimSuffix(base, "/")+"/secrets/status", nil)
	res, err := c.Do(r)
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
