package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

// Platform is everything host-specific: where secrets come from, how attestation evidence is produced, and where
// (encrypted) scratch storage lives. Moving to Google TDX (dstack too: same adapter) or Tinfoil Containers (their
// attestation document and secrets) means one more implementation of this, nothing else.
type Platform interface {
	Name() string
	// Secret returns a named secret, or "" when it isn't set.
	Secret(name string) string
	// Evidence returns attestation evidence whose report_data is exactly reportData (64 bytes), plus platform
	// info the verifier needs (for dstack: the app compose and event log).
	Evidence(ctx context.Context, reportData []byte) (quote, info json.RawMessage, err error)
	// StoragePath is a directory on the platform's encrypted disk for later tools, or "" when there's none.
	// Nothing uses it yet: the service is stateless.
	StoragePath() string
	// ActivityKey is key material only this attested app gets, for the activity signing key (docs/24): dstack's
	// KMS-derived key for a fixed path, the same after a restart. Locally, random per boot.
	ActivityKey(ctx context.Context) ([]byte, error)
}

// dstack: Phala Cloud, or open-source dstack on Google Cloud. Secrets are dstack's encrypted environment
// variables (encrypted to the CVM by the deployer, decrypted inside it); evidence comes from the guest agent socket.
type dstack struct {
	sock    string
	storage string
	http    *http.Client
}

func newDstack(sock, storage string) *dstack {
	return &dstack{sock: sock, storage: storage, http: &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", sock)
		},
	}}}
}

func (d *dstack) Name() string              { return "dstack" }
func (d *dstack) Secret(name string) string { return os.Getenv(name) }
func (d *dstack) StoragePath() string       { return d.storage }

func (d *dstack) call(ctx context.Context, method, path string, body any) (json.RawMessage, error) {
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequestWithContext(ctx, method, "http://dstack"+path, rd)
	req.Header.Set("Content-Type", "application/json")
	res, err := d.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	b, err := io.ReadAll(io.LimitReader(res.Body, 4<<20))
	if err != nil {
		return nil, err
	}
	if res.StatusCode != 200 {
		return nil, fmt.Errorf("dstack %s: %d", path, res.StatusCode)
	}
	return b, nil
}

func (d *dstack) Evidence(ctx context.Context, reportData []byte) (json.RawMessage, json.RawMessage, error) {
	if len(reportData) != 64 {
		return nil, nil, errors.New("report_data must be 64 bytes")
	}
	q, err := d.call(ctx, "POST", "/GetQuote", map[string]string{"report_data": hex.EncodeToString(reportData)})
	if err != nil {
		return nil, nil, err
	}
	info, err := d.call(ctx, "GET", "/Info", nil)
	if err != nil {
		return nil, nil, err
	}
	return q, info, nil
}

// ActivityKey asks the guest agent for the app's key at path "tacy/activity/v1" (dstack derives it from the KMS
// root, the app id and the path; it never leaves the CVM). The response's key is hex; its signature chain (which
// proves the key to dstack's KMS) isn't needed here: the browser learns the derived public key over EHBP from the
// attested VM (meta.activity).
func (d *dstack) ActivityKey(ctx context.Context) ([]byte, error) {
	b, err := d.call(ctx, "POST", "/GetKey", map[string]string{"path": "tacy/activity/v1", "purpose": "signing"})
	if err != nil {
		return nil, err
	}
	var r struct {
		Key string `json:"key"`
	}
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, err
	}
	k, err := hex.DecodeString(strings.TrimPrefix(r.Key, "0x"))
	if err != nil || len(k) < 32 {
		return nil, errors.New("dstack GetKey: no usable key")
	}
	return k, nil
}

// local is for development on a laptop: secrets from the environment, no attestation. The verifier refuses it
// unless told to skip attestation.
type local struct{}

func (local) Name() string              { return "local" }
func (local) Secret(name string) string { return os.Getenv(name) }
func (local) StoragePath() string       { return "" }
func (local) ActivityKey(context.Context) ([]byte, error) {
	k := make([]byte, 32)
	_, err := rand.Read(k)
	return k, err
}
func (local) Evidence(context.Context, []byte) (json.RawMessage, json.RawMessage, error) {
	return nil, nil, nil
}
