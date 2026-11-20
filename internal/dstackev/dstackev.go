// Package dstackev is a VM process's TDX evidence from dstack's guest agent: GetQuote with a 64-byte report_data,
// and Info (the app-compose and the instance id). vaultd uses it for its own key service release (agentd has its
// own platform code, app/platform.go). Only GetQuote and Info: never GetKey, whose keys are the provider's.
package dstackev

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

// Source asks the guest agent on its unix socket.
type Source struct{ http *http.Client }

// New is a Source on sock (/var/run/dstack.sock).
func New(sock string) *Source {
	return &Source{http: &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", sock)
		},
	}}}
}

func (s *Source) call(ctx context.Context, method, path string, body any) (json.RawMessage, error) {
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, "http://dstack"+path, rd)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := s.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	b, err := io.ReadAll(io.LimitReader(res.Body, 4<<20))
	if err != nil {
		return nil, err
	}
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("dstack %s: %d", path, res.StatusCode)
	}
	return b, nil
}

// Evidence is the quote for reportData and the guest agent's Info (kms/client.Evidence).
func (s *Source) Evidence(ctx context.Context, reportData []byte) (json.RawMessage, json.RawMessage, error) {
	if len(reportData) != 64 {
		return nil, nil, errors.New("report_data must be 64 bytes")
	}
	q, err := s.call(ctx, http.MethodPost, "/GetQuote", map[string]string{"report_data": hex.EncodeToString(reportData)})
	if err != nil {
		return nil, nil, err
	}
	info, err := s.call(ctx, http.MethodGet, "/Info", nil)
	if err != nil {
		return nil, nil, err
	}
	return q, info, nil
}
