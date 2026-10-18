// Package agentclient talks to an agent VM: fetch and verify its attestation, then send EHBP-encrypted /run
// requests to the attested key and read the decrypted event stream.
package agentclient

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	ehbpclient "github.com/tinfoilsh/encrypted-http-body-protocol/client"
	ehbpidentity "github.com/tinfoilsh/encrypted-http-body-protocol/identity"

	"github.com/tacyhq/tacy/proto"
	"github.com/tacyhq/tacy/verifier"
)

var plain = &http.Client{Timeout: 30 * time.Second}

// Attest fetches /attest with a fresh nonce and returns the response, its raw bytes and the nonce.
func Attest(ctx context.Context, base string) (*proto.Attestation, []byte, []byte, error) {
	nonce := make([]byte, 32)
	rand.Read(nonce)
	req, _ := http.NewRequestWithContext(ctx, "GET", strings.TrimSuffix(base, "/")+"/attest?nonce="+hex.EncodeToString(nonce), nil)
	res, err := plain.Do(req)
	if err != nil {
		return nil, nil, nil, err
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, 4<<20))
	if err != nil {
		return nil, nil, nil, err
	}
	if res.StatusCode != 200 {
		return nil, nil, nil, fmt.Errorf("attest: HTTP %d", res.StatusCode)
	}
	var a proto.Attestation
	if err := json.Unmarshal(raw, &a); err != nil {
		return nil, nil, nil, fmt.Errorf("attest: %w", err)
	}
	return &a, raw, nonce, nil
}

// Conn sends encrypted requests to one verified agent VM boot.
type Conn struct {
	Base  string
	Token string
	// User is the opaque per-user tag sent as X-Agent-User (fairness only); "" sends none.
	User string
	// Model, when set, is sent as X-Agent-Model instead of the request's model (tests: the VM must refuse it).
	Model string
	key   []byte
	http  *http.Client
}

// New makes a connection that encrypts to key (which must come from a verified attestation).
func New(base, token string, key []byte) (*Conn, error) {
	id, err := ehbpidentity.FromPublicKeyBytes(key)
	if err != nil {
		return nil, err
	}
	tr, err := ehbpclient.NewTransportWithIdentity(id)
	if err != nil {
		return nil, err
	}
	return &Conn{Base: strings.TrimSuffix(base, "/"), Token: token, key: key, http: &http.Client{Transport: tr}}, nil
}

// Connect attests, verifies and returns a connection to the attested key.
func Connect(ctx context.Context, base, token string, p verifier.Policy) (*Conn, *verifier.Result, error) {
	a, _, nonce, err := Attest(ctx, base)
	if err != nil {
		return nil, nil, err
	}
	res, err := verifier.Verify(ctx, a, nonce, p)
	if err != nil {
		return nil, res, err
	}
	c, err := New(base, token, res.HPKEPublicKey)
	return c, res, err
}

// Run posts req and calls on for each event until [DONE]. The request and every event are EHBP-encrypted.
func (c *Conn) Run(ctx context.Context, req proto.RunRequest, on func(proto.Event)) error {
	if req.Model == "" {
		req.Model = proto.DefaultModel
	}
	body, _ := json.Marshal(req)
	r, _ := http.NewRequestWithContext(ctx, "POST", c.Base+"/run", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer "+c.Token)
	r.Header.Set("X-Agent-Model", req.Model)
	if c.Model != "" {
		r.Header.Set("X-Agent-Model", c.Model)
	}
	if c.User != "" {
		r.Header.Set("X-Agent-User", c.User)
	}
	res, err := c.http.Do(r)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		b, _ := io.ReadAll(io.LimitReader(res.Body, 2000))
		return fmt.Errorf("run: HTTP %d: %s", res.StatusCode, strings.TrimSpace(string(b)))
	}
	sc := bufio.NewScanner(res.Body)
	sc.Buffer(make([]byte, 0, 64<<10), 8<<20)
	for sc.Scan() {
		data, ok := strings.CutPrefix(sc.Text(), "data: ")
		if !ok {
			continue
		}
		if data == "[DONE]" {
			return nil
		}
		var e proto.Event
		if err := json.Unmarshal([]byte(data), &e); err != nil {
			return fmt.Errorf("bad event: %w", err)
		}
		on(e)
	}
	if err := sc.Err(); err != nil {
		return err
	}
	return errors.New("stream ended without [DONE]")
}

// ---- the task API (docs/27; agentd's app/tasks.go) ----------------------------------------------------------

// Task is a task's state as POST /tasks and /tasks/status answer it.
type Task struct {
	Task     string `json:"task"`
	State    string `json:"state"`
	Sub      string `json:"sub,omitempty"`
	Attempt  int    `json:"attempt"`
	Events   int    `json:"events"`
	Held     int    `json:"held,omitempty"`
	Outcome  string `json:"outcome,omitempty"`
	Existing bool   `json:"existing,omitempty"`
}

// post sends one EHBP-encrypted task call and returns the decrypted response.
func (c *Conn) post(ctx context.Context, path, model string, v any) (*http.Response, error) {
	body, _ := json.Marshal(v)
	r, _ := http.NewRequestWithContext(ctx, "POST", c.Base+path, bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer "+c.Token)
	if model != "" {
		r.Header.Set("X-Agent-Model", model)
	}
	if c.User != "" {
		r.Header.Set("X-Agent-User", c.User)
	}
	res, err := c.http.Do(r)
	if err != nil {
		return nil, err
	}
	if res.StatusCode != 200 {
		b, _ := io.ReadAll(io.LimitReader(res.Body, 2000))
		res.Body.Close()
		return nil, fmt.Errorf("%s: HTTP %d: %s", path, res.StatusCode, strings.TrimSpace(string(b)))
	}
	return res, nil
}

func (c *Conn) taskCall(ctx context.Context, path, model string, v any) (*Task, error) {
	res, err := c.post(ctx, path, model, v)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	var t Task
	if err := json.NewDecoder(io.LimitReader(res.Body, 64<<10)).Decode(&t); err != nil {
		return nil, err
	}
	return &t, nil
}

// StartTask starts req as a task. key, when set, makes the start once-only (a retry finds the same task).
func (c *Conn) StartTask(ctx context.Context, req proto.RunRequest, key string) (*Task, error) {
	if req.Model == "" {
		req.Model = proto.DefaultModel
	}
	model := req.Model
	if c.Model != "" {
		model = c.Model
	}
	return c.taskCall(ctx, "/tasks", model, struct {
		proto.RunRequest
		Key string `json:"key,omitempty"`
	}{req, key})
}

// TaskStatus is a task's state.
func (c *Conn) TaskStatus(ctx context.Context, id string) (*Task, error) {
	return c.taskCall(ctx, "/tasks/status", "", map[string]any{"task": id})
}

// CancelTask cancels a task.
func (c *Conn) CancelTask(ctx context.Context, id string) (*Task, error) {
	return c.taskCall(ctx, "/tasks/cancel", "", map[string]any{"task": id})
}

// FollowTask calls on for each of the task's events after seq after, until the task ended ([DONE], nil) or ctx
// ends. Reconnect with the last seq on saw to continue.
func (c *Conn) FollowTask(ctx context.Context, id string, after int, on func(seq int, e proto.Event)) error {
	res, err := c.post(ctx, "/tasks/events", "", map[string]any{"task": id, "after": after})
	if err != nil {
		return err
	}
	defer res.Body.Close()
	sc := bufio.NewScanner(res.Body)
	sc.Buffer(make([]byte, 0, 64<<10), 8<<20)
	seq := 0
	for sc.Scan() {
		line := sc.Text()
		if v, ok := strings.CutPrefix(line, "id: "); ok {
			if _, err := fmt.Sscan(v, &seq); err != nil {
				return fmt.Errorf("bad event id %q", v)
			}
			continue
		}
		data, ok := strings.CutPrefix(line, "data: ")
		if !ok {
			continue
		}
		if data == "[DONE]" {
			return nil
		}
		var e proto.Event
		if err := json.Unmarshal([]byte(data), &e); err != nil {
			return fmt.Errorf("bad event: %w", err)
		}
		on(seq, e)
	}
	if err := sc.Err(); err != nil {
		return err
	}
	return errors.New("stream ended without [DONE]")
}
