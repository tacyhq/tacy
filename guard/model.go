package guard

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	ehbpidentity "github.com/tinfoilsh/encrypted-http-body-protocol/identity"

	"github.com/tacyhq/tacy/internal/tinfoil"
	"github.com/tacyhq/tacy/proto"
	"github.com/tacyhq/tacy/vault"
)

// Models are Tinfoil's chat models (docs.tinfoil.sh/models/chat, 2026-10-13), each with the reasoning_effort
// values it accepts (anything else is a 400 upstream). All six support tool calling.
var models = map[string][]string{
	"gpt-oss-120b":        {"low", "medium", "high"},
	"gemma4-31b":          {"none", "minimal", "low", "medium", "high", "xhigh", "max"},
	"llama3-3-70b":        nil,
	"glm-5-3":             {"low", "high", "max"},
	"kimi-k3":             {"low", "high", "max"},
	"deepseek-v4-1-flash": {"none", "low", "high", "xhigh", "max"},
}

const defaultModel = proto.DefaultModel

// Upstream is an OpenAI-compatible chat completions endpoint that streams.
type Upstream interface {
	// Stream posts body to /v1/chat/completions and returns the SSE response body.
	Stream(ctx context.Context, body []byte) (io.ReadCloser, error)
	// Meta describes the verified endpoint (filled into the run's meta event).
	Meta(ctx context.Context) (*proto.Meta, error)
}

// tinfoilUpstream calls Tinfoil's router after verifying it (internal/tinfoil), with bodies EHBP-encrypted to its
// attested key. The API key is leased for each call, for the verified host only, travels in a header to it,
// and is wiped when the response is closed.
type tinfoilUpstream struct {
	c     *tinfoil.Client
	lease Lease
}

const tinfoilKey = "TINFOIL_API_KEY"

// leasedBody is a response read under a leased key: Close wipes the key, and the model gateway redacts every
// encoding of it from what the model sent (Leased) before anything reaches people or the brain.
type leasedBody struct {
	io.ReadCloser
	key *vault.Secret
}

func (b *leasedBody) Leased() []*vault.Secret { return []*vault.Secret{b.key} }

func (b *leasedBody) Close() error {
	err := b.ReadCloser.Close()
	b.key.Wipe()
	return err
}

// leasedOf returns the secrets a stream was read under (nil for none).
func leasedOf(r io.ReadCloser) []*vault.Secret {
	if l, ok := r.(interface{ Leased() []*vault.Secret }); ok {
		return l.Leased()
	}
	return nil
}

func (t *tinfoilUpstream) Meta(ctx context.Context) (*proto.Meta, error) {
	v, _, err := t.c.Current(ctx)
	if err != nil {
		return nil, err
	}
	return &proto.Meta{TinfoilEnclave: v.Enclave, TinfoilRelease: v.Release, TinfoilMeasure: v.Measurement,
		TinfoilHPKEKey: v.HPKEKey}, nil
}

func (t *tinfoilUpstream) Stream(ctx context.Context, body []byte) (io.ReadCloser, error) {
	for attempt := 0; ; attempt++ {
		v, hc, err := t.c.Current(ctx)
		if err != nil {
			return nil, fmt.Errorf("Tinfoil verification failed: %w", err)
		}
		if t.lease == nil {
			return nil, errors.New("model key unavailable")
		}
		key, err := t.lease(ctx, tinfoilKey, "model", v.Enclave)
		if err != nil {
			return nil, leaseError(err, "model key unavailable") // the vault's rule stays in its record
		}
		req, _ := http.NewRequestWithContext(ctx, "POST", "https://"+v.Enclave+"/v1/chat/completions", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "text/event-stream")
		req.Header.Set("Authorization", "Bearer "+string(key.Bytes()))
		res, err := hc.Do(req)
		if err != nil {
			key.Wipe()
			// The router rotated its key: verify again and retry once (with a new lease).
			if ehbpidentity.IsKeyConfigError(err) && attempt == 0 {
				t.c.Invalidate()
				continue
			}
			return nil, fmt.Errorf("model request failed")
		}
		if res.StatusCode != 200 {
			b, _ := io.ReadAll(io.LimitReader(res.Body, 2000))
			res.Body.Close()
			b = exactRedact(b, []*vault.Secret{key})
			key.Wipe()
			return nil, fmt.Errorf("model returned %d: %s", res.StatusCode, upstreamError(b))
		}
		return &leasedBody{ReadCloser: res.Body, key: key}, nil
	}
}

// upstreamError extracts the error message of an OpenAI-style error body.
func upstreamError(b []byte) string {
	var e struct {
		Error struct {
			Message string `json:"message"`
		} `json:"error"`
		Message string `json:"message"`
	}
	if json.Unmarshal(b, &e) == nil {
		if e.Error.Message != "" {
			return capRunes(e.Error.Message, 300)
		}
		if e.Message != "" {
			return capRunes(e.Message, 300)
		}
	}
	return capRunes(strings.TrimSpace(string(b)), 300)
}

// plainUpstream is an unverified OpenAI-compatible endpoint, for tests only.
type plainUpstream struct {
	url  string
	http *http.Client
}

func (p *plainUpstream) Meta(context.Context) (*proto.Meta, error) {
	return &proto.Meta{TinfoilEnclave: "test"}, nil
}

func (p *plainUpstream) Stream(ctx context.Context, body []byte) (io.ReadCloser, error) {
	req, _ := http.NewRequestWithContext(ctx, "POST", p.url, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	res, err := p.http.Do(req)
	if err != nil {
		return nil, err
	}
	if res.StatusCode != 200 {
		b, _ := io.ReadAll(io.LimitReader(res.Body, 2000))
		res.Body.Close()
		return nil, fmt.Errorf("model returned %d: %s", res.StatusCode, upstreamError(b))
	}
	return res.Body, nil
}

// ---- streaming response parsing ------------------------------------------------------------------------------

type toolCall struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Function struct {
		Name      string `json:"name"`
		Arguments string `json:"arguments"`
	} `json:"function"`
}

type chunk struct {
	Choices []struct {
		Delta struct {
			Content          string `json:"content"`
			Reasoning        string `json:"reasoning"`
			ReasoningContent string `json:"reasoning_content"`
			ToolCalls        []struct {
				Index    int    `json:"index"`
				ID       string `json:"id"`
				Function struct {
					Name      string `json:"name"`
					Arguments string `json:"arguments"`
				} `json:"function"`
			} `json:"tool_calls"`
		} `json:"delta"`
		FinishReason string `json:"finish_reason"`
	} `json:"choices"`
	Usage *chunkUsage `json:"usage"`
}

// chunkUsage is OpenAI's usage object: the counts the run sums (proto.Usage) plus the cached prompt tokens, which
// only the metrics event carries.
type chunkUsage struct {
	proto.Usage
	PromptTokensDetails *struct {
		CachedTokens int `json:"cached_tokens"`
	} `json:"prompt_tokens_details"`
}

// stepResult is one streamed model response, assembled.
type stepResult struct {
	text, reasoning string
	calls           []toolCall
	finish          string
	usage           *proto.Usage
	cached          int       // prompt tokens served from the prompt cache, when reported
	firstAt, textAt time.Time // first token of any kind (reasoning, text, tool call) and first answer text; zero if none
}

const maxStepOutput = 4 << 20 // bytes of text + reasoning + tool arguments per model call

// readStream parses an OpenAI chat-completions SSE stream, calling onDelta for each text or reasoning piece.
func readStream(r io.Reader, onDelta func(kind, delta string) error) (*stepResult, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64<<10), 4<<20)
	res := &stepResult{}
	var text, reasoning strings.Builder
	byIndex := map[int]*toolCall{}
	var order []int
	size := 0
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		data := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		if data == "[DONE]" {
			break
		}
		var c chunk
		if err := json.Unmarshal([]byte(data), &c); err != nil {
			return nil, errors.New("model stream: malformed chunk")
		}
		if c.Usage != nil {
			u := c.Usage.Usage
			res.usage = &u
			if c.Usage.PromptTokensDetails != nil {
				res.cached = c.Usage.PromptTokensDetails.CachedTokens
			}
		}
		for _, ch := range c.Choices {
			d := ch.Delta
			if res.firstAt.IsZero() && (d.Reasoning != "" || d.ReasoningContent != "" || d.Content != "" || len(d.ToolCalls) > 0) {
				res.firstAt = time.Now()
			}
			if res.textAt.IsZero() && d.Content != "" {
				res.textAt = time.Now()
			}
			if r := d.Reasoning + d.ReasoningContent; r != "" {
				reasoning.WriteString(r)
				size += len(r)
				if err := onDelta("reasoning", r); err != nil {
					return nil, err
				}
			}
			if d.Content != "" {
				text.WriteString(d.Content)
				size += len(d.Content)
				if err := onDelta("text", d.Content); err != nil {
					return nil, err
				}
			}
			for _, tc := range d.ToolCalls {
				call, ok := byIndex[tc.Index]
				if !ok {
					call = &toolCall{Type: "function"}
					byIndex[tc.Index] = call
					order = append(order, tc.Index)
				}
				if tc.ID != "" {
					call.ID = tc.ID
				}
				call.Function.Name += tc.Function.Name
				call.Function.Arguments += tc.Function.Arguments
				size += len(tc.Function.Arguments)
			}
			if ch.FinishReason != "" {
				res.finish = ch.FinishReason
			}
		}
		if size > maxStepOutput {
			return nil, errors.New("model output too large")
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("model stream: %w", err)
	}
	res.text, res.reasoning = text.String(), reasoning.String()
	for i, idx := range order {
		c := byIndex[idx]
		if c.ID == "" {
			c.ID = fmt.Sprintf("call_%d", i+1)
		}
		res.calls = append(res.calls, *c)
	}
	return res, nil
}
