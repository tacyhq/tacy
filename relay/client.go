package relay

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
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
)

// Transport sends each request as a signed envelope in POST /v to the same host, encrypted to VMKey, and returns
// the inner response. What the relay (the chat's Worker) does, for Go tools and tests: agentclient, cmd/e2e.
type Transport struct {
	VMKey []byte             // agentd's attested HPKE public key
	Key   ed25519.PrivateKey // the relay-auth signing key
	Base  http.RoundTripper  // to the VM (nil: http.DefaultTransport)
	Now   func() time.Time   // nil: time.Now
	// Sent, when set, gets each outer request as it goes to the VM (tests: what the gateway sees).
	Sent func(*http.Request)

	outer http.RoundTripper
}

// skipHeaders are request headers the envelope doesn't carry: hop-by-hop, the HTTP client's own, and the bearer
// token that the signature replaces.
var skipHeaders = map[string]bool{"Authorization": true, "Content-Length": true, "Transfer-Encoding": true, "Connection": true,
	"Host": true, "User-Agent": true, "Accept-Encoding": true}

// ParseKey reads a relay-auth signing key: the 32-byte Ed25519 seed, base64 (standard or URL alphabet, padded or not).
func ParseKey(s string) (ed25519.PrivateKey, error) {
	s = strings.TrimRight(strings.TrimSpace(s), "=")
	b, err := base64.RawURLEncoding.DecodeString(strings.NewReplacer("+", "-", "/", "_").Replace(s))
	if err != nil || len(b) != ed25519.SeedSize {
		return nil, errors.New("relay: the signing key must be a 32-byte Ed25519 seed, base64")
	}
	return ed25519.NewKeyFromSeed(b), nil
}

// PublicKeyString is pub as the compose pins it ("ed25519:<base64>", like the safety keys).
func PublicKeyString(pub ed25519.PublicKey) string {
	return "ed25519:" + base64.StdEncoding.EncodeToString(pub)
}

// Seal makes one request's envelope plaintext: header and body, padded to a size class.
func Seal(method, path string, headers map[string]string, body []byte, key ed25519.PrivateKey, now time.Time) ([]byte, *Header, error) {
	nonce := make([]byte, NonceHex/2)
	rand.Read(nonce)
	return SealNonce(method, path, headers, body, key, now, hex.EncodeToString(nonce))
}

// SealNonce is Seal with a given nonce (golden vectors only: a nonce is never used twice).
func SealNonce(method, path string, headers map[string]string, body []byte, key ed25519.PrivateKey, now time.Time, nonce string) ([]byte, *Header, error) {
	h := &Header{Method: method, Path: path, Headers: headers}
	Sign(h, body, key, now, nonce)
	if err := h.Check(); err != nil {
		return nil, nil, err
	}
	hb, _ := json.Marshal(h)
	n := 4 + len(hb) + len(body)
	out := make([]byte, 0, proto.PadPow2(n, proto.AnswerMin, proto.AnswerMax))
	out = binary.BigEndian.AppendUint32(out, uint32(len(hb)))
	out = append(out, hb...)
	out = append(out, body...)
	return out[:cap(out)], h, nil
}

func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.outer == nil {
		id, err := ehbpidentity.FromPublicKeyBytes(t.VMKey)
		if err != nil {
			return nil, err
		}
		base := t.Base
		if base == nil {
			base = http.DefaultTransport
		}
		tr, err := ehbpclient.NewTransportWithIdentity(id, ehbpclient.WithHTTPClient(&http.Client{Transport: sentHook{base, t.Sent}}))
		if err != nil {
			return nil, err
		}
		t.outer = tr
	}
	var body []byte
	if req.Body != nil {
		b, err := io.ReadAll(io.LimitReader(req.Body, MaxBody+1))
		req.Body.Close()
		if err != nil {
			return nil, err
		}
		if len(b) > MaxBody {
			return nil, errors.New("relay: body too large")
		}
		body = b
	}
	headers := map[string]string{}
	for k, v := range req.Header {
		if !skipHeaders[k] && len(v) > 0 {
			headers[k] = v[0]
		}
	}
	now := time.Now
	if t.Now != nil {
		now = t.Now
	}
	plain, _, err := Seal(req.Method, req.URL.RequestURI(), headers, body, t.Key, now())
	if err != nil {
		return nil, err
	}
	u := *req.URL
	u.Path, u.RawPath, u.RawQuery = Path, "", ""
	out, _ := http.NewRequestWithContext(req.Context(), "POST", u.String(), bytes.NewReader(plain))
	out.Header.Set("Content-Type", "application/octet-stream")
	res, err := t.outer.RoundTrip(out)
	if err != nil {
		return nil, err
	}
	if res.StatusCode != 200 {
		return nil, fmt.Errorf("relay: the VM answered %d to the envelope", res.StatusCode)
	}
	inner, err := ReadResponse(res.Body)
	if err != nil {
		return nil, err
	}
	inner.Request = req
	return inner, nil
}

type sentHook struct {
	base http.RoundTripper
	sent func(*http.Request)
}

func (s sentHook) RoundTrip(r *http.Request) (*http.Response, error) {
	if s.sent != nil {
		s.sent(r)
	}
	return s.base.RoundTrip(r)
}
