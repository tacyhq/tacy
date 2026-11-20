// Package relay is how the chat's relay (the Worker) talks to agentd without telling the provider's gateway
// anything (the keys plan §3.4; closes PX-1 and PX-2 of the Phala-exposure audit).
//
// Phala's gateway terminates TLS in front of the VM. Before this, it saw every request's path (/tasks, /schedules/
// install, /connections/put …), the relay's bearer token, and the plaintext headers (X-Agent-User, X-Agent-Model,
// X-Agent-Kind, X-Agent-Bill, X-Schedule-Charge …): EHBP covered the bodies only. Now every call is one request
// type, POST /v, whose body is an EHBP envelope to agentd's attested HPKE key. Inside it:
//
//   - the method and the path (with its query);
//   - the headers the relay used to send in plaintext, the browser's own EHBP encapsulated key among them;
//   - the relay's signature (Ed25519, key purpose relay-auth; the public half is pinned in the attested compose as
//     agentd's -relay-auth-key) over all of that, a fresh nonce, the time, and the inner body's hash;
//   - the inner body: the browser's own EHBP ciphertext, opaque, or the relay's plaintext JSON for its own calls.
//
// The answer comes back the same way: the outer response is encrypted to the relay's request (EHBP), and inside it
// are frames: one with the inner status and headers (the billing witness X-Agent-Bill and the browser's
// Ehbp-Response-Nonce among them), then the inner body's bytes as they come (the browser's EHBP chunks for a stream).
// The gateway sees POST /v, sizes in padded buckets, and timing; never a path, a header, a token or a status.
//
// The signature replaces the bearer token: a call needs the relay's key, not a string that crossed the gateway. A
// signed envelope is good once (its nonce is remembered) and for Window around agentd's clock (and not older than
// the operator's signed time allows, when agentd has it: the host sets the VM's clock). The relay's key opens no
// data: what a person signs (their identity key) still authorizes everything that reads or changes their data, and
// destructive calls the relay makes for a person carry that person's signature too (app/handoff.go).
//
// Request plaintext (inside the outer EHBP body):
//
//	u32 big-endian n | n bytes: Header JSON | Header.Len bytes: the inner body | zero padding
//
// The relay pads the whole to proto.PadPow2 so the request's size is a size class too.
//
// Response plaintext (inside the outer EHBP response): frames, each
//
//	1 byte type | u32 big-endian n | n bytes
//
// type 'H' (first, once): ResponseHead JSON padded with spaces to a multiple of 512 bytes; 'D': inner body bytes.
// Each outer EHBP chunk carries whole frames.
package relay

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/textproto"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Path is the one request path the gateway sees.
const Path = "/v"

// Label is the signature's domain separation (the first line of what is signed).
const Label = "tacy/relay-auth/v1"

// Version is Header.V.
const Version = 1

// Limits.
const (
	Window     = 2 * time.Minute // a signed envelope is taken this long either side of agentd's clock
	MaxHeader  = 16 << 10        // the Header JSON
	MaxBody    = 8 << 20         // the inner body (a run's ciphertext is capped at 8 MiB already)
	MaxHeaders = 32              // inner headers
	NonceHex   = 32              // 16 random bytes, hex
)

// Header is an envelope's first part: what the relay asks for, signed.
type Header struct {
	V       int               `json:"v"`
	Method  string            `json:"m"`           // GET or POST
	Path    string            `json:"p"`           // the inner path and query, e.g. /tasks or /activity?chain=…
	Headers map[string]string `json:"h,omitempty"` // inner request headers (one value each)
	Len     int               `json:"n"`           // inner body bytes
	BodySHA string            `json:"b"`           // hex SHA-256 of the inner body
	Nonce   string            `json:"nonce"`       // NonceHex hex digits, never used twice
	Time    int64             `json:"t"`           // unix seconds when the relay signed it
	Sig     string            `json:"sig"`         // base64 Ed25519 over Signed()
}

// ResponseHead is a response's 'H' frame: the inner status and headers.
type ResponseHead struct {
	Status  int               `json:"s"`
	Headers map[string]string `json:"h,omitempty"`
}

var (
	nonceRe  = regexp.MustCompile(`^[0-9a-f]{32}\z`)
	shaRe    = regexp.MustCompile(`^[0-9a-f]{64}\z`)
	nameRe   = regexp.MustCompile(`^[A-Za-z0-9-]{1,64}\z`)
	pathRe   = regexp.MustCompile(`^/[A-Za-z0-9._~/%-]*(\?[A-Za-z0-9._~%&=+,:-]*)?\z`)
	errValue = errors.New("relay: a header value has a control character")
)

// Signed is the exact bytes the relay signs: the label, then one line each for the method, the path, the nonce, the
// time, the body's hash and length, then each header as "lowercase-name:value", sorted by name.
func (h *Header) Signed() []byte {
	var b strings.Builder
	b.WriteString(Label + "\n" + h.Method + "\n" + h.Path + "\n" + h.Nonce + "\n" + strconv.FormatInt(h.Time, 10) + "\n" +
		h.BodySHA + "\n" + strconv.Itoa(h.Len) + "\n")
	names := make([]string, 0, len(h.Headers))
	lower := make(map[string]string, len(h.Headers))
	for k, v := range h.Headers {
		lk := strings.ToLower(k)
		names = append(names, lk)
		lower[lk] = v
	}
	slices.Sort(names)
	for _, k := range names {
		b.WriteString(k + ":" + lower[k] + "\n")
	}
	return []byte(b.String())
}

// Check is the Header's form (not its signature): what agentd refuses before verifying anything.
func (h *Header) Check() error {
	switch {
	case h.V != Version:
		return fmt.Errorf("relay: version %d", h.V)
	case h.Method != "GET" && h.Method != "POST":
		return fmt.Errorf("relay: method %q", h.Method)
	case !pathRe.MatchString(h.Path) || strings.Contains(h.Path, "//") || strings.Contains(h.Path, "..") || h.Path == Path ||
		strings.HasPrefix(h.Path, Path+"?"):
		return errors.New("relay: bad path")
	case h.Len < 0 || h.Len > MaxBody:
		return errors.New("relay: body too large")
	case !shaRe.MatchString(h.BodySHA):
		return errors.New("relay: bad body hash")
	case !nonceRe.MatchString(h.Nonce):
		return errors.New("relay: bad nonce")
	case len(h.Headers) > MaxHeaders:
		return errors.New("relay: too many headers")
	}
	seen := map[string]bool{}
	for k, v := range h.Headers {
		lk := strings.ToLower(k)
		if !nameRe.MatchString(k) || seen[lk] || len(v) > 4096 {
			return fmt.Errorf("relay: header %q", k)
		}
		seen[lk] = true
		if strings.ContainsFunc(v, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
			return errValue
		}
	}
	return nil
}

// Sign fills h's time, nonce (when empty) and signature for body with key.
func Sign(h *Header, body []byte, key ed25519.PrivateKey, now time.Time, nonce string) {
	sum := sha256.Sum256(body)
	h.V, h.Len, h.BodySHA, h.Time, h.Nonce = Version, len(body), hex.EncodeToString(sum[:]), now.Unix(), nonce
	h.Sig = base64.StdEncoding.EncodeToString(ed25519.Sign(key, h.Signed()))
}

// Verify checks h's signature by pub and that body is the one it signed.
func (h *Header) Verify(pub ed25519.PublicKey, body []byte) error {
	if err := h.Check(); err != nil {
		return err
	}
	sum := sha256.Sum256(body)
	if len(body) != h.Len || hex.EncodeToString(sum[:]) != h.BodySHA {
		return errors.New("relay: the body isn't the one signed")
	}
	sig, err := base64.StdEncoding.DecodeString(h.Sig)
	if err != nil || len(sig) != ed25519.SignatureSize || !ed25519.Verify(pub, h.Signed(), sig) {
		return errors.New("relay: bad signature")
	}
	return nil
}

// canonical is a header name in Go's canonical form.
func canonical(k string) string { return textproto.CanonicalMIMEHeaderKey(k) }
