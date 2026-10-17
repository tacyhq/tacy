package vault

import (
	"bytes"

	"github.com/tacyhq/tacy/leakscan"
)

// Secret is a leased value. It prints, formats and marshals as "[secret]", so a stray log line or error can't
// carry it; Bytes is the one explicit way to use it. Wipe it when the request is done.
type Secret struct {
	v     []byte
	Lease string
}

const hidden = "[secret]"

// NewSecret wraps a copy of v (tests and local development, where no vault runs: the caller's keys).
func NewSecret(v []byte, lease string) *Secret { return &Secret{v: bytes.Clone(v), Lease: lease} }

func (s *Secret) String() string               { return hidden }
func (s *Secret) GoString() string             { return hidden }
func (s *Secret) MarshalText() ([]byte, error) { return []byte(hidden), nil }
func (s *Secret) MarshalJSON() ([]byte, error) { return []byte(`"` + hidden + `"`), nil }
func (s *Secret) Bytes() []byte                { return s.v }
func (s *Secret) Wipe()                        { clear(s.v); s.v = nil }

// Redact replaces every variant of s in data (leakscan.Variants: raw, base64, hex, percent-encoded) with
// placeholder and says how many it replaced. The gateway also runs leakscan.Redact on responses, which finds the
// value under any decoding ("exact vault values, including base64, URL and hex
// encodings").
func Redact(data []byte, s *Secret, placeholder string) ([]byte, int) {
	n := 0
	for _, v := range leakscan.Variants(s.Bytes()) {
		if c := bytes.Count(data, v); c > 0 {
			n += c
			data = bytes.ReplaceAll(data, v, []byte(placeholder))
		}
	}
	return data, n
}
