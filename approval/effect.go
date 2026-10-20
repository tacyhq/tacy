package approval

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/jsontext"
	"errors"
)

// EffectLabel prefixes what an effect hash covers.
const EffectLabel = "tacy-effect/v1"

// MaxEffect bounds an effect's canonical JSON (an action's arguments are at most 256 KiB; harness/v1).
const MaxEffect = 512 << 10

// Canonical is an effect in canonical JSON (RFC 8785, JCS: sorted member names, no whitespace, shortest numbers):
// the exact thing that would happen, which the person sees and the hash binds. Invalid JSON, duplicate member
// names, invalid UTF-8 and anything over MaxEffect are refused. The browser canonicalizes the same way to check
// the hash it shows.
func Canonical(effect []byte) ([]byte, error) {
	if len(effect) == 0 || len(effect) > MaxEffect {
		return nil, errors.New("approval: effect empty or too large")
	}
	v := jsontext.Value(append([]byte(nil), effect...))
	if err := v.Canonicalize(); err != nil {
		return nil, errors.New("approval: effect isn't valid JSON")
	}
	if v.Kind() != '{' {
		return nil, errors.New("approval: effect must be a JSON object")
	}
	return v, nil
}

// EffectHash is sha256("tacy-effect/v1" ‖ NUL ‖ canonical effect), lowercase hex. Callers pass Canonical's output.
func EffectHash(canonical []byte) string {
	h := sha256.New()
	h.Write([]byte(EffectLabel + "\x00"))
	h.Write(canonical)
	return hex.EncodeToString(h.Sum(nil))
}
