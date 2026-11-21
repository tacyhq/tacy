package guard

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
)

// The scope of Tinfoil's prompt cache (user_cache_secret) a task's model calls send (gateway.go, reader.go): the
// person's own when the run brought one (cache_secret, the chat's per-account secret), else one derived from the
// per-boot secret and the task's space, so runs of two spaces never share a scope. Scheduled runs and any request
// that leaves cache_secret out used to share the per-boot secret itself, so one space could time another's cached
// prompts. "": no per-boot secret (tests), none sent.
func (g *Guard) cacheScope(o TaskOptions) string {
	if o.CacheSecret != "" {
		return o.CacheSecret
	}
	return SpaceCacheSecret(g.cfg.CacheSecret, o.Space)
}

// SpaceCacheSecret is the scope for space under the per-boot secret boot: HMAC-SHA256(boot, label ‖ space), hex. ""
// when boot is "".
func SpaceCacheSecret(boot, space string) string {
	if boot == "" {
		return ""
	}
	m := hmac.New(sha256.New, []byte(boot))
	m.Write([]byte("tacy/prompt-cache-scope/v1\x00" + space))
	return hex.EncodeToString(m.Sum(nil))
}
