// The patterns below are ported from IronClaw's leak detector
// (github.com/nearai/ironclaw, crates/substrates/ironclaw_safety/src/leak_detector.rs,
// commit b0b999d96781516ee05e6ba961d6f3ead900da96). See NOTICE.
//
// MIT License
//
// Copyright (c) 2026 NEAR AI
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

package leakscan

import (
	"bytes"
	"encoding/json"
	"regexp"
	"strings"
)

// Severity of a finding, ordered: Low < Medium < High < Critical.
type Severity uint8

const (
	Low Severity = iota
	Medium
	High
	Critical
)

func (s Severity) String() string {
	switch s {
	case Low:
		return "low"
	case Medium:
		return "medium"
	case High:
		return "high"
	case Critical:
		return "critical"
	}
	return "unknown"
}

// Action is what a finding asks of the caller. Warn: record only. Redact: remove the match from what passes.
// Block: refuse the whole thing (outbound action arguments); Redact removes Block matches too.
type Action uint8

const (
	Warn Action = iota
	RedactMatch
	Block
)

func (a Action) String() string {
	switch a {
	case Warn:
		return "warn"
	case RedactMatch:
		return "redact"
	case Block:
		return "block"
	}
	return "unknown"
}

// Pattern describes one detector, without its regex.
type Pattern struct {
	ID       string
	Severity Severity
	Action   Action
}

type pattern struct {
	Pattern
	re   *regexp.Regexp
	need string // a literal every match contains; skips the regex when absent ("" = always run)
	jwt  bool   // bare_jwt: the first segment must decode to a JSON object with a string "alg"
	// within, when set, is a set of bytes every match is made of, holding every ASCII word character: the regex
	// then runs only on maximal runs of those bytes that pass run, which finds exactly the same matches (a
	// match can't cross a run's edge, and \b at a run's edge is the same as in the whole input). It keeps the
	// patterns without a literal prefix fast on ordinary text.
	within *[256]bool
	run    func([]byte) bool
	// pre, when set, must be true for the regex to run (a cheap necessary condition).
	pre func([]byte) bool
}

func set(chars string) *[256]bool {
	var t [256]bool
	for i := 0; i < len(chars); i++ {
		t[chars[i]] = true
	}
	return &t
}

const alnum = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

// find returns the pattern's matches in b.
func (p *pattern) find(b []byte) [][]int {
	if p.need != "" && !bytes.Contains(b, []byte(p.need)) || p.pre != nil && !p.pre(b) {
		return nil
	}
	if p.within == nil {
		return p.re.FindAllIndex(b, -1)
	}
	var out [][]int
	for i := 0; i < len(b); {
		if !p.within[b[i]] {
			i++
			continue
		}
		k := i
		for k < len(b) && p.within[b[k]] {
			k++
		}
		if p.run(b[i:k]) {
			for _, m := range p.re.FindAllIndex(b[i:k], -1) {
				out = append(out, []int{m[0] + i, m[1] + i})
			}
		}
		i = k
	}
	return out
}

// jwtRun: long enough for three segments, with two dots.
func jwtRun(r []byte) bool { return len(r) >= 22 && bytes.Count(r, []byte(".")) >= 2 }

// hexRun: the word boundaries on both sides make a match a whole run of word characters, 64 long.
func hexRun(r []byte) bool { return len(r) == 64 }

// hasAuthorization: some "authorization:" in any case (auth_header can't match without one).
func hasAuthorization(b []byte) bool {
	for i := 0; ; {
		k := bytes.IndexByte(b[i:], ':')
		if k < 0 {
			return false
		}
		i += k
		if i >= 13 && bytes.EqualFold(b[i-13:i], []byte("authorization")) {
			return true
		}
		i++
	}
}

// ws is Rust's Unicode \s. Go's \s is ASCII only ([\t\n\f\r ]), so each \s in the upstream patterns is replaced
// with this class to keep matching the same inputs (no-break and other Unicode spaces between "BEGIN" and
// "PRIVATE KEY", for example).
const ws = `[\t\n\v\f\r \x{85}\x{A0}\x{1680}\x{2000}-\x{200A}\x{2028}\x{2029}\x{202F}\x{205F}\x{3000}]`

// patterns are IronClaw's defaults in upstream order, minus nearai_session (NEAR AI's own session ids) and
// sandbox_credential_placeholder (IronClaw's icsbx_ placeholders), plus our placeholder format and our siblings of
// upstream's families at the end.
//
// Differences from upstream that come from the regex engines, all toward matching more:
//   - Go's \b is ASCII, Rust's is Unicode. A Go boundary exists wherever a Rust one does (before or after an
//     ASCII word character), and also next to non-ASCII letters (é, 中).
//   - Go's \d is ASCII; Rust's also matches other scripts' digits. Fullwidth digits are folded to ASCII by the
//     decoding layer (decode.go), so they are still caught there.
var patterns = []pattern{
	{Pattern: Pattern{"openai_api_key", Critical, Block}, need: "sk-",
		re: re(`sk-(?:proj-)?[a-zA-Z0-9]{20,}(?:T3BlbkFJ[a-zA-Z0-9_-]*)?`)},
	{Pattern: Pattern{"anthropic_api_key", Critical, Block}, need: "sk-ant-api",
		re: re(`sk-ant-api[a-zA-Z0-9_-]{90,}`)},
	{Pattern: Pattern{"aws_access_key", Critical, Block}, need: "AKIA",
		re: re(`AKIA[0-9A-Z]{16}`)},
	// Upstream keeps a floor of 16 (not the real 36): a short credential-shaped token must still fail safe.
	{Pattern: Pattern{"github_token", Critical, Block}, need: "gh",
		re: re(`gh[pousr]_[A-Za-z0-9_]{16,}`)},
	{Pattern: Pattern{"github_fine_grained_pat", Critical, Block}, need: "github_pat_",
		re: re(`github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}`)},
	{Pattern: Pattern{"stripe_api_key", Critical, Block}, need: "sk_",
		re: re(`sk_(?:live|test)_[a-zA-Z0-9]{24,}`)},
	// Private keys match the whole block, so redaction can't keep the key material. A missing END consumes the
	// rest of the input (over-redacts, fail safe).
	{Pattern: Pattern{"pem_private_key", Critical, Block}, need: "-----BEGIN",
		re: re(`-----BEGIN(?s:(?:\s+RSA\s+PRIVATE\s+KEY-----.*?(?:-----END\s+RSA\s+PRIVATE\s+KEY-----|$)|\s+PRIVATE\s+KEY-----.*?(?:-----END\s+PRIVATE\s+KEY-----|$)|\s+ENCRYPTED\s+PRIVATE\s+KEY-----.*?(?:-----END\s+ENCRYPTED\s+PRIVATE\s+KEY-----|$)))`)},
	{Pattern: Pattern{"ssh_private_key", Critical, Block}, need: "-----BEGIN",
		re: re(`-----BEGIN(?s:(?:\s+OPENSSH\s+PRIVATE\s+KEY-----.*?(?:-----END\s+OPENSSH\s+PRIVATE\s+KEY-----|$)|\s+EC\s+PRIVATE\s+KEY-----.*?(?:-----END\s+EC\s+PRIVATE\s+KEY-----|$)|\s+DSA\s+PRIVATE\s+KEY-----.*?(?:-----END\s+DSA\s+PRIVATE\s+KEY-----|$)))`)},
	{Pattern: Pattern{"pgp_private_key", Critical, Block}, need: "-----BEGIN",
		re: re(`-----BEGIN(?s:\s+PGP\s+PRIVATE\s+KEY\s+BLOCK-----.*?(?:-----END\s+PGP\s+PRIVATE\s+KEY\s+BLOCK-----|$))`)},
	{Pattern: Pattern{"google_api_key", High, Block}, need: "AIza",
		re: re(`AIza[0-9A-Za-z_-]{35}`)},
	{Pattern: Pattern{"slack_token", High, Block}, need: "xox",
		re: re(`xox[baprs]-[0-9a-zA-Z-]{10,}`)},
	{Pattern: Pattern{"twilio_api_key", High, Block}, need: "SK",
		re: re(`SK[a-fA-F0-9]{32}`)},
	{Pattern: Pattern{"sendgrid_api_key", High, Block}, need: "SG.",
		re: re(`SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}`)},
	// The regex finds the three-segment shape; the header check (hasJWTHeader) keeps dotted package names out.
	{Pattern: Pattern{"bare_jwt", High, RedactMatch}, jwt: true, within: set(alnum + "_-."), run: jwtRun,
		re: re(`\b[a-zA-Z0-9_-]{4,}\.[a-zA-Z0-9_-]{8,}\.[a-zA-Z0-9_-]{8,}`)},
	// RFC 6750 token68 alphabet plus padding, so no credential suffix survives redaction.
	{Pattern: Pattern{"bearer_token", High, RedactMatch}, need: "Bearer",
		re: re(`Bearer\s+[a-zA-Z0-9._~+/-]{20,}=*`)},
	{Pattern: Pattern{"auth_header", High, RedactMatch}, pre: hasAuthorization,
		re: re(`(?i)authorization:\s*[a-zA-Z]+\s+[a-zA-Z0-9._~+/-]{20,}=*`)},
	{Pattern: Pattern{"openrouter_api_key", Critical, Block}, need: "sk-or-v1-",
		re: re(`\bsk-or-v1-[a-fA-F0-9]{40,}`)},
	{Pattern: Pattern{"anthropic_oauth_token", Critical, Block}, need: "sk-ant-oat",
		re: re(`\bsk-ant-oat\d{2}-[a-zA-Z0-9_-]{50,}`)},
	{Pattern: Pattern{"telegram_bot_token", Critical, Block}, need: ":AA",
		re: re(`\b\d{8,12}:AA[A-Za-z0-9_-]{30,}`)},
	{Pattern: Pattern{"groq_api_key", Critical, Block}, need: "gsk_",
		re: re(`\bgsk_[A-Za-z0-9]{30,}`)},
	// 64 hex characters: often a secret, but just as often a SHA-256 digest. Warn only, never redacted.
	// 40-hex git SHAs don't match (exactly 64, with word boundaries).
	{Pattern: Pattern{"high_entropy_hex", Medium, Warn}, within: set(alnum + "_"), run: hexRun,
		re: re(`\b[a-fA-F0-9]{64}\b`)},
	// Ours (not upstream): a vault placeholder such as {{TAVILY_API_KEY}}.
	// Not a secret, so warn only: it is a signal when the brain puts one into an action's arguments. Responses
	// carry them legitimately after exact-value redaction.
	{Pattern: Pattern{"tacy_placeholder", Medium, Warn}, need: "{{",
		re: re(`\{\{[A-Z][A-Z0-9_]{2,63}\}\}`)},

	// Ours (not upstream, VM release 2): siblings of the families above that upstream doesn't cover. Each has a
	// fixed prefix, so ordinary text doesn't match.
	//
	// Temporary (STS) AWS access key ids, the same shape as aws_access_key's long-term AKIA ids. Like that one,
	// no word boundary on either side (a key glued to other text is still caught); a 16-character all-caps run
	// after the word "ASIA" (ASIAPACIFICREGIONS...) also matches, which is rare and fails safe.
	{Pattern: Pattern{"aws_temp_access_key", Critical, Block}, need: "ASIA",
		re: re(`ASIA[0-9A-Z]{16}`)},
	// OpenAI service-account and admin keys: the hyphen after the kind keeps openai_api_key from matching them.
	{Pattern: Pattern{"openai_service_key", Critical, Block}, need: "sk-",
		re: re(`\bsk-(?:svcacct|admin)-[A-Za-z0-9_-]{20,}`)},
	{Pattern: Pattern{"anthropic_admin_key", Critical, Block}, need: "sk-ant-admin",
		re: re(`\bsk-ant-admin\d{2}-[a-zA-Z0-9_-]{50,}`)},
	// Stripe restricted keys and webhook signing secrets, next to stripe_api_key's secret keys.
	{Pattern: Pattern{"stripe_restricted_key", Critical, Block}, need: "rk_",
		re: re(`\brk_(?:live|test)_[a-zA-Z0-9]{24,}`)},
	{Pattern: Pattern{"stripe_webhook_secret", High, Block}, need: "whsec_",
		re: re(`\bwhsec_[a-zA-Z0-9+/]{32,}`)},
	// Slack app-level tokens and token-rotation refresh tokens; slack_token covers xoxb/xoxa/xoxp/xoxr/xoxs.
	{Pattern: Pattern{"slack_app_token", High, Block}, need: "xapp-",
		re: re(`\bxapp-\d-[0-9a-zA-Z-]{20,}`)},
	{Pattern: Pattern{"slack_refresh_token", High, Block}, need: "xoxe-",
		re: re(`\bxoxe-\d-[0-9a-zA-Z-]{20,}`)},
	// GitLab personal access tokens, next to github_token.
	{Pattern: Pattern{"gitlab_token", Critical, Block}, need: "glpat-",
		re: re(`\bglpat-[A-Za-z0-9_-]{20,}`)},
	// Google OAuth client secrets and access tokens, next to google_api_key.
	{Pattern: Pattern{"google_oauth_client_secret", High, Block}, need: "GOCSPX-",
		re: re(`\bGOCSPX-[A-Za-z0-9_-]{24,}`)},
	{Pattern: Pattern{"google_oauth_token", High, Block}, need: "ya29.",
		re: re(`\bya29\.[0-9A-Za-z_-]{20,}`)},
}

func re(p string) *regexp.Regexp { return regexp.MustCompile(strings.ReplaceAll(p, `\s`, ws)) }

// Patterns lists the detectors in the order they run.
func Patterns() []Pattern {
	out := make([]Pattern, len(patterns))
	for i, p := range patterns {
		out[i] = p.Pattern
	}
	return out
}

// maxJWTCandidate is upstream's MAX_BARE_JWT_CANDIDATE_LEN: a longer three-segment candidate counts as a JWT
// without decoding anything (fail closed, no attacker-sized allocation).
const maxJWTCandidate = 64 << 10

// hasJWTHeader reports whether candidate's first of exactly three segments is unpadded base64url of a JSON
// object with a string "alg" (upstream has_json_web_token_header).
func hasJWTHeader(candidate []byte) bool {
	if len(candidate) > maxJWTCandidate {
		return true
	}
	parts := strings.Split(string(candidate), ".")
	if len(parts) != 3 {
		return false
	}
	h, ok := decodeBase64URLNoPad(parts[0])
	if !ok {
		return false
	}
	var obj map[string]any
	if json.Unmarshal(h, &obj) != nil {
		return false
	}
	_, ok = obj["alg"].(string)
	return ok
}

// decodeBase64URLNoPad is upstream's strict decoder: url alphabet, no padding, no leftover bits.
func decodeBase64URLNoPad(s string) ([]byte, bool) {
	if s == "" || len(s)%4 == 1 {
		return nil, false
	}
	out := make([]byte, 0, len(s)*3/4)
	var acc uint32
	var bits uint
	for i := 0; i < len(s); i++ {
		c := s[i]
		var v byte
		switch {
		case c >= 'A' && c <= 'Z':
			v = c - 'A'
		case c >= 'a' && c <= 'z':
			v = c - 'a' + 26
		case c >= '0' && c <= '9':
			v = c - '0' + 52
		case c == '-':
			v = 62
		case c == '_':
			v = 63
		default:
			return nil, false
		}
		acc = acc<<6 | uint32(v)
		bits += 6
		if bits >= 8 {
			bits -= 8
			out = append(out, byte(acc>>bits))
			acc &= 1<<bits - 1
		}
	}
	if acc != 0 {
		return nil, false
	}
	return out, true
}
