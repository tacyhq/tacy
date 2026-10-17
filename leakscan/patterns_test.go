package leakscan

import (
	"fmt"
	"slices"
	"strings"
	"testing"
)

// Test values only. Nothing here is a real credential: keys are built from obvious filler (repeated letters,
// counting digits, AWS's documented example id), and split with j() so no scanner reads a whole key in the source.
func j(parts ...string) string { return strings.Join(parts, "") }

var (
	fakeAWS        = j("AKIA", "IOSFODNN7EXAMPLE")
	fakeGitHub     = j("ghp", "_", strings.Repeat("x", 36))
	fakeOpenAI     = j("sk-", "proj-", "abc123def456ghi789jkl012mno345pqr", "T3BlbkFJ", "test123")
	fakeAnthropic  = j("sk-ant-", "api", strings.Repeat("a", 90))
	fakeStripe     = j("sk_", "live", "_", "aAbBcCdDfFgGhHjJkKmMnNpPqQ")
	fakeFineGrain  = j("github_", "pat_", strings.Repeat("A", 22), "_", strings.Repeat("b", 59))
	fakeGoogle     = j("AI", "za", strings.Repeat("F", 35))
	fakeSlack      = j("xo", "xb-", "1234567890-abcdefghij")
	fakeTwilio     = j("S", "K", strings.Repeat("0123456789abcdef", 2))
	fakeSendGrid   = j("SG", ".", strings.Repeat("a", 22), ".", strings.Repeat("b", 43))
	fakeJWT        = j("eyJhbGciOiJIUzI1NiJ9", ".", "eyJzdWIiOiIxMjM0NTY3ODkwIn0", ".", "signature123")
	fakeOpenRouter = j("sk-or-", "v1-", strings.Repeat("00112233445566778899aabbccddeeff", 2))
	fakeAnthOAuth  = j("sk-ant-", "oat01-", strings.Repeat("aaaBBBccc0", 9))
	fakeTelegram   = j("12345678901", ":AA", "HdqTcvCH1vGWJxfSeofSAs0K5PALDsaw")
	fakeGroq       = j("gs", "k_", strings.Repeat("aaaBBBccc0", 5))
	fakeHex64      = strings.Repeat("0123456789abcdef", 4)
	fakeBearer     = j("Bearer ", "abcdefghijklmnopqrstuvwxyz123456")
	fakeAuthHeader = j("Authorization: ", "Basic ", "QUFBQUFBQUFBQUFBQUFBQUFBQUE=")

	// Ours (VM release 2).
	fakeAWSTemp       = j("ASIA", "IOSFODNN7EXAMPLE")
	fakeOpenAISvc     = j("sk-", "svcacct-", strings.Repeat("aB3_", 6))
	fakeOpenAIAdmin   = j("sk-", "admin-", strings.Repeat("aB3-", 6))
	fakeAnthAdmin     = j("sk-ant-", "admin01-", strings.Repeat("aaaBBBccc0", 6))
	fakeStripeRK      = j("rk_", "live", "_", "aAbBcCdDfFgGhHjJkKmMnNpPqQ")
	fakeStripeWebhook = j("wh", "sec_", strings.Repeat("aB3+", 8))
	fakeSlackApp      = j("xa", "pp-1-", "A0123456789-1234567890123-", strings.Repeat("0a", 16))
	fakeSlackRefresh  = j("xo", "xe-1-", strings.Repeat("AbC0", 8))
	fakeGitLab        = j("gl", "pat-", strings.Repeat("xY_9", 5))
	fakeGoogleSecret  = j("GOC", "SPX-", strings.Repeat("aB3_", 7))
	fakeGoogleToken   = j("ya", "29.", "a0Af", strings.Repeat("xY_9", 6))
)

func pem(label, body string) string {
	return "-----BEGIN " + label + "-----\n" + body + "\n-----END " + label + "-----"
}

func ids(fs []Finding) []string {
	var out []string
	for _, f := range fs {
		out = append(out, f.Pattern)
	}
	return out
}

func has(fs []Finding, id string) bool { return slices.Contains(ids(fs), id) }

func TestPatternList(t *testing.T) {
	ps := Patterns()
	if len(ps) != 32 {
		t.Fatalf("%d patterns, want 32 (21 upstream + tacy_placeholder + 10 siblings)", len(ps))
	}
	seen := map[string]bool{}
	for _, p := range ps {
		if seen[p.ID] {
			t.Fatalf("duplicate id %s", p.ID)
		}
		seen[p.ID] = true
	}
	for _, gone := range []string{"nearai_session", "sandbox_credential_placeholder"} {
		if seen[gone] {
			t.Fatalf("%s should not be ported (docs/21)", gone)
		}
	}
}

// One positive per pattern, plus severity and action as upstream has them.
func TestPatternsPositive(t *testing.T) {
	cases := []struct {
		id, in string
		sev    Severity
		act    Action
	}{
		{"openai_api_key", "API key: " + fakeOpenAI, Critical, Block},
		{"anthropic_api_key", "Here's the key: " + fakeAnthropic, Critical, Block},
		{"aws_access_key", "AWS_ACCESS_KEY_ID=" + fakeAWS, Critical, Block},
		{"github_token", "token: " + fakeGitHub, Critical, Block},
		{"github_token", "bad credentials " + j("ghp", "_fake_fixture_token") + " (HTTP 403)", Critical, Block},
		{"github_fine_grained_pat", "pat " + fakeFineGrain, Critical, Block},
		{"stripe_api_key", fakeStripe, Critical, Block},
		{"pem_private_key", pem("RSA PRIVATE KEY", "MIIEowIBAAKCAQEA"), Critical, Block},
		{"pem_private_key", pem("PRIVATE KEY", "MIIEvQIBADANBg"), Critical, Block},
		{"pem_private_key", pem("ENCRYPTED PRIVATE KEY", "MIIFHDBOBgkq"), Critical, Block},
		{"ssh_private_key", "-----BEGIN OPENSSH PRIVATE KEY-----\nbase64data==", Critical, Block},
		{"ssh_private_key", pem("EC PRIVATE KEY", "MHcCAQEE"), Critical, Block},
		{"ssh_private_key", pem("DSA PRIVATE KEY", "MIIBuwIBAAKBgQ"), Critical, Block},
		{"pgp_private_key", pem("PGP PRIVATE KEY BLOCK", "lQOYBF"), Critical, Block},
		{"google_api_key", "key=" + fakeGoogle, High, Block},
		{"slack_token", fakeSlack, High, Block},
		{"twilio_api_key", "twilio " + fakeTwilio, High, Block},
		{"sendgrid_api_key", fakeSendGrid, High, Block},
		{"bare_jwt", fakeJWT, High, RedactMatch},
		// Header ` {"alg":"HS256"}`: JSON allows leading whitespace, so the check can't rely on "eyJ".
		{"bare_jwt", j("IHsiYWxnIjoiSFMyNTYifQ", ".eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature123"), High, RedactMatch},
		{"bearer_token", "token: " + fakeBearer, High, RedactMatch},
		{"auth_header", fakeAuthHeader, High, RedactMatch},
		{"auth_header", "AUTHORIZATION: token " + strings.Repeat("z", 24), High, RedactMatch},
		{"openrouter_api_key", "LLM_API_KEY=" + fakeOpenRouter, Critical, Block},
		{"openrouter_api_key", `{"api_key": "` + fakeOpenRouter + `"}`, Critical, Block},
		{"anthropic_oauth_token", "token=" + fakeAnthOAuth, Critical, Block},
		{"telegram_bot_token", "TELEGRAM_BOT_TOKEN=" + fakeTelegram, Critical, Block},
		{"groq_api_key", "GROQ_API_KEY=" + fakeGroq, Critical, Block},
		{"high_entropy_hex", "digest " + fakeHex64, Medium, Warn},
		{"tacy_placeholder", "Authorization: {{TAVILY_API_KEY}}", Medium, Warn},
		{"aws_temp_access_key", "AWS_ACCESS_KEY_ID=" + fakeAWSTemp, Critical, Block},
		{"aws_temp_access_key", `{"AccessKeyId":"` + fakeAWSTemp + `","SessionToken":"x"}`, Critical, Block},
		{"openai_service_key", "OPENAI_API_KEY=" + fakeOpenAISvc, Critical, Block},
		{"openai_service_key", "admin " + fakeOpenAIAdmin, Critical, Block},
		{"anthropic_admin_key", "key " + fakeAnthAdmin, Critical, Block},
		{"stripe_restricted_key", "STRIPE_KEY=" + fakeStripeRK, Critical, Block},
		{"stripe_webhook_secret", "STRIPE_WEBHOOK_SECRET=" + fakeStripeWebhook, High, Block},
		{"slack_app_token", "SLACK_APP_TOKEN=" + fakeSlackApp, High, Block},
		{"slack_refresh_token", "refresh " + fakeSlackRefresh, High, Block},
		{"gitlab_token", "GITLAB_TOKEN=" + fakeGitLab, Critical, Block},
		{"google_oauth_client_secret", `"client_secret":"` + fakeGoogleSecret + `"`, High, Block},
		{"google_oauth_token", "access_token=" + fakeGoogleToken, High, Block},
	}
	for _, c := range cases {
		fs := Scan([]byte(c.in))
		var hit *Finding
		for i := range fs {
			if fs[i].Pattern == c.id {
				hit = &fs[i]
			}
		}
		if hit == nil {
			t.Errorf("%s: not found in %q (got %v)", c.id, c.in, ids(fs))
			continue
		}
		if hit.Severity != c.sev || hit.Action != c.act || hit.Via != "" {
			t.Errorf("%s: %+v", c.id, *hit)
		}
		if hit.Offset < 0 || hit.End > len(c.in) || hit.Offset >= hit.End {
			t.Errorf("%s: bad span %d..%d", c.id, hit.Offset, hit.End)
		}
	}
}

// One or more near misses per pattern: too short, wrong prefix, or a lookalike shape.
func TestPatternsNegative(t *testing.T) {
	cases := []struct{ id, in string }{
		{"openai_api_key", "sk-this-is-too-short"},
		{"openai_api_key", "sk-" + strings.Repeat("a", 19)},
		{"anthropic_api_key", "sk-ant-api" + strings.Repeat("a", 89)},
		{"aws_access_key", "AKIA12345678"},
		{"aws_access_key", "AKIA" + strings.Repeat("a", 16)}, // lowercase
		{"github_token", j("ghp", "_", strings.Repeat("x", 15))},
		{"github_token", j("ghx", "_", strings.Repeat("x", 36))},
		{"github_fine_grained_pat", j("github_", "pat_", strings.Repeat("A", 21), "_", strings.Repeat("b", 59))},
		{"stripe_api_key", j("sk_", "live_", "short12345")},
		{"stripe_api_key", j("sk_", "prod_", strings.Repeat("a", 30))},
		{"pem_private_key", pem("RSA PUBLIC KEY", "PUBLIC_MATERIAL")},
		{"pem_private_key", pem("CERTIFICATE", "MIIC")},
		{"ssh_private_key", pem("OPENSSH PUBLIC KEY", "PUBLIC_MATERIAL")},
		{"pgp_private_key", pem("PGP PUBLIC KEY BLOCK", "mQINBF")},
		{"google_api_key", "AIza_short12345"},
		{"slack_token", "xoxb-short"},
		{"slack_token", "xoxz-1234567890-abcdefghij"},
		{"twilio_api_key", "SKabcdef1234567"},
		{"twilio_api_key", "SK" + strings.Repeat("g", 32)},
		{"sendgrid_api_key", "SG.short12345"},
		{"bare_jwt", "com.fasterxml.jackson"},
		{"bare_jwt", "org.springframework.integration.transformer"},
		{"bare_jwt", "abcd.efghijklmnop.qrstuvwxyz"}, // header isn't base64 JSON
		{"bearer_token", "Bearer authentication is required"},
		{"bearer_token", "Bearer shorttoken123"},
		{"auth_header", "authorization: Bearer short12345"},
		{"openrouter_api_key", "sk-or-v1-abc123"},
		{"openrouter_api_key", "xsk-or-v1-" + strings.Repeat("ab", 20)}, // no word boundary
		{"anthropic_oauth_token", "sk-ant-oat1-" + strings.Repeat("a", 60)},
		{"telegram_bot_token", "123:AAFoo"},
		{"telegram_bot_token", "1234567:AA" + strings.Repeat("b", 30)},
		{"groq_api_key", "gsk_abc"},
		{"groq_api_key", "xgsk_" + strings.Repeat("a", 30)},
		{"high_entropy_hex", strings.Repeat("a", 63)},
		{"high_entropy_hex", strings.Repeat("a", 65)},
		{"high_entropy_hex", "da39a3ee5e6b4b0d3255bfef95601890afd80709"}, // 40-hex git SHA
		{"tacy_placeholder", "{{x}} and {{ name }} and {{AB}}"},
		{"aws_temp_access_key", "ASIA12345678"},
		{"aws_temp_access_key", "ASIA" + strings.Repeat("a", 16)}, // lowercase
		{"aws_temp_access_key", "Asia" + strings.Repeat("A", 16)},
		{"aws_temp_access_key", "SOUTHEAST ASIA PACIFIC REGION, EURASIA, ASIAN MARKETS, ASIA-PACIFIC 2026"},
		{"openai_service_key", j("sk-", "svcacct-", "short")},
		{"openai_service_key", j("sk-", "service-", strings.Repeat("a", 30))},
		{"anthropic_admin_key", j("sk-ant-", "admin1-", strings.Repeat("a", 60))},
		{"anthropic_admin_key", j("sk-ant-", "admin01-", strings.Repeat("a", 49))},
		{"stripe_restricted_key", j("rk_", "live_", "short12345")},
		{"stripe_restricted_key", j("work_", "live_", strings.Repeat("a", 30))}, // no word boundary
		{"stripe_webhook_secret", j("wh", "sec_", strings.Repeat("a", 31))},
		{"slack_app_token", j("xa", "pp-", "short")},
		{"slack_app_token", j("xa", "pp-x-", strings.Repeat("a", 30))},
		{"slack_refresh_token", j("xo", "xe-1-", "short")},
		{"gitlab_token", j("gl", "pat-", "short")},
		{"gitlab_token", j("xgl", "pat-", strings.Repeat("a", 30))},
		{"google_oauth_client_secret", j("GOC", "SPX-", "short")},
		{"google_oauth_client_secret", j("goc", "spx-", strings.Repeat("a", 30))},
		{"google_oauth_token", j("ya", "29.", "short")},
		{"google_oauth_token", j("ya", "30.", strings.Repeat("a", 30))},
	}
	for _, c := range cases {
		if fs := Scan([]byte(c.in)); has(fs, c.id) {
			t.Errorf("%s: false positive on %q", c.id, c.in)
		}
	}
}

// Upstream: redaction removes the complete block for every delimiter pair, and the context survives.
func TestPrivateKeyBlocks(t *testing.T) {
	labels := []string{"RSA PRIVATE KEY", "PRIVATE KEY", "ENCRYPTED PRIVATE KEY", "PGP PRIVATE KEY BLOCK",
		"OPENSSH PRIVATE KEY", "EC PRIVATE KEY", "DSA PRIVATE KEY"}
	for _, l := range labels {
		in := "before\n" + pem(l, "TEST_PRIVATE_KEY_MATERIAL") + "\nafter"
		if got := string(Redact([]byte(in), nil)); got != "before\n[REDACTED]\nafter" {
			t.Errorf("%s: %q", l, got)
		}
		// Unterminated: the bounded remainder goes.
		in = "before\n-----BEGIN " + l + "-----\nTEST_PRIVATE_KEY_MATERIAL"
		if got := string(Redact([]byte(in), nil)); got != "before\n[REDACTED]" {
			t.Errorf("%s unterminated: %q", l, got)
		}
		// A no-break space between the words still counts (Rust's \s is Unicode).
		in = "-----BEGIN " + strings.ReplaceAll(l, " ", "\u00a0") + "-----\nX"
		if !Blocked(Scan([]byte(in))) {
			t.Errorf("%s with NBSP not blocked", l)
		}
	}
	mismatched := [][2]string{{"RSA PRIVATE KEY", "PRIVATE KEY"}, {"PRIVATE KEY", "RSA PRIVATE KEY"},
		{"ENCRYPTED PRIVATE KEY", "PRIVATE KEY"}, {"PGP PRIVATE KEY BLOCK", "PGP PUBLIC KEY BLOCK"},
		{"OPENSSH PRIVATE KEY", "EC PRIVATE KEY"}, {"EC PRIVATE KEY", "DSA PRIVATE KEY"},
		{"DSA PRIVATE KEY", "EC PRIVATE KEY"}}
	for _, m := range mismatched {
		in := "before\n-----BEGIN " + m[0] + "-----\nFIRST\n-----END " + m[1] + "-----\nTRAILING_FRAGMENT"
		if got := string(Redact([]byte(in), nil)); got != "before\n[REDACTED]" {
			t.Errorf("%v: %q", m, got)
		}
	}
	// Multibyte text around a key.
	if !has(Scan([]byte("中文内容\n-----BEGIN RSA PRIVATE KEY-----\ndata\n中文结尾")), "pem_private_key") {
		t.Error("PEM between multibyte text")
	}
}

// Upstream's bearer and JWT redaction vectors: nothing of the token survives, the text around it does.
func TestRedactTokens(t *testing.T) {
	jwtHeader, payload, sig := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", strings.Repeat("a", 32), strings.Repeat("b", 32)
	cases := []struct{ in, want string }{
		{"token: Bearer " + jwtHeader + "." + payload + "." + sig, "token: [REDACTED]"},
		{"prefix Bearer abcdef1234567890123456. The next sentence.", "prefix [REDACTED] The next sentence."},
		{"token=Bearer opaquePrefix1234567890.middle.segment.value.opaqueSuffix0987654321; after token",
			"token=[REDACTED]; after token"},
		{"token=Bearer AAAAAAAAAAAAAAAAAAAA~+/==; retained", "token=[REDACTED]; retained"},
		{"Authorization: Basic AAAAAAAAAAAAAAAAAAAA~+/==; retained", "[REDACTED]; retained"},
		{"Authorization: Bearer abcdefghijklmnopqrstuvwxyz123456", "[REDACTED]"},
		{fakeJWT, "[REDACTED]"},
		{fakeJWT[:len(fakeJWT)-1] + "-", "[REDACTED]"},
		{fakeTelegram[:len(fakeTelegram)-1] + "-", "[REDACTED]"},
		{"auth failed at /workspace/config using " + fakeGitHub + " and " + fakeAWS + " (HTTP 401)",
			"auth failed at /workspace/config using [REDACTED] and [REDACTED] (HTTP 401)"},
		{"read_file failed at /workspace/x (HTTP 404)", "read_file failed at /workspace/x (HTTP 404)"},
	}
	for _, c := range cases {
		if got := string(Redact([]byte(c.in), nil)); got != c.want {
			t.Errorf("Redact(%q)\n got %q\nwant %q", c.in, got, c.want)
		}
	}
	// Oversized three-segment candidate: counts as a JWT without decoding (fail closed).
	big := strings.Repeat("A", maxJWTCandidate+1) + ".payload12.signature12-"
	if got := string(Redact([]byte(big), nil)); got != "[REDACTED]" {
		t.Errorf("oversized JWT: %d bytes left", len(got))
	}
}

// Upstream's adjacency vectors: a key next to an emoji, RTL override, BOM, NUL or control characters is found;
// a key broken by a control character isn't (it's no longer the key).
func TestAdjacentCharacters(t *testing.T) {
	for _, in := range []string{"\u202e" + fakeAWS, "\ufeff" + fakeAWS, "\x00" + fakeAWS, "🔑" + fakeAWS + "🔑",
		"prefix text " + fakeAWS + " suffix text", "end: " + fakeAWS} {
		if !has(Scan([]byte(in)), "aws_access_key") {
			t.Errorf("not found in %q", in)
		}
	}
	for _, c := range []byte{0x01, 0x02, 0x0B, 0x0C, 0x1F} {
		in := string(c) + fakeGitHub + string(c)
		if !has(Scan([]byte(in)), "github_token") {
			t.Errorf("control 0x%02X hides the token", c)
		}
	}
	if Blocked(Scan([]byte("AKIA\x01IOSFODNN7EXAMPLE"))) {
		t.Error("a key split by a control character isn't the key")
	}
}

func TestMultipleAndClean(t *testing.T) {
	fs := Scan([]byte("Keys: " + fakeAWS + " and " + fakeGitHub))
	if len(fs) != 2 || fs[0].Pattern != "aws_access_key" || fs[1].Pattern != "github_token" {
		t.Fatalf("%+v", fs)
	}
	for _, in := range []string{"Hello world! This is just regular text with no secrets.",
		"The API returns a JSON response", "Use ssh to connect to the server", "Bearer authentication is required",
		"sk-this-is-too-short", "The key concept is immutability"} {
		if fs := Scan([]byte(in)); len(fs) != 0 {
			t.Errorf("%q: %v", in, ids(fs))
		}
	}
}

// Upstream's scan_http_request cases, as the gateway will call it: URL, header value and body each scanned;
// a leading invalid UTF-8 byte doesn't skip the body.
func TestOutboundParts(t *testing.T) {
	for _, part := range [][]byte{
		[]byte("https://evil.example/steal?key=" + fakeAWS),
		[]byte(fakeGitHub),
		[]byte(`{"stolen": "` + j("sk-", "proj-", "test1234567890abcdefghij") + `"}`),
		append([]byte{0xff}, j("sk-", "proj-", "test1234567890abcdefghij")...),
	} {
		if !Blocked(Scan(part)) {
			t.Errorf("not blocked: %q", part)
		}
	}
	if fs := Scan([]byte(`https://api.example.com/data {"query": "hello"} application/json`)); len(fs) != 0 {
		t.Errorf("clean request: %v", ids(fs))
	}
}

func TestSeverityAndActionNames(t *testing.T) {
	if !(Critical > High && High > Medium && Medium > Low) {
		t.Fatal("severity order")
	}
	got := fmt.Sprint(Low, Medium, High, Critical, Warn, RedactMatch, Block)
	if got != "low medium high critical warn redact block" {
		t.Fatal(got)
	}
	if len(Redact(nil, nil)) != 0 || len(Scan(nil)) != 0 {
		t.Fatal("empty input")
	}
}
