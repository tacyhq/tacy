package leakscan

import (
	"bytes"
	"encoding/base64"
	"math/rand/v2"
	"strings"
	"testing"
)

// Ordinary content must pass untouched: nothing blocked, nothing redacted. The decoders run on all of it (HTML
// entities, JSON escapes, percent-encoded queries, base64 images), so this also checks they don't invent keys.
//
// Decisions:
//   - 40-hex git SHAs are not flagged. They are public ids all over code, URLs and logs; no default pattern
//     matches them (high_entropy_hex is exactly 64 with word boundaries).
//   - 64-hex strings (SHA-256 digests, also some secrets) are a Warn finding: recorded, never blocked or
//     redacted.
//   - UUIDs are not flagged.
//   - Decoded base64 that doesn't read as text (images, the garbage a long word or a path decodes to) isn't
//     scanned.
func TestFalsePositives(t *testing.T) {
	rng := rand.New(rand.NewPCG(1, 2))
	img := make([]byte, 6000)
	for i := range img {
		img[i] = byte(rng.Uint32())
	}
	samples := map[string]string{
		"prose": "The quick brown fox jumps over the lazy dog. Internationalization and counterrevolutionaries " +
			"are long words; so is pneumonoultramicroscopicsilicovolcanoconiosis. Bearer bonds are bonds. " +
			"Authorization is required to continue. Ask Skyler about the SK-5 model.",
		"go code": "package main\n\nimport \"fmt\"\n\nfunc main() {\n\tm := map[string]int{\"a\": 1}\n" +
			"\tfmt.Printf(\"%v\\n\", m)\n\tskip := \"sk-\" + name // build\n\tvar ghp_ = 3\n}\n",
		"json": `{"id":"550e8400-e29b-41d4-a716-446655440000","name":"Ünïcödé \"quoted\" \/ \u00e9",` +
			`"path":"C:\\Users\\me\\file.txt","list":[1,2,3],"nested":{"k":"v\n"}}`,
		"urls": "https://www.example.com/search?q=hello+world%21&lang=en-US&page=2 " +
			"https://github.com/golang/go/commit/da39a3ee5e6b4b0d3255bfef95601890afd80709 " +
			"https://en.wikipedia.org/wiki/Base64#Examples /usr/local/lib/python3.12/site-packages/requests/api.py",
		"uuids": "550e8400-e29b-41d4-a716-446655440000 6ba7b810-9dad-11d1-80b4-00c04fd430c8 " +
			"{F47AC10B-58CC-4372-A567-0E02B2C3D479} 550e8400e29b41d4a716446655440000",
		"git shas": "commit da39a3ee5e6b4b0d3255bfef95601890afd80709\nMerge: 2fd4e1c 67d8b5e\n" +
			"Revert \"x\" (2fd4e1c67a2d28fced849ee1bb76e7391b93eb12)",
		"html": `<p>Tom &amp; Jerry &lt;3 &quot;cheese&quot; &mdash; &#169; 2026 &nbsp;<a href="/a?b=1&amp;c=2">` +
			`link</a> &copy; caf&eacute; &#x1F600;</p>`,
		"emails and dotted names": "alice@example.com bob.smith@mail.example.org com.fasterxml.jackson.databind " +
			"org.springframework.boot.autoconfigure v1.2.3-beta.4 a.b.c",
		"data uri":     "<img src=\"data:image/png;base64," + base64.StdEncoding.EncodeToString(img) + "\">",
		"markdown":     "# Title\n\n- item `code` **bold** _it_\n\n```sh\ncurl -H 'Accept: application/json' https://api.example.com\n```\n",
		"unicode":      "日本語のテキスト。Привет, мир! Γειά σου Κόσμε. 🔑🔐 مرحبا",
		"escaped text": `line one\nline two\ttabbed \u00e9\u00e8 \x41\x42 \/path`,
		"base64 text":  base64.StdEncoding.EncodeToString([]byte("just an ordinary sentence, nothing to see here")),
		"numbers":      "1234567890:AAAA 12345678:AA short 3.14159265358979 +1 (555) 010-0199",
	}
	for name, s := range samples {
		fs := Scan([]byte(s))
		for _, f := range fs {
			if f.Action != Warn {
				t.Errorf("%s: %s at %d..%d (via %q) in %q", name, f.Pattern, f.Offset, f.End, f.Via, s[f.Offset:f.End])
			}
		}
		if out := Redact([]byte(s), nil); !bytes.Equal(out, []byte(s)) {
			t.Errorf("%s: Redact changed clean text", name)
		}
	}
	// A SHA-256 digest: warned, kept.
	sha := "269cc57b4d0c4368d8b02738ab709c810adb6212729b24bbdc34efb539a3ed07"
	fs := Scan([]byte("sha256:" + sha))
	if len(fs) != 1 || fs[0].Pattern != "high_entropy_hex" || fs[0].Action != Warn || Blocked(fs) {
		t.Fatalf("%+v", fs)
	}
	if out := string(Redact([]byte("sha256:"+sha), nil)); !strings.Contains(out, sha) {
		t.Fatal("digest redacted")
	}
}
