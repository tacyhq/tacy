package leakscan

import (
	"encoding/base64"
	"net/url"
	"strings"
	"testing"
	"time"
)

// budget is generous so the race detector and slow CI machines pass; the point is linear, not fast. Upstream
// allows 2 s for 100 KB; these inputs are 1 MiB (256 KiB with -short).
const budget = 10 * time.Second

func size(t *testing.T) int {
	if testing.Short() {
		return 256 << 10
	}
	return 1 << 20
}

func fill(chunk string, n int) []byte {
	return []byte(strings.Repeat(chunk, n/len(chunk)+1)[:n])
}

func timed(t *testing.T, name string, f func()) {
	t.Helper()
	start := time.Now()
	f()
	d := time.Since(start)
	if testing.Verbose() {
		t.Logf("%-28s %v", name, d)
	}
	if d > budget {
		t.Errorf("%s took %v", name, d)
	}
}

// Upstream's ReDoS near misses, plus decoder bombs: everything finishes in time and within the work budget.
func TestAdversarialInputs(t *testing.T) {
	n := size(t)
	inputs := map[string][]byte{
		"openai near miss":   fill("sk-abcdefghij1234567 ", n),
		"hex near miss":      fill(strings.Repeat("a", 63)+" ", n),
		"bearer near miss":   fill("Bearer shorttoken123 ", n),
		"auth near miss":     fill("authorization: Bearer short12345 ", n),
		"anthropic miss":     fill("sk-ant-api-shortkey12345 ", n),
		"aws near miss":      fill("AKIA12345678 ", n),
		"github near miss":   fill("ghp_shorttoken12345 ", n),
		"fine-grained miss":  fill("github_pat_shortval12 ", n),
		"stripe near miss":   fill("sk_live_short12345 ", n),
		"pem near miss":      fill("-----BEGIN RSA PUBLIC KEY-----\n", n),
		"ssh near miss":      fill("-----BEGIN OPENSSH PUBLIC KEY-----\n", n),
		"pgp near miss":      fill("-----BEGIN PGP PUBLIC KEY BLOCK-----\n", n),
		"pem unterminated":   fill("-----BEGIN RSA PRIVATE KEY-----\n", n),
		"google near miss":   fill("AIza_short12345 ", n),
		"slack near miss":    fill("xoxb-short ", n),
		"twilio near miss":   fill("SKabcdef1234567 ", n),
		"sendgrid near miss": fill("SG.short12345 ", n),
		"jwt-ish dots":       fill("abcd.efghijklmnop.qrstuvwxyz.", n),
		"telegram-ish":       fill("123456789:AA", n),
		"clean text":         fill("The quick brown fox jumps over the lazy dog. ", n),
		"percent bomb":       fill("%25", n),
		"percent of all":     fill("%41", n),
		"html bomb":          fill("&amp;", n),
		"html numeric":       fill("&#65;", n),
		"unicode escapes":    fill(`A`, n),
		"backslashes":        fill(`\\`, n),
		"zero width":         fill("\u200b", n),
		"homoglyphs":         fill("\u0410", n),
		"one base64 run":     fill("QUFB", n),
		"base64 text":        []byte(base64.StdEncoding.EncodeToString(fill("text ", n*3/4))),
		"base64 of base64":   []byte(nest(fill("text ", n/4), 4)),
		"mixed layers":       fill("%26%2365%3B\\u0041&#x25;41"+base64.StdEncoding.EncodeToString([]byte("%41%41%41")), n),
		"many short runs":    fill("QUFBQUFBQUFBQUFBQUFB ", n),
		"many aws keys":      fill(fakeAWS+" ", n),
		"invalid utf8":       fill("\xff\xfe\xc3", n),
	}
	for name, in := range inputs {
		timed(t, name, func() {
			s := newScanner(len(in), nil, true)
			s.run(in)
			if s.work > s.budget {
				t.Errorf("%s: work %d over budget %d", name, s.work, s.budget)
			}
			if len(s.result()) > MaxFindings+1 {
				t.Errorf("%s: %d findings", name, len(s.found))
			}
		})
		timed(t, name+" (redact)", func() { Redact(in, [][]byte{[]byte("tvly-test-0123456789")}) })
	}
}

func nest(b []byte, k int) string {
	s := string(b)
	for i := 0; i < k; i++ {
		s = base64.StdEncoding.EncodeToString([]byte(s))
	}
	return s
}

// Ordinary large content (the kind of page web.fetch returns) stays well inside the work budget, so decoding is
// never cut short and Scan never fails closed on it.
func TestRealisticWithinBudget(t *testing.T) {
	var b strings.Builder
	img := make([]byte, 30000)
	for i := range img {
		img[i] = byte(i*7 + i/13)
	}
	for b.Len() < 2<<20 {
		b.WriteString(`<script>function initializeApplicationStateManagerFactory(configurationOptions){return x}</script>`)
		b.WriteString("sha256:269cc57b4d0c4368d8b02738ab709c810adb6212729b24bbdc34efb539a3ed07 id=550e8400e29b41d4a716446655440000\n")
		b.WriteString(`<a href="/search?q=caf%C3%A9+au+lait&amp;page=2">r&eacute;sum&eacute;</a> {"t":"line\nnext \u00e9"}`)
		b.WriteString(" /usr/local/share/applications/org.example.SomethingVeryLongName.desktop ")
		b.WriteString(`<img src="data:image/png;base64,` + base64.StdEncoding.EncodeToString(img[:1000+b.Len()%20000]) + `">`)
		b.WriteString(" commit da39a3ee5e6b4b0d3255bfef95601890afd80709 " + strings.Repeat("Internationalization ", 20) + "\n")
	}
	in := []byte(b.String())
	s := newScanner(len(in), nil, true)
	s.run(in)
	t.Logf("work %d for %d bytes", s.work, len(in))
	if s.limited || s.work > s.budget/2 {
		t.Fatalf("work %d of budget %d (limited=%v)", s.work, s.budget, s.limited)
	}
	if Blocked(s.result()) {
		t.Fatalf("%v", ids(s.found))
	}
}

// Work grows linearly: 4x the input takes nowhere near 16x the time.
func TestLinear(t *testing.T) {
	if testing.Short() {
		t.Skip("timing")
	}
	in := fill("%2541 &#65; \\u0041 QUtJQUlPU0ZPRE5ON0VYQU1QTEU= Bearer x sk-a ", 256<<10)
	t1 := minTime(func() { Scan(in) })
	t4 := minTime(func() { Scan(fill(string(in), 4*len(in))) })
	if t4 > 12*t1 {
		t.Fatalf("1x %v, 4x %v", t1, t4)
	}
}

func minTime(f func()) time.Duration {
	best := time.Duration(1 << 62)
	for i := 0; i < 3; i++ {
		s := time.Now()
		f()
		best = min(best, time.Since(s))
	}
	return best
}

// Past MaxInput, Scan reports scan_limit (Block), so an oversized outbound argument fails closed; Redact still
// removes keys anywhere, in windows.
func TestOverMaxInput(t *testing.T) {
	if testing.Short() {
		t.Skip("allocates ~20 MiB")
	}
	filler := fill("lorem ipsum dolor sit amet ", MaxInput)
	in := append([]byte(fakeAWS+" "), filler...)
	in = append(in, " AKIA%49OSFODNN7EXAMPLE "...)
	in = append(in, filler...)
	in = append(in, " "+fakeGitHub...)
	fs := Scan(in)
	if !has(fs, ScanLimit) || !Blocked(fs) {
		t.Fatalf("%v", ids(fs))
	}
	out := string(Redact(in, nil))
	if strings.Contains(out, "AKIA") || strings.Contains(out, "ghp_") || strings.Count(out, Replacement) != 3 {
		t.Fatalf("left a key: %d replacements", strings.Count(out, Replacement))
	}
	if len(out) != len(in)-len(fakeAWS)-len("AKIA%49OSFODNN7EXAMPLE")-len(fakeGitHub)+3*len(Replacement) {
		t.Fatal("redaction changed other bytes")
	}
}

// More findings than MaxFindings: the list stops with a scan_limit; Redact still removes all of them.
func TestManyFindings(t *testing.T) {
	in := []byte(strings.Repeat(fakeAWS+" ", 3*MaxFindings))
	fs := Scan(in)
	if len(fs) != MaxFindings+1 || !has(fs, ScanLimit) {
		t.Fatalf("%d findings", len(fs))
	}
	if out := string(Redact(in, nil)); strings.Contains(out, "AKIA") {
		t.Fatal("a key survived")
	}
}

// The work budget is what stops a decoding bomb: a fully percent-encoded, base64-wrapped, four-level input
// still decodes within WorkFactor and is found.
func TestWorkBudgetFindsNested(t *testing.T) {
	in := url.QueryEscape(base64.StdEncoding.EncodeToString([]byte(pctAll("id=" + fakeAWS))))
	s := newScanner(len(in), nil, true)
	s.run([]byte(in))
	if !has(s.result(), "aws_access_key") || s.limited {
		t.Fatalf("%v limited=%v", ids(s.found), s.limited)
	}
}

// go test -bench . ./leakscan/
func BenchmarkScan(b *testing.B) {
	for name, in := range map[string][]byte{
		"prose":  fill("The quick brown fox jumps over the lazy dog. ", 1<<20),
		"json":   fill(`{"title":"Café &amp; bar","url":"https://example.com/a?b=c%20d","id":"550e8400-e29b-41d4"}, `, 1<<20),
		"base64": []byte(base64.StdEncoding.EncodeToString(fill("text ", 3<<18))),
	} {
		b.Run(name, func(b *testing.B) {
			b.SetBytes(int64(len(in)))
			for b.Loop() {
				Scan(in)
			}
		})
	}
}
