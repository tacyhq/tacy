package leakscan

import (
	"bytes"
	"encoding/base64"
	"math/rand/v2"
	"net/url"
	"strings"
	"testing"
)

// streamAll writes in in chunks of the given sizes (cycled) and returns the joined output and findings.
func streamAll(in []byte, exact [][]byte, sizes []int) ([]byte, []Finding) {
	st := NewStream(exact)
	var out []byte
	for i, k := 0, 0; i < len(in); k++ {
		n := min(sizes[k%len(sizes)], len(in)-i)
		out = append(out, st.Write(in[i:i+n])...)
		i += n
	}
	out = append(out, st.Flush()...)
	return out, st.Findings()
}

// A secret split at every position across two chunks is still removed, raw or encoded.
func TestStreamSplitEverywhere(t *testing.T) {
	secret := []byte("tvly-test-not-a-real-key-0123456789")
	for _, mid := range []string{fakeAWS, "AKIA%49OSFODNN7EXAMPLE", "AKIA%2549OSFODNN7EXAMPLE", b64("id=" + fakeAWS),
		entAll(fakeAWS, false), uescAll(fakeAWS), pem("RSA PRIVATE KEY", "MIIEowIBAAKCAQEA"), string(secret),
		pctAll(string(secret))} {
		in := []byte("head " + mid + " tail")
		want := Redact(in, [][]byte{secret})
		for cut := 1; cut < len(in); cut++ {
			out, _ := streamAll(in, [][]byte{secret}, []int{cut, len(in)})
			if !bytes.Equal(out, want) {
				t.Fatalf("%q cut at %d:\n got %q\nwant %q", mid, cut, out, want)
			}
		}
	}
}

// With a small Hold the window edges land inside matches: every chunk size gives Redact's output.
func TestStreamWindowEdges(t *testing.T) {
	defer func(h, s int) { hold, step = h, s }(hold, step)
	hold, step = 128, 256
	secret := []byte("tvly-test-not-a-real-key-0123456789")
	for _, mid := range []string{fakeAWS, "AKIA%2549OSFODNN7EXAMPLE", b64("id=" + fakeAWS), fakeJWT,
		"Authorization: Bearer " + strings.Repeat("z", 40), string(secret), b64(string(secret)), url.QueryEscape(string(secret))} {
		in := []byte(string(fill("lorem ipsum dolor ", 1000)) + " " + mid + string(fill(" sit amet", 700)) + " " + mid + " end")
		want := Redact(in, [][]byte{secret})
		if bytes.Contains(want, []byte(mid)) {
			t.Fatalf("Redact left %q", mid)
		}
		for size := 1; size <= 400; size++ {
			out, fs := streamAll(in, [][]byte{secret}, []int{size})
			if !bytes.Equal(out, want) {
				t.Fatalf("%q in chunks of %d:\n got %q\nwant %q", mid, size, out, want)
			}
			if !Blocked(fs) && !hasAny(fs, "bare_jwt", "bearer_token", "auth_header") {
				t.Fatalf("%q in chunks of %d: findings %v", mid, size, ids(fs))
			}
		}
	}
}

// Big responses in random chunk sizes, with keys and encoded keys spread through them, including inside a
// long base64 run that a window boundary cuts in the middle.
func TestStreamLarge(t *testing.T) {
	rng := rand.New(rand.NewPCG(3, 4))
	filler := func(n int) string { return string(fill("Lorem ipsum dolor sit amet, consectetur adipiscing. ", n)) }
	secret := []byte("tvly-test-not-a-real-key-0123456789")
	blob := base64.StdEncoding.EncodeToString([]byte(filler(150<<10) + " key=" + fakeAWS + " " + filler(150<<10)))
	parts := []string{filler(100 << 10), fakeAWS, filler(70 << 10), "AKIA%2549OSFODNN7EXAMPLE", filler(Hold),
		string(secret), filler(Hold - 3), blob, filler(5000), pem("OPENSSH PRIVATE KEY", strings.Repeat("QUJD", 800)),
		filler(200 << 10), b64(string(secret)), filler(10)}
	in := []byte(strings.Join(parts, " "))
	want := Redact(in, [][]byte{secret})
	for _, sizes := range [][]int{{1 << 20}, {4096}, {1, 7, 333, 5000, 65536}, {rng.IntN(100) + 1, rng.IntN(20000) + 1}} {
		out, fs := streamAll(in, [][]byte{secret}, sizes)
		if !bytes.Equal(out, want) {
			t.Fatalf("sizes %v: stream output differs from Redact (%d vs %d bytes)", sizes, len(out), len(want))
		}
		for _, bad := range []string{"AKIA", "%2549OSF", string(secret), b64(string(secret)), "QUJDQUJD"} {
			if bytes.Contains(out, []byte(bad)) {
				t.Fatalf("sizes %v: %q survived", sizes, bad)
			}
		}
		// Findings: offsets are in the whole stream and point at the original bytes.
		var aws int
		for _, f := range fs {
			if f.Offset < 0 || f.End > len(in) || f.Offset > f.End {
				t.Fatalf("bad span %+v", f)
			}
			if f.Pattern == "aws_access_key" {
				aws++
			}
		}
		if aws != 3 || !has(fs, ExactSecret) || !has(fs, "ssh_private_key") {
			t.Fatalf("sizes %v: aws=%d %v", sizes, aws, ids(fs))
		}
	}
	// The base64 key was found through decoding, in the middle of the blob.
	if !strings.Contains(string(Redact([]byte(blob), nil)), Replacement) {
		t.Fatal("key inside base64 blob")
	}
}

// Many tiny writes don't rescan the held bytes each time: the pass count stays proportional to the input.
func TestStreamTinyWrites(t *testing.T) {
	in := fill("Lorem ipsum dolor sit amet. ", 512<<10)
	st := NewStream(nil)
	var out []byte
	timed(t, "1-byte writes", func() {
		for i := range in {
			out = append(out, st.Write(in[i:i+1])...)
		}
		out = append(out, st.Flush()...)
	})
	if !bytes.Equal(out, in) {
		t.Fatal("clean stream changed")
	}
}

// A match that never ends (unterminated PEM) is held until Flush, then redacted to the end.
func TestStreamUnterminated(t *testing.T) {
	in := []byte("ok\n-----BEGIN RSA PRIVATE KEY-----\n" + strings.Repeat("QUJD", 30000))
	out, _ := streamAll(in, nil, []int{1000})
	if string(out) != "ok\n[REDACTED]" {
		t.Fatalf("%q", out[:min(len(out), 40)])
	}
}
