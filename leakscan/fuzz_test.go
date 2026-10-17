package leakscan

import (
	"bytes"
	"testing"
)

// FuzzScan: no panics; the prefilters (need, pre, within) find exactly what the bare regex finds; spans are
// inside the input and ordered; an exact secret planted anywhere never survives Redact or the stream; and the
// stream, when the input fits in one pass, gives Redact's output exactly.
// Seeds run with go test; fuzz with go test -fuzz=FuzzScan ./leakscan/.
func FuzzScan(f *testing.F) {
	for _, s := range []string{"", "plain text", fakeAWS, "AKIA%49OSFODNN7EXAMPLE", "AKIA%2549OSFODNN7EXAMPLE",
		b64("id=" + fakeAWS), entAll(fakeAWS, true), uescAll(fakeAWS), "\\ud83d\\ude00 \\u{1F600} \\x41",
		pem("RSA PRIVATE KEY", "MII"), "-----BEGIN PGP PRIVATE KEY BLOCK-----", fakeJWT, fakeBearer, fakeAuthHeader,
		"&#x110000; &#99999999; &amp &", "%", "%%4", "\\u", "\\uD800\\u0041", "QUJD\r\nQUJD\nQUJD", "====",
		"\xff\xfe\u200b\u0410", "{{TAVILY_API_KEY}}", fakeTelegram,
		"\u00e9" + fakeHex64 + "_x " + fakeHex64, "x.yyyyyyyy.zzzzzzzz-" + fakeJWT + ".",
		"AuThOrIzAtIoN: Basic " + fakeGitHub, "authorization:authorization: x"} {
		f.Add([]byte(s), uint16(len(s)/2))
	}
	secret := []byte("tvly-test-not-a-real-key-0123456789")
	f.Fuzz(func(t *testing.T, data []byte, at uint16) {
		for i := range patterns {
			p := &patterns[i]
			got, want := p.find(data), p.re.FindAllIndex(data, -1)
			if len(got) != len(want) {
				t.Fatalf("%s: prefiltered %v, regex %v", p.ID, got, want)
			}
			for k := range got {
				if got[k][0] != want[k][0] || got[k][1] != want[k][1] {
					t.Fatalf("%s: prefiltered %v, regex %v", p.ID, got, want)
				}
			}
		}
		fs := Scan(data)
		for i, x := range fs {
			if x.Offset < 0 || x.End > len(data) || x.Offset > x.End {
				t.Fatalf("bad span %+v for %d bytes", x, len(data))
			}
			if i > 0 && fs[i-1].Offset > x.Offset {
				t.Fatal("not sorted")
			}
		}
		k := int(at) % (len(data) + 1)
		in := append(append(append([]byte{}, data[:k]...), secret...), data[k:]...)
		out := Redact(in, [][]byte{secret})
		if bytes.Contains(out, secret) {
			t.Fatalf("secret survived Redact: %q", out)
		}
		st := NewStream([][]byte{secret})
		sout := append(st.Write(in[:k]), st.Write(in[k:])...)
		sout = append(sout, st.Flush()...)
		if bytes.Contains(sout, secret) {
			t.Fatalf("secret survived the stream: %q", sout)
		}
		if len(in) < Step && !bytes.Equal(sout, out) {
			t.Fatalf("stream %q != Redact %q", sout, out)
		}
	})
}
