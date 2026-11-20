package proto

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestPadBucket(t *testing.T) {
	for _, c := range []struct{ n, want int }{{0, 512}, {1, 512}, {512, 512}, {513, 1024}, {1500, 1536}} {
		if got := PadBucket(c.n, StreamBucket); got != c.want {
			t.Errorf("PadBucket(%d) = %d, want %d", c.n, got, c.want)
		}
	}
}

func TestPadPow2(t *testing.T) {
	for _, c := range []struct{ n, want int }{
		{0, 512}, {10, 512}, {512, 512}, {513, 1024}, {3000, 4096}, {40000, 65536}, {65536, 65536},
		{65537, 131072}, {200000, 262144}, // above 64 KiB: multiples of 64 KiB
	} {
		if got := PadPow2(c.n, AnswerMin, AnswerMax); got != c.want {
			t.Errorf("PadPow2(%d) = %d, want %d", c.n, got, c.want)
		}
	}
}

// Every padded batch is a multiple of 512 bytes, keeps its events, and ends in a comment readers skip.
func TestPadSSE(t *testing.T) {
	for _, n := range []int{0, 1, 100, 508, 509, 510, 511, 512, 1000, 5000} {
		ev := "data: " + strings.Repeat("x", n) + "\n\n"
		out := PadSSE([]byte(ev))
		if len(out)%StreamBucket != 0 {
			t.Fatalf("n=%d: %d bytes, not a multiple of %d", n, len(out), StreamBucket)
		}
		if len(out) >= len(ev)+StreamBucket+sseCommentMin {
			t.Fatalf("n=%d: padded more than a bucket: %d", n, len(out))
		}
		if !strings.HasPrefix(string(out), ev) {
			t.Fatalf("n=%d: events changed", n)
		}
		rest := string(out[len(ev):])
		if !strings.HasPrefix(rest, ":") || !strings.HasSuffix(rest, "\n\n") || strings.Count(rest, "\n") != 2 {
			t.Fatalf("n=%d: padding isn't one SSE comment: %q", n, rest)
		}
	}
	// Two answers of different lengths in the same bucket look the same.
	a, b := PadSSE([]byte("data: {\"type\":\"delta\",\"delta\":\"yes\"}\n\n")), PadSSE([]byte("data: {\"type\":\"delta\",\"delta\":\"no, not at all\"}\n\n"))
	if len(a) != len(b) {
		t.Fatalf("%d != %d", len(a), len(b))
	}
}

func TestPadJSON(t *testing.T) {
	for _, n := range []int{1, 300, 600, 70000} {
		doc, _ := json.Marshal(map[string]string{"answer": strings.Repeat("a", n)})
		out := PadJSON(doc)
		if len(out) != PadPow2(len(doc), AnswerMin, AnswerMax) {
			t.Fatalf("n=%d: %d bytes", n, len(out))
		}
		var v map[string]string
		if err := json.Unmarshal(out, &v); err != nil || len(v["answer"]) != n {
			t.Fatalf("n=%d: doesn't parse the same: %v", n, err)
		}
	}
}
