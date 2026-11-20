package proto

import (
	"bytes"
	"time"
)

// Padding (the keys plan §3.4, PX-3). Whoever carries the VM's encrypted answers (Phala's gateway terminates TLS in front
// of the VM; Cloudflare runs the relay) sees each encrypted chunk's size and when it was sent. Without padding a
// streamed answer's chunks follow its tokens' lengths, and a short answer's size says what it was ("Whisper Leak").
// So:
//
//   - a stream (SSE) is written in batches, at most one every StreamBatch, each padded to a multiple of StreamBucket
//     bytes with an SSE comment every reader skips (like the keepalive);
//   - a whole answer (a JSON body) is padded with trailing whitespace, which every JSON parser skips, to a power of
//     two of at least AnswerMin bytes, and above AnswerMax to a multiple of AnswerMax.
//
// What remains visible: how many buckets a batch filled, when batches went out (at most one per StreamBatch), and a
// whole answer's size class.
const (
	StreamBucket = 512
	StreamBatch  = 50 * time.Millisecond
	AnswerMin    = 512
	AnswerMax    = 64 << 10
)

// PadBucket is n rounded up to a multiple of bucket (n itself when it is one; bucket when n is 0).
func PadBucket(n, bucket int) int {
	if n <= 0 {
		return bucket
	}
	return (n + bucket - 1) / bucket * bucket
}

// PadPow2 is n rounded up to a power of two of at least min; above max, to a multiple of max.
func PadPow2(n, min, max int) int {
	if n > max {
		return PadBucket(n, max)
	}
	p := min
	for p < n {
		p <<= 1
	}
	return p
}

// sseCommentMin is the shortest SSE comment: ":" and the blank line that ends it.
const sseCommentMin = len(":\n\n")

// PadSSE returns b, whole SSE events, with one SSE comment line added so the result is a multiple of StreamBucket
// bytes. Readers skip comments, so the events read the same.
func PadSSE(b []byte) []byte {
	target := PadBucket(len(b)+sseCommentMin, StreamBucket)
	out := make([]byte, 0, target)
	out = append(out, b...)
	out = append(out, ':')
	out = append(out, bytes.Repeat([]byte{' '}, target-len(b)-sseCommentMin)...)
	return append(out, '\n', '\n')
}

// PadJSON returns a JSON document b with trailing spaces up to PadPow2(len(b), AnswerMin, AnswerMax) bytes. JSON
// allows whitespace after the value, so it parses the same.
func PadJSON(b []byte) []byte {
	target := PadPow2(len(b), AnswerMin, AnswerMax)
	out := make([]byte, 0, target)
	out = append(out, b...)
	return append(out, bytes.Repeat([]byte{' '}, target-len(b))...)
}
