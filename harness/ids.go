package harness

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/binary"
	"strings"
)

// Task ids (docs/27 section 1): "tk_" plus 26 lowercase base32 characters (RFC 4648 alphabet, no padding:
// 128 bits). `t_` is already a thread. A task is random unless it must be once-only: then its id is
// derived from what makes it unique (a repeated start's key, later a schedule slot or a parent's action), so a
// repeat makes the same id and the queue's unique key refuses a second task.

// TaskPrefix starts every task id.
const TaskPrefix = "tk_"

var idEncoding = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)

// NewTaskID is a random task id.
func NewTaskID() string {
	var b [16]byte
	rand.Read(b[:])
	return TaskPrefix + idEncoding.EncodeToString(b[:])
}

// DeriveTaskID is the task id derived from key (a per-space secret, so ids stay unguessable) and parts: the first
// 128 bits of HMAC-SHA256(key, "tacy-task-id/v1" ‖ each part with its length). The same key and parts always give
// the same id; parts are length-prefixed, so ("ab", "c") and ("a", "bc") differ.
func DeriveTaskID(key []byte, parts ...string) string {
	m := hmac.New(sha256.New, key)
	m.Write([]byte("tacy-task-id/v1\x00"))
	var n [8]byte
	for _, p := range parts {
		binary.BigEndian.PutUint64(n[:], uint64(len(p)))
		m.Write(n[:])
		m.Write([]byte(p))
	}
	return TaskPrefix + idEncoding.EncodeToString(m.Sum(nil)[:16])
}

// ValidTaskID reports whether s is a task id in this format.
func ValidTaskID(s string) bool {
	rest, ok := strings.CutPrefix(s, TaskPrefix)
	if !ok || len(rest) != 26 {
		return false
	}
	for i := 0; i < len(rest); i++ {
		if c := rest[i]; !(c >= 'a' && c <= 'z' || c >= '2' && c <= '7') {
			return false
		}
	}
	// The last character carries 3 bits of the 128 and 2 zero bits: only canonical encodings are ids.
	b, err := idEncoding.DecodeString(rest)
	return err == nil && len(b) == 16 && idEncoding.EncodeToString(b) == rest
}
