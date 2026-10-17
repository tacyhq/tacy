package release

import (
	"bytes"
	"strings"
	"testing"
)

func TestDecodeSnappy(t *testing.T) {
	long := bytes.Repeat([]byte("x"), 100)
	ok := []struct {
		name string
		in   []byte
		want string
	}{
		{"literal", []byte{5, 0x10, 'h', 'e', 'l', 'l', 'o'}, "hello"},
		{"copy, 1-byte offset, overlapping", []byte{8, 0x04, 'a', 'b', 0x09, 2}, "abababab"},
		{"copy, 2-byte offset", []byte{8, 0x04, 'a', 'b', 0x16, 2, 0}, "abababab"},
		{"copy, 4-byte offset", []byte{8, 0x04, 'a', 'b', 0x17, 2, 0, 0, 0}, "abababab"},
		{"long literal (1 length byte)", append([]byte{100, 0xf0, 99}, long...), string(long)},
		{"empty", []byte{0}, ""},
	}
	for _, c := range ok {
		got, err := decodeSnappy(c.in, 1000)
		if err != nil || string(got) != c.want {
			t.Errorf("%s: %q, %v", c.name, got, err)
		}
	}
	bad := []struct {
		name, want string
		in         []byte
	}{
		{"no header", "length header", nil},
		{"over the limit", "limit", []byte{0xe9, 0x07}}, // 1001
		{"copy with offset 0", "out of range", []byte{8, 0x04, 'a', 'b', 0x09, 0}},
		{"copy before the start", "out of range", []byte{8, 0x04, 'a', 'b', 0x09, 3}},
		{"copy past the declared length", "out of range", []byte{4, 0x04, 'a', 'b', 0x09, 2}},
		{"truncated literal", "overflows", []byte{5, 0x10, 'h', 'e'}},
		{"literal past the declared length", "overflows", []byte{2, 0x10, 'h', 'e', 'l', 'l', 'o'}},
		{"truncated copy", "truncated", []byte{8, 0x04, 'a', 'b', 0x16, 2}},
		{"shorter than declared", "header says", []byte{9, 0x04, 'a', 'b', 0x09, 2}},
		{"huge 4-byte offset", "out of range", []byte{8, 0x04, 'a', 'b', 0x17, 0xff, 0xff, 0xff, 0xff}},
		{"huge literal length", "overflows", []byte{8, 0xfc, 0xff, 0xff, 0xff, 0xff}},
	}
	for _, c := range bad {
		if got, err := decodeSnappy(c.in, 1000); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %q, %v", c.name, got, err)
		}
	}
}
