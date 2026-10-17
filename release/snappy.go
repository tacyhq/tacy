package release

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// decodeSnappy decodes the Snappy block format (https://github.com/google/snappy/blob/main/format_description.txt),
// which GitHub uses for the bundles behind an attestation's bundle_url (".json.sn", application/x-snappy). It
// refuses output longer than max before allocating it. Written here rather than imported so the module (whose
// go.sum compose.yaml embeds) gains no dependency.
func decodeSnappy(src []byte, max int) ([]byte, error) {
	n, k := binary.Uvarint(src)
	if k <= 0 {
		return nil, errors.New("snappy: bad length header")
	}
	if n > uint64(max) {
		return nil, fmt.Errorf("snappy: decoded length %d is over the %d byte limit", n, max)
	}
	dst := make([]byte, 0, n)
	s := src[k:]
	for len(s) > 0 {
		tag := s[0]
		var length, offset int
		switch tag & 3 {
		case 0: // literal
			length = int(tag >> 2)
			s = s[1:]
			if length >= 60 {
				extra := length - 59 // 1 to 4 little-endian bytes hold length-1
				if len(s) < extra {
					return nil, errors.New("snappy: truncated literal length")
				}
				var v uint32
				for i := extra - 1; i >= 0; i-- {
					v = v<<8 | uint32(s[i])
				}
				s = s[extra:]
				if uint64(v)+1 > n {
					return nil, errors.New("snappy: literal overflows the decoded length")
				}
				length = int(v)
			}
			length++
			if len(s) < length || len(dst)+length > int(n) {
				return nil, errors.New("snappy: literal overflows the input or the decoded length")
			}
			dst = append(dst, s[:length]...)
			s = s[length:]
			continue
		case 1: // copy, 1-byte offset
			if len(s) < 2 {
				return nil, errors.New("snappy: truncated copy")
			}
			length = 4 + int(tag>>2)&7
			offset = int(tag&0xe0)<<3 | int(s[1])
			s = s[2:]
		case 2: // copy, 2-byte offset
			if len(s) < 3 {
				return nil, errors.New("snappy: truncated copy")
			}
			length = 1 + int(tag>>2)
			offset = int(binary.LittleEndian.Uint16(s[1:3]))
			s = s[3:]
		case 3: // copy, 4-byte offset
			if len(s) < 5 {
				return nil, errors.New("snappy: truncated copy")
			}
			length = 1 + int(tag>>2)
			o := binary.LittleEndian.Uint32(s[1:5])
			if uint64(o) > n {
				return nil, errors.New("snappy: copy offset out of range")
			}
			offset = int(o)
			s = s[5:]
		}
		if offset <= 0 || offset > len(dst) || len(dst)+length > int(n) {
			return nil, errors.New("snappy: copy out of range")
		}
		start := len(dst) - offset
		for i := 0; i < length; i++ { // byte by byte: a copy may overlap what it produces
			dst = append(dst, dst[start+i])
		}
	}
	if len(dst) != int(n) {
		return nil, fmt.Errorf("snappy: decoded %d bytes, header says %d", len(dst), n)
	}
	return dst, nil
}
