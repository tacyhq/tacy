package imapro

import (
	"encoding/base64"
	"strings"
	"unicode/utf16"
)

// decodeUTF7 decodes a folder name in IMAP's modified UTF-7 (RFC 3501 section 5.1.3) for people to read. A name
// that isn't valid modified UTF-7 is returned as it is.
func decodeUTF7(s string) string {
	if !strings.Contains(s, "&") {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c != '&' {
			b.WriteByte(c)
			continue
		}
		end := strings.IndexByte(s[i+1:], '-')
		if end < 0 {
			return s
		}
		enc := s[i+1 : i+1+end]
		i += end + 1
		if enc == "" {
			b.WriteByte('&')
			continue
		}
		raw, err := base64.RawStdEncoding.DecodeString(strings.ReplaceAll(enc, ",", "/"))
		if err != nil || len(raw)%2 != 0 {
			return s
		}
		u := make([]uint16, len(raw)/2)
		for j := range u {
			u[j] = uint16(raw[2*j])<<8 | uint16(raw[2*j+1])
		}
		b.WriteString(string(utf16.Decode(u)))
	}
	return b.String()
}
