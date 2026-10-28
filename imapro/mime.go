package imapro

import (
	"bytes"
	"encoding/base64"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/mail"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/text/encoding/htmlindex"
)

// Address is a mailbox in a header: the display name (decoded) and the bare address.
type Address struct {
	Name string
	Addr string
}

// Attachment is a part that isn't the message's text: its file name (decoded), type and decoded size.
type Attachment struct {
	Name string
	Type string
	Size int
}

// Message is a message (or its headers) parsed for reading: everything decoded to UTF-8.
type Message struct {
	Subject     string
	From        []Address
	To          []Address
	Cc          []Address
	Date        time.Time
	Text        string // the text/plain body (the first one), or ""
	HTML        string // the text/html body when there's no text/plain, or ""
	Attachments []Attachment
}

// Limits on what a message's parts may take.
const (
	maxParts     = 100
	maxDepth     = 8
	maxPartBytes = 4 << 20
)

var wordDecoder = &mime.WordDecoder{CharsetReader: charsetReader}

func charsetReader(charset string, in io.Reader) (io.Reader, error) {
	enc, err := htmlindex.Get(charset)
	if err != nil {
		return nil, err
	}
	return enc.NewDecoder().Reader(in), nil
}

// decodeHeader decodes RFC 2047 encoded words; undecodable text stays as it is, made valid UTF-8.
func decodeHeader(s string) string {
	d, err := wordDecoder.DecodeHeader(s)
	if err != nil {
		d = s
	}
	return strings.ToValidUTF8(strings.Join(strings.Fields(d), " "), "�")
}

func addresses(h mail.Header, key string) []Address {
	v := h.Get(key)
	if v == "" {
		return nil
	}
	p := mail.AddressParser{WordDecoder: wordDecoder}
	list, err := p.ParseList(v)
	if err != nil {
		// One that doesn't parse: keep a bare address if there is one.
		if a, err := p.Parse(v); err == nil {
			return []Address{{Name: decodeHeader(a.Name), Addr: a.Address}}
		}
		return nil
	}
	var out []Address
	for _, a := range list {
		out = append(out, Address{Name: decodeHeader(a.Name), Addr: a.Address})
		if len(out) >= 50 {
			break
		}
	}
	return out
}

// ParseHeaders parses a header section (a search's BODY.PEEK[HEADER.FIELDS …]).
func ParseHeaders(raw []byte) *Message {
	m, err := mail.ReadMessage(bytes.NewReader(append(bytes.TrimRight(raw, "\r\n"), "\r\n\r\n"...)))
	if err != nil {
		return &Message{}
	}
	return headerFields(m.Header)
}

func headerFields(h mail.Header) *Message {
	msg := &Message{Subject: decodeHeader(h.Get("Subject")), From: addresses(h, "From"), To: addresses(h, "To"),
		Cc: addresses(h, "Cc")}
	if d, err := h.Date(); err == nil {
		msg.Date = d
	}
	return msg
}

// ParseMessage parses a whole message, or its first bytes (a FETCH cut at the read limit: what decodes is kept).
// The body is the first text/plain part, else the first text/html part; other parts are attachments (names, types
// and sizes only).
func ParseMessage(raw []byte) *Message {
	m, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		// Not even a header: the bytes as text.
		return &Message{Text: strings.ToValidUTF8(string(raw), "�")}
	}
	msg := headerFields(m.Header)
	parts := 0
	walk(msg, m.Header.Get("Content-Type"), m.Header.Get("Content-Transfer-Encoding"), m.Header.Get("Content-Disposition"), m.Body, 0, &parts)
	return msg
}

func walk(msg *Message, ctype, cte, disp string, body io.Reader, depth int, parts *int) {
	*parts++
	if *parts > maxParts || depth > maxDepth {
		return
	}
	mt, params, err := mime.ParseMediaType(ctype)
	if err != nil || ctype == "" {
		mt, params = "text/plain", map[string]string{"charset": "us-ascii"}
	}
	if strings.HasPrefix(mt, "multipart/") {
		boundary := params["boundary"]
		if boundary == "" {
			return
		}
		mr := multipart.NewReader(body, boundary)
		for {
			p, err := mr.NextRawPart()
			if err != nil {
				return // the end, or a message cut at the read limit
			}
			walk(msg, p.Header.Get("Content-Type"), p.Header.Get("Content-Transfer-Encoding"), p.Header.Get("Content-Disposition"), p, depth+1, parts)
			if *parts > maxParts {
				return
			}
		}
	}
	data := decodeBody(body, cte)
	dispType, dparams, _ := mime.ParseMediaType(disp)
	name := dparams["filename"]
	if name == "" {
		name = params["name"]
	}
	attached := strings.EqualFold(dispType, "attachment") || name != ""
	switch {
	case !attached && mt == "text/plain" && msg.Text == "":
		msg.Text = toUTF8(data, params["charset"])
	case !attached && mt == "text/html" && msg.HTML == "":
		msg.HTML = toUTF8(data, params["charset"])
	case !attached && (mt == "text/plain" || mt == "text/html"):
		// a second body (an alternative already taken): skipped
	case mt == "message/rfc822" && !attached:
		msg.Attachments = append(msg.Attachments, Attachment{Name: "forwarded message", Type: mt, Size: len(data)})
	default:
		if len(msg.Attachments) < 50 {
			msg.Attachments = append(msg.Attachments, Attachment{Name: decodeHeader(name), Type: mt, Size: len(data)})
		}
	}
}

// decodeBody reads a part's body (at most maxPartBytes), undoing its transfer encoding; what fails to decode at the
// end (a cut message) is dropped, the rest kept.
func decodeBody(r io.Reader, cte string) []byte {
	lim := io.LimitReader(r, maxPartBytes)
	var src io.Reader = lim
	switch strings.ToLower(strings.TrimSpace(cte)) {
	case "base64":
		src = base64.NewDecoder(base64.StdEncoding, &stripSpace{r: lim})
	case "quoted-printable":
		src = quotedprintable.NewReader(lim)
	}
	var buf bytes.Buffer
	io.Copy(&buf, io.LimitReader(src, maxPartBytes))
	return buf.Bytes()
}

// stripSpace drops CR, LF, spaces and tabs (base64 bodies are wrapped).
type stripSpace struct{ r io.Reader }

func (s *stripSpace) Read(p []byte) (int, error) {
	n, err := s.r.Read(p)
	j := 0
	for i := 0; i < n; i++ {
		if c := p[i]; c != '\r' && c != '\n' && c != ' ' && c != '\t' {
			p[j] = c
			j++
		}
	}
	if j == 0 && n > 0 && err == nil {
		return s.Read(p)
	}
	return j, err
}

func toUTF8(b []byte, charset string) string {
	cs := strings.ToLower(strings.TrimSpace(charset))
	if cs == "" || cs == "utf-8" || cs == "utf8" || cs == "us-ascii" || cs == "ascii" {
		return strings.ToValidUTF8(string(b), "�")
	}
	enc, err := htmlindex.Get(cs)
	if err != nil {
		return strings.ToValidUTF8(string(b), "�")
	}
	out, err := enc.NewDecoder().Bytes(b)
	if err != nil || !utf8.Valid(out) {
		return strings.ToValidUTF8(string(b), "�")
	}
	return string(out)
}
