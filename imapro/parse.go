package imapro

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// value is one parsed IMAP value: an atom (or number), a string (quoted or literal), NIL or a list.
type value struct {
	kind byte // 'a' atom, 's' string, 'n' NIL, 'l' list
	s    string
	list []value
}

func (v value) str() string {
	if v.kind == 'a' || v.kind == 's' {
		return v.s
	}
	return ""
}

func (v value) num() (uint32, bool) {
	if v.kind != 'a' {
		return 0, false
	}
	n, err := strconv.ParseUint(v.s, 10, 32)
	return uint32(n), err == nil
}

// response is one server response: untagged ("*"), continuation ("+") or tagged.
type response struct {
	tag    string // "*", "+" or the command's tag
	status string // OK, NO, BAD, BYE, PREAUTH for status responses ("" otherwise)
	code   string // the [CODE …] of a status response, upper-cased ("READ-ONLY", "AUTHENTICATIONFAILED …")
	text   string // a status response's text after the code
	num    uint32 // "* 12 FETCH": 12
	name   string // the response's name: CAPABILITY, LIST, SEARCH, FETCH, EXISTS, FLAGS, …
	values []value
}

// reader parses responses from the server, with a cap on what one response may hold.
type reader struct {
	r     *bufio.Reader
	left  int // bytes this response may still take
	limit int
}

var errTooBig = errors.New("imapro: server response too large")

func (p *reader) byte() (byte, error) {
	if p.left <= 0 {
		return 0, errTooBig
	}
	b, err := p.r.ReadByte()
	if err == nil {
		p.left--
	}
	return b, err
}

func (p *reader) peek() (byte, error) {
	b, err := p.r.Peek(1)
	if err != nil {
		return 0, err
	}
	return b[0], nil
}

// line reads to CRLF (the CRLF dropped).
func (p *reader) line() (string, error) {
	var b strings.Builder
	for {
		c, err := p.byte()
		if err != nil {
			return "", err
		}
		if c == '\n' {
			return strings.TrimSuffix(b.String(), "\r"), nil
		}
		b.WriteByte(c)
	}
}

// read reads one response.
func (p *reader) read() (*response, error) {
	p.left = p.limit
	tag, err := p.word()
	if err != nil {
		return nil, err
	}
	r := &response{tag: tag}
	if tag == "+" {
		r.text, err = p.line()
		return r, err
	}
	first, err := p.word()
	if err != nil {
		return nil, err
	}
	up := strings.ToUpper(first)
	switch up {
	case "OK", "NO", "BAD", "BYE", "PREAUTH":
		r.status = up
		rest, err := p.line()
		if err != nil {
			return nil, err
		}
		r.code, r.text = splitCode(rest)
		return r, nil
	}
	if tag != "*" {
		return nil, fmt.Errorf("imapro: unexpected tagged response %q", up)
	}
	if n, err := strconv.ParseUint(first, 10, 32); err == nil {
		r.num = uint32(n)
		if r.name, err = p.word(); err != nil {
			return nil, err
		}
		r.name = strings.ToUpper(r.name)
	} else {
		r.name = up
	}
	r.values, err = p.values()
	return r, err
}

// word reads an atom up to a space or CRLF, consuming one following space.
func (p *reader) word() (string, error) {
	var b strings.Builder
	for {
		c, err := p.peek()
		if err != nil {
			return "", err
		}
		if c == ' ' {
			p.byte()
			break
		}
		if c == '\r' || c == '\n' {
			break
		}
		p.byte()
		b.WriteByte(c)
		if b.Len() > 1024 {
			return "", errors.New("imapro: word too long")
		}
	}
	if b.Len() == 0 {
		return "", errors.New("imapro: empty word")
	}
	return b.String(), nil
}

// values reads values to the end of the line.
func (p *reader) values() ([]value, error) {
	var out []value
	for {
		c, err := p.peek()
		if err != nil {
			return nil, err
		}
		switch c {
		case ' ':
			p.byte()
			continue
		case '\r':
			p.byte()
			continue
		case '\n':
			p.byte()
			return out, nil
		}
		v, err := p.value(0)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
		if len(out) > 100000 {
			return nil, errTooBig
		}
	}
}

func (p *reader) value(depth int) (value, error) {
	if depth > 16 {
		return value{}, errors.New("imapro: nested too deep")
	}
	c, err := p.peek()
	if err != nil {
		return value{}, err
	}
	switch c {
	case '(':
		p.byte()
		v := value{kind: 'l'}
		for {
			c, err := p.peek()
			if err != nil {
				return value{}, err
			}
			switch c {
			case ')':
				p.byte()
				return v, nil
			case ' ':
				p.byte()
				continue
			case '\r', '\n':
				return value{}, errors.New("imapro: unterminated list")
			}
			e, err := p.value(depth + 1)
			if err != nil {
				return value{}, err
			}
			v.list = append(v.list, e)
			if len(v.list) > 100000 {
				return value{}, errTooBig
			}
		}
	case '"':
		p.byte()
		var b strings.Builder
		for {
			c, err := p.byte()
			if err != nil {
				return value{}, err
			}
			switch c {
			case '"':
				return value{kind: 's', s: b.String()}, nil
			case '\\':
				c, err = p.byte()
				if err != nil {
					return value{}, err
				}
			case '\r', '\n':
				return value{}, errors.New("imapro: newline in a quoted string")
			}
			b.WriteByte(c)
		}
	case '{', '~':
		if c == '~' {
			p.byte()
		}
		p.byte() // {
		var n strings.Builder
		for {
			c, err := p.byte()
			if err != nil {
				return value{}, err
			}
			if c == '}' {
				break
			}
			if c == '+' {
				continue
			}
			if c < '0' || c > '9' || n.Len() > 9 {
				return value{}, errors.New("imapro: bad literal")
			}
			n.WriteByte(c)
		}
		size, err := strconv.Atoi(n.String())
		if err != nil {
			return value{}, errors.New("imapro: bad literal")
		}
		if c, _ := p.byte(); c == '\r' {
			p.byte()
		}
		if size > p.left {
			return value{}, errTooBig
		}
		buf := make([]byte, size)
		if _, err := io.ReadFull(p.r, buf); err != nil {
			return value{}, err
		}
		p.left -= size
		return value{kind: 's', s: string(buf)}, nil
	}
	// An atom: up to a space, a paren or CRLF; a [section] is part of it, spaces and parens inside included
	// ("BODY[HEADER.FIELDS (DATE FROM)]"), and so is a <partial>.
	var b strings.Builder
	bracket := 0
	for {
		c, err := p.peek()
		if err != nil {
			return value{}, err
		}
		if bracket == 0 && (c == ' ' || c == '(' || c == ')' || c == '\r' || c == '\n') {
			break
		}
		if bracket > 0 && (c == '\r' || c == '\n') {
			return value{}, errors.New("imapro: unterminated section")
		}
		p.byte()
		switch c {
		case '[':
			bracket++
		case ']':
			bracket--
		}
		b.WriteByte(c)
		if b.Len() > 4096 {
			return value{}, errors.New("imapro: atom too long")
		}
	}
	if strings.EqualFold(b.String(), "NIL") {
		return value{kind: 'n'}, nil
	}
	return value{kind: 'a', s: b.String()}, nil
}

// splitCode splits a status response's text into its [CODE …] (upper-cased) and the rest.
func splitCode(s string) (code, text string) {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, "[") {
		return "", s
	}
	end := strings.IndexByte(s, ']')
	if end < 0 {
		return "", s
	}
	return strings.ToUpper(s[1:end]), strings.TrimSpace(s[end+1:])
}
