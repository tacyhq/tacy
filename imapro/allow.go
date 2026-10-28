// Package imapro is a read-only IMAP client (RFC 3501 / 9051 subset) for the mail connector in gatewayd (docs/34
// step 4, CONNECTIONS.md). The person's app password could read, send and delete their mail; this client can only
// read it, and that is enforced here in code, at the one place commands are written (Client.write, via Allowed):
//
//   - commands: CAPABILITY, STARTTLS, LOGIN, AUTHENTICATE PLAIN, EXAMINE, SEARCH, FETCH, UID SEARCH, UID FETCH, LIST,
//     NOOP, LOGOUT. Anything else (SELECT, STORE, EXPUNGE, APPEND, COPY, MOVE, CREATE, DELETE, RENAME, SUBSCRIBE,
//     CLOSE, UNSELECT, IDLE, ENABLE, UID STORE / COPY / MOVE / EXPUNGE, …) is refused before a byte is written;
//   - FETCH data items: only UID, FLAGS, INTERNALDATE, RFC822.SIZE, ENVELOPE, BODYSTRUCTURE and BODY.PEEK[…] (with a
//     partial range). BODY[…], RFC822, RFC822.TEXT and RFC822.HEADER are refused: the first three set \Seen, and
//     the rule is "PEEK or nothing";
//   - folders are only ever opened with EXAMINE (read-only), and a server whose EXAMINE doesn't answer [READ-ONLY]
//     is hung up on, so even a server that ignored PEEK couldn't mark anything read;
//   - TLS only: implicit TLS, or STARTTLS before anything else is sent; certificates checked against the roots.
//
// Standard library plus golang.org/x/net/html and x/text (both already pinned for the guard).
package imapro

import (
	"errors"
	"fmt"
	"strings"
)

// ErrRefused is the error for a command or FETCH item this client never sends.
var ErrRefused = errors.New("imapro: refused: read-only client")

// allowedCommands are the only command names written (after the tag). UID is a prefix and is checked with its
// sub-command; AUTHENTICATE only with PLAIN.
var allowedCommands = map[string]bool{
	"CAPABILITY": true, "STARTTLS": true, "LOGIN": true, "AUTHENTICATE": true, "EXAMINE": true, "SEARCH": true,
	"FETCH": true, "UID": true, "LIST": true, "NOOP": true, "LOGOUT": true,
}

// allowedUID are the commands UID may prefix.
var allowedUID = map[string]bool{"SEARCH": true, "FETCH": true}

// allowedFetch are the FETCH data items that never change a message (BODY.PEEK[…] is checked apart).
var allowedFetch = map[string]bool{"UID": true, "FLAGS": true, "INTERNALDATE": true, "RFC822.SIZE": true,
	"ENVELOPE": true, "BODYSTRUCTURE": true}

// Allowed checks one command as it would be written (its text without the tag and without any literal's bytes:
// "UID FETCH 12 (UID BODY.PEEK[])"). It is the read-only rule; Client.write calls it for every command.
func Allowed(cmd string) error {
	cmd = strings.TrimSpace(cmd)
	if cmd == "" || strings.ContainsAny(cmd, "\r\n\x00") {
		return fmt.Errorf("%w: malformed command", ErrRefused)
	}
	words := strings.Fields(cmd)
	name := strings.ToUpper(words[0])
	if !allowedCommands[name] {
		return fmt.Errorf("%w: %s", ErrRefused, name)
	}
	rest := words[1:]
	switch name {
	case "UID":
		if len(rest) == 0 || !allowedUID[strings.ToUpper(rest[0])] {
			sub := ""
			if len(rest) > 0 {
				sub = " " + strings.ToUpper(rest[0])
			}
			return fmt.Errorf("%w: UID%s", ErrRefused, sub)
		}
		if strings.EqualFold(rest[0], "FETCH") {
			return allowedFetchItems(strings.Join(rest[1:], " "))
		}
	case "FETCH":
		return allowedFetchItems(strings.Join(rest, " "))
	case "AUTHENTICATE":
		if len(rest) == 0 || !strings.EqualFold(rest[0], "PLAIN") {
			return fmt.Errorf("%w: AUTHENTICATE other than PLAIN", ErrRefused)
		}
	case "CAPABILITY", "STARTTLS", "NOOP", "LOGOUT":
		if len(rest) > 0 {
			return fmt.Errorf("%w: %s takes no arguments", ErrRefused, name)
		}
	}
	return nil
}

// allowedFetchItems checks a FETCH's "<set> <items>": items is one item or a parenthesized list; macros (ALL, FAST,
// FULL) are refused (spelled out instead), as is every item that isn't in allowedFetch or a BODY.PEEK.
func allowedFetchItems(s string) error {
	set, items, ok := strings.Cut(strings.TrimSpace(s), " ")
	if !ok || set == "" || !validSet(set) {
		return fmt.Errorf("%w: FETCH needs a message set and items", ErrRefused)
	}
	items = strings.TrimSpace(items)
	if strings.HasPrefix(items, "(") {
		if !strings.HasSuffix(items, ")") {
			return fmt.Errorf("%w: FETCH items", ErrRefused)
		}
		items = items[1 : len(items)-1]
	}
	list, err := splitItems(items)
	if err != nil || len(list) == 0 {
		return fmt.Errorf("%w: FETCH items", ErrRefused)
	}
	for _, it := range list {
		u := strings.ToUpper(it)
		if allowedFetch[u] {
			continue
		}
		if strings.HasPrefix(u, "BODY.PEEK[") && peekSection(u[len("BODY.PEEK"):]) {
			continue
		}
		return fmt.Errorf("%w: FETCH %s", ErrRefused, u)
	}
	return nil
}

// splitItems splits FETCH items on spaces outside brackets: "BODY.PEEK[HEADER.FIELDS (DATE FROM)]" is one item.
func splitItems(s string) ([]string, error) {
	var out []string
	depth, start := 0, -1
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '[':
			depth++
		case c == ']':
			depth--
			if depth < 0 {
				return nil, errors.New("brackets")
			}
		case c == '(' || c == ')':
			if depth == 0 {
				return nil, errors.New("nested list")
			}
		}
		if c == ' ' && depth == 0 {
			if start >= 0 {
				out = append(out, s[start:i])
				start = -1
			}
			continue
		}
		if start < 0 {
			start = i
		}
	}
	if depth != 0 {
		return nil, errors.New("brackets")
	}
	if start >= 0 {
		out = append(out, s[start:])
	}
	return out, nil
}

// peekSection checks "[section]<partial>" of a BODY.PEEK: the section is empty, HEADER, TEXT, MIME, a part number
// like 1.2 (with .HEADER/.TEXT/.MIME), or HEADER.FIELDS (…) / HEADER.FIELDS.NOT (…) of atoms; partial is <n.m>.
func peekSection(s string) bool {
	end := strings.IndexByte(s, ']')
	if !strings.HasPrefix(s, "[") || end < 0 {
		return false
	}
	sec, partial := s[1:end], s[end+1:]
	if partial != "" {
		if !strings.HasPrefix(partial, "<") || !strings.HasSuffix(partial, ">") {
			return false
		}
		a, b, ok := strings.Cut(partial[1:len(partial)-1], ".")
		if !ok || !digits(a) || !digits(b) {
			return false
		}
	}
	if sec == "" || sec == "HEADER" || sec == "TEXT" || sec == "MIME" {
		return true
	}
	if f, ok := strings.CutPrefix(sec, "HEADER.FIELDS"); ok {
		f = strings.TrimPrefix(f, ".NOT")
		f = strings.TrimSpace(f)
		if !strings.HasPrefix(f, "(") || !strings.HasSuffix(f, ")") {
			return false
		}
		for _, h := range strings.Fields(f[1 : len(f)-1]) {
			for _, c := range h {
				if !(c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
					return false
				}
			}
		}
		return true
	}
	// A part number, optionally with HEADER / TEXT / MIME.
	parts := strings.Split(sec, ".")
	for i, p := range parts {
		if digits(p) {
			continue
		}
		return i > 0 && i == len(parts)-1 && (p == "HEADER" || p == "TEXT" || p == "MIME")
	}
	return true
}

func digits(s string) bool {
	if s == "" || len(s) > 10 {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// validSet: a message set of numbers, ranges and "*" ("1:4,7,9:*").
func validSet(s string) bool {
	if s == "" || len(s) > 4096 {
		return false
	}
	for _, part := range strings.Split(s, ",") {
		a, b, rng := strings.Cut(part, ":")
		if !(digits(a) || a == "*") || rng && !(digits(b) || b == "*") {
			return false
		}
	}
	return true
}
