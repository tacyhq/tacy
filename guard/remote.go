package guard

import (
	"regexp"
	"strings"

	"github.com/tacyhq/tacy/proto"
)

// R4 of the rule of two (the v1 design §5.6): the result of an unattended run that read mail is given to the person
// with its remote images and links as text, so opening it fetches nothing (a remote image in an answer written
// after reading someone's mail is a way out for what the mail said). The VM does it before it seals the result
// (app/schedules.go, MailRead in the result), and the client renders such a result without images or links too.
// In v1 no unattended run reads mail (R1, R2); this is the line after them.

var (
	remoteImageRe = regexp.MustCompile(`!\[([^\]\n]*)\]\(\s*<?([^()\s<>]+)>?(?:\s+"[^"\n]*")?\s*\)`)
	remoteLinkRe  = regexp.MustCompile(`\[([^\]\n]*)\]\(\s*<?([^()\s<>]+)>?(?:\s+"[^"\n]*")?\s*\)`)
	autoLinkRe    = regexp.MustCompile(`<((?:https?|ftp)://[^>\s]+)>`)
	bareURLRe     = regexp.MustCompile(`(?i)\b(?:(?:https?|ftp)://|www\.)[^\s` + "`" + `"'<>()]+`)
	// A link reference definition ("[label]: dest", the destination maybe on the next line), at a line start or
	// after container markers (block quotes, list items): CommonMark applies it document-wide (review 2, L4).
	refDefRe = regexp.MustCompile(`(?m)^((?:[ \t]*(?:>|[-*+]|\d{1,9}[.)])[ \t]*)*[ \t]{0,3})\[([^\]\n]+)\]:[ \t]*(?:\n[ \t]*)?(<[^>\n]*>|\S+)`)
	// An image by reference ("![alt][ref]", "![alt][]", "![alt]"): left once the inline ones are replaced.
	refImageRe = regexp.MustCompile(`!\[([^\]\n]*)\](?:\[[^\]\n]*\])?`)
)

// PlainRemote is markdown text with every image and link made plain text: an image is "[image: alt]" and its
// address in code, a link its words and its address in code, a bare address (or www. autolink) in code, a reference
// definition escaped with its address in code (so no "![x][1]" resolves, //host ones included), an image by
// reference "[image: alt]", and an HTML tag escaped. A
// markdown renderer then shows addresses as text: nothing is loaded, nothing is a link.
func PlainRemote(s string) string {
	code := func(u string) string { return "`" + strings.ReplaceAll(u, "`", "") + "`" }
	// Definitions first: "\[label\]: `dest`" is no definition, so no reference (image or link) resolves.
	s = refDefRe.ReplaceAllStringFunc(s, func(m string) string {
		p := refDefRe.FindStringSubmatch(m)
		dest := strings.TrimSuffix(strings.TrimPrefix(p[3], "<"), ">")
		return p[1] + `\[` + p[2] + `\]: ` + "\x00" + code(dest) + "\x00"
	})
	s = remoteImageRe.ReplaceAllStringFunc(s, func(m string) string {
		p := remoteImageRe.FindStringSubmatch(m)
		return "[image: " + strings.TrimSpace(p[1]) + "] " + "\x00" + code(p[2]) + "\x00"
	})
	s = refImageRe.ReplaceAllStringFunc(s, func(m string) string {
		return "[image: " + strings.TrimSpace(refImageRe.FindStringSubmatch(m)[1]) + "]"
	})
	s = remoteLinkRe.ReplaceAllStringFunc(s, func(m string) string {
		p := remoteLinkRe.FindStringSubmatch(m)
		return p[1] + " (" + "\x00" + code(p[2]) + "\x00" + ")"
	})
	s = autoLinkRe.ReplaceAllString(s, "$1")
	// Outside code spans (and the addresses just put in code): bare addresses in code, tags escaped.
	var b strings.Builder
	for i, part := range splitCode(s) {
		if i%2 == 1 {
			b.WriteString(part)
			continue
		}
		part = bareURLRe.ReplaceAllStringFunc(part, func(u string) string {
			t := strings.TrimRight(u, ".,;:!?")
			return code(t) + u[len(t):]
		})
		part = strings.ReplaceAll(part, "<", `\<`)
		b.WriteString(part)
	}
	return strings.ReplaceAll(b.String(), "\x00", "")
}

// splitCode splits s into text and code: even parts are outside code spans (`...`, and the \x00-marked addresses),
// odd ones inside, delimiters kept with the code.
func splitCode(s string) []string {
	var out []string
	cur := strings.Builder{}
	for len(s) > 0 {
		i := strings.IndexAny(s, "`\x00")
		if i < 0 {
			cur.WriteString(s)
			break
		}
		cur.WriteString(s[:i])
		d := s[i]
		j := strings.IndexByte(s[i+1:], d)
		if j < 0 {
			cur.WriteString(s[i:])
			break
		}
		out = append(out, cur.String())
		cur.Reset()
		out = append(out, s[i:i+j+2])
		s = s[i+j+2:]
	}
	return append(out, cur.String())
}

// MailRead: the events show a mail tool's result (the run read the person's mail, or tried to).
func MailRead(evs []proto.Event) bool {
	for _, e := range evs {
		if (e.Type == "tool_result" || e.Type == "tool_call") && isMailToolName(e.Name) {
			return true
		}
	}
	return false
}

func isMailToolName(n string) bool {
	for _, m := range mailTools {
		if m.name == n {
			return true
		}
	}
	return false
}
