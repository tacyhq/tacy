package guard

import (
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/tacyhq/tacy/proto"
)

// Where a page fetch's address comes from (docs/27 sections 5 and 6). With the quarantined reader on, the acting
// model never gets a source's full address: search results and read pages come to it as a number, [n], and the
// site (scheme and host); the guard keeps each [n]'s address (Tools.sources) and fetches it when the model asks for
// "[n]". Text a page's author wrote can't reach the model through an address's path or query that way.
//
// That also tells the guard which addresses came from code: a [n] (an address a search returned or a page the task
// read), or an address in the person's own messages (TaskOptions.Links). Anything else the model composed itself.
// On a tainted task such an address is never opened, and the person isn't asked about it (Prompts.Hold, permit:
// PermNotFromResults): a page that steered the model can't send data out through an address it made up.

// maxPersonLinks caps the addresses kept from the person's messages.
const maxPersonLinks = 64

// sourceRefRe is a fetch's url argument naming a source: "[3]".
var sourceRefRe = regexp.MustCompile(`^(?:\[\s*([0-9]{1,4})\s*\]|([0-9]{1,4}))$`)

// SourceRef reads a fetch's url argument of the form "[n]", or a bare "n" (never an address: cmd/digestlab
// 2026-10-20 saw models fetch "14" for [14], refused as a composed address, and spend steps finding out).
func SourceRef(s string) (int, bool) {
	m := sourceRefRe.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return 0, false
	}
	n, err := strconv.Atoi(m[1] + m[2])
	return n, err == nil && n > 0
}

// linkKey is an address in a form two spellings of it share: http(s) only, scheme and host lowercased, the default
// port and the fragment dropped, an empty path as "/". ok is false for anything else.
func linkKey(raw string) (string, bool) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || (!strings.EqualFold(u.Scheme, "http") && !strings.EqualFold(u.Scheme, "https")) || u.Host == "" || u.User != nil {
		return "", false
	}
	u.Scheme, u.Host, u.Fragment, u.RawFragment = strings.ToLower(u.Scheme), strings.ToLower(u.Host), "", ""
	if p := u.Port(); p == "80" && u.Scheme == "http" || p == "443" && u.Scheme == "https" {
		u.Host = u.Hostname()
	}
	if u.Path == "" && u.RawPath == "" {
		u.Path = "/"
	}
	return u.String(), true
}

// siteOf is what the acting model gets of an address: its scheme and host ("https://example.com"), nothing the
// page's author chose after that.
func siteOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return ""
	}
	return strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Host)
}

// personLinkRe finds addresses in a person's message: http(s) URLs and www. ones.
var personLinkRe = regexp.MustCompile(`(?i)\b(?:https?://|www\.)[^\s<>"'\x60]+`)

// personLinks are the addresses in the person's own messages (role user), as linkKeys, in order, at most
// maxPersonLinks. A www. address counts in both schemes.
func personLinks(ms []proto.Message) []string {
	var out []string
	seen := map[string]bool{}
	add := func(raw string) {
		if k, ok := linkKey(raw); ok && !seen[k] && len(out) < maxPersonLinks && len(k) <= maxGrantValue {
			seen[k] = true
			out = append(out, k)
		}
	}
	for _, m := range ms {
		if m.Role != "user" {
			continue
		}
		for _, raw := range personLinkRe.FindAllString(m.Content, -1) {
			raw = strings.TrimRight(raw, ".,;:!?)]}")
			if strings.HasPrefix(strings.ToLower(raw), "www.") {
				add("https://" + raw)
				add("http://" + raw)
				continue
			}
			add(raw)
		}
	}
	return out
}

// FetchTarget is a page fetch's address: the url argument, or the address of the source it names ("[n]", from
// sources: the task's [n] -> address). fromCode says the address came from code: a source of this task (named by
// number, or written out the same), or an address in the person's own messages (links, TaskOptions.Links). ok is
// false when the arguments name no usable address (no url, or a [n] the task doesn't have).
func FetchTarget(args []byte, sources map[int]string, links []string) (target string, fromCode, ok bool) {
	raw, ok := fetchURLArg(args)
	if !ok {
		return "", false, false
	}
	if n, isRef := SourceRef(raw); isRef {
		u, found := sources[n]
		return u, found, found
	}
	k, valid := linkKey(raw)
	if !valid {
		return raw, false, true
	}
	for _, l := range links {
		if l == k {
			return raw, true, true
		}
	}
	for _, u := range sources {
		if uk, _ := linkKey(u); uk == k {
			return raw, true, true
		}
	}
	return raw, false, true
}

// shownArgs are a tool call's arguments as people see them: a fetch of "[n]" shows the address it names (the model
// never sees it; the person does, as in the prompt).
func (t *task) shownArgs(action string, args []byte) []byte {
	if PermissionKind(action) != "web.fetch" {
		return args
	}
	raw, ok := fetchURLArg(args)
	if !ok {
		return args
	}
	n, isRef := SourceRef(raw)
	if !isRef {
		return args
	}
	u, found := t.tools.sourceMap()[n]
	if !found {
		return args
	}
	if b, err := withValue(action, args, u); err == nil {
		return b
	}
	return args
}
