package guard

import (
	"bytes"
	"encoding/json/jsontext"
	"io"
	"slices"
	"strings"

	"github.com/tacyhq/tacy/leakscan"
)

// Leak scanning in the web connector (docs/21 section 2): the arguments a brain chose are scanned
// before anything is sent (a credential pattern blocks the action: denied), and what comes back is redacted before
// the brain or people see it. Model calls aren't pattern-scanned (the prompt is the point and the model is
// attested); their leased key is redacted in every encoding (gateway.go, keys.go).

// Egress is the gateway's record of one leak-scan decision: metadata only, never the arguments, the URL or host,
// or the matched bytes. Later these become signed records sealed to the firm; until then gatewayd
// writes them to its log.
type Egress struct {
	Task     string   `json:"task"`
	Action   string   `json:"action"`   // the harness request id
	Op       string   `json:"op"`       // web.search, web.fetch, web.images
	Decision string   `json:"decision"` // denied (nothing sent) | redacted (the response, before the brain)
	Rule     string   `json:"rule"`     // leak_scan | policy | permission (no answer from the person)
	Patterns []string `json:"patterns"` // pattern ids that matched, sorted, each once
}

// patternIDs are the ids of the findings that block (outbound) or redact (responses), sorted, each once.
func patternIDs(fs []leakscan.Finding, blocking bool) []string {
	var ids []string
	for _, f := range fs {
		if blocking && f.Action != leakscan.Block || !blocking && f.Action == leakscan.Warn {
			continue
		}
		if !slices.Contains(ids, f.Pattern) {
			ids = append(ids, f.Pattern)
		}
	}
	slices.Sort(ids)
	return ids
}

// outboundLeak scans an action's arguments as the brain sent them (every decoding: leakscan) and returns the ids
// of the patterns that block it, or nil.
func outboundLeak(args []byte) []string {
	fs := leakscan.Scan(args)
	if !leakscan.Blocked(fs) {
		return nil
	}
	return patternIDs(fs, true)
}

// leakRefused is the outcome of an action blocked by the leak scan: refused before anything was sent, like a URL
// with personal data.
func leakRefused(ids []string, provider string) toolOutcome {
	o := errorOutcome("refused: the arguments contain what looks like a credential (" + strings.Join(ids, ", ") +
		"), so nothing was sent")
	o.ran, o.failed, o.provider = true, "refused", provider
	return o
}

// redactOutcome removes credentials from what a connector brought back (the tool's JSON, which the brain gets and
// people see as the tool_result, and the titles and snippets shown as sources and images) and returns the ids of
// the patterns it removed. Nothing changes when nothing matched, so a clean result keeps its exact bytes.
func redactOutcome(out *toolOutcome) []string {
	var ids []string
	add := func(fs []leakscan.Finding) {
		for _, id := range patternIDs(fs, false) {
			if !slices.Contains(ids, id) {
				ids = append(ids, id)
			}
		}
	}
	if fs := leakscan.Scan([]byte(out.content)); len(patternIDs(fs, false)) > 0 {
		add(fs)
		out.content = redactJSONStrings(out.content)
	}
	str := func(s *string) {
		if fs := leakscan.Scan([]byte(*s)); len(patternIDs(fs, false)) > 0 {
			add(fs)
			*s = string(leakscan.Redact([]byte(*s), nil))
		}
	}
	for i := range out.citations {
		str(&out.citations[i].Title)
		str(&out.citations[i].Snippet)
	}
	for i := range out.links {
		str(&out.links[i].Title)
	}
	for i := range out.images {
		str(&out.images[i].Title)
	}
	for i := range out.quotes {
		str(&out.quotes[i].Text)
	}
	slices.Sort(ids)
	return ids
}

// redactJSONStrings redacts every string in a JSON document, keeping its structure and member order (a span
// can't cut through the JSON syntax). A document that doesn't parse is replaced whole.
func redactJSONStrings(doc string) string {
	dec := jsontext.NewDecoder(strings.NewReader(doc))
	var b bytes.Buffer
	enc := jsontext.NewEncoder(&b)
	for {
		tok, err := dec.ReadToken()
		if err == io.EOF {
			break
		}
		if err != nil {
			return `{"error":"the response was withheld: it contained what looks like a credential"}`
		}
		if tok.Kind() == '"' {
			s := tok.String()
			if r := leakscan.Redact([]byte(s), nil); !bytes.Equal(r, []byte(s)) {
				tok = jsontext.String(string(r))
			}
		}
		if err := enc.WriteToken(tok); err != nil {
			return `{"error":"the response was withheld: it contained what looks like a credential"}`
		}
	}
	return strings.TrimSpace(b.String())
}
