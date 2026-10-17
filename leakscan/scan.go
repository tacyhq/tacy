// Package leakscan finds credentials in text before it crosses the gateway: in an action's arguments on the way
// out (block) and in a connector's response on the way back to the brain (redact). docs/21-gateway-v0.md
// section 2.
//
// The patterns are IronClaw's (patterns.go, MIT, see NOTICE). Unlike upstream, the scanner decodes before it
// scans: percent-encoding (repeated, so double encoding too), HTML character references, JSON and unicode
// escapes, base64 and base64url segments, zero-width characters and look-alike letters. It scans the raw input
// and every decoded form, and reports each finding at its place in the original input, so one encoded character
// no longer gets a key past it.
//
// Findings carry the pattern id, the span and the severity, never the matched value.
//
// Bounds (denial of service): the input is scanned up to MaxInput bytes; decoding goes MaxDepth levels deep;
// the decoded bytes produced and scanned stay under WorkFactor times the input; regexes are Go's RE2, linear in
// the input. Past a bound the scan stops decoding and reports a "scan_limit" finding (Block), so an outbound
// check fails closed. Redact never refuses: it removes what it found and handles any size in windows (Stream).
//
// Not imported by ./app, so it isn't part of the attested compose (cmd/compose). Not wired into guard/ yet.
package leakscan

import (
	"bytes"
	"cmp"
	"encoding/base64"
	"encoding/hex"
	"hash/maphash"
	"net/url"
	"slices"
	"strings"
)

const (
	MaxInput    = 4 << 20 // bytes scanned per call (the harness frame cap); Redact goes past it in windows
	MaxDepth    = 4       // decoding levels: percent of percent of percent of percent, base64 inside percent, ...
	WorkFactor  = 8       // bytes scanned, raw and decoded, as a multiple of the input (each decoded byte is scanned once)
	workSlack   = 64 << 10
	MinBase64   = 16   // base64 segments shorter than this aren't decoded (12 bytes of text)
	probeChars  = 256  // base64 characters decoded to check that a segment reads as text
	MaxFindings = 1000 // findings reported per call; more add a scan_limit finding
)

// Pattern ids that aren't regexes.
const (
	ExactSecret = "exact_secret" // a value passed to ScanWith or Redact, in any encoding
	ScanLimit   = "scan_limit"   // a bound was hit: part of the input wasn't scanned or decoded
)

// Replacement is what Redact puts in place of each match.
const Replacement = "[REDACTED]"

// Finding is one match: which pattern, where in the original input, how bad. Never the value.
type Finding struct {
	Pattern  string
	Offset   int // start in the original input, in bytes
	End      int // end (exclusive) in the original input
	Severity Severity
	Action   Action
	Via      string // the decoding that revealed it ("" when raw; "percent>percent", "base64", ...)
}

// Blocked reports whether any finding asks to block.
func Blocked(fs []Finding) bool {
	for _, f := range fs {
		if f.Action == Block {
			return true
		}
	}
	return false
}

// Scan finds credential patterns in b and in its decoded forms.
func Scan(b []byte) []Finding { return ScanWith(b, nil) }

// ScanWith is Scan plus the exact values given (leased secrets), in any of their encodings.
func ScanWith(b []byte, exact [][]byte) []Finding {
	in := b
	if len(in) > MaxInput {
		in = in[:MaxInput]
	}
	s := newScanner(len(in), exact, true)
	s.run(in)
	if len(b) > MaxInput {
		s.limit(MaxInput)
	}
	return s.result()
}

// Redact returns b with every pattern match that asks to redact or block, and every encoding of each exact
// value, replaced by Replacement. Warn-only matches (64-hex, placeholders) stay. b isn't modified.
func Redact(b []byte, exact [][]byte) []byte {
	if len(b) <= MaxInput {
		s := newScanner(len(b), exact, false)
		s.run(b)
		return apply(b, s.spans)
	}
	st := NewStream(exact)
	out := st.Write(b)
	return append(out, st.Flush()...)
}

// Variants are the forms a secret takes when echoed back: raw, base64 (standard and URL, padded or not), hex
// (lower and upper) and percent-encoded (query and path style). Longest first, so a longer encoding is replaced
// before a shorter form that is part of it. Other encodings (lowercase or full percent-encoding, HTML, escapes,
// base64 inside percent, ...) are caught by searching every decoded view for these forms.
func Variants(v []byte) [][]byte {
	if len(v) == 0 {
		return nil
	}
	forms := []string{
		string(v),
		base64.StdEncoding.EncodeToString(v),
		base64.RawStdEncoding.EncodeToString(v),
		base64.URLEncoding.EncodeToString(v),
		base64.RawURLEncoding.EncodeToString(v),
		hex.EncodeToString(v),
		strings.ToUpper(hex.EncodeToString(v)),
		url.QueryEscape(string(v)),
		url.PathEscape(string(v)),
	}
	var out [][]byte
	for _, f := range forms {
		if !slices.ContainsFunc(out, func(o []byte) bool { return string(o) == f }) {
			out = append(out, []byte(f))
		}
	}
	slices.SortStableFunc(out, func(a, b []byte) int { return cmp.Compare(len(b), len(a)) })
	return out
}

type span struct{ s, e int }

type findKey struct {
	p    string
	s, e int
}

type segKey struct {
	h    uint64
	s, e int
}

type scanner struct {
	exact    [][]byte
	findings bool // collect findings (Scan) or only spans (Redact)
	work     int
	budget   int
	limited  bool
	spans    []span
	found    []Finding
	seen     map[findKey]struct{}
	segs     map[segKey]struct{}
	seed     maphash.Seed
}

func newScanner(n int, exact [][]byte, findings bool) *scanner {
	s := &scanner{findings: findings, budget: WorkFactor*n + workSlack, seen: map[findKey]struct{}{},
		segs: map[segKey]struct{}{}, seed: maphash.MakeSeed()}
	for _, e := range exact {
		s.exact = append(s.exact, Variants(e)...)
	}
	slices.SortStableFunc(s.exact, func(a, b []byte) int { return cmp.Compare(len(b), len(a)) })
	return s
}

func (s *scanner) limit(at int) {
	s.limited = true
	s.add(Finding{Pattern: ScanLimit, Offset: at, End: at, Severity: High, Action: Block}, false)
}

// add records a finding; redact says whether its span is to be removed.
func (s *scanner) add(f Finding, redact bool) {
	if redact {
		s.spans = append(s.spans, span{f.Offset, f.End})
	}
	if !s.findings {
		return
	}
	k := findKey{f.Pattern, f.Offset, f.End}
	if _, ok := s.seen[k]; ok {
		return
	}
	if len(s.found) >= MaxFindings && f.Pattern != ScanLimit {
		if !s.limited {
			s.limit(f.Offset)
		}
		return
	}
	s.seen[k] = struct{}{}
	s.found = append(s.found, f)
}

func (s *scanner) result() []Finding {
	slices.SortStableFunc(s.found, func(a, b Finding) int {
		return cmp.Or(cmp.Compare(a.Offset, b.Offset), cmp.Compare(a.End, b.End), strings.Compare(a.Pattern, b.Pattern))
	})
	return s.found
}

// spend takes n bytes of work from the budget; false (and a scan_limit finding) when it's spent.
func (s *scanner) spend(n int) bool {
	if s.work+n > s.budget {
		s.over()
		return false
	}
	s.work += n
	return true
}

// over records that the work budget ran out: decoding stops, what is queued is still scanned.
func (s *scanner) over() {
	if !s.limited {
		s.limit(0)
	}
}

// run scans the input and its decoded views, breadth first: shallow decodings before deep ones.
func (s *scanner) run(raw []byte) {
	queue := []*view{{b: raw}}
	s.work = len(raw)
	for len(queue) > 0 {
		v := queue[0]
		queue = queue[1:]
		s.scan(v)
		if v.depth >= MaxDepth || s.limited {
			continue
		}
		if next := level(v); next != nil {
			if !s.spend(len(next.b)) {
				continue
			}
			queue = append(queue, next)
		}
		queue = append(queue, s.base64(v)...)
	}
}

// base64 decodes v's base64 segments that read as text. A segment's first character isn't always where its
// encoding starts (letters right before it, or a stream window starting mid-run), so when the decoding from the
// first character isn't text, the next three alignments are tried. Each alignment is probed on its first
// probeChars characters before the whole run is decoded, so binary (images in data URIs) costs little.
func (s *scanner) base64(v *view) []*view {
	var out []*view
	for _, r := range b64runs(v.b, MinBase64) {
		os, oe := v.span(r.from, r.to)
		k := segKey{maphash.Bytes(s.seed, v.b[r.from:r.to]), os, oe}
		if _, ok := s.segs[k]; ok {
			continue
		}
		s.segs[k] = struct{}{}
		for sh := 0; sh < 4 && len(r.pos)-sh >= MinBase64; sh++ {
			probe := b64run{pos: r.pos[:min(len(r.pos), sh+probeChars)]}
			if !s.spend(len(probe.pos)-sh) || !textLike(decodeRun(v, probe, sh).b) {
				continue
			}
			if !s.spend(len(r.pos) * 3 / 4) {
				return out
			}
			d := decodeRun(v, r, sh)
			if !textLike(d.b) {
				continue
			}
			d.via = joinVia(v.via, "base64")
			d.depth = v.depth + 1
			out = append(out, d)
			break
		}
	}
	return out
}

// scan runs every pattern and searches every exact form over one view.
func (s *scanner) scan(v *view) {
	for i := range patterns {
		p := &patterns[i]
		for _, m := range p.find(v.b) {
			if p.jwt && !hasJWTHeader(v.b[m[0]:m[1]]) {
				continue
			}
			os, oe := v.span(m[0], m[1])
			s.add(Finding{Pattern: p.ID, Offset: os, End: oe, Severity: p.Severity, Action: p.Action, Via: v.via},
				p.Action != Warn)
		}
	}
	for _, x := range s.exact {
		for i := 0; ; {
			k := bytes.Index(v.b[i:], x)
			if k < 0 {
				break
			}
			os, oe := v.span(i+k, i+k+len(x))
			s.add(Finding{Pattern: ExactSecret, Offset: os, End: oe, Severity: Critical, Action: Block, Via: v.via}, true)
			i += k + len(x)
		}
	}
}

// merge sorts spans and joins overlapping or touching ones (upstream merge_ranges), so one secret matched by
// two patterns, or by its raw and decoded forms, becomes one Replacement.
func merge(sp []span) []span {
	sp = slices.Clone(sp)
	slices.SortFunc(sp, func(a, b span) int { return cmp.Compare(a.s, b.s) })
	var out []span
	for _, x := range sp {
		if x.e <= x.s {
			continue
		}
		if n := len(out); n > 0 && x.s <= out[n-1].e {
			out[n-1].e = max(out[n-1].e, x.e)
			continue
		}
		out = append(out, x)
	}
	return out
}

// apply replaces the merged spans in b (all within b).
func apply(b []byte, sp []span) []byte {
	out := make([]byte, 0, len(b))
	last := 0
	for _, x := range merge(sp) {
		out = append(out, b[last:x.s]...)
		out = append(out, Replacement...)
		last = x.e
	}
	return append(out, b[last:]...)
}
