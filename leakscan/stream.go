package leakscan

import (
	"cmp"
	"slices"
	"strings"
)

const (
	// Hold is how much of the stream is kept back after each pass: a match (or an encoded secret) split across
	// chunks is found once both halves are in, as long as it is shorter than Hold. Real keys, tokens and PEM
	// blocks are well under it.
	Hold = 16 << 10
	// Step is how much new data a pass waits for, so tiny chunks don't rescan the held bytes each time.
	Step = 64 << 10
)

// hold and step are Hold and Step; tests shrink them to put window edges inside matches.
var hold, step = Hold, Step

// Stream redacts a response that arrives in chunks (Write each chunk, then Flush), catching secrets split across
// chunk boundaries. Output comes out in order, delayed by up to Hold plus Step bytes. Joined, it is what Redact
// returns for the whole input whenever each match (in its encoded form) is shorter than Hold; a match longer than
// MaxInput is cut at a window edge.
// Rescanning stays linear: each pass scans the held bytes plus at least as many new ones.
//
// Not safe for concurrent use.
type Stream struct {
	exact    [][]byte
	buf      []byte // bytes not yet emitted
	base     int    // stream offset of buf[0]
	pending  int    // bytes at the end of buf that no pass has scanned yet
	found    []Finding
	seen     map[findKey]struct{}
	overflow bool
}

// NewStream starts a stream that redacts like Redact(_, exact).
func NewStream(exact [][]byte) *Stream {
	return &Stream{exact: exact, seen: map[findKey]struct{}{}}
}

// Write adds a chunk and returns the redacted bytes that are now safe to pass on (often none).
func (st *Stream) Write(p []byte) []byte {
	st.buf = append(st.buf, p...)
	st.pending += len(p)
	var out []byte
	for {
		held := len(st.buf) - st.pending
		if len(st.buf) <= MaxInput && (st.pending < step || st.pending < held) {
			return out
		}
		out = append(out, st.pass(false)...)
	}
}

// Flush returns the rest, redacted. The stream is empty afterwards.
func (st *Stream) Flush() []byte {
	var out []byte
	for len(st.buf) > 0 {
		out = append(out, st.pass(true)...)
	}
	st.pending = 0
	return out
}

// Findings returns what the stream has found so far in the bytes it emitted, with offsets in the whole stream.
func (st *Stream) Findings() []Finding {
	out := slices.Clone(st.found)
	slices.SortStableFunc(out, func(a, b Finding) int {
		return cmp.Or(cmp.Compare(a.Offset, b.Offset), cmp.Compare(a.End, b.End), strings.Compare(a.Pattern, b.Pattern))
	})
	return out
}

// pass scans a window from the start of buf and emits it up to a cut: Hold bytes before the end, moved back to
// the start of any match that crosses it. When final and the window is all of buf, it emits everything.
func (st *Stream) pass(final bool) []byte {
	w := st.buf
	if len(w) > MaxInput {
		w = w[:MaxInput]
	}
	s := newScanner(len(w), st.exact, true)
	s.run(w)
	spans := merge(s.spans)
	cut := len(w)
	if !final || len(w) < len(st.buf) {
		cut = len(w) - hold
		for moved := true; moved && cut > 0; {
			moved = false
			for _, x := range spans {
				if x.s < cut && x.e > cut {
					cut, moved = x.s, true
				}
			}
			for _, f := range s.found {
				if f.Offset < cut && f.End > cut {
					cut, moved = f.Offset, true
				}
			}
		}
		if cut <= 0 {
			if len(w) < MaxInput {
				st.pending = len(st.buf) - len(w) // wait for at least as much new data as is held
				return nil
			}
			cut = len(w) // one match as long as the window: emit it redacted
		}
	}
	var keep []span
	for _, x := range spans {
		if x.e <= cut {
			keep = append(keep, x)
		}
	}
	out := apply(w[:cut], keep)
	for _, f := range s.found {
		if f.Offset >= cut && f.Pattern != ScanLimit {
			continue
		}
		f.Offset += st.base
		f.End += st.base
		k := findKey{f.Pattern, f.Offset, f.End}
		if _, ok := st.seen[k]; ok {
			continue
		}
		if len(st.found) >= MaxFindings {
			if !st.overflow {
				st.overflow = true
				st.found = append(st.found, Finding{Pattern: ScanLimit, Offset: f.Offset, End: f.Offset, Severity: High, Action: Block})
			}
			continue
		}
		st.seen[k] = struct{}{}
		st.found = append(st.found, f)
	}
	st.buf = append([]byte(nil), st.buf[cut:]...)
	st.base += cut
	st.pending = len(st.buf) - (len(w) - cut) // bytes past the window weren't scanned yet
	return out
}
