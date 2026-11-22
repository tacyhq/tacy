package safety

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"maps"
)

// The overlap's end, signed (routing re-review M1): a Fix B build accepts the KMS-fallback release v0.20.0 by its
// exact pins until a fixed date (verifier/overlap.go). Routing keeps v1 builds off it, but routing runs on Cloudflare,
// so a hostile Cloudflare could send a v1 build there until that date. The admin key ends the overlap early by
// signing a trust list with the optional member "overlap_ended": true. A Fix B build that has verified such a list
// refuses v0.20.0 from then on:
//
//   - at once: an ending narrows trust, so it gets no 24 h delay;
//   - for good: the verifier keeps it in its own record (TrustSeen.OverlapEnded), which a device keeps with its last
//     list (client-core trust-list.ts), so a later list without the member, or an older one replayed, doesn't bring
//     the overlap back. There is no way to sign it back on;
//   - only in builds that read it: an older build ignores the optional member (the overlap ends there on its date).

// TrustOverlapEndedMember is the optional member that ends the KMS-fallback overlap ("overlap_ended": true).
const TrustOverlapEndedMember = "overlap_ended"

// OverlapEnded says whether l ends the overlap (its optional member overlap_ended is true).
func (l *TrustList) OverlapEnded() bool {
	if l == nil {
		return false
	}
	raw, ok := l.Optional[TrustOverlapEndedMember]
	var v bool
	return ok && json.Unmarshal(raw, &v) == nil && v
}

// checkOverlapEnded: the member, when present, is exactly true (false can't turn an ending off, so it isn't signed).
func (l *TrustList) checkOverlapEnded() error {
	if raw, ok := l.Optional[TrustOverlapEndedMember]; ok {
		var v bool
		if json.Unmarshal(raw, &v) != nil || !v {
			return errors.New(`trust list: overlap_ended must be true (an ended overlap can't be turned back on)`)
		}
	}
	return nil
}

// SetOverlapEnded makes l end the overlap (kmsctl approve -end-overlap).
func (l *TrustList) SetOverlapEnded() {
	l.Optional = maps.Clone(l.Optional)
	if l.Optional == nil {
		l.Optional = map[string]jsontext.Value{}
	}
	l.Optional[TrustOverlapEndedMember] = jsontext.Value("true")
}
