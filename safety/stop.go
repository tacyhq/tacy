package safety

import (
	"crypto/ed25519"
	"encoding/json/v2"
	"errors"
	"time"
)

// StopType names this stop list format.
const StopType = "tacy.stop/v1"

// Stop list issuers.
const (
	IssuerOperator = "operator" // us: a global stop or a stop for a firm or space (availability only)
	IssuerFirm     = "firm"     // the firm's admins: their whole firm or some spaces
)

// MaxStopLifetime bounds an operator list's validity: it is a heartbeat, signed again and again.
const MaxStopLifetime = time.Hour

// StopList is a signed list of what must stop. The newest list of each issuer replaces the older one (Seq only
// goes up). The operator's list also proves freshness: it expires soon after it's signed, and a VM whose newest
// operator list is stale stops side effects (and reads, unless the policy allows them).
type StopList struct {
	Type      string    `json:"type"`
	Issuer    string    `json:"issuer"`
	Firm      string    `json:"firm,omitzero"` // firm lists: the firm
	Seq       uint64    `json:"seq"`
	IssuedAt  time.Time `json:"issued_at"`
	ExpiresAt time.Time `json:"expires_at,omitzero"` // required for the operator's list
	// All stops everything the issuer covers: every firm (operator) or the whole firm (firm).
	All  bool     `json:"all,omitzero"`
	Stop []Target `json:"stop,omitzero"`
}

// Target is a firm (Space "") or one of its spaces. In a firm's list, Firm must be the list's.
type Target struct {
	Firm  string `json:"firm"`
	Space string `json:"space,omitzero"`
}

// Validate checks a stop list's shape.
func (l *StopList) Validate() error {
	switch {
	case l.Type != StopType:
		return errors.New("stop list: type must be " + StopType)
	case l.Seq == 0 || l.IssuedAt.IsZero():
		return errors.New("stop list: seq and issued_at are required")
	case len(l.Stop) > 256:
		return errors.New("stop list: too many targets")
	}
	switch l.Issuer {
	case IssuerOperator:
		if l.Firm != "" || l.ExpiresAt.IsZero() || !l.ExpiresAt.After(l.IssuedAt) || l.ExpiresAt.Sub(l.IssuedAt) > MaxStopLifetime {
			return errors.New("stop list: an operator list has no firm and expires within an hour of issue")
		}
		// Its seq is its signing time in ms (one more than the last when lists come faster). A seq far past its
		// issued_at would raise the floor so high that no later list could pass it, and the VM would stay stale
		// until its disk was wiped: refused.
		if l.Seq > uint64(max(0, l.IssuedAt.Add(MaxSkew).UnixMilli())) {
			return errors.New("stop list: an operator list's seq can't be ahead of its issued_at (in ms) by more than 5 minutes")
		}
	case IssuerFirm:
		if !ValidID(l.Firm) {
			return errors.New("stop list: a firm list names its firm")
		}
	default:
		return errors.New("stop list: issuer must be operator or firm")
	}
	for _, t := range l.Stop {
		if !ValidID(t.Firm) || t.Space != "" && !ValidID(t.Space) || l.Issuer == IssuerFirm && t.Firm != l.Firm {
			return errors.New("stop list: bad target")
		}
	}
	return nil
}

// stops: whether the list stops space in firm.
func (l *StopList) stops(firm, space string) bool {
	if l == nil {
		return false
	}
	if l.All {
		return true
	}
	for _, t := range l.Stop {
		if t.Firm == firm && (t.Space == "" || t.Space == space) {
			return true
		}
	}
	return false
}

// Heartbeat is the operator's stop list signed at now: seq (0: now in ms), expiring ttl later, all stopping
// everything. cmd/safetysign and the operator's Worker (WebCrypto) make it; both give the same bytes for the same
// inputs (testdata/heartbeat-golden.json pins them, and the Worker's test checks that file).
func Heartbeat(key ed25519.PrivateKey, seq uint64, now time.Time, ttl time.Duration, all bool) (Envelope, error) {
	now = now.UTC()
	if seq == 0 {
		seq = uint64(now.UnixMilli())
	}
	l := StopList{Type: StopType, Issuer: IssuerOperator, Seq: seq, IssuedAt: now, ExpiresAt: now.Add(ttl), All: all}
	if err := l.Validate(); err != nil {
		return Envelope{}, err
	}
	b, err := json.Marshal(l)
	if err != nil {
		return Envelope{}, err
	}
	return Sign(KindStop, b, key), nil
}
