package approval

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json/v2"
	"errors"
	"slices"
	"time"

	"github.com/tacyhq/tacy/identity"
)

// PayloadType names an approval payload.
const PayloadType = "tacy.approval/v1"

// ChallengeLabel prefixes what an approval's WebAuthn challenge is the hash of.
const ChallengeLabel = "tacy-approval/v1"

// Decisions a person makes.
const (
	Approve = "approve"
	Deny    = "deny"
)

// Payload is what a person's passkey signs (through the challenge): one decision on one held effect. Every field
// is checked against what the checker holds itself; the effect hash is recomputed from the action, never taken from
// the request.
type Payload struct {
	Type       string    `json:"type"`
	Approval   string    `json:"approval"` // ap_
	Firm       string    `json:"firm"`
	Space      string    `json:"space"`
	Task       string    `json:"task"`
	Request    string    `json:"request"` // the held harness request id
	Action     string    `json:"action"`
	EffectHash string    `json:"effect_hash"`
	Decision   string    `json:"decision"` // approve | deny
	Approver   string    `json:"approver"` // i_
	ExpiresAt  time.Time `json:"expires_at"`
}

// Challenge is the WebAuthn challenge for a payload: SHA-256(ChallengeLabel ‖ NUL ‖ payload bytes as signed).
func Challenge(payload []byte) []byte {
	h := sha256.New()
	h.Write([]byte(ChallengeLabel + "\x00"))
	h.Write(payload)
	return h.Sum(nil)
}

// Submission is one person's decision as the browser sends it (POST /approvals): the payload exactly as its
// challenge was made, the passkey's assertion, and the certificate that ties the passkey to the approver.
type Submission struct {
	Payload   []byte     `json:"payload"`
	Assertion Assertion  `json:"assertion"`
	Cert      SignedCert `json:"cert"`
}

// Expect is what a checker holds for one held approval: the payload must match it field for field.
type Expect struct {
	Approval, Firm, Space, Task, Request, Action, EffectHash string
	Approvers                                                []string
	ExpiresAt                                                time.Time
}

// Config is what Check needs: who is current (Dir), which origin and rpId the release pins, and the clock.
type Config struct {
	Dir identity.Directory
	RP  RP
	Now func() time.Time
}

func (c *Config) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

// Errors of Check.
var (
	ErrExpired  = errors.New("approval: expired")
	ErrMismatch = errors.New("approval: payload doesn't match the held effect")
)

// Check verifies a submission against want, on its own (agentd and gatewayd each call it): the payload decodes
// strictly and names exactly the held approval (ids, action, the effect hash the checker computed, the expiry it
// set); the decision is approve or deny; the approver is one of want's; it hasn't expired; the certificate is signed
// by the approver's current identity and names the assertion's credential; the assertion is a user-verified
// WebAuthn assertion over the payload's challenge for the pinned origin and rpId. A deny needs all of it too (only
// the approver may say no). Single use is the caller's: a held approval takes one decision.
func Check(sub *Submission, want Expect, cfg Config) (*Payload, error) {
	if sub == nil || len(sub.Payload) == 0 || len(sub.Payload) > 4<<10 {
		return nil, errors.New("approval: no payload")
	}
	var p Payload
	if err := json.Unmarshal(sub.Payload, &p, json.RejectUnknownMembers(true)); err != nil {
		return nil, errors.New("approval: bad payload")
	}
	if p.Type != PayloadType || p.Approval != want.Approval || p.Firm != want.Firm || p.Space != want.Space ||
		p.Task != want.Task || p.Request != want.Request || p.Action != want.Action || p.EffectHash != want.EffectHash ||
		want.EffectHash == "" || !p.ExpiresAt.Equal(want.ExpiresAt) {
		return nil, ErrMismatch
	}
	if p.Decision != Approve && p.Decision != Deny {
		return nil, errors.New("approval: decision must be approve or deny")
	}
	if !slices.Contains(want.Approvers, p.Approver) {
		return nil, errors.New("approval: not an approver of this effect")
	}
	if !cfg.now().Before(p.ExpiresAt) {
		return nil, ErrExpired
	}
	c, pub, err := sub.Cert.Verify(cfg.Dir, p.Firm, p.Space)
	if err != nil {
		return nil, err
	}
	if c.Identity != p.Approver || c.Credential != sub.Assertion.CredentialID {
		return nil, errors.New("approval: certificate isn't the approver's passkey")
	}
	if err := sub.Assertion.Verify(pub, Challenge(sub.Payload), cfg.RP); err != nil {
		return nil, err
	}
	return &p, nil
}

// ID is an approval's id, derived from the held request so a restarted runtime finds the same one: "ap_" + the
// first 128 bits of HMAC-SHA256(key, "tacy-approval-id/v1" ‖ task ‖ request, each length-prefixed). key is
// agentd's per-firm id key (dstack's KMS).
func ID(key []byte, task, request string) string {
	m := hmac.New(sha256.New, key)
	m.Write([]byte("tacy-approval-id/v1\x00"))
	var n [8]byte
	for _, p := range []string{task, request} {
		binary.BigEndian.PutUint64(n[:], uint64(len(p)))
		m.Write(n[:])
		m.Write([]byte(p))
	}
	return identity.IDFrom("ap", m.Sum(nil))
}

// DefaultTTL is how long an approval may wait (docs/27 section 4: 24 hours by default; a policy may later set 15
// minutes to 7 days). Expired is denied.
const DefaultTTL = 24 * time.Hour
