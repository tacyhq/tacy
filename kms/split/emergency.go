package split

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"encoding/json"

	"github.com/tacyhq/tacy/kms"
	"github.com/tacyhq/tacy/safety"
)

// The emergency override (the no-downtime plan row 13): an urgent fix may unlock at once, without the
// holders' 24 h pin delay, only when the policy carries an Emergency signed by the KMS id, on top of the policy's
// admin signature. The KMS id's key derives only from M, which only two of the admin's passphrase shares rebuild
// (the same proof as break-glass), so the admin key alone can't skip the delay, and no holder can (they hold epoch
// roots, which don't derive the KMS id). It names the policy seq it is for and the policy items (PolicyItems:
// "release:<sha256>", "os:<hash>", ...) it expedites; every holder alerts when it takes one.

const sigEmergency = "tacy-split/emergency/v1" // Ed25519 label (KMS id): an emergency override

// Emergency expedites Items (policy items of the policy of seq PolicySeq).
type Emergency struct {
	KMSID     string    `json:"kms_id"`
	PolicySeq uint64    `json:"policy_seq"`
	Items     []string  `json:"items"`
	Reason    string    `json:"reason"` // shown in every holder's alert
	IssuedAt  time.Time `json:"issued_at"`
}

// SignedEmergency is an Emergency's exact JSON and the KMS id's signature over label ‖ 0 ‖ doc.
type SignedEmergency struct {
	Doc []byte `json:"doc"`
	Sig []byte `json:"sig"`
}

// NewEmergency signs an override for policy seq and items with the KMS id M derives (M from two passphrase
// shares: kmsctl approve -emergency).
func NewEmergency(master []byte, kmsID string, seq uint64, items []string, reason string, issuedAt time.Time) (*SignedEmergency, error) {
	id, err := checkMaster(master, kmsID)
	if err != nil {
		return nil, err
	}
	defer clear(id)
	e := Emergency{KMSID: kmsID, PolicySeq: seq, Items: items, Reason: reason, IssuedAt: issuedAt.UTC()}
	if err := e.validate(); err != nil {
		return nil, err
	}
	doc, err := json.Marshal(e)
	if err != nil {
		return nil, err
	}
	return &SignedEmergency{Doc: doc, Sig: ed25519.Sign(id, signMessage(sigEmergency, doc))}, nil
}

func (e *Emergency) validate() error {
	if e.PolicySeq == 0 || len(e.Items) == 0 || len(e.Items) > 8 || e.Reason == "" || len(e.Reason) > 200 {
		return errors.New("split: an emergency names its policy seq, 1 to 8 items and a reason (at most 200 bytes)")
	}
	for _, it := range e.Items {
		if !strings.Contains(it, ":") || len(it) > 200 {
			return fmt.Errorf("split: emergency item %q isn't a policy item", it)
		}
	}
	return nil
}

// Open checks the KMS id signed e, for policy p (its seq, and pins it pins), and returns it.
func (e SignedEmergency) Open(kmsID ed25519.PublicKey, p *UnlockPolicy) (*Emergency, error) {
	if len(e.Sig) != ed25519.SignatureSize || !ed25519.Verify(kmsID, signMessage(sigEmergency, e.Doc), e.Sig) {
		return nil, errors.New("split: the emergency override isn't signed by the KMS id (it takes two passphrase shares)")
	}
	var em Emergency
	if err := kms.Strict(e.Doc, &em); err != nil {
		return nil, fmt.Errorf("split: emergency: %w", err)
	}
	if err := em.validate(); err != nil {
		return nil, err
	}
	if em.KMSID != kms.IDString(kmsID) || em.PolicySeq != p.Seq {
		return nil, fmt.Errorf("split: the emergency override is for policy seq %d, not %d", em.PolicySeq, p.Seq)
	}
	items := PolicyItems(p)
	for _, it := range em.Items {
		if !slices.Contains(items, it) {
			return nil, fmt.Errorf("split: the emergency override names %s, which this policy doesn't allow", it)
		}
	}
	return &em, nil
}

// NewTrustEmergency signs the trust list's emergency override (safety.SignedTrustEmergency) for list seq and its
// items with the KMS id M derives: the clients' counterpart of NewEmergency (their 24 h delay on trust-list
// additions, safety/trustdelay.go), under its own label, so neither override stands in for the other.
func NewTrustEmergency(master []byte, kmsID string, seq uint64, items []string, reason string, issuedAt time.Time) (*safety.SignedTrustEmergency, error) {
	id, err := checkMaster(master, kmsID)
	if err != nil {
		return nil, err
	}
	defer clear(id)
	return safety.SignTrustEmergency(id, safety.TrustEmergency{ListSeq: seq, Items: items, Reason: reason, IssuedAt: issuedAt})
}

// NewMachineCert signs a machine certificate (safety.SignedMachineCert, V1-DESIGN §3.2) with the KMS id M derives
// (M from two passphrase shares: kmsctl machine-cert). Only the KMS id makes one; an admin key can't.
func NewMachineCert(master []byte, kmsID string, d safety.MachineDoc) (*safety.SignedMachineCert, error) {
	id, err := checkMaster(master, kmsID)
	if err != nil {
		return nil, err
	}
	defer clear(id)
	return safety.SignMachineCert(id, d)
}
