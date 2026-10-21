package runauth

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"time"
)

// Schedule calls (v0.12.0, docs/30 "Scheduled tasks"; the contract is in the chat's repository): installing,
// listing, stopping and removing a personal space's schedules and fetching their sealed results carry the same where
// and who as a run, each call under its own label, followed by the call's own items:
//
//	install:         "tacy/v2/schedule-install",         the definition envelope's hash (safety.Envelope.Hash)
//	list:            "tacy/v2/schedule-list",            (none)
//	stop:            "tacy/v2/schedule-stop",            agent
//	remove:          "tacy/v2/schedule-remove",          agent
//	results:         "tacy/v2/schedule-results",         after (decimal)
//	result:          "tacy/v2/schedule-result",          task
//	results delete:  "tacy/v2/schedule-results-delete",  the task ids joined by ","
//
// so no signature made for one call passes for another, or for a run.
const (
	InstallLabel       = "tacy/v2/schedule-install"
	ListLabel          = "tacy/v2/schedule-list"
	StopLabel          = "tacy/v2/schedule-stop"
	RemoveLabel        = "tacy/v2/schedule-remove"
	ResultsLabel       = "tacy/v2/schedule-results"
	ResultLabel        = "tacy/v2/schedule-result"
	ResultsDeleteLabel = "tacy/v2/schedule-results-delete"
)

// Where is a schedule call's where and who, as a run request has them (the JSON field names are the run's).
type Where struct {
	Space       string `json:"space"`
	SpaceSeal   string `json:"space_seal"`
	SpaceProof  []byte `json:"space_proof"`
	Identity    string `json:"identity"`
	IdentityKey string `json:"identity_key"`
	Nonce       string `json:"nonce"`
	SignedAt    int64  `json:"signed_at"`
	IdentitySig []byte `json:"identity_sig"`
}

func (w *Where) fields() fields {
	return fields{w.Space, w.SpaceSeal, w.SpaceProof, w.Identity, w.IdentityKey, w.Nonce, w.SignedAt, w.IdentitySig}
}

// CallDigest is a schedule call's digest for vmPub: label, the VM key, w's where and who, then items.
func CallDigest(label string, vmPub []byte, w *Where, items ...string) [32]byte {
	return digest(label, vmPub, w.fields(), items...)
}

// SignCall is the browser's side (tests, and what the chat does): the identity's signature over a call.
func SignCall(priv ed25519.PrivateKey, label string, w *Where, vmPub []byte, items ...string) []byte {
	return ed25519.Sign(priv, signed(label, CallDigest(label, vmPub, w, items...)))
}

// CheckCall verifies a schedule call's where and who against this boot's EHBP key vm at now, as Check does for a
// run (the nonce is the caller's to claim).
func CheckCall(vm *ecdh.PrivateKey, label string, w *Where, now time.Time, items ...string) (Who, error) {
	return check(vm, w.fields(), label, CallDigest(label, vm.PublicKey().Bytes(), w, items...), now)
}

// Call makes a schedule call's where and who for the VM key vmPub under label, signed over items (tests, and what
// the chat does in TypeScript).
func (a *Asker) Call(label string, vmPub []byte, items ...string) (Where, error) {
	f, err := a.where(vmPub)
	if err != nil {
		return Where{}, err
	}
	w := Where{Space: f.Space, SpaceSeal: f.SpaceSeal, SpaceProof: f.SpaceProof, Identity: f.Identity, IdentityKey: f.IdentityKey,
		Nonce: f.Nonce, SignedAt: f.SignedAt}
	w.IdentitySig = SignCall(a.Key, label, &w, vmPub, items...)
	return w, nil
}
