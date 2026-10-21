package runauth

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"sync"
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
	// NotifyLabel: turning run notifications on or off for the space (app/notify.go); own item "on" or "off".
	NotifyLabel = "tacy/v2/notify-set"
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

// ---- personal spaces: the seal key pinned per space ---------------------------------------------------------

// On the shared chat VM a personal space has no signed policy or space log here: a request proves it holds *a* seal
// key for the space it names, and nothing else ties that key to the space. So each personal space is pinned to the
// first seal key proven for it (trust on first use; agentd also seeds the pins from the holders its schedules
// recorded before v0.16.0), and every run, search, pictures request or call naming the space with another seal key
// is refused: someone who knows a space's id can't spend its budget, or fill, change or remove its schedules, with a
// key of their own.
//
// A rotation (a new seal key generation for the space) moves the pin with a reseal call (POST /spaces/reseal) that
// proves both keys: the new one as any call's where and who, the old one with its own space proof against this boot's
// key (an X25519 key can't sign; the proof is how it shows itself). The identity's signature covers both:
//
//	reseal:  "tacy/v2/space-reseal",  old_seal, base64(old_proof)
//
// The pin moves only from the key it holds now: a stale or a third key is refused.
const ResealLabel = "tacy/v2/space-reseal"

// ErrSealPinned: the request's seal key isn't the one pinned for its space.
var ErrSealPinned = errors.New("runauth: the space's seal key isn't the one this VM pinned for it")

// PinStore keeps each personal space's pinned seal key (agentd's side file; MemPins in memory).
type PinStore interface {
	// PinSeal pins seal for space when the space has no pin yet, and returns the space's pin (seal, or the earlier one).
	PinSeal(space, seal string, at time.Time) (pinned string, err error)
	// RepinSeal moves space's pin from old to seal; ErrSealPinned when the pin isn't old. A space without a pin gets
	// seal.
	RepinSeal(space, old, seal string, at time.Time) error
}

// CheckPin pins who's seal key for its space on first use and refuses another one (ErrSealPinned).
func CheckPin(p PinStore, who Who, now time.Time) error {
	pinned, err := p.PinSeal(who.Space, who.Seal, now)
	if err != nil {
		return err
	}
	if pinned != who.Seal {
		return ErrSealPinned
	}
	return nil
}

// ResealItems are a reseal call's own items: the old seal key and its proof.
func ResealItems(oldSeal string, oldProof []byte) []string {
	return []string{oldSeal, base64.StdEncoding.EncodeToString(oldProof)}
}

// CheckReseal verifies a reseal call against this boot's key vm: w proves the new seal key and carries the
// identity's signature over the old key and its proof (ResealItems), and oldProof proves the old key for the same
// space. The nonce is the caller's to claim, and moving the pin (PinStore.RepinSeal) too.
func CheckReseal(vm *ecdh.PrivateKey, w *Where, oldSeal string, oldProof []byte, now time.Time) (Who, error) {
	who, err := CheckCall(vm, ResealLabel, w, now, ResealItems(oldSeal, oldProof)...)
	if err != nil {
		return Who{}, err
	}
	if oldSeal == who.Seal {
		return Who{}, errors.New("runauth: the new seal key is the old one")
	}
	if err := CheckSpaceProof(vm, who.Space, oldSeal, oldProof); err != nil {
		return Who{}, err
	}
	return who, nil
}

// Reseal makes a reseal call moving a's space from its seal key to next, for the VM key vmPub (tests, and what a
// browser that rotates a space's seal key would do). a keeps its old key; the caller switches to next afterwards.
func (a *Asker) Reseal(next *ecdh.PrivateKey, vmPub []byte) (w Where, oldSeal string, oldProof []byte, err error) {
	peer, err := ecdh.X25519().NewPublicKey(vmPub)
	if err != nil {
		return Where{}, "", nil, err
	}
	oldSeal = a.SealString()
	if oldProof, err = SpaceProof(a.Seal, peer, a.Space, oldSeal, vmPub); err != nil {
		return Where{}, "", nil, err
	}
	nextAsker := *a
	nextAsker.Seal = next
	w, err = nextAsker.Call(ResealLabel, vmPub, ResealItems(oldSeal, oldProof)...)
	return w, oldSeal, oldProof, err
}

// MemPins is an in-memory PinStore.
type MemPins struct {
	mu sync.Mutex
	m  map[string]string
}

func (m *MemPins) PinSeal(space, seal string, _ time.Time) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.m == nil {
		m.m = map[string]string{}
	}
	if p, ok := m.m[space]; ok {
		return p, nil
	}
	m.m[space] = seal
	return seal, nil
}

func (m *MemPins) RepinSeal(space, old, seal string, _ time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.m == nil {
		m.m = map[string]string{}
	}
	if p, ok := m.m[space]; ok && p != old {
		return ErrSealPinned
	}
	m.m[space] = seal
	return nil
}
