package main

import (
	"context"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"sync"

	"github.com/tacyhq/tacy/unlock"
)

// KeySource gives agentd its lasting keys. Nothing it keeps may be protected by a provider's keys ("Keys:
// never a provider's", the keys plan): no dstack GetKey, no Phala KMS, no cloud KMS. On the CVM the keys come from
// unlockd (unlockKeys: the split-key unlock's epoch root R_e, the keys plan §11.2), so activity records and task ids keep
// their keys across restarts, releases and app ids, and sealed state opens again on any VM the holders unlock.
// Without it (-unlock-socket unset: local runs and the memory-only quick path) the
// keys are made fresh at each boot in this TD and never stored (bootKeys): a new activity chain each boot, and task
// ids that are once-only within a boot.
type KeySource interface {
	// Key is 32 bytes of key material for purpose (one of the Purpose constants), the same for every call in a boot.
	Key(ctx context.Context, purpose string) ([]byte, error)
	// Binding is what sealed state is bound to besides its key (sealstate's AAD): the key service's app name, the
	// same on every instance and release of the app; "" for boot keys.
	Binding() string
	// Lasting: the keys are the same after a restart (the key service), so sealed state can be kept. Boot keys
	// aren't: state sealed under them could never open again, so agentd keeps everything in memory with them.
	Lasting() bool
}

// The purposes agentd asks for (the keys plan §2.4). vaultd asks for conn/v1 itself; agentd never holds it.
const (
	PurposeState    = "state/v1"
	PurposeActivity = "activity-sign/v1"
	PurposeTaskIDs  = "task-ids/v1"
)

// agentPurposes is agentd's whole release.
var agentPurposes = []string{PurposeState, PurposeActivity, PurposeTaskIDs}

// unlockKeys are agentd's keys from unlockd (the split-key unlock, the keys plan §11.2).
type unlockKeys struct{ *unlock.Keys }

func (k unlockKeys) Binding() string { return k.App }
func (unlockKeys) Lasting() bool     { return true }

// floors are the lowest generations of agentd's sealed states unlockd hands on (none since the legacy witness went).
func (k unlockKeys) floors() map[string]uint64 { return k.Floors }

// bootKeys is the KeySource without a key service: random keys made at first use, in memory only.
type bootKeys struct {
	mu   sync.Mutex
	keys map[string][]byte
}

func newBootKeys() *bootKeys { return &bootKeys{keys: map[string][]byte{}} }

func (b *bootKeys) Binding() string { return "" }
func (b *bootKeys) Lasting() bool   { return false }

func (b *bootKeys) Key(_ context.Context, purpose string) ([]byte, error) {
	if purpose == "" {
		return nil, errors.New("keys: no purpose")
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	k, ok := b.keys[purpose]
	if !ok {
		k = make([]byte, 32)
		if _, err := rand.Read(k); err != nil {
			return nil, err
		}
		b.keys[purpose] = k
	}
	return append([]byte(nil), k...), nil
}

// devKeys is a lasting KeySource from one seed (-platform local only: -dev-state-key), so local runs can keep sealed
// state in a directory across restarts. Never on the CVM.
type devKeys struct{ seed []byte }

func (d devKeys) Key(_ context.Context, purpose string) ([]byte, error) {
	if purpose == "" {
		return nil, errors.New("keys: no purpose")
	}
	return hkdf.Key(sha256.New, d.seed, nil, "tacy-dev-keys/v1\x00"+purpose, 32)
}
func (devKeys) Binding() string { return "dev" }
func (devKeys) Lasting() bool   { return true }
