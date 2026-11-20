package main

import (
	"context"
	"crypto/rand"
	"errors"
	"sync"
)

// KeySource gives agentd its lasting keys. Nothing it keeps may be protected by a provider's keys ("Keys:
// never a provider's", the keys plan): no dstack GetKey, no Phala KMS, no cloud KMS. The keys come from the Tacy key
// service (kms/, an attested release of its own) or, until it is wired in, are made fresh at each
// boot in this TD and never stored (bootKeys): a new activity chain each boot, and task ids that are once-only within
// a boot (the queue is memory only, so a task never outlives the boot anyway).
//
// TODO(kms): wire in the Tacy key service's client here (kms/ exports a KeySource: Key(ctx, purpose) for these
// purposes, released only to an attested tacy release holding the instance lease). Then main uses it instead of
// bootKeys, and activity records and task ids keep their keys across restarts, releases and app ids.
type KeySource interface {
	// Key is 32 bytes of key material for purpose (one of the Purpose constants), the same for every call in a boot.
	Key(ctx context.Context, purpose string) ([]byte, error)
}

// The purposes agentd asks for (the keys plan §2.4).
const (
	PurposeActivity = "activity-sign/v1"
	PurposeTaskIDs  = "task-ids/v1"
)

// bootKeys is the KeySource without a key service: random keys made at first use, in memory only.
type bootKeys struct {
	mu   sync.Mutex
	keys map[string][]byte
}

func newBootKeys() *bootKeys { return &bootKeys{keys: map[string][]byte{}} }

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
