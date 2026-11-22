package unlock

import (
	"crypto/ed25519"
	"errors"
	"fmt"

	"github.com/tacyhq/tacy/kms"
	"github.com/tacyhq/tacy/kms/split"
	"github.com/tacyhq/tacy/safety"
)

// OpenPolicy is unlockd's reading of the newest unlock policy (what split.Unlock reads too): the admin keys the
// compose pins signed it (privacy review #4: a forged holder list or grant never reaches the VM; nil only for a
// development VM), its form and KMS id, its share sets signed by kmsID. unlockd needs it for the grant (which app,
// firm and purposes its attested app-compose is pinned as) and the holder list; every holder checks it again.
func OpenPolicy(raw []byte, kmsID ed25519.PublicKey, admin *kms.AdminKeys) (*split.UnlockPolicy, []*split.ShareSet, error) {
	var env safety.Envelope
	if err := kms.Strict(raw, &env); err != nil || env.Kind != split.KindUnlockPolicy {
		return nil, nil, errors.New("unlock: not an unlock policy envelope")
	}
	var pol split.UnlockPolicy
	if admin != nil {
		if err := admin.Open(&env, split.KindUnlockPolicy, &pol); err != nil {
			return nil, nil, fmt.Errorf("unlock: policy: %w", err)
		}
	} else if err := kms.Strict(env.Payload, &pol); err != nil {
		return nil, nil, fmt.Errorf("unlock: policy: %w", err)
	}
	if err := pol.Validate(); err != nil {
		return nil, nil, err
	}
	if pol.KMSID != kms.IDString(kmsID) {
		return nil, nil, errors.New("unlock: the policy is for another KMS id")
	}
	sets, err := pol.OpenShareSets(kmsID)
	if err != nil {
		return nil, nil, err
	}
	return &pol, sets, nil
}
