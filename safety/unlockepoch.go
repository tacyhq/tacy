package safety

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"fmt"
)

// TrustMinUnlockEpochMember is the trust list's optional member that retires old key epochs at clients (gcp-prod
// review H1, review M1): a client accepts a Google VM's unlock proof (proto.UnlockProof) only of this epoch or a
// later one, on top of the attested compose's unlockd -min-epoch. After a leaked epoch root R_e and the re-split to
// e+1, the list names e+1, so proofs signed with the old epoch's activity signer stop counting at once, whatever
// release a forged quote claims. Optional: a build that doesn't read it accepts no proof at all. A JSON number.
const TrustMinUnlockEpochMember = "min_unlock_epoch"

// MinUnlockEpoch is the list's minimum unlock epoch (0: none named).
func (l *TrustList) MinUnlockEpoch() (uint32, error) {
	raw, ok := l.Optional[TrustMinUnlockEpochMember]
	if !ok {
		return 0, nil
	}
	var e uint32
	if err := strict(raw, &e); err != nil || e == 0 {
		return 0, fmt.Errorf("trust list %d: %s must be an epoch (a number above 0)", l.Seq, TrustMinUnlockEpochMember)
	}
	return e, nil
}

// SetMinUnlockEpoch names e as the list's minimum unlock epoch (before l is signed).
func (l *TrustList) SetMinUnlockEpoch(e uint32) error {
	if e == 0 {
		return fmt.Errorf("trust list: %s must be above 0", TrustMinUnlockEpochMember)
	}
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	if l.Optional == nil {
		l.Optional = map[string]jsontext.Value{}
	}
	l.Optional[TrustMinUnlockEpochMember] = jsontext.Value(b)
	return nil
}
