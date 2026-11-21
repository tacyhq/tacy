package unlock

import (
	"testing"
	"time"

	"github.com/tacyhq/tacy/kms/split"
)

// The witnesses' head reaches each process as floors for its own sealed states only.
func TestHeadFloorsByRole(t *testing.T) {
	k := &Keyring{Keys: map[string][]byte{}, Floors: headFloors(&split.StateHead{Counter: 3, At: time.Now(),
		Names: map[string]split.HeadEntry{"state/side": {Gen: 7}, "state/activity": {Gen: 4}, "conn/connections": {Gen: 2}}})}
	a, err := k.For(RoleAgent)
	if err != nil || len(a.Floors) != 2 || a.Floors["side"] != 7 || a.Floors["activity"] != 4 {
		t.Fatalf("agentd's floors %v %v", a.Floors, err)
	}
	v, err := k.For(RoleVault)
	if err != nil || len(v.Floors) != 1 || v.Floors["connections"] != 2 {
		t.Fatalf("vaultd's floors %v %v", v.Floors, err)
	}
	if headFloors(nil) != nil {
		t.Fatal("no head, floors")
	}
}
