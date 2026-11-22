package unlock

import (
	"testing"
)

// Floors reach each process for its own sealed states only.
func TestFloorsByRole(t *testing.T) {
	k := &Keyring{Keys: map[string][]byte{}, Floors: map[string]uint64{"state/side": 7, "state/activity": 4, "conn/connections": 2}}
	a, err := k.For(RoleAgent)
	if err != nil || len(a.Floors) != 2 || a.Floors["side"] != 7 || a.Floors["activity"] != 4 {
		t.Fatalf("agentd's floors %v %v", a.Floors, err)
	}
	v, err := k.For(RoleVault)
	if err != nil || len(v.Floors) != 1 || v.Floors["connections"] != 2 {
		t.Fatalf("vaultd's floors %v %v", v.Floors, err)
	}
}
