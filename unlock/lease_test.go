package unlock

import (
	"testing"

	"github.com/tacyhq/tacy/kmsvm"
)

// The writer lease's row name: the VM's (app/lease.go leaseScope), the stand-in's (kmsvm) and the Worker's (apps/chat
// vm-lease.ts leaseName; test/worker/vm-lease.test.ts holds the same constant) are one.
func TestLeaseNameShared(t *testing.T) {
	const want = "o8d69409813c77f0a37ed602a5e390485f749002c5e20ecb7"
	if LeaseName("state/all") != want || kmsvm.LeaseAllName != want {
		t.Fatalf("VM %s, stand-in %s, want %s", LeaseName("state/all"), kmsvm.LeaseAllName, want)
	}
	if LeaseName("state/all") == OwnerName("state/all") {
		t.Fatal("a lease row and a space's ownership row share a name")
	}
}
