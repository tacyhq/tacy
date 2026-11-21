package unlock_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/tacyhq/tacy/gateway"
	"github.com/tacyhq/tacy/unlock"
)

// Two unlocked VMs never both fire a space's schedules: the ownership row at the Worker goes to one, is renewed by
// it, and passes to the other only once it lapses.
func TestScheduleOwnership(t *testing.T) {
	r := newRig(t, []string{"cloudflare", "vercel"}, 2)
	u := r.unlocker(nil)
	r.run(u, 30*time.Second)
	k := r.mustKeys(u, unlock.RoleAgent)
	auth, err := k.StoreAuth("state/v1", r.w.Now)
	if err != nil {
		t.Fatal(err)
	}
	hc := gateway.StateHTTP{D: gateway.FixedGate{D: r.fixed, Allow: gateway.AgentCalls}}
	a := &unlock.Owner{Client: hc, Auth: auth, ID: "app/inst-a", Now: r.w.Now}
	b := &unlock.Owner{Client: hc, Auth: auth, ID: "app/inst-b", Now: r.w.Now}
	ctx := context.Background()
	if !a.Holds(ctx, "s_one") || b.Holds(ctx, "s_one") {
		t.Fatal("both or neither VM holds the space")
	}
	if !b.Holds(ctx, "s_two") {
		t.Fatal("another space is free")
	}
	r.w.Advance(3 * time.Minute) // past half the claim: a renews
	if !a.Holds(ctx, "s_one") || b.Holds(ctx, "s_one") {
		t.Fatal("a's renewal")
	}
	r.w.Advance(unlock.OwnerTTL + time.Second) // a stopped renewing: its row lapses
	if !b.Holds(ctx, "s_one") || a.Holds(ctx, "s_one") {
		t.Fatal("the row didn't pass after it lapsed")
	}
	// An unsigned claim is refused.
	c := &unlock.Owner{Client: hc, ID: "app/inst-c", Now: r.w.Now}
	if c.Holds(ctx, "s_three") {
		t.Fatal("an unsigned claim was taken")
	}
	for n := range r.worker.Owners() {
		if strings.Contains(n, "s_one") {
			t.Fatal("a space id at the Worker")
		}
	}
}
