package split

import (
	"strings"
	"testing"

	"github.com/tacyhq/tacy/kms"
	"github.com/tacyhq/tacy/safety"
)

// A boot set is the same item in the trust list (clients' delay) as in the unlock policy (holders' delay), so one
// emergency item names it in both; the OS image, pre-launch, KMS root and platform items share their prefixes.
func TestTrustItemsMatchPolicyItems(t *testing.T) {
	b := kms.BootSet{Name: "x", OSImage: strings.Repeat("a", 64), MRTD: "1", RTMR0: "2", RTMR1: "3", RTMR2: "4"}
	tb := safety.TrustBoot{Name: "other name", OSImage: b.OSImage, MRTD: b.MRTD, RTMR0: b.RTMR0, RTMR1: b.RTMR1, RTMR2: b.RTMR2, Source: "s"}
	if safety.TrustBootItem(tb) != BootItem(b) {
		t.Fatal("trust-list and policy boot items differ")
	}
	for p, q := range map[string]string{safety.TrustItemOS: ItemOS, safety.TrustItemBoot: ItemBoot, safety.TrustItemPreLaunch: ItemPreLaunch,
		safety.TrustItemKMSRoot: ItemKMSRoot, safety.TrustItemPlatform: ItemPlatform, safety.TrustItemTCBGrace: ItemTCBGrace, safety.TrustItemFloor: ItemFloor} {
		if p != q {
			t.Errorf("prefix %q vs %q", p, q)
		}
	}
}
