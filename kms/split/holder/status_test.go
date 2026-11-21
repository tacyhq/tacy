package holder

import (
	"context"
	"strings"
	"testing"
)

// /v1/status reports the holder's policy seq and build; a build the policy doesn't pin for it alerts.
func TestStatusAndBuildPin(t *testing.T) {
	r := newRig(t, twoOfTwo, 2)
	build := strings.Repeat("b", 64)
	r.holders["vercel"] = r.newHolder("vercel", func(c *Config) { c.Build = build })
	if st := r.holders["vercel"].Status(context.Background()); st.PolicySeq != 0 || st.Build != build {
		t.Fatalf("status before any policy: %+v", st)
	}
	r.pol.Holders[1].Build = strings.Repeat("c", 64) // the pinned build is another one
	r.push(t)
	if st := r.holders["vercel"].Status(context.Background()); st.PolicySeq != r.pol.Seq {
		t.Fatalf("status after a push: %+v", st)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	found := false
	for _, e := range r.events {
		found = found || e.Holder == "vercel" && e.Kind == "change" && strings.Contains(e.Reason, "runs build "+build)
	}
	if !found {
		t.Fatal("a build the policy doesn't pin should alert")
	}
}
