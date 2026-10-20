package guard

import (
	"testing"
	"time"

	"github.com/tacyhq/tacy/proto"
)

// testSpace is the space the guard's tests run in (keys v2 slice 6: every run names one; agentd proves it, a guard
// alone takes it as named).
const testSpace = "s_test"

// Keys v2 slice 6: no run without a space, and the one agentd verified wins over what the request names.
func TestStartForSpace(t *testing.T) {
	msgs := []proto.Message{{Role: "user", Content: "hi"}}
	if _, _, err := StartFor(&proto.RunRequest{Messages: msgs}, time.Now()); err == nil {
		t.Fatal("a run without a space started")
	}
	s, _, err := StartFor(&proto.RunRequest{Space: testSpace, Messages: msgs}, time.Now())
	if err != nil || s.Space != testSpace {
		t.Fatalf("named: %q %v", s.Space, err)
	}
	s, _, err = StartFor(&proto.RunRequest{Space: "s_other", Messages: msgs, Verified: &proto.Verified{Space: testSpace}}, time.Now())
	if err != nil || s.Space != testSpace {
		t.Fatalf("verified: %q %v", s.Space, err)
	}
}
