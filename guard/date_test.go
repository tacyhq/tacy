package guard

import (
	"strings"
	"testing"
	"time"

	"github.com/tacyhq/tacy/proto"
)

// One date in the prompt, the person's: when the chat's system note says what day it is (in the browser's time
// zone), the VM states no UTC date of its own; without such a note it still gives the UTC date.
func TestInstructionsDateIsThePersons(t *testing.T) {
	// 03:30 UTC on Oct 17 is the evening of Oct 16 in the US: the UTC date would say "tomorrow".
	now := time.Date(2026, 10, 17, 3, 30, 0, 0, time.UTC)
	note := "You are Tacy, a private AI assistant.\n- Today is Friday, October 16, 2026. Your training data is older."
	for _, c := range []struct {
		name    string
		msgs    []proto.Message
		utcDate bool
	}{
		{"chat note", []proto.Message{{Role: "system", Content: note}, {Role: "user", Content: "what happened yesterday?"}}, false},
		{"no note", []proto.Message{{Role: "user", Content: "what happened yesterday?"}}, true},
		{"date only in a user message", []proto.Message{{Role: "user", Content: "Today is Friday, October 16, 2026. What's on?"}}, true},
		{"other system note", []proto.Message{{Role: "system", Content: "Be brief."}, {Role: "user", Content: "q"}}, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			s, _, err := StartFor(&proto.RunRequest{Messages: c.msgs}, now)
			if err != nil {
				t.Fatal(err)
			}
			hasUTC := strings.Contains(s.Instructions, "Today is Saturday, 17 October 2026 (UTC)")
			if hasUTC != c.utcDate {
				t.Fatalf("UTC date in the instructions: %v\n%s", hasUTC, s.Instructions)
			}
			if !c.utcDate && strings.Contains(s.Instructions, "Today is") {
				t.Fatalf("the instructions state a date of their own:\n%s", s.Instructions)
			}
		})
	}
}
