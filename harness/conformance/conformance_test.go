package conformance

import (
	"testing"

	"github.com/tacyhq/tacy/harness/refbrain"
)

// The suite's own checks: the reference brain against the fake runtime, and the fake runtime (the protocol engine
// the real runtime will share) against the hostile brain.

func TestReferenceBrain(t *testing.T) { RunBrain(t, refbrain.Run) }

func TestFakeRuntime(t *testing.T) { RunRuntime(t, FakeTarget) }
