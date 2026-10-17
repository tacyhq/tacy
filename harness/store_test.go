package harness_test

import (
	"testing"

	"github.com/tacyhq/tacy/harness"
	"github.com/tacyhq/tacy/harness/storetest"
)

func TestMemStore(t *testing.T) {
	storetest.Run(t, func(*testing.T) harness.Store { return harness.NewMemStore() }, nil)
}
