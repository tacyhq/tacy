package safety

import (
	"sync"
	"testing"
)

// ReserveKeeping (a built-in agent's reserve for its answer, 2026-11-23): a request that would leave less than the
// keep is held, not reserved, with what the run's own requests in flight hold of the budget and a channel that closes
// when one of them settles; after it settles below its reservation, the held request fits.
func TestReserveKeepingHeldUntilSettled(t *testing.T) {
	l := &Ledger{}
	b := Budgets{Run: Limits{CostMicros: 400_000}}
	if _, _, err := l.ReserveKeeping("t", Usage{CostMicros: 1}, b, 50_000); err == nil {
		t.Fatal("unknown run reserved")
	}
	l.Begin("t", "s_a", "m")
	search := Usage{ToolCalls: 1, CostMicros: 150_000} // a search with its reader at its largest
	c1, h, err := l.ReserveKeeping("t", search, b, 50_000)
	if err != nil || h != nil {
		t.Fatalf("first: %v %+v", err, h)
	}
	c2, h, err := l.ReserveKeeping("t", search, b, 50_000)
	if err != nil || h != nil {
		t.Fatalf("second: %v %+v", err, h)
	}
	// A third would leave 400 - 3 x 150 < 50: held, with the 300,000 the two hold.
	c3, h, err := l.ReserveKeeping("t", search, b, 50_000)
	if err != nil || c3 != nil || h == nil || h.Left != 100_000 || h.Held != 300_000 {
		t.Fatalf("third: %v %+v", err, h)
	}
	select {
	case <-h.Settled:
		t.Fatal("settled before anything did")
	default:
	}
	c1(Usage{ToolCalls: 1, CostMicros: 20_000}) // what it really cost
	select {
	case <-h.Settled:
	default:
		t.Fatal("not told when one settled")
	}
	if c3, h, err = l.ReserveKeeping("t", search, b, 50_000); err != nil || h != nil {
		t.Fatalf("third after the first settled: %v %+v", err, h)
	}
	c2(Usage{ToolCalls: 1, CostMicros: 20_000})
	c3(Usage{ToolCalls: 1, CostMicros: 20_000})
	// Nothing in flight and too little left: held with nothing held, which the caller takes as "used up".
	if _, h, _ = l.ReserveKeeping("t", Usage{CostMicros: 300_000}, b, 50_000); h == nil || h.Held != 0 || h.Left != 340_000 {
		t.Fatalf("used up: %+v", h)
	}
	// keep 0 is Reserve: only the budget itself refuses.
	if c, h, err := l.ReserveKeeping("t", Usage{CostMicros: 300_000}, b, 0); err != nil || h != nil {
		t.Fatalf("keep 0: %v %+v", err, h)
	} else {
		c(Usage{})
	}
	if _, _, err := l.ReserveKeeping("t", Usage{CostMicros: 400_000}, b, 0); err == nil {
		t.Fatal("past the budget reserved")
	}
}

// The check and the reservation are one step: of many parallel requests, only as many as leave the keep get one.
func TestReserveKeepingAtomic(t *testing.T) {
	l := &Ledger{}
	b := Budgets{Run: Limits{CostMicros: 400_000}}
	l.Begin("t", "s_a", "m")
	var mu sync.Mutex
	var wg sync.WaitGroup
	got := 0
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if c, h, err := l.ReserveKeeping("t", Usage{CostMicros: 150_000}, b, 50_000); err == nil && h == nil && c != nil {
				mu.Lock()
				got++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if got != 2 { // 400 - 2 x 150 = 100 >= 50; a third would leave -50
		t.Fatalf("%d reserved, want 2", got)
	}
}
