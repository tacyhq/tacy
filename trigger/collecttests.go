package trigger

import (
	"testing"
	"time"
)

// RunCollectStoreTests checks a ResultStore's collect counts (MemResults here, the side file in package queue).
func RunCollectStoreTests(t *testing.T, rs interface {
	ResultStore
	CollectStore
}) {
	t.Helper()
	t0 := time.Date(2026, 10, 21, 6, 0, 0, 0, time.UTC)
	put := func(task, agent string, ended time.Time) {
		if _, err := rs.PutResult(Result{Task: task, Space: "s_1", Seal: "x25519:a", Agent: agent, Version: 1, Trigger: "tr_1",
			ScheduledAt: t0, StartedAt: t0, EndedAt: ended, State: "succeeded", Enc: []byte("e"), CT: []byte("c")}); err != nil {
			t.Fatal(err)
		}
	}
	count := func(agent string) int {
		n, err := rs.Uncollected(agent)
		if err != nil {
			t.Fatal(err)
		}
		return n
	}
	if count("a_1") != 0 {
		t.Fatal("count before")
	}
	put("tk_1", "a_1", t0)
	put("tk_1", "a_1", t0) // the same task again: not another result
	put("tk_2", "a_1", t0.Add(time.Hour))
	put("tk_3", "a_2", t0)
	if count("a_1") != 2 || count("a_2") != 1 {
		t.Fatalf("counts %d %d", count("a_1"), count("a_2"))
	}
	rs.PruneResults(t0.Add(time.Minute)) // tk_1 and tk_3 past their keep: not collected
	if count("a_1") != 2 || count("a_2") != 1 {
		t.Fatal("a prune reset the count")
	}
	if n, _ := rs.DeleteResults("s_1", "x25519:other", []string{"tk_2"}); n != 0 || count("a_1") != 2 {
		t.Fatal("a delete with another seal key reset the count")
	}
	if n, _ := rs.DeleteResults("s_1", "x25519:a", []string{"tk_2"}); n != 1 || count("a_1") != 0 || count("a_2") != 1 {
		t.Fatalf("collected: %d %d", count("a_1"), count("a_2"))
	}
	put("tk_4", "a_1", t0)
	if ok, _ := rs.StoppedUncollected("a_1", 1); ok {
		t.Fatal("stopped before")
	}
	if err := rs.SetStoppedUncollected("a_1", 1); err != nil {
		t.Fatal(err)
	}
	if ok, _ := rs.StoppedUncollected("a_1", 1); !ok {
		t.Fatal("stop reason not kept")
	}
	if ok, _ := rs.StoppedUncollected("a_1", 2); ok {
		t.Fatal("stop reason for another version")
	}
	if err := rs.ResetCollect("a_1"); err != nil || count("a_1") != 0 {
		t.Fatal("reset")
	}
	if ok, _ := rs.StoppedUncollected("a_1", 1); ok {
		t.Fatal("stop reason after reset")
	}
	put("tk_5", "a_2", t0)
	rs.DeleteAgentResults("s_1", "a_2")
	if count("a_2") != 0 {
		t.Fatal("removed schedule still counted")
	}
}
