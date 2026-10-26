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

// RunHandoffStoreTests checks a ResultStore's hand-off to the relay (v0.18.0): Pending lists every space's results
// oldest first without ciphertext, and DeleteCollected deletes by space and task and starts the counts again.
func RunHandoffStoreTests(t *testing.T, rs interface {
	ResultStore
	CollectStore
	HandoffStore
}) {
	t.Helper()
	t0 := time.Date(2026, 10, 26, 14, 0, 0, 0, time.UTC)
	put := func(task, space, agent string) {
		if _, err := rs.PutResult(Result{Task: task, Space: space, Seal: "x25519:" + space, Agent: agent, Version: 1, Trigger: "tr_1",
			ScheduledAt: t0, StartedAt: t0, EndedAt: t0, State: "succeeded", Enc: []byte("enc"), CT: []byte("ciphertext")}); err != nil {
			t.Fatal(err)
		}
	}
	put("tk_1", "s_1", "a_1")
	put("tk_2", "s_2", "a_2")
	put("tk_3", "s_1", "a_1")
	got, err := rs.Pending(10)
	if err != nil || len(got) != 3 {
		t.Fatalf("pending %d %v", len(got), err)
	}
	for i, want := range []string{"tk_1", "tk_2", "tk_3"} {
		if got[i].Task != want || len(got[i].CT) != 0 || cap(got[i].CT) != len("ciphertext") || got[i].Enc != nil {
			t.Fatalf("pending[%d] = %s, ct %d/%d, enc %v", i, got[i].Task, len(got[i].CT), cap(got[i].CT), got[i].Enc)
		}
	}
	if got, _ := rs.Pending(2); len(got) != 2 {
		t.Fatalf("limit: %d", len(got))
	}
	// Another space's task id: nothing deleted.
	if n, err := rs.DeleteCollected([]SpaceTask{{Space: "s_2", Task: "tk_1"}}); n != 0 || err != nil {
		t.Fatalf("wrong space deleted %d %v", n, err)
	}
	if n, _ := rs.Uncollected("a_1"); n != 2 {
		t.Fatalf("count %d before", n)
	}
	if n, err := rs.DeleteCollected([]SpaceTask{{Space: "s_1", Task: "tk_1"}, {Space: "s_1", Task: "tk_9"}}); n != 1 || err != nil {
		t.Fatalf("collected %d %v", n, err)
	}
	if n, _ := rs.Uncollected("a_1"); n != 0 {
		t.Fatalf("count %d after collected", n)
	}
	if n, _ := rs.Uncollected("a_2"); n != 1 {
		t.Fatalf("other schedule's count %d", n)
	}
	if got, _ := rs.Pending(10); len(got) != 2 || got[0].Task != "tk_2" || got[1].Task != "tk_3" {
		t.Fatalf("pending after: %v", got)
	}
}
