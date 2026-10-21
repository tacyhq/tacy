package trigger

import (
	"testing"
	"time"
)

// RunPersonalStoreTests checks a HolderStore and ResultStore (the Mem ones here, the queue's side file in package
// queue).
func RunPersonalStoreTests(t *testing.T, h HolderStore, rs ResultStore) {
	t.Helper()
	t0 := time.Date(2026, 10, 21, 6, 0, 0, 0, time.UTC)
	if got, err := h.Holder("s_1", "i_1"); err != nil || got != nil {
		t.Fatalf("holder before: %v %v", got, err)
	}
	h.PutHolder(Holder{Space: "s_1", Identity: "i_1", Key: "ed25519:a", Seal: "x25519:a", At: t0})
	h.PutHolder(Holder{Space: "s_1", Identity: "i_1", Key: "ed25519:b", Seal: "x25519:b", At: t0.Add(time.Hour)})
	if got, err := h.Holder("s_1", "i_1"); err != nil || got == nil || got.Key != "ed25519:b" || got.Seal != "x25519:b" || !got.At.Equal(t0.Add(time.Hour)) {
		t.Fatalf("holder: %+v %v", got, err)
	}
	if got, _ := h.Holder("s_2", "i_1"); got != nil {
		t.Fatal("holder of another space")
	}
	mk := func(task, space, seal, agent string, ended time.Time) Result {
		return Result{Task: task, Space: space, Seal: seal, Agent: agent, Version: 2, Trigger: "tr_1", Day: "2026-10-21",
			ScheduledAt: t0, StartedAt: t0.Add(time.Second), EndedAt: ended, State: "succeeded", Enc: []byte("enc"), CT: []byte("ciphertext")}
	}
	s1, _ := rs.PutResult(mk("tk_1", "s_1", "x25519:a", "a_1", t0.Add(time.Minute)))
	if again, _ := rs.PutResult(mk("tk_1", "s_1", "x25519:a", "a_1", t0.Add(time.Hour))); again != s1 {
		t.Fatal("a second result for a task replaced the first")
	}
	rs.PutResult(mk("tk_2", "s_1", "x25519:a", "a_2", t0.Add(48*time.Hour)))
	rs.PutResult(mk("tk_3", "s_1", "x25519:other", "a_1", t0.Add(48*time.Hour)))
	rs.PutResult(mk("tk_4", "s_2", "x25519:a", "a_1", t0.Add(48*time.Hour)))
	list, err := rs.Results("s_1", "x25519:a", 0, 50)
	if err != nil || len(list) != 2 || list[0].Task != "tk_1" || list[1].Task != "tk_2" || len(list[0].CT) != 0 || cap(list[0].CT) != 10 ||
		list[0].Version != 2 || list[0].Day != "2026-10-21" || !list[0].EndedAt.Equal(t0.Add(time.Minute)) {
		t.Fatalf("results: %+v %v", list, err)
	}
	if after, _ := rs.Results("s_1", "x25519:a", list[0].Seq, 50); len(after) != 1 || after[0].Task != "tk_2" {
		t.Fatalf("after: %+v", after)
	}
	if one, _ := rs.Results("s_1", "x25519:a", 0, 1); len(one) != 1 {
		t.Fatal("limit")
	}
	if r, _ := rs.GetResult("s_1", "x25519:other", "tk_1"); r != nil {
		t.Fatal("a result fetched with another seal key")
	}
	if r, err := rs.GetResult("s_1", "x25519:a", "tk_1"); err != nil || r == nil || string(r.CT) != "ciphertext" || string(r.Enc) != "enc" {
		t.Fatalf("get: %+v %v", r, err)
	}
	if n, _ := rs.DeleteResults("s_1", "x25519:a", []string{"tk_4", "tk_x"}); n != 0 {
		t.Fatal("deleted another space's result")
	}
	rs.PruneResults(t0.Add(time.Hour)) // tk_1 ended before
	if r, _ := rs.GetResult("s_1", "x25519:a", "tk_1"); r != nil {
		t.Fatal("not pruned")
	}
	if n, _ := rs.DeleteResults("s_1", "x25519:a", []string{"tk_2"}); n != 1 {
		t.Fatal("delete")
	}
	if n, _ := rs.DeleteAgentResults("s_1", "a_1"); n != 1 { // tk_3
		t.Fatalf("delete agent results: %d", n)
	}
	if r, _ := rs.GetResult("s_2", "x25519:a", "tk_4"); r == nil {
		t.Fatal("another space's result went")
	}
}
