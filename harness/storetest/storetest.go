// Package storetest checks a harness.Store: every implementation (MemStore, the SQLite queue) runs Run.
package storetest

import (
	"encoding/json/jsontext"
	"testing"

	"github.com/tacyhq/tacy/harness"
)

// Run checks the Store contract on stores made by open. reopen, when set, opens the same store again (a runtime
// restart): what was recorded must still be there.
func Run(t *testing.T, open func(t *testing.T) harness.Store, reopen func(t *testing.T, s harness.Store) harness.Store) {
	t.Run("tasks", func(t *testing.T) {
		s := open(t)
		start, opts := jsontext.Value(`{"space":"s1"}`), jsontext.Value(`{"reasoning_effort":"low"}`)
		must(t, s.AddTask("t1", start, opts))
		must(t, s.AddTask("t2", start, nil))
		if s.AddTask("t1", start, nil) == nil {
			t.Error("a second task t1 was added")
		}
		must(t, s.SetAttempt("t1", 2))
		must(t, s.AddSteer("t1", harness.Steer{N: 1, Text: "one"}))
		must(t, s.AddSteer("t1", harness.Steer{N: 2, Text: "two"}))
		must(t, s.AddTask("t3", start, nil))
		must(t, s.EndTask("t2", harness.Outcome{State: harness.OutcomeSucceeded}))
		if reopen != nil {
			s = reopen(t, s)
		}
		open, err := s.OpenTasks()
		must(t, err)
		if len(open) != 2 || open[0].ID != "t1" || open[1].ID != "t3" {
			t.Fatalf("open tasks %+v, want t1 and t3 in order", open)
		}
		t1 := open[0]
		if string(t1.Start) != string(start) || string(t1.Options) != string(opts) || t1.Attempt != 2 ||
			len(t1.Steers) != 2 || t1.Steers[1] != (harness.Steer{N: 2, Text: "two"}) {
			t.Errorf("t1 %+v", t1)
		}
		if open[1].Options != nil || open[1].Attempt != 0 || len(open[1].Steers) != 0 {
			t.Errorf("t3 %+v", open[1])
		}
	})
	t.Run("journal and checkpoints", func(t *testing.T) {
		s := open(t)
		must(t, s.AddTask("t1", jsontext.Value(`{}`), nil))
		h := [32]byte{1, 2}
		rec, fresh, err := s.Begin("t1", "m1", harness.TypeModelCall, h, jsontext.Value(`{"a":1}`))
		if err != nil || !fresh || rec.ID != "m1" || rec.Done {
			t.Fatalf("begin: %+v %v %v", rec, fresh, err)
		}
		if _, fresh, _ := s.Begin("t1", "m1", harness.TypeModelCall, h, jsontext.Value(`{"a":1}`)); fresh {
			t.Error("m1 begun twice")
		}
		_, _, err = s.Begin("t1", "a1", harness.TypeAction, [32]byte{3}, jsontext.Value(`{"b":2}`))
		must(t, err)
		must(t, s.Finish("t1", "m1", jsontext.Value(`{"ok":true}`), nil))
		must(t, s.Finish("t1", "a1", nil, harness.Errf(harness.CodeInterrupted, "gone")))
		must(t, s.SaveCheckpoint("t1", &harness.Checkpoint{Seq: 1, State: []byte("one")}))
		must(t, s.SaveCheckpoint("t1", &harness.Checkpoint{Seq: 2, SteerApplied: 1, State: []byte("two")}))
		if reopen != nil {
			s = reopen(t, s)
		}
		recs, err := s.Journal("t1")
		must(t, err)
		if len(recs) != 2 || recs[0].ID != "m1" || recs[0].Hash != h || !recs[0].Done || string(recs[0].Body) != `{"ok":true}` ||
			string(recs[0].Req) != `{"a":1}` || recs[1].Kind != harness.TypeAction || recs[1].Err == nil ||
			recs[1].Err.Code != harness.CodeInterrupted || recs[1].Body != nil {
			t.Fatalf("journal %+v", recs)
		}
		rec, fresh, _ = s.Begin("t1", "a1", harness.TypeAction, [32]byte{3}, nil)
		if fresh || !rec.Done || rec.Err == nil {
			t.Errorf("a1 after reopening: %+v fresh %v", rec, fresh)
		}
		cp, err := s.Checkpoint("t1")
		must(t, err)
		if cp == nil || cp.Seq != 2 || cp.SteerApplied != 1 || string(cp.State) != "two" {
			t.Errorf("checkpoint %+v", cp)
		}
		if cp, _ := s.Checkpoint("t9"); cp != nil {
			t.Errorf("checkpoint of an unknown task: %+v", cp)
		}
		if recs, _ := s.Journal("t9"); len(recs) != 0 {
			t.Errorf("journal of an unknown task: %+v", recs)
		}
	})
	t.Run("delete", func(t *testing.T) {
		s := open(t)
		must(t, s.AddTask("t1", jsontext.Value(`{}`), nil))
		must(t, s.AddTask("t2", jsontext.Value(`{}`), nil))
		must(t, s.AddSteer("t1", harness.Steer{N: 1, Text: "x"}))
		_, _, err := s.Begin("t1", "m1", harness.TypeModelCall, [32]byte{}, jsontext.Value(`{}`))
		must(t, err)
		_, _, err = s.Begin("t2", "m1", harness.TypeModelCall, [32]byte{}, jsontext.Value(`{}`))
		must(t, err)
		must(t, s.SaveCheckpoint("t1", &harness.Checkpoint{Seq: 1, State: []byte("x")}))
		must(t, s.DeleteTask("t1"))
		if reopen != nil {
			s = reopen(t, s)
		}
		open, _ := s.OpenTasks()
		recs1, _ := s.Journal("t1")
		recs2, _ := s.Journal("t2")
		cp, _ := s.Checkpoint("t1")
		if len(open) != 1 || open[0].ID != "t2" || len(recs1) != 0 || len(recs2) != 1 || cp != nil {
			t.Errorf("after delete: open %+v, journal %d/%d, checkpoint %v", open, len(recs1), len(recs2), cp)
		}
		// The id can be used again (it's random in practice).
		must(t, s.AddTask("t1", jsontext.Value(`{}`), nil))
	})
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
