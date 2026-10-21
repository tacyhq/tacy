// Package storetest checks a harness.Store: every implementation (MemStore, the SQLite queue) runs Run.
package storetest

import (
	"encoding/json/jsontext"
	"testing"
	"time"

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
		must(t, s.SetAttempt("t1", 2, 1))
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
		if string(t1.Start) != string(start) || string(t1.Options) != string(opts) || t1.Attempt != 2 || t1.Failures != 1 ||
			len(t1.Steers) != 2 || t1.Steers[1] != (harness.Steer{N: 2, Text: "two"}) {
			t.Errorf("t1 %+v", t1)
		}
		if open[1].Options != nil || open[1].Attempt != 0 || len(open[1].Steers) != 0 || open[1].State != harness.StateQueued {
			t.Errorf("t3 %+v", open[1])
		}
		// An ended task keeps its id until it's deleted: a derived id can't make a second task.
		if s.AddTask("t2", start, nil) == nil {
			t.Error("a task was added under an ended task's id")
		}
	})
	t.Run("state and retention", func(t *testing.T) {
		s := open(t)
		before := time.Now().Add(-time.Second)
		must(t, s.AddTask("t1", jsontext.Value(`{}`), nil))
		must(t, s.AddTask("t2", jsontext.Value(`{}`), nil))
		must(t, s.SetState("t1", harness.StateWaiting, harness.WaitApproval))
		must(t, s.EndTask("t2", harness.Outcome{State: harness.OutcomeCancelled}))
		must(t, s.SetState("t2", harness.StateRunning, "")) // ended: the state stays
		// Taint (docs/27 section 5): the first request that brought untrusted content in is kept; it's never lifted.
		must(t, s.SetTaint("t1", "a3"))
		must(t, s.SetTaint("t1", "a7"))
		if reopen != nil {
			s = reopen(t, s)
		}
		t1, err := s.Task("t1")
		must(t, err)
		if t1 == nil || t1.State != harness.StateWaiting || t1.Sub != harness.WaitApproval || !t1.Ended.IsZero() ||
			t1.Created.Before(before) || t1.Created.After(time.Now()) || t1.Taint != "a3" {
			t.Fatalf("t1 %+v", t1)
		}
		if open, _ := s.OpenTasks(); len(open) != 1 || open[0].Taint != "a3" {
			t.Fatalf("open tasks lost the taint: %+v", open)
		}
		t2, _ := s.Task("t2")
		if t2 == nil || t2.State != harness.StateCancelled || t2.Outcome != harness.OutcomeCancelled || t2.Ended.Before(before) {
			t.Fatalf("t2 %+v", t2)
		}
		if t9, err := s.Task("t9"); err != nil || t9 != nil {
			t.Fatalf("unknown task: %+v %v", t9, err)
		}
		if ids, _ := s.EndedBefore(before); len(ids) != 0 {
			t.Errorf("ended before the test: %v", ids)
		}
		if ids, _ := s.EndedBefore(time.Now().Add(time.Second)); len(ids) != 1 || ids[0] != "t2" {
			t.Errorf("ended: %v", ids)
		}
	})
	t.Run("events", func(t *testing.T) {
		s := open(t)
		must(t, s.AddTask("t1", jsontext.Value(`{}`), nil))
		must(t, s.AddEvents("t1", []harness.StoredEvent{{Seq: 1, Data: []byte(`{"type":"meta"}`)}, {Seq: 2, Data: []byte(`{"type":"delta"}`)}}))
		must(t, s.AddEvents("t1", []harness.StoredEvent{{Seq: 3, Data: []byte(`{"type":"done"}`)}}))
		if s.AddEvents("t1", []harness.StoredEvent{{Seq: 3, Data: []byte(`{}`)}}) == nil {
			t.Error("event 3 added twice")
		}
		if reopen != nil {
			s = reopen(t, s)
		}
		all, err := s.Events("t1", 0, 100)
		must(t, err)
		if len(all) != 3 || all[0].Seq != 1 || string(all[2].Data) != `{"type":"done"}` {
			t.Fatalf("events %+v", all)
		}
		if after, _ := s.Events("t1", 1, 1); len(after) != 1 || after[0].Seq != 2 {
			t.Fatalf("after 1, limit 1: %+v", after)
		}
		if none, _ := s.Events("t9", 0, 10); len(none) != 0 {
			t.Fatalf("unknown task's events: %+v", none)
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
		_, _, err = s.Begin("t1", "a2", harness.TypeAction, [32]byte{4}, jsontext.Value(`{"c":3}`))
		must(t, err)
		must(t, s.Hold("t1", "a2", harness.WaitApproval))
		must(t, s.SaveCheckpoint("t1", &harness.Checkpoint{Seq: 1, State: []byte("one")}))
		must(t, s.SaveCheckpoint("t1", &harness.Checkpoint{Seq: 2, SteerApplied: 1, State: []byte("two")}))
		if reopen != nil {
			s = reopen(t, s)
		}
		recs, err := s.Journal("t1")
		must(t, err)
		if len(recs) != 3 || recs[2].ID != "a2" || recs[2].Held != harness.WaitApproval || recs[2].Done || recs[0].Held != "" {
			t.Fatalf("held record %+v", recs)
		}
		must(t, s.Finish("t1", "a2", jsontext.Value(`{"status":"denied"}`), nil))
		if rec, _, _ := s.Begin("t1", "a2", harness.TypeAction, [32]byte{4}, nil); !rec.Done || rec.Held != harness.WaitApproval {
			t.Errorf("a2 after its decision: %+v", rec)
		}
		recs = recs[:2]
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
	t.Run("scrub", func(t *testing.T) {
		s := open(t)
		start, opts := jsontext.Value(`{"input":"the person's words"}`), jsontext.Value(`{"question":"the person's words","user":"u"}`)
		must(t, s.AddTask("t1", start, opts))
		must(t, s.AddTask("t2", start, opts))
		for _, id := range []string{"t1", "t2"} {
			must(t, s.AddSteer(id, harness.Steer{N: 1, Text: "steer"}))
			_, _, err := s.Begin(id, "m1", harness.TypeModelCall, [32]byte{7}, jsontext.Value(`{"messages":"secret"}`))
			must(t, err)
			must(t, s.Finish(id, "m1", jsontext.Value(`{"text":"secret"}`), harness.Errf(harness.CodeInternal, "secret")))
			must(t, s.SaveCheckpoint(id, &harness.Checkpoint{Seq: 1, State: []byte("secret")}))
			must(t, s.AddEvents(id, []harness.StoredEvent{{Seq: 1, Data: []byte(`{"type":"done"}`)}}))
		}
		// t2 hasn't ended: a scrub leaves it as it was.
		must(t, s.Scrub("t2", jsontext.Value(`{}`)))
		must(t, s.EndTask("t1", harness.Outcome{State: harness.OutcomeSucceeded}))
		must(t, s.Scrub("t1", jsontext.Value(`{"user":"u"}`)))
		must(t, s.Scrub("t9", nil)) // unknown: nothing
		// Late writes (a request that was still running when the task ended) keep no content either.
		_, _, err := s.Begin("t1", "a9", harness.TypeAction, [32]byte{9}, jsontext.Value(`{"late":"secret"}`))
		must(t, err)
		must(t, s.Finish("t1", "a9", jsontext.Value(`{"late":"secret"}`), nil))
		must(t, s.SaveCheckpoint("t1", &harness.Checkpoint{Seq: 9, State: []byte("secret")}))
		if reopen != nil {
			s = reopen(t, s)
		}
		if recs, _ := s.Journal("t1"); len(recs) != 2 || recs[1].ID != "a9" || !recs[1].Done || recs[1].Req != nil || recs[1].Body != nil {
			t.Fatalf("a late request of an ended task: %+v", recs)
		}
		t1, _ := s.Task("t1")
		if t1 == nil || string(t1.Start) != `{}` || string(t1.Options) != `{"user":"u"}` || t1.Outcome != harness.OutcomeSucceeded {
			t.Fatalf("t1 after its scrub: %+v", t1)
		}
		recs, _ := s.Journal("t1")
		recs = recs[:min(1, len(recs))]
		if len(recs) != 1 || recs[0].ID != "m1" || recs[0].Hash != ([32]byte{7}) || !recs[0].Done || recs[0].Req != nil ||
			recs[0].Body != nil || recs[0].Err != nil {
			t.Fatalf("t1's journal after its scrub: %+v", recs)
		}
		if rec, fresh, _ := s.Begin("t1", "m1", harness.TypeModelCall, [32]byte{7}, nil); fresh || !rec.Done {
			t.Fatalf("a scrubbed request id could run again: %+v %v", rec, fresh)
		}
		if cp, _ := s.Checkpoint("t1"); cp != nil {
			t.Fatalf("t1's checkpoint after its scrub: %+v", cp)
		}
		if evs, _ := s.Events("t1", 0, 10); len(evs) != 1 {
			t.Fatalf("t1's events (its result) went with the scrub: %d", len(evs))
		}
		open, _ := s.OpenTasks()
		if len(open) != 1 || open[0].ID != "t2" || string(open[0].Start) != string(start) || string(open[0].Options) != string(opts) ||
			len(open[0].Steers) != 1 {
			t.Fatalf("t2 (open) after a scrub: %+v", open)
		}
		if recs, _ := s.Journal("t2"); len(recs) != 1 || recs[0].Req == nil || recs[0].Body == nil {
			t.Fatalf("t2's journal after a scrub: %+v", recs)
		}
		if cp, _ := s.Checkpoint("t2"); cp == nil {
			t.Fatal("t2's checkpoint went")
		}
		// Delivery marks (optional): only an ended task's, the first time counts, gone with the task.
		d, ok := s.(harness.DeliveryStore)
		if !ok {
			return
		}
		at := time.Now().Add(-time.Minute)
		must(t, d.MarkDelivered("t1", at))
		must(t, d.MarkDelivered("t1", at.Add(time.Hour)))
		must(t, d.MarkDelivered("t2", at)) // not ended: not marked
		if ids, _ := d.DeliveredBefore(at); len(ids) != 0 {
			t.Fatalf("delivered before the mark: %v", ids)
		}
		if ids, _ := d.DeliveredBefore(at.Add(time.Second)); len(ids) != 1 || ids[0] != "t1" {
			t.Fatalf("delivered: %v", ids)
		}
		must(t, s.DeleteTask("t1"))
		if ids, _ := d.DeliveredBefore(time.Now().Add(time.Hour)); len(ids) != 0 {
			t.Fatalf("a deleted task's mark: %v", ids)
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
		must(t, s.AddEvents("t1", []harness.StoredEvent{{Seq: 1, Data: []byte(`{}`)}}))
		must(t, s.AddEvents("t2", []harness.StoredEvent{{Seq: 1, Data: []byte(`{}`)}}))
		must(t, s.DeleteTask("t1"))
		if reopen != nil {
			s = reopen(t, s)
		}
		open, _ := s.OpenTasks()
		recs1, _ := s.Journal("t1")
		recs2, _ := s.Journal("t2")
		cp, _ := s.Checkpoint("t1")
		ev1, _ := s.Events("t1", 0, 10)
		ev2, _ := s.Events("t2", 0, 10)
		gone, _ := s.Task("t1")
		if len(open) != 1 || open[0].ID != "t2" || len(recs1) != 0 || len(recs2) != 1 || cp != nil || len(ev1) != 0 || len(ev2) != 1 || gone != nil {
			t.Errorf("after delete: open %+v, journal %d/%d, checkpoint %v, events %d/%d, task %v", open, len(recs1), len(recs2), cp, len(ev1), len(ev2), gone)
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
