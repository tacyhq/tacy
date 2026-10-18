package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// blockingSearch holds the first search until release, telling started when it's there.
type blockingSearch struct {
	*paritySearch
	started, release chan struct{}
	first            bool
}

func (b *blockingSearch) Search(ctx context.Context, q string, n int) ([]SearchResult, error) {
	if !b.first {
		b.first = true
		close(b.started)
		<-b.release
	}
	return b.paritySearch.Search(ctx, q, n)
}

// The brain in its sandbox crashes while its search runs: agentd starts a new sandbox through runnerd, the runtime
// resumes the task from its checkpoint, and the run's events are exactly the recorded ones; the search ran once and
// the model wasn't asked again for the step it had answered. In real gVisor with TACY_RUNSC and TACY_BRAIN_BIN.
func TestBrainCrashBehindRunner(t *testing.T) {
	var sc parityScenario
	for _, s := range parityScenarios {
		if s.name == "search" {
			sc = s
		}
	}
	pm := &parityModel{replies: sc.model}
	model := httptest.NewServer(pm)
	defer model.Close()
	ps := &blockingSearch{paritySearch: &paritySearch{}, started: make(chan struct{}), release: make(chan struct{})}
	s, env := parityServerEnv(t, "gatewayd+runner", model, ps, newParityWeb())
	go func() {
		<-ps.started
		if n := env.KillBrains(); n != 1 {
			t.Errorf("killed %d brains, want 1", n)
		}
		for deadline := time.Now().Add(15 * time.Second); env.Brains() != 1 || !s.rt.Connected(); {
			if time.Now().After(deadline) {
				t.Error("no new brain")
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		close(ps.release)
	}()
	got := normalize(runParity(t, s, sc.req))
	b, _ := json.MarshalIndent(got, "", " ")
	want, err := os.ReadFile(filepath.Join("testdata", "parity", "search.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(bytes.TrimSpace(want), bytes.TrimSpace(b)) {
		t.Errorf("events after a brain crash differ from the recorded run\nwant %s\ngot  %s", types(mustRecord(want).Events), types(got.Events))
	}
	if len(ps.queries) != 1 || pm.n != 2 {
		t.Errorf("searches %d, model calls %d: want 1 and 2", len(ps.queries), pm.n)
	}
}

func mustRecord(b []byte) parityRecord {
	var r parityRecord
	json.Unmarshal(b, &r)
	return r
}
