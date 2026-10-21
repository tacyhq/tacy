package testspend

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/tacyhq/tacy/proto"
	"github.com/tacyhq/tacy/safety"
)

func metric(m proto.Metric) proto.Event { return proto.Event{Type: "metrics", Metrics: &m} }

// A meter counts model and reader calls at the VM's prices and searches at its search price; a task's event once,
// however often it is followed; nothing else.
func TestMeter(t *testing.T) {
	var m Meter
	model := metric(proto.Metric{Kind: "model", Model: "deepseek-v4-1-flash", Prompt: 10_000, Completion: 1_000, Outcome: "ok"})
	reader := metric(proto.Metric{Kind: "reader", Model: "deepseek-v4-1-flash", Prompt: 3_000, Completion: 900, Outcome: "ok"})
	search := metric(proto.Metric{Kind: "search", Outcome: "ok"})
	m.Observe("", 0, model)
	m.Observe("tk_1", 3, reader)
	m.Observe("tk_1", 3, reader) // followed again from an earlier seq
	m.Observe("tk_1", 4, search)
	m.Observe("", 0, metric(proto.Metric{Kind: "search", Outcome: "refused"}))
	m.Observe("", 0, metric(proto.Metric{Kind: "fetch", Outcome: "ok"}))
	m.Observe("", 0, proto.Event{Type: "text", Delta: "hi"})
	want := safety.ModelCost("deepseek-v4-1-flash", 10_000, 1_000) + safety.ModelCost("deepseek-v4-1-flash", 3_000, 900) + safety.SearchCost
	if m.Micros() != want {
		t.Fatalf("micros %d, want %d", m.Micros(), want)
	}
}

// The ledger adds per tool and UTC day, keeps 31 days, and refuses a label that could be anything.
func TestRecord(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lab", "test-spend.json")
	now := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	if _, _, err := Record(path, "e2e", 1_000, now.AddDate(0, 0, -40)); err != nil {
		t.Fatal(err)
	}
	if _, total, err := Record(path, "e2e", 20_000, now); err != nil || total != 20_000 {
		t.Fatalf("%d %v", total, err)
	}
	day, total, err := Record(path, "photolab", 5_500, now)
	if err != nil || day != "2026-10-21" || total != 25_500 {
		t.Fatalf("%s %d %v", day, total, err)
	}
	if _, _, err := Record(path, "Bad Label!", 1, now); err == nil {
		t.Fatal("a bad label was taken")
	}
	b, _ := os.ReadFile(path)
	var l Ledger
	if err := json.Unmarshal(b, &l); err != nil {
		t.Fatal(err)
	}
	if len(l.Days) != 1 || l.Days["2026-10-21"]["e2e"] != 20_000 || l.Days["2026-10-21"]["photolab"] != 5_500 {
		t.Fatalf("ledger %s", b)
	}
	if st, _ := os.Stat(path); st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", st.Mode())
	}
}
