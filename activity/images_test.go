package activity

import (
	"encoding/json"
	"strings"
	"testing"
)

// Image failures on the record: counts by fixed reason, added up across a call's downloads and a run's late ones.
func TestImagesAdd(t *testing.T) {
	var m *Images
	if m = m.Add(nil); m != nil {
		t.Fatal("nothing added made a value")
	}
	m = m.Add(&Images{Failed: 2, Reasons: map[string]int{"blocked": 1, "timeout": 1}})
	m = m.Add(&Images{Failed: 1, Reasons: map[string]int{"never_arrived": 1}})
	c := m.Clone()
	c.Reasons["blocked"] = 9
	if m.Failed != 3 || m.Reasons["blocked"] != 1 || m.Reasons["never_arrived"] != 1 {
		t.Fatalf("%+v", m)
	}
	b, _ := json.Marshal(Call{ID: "a1", Kind: "action", Name: "web.images", Outcome: "ok", Images: m})
	if !strings.Contains(string(b), `"images":{"failed":3,"reasons":{"blocked":1,"never_arrived":1,"timeout":1}}`) {
		t.Fatalf("%s", b)
	}
	if b, _ := json.Marshal(Call{ID: "a1"}); strings.Contains(string(b), "images") {
		t.Fatalf("empty images on the record: %s", b)
	}
}
