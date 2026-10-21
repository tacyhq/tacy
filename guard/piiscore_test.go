package guard

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// TestPIIScorecardDump is measurement tooling for the chat's PII scorecard, not a check: given
// PII_SCORECARD_IN (a JSON list of {text, url}) it writes PII_SCORECARD_OUT with what the VM does with each, through
// the production code: for a query, Outgoing's value (the permission prompt and the grant) and the web_search tool's
// own maskPII of it (what goes to the provider); for a page or image address (url true), the kinds fetch_page and
// image downloads refuse it for. Skipped without the variable.
func TestPIIScorecardDump(t *testing.T) {
	in := os.Getenv("PII_SCORECARD_IN")
	if in == "" {
		t.Skip("PII_SCORECARD_IN not set (run by pnpm pii-scorecard)")
	}
	raw, err := os.ReadFile(in)
	if err != nil {
		t.Fatal(err)
	}
	var items []struct {
		Text string `json:"text"`
		URL  bool   `json:"url"`
	}
	if err := json.Unmarshal(raw, &items); err != nil {
		t.Fatal(err)
	}
	type row struct {
		Outgoing string   `json:"outgoing,omitempty"`
		Sent     string   `json:"sent,omitempty"`
		Kinds    []string `json:"kinds"`
		Refused  []string `json:"refused,omitempty"`
	}
	out := make([]row, len(items))
	for i, it := range items {
		if it.URL {
			out[i] = row{Refused: urlRefusedKinds(it.Text)}
			continue
		}
		args, _ := json.Marshal(map[string]any{"query": it.Text, "count": 5})
		shown, _ := Outgoing("web.search", args, nil)
		// tools.go web_search: maskPII(capRunes(TrimSpace(query), 300)) on the arguments it runs with.
		sent, _ := maskPII(capRunes(strings.TrimSpace(shown), 300))
		// The kinds the tool reports (the card's "Masked before the query left the agent VM"): on the model's query.
		_, kinds := maskPII(capRunes(strings.TrimSpace(it.Text), 300))
		out[i] = row{Outgoing: shown, Sent: sent, Kinds: kinds}
	}
	b, _ := json.MarshalIndent(out, "", " ")
	if err := os.WriteFile(os.Getenv("PII_SCORECARD_OUT"), b, 0o644); err != nil {
		t.Fatal(err)
	}
}

// urlRefusedKinds is tools.go's fetch_page check on a model-written address: the kinds it refuses the URL for.
func urlRefusedKinds(u string) []string { return urlPersonalData(u) }
