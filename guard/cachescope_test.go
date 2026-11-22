package guard

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/tacyhq/tacy/harness"
	"github.com/tacyhq/tacy/proto"
	"github.com/tacyhq/tacy/trigger"
)

// The prompt cache's scope per space: Tinfoil's prompt cache is
// scoped by user_cache_secret. A chat run sends the person's own (cache_secret); a scheduled run, or a request that
// leaves it out, used to send gatewayd's one per-boot secret, so two people's prompts shared one cache (a timing side
// channel). Now each space gets its own scope derived from the per-boot secret; a run's own secret still wins.
func TestCacheScopePerSpace(t *testing.T) {
	fm := &fakeModel{responses: []string{textSSE("a"), textSSE("b"), textSSE("c"), textSSE("d")}}
	srv := httptest.NewServer(fm)
	t.Cleanup(srv.Close)
	g := New(Config{Up: &plainUpstream{url: srv.URL, http: srv.Client()}, CacheSecret: "boot-secret",
		Now: func() time.Time { return time.Date(2026, 11, 18, 0, 0, 0, 0, time.UTC) }})
	now := time.Now().UTC()
	scheduled := func(task, space, sponsor string) {
		d := trigger.Definition{Firm: "f_chat", Space: space, Agent: "a_" + task, Version: 1, Sponsor: sponsor,
			Instructions: "Summarize my mail from my bank.", Models: []string{"deepseek-v4-1-flash"}, Tools: []string{"web.fetch"},
			Triggers: []trigger.Trigger{{ID: "tr_" + task, Kind: trigger.Schedule, Daily: "08:00", Zone: "UTC"}}}
		start, opts, err := TriggeredStart(trigger.Fire{Def: &d, Trigger: d.Triggers[0], At: now, Task: task}, "f_chat", now, nil)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := json.Marshal(opts)
		ti := &harness.TaskInfo{ID: task, Start: &start, Options: raw}
		if _, err := g.ModelCall(context.Background(), ti, &harness.ModelCall{Model: "deepseek-v4-1-flash",
			Messages: []harness.Message{{Role: "user", Content: d.Instructions}}}); err != nil {
			t.Fatal(err)
		}
	}
	scheduled("tk_a", "s_usera", "i_usera")  // user A's scheduled run
	scheduled("tk_b", "s_userb", "i_userb")  // user B's
	scheduled("tk_a2", "s_usera", "i_usera") // user A's again
	a, b, a2 := fm.request(0)["user_cache_secret"], fm.request(1)["user_cache_secret"], fm.request(2)["user_cache_secret"]
	if a == b {
		t.Errorf("two people's scheduled runs share one prompt-cache scope (%v)", a)
	}
	if a == "boot-secret" || b == "boot-secret" {
		t.Errorf("a scheduled run sent the per-boot secret itself (%v, %v)", a, b)
	}
	if a != a2 || a != SpaceCacheSecret("boot-secret", "s_usera") {
		t.Errorf("one space's runs don't share their scope (%v, %v)", a, a2)
	}
	// A run's own secret (the chat's per-account one) is sent as it is.
	start, opts, err := g.StartFor(&proto.RunRequest{Space: testSpace, Permissions: AllowAll(), Messages: user("q"), CacheSecret: "person-secret"})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(opts)
	if _, err := g.ModelCall(context.Background(), &harness.TaskInfo{ID: "tk_c", Start: &start, Options: raw},
		&harness.ModelCall{Model: "deepseek-v4-1-flash", Messages: []harness.Message{{Role: "user", Content: "q"}}}); err != nil {
		t.Fatal(err)
	}
	if got := fm.request(3)["user_cache_secret"]; got != "person-secret" {
		t.Errorf("a run's own cache secret: %v", got)
	}
	if SpaceCacheSecret("", "s_usera") != "" || SpaceCacheSecret("boot-secret", "s_a") == SpaceCacheSecret("other-boot", "s_a") {
		t.Error("SpaceCacheSecret: no boot secret, or another boot's")
	}
}
