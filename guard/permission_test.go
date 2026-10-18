package guard

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tacyhq/tacy/harness"
	"github.com/tacyhq/tacy/proto"
)

const testSecret = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"

// The grant MAC, pinned: the chat computes the same (the chat's agent-permissions test).
func TestGrantMACVector(t *testing.T) {
	g := Grant{Task: "tk_test", Request: "r1", Kind: "web.search", Decision: DecideOnce, Value: "weather paris"}
	const want = "3fb04e9961758423d30a89246fb29b40d24f2955e3a6d668cf847e77bda30736"
	if got := GrantMAC(testSecret, g); got != want {
		t.Fatalf("MAC %s, want %s", got, want)
	}
	g.MAC = want
	if !g.Verify(testSecret) || g.Verify(strings.Repeat("ab", 32)) || g.Verify("") {
		t.Fatal("verify")
	}
	g.Value = "weather\x00paris"
	if g.Verify(testSecret) {
		t.Fatal("a NUL in a field verified")
	}
}

// gatewayd's own check (permit): nothing goes out without the setting or a grant that checks with the run's secret
// for this task and kind; Allow once covers its own request only; Always allow its kind only; an edit is sent.
func TestPermitChecksTheGrantItself(t *testing.T) {
	fs := &fakeSearch{}
	g := New(Config{Up: &plainUpstream{}, Search: fs, Now: time.Now})
	opts, _ := json.Marshal(TaskOptions{RunSecret: testSecret, Permissions: map[string]string{"web.images": "never"}})
	ti := &harness.TaskInfo{ID: "tk_p", Start: &harness.Start{}, Options: opts}
	search := func(id string, gr *Grant) *harness.ActionResult {
		t.Helper()
		ctx := WithGrant(harness.WithRequestID(context.Background(), id), gr)
		res, err := g.Action(ctx, ti, id, &harness.Action{Name: "web.search", Args: []byte(`{"query":"model q"}`)})
		if err != nil {
			t.Fatal(err)
		}
		return res
	}
	grant := func(task, req, kind, decision, value string) *Grant {
		gr := &Grant{Task: task, Request: req, Kind: kind, Decision: decision, Value: value}
		gr.MAC = GrantMAC(testSecret, *gr)
		return gr
	}
	forged := grant("tk_p", "r1", "web.search", DecideOnce, "model q")
	forged.MAC = GrantMAC(strings.Repeat("cd", 32), *forged)
	for name, gr := range map[string]*Grant{
		"none":          nil,
		"forged":        forged,
		"other task":    grant("tk_other", "r1", "web.search", DecideOnce, "model q"),
		"other kind":    grant("tk_p", "r1", "web.fetch", DecideAlways, "https://a.example/"),
		"other request": grant("tk_p", "r0", "web.search", DecideOnce, "model q"),
		"deny":          grant("tk_p", "r1", "web.search", DecideDeny, "model q"),
	} {
		if res := search("r1", gr); res.Status != harness.ActionDenied || !strings.HasPrefix(res.Error, "permission_denied") {
			t.Errorf("%s: %+v", name, res)
		}
	}
	if len(fs.queries) != 0 {
		t.Fatalf("searched without a valid grant: %q", fs.queries)
	}
	if res := search("r1", grant("tk_p", "r1", "web.search", DecideOnce, "person q")); res.Status != harness.ActionDone {
		t.Fatalf("once: %+v", res)
	}
	always := grant("tk_p", "r2", "web.search", DecideAlways, "model q")
	if res := search("r3", always); res.Status != harness.ActionDone { // a later request of the kind
		t.Fatalf("always: %+v", res)
	}
	if want := []string{"person q", "model q"}; strings.Join(fs.queries, "|") != strings.Join(want, "|") {
		t.Fatalf("searched %q, want %q", fs.queries, want)
	}
	// Never (the setting) is refused whatever the grant says.
	ctx := WithGrant(context.Background(), grant("tk_p", "r9", "web.images", DecideOnce, "posters"))
	res, _ := g.Action(ctx, ti, "r9", &harness.Action{Name: "web.images", Args: []byte(`{"query":"posters"}`)})
	if res.Status != harness.ActionDenied {
		t.Fatalf("never: %+v", res)
	}
}

// What a prompt shows is exactly what goes out.
func TestOutgoingAndValues(t *testing.T) {
	if v, ok := Outgoing("web.search", []byte(`{"query":"  mail me at jane@example.com  "}`), nil); !ok || strings.Contains(v, "jane@") || strings.HasPrefix(v, " ") {
		t.Fatalf("search %q", v)
	}
	if v, ok := Outgoing("web.fetch", []byte(`{"url":"https://a.example/x?y=1"}`), nil); !ok || v != "https://a.example/x?y=1" {
		t.Fatalf("fetch %q", v)
	}
	for _, bad := range []string{`{}`, `{"query":"  "}`, `nope`} {
		if _, ok := Outgoing("web.search", []byte(bad), nil); ok {
			t.Errorf("outgoing for %s", bad)
		}
	}
	if _, ok := Outgoing("mail.send", []byte(`{}`), nil); ok {
		t.Error("a non-permission action")
	}
	for _, c := range []struct {
		kind, v string
		ok      bool
	}{{"web.search", "fine", true}, {"web.search", "", false}, {"web.search", "a\u0085b", false}, {"web.search", strings.Repeat("x", 2001), false},
		{"web.fetch", "https://a.example/", true}, {"web.fetch", "HTTPS://a.example/", true}, {"web.fetch", "ftp://a.example/", false},
		{"web.fetch", "/relative", false}} {
		if err := CheckGrantValue(c.kind, c.v); (err == nil) != c.ok {
			t.Errorf("CheckGrantValue(%s, %q) = %v", c.kind, c.v, err)
		}
	}
	args, err := withValue("web.search", []byte(`{"query":"a","count":3}`), "b")
	if err != nil || string(args) != `{"count":3,"query":"b"}` {
		t.Fatalf("withValue %s %v", args, err)
	}
}

// After an agentd restart a held action's prompt is shown again with a fresh timeout, and its answer releases it.
func TestPromptsResumeAsksAgain(t *testing.T) {
	var mu sync.Mutex
	var shown []proto.Event
	released := make(chan string, 4)
	p := &Prompts{Release: func(task, id string, allow bool, _ string) error { released <- id; return nil },
		Emit: func(_ string, e proto.Event) { mu.Lock(); shown = append(shown, e); mu.Unlock() }}
	opts, _ := json.Marshal(TaskOptions{RunSecret: testSecret})
	ti := &harness.TaskInfo{ID: "tk_r", Start: &harness.Start{}, Options: opts}
	req, _ := json.Marshal(harness.Action{Name: "web.fetch", Call: "c1", Args: []byte(`{"url":"https://a.example/"}`)})
	p.Resume(ti, []harness.Record{{ID: "r1", Kind: harness.TypeAction, Req: req, Held: harness.WaitPermission}})
	mu.Lock()
	if len(shown) != 1 || shown[0].Permission == nil || shown[0].Permission.Value != "https://a.example/" || shown[0].ID != "c1" {
		t.Fatalf("shown %+v", shown)
	}
	mu.Unlock()
	gr := Grant{Task: "tk_r", Request: "r1", Kind: "web.fetch", Decision: DecideOnce, Value: "https://a.example/"}
	gr.MAC = GrantMAC(testSecret, gr)
	if o, err := p.Answer(gr); err != nil || o != PermAllowedOnce {
		t.Fatalf("answer %s %v", o, err)
	}
	select {
	case id := <-released:
		if id != "r1" {
			t.Fatal(id)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("not released")
	}
	if _, err := p.Answer(gr); err != ErrNoPrompt {
		t.Fatalf("replay: %v", err)
	}
	p.Forget("tk_r")
	if _, ok := p.Outcome("tk_r", "r1"); ok {
		t.Fatal("forget")
	}
}

// v0.8.1: a chat run's deadline is its overall cap (RunCap, 30 minutes), not its 5 minutes of running time, so a
// prompt waits the full 10 minutes; a prompt still never waits past the deadline less a minute; agentd is told when
// each prompt opens and closes (answered, timed out, dropped) to stop the run's clock meanwhile.
func TestPromptWaitsTenMinutesUnderTheCap(t *testing.T) {
	start, _, err := StartFor(&proto.RunRequest{Messages: []proto.Message{{Role: "user", Content: "hi"}}}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	end, _ := time.Parse(time.RFC3339, start.Limits.Deadline)
	if d := time.Until(end); d < RunCap-time.Minute || d > RunCap+time.Second || RunCap != 30*time.Minute {
		t.Fatalf("deadline in %v, want the 30-minute cap", d)
	}
	var mu sync.Mutex
	var shown []proto.Event
	var waits []bool
	p := &Prompts{Release: func(string, string, bool, string) error { return nil },
		Emit:   func(_ string, e proto.Event) { mu.Lock(); shown = append(shown, e); mu.Unlock() },
		OnWait: func(_ string, open bool) { mu.Lock(); waits = append(waits, open); mu.Unlock() }}
	opts, _ := json.Marshal(TaskOptions{RunSecret: testSecret})
	ti := &harness.TaskInfo{ID: "tk_w", Start: &start, Options: opts}
	search := &harness.Action{Name: "web.search", Call: "c1", Args: []byte(`{"query":"q"}`)}
	if sub := p.Hold(ti, "r1", search); sub != harness.WaitPermission {
		t.Fatalf("not held: %q", sub)
	}
	mu.Lock()
	if len(shown) != 1 || shown[0].Permission.TimeoutS != 600 || len(waits) != 1 || !waits[0] {
		t.Fatalf("shown %+v, waits %v: want a 600 s prompt and the clock told", shown, waits)
	}
	mu.Unlock()
	gr := Grant{Task: "tk_w", Request: "r1", Kind: "web.search", Decision: DecideDeny}
	gr.MAC = GrantMAC(testSecret, gr)
	if _, err := p.Answer(gr); err != nil {
		t.Fatal(err)
	}
	// The cap still bounds a prompt: 5 minutes left gives 4 minutes; one that times out closes too; so does Forget.
	short := start
	short.Limits.Deadline = time.Now().Add(5 * time.Minute).UTC().Format(time.RFC3339)
	ti2 := &harness.TaskInfo{ID: "tk_w", Start: &short, Options: opts}
	p.Hold(ti2, "r2", search)
	p.Timeout = 50 * time.Millisecond
	p.Hold(ti2, "r3", search)
	time.Sleep(300 * time.Millisecond)
	p.Forget("tk_w")
	mu.Lock()
	defer mu.Unlock()
	if s := shown[2].Permission.TimeoutS; s < 235 || s > 240 {
		t.Fatalf("prompt with 5 minutes left waits %d s, want about 4 minutes", s)
	}
	if want := []bool{true, false, true, true, false, false}; !slices.Equal(waits, want) {
		t.Fatalf("waits %v, want %v", waits, want)
	}
}
