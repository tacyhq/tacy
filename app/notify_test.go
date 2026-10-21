package main

import (
	"context"
	"crypto/ecdh"
	"encoding/hex"
	"encoding/json"
	jsonv2 "encoding/json/v2"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tacyhq/tacy/guard"
	"github.com/tacyhq/tacy/harness"
	"github.com/tacyhq/tacy/proto"
	"github.com/tacyhq/tacy/runauth"
)

// A hand-off task (a built-in agent) that ends while no stream follows it marks "finished"; a followed one, a chat
// turn or a scheduled run doesn't (the scheduled run's result says "done" instead).
func TestHandoffEndedMarksFinished(t *testing.T) {
	s := &server{}
	s.notify, _ = openNotifier("")
	s.notify.Set("s_a", true)
	s.followTask("tk_followed", 1)
	for _, c := range []struct {
		id    string
		agent string
	}{{"tk_followed", guard.AgentResearch}, {"tk_chat", ""}, {"tk_sched", guard.AgentScheduled}} {
		s.taskEnded(c.id, guard.TaskOptions{Space: "s_a", Agent: c.agent})
	}
	if got := s.notify.Drain([]string{"s_a"}); len(got) != 0 {
		t.Fatalf("marked: %+v", got)
	}
	s.taskEnded("tk_review", guard.TaskOptions{Space: "s_a", Agent: guard.AgentReview})
	if got := s.notify.Drain([]string{"s_a"}); len(got) != 1 || got[0].Kind != "finished" {
		t.Fatalf("unfollowed hand-off: %+v", got)
	}
}

// guard.Host tells TaskEnded about a POST /tasks task once it ended.
func TestHostTellsTaskEnded(t *testing.T) {
	p := bootTasks(t, filepath.Join(t.TempDir(), "queue.db"), newStepModel(t, pText("done")), &fakeSearch{}, false)
	ended := make(chan string, 4)
	p.s.tasks().TaskEnded = func(id string, _ guard.TaskOptions) { ended <- id }
	c := p.conn(t, tasksUser)
	a, err := c.StartTask(context.Background(), proto.RunRequest{Permissions: guard.AllowAll(), Messages: user1("hi")}, "k-end")
	if err != nil {
		t.Fatal(err)
	}
	select {
	case id := <-ended:
		if id != a.Task {
			t.Fatalf("ended %s, started %s", id, a.Task)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("TaskEnded wasn't told")
	}
}

// The chat's golden vectors for POST /notify/set (the chat's test/golden/v2-notify.json, made with node:crypto; copied to
// runauth/testdata): each body decodes strictly as the handler reads it, its digest and signature check under the
// notify label over its own "on"/"off", and neither passes for the other value or another call.
func TestNotifyGoldenVectors(t *testing.T) {
	b, err := os.ReadFile("../runauth/testdata/v2-notify.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Constants struct {
			Labels struct{ NotifySet string } `json:"labels"`
		}
		VMPrivate string `json:"vm_private"`
		Space     string
		Identity  struct{ ID string }
		Requests  []struct {
			Name, Body, Digest string
			Own                []string
		}
	}
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	if v.Constants.Labels.NotifySet != runauth.NotifyLabel || len(v.Requests) != 2 {
		t.Fatalf("vectors: %+v", v.Constants)
	}
	pk, _ := hex.DecodeString(v.VMPrivate)
	vm, _ := ecdh.X25519().NewPrivateKey(pk)
	for _, r := range v.Requests {
		var req notifySetRequest
		if err := jsonv2.Unmarshal([]byte(r.Body), &req, jsonv2.RejectUnknownMembers(true)); err != nil {
			t.Fatalf("%s: %v", r.Name, err)
		}
		own := map[bool]string{true: "on", false: "off"}[req.On]
		if len(r.Own) != 1 || r.Own[0] != own {
			t.Fatalf("%s: own %q, on %v", r.Name, r.Own, req.On)
		}
		dg := runauth.CallDigest(runauth.NotifyLabel, vm.PublicKey().Bytes(), &req.Where, own)
		if hex.EncodeToString(dg[:]) != r.Digest {
			t.Fatalf("%s: digest %x", r.Name, dg)
		}
		at := time.Unix(req.SignedAt, 0)
		who, err := runauth.CheckCall(vm, runauth.NotifyLabel, &req.Where, at, own)
		if err != nil || who.Space != v.Space || who.Identity != v.Identity.ID {
			t.Fatalf("%s: %+v %v", r.Name, who, err)
		}
		flip := map[string]string{"on": "off", "off": "on"}[own]
		if _, err := runauth.CheckCall(vm, runauth.NotifyLabel, &req.Where, at, flip); err == nil {
			t.Fatalf("%s: passed for %q", r.Name, flip)
		}
		if _, err := runauth.CheckCall(vm, runauth.ListLabel, &req.Where, at, own); err == nil {
			t.Fatalf("%s: passed as a schedule call", r.Name)
		}
	}
}

// Run notifications (notify.go): off unless the space's holder turned them on; the marks name only a space and a
// kind; the relay drains only the spaces it names, and every other mark is dropped.

func TestNotifierMarksOnlySpacesTurnedOn(t *testing.T) {
	path := filepath.Join(t.TempDir(), "notify.json")
	n, err := openNotifier(path)
	if err != nil {
		t.Fatal(err)
	}
	n.Mark("s_off", notifyDone) // never turned on: nothing kept
	if err := n.Set("s_a", true); err != nil {
		t.Fatal(err)
	}
	if err := n.Set("s_b", true); err != nil {
		t.Fatal(err)
	}
	n.Mark("s_a", notifyDone)
	n.Mark("s_a", notifyDone) // a burst is one mark
	n.Mark("s_a", notifyWaiting)
	n.Mark("s_b", notifyDone)
	got := n.Drain([]string{"s_a", "s_off", "s_a"})
	want := []notifyEvent{{"s_a", "waiting"}, {"s_a", "done"}}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("drain: %+v", got)
	}
	// s_b wasn't named (no device subscribed): its mark is dropped, not kept for later.
	if got := n.Drain([]string{"s_a", "s_b"}); len(got) != 0 {
		t.Fatalf("second drain: %+v", got)
	}
	// Turned on is kept across a restart (the file holds space ids only); off drops the space and its marks.
	b, _ := os.ReadFile(path)
	if string(b) != `{"on":["s_a","s_b"]}` {
		t.Fatalf("file: %s", b)
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", fi.Mode())
	}
	n.Mark("s_b", notifyDone)
	if err := n.Set("s_b", false); err != nil {
		t.Fatal(err)
	}
	if got := n.Drain([]string{"s_b"}); len(got) != 0 {
		t.Fatalf("after off: %+v", got)
	}
	again, err := openNotifier(path)
	if err != nil || !again.On("s_a") || again.On("s_b") {
		t.Fatalf("reopened: %v %v", err, again.on)
	}
	var nilN *notifier // a VM without notifications: every call is a no-op
	nilN.Mark("s_a", notifyDone)
	if nilN.On("s_a") || len(nilN.Drain([]string{"s_a"})) != 0 {
		t.Fatal("nil notifier")
	}
}

// Only the space's holder turns notices on, for its own space, with a signature made for this call.
func TestNotifySetSigned(t *testing.T) {
	e := newSchedEnv(t)
	e.s.notify, _ = openNotifier("")
	other, _ := runauth.NewAsker()
	cases := map[string]struct {
		req  func() notifySetRequest
		code int
		err  string
	}{
		"signed for another call": {func() notifySetRequest {
			return notifySetRequest{Where: e.where(e.me, runauth.ListLabel), On: true}
		}, 403, "bad_proof"},
		"signed for off, sent as on": {func() notifySetRequest {
			return notifySetRequest{Where: e.where(e.me, runauth.NotifyLabel, "off"), On: true}
		}, 403, "bad_proof"},
		"signed by another key": {func() notifySetRequest {
			w := e.where(e.me, runauth.NotifyLabel, "on")
			w.IdentitySig = runauth.SignCall(other.Key, runauth.NotifyLabel, &w, e.vm(), "on")
			return notifySetRequest{Where: w, On: true}
		}, 403, "bad_proof"},
	}
	for name, c := range cases {
		code, out := e.call(e.s.notifySet, c.req())
		if code != c.code || errOf(out) != c.err {
			t.Errorf("%s: %d %v", name, code, out)
		}
	}
	if e.s.notify.On(e.me.Space) {
		t.Fatal("turned on by a refused call")
	}
	w := e.where(e.me, runauth.NotifyLabel, "on")
	if code, out := e.call(e.s.notifySet, notifySetRequest{Where: w, On: true}); code != 200 || out["on"] != true {
		t.Fatalf("on: %d %v", code, out)
	}
	if code, out := e.call(e.s.notifySet, notifySetRequest{Where: w, On: true}); code != 409 || errOf(out) != "replayed" {
		t.Fatalf("replay: %d %v", code, out)
	}
	if !e.s.notify.On(e.me.Space) || e.s.notify.On(other.Space) {
		t.Fatal("not on for the holder's space alone")
	}
	if code, _ := e.call(e.s.notifySet, notifySetRequest{Where: e.where(e.me, runauth.NotifyLabel, "off"), On: false}); code != 200 || e.s.notify.On(e.me.Space) {
		t.Fatalf("off: %d", code)
	}
}

// A scheduled run's result marks its space "done" when the person turned notices on, and nothing otherwise; the
// relay's drain answers the space and the kind, nothing about the run.
func TestScheduledRunNotifies(t *testing.T) {
	for _, on := range []bool{false, true} {
		e := newSchedEnv(t, pText("Today's digest."))
		e.s.notify, _ = openNotifier("")
		if on {
			if code, out := e.call(e.s.notifySet, notifySetRequest{Where: e.where(e.me, runauth.NotifyLabel, "on"), On: true}); code != 200 {
				t.Fatalf("on: %d %v", code, out)
			}
		}
		if code, out := e.install(e.me, e.sign(e.daily(e.me, nil), e.me.Key)); code != 200 {
			t.Fatalf("install %d %v", code, out)
		}
		e.s.triggerTick(context.Background())
		var task string
		for id := range e.s.tasks().Triggered() {
			task = id
		}
		e.waitResult(task)
		body, _ := json.Marshal(pendingRequest{Spaces: []string{e.me.Space}})
		rr := httptest.NewRecorder()
		r := httptest.NewRequest("POST", "/notify/pending", strings.NewReader(string(body)))
		r.Header.Set("Authorization", "Bearer tok")
		e.s.notifyPending(rr, r)
		want := `{"events":[]}`
		if on {
			want = `{"events":[{"space":"` + e.me.Space + `","kind":"done"}]}`
		}
		if rr.Code != 200 || strings.TrimSpace(rr.Body.String()) != want {
			t.Fatalf("on=%v: %d %s", on, rr.Code, rr.Body)
		}
	}
}

// pendingNotices drains the space's marks as the relay does (POST /notify/pending), as the answer's JSON.
func (e *schedEnv) pendingNotices() string {
	e.t.Helper()
	body, _ := json.Marshal(pendingRequest{Spaces: []string{e.me.Space}})
	rr := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/notify/pending", strings.NewReader(string(body)))
	r.Header.Set("Authorization", "Bearer tok")
	e.s.notifyPending(rr, r)
	if rr.Code != 200 {
		e.t.Fatalf("pending %d %s", rr.Code, rr.Body)
	}
	return strings.TrimSpace(rr.Body.String())
}

// A stopped run and a quiet one (schedule.no_change: nothing changed) never notify; any other result does. Removing
// the quiet line from resultNotifies fails here and in TestScheduleSearchMemoryAndQuiet.
func TestResultNotifies(t *testing.T) {
	for _, c := range []struct {
		b    *resultBody
		want bool
	}{
		{nil, false},
		{&resultBody{State: harness.OutcomeSucceeded}, true},
		{&resultBody{State: harness.OutcomeFailed}, true},
		{&resultBody{State: harness.OutcomeCancelled}, false},
		{&resultBody{State: harness.OutcomeSucceeded, Quiet: true, Note: "still Rust 1.90"}, false},
	} {
		if got := resultNotifies(c.b); got != c.want {
			t.Errorf("resultNotifies(%+v) = %v, want %v", c.b, got, c.want)
		}
	}
}

func TestNotifyPendingNeedsToken(t *testing.T) {
	e := newSchedEnv(t)
	e.s.notify, _ = openNotifier("")
	for name, c := range map[string]struct {
		auth, body string
		code       int
	}{
		"no token":      {"", `{"spaces":[]}`, 401},
		"wrong token":   {"Bearer nope", `{"spaces":[]}`, 401},
		"not a space":   {"Bearer tok", `{"spaces":["u_1"]}`, 400},
		"not JSON":      {"Bearer tok", `spaces`, 400},
		"empty is fine": {"Bearer tok", `{"spaces":[]}`, 200},
	} {
		rr := httptest.NewRecorder()
		r := httptest.NewRequest("POST", "/notify/pending", strings.NewReader(c.body))
		if c.auth != "" {
			r.Header.Set("Authorization", c.auth)
		}
		e.s.notifyPending(rr, r)
		if rr.Code != c.code {
			t.Errorf("%s: %d %s", name, rr.Code, rr.Body)
		}
	}
}

// A prompt opening in a task nobody follows marks "waiting"; one in a followed task (the tab is open) doesn't.
func TestPromptWaitingMarksUnfollowed(t *testing.T) {
	s := &server{}
	s.notify, _ = openNotifier("")
	s.notify.Set("s_a", true)
	var ledger []bool
	hook := s.onWait(func(_ string, open bool) { ledger = append(ledger, open) }, func(task string) string {
		return map[string]string{"tk_1": "s_a", "tk_2": "s_a"}[task]
	})
	s.followTask("tk_1", 1)
	hook("tk_1", true)
	if got := s.notify.Drain([]string{"s_a"}); len(got) != 0 {
		t.Fatalf("followed: %+v", got)
	}
	s.followTask("tk_1", -1)
	hook("tk_2", true)
	hook("tk_2", false)
	hook("tk_9", true) // not running here: no space
	if got := s.notify.Drain([]string{"s_a"}); len(got) != 1 || got[0].Kind != "waiting" {
		t.Fatalf("unfollowed: %+v", got)
	}
	if len(ledger) != 4 || s.followed("tk_1") {
		t.Fatalf("ledger %v", ledger)
	}
}
