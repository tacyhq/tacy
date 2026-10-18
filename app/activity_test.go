package main

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/tacyhq/tacy/activity"
	"github.com/tacyhq/tacy/proto"
	"github.com/tacyhq/tacy/safety"
)

// Activity records end to end in agentd (docs/24): every kind of run (an answer, tool calls, a refusal at the
// door, a policy denial, a budget, the kill switch, a run cut by a restart) writes records, and together they
// make one valid chain per recipient: no gaps, every start has its end, signed by the key meta announced. No record
// holds content.

func recipientKey(t *testing.T) (*ecdh.PrivateKey, string) {
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k, activity.RecipientString(k.PublicKey())
}

// recorded is a request whose records go to priv's key, with the proof the browser makes against the VM's key.
func (e *safeEnv) recorded(priv *ecdh.PrivateKey, req proto.RunRequest) proto.RunRequest {
	to := activity.RecipientString(priv.PublicKey())
	p, err := activity.RecordProof(priv, e.vmKey.PublicKey(), to, e.vmKey.PublicKey().Bytes())
	if err != nil {
		e.t.Fatal(err)
	}
	req.RecordTo, req.RecordProof = to, p
	return req
}

// opened is a run's activity event, checked and opened.
func openedActivity(t *testing.T, evs []proto.Event, priv *ecdh.PrivateKey, key string) []*activity.Run {
	t.Helper()
	var out []*activity.Run
	n := 0
	for i, ev := range evs {
		if ev.Type != "activity" {
			continue
		}
		n++
		if i != len(evs)-2 || (evs[i+1].Type != "done" && evs[i+1].Type != "error") {
			t.Fatalf("activity isn't right before the end: %s", types(evs))
		}
		for _, raw := range ev.Activity {
			var s activity.Sealed
			if err := json.Unmarshal(raw, &s); err != nil {
				t.Fatal(err)
			}
			_, body, err := activity.Open(s, priv, func(k string) bool { return k == key })
			if err != nil {
				t.Fatalf("open: %v", err)
			}
			out = append(out, body)
		}
	}
	if n > 1 {
		t.Fatalf("%d activity events", n)
	}
	return out
}

func metaOf(evs []proto.Event) *proto.Meta {
	for _, ev := range evs {
		if ev.Type == "meta" {
			return ev.Meta
		}
	}
	return nil
}

func TestActivityEveryRunMakesAValidChain(t *testing.T) { testActivityChain(t, false) }

// TestActivityBehindRunner: the same conformance with the brain in its sandbox behind a runnerd, as on the CVM
// since v0.4.0 (real gVisor in CI's sandbox-runsc job, else the fake sandbox). The recorder sits between the
// runtime and the safety checks, so the brain's transport changes nothing on the record.
func TestActivityBehindRunner(t *testing.T) { testActivityChain(t, true) }

func testActivityChain(t *testing.T, behindRunner bool) {
	page := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "<html><head><title>Release notes</title></head><body><p>The secret page text about v0.6.1 and more words to keep.</p></body></html>")
	}))
	defer page.Close()
	pageURL := page.URL + "/private/path?q=client-matter-7"
	pageHost, _ := url.Parse(page.URL)
	e := newSafeEnvBrain(t, behindRunner,
		pText("The answer is 42."), // 1: answer
		pCalls([3]string{"c1", "web_search", `{"query":"jane doe divorce settlement"}`}, [3]string{"c2", "fetch_page", `{"url":"` + pageURL + `"}`}),
		pText("Found it [1]."), // 2: tools
	)
	e.mustPost(e.policy(1, nil), e.heartbeat())
	priv, to := recipientKey(t)
	key := e.rec.Signer.Public()
	var all []*activity.Run

	// 1. A plain answer.
	evs := runParity(t, e.s, e.recorded(priv, proto.RunRequest{Messages: user1("what is the meaning of life, my SSN is 078-05-1120")}))
	m := metaOf(evs)
	if m == nil || m.Activity == nil || m.Activity.Key != key || m.Activity.Seq != 0 || m.Activity.Head != "" || m.Activity.Chain != activity.ChainID("s_chat", to) {
		t.Fatalf("meta.activity: %+v", m)
	}
	runs := openedActivity(t, evs, priv, key)
	if len(runs) != 2 || runs[0].Event != activity.EventStart || runs[1].Event != activity.EventEnd || runs[1].Status.State != "succeeded" ||
		len(runs[1].Calls) != 1 || runs[1].Calls[0].Kind != "model" || runs[1].Calls[0].Prompt == 0 {
		t.Fatalf("answer run: %+v %+v", runs[0], runs[1])
	}
	if runs[0].Controls == nil || len(runs[0].Controls.Policy) != 1 || runs[0].Agent.ID != "a_chat" || runs[0].Input.Messages != 1 {
		t.Fatalf("start: %+v", runs[0])
	}
	all = append(all, runs...)

	// 2. A search and a fetch: the page's host and sizes are on the record, never the query, path or text.
	evs = runParity(t, e.s, e.recorded(priv, proto.RunRequest{Messages: user1("look it up")}))
	if m := metaOf(evs); m.Activity.Seq != 2 {
		t.Fatalf("second run's meta: %+v", m.Activity)
	}
	runs = openedActivity(t, evs, priv, key)
	end := runs[1]
	var fetch, search *activity.Call
	for i := range end.Calls {
		switch end.Calls[i].Name {
		case "web.fetch":
			fetch = &end.Calls[i]
		case "web.search":
			search = &end.Calls[i]
		}
	}
	if fetch == nil || search == nil || fetch.Outcome != "ok" || len(fetch.Hosts) != 1 || fetch.Hosts[0].Host != pageHost.Hostname() ||
		fetch.Hosts[0].Requests != 1 || fetch.Hosts[0].BytesIn == 0 || fetch.Connector != "web" || end.Usage == nil || end.Usage.ToolCalls != 2 {
		t.Fatalf("tool run: %+v", end)
	}
	all = append(all, runs...)

	// 3. Refused at the door (a firm stop): one refused record.
	e.mustPost(e.stop(safety.IssuerFirm, 1, func(l *safety.StopList) { l.All = true }, e.admin))
	evs = runParity(t, e.s, e.recorded(priv, proto.RunRequest{Messages: user1("again")}))
	runs = openedActivity(t, evs, priv, key)
	if len(runs) != 1 || runs[0].Event != activity.EventRefused || runs[0].Status.Code != safety.CodeStopped {
		t.Fatalf("refused: %+v", runs)
	}
	all = append(all, runs...)
	e.mustPost(e.stop(safety.IssuerFirm, 2, nil, e.admin))

	// 4. A run without a recipient isn't recorded (and gets no activity event).
	e.model.replies = append(e.model.replies, pText("unrecorded"))
	evs = runParity(t, e.s, proto.RunRequest{Messages: user1("hi")})
	if strings.Contains(types(evs), "activity") || metaOf(evs).Activity != nil {
		t.Fatalf("unrecorded run: %s", types(evs))
	}

	// 5. A budget ends it: the end says which control.
	e.mustPost(e.policy(2, func(p *safety.Policy) { p.Budget.Run.Tokens = 300 }))
	evs = runParity(t, e.s, e.recorded(priv, proto.RunRequest{Messages: user1("hi")}))
	runs = openedActivity(t, evs, priv, key)
	if len(runs) != 2 || runs[1].Status.Code != safety.CodeBudgetExceeded || runs[1].Status.State != "failed" ||
		len(runs[1].Calls) != 1 || runs[1].Calls[0].Outcome != "refused" || runs[1].Calls[0].Code != safety.CodeBudgetExceeded {
		t.Fatalf("budget: %+v", runs)
	}
	all = append(all, runs...)

	// 6. A run cut by a restart: the next process writes its end as interrupted.
	if _, err := e.rec.Begin(activity.Start{Run: "t_cut", Space: "s_chat", To: to}); err != nil {
		t.Fatal(err)
	}
	next := &activity.Recorder{Signer: e.rec.Signer, Store: e.rec.Store}
	if n, err := next.Recover(); err != nil || n != 1 {
		t.Fatalf("recover: %d %v", n, err)
	}

	// The whole chain, as the relay fetches it: valid from seq 1, every start ended once.
	w := httptest.NewRecorder()
	e.s.activityOut(w, httptest.NewRequest("GET", "/activity?chain="+activity.ChainID("s_chat", to)+"&after=0", nil))
	if w.Code != 401 {
		t.Fatalf("GET /activity without the token: %d", w.Code)
	}
	r := httptest.NewRequest("GET", "/activity?chain="+activity.ChainID("s_chat", to)+"&after=0", nil)
	r.Header.Set("Authorization", "Bearer tok")
	w = httptest.NewRecorder()
	e.s.activityOut(w, r)
	var got struct {
		Records []activity.Sealed `json:"records"`
		Head    activity.Link     `json:"head"`
		Key     string            `json:"key"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil || w.Code != 200 {
		t.Fatalf("GET /activity: %d %s", w.Code, w.Body)
	}
	endLink, err := activity.VerifyChain(got.Records, func(k string) bool { return k == key }, nil)
	if err != nil || endLink != got.Head || got.Key != key {
		t.Fatalf("chain: %+v %v (head %+v)", endLink, err, got.Head)
	}
	starts, ends := map[uint64]string{}, map[string]int{}
	for _, s := range got.Records {
		_, body, err := activity.Open(s, priv, nil)
		if err != nil {
			t.Fatal(err)
		}
		switch body.Event {
		case activity.EventStart:
			starts[body.Seq] = body.Run
		case activity.EventEnd, activity.EventInterrupted:
			if starts[body.StartSeq] != body.Run {
				t.Fatalf("end of %s names start %d", body.Run, body.StartSeq)
			}
			ends[body.Run]++
		}
		// No content anywhere in a record.
		b, _ := json.Marshal(body)
		for _, leak := range []string{"meaning of life", "078-05-1120", "jane doe", "divorce", "private/path", "client-matter",
			"secret page", "Release notes", "answer is 42", "Found it", "look it up"} {
			if strings.Contains(strings.ToLower(string(b)), strings.ToLower(leak)) {
				t.Fatalf("record %d holds %q: %s", body.Seq, leak, b)
			}
		}
	}
	for seq, run := range starts {
		if ends[run] != 1 {
			t.Fatalf("run %s (start %d) ended %d times", run, seq, ends[run])
		}
	}
	if len(starts) != 4 || len(got.Records) != 2*4+1 {
		t.Fatalf("%d runs, %d records", len(starts), len(got.Records))
	}
	_ = all
	_ = time.Second
}

func TestActivityKillSwitchOnTheRecord(t *testing.T) {
	block := make(chan struct{})
	page := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-block:
		case <-r.Context().Done():
		}
	}))
	defer page.Close()
	defer close(block)
	e := newSafeEnv(t, pCalls([3]string{"c1", "fetch_page", `{"url":"` + page.URL + `/slow"}`}), pText("never"))
	e.mustPost(e.policy(1, nil), e.heartbeat())
	priv, _ := recipientKey(t)
	done := make(chan []proto.Event, 1)
	go func() { done <- runParity(t, e.s, e.recorded(priv, proto.RunRequest{Messages: user1("read it")})) }()
	deadline := time.Now().Add(5 * time.Second)
	for e.modelReqs.Load() < 1 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(200 * time.Millisecond)
	e.mustPost(e.stop(safety.IssuerFirm, 1, func(l *safety.StopList) { l.Stop = []safety.Target{{Firm: "f_chat", Space: "s_chat"}} }, e.admin))
	var evs []proto.Event
	select {
	case evs = <-done:
	case <-time.After(15 * time.Second):
		t.Fatal("the run didn't stop")
	}
	runs := openedActivity(t, evs, priv, e.rec.Signer.Public())
	if len(runs) != 2 {
		t.Fatalf("records: %+v", runs)
	}
	st := runs[1].Status
	if st.State != "cancelled" || st.Code != safety.CodeStopped || st.Reason != "kill_switch" {
		t.Fatalf("status: %+v", st)
	}
	var fetch *activity.Call
	for i := range runs[1].Calls {
		if runs[1].Calls[i].Name == "web.fetch" {
			fetch = &runs[1].Calls[i]
		}
	}
	if fetch == nil || fetch.Outcome != "cancelled" {
		t.Fatalf("the fetch the stop cut: %+v", runs[1].Calls)
	}
}

func TestActivityBadRecipientRefused(t *testing.T) {
	e := newSafeEnv(t, pText("x"))
	e.mustPost(e.policy(1, nil), e.heartbeat())
	body, _ := json.Marshal(proto.RunRequest{Messages: user1("hi"), RecordTo: "x25519:AAAA"})
	r := httptest.NewRequest("POST", "/run", strings.NewReader(string(body)))
	r.Header.Set(ModelHeader, proto.DefaultModel)
	w := httptest.NewRecorder()
	e.s.run(w, r)
	if w.Code != 400 || !strings.Contains(w.Body.String(), "record_to") {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	// Someone else's key without its private half (our relay, or another person who saw it): refused, and
	// nothing reveals that chain's length.
	victim, to := recipientKey(t)
	_ = victim
	forger, _ := recipientKey(t)
	forged, _ := activity.RecordProof(forger, e.vmKey.PublicKey(), to, e.vmKey.PublicKey().Bytes())
	for _, proof := range [][]byte{nil, forged} {
		body, _ := json.Marshal(proto.RunRequest{Messages: user1("hi"), RecordTo: to, RecordProof: proof})
		r := httptest.NewRequest("POST", "/run", strings.NewReader(string(body)))
		r.Header.Set(ModelHeader, proto.DefaultModel)
		w := httptest.NewRecorder()
		e.s.run(w, r)
		if w.Code != 400 || !strings.Contains(w.Body.String(), "record_proof") {
			t.Fatalf("forged proof: %d %s", w.Code, w.Body)
		}
	}
	if _, head, _ := e.rec.Head("s_chat", to); head.Seq != 0 {
		t.Fatal("a record was written for an unproven key")
	}
}
