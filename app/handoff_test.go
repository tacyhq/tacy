package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	jsonv2 "encoding/json/v2"

	"github.com/tacyhq/tacy/activity"
	"github.com/tacyhq/tacy/identity"
	"github.com/tacyhq/tacy/runauth"
	"github.com/tacyhq/tacy/trigger"
)

// handoff posts a hand-off call; auth "relayed": as from inside the relay's signed envelope, "": not.
func (e *schedEnv) handoff(auth string, body any) (int, map[string]any) {
	b, _ := jsonv2.Marshal(body)
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/schedules/handoff", bytes.NewReader(b))
	if auth == "relayed" {
		r = asRelay(r)
	}
	e.s.scheduleHandoff(w, r)
	var out map[string]any
	json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

// collectedBy is a collected entry for task in a's space, signed by a's identity (what the browser makes).
func collectedBy(a *runauth.Asker, space, task string) collectedResult {
	return collectedResult{Space: space, Task: task, Identity: a.Identity, Sig: ed25519.Sign(a.Key, collectedMessage(space, a.Identity, task))}
}

// A scheduled run's sealed result goes to the relay (v0.18.0): only for the spaces it names, signed by the activity
// key the list announces, the same ciphertext the person's own fetch gets (it opens with the seal key, bound to its
// space and task); acknowledged ones aren't sent again; "collected" deletes the VM's copy and starts the schedule's
// uncollected count again. Nothing but space, task, ciphertext and signature crosses.
func TestScheduleHandoff(t *testing.T) {
	e := newSchedEnv(t, pText("Today's digest: three stories."))
	d := e.daily(e.me, nil)
	if code, out := e.install(e.me, e.sign(d, e.me.Key)); code != 200 {
		t.Fatalf("install %d %v", code, out)
	}
	e.s.triggerTick(context.Background())
	var task string
	for id := range e.s.tasks().Triggered() {
		task = id
	}
	r := e.waitResult(task)

	// The list names the signer (over EHBP in production).
	_, lo := e.call(e.s.scheduleList, e.where(e.me, runauth.ListLabel))
	signer, _ := lo["signer"].(string)
	pub, err := activity.ParseKey(signer)
	if err != nil || signer != e.rec.Signer.Public() {
		t.Fatalf("list's signer %q: %v", signer, err)
	}

	// Refusals.
	for name, c := range map[string]struct {
		auth string
		body string
		code int
	}{
		"not relayed":       {"", `{"spaces":[]}`, 401},
		"not a space":       {"relayed", `{"spaces":["u_1"]}`, 400},
		"bad ack":           {"relayed", `{"spaces":[],"ack":["nope"]}`, 400},
		"bad collected":     {"relayed", `{"spaces":[],"collected":[{"space":"s_1","task":"x"}]}`, 400},
		"no identity":       {"relayed", `{"spaces":[],"collected":[{"space":"s_1","task":"tk_bbbbbbbbbbbbbbbbbbbbbbbbbb"}]}`, 400},
		"not JSON":          {"relayed", `spaces`, 400},
		"nothing asked for": {"relayed", `{"spaces":[]}`, 200},
	} {
		w := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "/schedules/handoff", strings.NewReader(c.body))
		if c.auth != "" {
			req = asRelay(req)
		}
		e.s.scheduleHandoff(w, req)
		if w.Code != c.code {
			t.Fatalf("%s: %d %s", name, w.Code, w.Body)
		}
	}

	// Another space only: nothing.
	other, _ := runauth.NewAsker()
	if code, out := e.handoff("relayed", map[string]any{"spaces": []string{other.Space}}); code != 200 || len(out["results"].([]any)) != 0 {
		t.Fatalf("another space's hand-off: %d %v", code, out)
	}
	code, out := e.handoff("relayed", map[string]any{"spaces": []string{other.Space, e.me.Space}})
	rs, _ := out["results"].([]any)
	if code != 200 || len(rs) != 1 || out["more"] != false || out["deleted"] != float64(0) {
		t.Fatalf("hand-off %d %v", code, out)
	}
	h := rs[0].(map[string]any)
	if len(h) != 5 || h["space"] != e.me.Space || h["task"] != task {
		t.Fatalf("handed %v", h)
	}
	enc, _ := jsonDecodeB64(h["enc"])
	ct, _ := jsonDecodeB64(h["ct"])
	sig, _ := jsonDecodeB64(h["sig"])
	if !bytes.Equal(enc, r.Enc) || !bytes.Equal(ct, r.CT) {
		t.Fatal("handed ciphertext isn't the stored result")
	}
	dg := handoffDigest(e.me.Space, task, enc, ct)
	if !ed25519.Verify(pub, append([]byte(handoffLabel+"\x00"), dg[:]...), sig) {
		t.Fatal("signature doesn't check with the list's signer")
	}
	for _, bad := range [][32]byte{handoffDigest(other.Space, task, enc, ct), handoffDigest(e.me.Space, "tk_other", enc, ct), handoffDigest(e.me.Space, task, enc, append(bytes.Clone(ct), 0))} {
		if ed25519.Verify(pub, append([]byte(handoffLabel+"\x00"), bad[:]...), sig) {
			t.Fatal("signature checks for another space, task or ciphertext")
		}
	}
	pt, err := activity.OpenFrom(e.me.Seal, []byte(resultInfo), resultAAD(e.me.Space, task), enc, ct)
	if err != nil || !bytes.Contains(pt, []byte("three stories")) {
		t.Fatalf("handed result doesn't open: %v", err)
	}
	// Not acknowledged: sent again. Acknowledged: not again.
	if _, out := e.handoff("relayed", map[string]any{"spaces": []string{e.me.Space}}); len(out["results"].([]any)) != 1 {
		t.Fatalf("unacknowledged result not sent again: %v", out)
	}
	if _, out := e.handoff("relayed", map[string]any{"spaces": []string{e.me.Space}, "ack": []string{task}}); len(out["results"].([]any)) != 0 {
		t.Fatalf("acknowledged result sent again: %v", out)
	}
	cs := e.s.results.(trigger.CollectStore)
	if n, _ := cs.Uncollected(d.Agent); n != 1 {
		t.Fatalf("count %d before collected", n)
	}
	// A delete needs the space holder's signature (the keys plan §3.4, PX-2): the relay alone (no signature, or a forged
	// one), someone else's identity, a signature over another task, or the right one under another space: refused and
	// counted, nothing deleted.
	unsigned := collectedBy(e.me, e.me.Space, task)
	unsigned.Sig = nil
	otherTask := collectedBy(e.me, e.me.Space, "tk_bbbbbbbbbbbbbbbbbbbbbbbbbb")
	otherTask.Task = task
	forged := collectedBy(e.me, e.me.Space, task)
	forged.Sig = bytes.Repeat([]byte{1}, ed25519.SignatureSize)
	for name, c := range map[string]collectedResult{
		"unsigned":        unsigned,
		"forged":          forged,
		"not the holder":  collectedBy(other, e.me.Space, task),
		"another task":    otherTask,
		"another space":   collectedBy(e.me, other.Space, task),
		"holder's, moved": {Space: e.me.Space, Task: task, Identity: other.Identity, Sig: collectedBy(e.me, e.me.Space, task).Sig},
	} {
		code, out := e.handoff("relayed", map[string]any{"spaces": []string{}, "collected": []collectedResult{c}})
		if code != 200 || out["deleted"] != float64(0) || out["refused"] != float64(1) {
			t.Fatalf("%s: %d %v", name, code, out)
		}
		if n, _ := cs.Uncollected(d.Agent); n != 1 {
			t.Fatalf("%s: count %d", name, n)
		}
	}
	// Signed by the holder: deleted, count back to 0; sending it again deletes nothing more.
	if _, out := e.handoff("relayed", map[string]any{"spaces": []string{e.me.Space}, "collected": []collectedResult{collectedBy(e.me, e.me.Space, task)}}); out["deleted"] != float64(1) || out["refused"] != float64(0) {
		t.Fatalf("collected: %v", out)
	}
	if _, out := e.handoff("relayed", map[string]any{"spaces": []string{}, "collected": []collectedResult{collectedBy(e.me, e.me.Space, task)}}); out["deleted"] != float64(0) {
		t.Fatalf("collected again: %v", out)
	}
	if n, _ := cs.Uncollected(d.Agent); n != 0 {
		t.Fatalf("count %d after collected", n)
	}
	if code, _ := e.openResult(e.me, task); code != 404 {
		t.Fatalf("collected result still fetched: %d", code)
	}
}

// One answer holds at most handoffPage results; the rest come with "more" and the next call.
func TestScheduleHandoffPages(t *testing.T) {
	e := newSchedEnv(t)
	for range handoffPage + 3 {
		e.s.results.PutResult(trigger.Result{Task: randID("tk"), Space: e.me.Space, Seal: e.me.SealString(), Agent: "a_x", Version: 1,
			Trigger: "tr_x", State: "succeeded", Enc: []byte{1}, CT: []byte{2}})
	}
	_, out := e.handoff("relayed", map[string]any{"spaces": []string{e.me.Space}})
	first := out["results"].([]any)
	if len(first) != handoffPage || out["more"] != true {
		t.Fatalf("first page %d more %v", len(first), out["more"])
	}
	var ack []string
	for _, x := range first {
		ack = append(ack, x.(map[string]any)["task"].(string))
	}
	_, out = e.handoff("relayed", map[string]any{"spaces": []string{e.me.Space}, "ack": ack})
	if n := len(out["results"].([]any)); n != 3 || out["more"] != false {
		t.Fatalf("second page %d more %v", n, out["more"])
	}
}

// The hand-off signature's golden vector (testdata/v2-schedule-handoff.json; the chat's test/golden copy checks its
// verifier against it). UPDATE_GOLDEN=1 writes it.
func TestScheduleHandoffGolden(t *testing.T) {
	seed := bytes.Repeat([]byte{7}, 32)
	s, err := activity.NewSigner(seed)
	if err != nil {
		t.Fatal(err)
	}
	space, task := "s_aaaaaaaaaaaaaaaaaaaaaaaaaa", "tk_bbbbbbbbbbbbbbbbbbbbbbbbbb"
	enc, ct := bytes.Repeat([]byte{1}, 32), []byte("ciphertext of a scheduled run's result")
	dg := handoffDigest(space, task, enc, ct)
	sig, err := s.SignLabeled(handoffLabel, dg)
	if err != nil {
		t.Fatal(err)
	}
	type vec struct {
		// constants.labels: the chat's golden-v2 test finds every tacy/v2 label of its code in some fixture's.
		Constants struct {
			Labels map[string]string `json:"labels"`
		} `json:"constants"`
		Label  string `json:"label"`
		Signer string `json:"signer"`
		Space  string `json:"space"`
		Task   string `json:"task"`
		Enc    []byte `json:"enc"`
		CT     []byte `json:"ct"`
		Digest string `json:"digest"`
		Sig    []byte `json:"sig"`
		// Collected: a collected result's signature by the space holder's identity (the browser makes it).
		Collected struct {
			Identity    string `json:"identity"`
			IdentityKey string `json:"identity_key"`
			Message     string `json:"message"`
			Sig         []byte `json:"sig"`
		} `json:"collected"`
	}
	got := vec{Label: handoffLabel, Signer: s.Public(), Space: space, Task: task, Enc: enc, CT: ct, Digest: hex.EncodeToString(dg[:]), Sig: sig}
	got.Constants.Labels = map[string]string{"handoff": handoffLabel, "collected": collectedLabel}
	idKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, 32))
	idName := "i_ccccccccccccccccccccccccca"
	got.Collected.Identity, got.Collected.IdentityKey = idName, identity.KeyString(idKey.Public().(ed25519.PublicKey))
	got.Collected.Message = string(collectedMessage(space, idName, task))
	got.Collected.Sig = ed25519.Sign(idKey, collectedMessage(space, idName, task))
	path := filepath.Join("testdata", "v2-schedule-handoff.json")
	if os.Getenv("UPDATE_GOLDEN") == "1" {
		b, _ := json.MarshalIndent(got, "", "  ")
		if err := os.WriteFile(path, append(b, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var want vec
	if err := json.Unmarshal(b, &want); err != nil {
		t.Fatal(err)
	}
	if want.Constants.Labels["handoff"] != handoffLabel || want.Constants.Labels["collected"] != collectedLabel || !bytes.Equal(want.Collected.Sig, got.Collected.Sig) ||
		want.Collected.Message != got.Collected.Message || want.Label != got.Label || want.Signer != got.Signer || want.Digest != got.Digest || !bytes.Equal(want.Sig, got.Sig) {
		t.Fatalf("golden vector changed: %+v", got)
	}
}

func TestSignLabeledRefusesTheRecordsLabel(t *testing.T) {
	s, err := activity.NewSigner(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.SignLabeled(activity.Label, [32]byte{}); err == nil {
		t.Fatal("signed under the records' label")
	}
}
