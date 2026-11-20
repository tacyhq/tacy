package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"slices"
	"strings"
	"sync"

	"github.com/tacyhq/tacy/harness"
	"github.com/tacyhq/tacy/identity"
	"github.com/tacyhq/tacy/runauth"
	"github.com/tacyhq/tacy/trigger"
)

// Results handed to the relay (v0.18.0; the schedules contract "Hand-off to the relay"). A scheduled run's result is sealed to
// the space's seal key when the run ends (schedules.go triggeredDone). Until now it waited here for the person's
// browser, so with the VM stopped between runs (the Worker wakes it only for a run) nobody saw it until a tab started
// the VM again and collected it (about a minute of boot). Now the relay's cron, while the VM is up, takes a copy of
// each sealed result and keeps it for the browser, which opens it on load with the VM off:
//
//	POST /schedules/handoff  {spaces, ack, collected} -> {results: [{space, task, enc, ct, sig}], more, deleted}
//
// In the relay's signed envelope (POST /v, ../relay), plaintext JSON inside it, like /notify/pending: what crosses is ciphertext only the space's seal key opens (the
// relay can't read it), with its space and task ids (the relay knows the space; the task id is random). Nothing else
// of the run: no schedule id, day, times, state, model or quiet mark (all inside the ciphertext).
//
// The relay could still make up a result of its own: the seal key is public and HPKE's base mode doesn't say who
// sealed. So each one carries sig, the VM's activity signing key (KMS-derived, the same after a restart) over the
// space, task and ciphertext; the browser accepts a result from the relay only when it checks with the key a
// verified VM gave it over EHBP (the list's "signer", pinned per space).
//
// ack: the results the relay stored from earlier answers (it isn't sent them again; memory only, so after a restart
// it gets them again and keeps one copy). collected: results the person's browser saved from the relay's copy and
// deleted there; the VM deletes its own as the browser's own delete does (results/delete), so their schedules'
// uncollected counts start again (trigger/collect.go). A delete is the person's to make (the keys plan §3.4, PX-2): each
// collected entry carries the space holder's identity signature over the space and the task (collectedMessage),
// made in their browser when it saved the result, and the VM checks it against the identity key the space's holder
// proved (the holder directory). An entry without one, or by anyone else, is refused and counted, never deleted. So
// a relay (or whoever holds its key) can withhold a delete or keep a schedule from stopping itself (a cost guard for
// the person, who it bills anyway), but it can't delete a result, read one or make one up. The signature names the
// task, whose id is random and used once, so sending it again deletes nothing new; it needs no time or nonce.

const (
	handoffLabel     = "tacy/v2/schedule-handoff"
	handoffPage      = 8       // results per answer
	handoffBytes     = 4 << 20 // ciphertext per answer (at least one result)
	handoffScan      = 4096    // results looked at per call
	maxHandoffSpaces = 10_000
	maxHandoffItems  = 50 // acks, and collected results, per call
	maxHanded        = 100_000
)

// handedSet is the tasks the relay acknowledged storing (memory only).
type handedSet struct {
	mu sync.Mutex
	m  map[string]bool
}

func (h *handedSet) add(tasks []string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.m == nil || len(h.m)+len(tasks) > maxHanded {
		h.m = map[string]bool{} // forgotten: the relay keeps one copy of whatever comes again
	}
	for _, t := range tasks {
		h.m[t] = true
	}
}

func (h *handedSet) has(task string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.m[task]
}

// keep drops the tasks that aren't pending any more.
func (h *handedSet) keep(pending map[string]bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for t := range h.m {
		if !pending[t] {
			delete(h.m, t)
		}
	}
}

type handoffRequest struct {
	Spaces    []string          `json:"spaces"`
	Ack       []string          `json:"ack"`
	Collected []collectedResult `json:"collected"`
}

// collectedResult is one result the person saved: its space and task, and their identity's signature over both.
type collectedResult struct {
	Space    string `json:"space"`
	Task     string `json:"task"`
	Identity string `json:"identity"`
	Sig      []byte `json:"sig"`
}

// collectedLabel is the label of a collected result's signature (the chat's schedule-center.ts signs it).
const collectedLabel = "tacy/v2/schedule-collected"

// collectedMessage is what the space holder's identity key signs (Ed25519) for one collected result.
func collectedMessage(space, identity, task string) []byte {
	return []byte(collectedLabel + "\n" + space + "\n" + identity + "\n" + task)
}

// verifyCollected keeps the entries whose signature is by the identity key the space's holder proved.
func (s *server) verifyCollected(in []collectedResult) (ok []trigger.SpaceTask, refused int, err error) {
	for _, c := range in {
		h, err := s.holders.Holder(c.Space, c.Identity)
		if err != nil {
			return nil, 0, err
		}
		var key ed25519.PublicKey
		if h != nil {
			key, _ = identity.ParseKey(h.Key)
		}
		if key == nil || len(c.Sig) != ed25519.SignatureSize || !ed25519.Verify(key, collectedMessage(c.Space, c.Identity, c.Task), c.Sig) {
			refused++
			continue
		}
		ok = append(ok, trigger.SpaceTask{Space: c.Space, Task: c.Task})
	}
	return ok, refused, nil
}

type handoffResult struct {
	Space string `json:"space"`
	Task  string `json:"task"`
	Enc   []byte `json:"enc"`
	CT    []byte `json:"ct"`
	Sig   []byte `json:"sig"`
}

// handoffDigest is what sig signs (with the label): SHA-256 of the four items' SHA-256s, in order.
func handoffDigest(space, task string, enc, ct []byte) [32]byte {
	h := sha256.New()
	for _, b := range [][]byte{[]byte(space), []byte(task), enc, ct} {
		d := sha256.Sum256(b)
		h.Write(d[:])
	}
	var out [32]byte
	h.Sum(out[:0])
	return out
}

func validSpace(s string) bool { return strings.HasPrefix(s, "s_") && len(s) <= 64 }

// scheduleHandoff: POST /schedules/handoff, the relay's cron.
func (s *server) scheduleHandoff(w http.ResponseWriter, r *http.Request) {
	if !s.authorized(r) {
		fail(w, 401, "unauthorized")
		return
	}
	var req handoffRequest
	body, err := io.ReadAll(io.LimitReader(r.Body, 2<<20))
	if err == nil {
		err = json.Unmarshal(body, &req)
	}
	if err != nil || len(req.Spaces) > maxHandoffSpaces || len(req.Ack) > maxHandoffItems || len(req.Collected) > maxHandoffItems ||
		slices.ContainsFunc(req.Spaces, func(sp string) bool { return !validSpace(sp) }) ||
		slices.ContainsFunc(req.Ack, func(t string) bool { return !harness.ValidTaskID(t) }) ||
		slices.ContainsFunc(req.Collected, func(c collectedResult) bool {
			return !validSpace(c.Space) || !harness.ValidTaskID(c.Task) || !runauth.IsID(c.Identity, "i")
		}) {
		failDetail(w, 400, "bad_request", `body must be {"spaces": ["s_…"], "ack": ["tk_…"], "collected": [{"space", "task", "identity", "sig"}]}`)
		return
	}
	hs, ok := s.results.(trigger.HandoffStore)
	if !s.personal() || !ok || s.rec == nil {
		fail(w, 503, "identity_unavailable")
		return
	}
	deleted, refused := 0, 0
	if len(req.Collected) > 0 {
		var signed []trigger.SpaceTask
		if signed, refused, err = s.verifyCollected(req.Collected); err != nil {
			fail(w, 500, "store_unavailable")
			return
		}
		if len(signed) > 0 {
			if deleted, err = hs.DeleteCollected(signed); err != nil {
				fail(w, 500, "store_unavailable")
				return
			}
		}
	}
	s.handed.add(req.Ack)
	pending, err := hs.Pending(handoffScan)
	if err != nil {
		fail(w, 500, "store_unavailable")
		return
	}
	want := map[string]bool{}
	for _, sp := range req.Spaces {
		want[sp] = true
	}
	live := map[string]bool{}
	out := []handoffResult{}
	more, size := false, 0
	for _, p := range pending {
		live[p.Task] = true
		if !want[p.Space] || s.handed.has(p.Task) {
			continue
		}
		if len(out) == handoffPage || (len(out) > 0 && size+cap(p.CT) > handoffBytes) {
			more = true
			continue
		}
		x, err := s.results.GetResult(p.Space, p.Seal, p.Task)
		if err != nil {
			fail(w, 500, "store_unavailable")
			return
		}
		if x == nil { // deleted meanwhile
			continue
		}
		sig, err := s.rec.Signer.SignLabeled(handoffLabel, handoffDigest(x.Space, x.Task, x.Enc, x.CT))
		if err != nil {
			log.Printf("schedules: a hand-off wasn't signed: %v", err)
			fail(w, 500, "store_unavailable")
			return
		}
		out = append(out, handoffResult{Space: x.Space, Task: x.Task, Enc: x.Enc, CT: x.CT, Sig: sig})
		size += len(x.CT)
	}
	if len(pending) < handoffScan {
		s.handed.keep(live)
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, map[string]any{"results": out, "more": more, "deleted": deleted, "refused": refused})
}
