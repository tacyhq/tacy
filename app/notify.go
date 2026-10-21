package main

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"

	ehbpidentity "github.com/tinfoilsh/encrypted-http-body-protocol/identity"

	"github.com/tacyhq/tacy/guard"
	"github.com/tacyhq/tacy/harness"
	"github.com/tacyhq/tacy/runauth"
)

// Run notifications (decided 2026-10-21; the chat's Web Push relay is the other half): a content-free notice
// on the person's devices when a run of theirs finished unattended or waits for them, so they know to open Tacy. Off
// unless the person turned it on for their space (POST /notify/set, signed like a schedule call: the relay can't turn
// it on for anyone). Then, and only then, the space is marked when
//
//   - a scheduled run ended with a result the chat saves as a new message ("done"; resultNotifies),
//   - a hand-off task (a built-in agent the chat started: research, review) ended while nobody followed it
//     ("finished"; handoffNotifies), or
//   - a prompt (a permission, or approve-before-send) opened in a task nobody follows right now ("waiting").
//
// The relay's cron drains the marks (POST /notify/pending, bearer token, plaintext): per space at most one mark of
// each kind since its last drain. It learns that the space had such an event within that minute, nothing else:
// no task, schedule, conversation, count, model or time beyond the drain's. The relay sends only the spaces with a
// device subscribed; marks for any other space are dropped, never answered.
//
//	POST /notify/set      {where and who, on} -> {on}                       EHBP; label tacy/v2/notify-set, item "on"|"off"
//	POST /notify/pending  {spaces: ["s_…", …]} -> {events: [{space, kind}]}  bearer token; kind "done" | "finished" | "waiting"
//
// The spaces turned on are kept in notify.json on the VM's encrypted disk (its own file, so a rollback's agentd, which
// doesn't know it, simply never reads it); the marks are memory only (a restart drops them: a missed notice, nothing
// worse).

const (
	notifyDone uint8 = 1 << iota
	notifyWaiting
	notifyFinished
)

// maxNotifySpaces bounds the spaces turned on, and the marks kept between drains.
const maxNotifySpaces = 100_000

// maxPendingSpaces bounds one drain's request (the relay sends its subscribed spaces).
const maxPendingSpaces = 10_000

type notifier struct {
	mu      sync.Mutex
	path    string // "" in memory
	on      map[string]bool
	pending map[string]uint8
}

type notifyFile struct {
	On []string `json:"on"`
}

// openNotifier loads the spaces turned on from path ("" or missing: none).
func openNotifier(path string) (*notifier, error) {
	n := &notifier{path: path, on: map[string]bool{}, pending: map[string]uint8{}}
	if path == "" {
		return n, nil
	}
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return n, nil
	}
	if err != nil {
		return nil, err
	}
	var f notifyFile
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, err
	}
	for _, s := range f.On {
		n.on[s] = true
	}
	return n, nil
}

// save writes the spaces turned on (n.mu held): a temporary file, then a rename.
func (n *notifier) save() error {
	if n.path == "" {
		return nil
	}
	f := notifyFile{On: make([]string, 0, len(n.on))}
	for s := range n.on {
		f.On = append(f.On, s)
	}
	slices.Sort(f.On)
	b, err := json.Marshal(f)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(n.path), 0o700); err != nil {
		return err
	}
	tmp := n.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, n.path)
}

// Set turns notifications on or off for a space. Off drops its marks too.
func (n *notifier) Set(space string, on bool) error {
	if n == nil {
		return nil
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.on[space] == on {
		return nil
	}
	if on {
		if len(n.on) >= maxNotifySpaces {
			return errTooManyNotify
		}
		n.on[space] = true
	} else {
		delete(n.on, space)
		delete(n.pending, space)
	}
	if err := n.save(); err != nil {
		if on {
			delete(n.on, space)
		} else {
			n.on[space] = true
		}
		return err
	}
	return nil
}

// On says whether the space turned notifications on.
func (n *notifier) On(space string) bool {
	if n == nil {
		return false
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.on[space]
}

// Mark notes an event of kind for the space, if it turned notifications on (else nothing is kept).
func (n *notifier) Mark(space string, kind uint8) {
	if n == nil || space == "" {
		return
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if !n.on[space] {
		return
	}
	if _, ok := n.pending[space]; !ok && len(n.pending) >= maxNotifySpaces {
		return
	}
	n.pending[space] |= kind
}

type notifyEvent struct {
	Space string `json:"space"`
	Kind  string `json:"kind"`
}

// Drain returns the marks of the spaces named (still turned on), and forgets every mark, named or not.
func (n *notifier) Drain(spaces []string) []notifyEvent {
	out := []notifyEvent{}
	if n == nil {
		return out
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	seen := map[string]bool{}
	for _, s := range spaces {
		k, ok := n.pending[s]
		if !ok || seen[s] || !n.on[s] {
			continue
		}
		seen[s] = true
		if k&notifyWaiting != 0 {
			out = append(out, notifyEvent{Space: s, Kind: "waiting"})
		}
		if k&notifyDone != 0 {
			out = append(out, notifyEvent{Space: s, Kind: "done"})
		}
		if k&notifyFinished != 0 {
			out = append(out, notifyEvent{Space: s, Kind: "finished"})
		}
	}
	clear(n.pending)
	return out
}

type notifyError string

func (e notifyError) Error() string { return string(e) }

const errTooManyNotify = notifyError("too many spaces with notifications on")

// resultNotifies says whether a scheduled run's result notifies its person (when they turned notifications on): a
// result the chat saves as a new message in the schedule's conversation. A run the person stopped doesn't, nor does a
// quiet run, one that found nothing new to say ("only tell me when something changes": trigger.Result.Quiet, set from
// guard.QuietRun in triggeredDone), which the chat records in the schedule's entry without a message.
func resultNotifies(b *resultBody) bool {
	if b != nil && b.Quiet {
		return false
	}
	return b != nil && b.State != harness.OutcomeCancelled
}

// handoffNotifies says whether an ended POST /tasks task notifies its person (when they turned notifications on): a
// hand-off to a built-in agent (research, review), not a chat turn or a scheduled run (resultNotifies says for those).
func handoffNotifies(o guard.TaskOptions) bool {
	return o.Agent != "" && o.Agent != guard.AgentScheduled
}

// taskEnded is guard.Host.TaskEnded: a hand-off task that ended while no event stream followed it marks its space
// "finished" (if on). One that a tab follows was seen there.
func (s *server) taskEnded(id string, o guard.TaskOptions) {
	if handoffNotifies(o) && !s.followed(id) {
		s.notify.Mark(o.Space, notifyFinished)
	}
}

// notifyRoutes serves POST /notify/set behind EHBP with id, and the relay's POST /notify/pending.
func (s *server) notifyRoutes(mux *http.ServeMux, id *ehbpidentity.Identity) {
	mux.Handle("POST /notify/set", s.taskGuard(false, false, id.Middleware()(http.HandlerFunc(s.notifySet))))
	mux.HandleFunc("POST /notify/pending", s.notifyPending)
}

type notifySetRequest struct {
	runauth.Where
	On bool `json:"on"`
}

// notifySet: POST /notify/set. The space's holder (the same where and who as a schedule call) turns notices on or off.
func (s *server) notifySet(w http.ResponseWriter, r *http.Request) {
	var req notifySetRequest
	if !readCall(w, r, 16<<10, &req) {
		return
	}
	who, ok := s.callWho(w, runauth.NotifyLabel, &req.Where, map[bool]string{true: "on", false: "off"}[req.On])
	if !ok {
		return
	}
	if s.notify == nil {
		fail(w, 503, "identity_unavailable")
		return
	}
	switch err := s.notify.Set(who.Space, req.On); {
	case err == errTooManyNotify:
		fail(w, 429, "busy")
	case err != nil:
		fail(w, 500, "store_unavailable")
	default:
		writeJSON(w, 200, map[string]bool{"on": req.On})
	}
}

type pendingRequest struct {
	Spaces []string `json:"spaces"`
}

// notifyPending: POST /notify/pending, the relay's cron. Bearer token; plaintext (space ids the relay already knows,
// and a kind).
func (s *server) notifyPending(w http.ResponseWriter, r *http.Request) {
	if !s.authorized(r) {
		fail(w, 401, "unauthorized")
		return
	}
	var req pendingRequest
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err == nil {
		err = json.Unmarshal(body, &req)
	}
	if err != nil || len(req.Spaces) > maxPendingSpaces {
		fail(w, 400, `body must be {"spaces": ["s_…", …]}`)
		return
	}
	for _, sp := range req.Spaces {
		if !strings.HasPrefix(sp, "s_") || len(sp) > 64 {
			fail(w, 400, "bad space id")
			return
		}
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, map[string]any{"events": s.notify.Drain(req.Spaces)})
}

// followTask counts an event stream following task (+1 when it opens, -1 when it closes).
func (s *server) followTask(task string, d int) {
	s.followMu.Lock()
	defer s.followMu.Unlock()
	if s.taskFollows == nil {
		s.taskFollows = map[string]int{}
	}
	if s.taskFollows[task] += d; s.taskFollows[task] <= 0 {
		delete(s.taskFollows, task)
	}
}

func (s *server) followed(task string) bool {
	s.followMu.Lock()
	defer s.followMu.Unlock()
	return s.taskFollows[task] > 0
}

// promptOpened is told when a prompt of task opens: a task nobody follows marks its space "waiting" (if on). Called
// with the prompts' lock held (guard.Prompts.OnWait): it touches only the follow count and the notifier.
func (s *server) promptOpened(task, space string) {
	if space == "" || s.followed(task) {
		return
	}
	s.notify.Mark(space, notifyWaiting)
}

// onWait wraps a prompts' OnWait (next: the ledger's clock) with the waiting mark.
func (s *server) onWait(next func(string, bool), spaceOf func(string) string) func(string, bool) {
	return func(task string, open bool) {
		if next != nil {
			next(task, open)
		}
		if open && spaceOf != nil {
			s.promptOpened(task, spaceOf(task))
		}
	}
}
