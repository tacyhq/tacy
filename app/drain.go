package main

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Drain (V1-DESIGN §4.5; the chat Worker's blue/green switch, the chat Worker's vm-switch.ts). Before the Worker
// points new requests at another VM it drains this one, through the tunnel, in the relay's signed envelope like every
// other Worker call (POST /v; the ingress allowlist in gateway/cftunnel passes nothing else):
//
//	POST /drain   {"until": <unix seconds>}  -> 200 {"drained": true, "until": <unix>, "open": n}
//	POST /undrain {}                         -> 200 {"drained": false, "open": n}
//
// While drained this VM starts nothing new and changes no state but what finishing its work needs:
//   - every route but the ones that follow or finish running work answers 503 {"error": "draining"} (drainPasses):
//     no task start (POST /tasks, /run), no schedule install, change, event or reseal, no connection or notification
//     change, no search;
//   - no schedule fires, and the timed writes wait (the trigger engine's files' keys expiring and pruning, results'
//     and activity records' pruning): triggerTick, pruneResults and pruneActivity skip them. Not firing also means not renewing the spaces' ownership rows (unlock/owner.go), which
//     lapse for the new VM;
//   - running tasks go on to their end (their status, events, cancel, delete, prompts' answers, mail logins sent
//     again, approvals), and what they leave is delivered (POST /schedules/handoff, /notify/pending). The signed
//     safety documents keep arriving (their floors are written while drained, V1-DESIGN §4.6). GETs pass.
//
// The drain ends by itself at `until`, at most drainMax after it arrived (a forgotten drain can't stop a VM's
// schedules), or on /undrain. With the task queue in agentd's host tmpfs (-tasks-dir) the end time is kept there
// (drainFile: one number), so the hourly container restart doesn't end a drain early; a real boot does.
const drainMax = 2 * time.Hour

// drainFile is the drain's end time in the task queue's tmpfs directory.
const drainFile = "drain"

type drainState struct {
	mu    sync.Mutex
	until time.Time // zero: not drained
	dir   string    // the task queue's host tmpfs ("": memory only)
}

// on says whether the VM is drained at now.
func (d *drainState) on(now time.Time) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return now.Before(d.until)
}

// set drains until u (zero: undrains) and keeps it in the tmpfs, if any.
func (d *drainState) set(u time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.until = u
	if d.dir == "" {
		return
	}
	if err := d.keep(u); err != nil {
		log.Printf("drain: not kept in the tmpfs (it holds until this process ends): %v", err)
	}
}

// keep writes u (unix seconds; 0: none) into the task queue's tmpfs, which queue.OpenTmpfs checked is memory and
// agentd's alone before anything ran. A number only, nothing of anyone's.
func (d *drainState) keep(u time.Time) error {
	v := int64(0)
	if !u.IsZero() {
		v = u.Unix()
	}
	p := d.dir + "/" + drainFile
	if err := os.WriteFile(p+".tmp", []byte(strconv.FormatInt(v, 10)+"\n"), 0o600); err != nil {
		return err
	}
	return os.Rename(p+".tmp", p)
}

// restore takes up a drain an earlier process of this boot kept in dir (the queue's tmpfs), if it hasn't ended.
func (d *drainState) restore(dir string, now time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.dir = dir
	b, err := os.ReadFile(dir + "/" + drainFile)
	if err != nil {
		return
	}
	v, err := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
	if err != nil || v <= 0 {
		return
	}
	if u := time.Unix(v, 0); now.Before(u) && !u.After(now.Add(drainMax)) {
		d.until = u
		log.Printf("drain: drained until %s (kept from the last process)", u.UTC().Format(time.RFC3339))
	}
}

// drainPassing are the POST routes a drained VM still serves: what follows or finishes running work, the relay's
// deliveries of what it left, the signed safety documents, connection deletions (a person's remove, the relay's forget
// of a deleted account: final review L5, so a VM undrained later by a rollback doesn't keep a login the active one
// forgot), and the drain itself.
var drainPassing = map[string]bool{
	"/drain": true, "/undrain": true,
	"/connections/remove": true, "/connections/forget": true,
	"/tasks/status": true, "/tasks/events": true, "/tasks/cancel": true, "/tasks/delete": true,
	"/tasks/grant": true, "/tasks/credential": true,
	"/approvals": true, "/approvals/list": true,
	"/schedules/handoff": true, "/notify/pending": true,
	"/safety": true, "/keylog": true,
}

func drainPasses(r *http.Request) bool {
	return r.Method == http.MethodGet || r.Method == http.MethodHead || drainPassing[r.URL.Path]
}

// drainRoutes serves POST /drain and /undrain (the relay's envelope; plaintext JSON inside it).
func (s *server) drainRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /drain", s.drainIn)
	mux.HandleFunc("POST /undrain", s.undrainIn)
}

func (s *server) drainIn(w http.ResponseWriter, r *http.Request) {
	if !s.authorized(r) {
		fail(w, 401, "unauthorized")
		return
	}
	var b struct {
		Until int64 `json:"until"`
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1024))
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err != nil || dec.Decode(&b) != nil {
		fail(w, 400, "body must be {\"until\": <unix seconds>}")
		return
	}
	now := time.Now()
	u := time.Unix(b.Until, 0)
	if b.Until <= 0 || !u.After(now) {
		fail(w, 400, "until must be in the future")
		return
	}
	if most := now.Add(drainMax).Truncate(time.Second); u.After(most) {
		u = most
	}
	s.drain.set(u)
	log.Printf("drain: drained until %s (%d tasks open)", u.UTC().Format(time.RFC3339), s.tasks().Open())
	writeJSON(w, 200, map[string]any{"drained": true, "until": u.Unix(), "open": s.tasks().Open()})
}

func (s *server) undrainIn(w http.ResponseWriter, r *http.Request) {
	if !s.authorized(r) {
		fail(w, 401, "unauthorized")
		return
	}
	s.drain.set(time.Time{})
	log.Printf("drain: undrained")
	writeJSON(w, 200, map[string]any{"drained": false, "open": s.tasks().Open()})
}
