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
	"sync/atomic"
	"time"

	"github.com/tacyhq/tacy/unlock"
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
	// standby: this VM doesn't hold the sealed state's writer lease (lease.go: another VM does, it was released, or
	// it is close to its end): drained to every route as if by the Worker, and the routes that change sealed state
	// refused too (standbyPasses).
	standby atomic.Bool
	// admitting counts new-work requests past the drain check and not yet answered (gate): a drain's release waits
	// for them (design review M2: a task start admitted just before the drain counts as open once it is queued).
	admitting atomic.Int64
}

// on says whether the VM is drained at now: by the Worker, or as a standby without the writer lease.
func (d *drainState) on(now time.Time) bool {
	if d.standby.Load() {
		return true
	}
	return d.byWorker(now)
}

// settle waits up to d for the new-work requests admitted before the drain to be answered (a task start is then
// open, or refused).
func (d *drainState) settle(limit time.Duration) {
	for t0 := time.Now(); d.admitting.Load() > 0 && time.Since(t0) < limit; {
		time.Sleep(20 * time.Millisecond)
	}
}

// byWorker says whether the Worker drained this VM (its /drain, not yet ended or undone).
func (d *drainState) byWorker(now time.Time) bool {
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

// standbyPassing are the POST routes a VM without the writer lease still serves: reading a task's status and events,
// the signed safety documents (their floors stay in memory), and the drain itself. Everything else changes sealed
// state, which this VM can no longer save (design review M2: a delete, a handoff or an approval answered here would
// be lost); with nothing open after the release, there is nothing else to follow.
var standbyPassing = map[string]bool{
	"/drain": true, "/undrain": true,
	"/tasks/status": true, "/tasks/events": true,
	"/safety": true, "/keylog": true,
}

func standbyPasses(r *http.Request) bool {
	return r.Method == http.MethodGet || r.Method == http.MethodHead || standbyPassing[r.URL.Path]
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
		// Handoff "legacy": the switch goes to a VM built before the lease; once released, the row goes to the
		// legacy holder (lease.go toLegacy).
		Handoff string `json:"handoff,omitempty"`
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
	out := map[string]any{"drained": true, "until": u.Unix(), "open": s.tasks().Open()}
	// The writer lease (lease.go): released now if nothing is open or being admitted (a last save first), else once
	// they end; the Worker's switch asks again (drain is idempotent) until it says so.
	if s.lease != nil {
		s.drain.settle(5 * time.Second)
		out["lease"] = s.lease.drainedNow(r.Context())
		if b.Handoff == unlock.LegacyHolder {
			out["lease"] = s.lease.toLegacy(r.Context())
		}
		out["holder"] = s.lease.holder
		out["open"] = s.tasks().Open()
	}
	writeJSON(w, 200, out)
}

func (s *server) undrainIn(w http.ResponseWriter, r *http.Request) {
	if !s.authorized(r) {
		fail(w, 401, "unauthorized")
		return
	}
	// {} or {"take": "<holder>"}: the switch gives this VM the writer lease from that holder (lease.go undrained).
	var b struct {
		Take string `json:"take,omitempty"`
	}
	if body, err := io.ReadAll(io.LimitReader(r.Body, 1024)); err != nil || (len(bytes.TrimSpace(body)) > 0 && json.Unmarshal(body, &b) != nil) || len(b.Take) > 160 {
		fail(w, 400, `body must be {} or {"take": "<holder>"}`)
		return
	}
	s.drain.set(time.Time{})
	log.Printf("drain: undrained")
	out := map[string]any{"drained": false, "open": s.tasks().Open()}
	// The VM a switch moves to claims the writer lease now: held, standby (the old VM hasn't released it yet: ask
	// again), or reloading (another VM saved since this one loaded: it restarts to load that; ask again).
	if s.lease != nil {
		out["lease"] = s.lease.undrained(r.Context(), b.Take)
		out["holder"] = s.lease.holder
		out["row"] = s.lease.RowHolder()
	}
	writeJSON(w, 200, out)
}
