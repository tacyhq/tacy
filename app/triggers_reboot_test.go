package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/tacyhq/tacy/guard"
	"github.com/tacyhq/tacy/harness"
	"github.com/tacyhq/tacy/identity"
	"github.com/tacyhq/tacy/safety"
	"github.com/tacyhq/tacy/trigger"
)

// TestEventNoDoubleRunAcrossReboot (V1-DESIGN §6.3, review M5): an event starts a task, and the VM reboots before the
// side state's next debounced save (here: no save at all, no SIGTERM). The task queue is gone with TD memory. The
// same signed event, delivered again inside its window, must not run a second time: the delivery was recorded and
// saved, sealed at the Worker, before the task started. And when that save fails, nothing starts and the delivery
// is given back, so a later delivery runs it once.
func TestEventNoDoubleRunAcrossReboot(t *testing.T) {
	ctx := context.Background()
	w := newKMSWorld(t)
	se := newTriggerEnv(t, pText("Nothing to do."))
	_, sender, _ := ed25519.GenerateKey(nil)
	evTrigger := randID("tr")
	def, _ := trigger.SignDefinition(se.definition(func(d *trigger.Definition) {
		d.Triggers = []trigger.Trigger{{ID: evTrigger, Kind: trigger.Event, Sender: identity.KeyString(sender.Public().(ed25519.PublicKey))}}
	}), se.sponsor.Identity)
	// boot binds se's server to a boot's sealed side state, as main.go does: the trigger engine on it, and the
	// synchronous save; a fresh task queue (a reboot leaves none).
	boot := func(b *booted) {
		se.s.triggers = trigger.New(trigger.Config{Firm: "f_chat", Dir: &se.dir, Store: b.kept.side, IDKey: []byte("agentd id key"),
			Trusted: se.s.safety.OperatorTime})
		if _, err := se.s.triggers.Load(); err != nil {
			t.Fatal(err)
		}
		se.s.saveState = b.kept.keeper.SaveNow
		se.s.rt = newRuntime(se.s.rt.Guard, harness.NewMemStore(), se.s.lim)
		se.s.host = &guard.Host{RT: se.s.rt, GW: se.s.tasks().GW, IDKey: []byte("agentd id key")}
	}
	post := func(env safety.Envelope) (int, string) {
		return se.call(func(w *httptest.ResponseRecorder, b []byte) {
			se.s.triggersEvent(w, httptest.NewRequest("POST", "/triggers/event", bytes.NewReader(b)))
		}, env)
	}
	started := func() int {
		open, _ := se.s.rt.Store.OpenTasks()
		return len(open)
	}

	b1, k1 := w.bootAgent(t, "inst-1")
	boot(b1)
	if code, body := se.install(def); code != 200 {
		t.Fatalf("install %d %s", code, body)
	}
	if err := b1.kept.keeper.Flush(ctx); err != nil { // the definition was saved long before the event
		t.Fatal(err)
	}
	ev, _ := trigger.SignEvent(trigger.EventPayload{Trigger: evTrigger, Delivery: "msg-1", SentAt: time.Now()}, sender)
	code, body := post(ev)
	if code != 200 || started() != 1 {
		t.Fatalf("event %d %s, %d tasks", code, body, started())
	}
	var out struct {
		Task string `json:"task"`
	}
	json.Unmarshal([]byte(body), &out)
	// The reboot: no final save, the lease freed (the old instance is gone), the queue empty.
	if err := k1.Drop(ctx); err != nil {
		t.Fatal(err)
	}
	b2, _ := w.bootAgent(t, "inst-2")
	boot(b2)
	if code, body := post(ev); code != 409 || started() != 0 {
		t.Errorf("the same event after the reboot: %d %s, %d tasks started (want 409, none): it ran twice", code, body, started())
	}
	if seen, err := b2.kept.side.Seen(evTrigger, "msg-1"); err != nil || !seen {
		t.Fatalf("after the reboot the delivery isn't recorded (%v)", err)
	}
	if st, err := se.s.rt.Status(out.Task); err == nil {
		t.Fatalf("the event's task runs again after the reboot: %+v", st)
	}

	// The save fails (the Worker unreachable): nothing starts, and the delivery is given back.
	saveNow := se.s.saveState
	se.s.saveState = func(context.Context, string) error { return errors.New("the Worker is unreachable") }
	ev2, _ := trigger.SignEvent(trigger.EventPayload{Trigger: evTrigger, Delivery: "msg-2", SentAt: time.Now()}, sender)
	if code, body := post(ev2); code != 503 || started() != 0 {
		t.Fatalf("a delivery whose record can't be saved: %d %s, %d tasks (want 503, none)", code, body, started())
	}
	if seen, _ := b2.kept.side.Seen(evTrigger, "msg-2"); seen {
		t.Fatal("a delivery whose record wasn't saved stays used")
	}
	se.s.saveState = saveNow
	if code, body := post(ev2); code != 200 || started() != 1 {
		t.Fatalf("the same delivery once the Worker is back: %d %s, %d tasks", code, body, started())
	}
	if code, _ := post(ev2); code != 409 || started() != 1 {
		t.Fatalf("its replay: %d, %d tasks", code, started())
	}
}
