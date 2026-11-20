package verifier

import (
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/tacyhq/tacy/internal/tdx"
	"github.com/tacyhq/tacy/proto"
)

// Any root process in a dstack CVM can extend RTMR3 after boot and append the event to the log it serves (dstack-util
// extend, the TDX guest device; dstack's own verifier reads nothing past "system-ready" for this reason). So any VM on
// a production dstack image could boot its own compose, then measure an approved compose's hash, and the replay would
// still match its genuine quote. These tests take the real recordings, give the VM another compose at boot (its
// genuine compose-hash event), append events after system-ready, and set the quote's RTMR3 to what the edited log
// replays to (what such a VM's real quote carries). Verify must refuse them at the event log check.

const eventLogCheck = "event log replays to RTMR3; compose-hash event = sha256(app-compose.json)"

// forge edits a's runtime events and returns a quote verifier (offline) whose RTMR3 is the edited log's replay.
func forge(t *testing.T, a *proto.Attestation, edit func([]tdx.Event) []tdx.Event) func(context.Context, []byte) (*tdx.Quote, error) {
	t.Helper()
	var q map[string]any
	json.Unmarshal(a.Quote, &q)
	ev, err := tdx.ParseEventLog(json.RawMessage(mustJSON(q["event_log"])))
	if err != nil {
		t.Fatal(err)
	}
	ev = edit(ev)
	mr := make([]byte, 48)
	for i, e := range ev {
		if e.IMR != 3 {
			continue
		}
		d := eventDigest(t, e)
		ev[i].Digest = hex.EncodeToString(d)
		h := sha512.New384()
		h.Write(mr)
		h.Write(d)
		mr = h.Sum(nil)
	}
	b, _ := json.Marshal(ev)
	q["event_log"] = string(b)
	a.Quote, _ = json.Marshal(q)
	return changeQuote(func(q *tdx.Quote) { q.Rtmrs[3] = mr })
}

// eventDigest is dstack's runtime event digest (cc-eventlog V1 and V2), written out here so the forged logs don't
// depend on the code under test.
func eventDigest(t *testing.T, e tdx.Event) []byte {
	t.Helper()
	payload, err := hex.DecodeString(e.EventPayload)
	if err != nil {
		t.Fatal(err)
	}
	if e.Version != nil && *e.Version >= 2 {
		j, _ := json.Marshal(struct {
			Name    string `json:"name"`
			Payload string `json:"payload"`
			Type    uint32 `json:"type"`
		}{e.Event, e.EventPayload, 0x08000001})
		h := sha512.Sum384(j)
		return h[:]
	}
	h := sha512.New384()
	binary.Write(h, binary.LittleEndian, uint32(0x08000001))
	h.Write([]byte(":" + e.Event + ":"))
	h.Write(payload)
	return h.Sum(nil)
}

// copyOf is a copy of the first runtime event named name, with payload if given.
func copyOf(t *testing.T, ev []tdx.Event, name string, payload *string) tdx.Event {
	t.Helper()
	for _, e := range ev {
		if e.IMR == 3 && e.Event == name {
			if payload != nil {
				e.EventPayload = *payload
			}
			return e
		}
	}
	t.Fatalf("no %s event", name)
	return tdx.Event{}
}

// bootedOther gives the VM another compose at boot: its compose-hash event is that compose's hash.
func bootedOther(ev []tdx.Event) []tdx.Event {
	other := sha256.Sum256([]byte(`{"docker_compose_file":"services: {attacker: {image: busybox}}"}`))
	for i := range ev {
		if ev[i].IMR == 3 && ev[i].Event == "compose-hash" {
			ev[i].EventPayload = hex.EncodeToString(other[:])
			break
		}
	}
	return ev
}

// beforeReady inserts e right before system-ready.
func beforeReady(ev []tdx.Event, e tdx.Event) []tdx.Event {
	for i := range ev {
		if ev[i].IMR == 3 && ev[i].Event == "system-ready" {
			return append(ev[:i], append([]tdx.Event{e}, ev[i:]...)...)
		}
	}
	return ev
}

type recording struct {
	name string
	load func(t *testing.T) (*proto.Attestation, []byte, Policy)
}

// The 0.6.4 recording passes every check under its policy, so a refusal at the event log check is the new rule.
var recordings = []recording{
	{"0.6.4", func(t *testing.T) (*proto.Attestation, []byte, Policy) {
		a, nonce, compose := load064(t)
		return a, nonce, Policy{AllowStaleTCB: true, VerifyQuote: offline.VerifyQuote, Compose: compose, legacy: true,
			PreLaunch: RetiredPreLaunchScripts, ProdImages: allImages(), Boot: allSets()}
	}},
}

func TestEventLogUnchangedPasses(t *testing.T) {
	for _, rec := range recordings {
		a, nonce, p := rec.load(t)
		p.VerifyQuote = forge(t, a, func(ev []tdx.Event) []tdx.Event { return ev })
		_, err := Verify(context.Background(), a, nonce, p)
		if err != nil {
			t.Fatalf("%s unchanged: %v", rec.name, err)
		}
		// An app's own event after system-ready, under a name that isn't dstack's, changes nothing.
		a, nonce, p = rec.load(t)
		p.VerifyQuote = forge(t, a, func(ev []tdx.Event) []tdx.Event {
			e := copyOf(t, ev, "storage-fs", nil)
			e.Event, e.EventPayload = "app-ready", hex.EncodeToString([]byte("1"))
			return append(ev, e)
		})
		if _, err2 := Verify(context.Background(), a, nonce, p); (err == nil) != (err2 == nil) {
			t.Fatalf("%s with an app event after system-ready: %v (unchanged: %v)", rec.name, err2, err)
		}
	}
}

func TestEventLogForgeriesRefused(t *testing.T) {
	type forgery struct {
		name string
		edit func(t *testing.T, ev []tdx.Event) []tdx.Event
	}
	forgeries := []forgery{
		{"another compose at boot, the approved compose-hash after system-ready", func(t *testing.T, ev []tdx.Event) []tdx.Event {
			approved := copyOf(t, ev, "compose-hash", nil)
			return append(bootedOther(ev), approved)
		}},
		{"another compose at boot, then every system event again after system-ready", func(t *testing.T, ev []tdx.Event) []tdx.Event {
			var tail []tdx.Event
			for _, n := range []string{"system-preparing", "app-id", "compose-hash", "instance-id", "boot-mr-done", "os-image-hash",
				"key-provider", "storage-fs", "storage-encrypted", "system-ready"} {
				tail = append(tail, copyOf(t, ev, n, nil))
			}
			return append(bootedOther(ev), tail...)
		}},
		{"another compose at boot, the approved compose-hash measured again before system-ready", func(t *testing.T, ev []tdx.Event) []tdx.Event {
			approved := copyOf(t, ev, "compose-hash", nil)
			return beforeReady(bootedOther(ev), approved)
		}},
	}
	// Each system event the verifier reads, appended after system-ready with its own value or another: refused by
	// its name, whatever the value.
	other := strings.Repeat("ab", 32)
	for _, n := range []string{"app-id", "compose-hash", "instance-id", "key-provider", "os-image-hash", "boot-mr-done", "system-ready"} {
		forgeries = append(forgeries,
			forgery{n + " again after system-ready", func(t *testing.T, ev []tdx.Event) []tdx.Event {
				return append(ev, copyOf(t, ev, n, nil))
			}},
			forgery{n + " with another value after system-ready", func(t *testing.T, ev []tdx.Event) []tdx.Event {
				return append(ev, copyOf(t, ev, n, &other))
			}},
			forgery{n + " twice before system-ready", func(t *testing.T, ev []tdx.Event) []tdx.Event {
				return beforeReady(ev, copyOf(t, ev, n, &other))
			}})
	}
	for _, rec := range recordings {
		for _, f := range forgeries {
			a, nonce, p := rec.load(t)
			p.VerifyQuote = forge(t, a, func(ev []tdx.Event) []tdx.Event { return f.edit(t, ev) })
			res, err := Verify(context.Background(), a, nonce, p)
			if err == nil || !strings.HasPrefix(err.Error(), eventLogCheck+": ") {
				t.Errorf("%s, %s: want refused at the event log check, got %v", rec.name, f.name, err)
				continue
			}
			if res.HPKEPublicKey != nil || res.Facts["compose hash"] != "" || res.Facts["app id"] != "" {
				t.Errorf("%s, %s: refused but facts %v", rec.name, f.name, res.Facts)
			}
		}
	}
}
