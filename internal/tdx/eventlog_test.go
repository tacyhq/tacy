package tdx

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"strings"
	"testing"
)

// Any root process in a dstack CVM can extend RTMR3 after boot and append the event to the log, so the log can end
// with events the app chose; the replay still matches the quote. Only the events dstack's guest measured before
// "system-ready" say what booted. These logs are synthetic; verifier's eventlog tests use real recordings.

func ev(name string, payload []byte) Event {
	two := 2
	return Event{IMR: 3, EventType: runtimeEventType, Event: name, EventPayload: hex.EncodeToString(payload), Version: &two}
}

func boot(compose []byte) []Event {
	h := sha256.Sum256(compose)
	return []Event{
		ev("system-preparing", nil), ev("app-id", []byte("app-id-20-bytes-long")), ev("compose-hash", h[:]),
		ev("instance-id", []byte("instance-id-20-bytes")), ev("boot-mr-done", nil), ev("os-image-hash", make([]byte, 32)),
		ev("key-provider", []byte(`{"name":"none","id":""}`)), ev("storage-fs", []byte("ext4")),
		ev("storage-encrypted", []byte("1")), ev("system-ready", nil),
	}
}

// quoteFor is a quote whose RTMR3 is what log replays to, as a real quote of a VM that extended those events carries.
func quoteFor(t *testing.T, log []Event) *Quote {
	t.Helper()
	mr := make([]byte, 48)
	for _, e := range log {
		d, err := runtimeDigest(e)
		if err != nil {
			t.Fatal(err)
		}
		h := sha512.New384()
		h.Write(mr)
		h.Write(d)
		mr = h.Sum(nil)
	}
	q := &Quote{}
	q.Rtmrs[3] = mr
	return q
}

func TestCheckAppBootLog(t *testing.T) {
	approved := []byte(`{"approved":"compose"}`)
	log := boot(approved)
	rt, err := CheckApp(quoteFor(t, log), log, approved)
	if err != nil {
		t.Fatal(err)
	}
	if rt.Values["app-id"] != hex.EncodeToString([]byte("app-id-20-bytes-long")) {
		t.Fatalf("values %v", rt.Values)
	}
	// An app's own events after system-ready, under names that aren't dstack's, are allowed and not read.
	log = append(log, ev("my-app-event", []byte("x")))
	if _, err := CheckApp(quoteFor(t, log), log, approved); err != nil {
		t.Fatalf("app event after system-ready: %v", err)
	}
	// One init-script-hash per init script (dstack measures each).
	log = boot(approved)
	log = append(log[:3], append([]Event{ev("init-script-hash", []byte("a")), ev("init-script-hash", []byte("b"))}, log[3:]...)...)
	if _, err := CheckApp(quoteFor(t, log), log, approved); err != nil {
		t.Fatalf("two init-script-hash events: %v", err)
	}
}

// The review probe: the VM booted another compose, then measured the approved compose's hash after system-ready.
func TestForgedComposeAfterSystemReady(t *testing.T) {
	approved := []byte(`{"approved":"compose"}`)
	want := sha256.Sum256(approved)
	log := append(boot([]byte(`{"attacker":"compose"}`)), ev("compose-hash", want[:]))
	if _, err := CheckApp(quoteFor(t, log), log, approved); err == nil || !strings.Contains(err.Error(), "after system-ready") {
		t.Fatalf("a compose-hash after system-ready was accepted: %v", err)
	}
}

func TestBootLogRules(t *testing.T) {
	approved := []byte(`{"approved":"compose"}`)
	h := sha256.Sum256(approved)
	// dstack's boot events (dstack-util system_setup.rs, 0.5 to 0.6.5).
	names := []string{"system-preparing", "app-id", "compose-hash", "init-script-hash", "gpu-policy-hash", "instance-id",
		"boot-mr-done", "mr-kms", "os-image-hash", "key-provider", "gpu-attestation", "storage-fs", "storage-encrypted",
		"rootfs-hash", "system-ready"}
	for _, name := range names {
		// The same value again after system-ready: refused for its name, whatever its value.
		log := boot(approved)
		var payload []byte
		for _, e := range log {
			if e.Event == name {
				payload, _ = hex.DecodeString(e.EventPayload)
			}
		}
		log = append(log, ev(name, payload))
		if _, err := CheckApp(quoteFor(t, log), log, approved); err == nil || !strings.Contains(err.Error(), "after system-ready") {
			t.Errorf("%s after system-ready: %v", name, err)
		}
	}
	for _, name := range []string{"compose-hash", "app-id", "instance-id", "key-provider", "os-image-hash", "boot-mr-done"} {
		// Measured twice before system-ready: refused (no reader can pick one).
		log := boot(approved)
		i := len(log) - 1
		log = append(log[:i], ev(name, h[:]), log[i])
		if _, err := CheckApp(quoteFor(t, log), log, approved); err == nil || !strings.Contains(err.Error(), "measured twice") {
			t.Errorf("%s twice before system-ready: %v", name, err)
		}
	}
	// No system-ready: the VM hasn't finished booting; nothing in the log is a boot-time value yet.
	log := boot(approved)
	log = log[:len(log)-1]
	if _, err := CheckApp(quoteFor(t, log), log, approved); err == nil || !strings.Contains(err.Error(), "no system-ready") {
		t.Fatalf("no system-ready: %v", err)
	}
}
