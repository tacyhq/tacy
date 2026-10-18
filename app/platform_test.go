package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeGuestAgent serves /GetQuote and /Info on a unix socket like dstack's guest agent: quotes are TDX v4-shaped
// with RTMR3 = rtmr3 (settable), /Info carries the same RTMR3 and, once ready, a "system-ready" event.
type fakeGuestAgent struct {
	mu     sync.Mutex
	rtmr3  byte // every byte of RTMR3
	ready  bool
	quotes atomic.Int32
	infos  atomic.Int32
}

func (f *fakeGuestAgent) state() ([]byte, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return bytes.Repeat([]byte{f.rtmr3}, 48), f.ready
}

func (f *fakeGuestAgent) set(rtmr3 byte, ready bool) {
	f.mu.Lock()
	f.rtmr3, f.ready = rtmr3, ready
	f.mu.Unlock()
}

func fakeQuote(rtmr3 []byte) []byte {
	raw := make([]byte, 632)
	raw[0], raw[4] = 4, 0x81
	copy(raw[tdxQuoteRTMR3:], rtmr3)
	return raw
}

func (f *fakeGuestAgent) start(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "ga")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "d.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /GetQuote", func(w http.ResponseWriter, r *http.Request) {
		f.quotes.Add(1)
		rt, _ := f.state()
		json.NewEncoder(w).Encode(map[string]string{"quote": hex.EncodeToString(fakeQuote(rt)), "event_log": "[]"})
	})
	mux.HandleFunc("GET /Info", func(w http.ResponseWriter, r *http.Request) {
		f.infos.Add(1)
		rt, ready := f.state()
		events := []map[string]any{{"imr": 3, "event": "compose-hash"}}
		if ready {
			events = append(events, map[string]any{"imr": 3, "event": "system-ready"})
		}
		tcb, _ := json.Marshal(map[string]any{"rtmr3": hex.EncodeToString(rt), "event_log": events, "app_compose": "{}"})
		json.NewEncoder(w).Encode(map[string]any{"app_id": "a", "tcb_info": string(tcb)}) // tcb_info as a string, like dstack
	})
	srv := &http.Server{Handler: mux}
	go srv.Serve(l)
	t.Cleanup(func() { srv.Close() })
	return sock
}

func infoOf(t *testing.T, info json.RawMessage) byte {
	t.Helper()
	rt, _ := infoRTMR3(info)
	if len(rt) != 48 {
		t.Fatalf("info without rtmr3: %s", info)
	}
	return rt[0]
}

// /Info is fetched once per RTMR3, not per /attest; a quote whose RTMR3 moved gets a fresh /Info.
func TestEvidenceReusesInfoForTheSameRTMR3(t *testing.T) {
	f := &fakeGuestAgent{rtmr3: 1, ready: true}
	d := newDstack(f.start(t), "")
	ctx := context.Background()
	rd := make([]byte, 64)
	for i := range 3 {
		q, info, err := d.Evidence(ctx, rd)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(quoteRTMR3(q), bytes.Repeat([]byte{1}, 48)) || infoOf(t, info) != 1 {
			t.Fatalf("call %d: quote and info disagree", i)
		}
	}
	if q, i := f.quotes.Load(), f.infos.Load(); q != 3 || i != 1 {
		t.Fatalf("quotes %d, infos %d; want 3 fresh quotes and 1 info", q, i)
	}
	f.set(2, true) // RTMR3 extended: the kept /Info no longer matches
	_, info, err := d.Evidence(ctx, rd)
	if err != nil {
		t.Fatal(err)
	}
	if infoOf(t, info) != 2 || f.infos.Load() != 2 {
		t.Fatalf("info rtmr3 %d after %d fetches; want a fresh one", infoOf(t, info), f.infos.Load())
	}
}

// The boot prefetch keeps trying until dstack's boot finished (system-ready), then stops; /attest after it makes
// one guest agent call.
func TestPrefetchInfoUntilSystemReady(t *testing.T) {
	f := &fakeGuestAgent{rtmr3: 1}
	d := newDstack(f.start(t), "")
	done := make(chan struct{})
	go func() { d.PrefetchInfo(context.Background(), 10*time.Millisecond, 10*time.Second); close(done) }()
	for f.infos.Load() < 2 {
		time.Sleep(5 * time.Millisecond)
	}
	f.set(3, true)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("prefetch didn't stop after system-ready")
	}
	n := f.infos.Load()
	_, info, err := d.Evidence(context.Background(), make([]byte, 64))
	if err != nil {
		t.Fatal(err)
	}
	if infoOf(t, info) != 3 || f.infos.Load() != n {
		t.Fatalf("attest fetched /Info again (%d -> %d) or got rtmr3 %d", n, f.infos.Load(), infoOf(t, info))
	}
}

// A response that isn't a TDX v4 quote never reuses a kept /Info.
func TestQuoteRTMR3RefusesOtherShapes(t *testing.T) {
	good := fakeQuote(bytes.Repeat([]byte{7}, 48))
	j := func(raw []byte) json.RawMessage {
		b, _ := json.Marshal(map[string]string{"quote": hex.EncodeToString(raw)})
		return b
	}
	if rt := quoteRTMR3(j(good)); len(rt) != 48 || rt[0] != 7 {
		t.Fatalf("v4 quote: %x", rt)
	}
	v3 := bytes.Clone(good)
	v3[0] = 3
	sgx := bytes.Clone(good)
	sgx[4] = 0
	for name, in := range map[string]json.RawMessage{"v3": j(v3), "sgx": j(sgx), "short": j(good[:500]), "not json": json.RawMessage(`x`),
		"not hex": json.RawMessage(`{"quote":"zz"}`)} {
		if rt := quoteRTMR3(in); rt != nil {
			t.Errorf("%s: got %x", name, rt)
		}
	}
}

// The real fixture: the quote's RTMR3 at the offset used here equals /Info's tcb_info.rtmr3, and its event log
// ends with system-ready.
func TestRTMR3OffsetOnARealAttestation(t *testing.T) {
	b, err := os.ReadFile("../testdata/attest-061.json")
	if err != nil {
		t.Fatal(err)
	}
	var a struct {
		Quote json.RawMessage `json:"quote"`
		Info  json.RawMessage `json:"info"`
	}
	if err := json.Unmarshal(b, &a); err != nil {
		t.Fatal(err)
	}
	q := quoteRTMR3(a.Quote)
	i, ready := infoRTMR3(a.Info)
	if q == nil || !bytes.Equal(q, i) || !ready {
		t.Fatalf("quote rtmr3 %x, info rtmr3 %x, ready %v", q, i, ready)
	}
}
