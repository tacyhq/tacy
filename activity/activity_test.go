package activity

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var update = flag.Bool("update", false, "rewrite testdata/vector.json (and the chat's copy)")

func signer(t testing.TB, b byte) *Signer {
	s, err := NewSigner(bytes.Repeat([]byte{b}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func recipient(t testing.TB) (*ecdh.PrivateKey, string) {
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k, RecipientString(k.PublicKey())
}

func trust(keys ...string) func(string) bool {
	return func(k string) bool {
		for _, x := range keys {
			if x == k {
				return true
			}
		}
		return false
	}
}

// runs records n runs in one chain (each a start and an end record) and returns the chain's records.
func runs(t *testing.T, rec *Recorder, to string, n int) []Sealed {
	t.Helper()
	for i := range n {
		id := "t_" + string(rune('a'+i))
		if _, err := rec.Begin(Start{Run: id, Space: "s_chat", To: to, Agent: Agent{ID: "a_chat", Version: "1", Digest: "unsigned"},
			Trigger: Trigger{Kind: "chat", Via: "relay"}, Models: []string{"gpt-oss-120b"}, Tools: []string{"web.search"},
			Input: Input{Messages: 2, Bytes: 120}}); err != nil {
			t.Fatal(err)
		}
		rec.Call(id, Call{ID: "m1", Kind: "model", Name: "gpt-oss-120b", Connector: "model", Outcome: "ok", Prompt: 100, Completion: 20,
			Hosts: []Host{{Host: "inference.tinfoil.sh", Requests: 1, BytesOut: 900, BytesIn: 400}}},
			[]Lease{{Secret: "TINFOIL_API_KEY", Connector: "model", Host: "inference.tinfoil.sh", Decision: "released", Lease: "l1"}})
		rec.Call(id, Call{ID: "a1", Kind: "action", Name: "web.search", Connector: "web", Outcome: "ok",
			Hosts: []Host{{Host: "api.tavily.com", Requests: 1, BytesOut: 80, BytesIn: 3000}}}, nil)
		if _, err := rec.Finish(id, End{Status: Status{State: "succeeded", Finish: "stop"}, Usage: &Usage{Tokens: 120, ToolCalls: 1}, Steps: 2}); err != nil {
			t.Fatal(err)
		}
	}
	chain, head, err := rec.Head("s_chat", to)
	if err != nil || head.Seq != uint64(2*n) {
		t.Fatalf("head %+v, %v", head, err)
	}
	recs, err := rec.Store.Records(chain, 0, 1000)
	if err != nil || len(recs) != 2*n {
		t.Fatalf("%d records, %v", len(recs), err)
	}
	return recs
}

func TestChainRoundTrip(t *testing.T) {
	s := signer(t, 7)
	priv, to := recipient(t)
	rec := &Recorder{Signer: s, Store: NewMemStore()}
	recs := runs(t, rec, to, 3)
	end, err := VerifyChain(recs, trust(s.Public()), nil)
	if err != nil || end.Seq != 6 {
		t.Fatalf("verify: %+v %v", end, err)
	}
	for i, r := range recs {
		h, body, err := Open(r, priv, trust(s.Public()))
		if err != nil {
			t.Fatalf("open %d: %v", i, err)
		}
		if h.Seq != uint64(i+1) || body.Seq != h.Seq || body.Space != "s_chat" {
			t.Fatalf("record %d: %+v %+v", i, h, body)
		}
		want := EventStart
		if i%2 == 1 {
			want = EventEnd
			if len(body.Calls) != 2 || len(body.Leases) != 1 || body.Leases[0].Call != "m1" || body.Status.State != "succeeded" || body.StartSeq != h.Seq-1 {
				t.Fatalf("end body: %+v", body)
			}
		}
		if body.Event != want {
			t.Fatalf("record %d is %s", i, body.Event)
		}
	}
	// Verifying in two parts (a browser that already checked the first part) gives the same end.
	mid, err := VerifyChain(recs[:3], trust(s.Public()), nil)
	if err != nil {
		t.Fatal(err)
	}
	if end2, err := VerifyChain(recs[3:], trust(s.Public()), &mid); err != nil || end2 != end {
		t.Fatalf("resumed verify: %+v %v", end2, err)
	}
	// Another recipient can't open it; the header says nothing but ids, times, keys and sizes.
	other, _ := recipient(t)
	if _, _, err := Open(recs[0], other, nil); err == nil {
		t.Fatal("opened with another key")
	}
	// Bodies are padded to size buckets: a start and an end record of a small run are the same size.
	sizes := map[int]bool{}
	for _, r := range recs {
		h, _, _ := Check(r, nil)
		sizes[h.CTLen] = true
	}
	if len(sizes) != 1 || !sizes[1024+16] {
		t.Fatalf("ciphertext sizes %v", sizes)
	}
	hb, _ := b64.DecodeString(recs[1].Header)
	for _, leak := range []string{"tavily", "tinfoil", "web.search", "s_chat", "t_a", "gpt-oss", "succeeded"} {
		if bytes.Contains(hb, []byte(leak)) {
			t.Fatalf("header names %q: %s", leak, hb)
		}
	}
}

func TestTamper(t *testing.T) {
	s := signer(t, 7)
	_, to := recipient(t)
	rec := &Recorder{Signer: s, Store: NewMemStore()}
	recs := runs(t, rec, to, 3)
	ok := trust(s.Public())
	mutate := func(i int, f func(h map[string]any)) []Sealed {
		out := append([]Sealed(nil), recs...)
		hb, _ := b64.DecodeString(out[i].Header)
		var h map[string]any
		json.Unmarshal(hb, &h)
		f(h)
		nb, _ := json.Marshal(h)
		out[i].Header = b64.EncodeToString(nb)
		return out
	}
	attacker := signer(t, 9)
	forge := func(i int, by *Signer, key string) []Sealed {
		out := append([]Sealed(nil), recs...)
		hb, _ := b64.DecodeString(out[i].Header)
		var h Header
		json.Unmarshal(hb, &h)
		h.Time++
		h.Key = key
		nb, _ := json.Marshal(&h)
		out[i].Header = b64.EncodeToString(nb)
		out[i].Sig = b64.EncodeToString(ed25519.Sign(by.priv, signedBytes(nb)))
		return out
	}
	cases := map[string]struct {
		recs []Sealed
		want error
	}{
		"removed":             {append(append([]Sealed(nil), recs[:2]...), recs[3:]...), ErrChain},
		"removed first":       {recs[1:], ErrChain},
		"reordered":           {[]Sealed{recs[0], recs[2], recs[1], recs[3], recs[4], recs[5]}, ErrChain},
		"duplicated":          {[]Sealed{recs[0], recs[1], recs[1], recs[2]}, ErrChain},
		"header edited":       {mutate(2, func(h map[string]any) { h["time"] = h["time"].(float64) + 1 }), ErrSignature},
		"seq edited":          {mutate(2, func(h map[string]any) { h["seq"] = 9 }), ErrSignature},
		"unknown field added": {mutate(2, func(h map[string]any) { h["note"] = "x" }), ErrFormat},
		"ciphertext edited": {func() []Sealed {
			out := append([]Sealed(nil), recs...)
			ct, _ := b64.DecodeString(out[3].CT)
			ct[5] ^= 1
			out[3].CT = b64.EncodeToString(ct)
			return out
		}(), ErrCipher},
		"ciphertext swapped": {func() []Sealed {
			out := append([]Sealed(nil), recs...)
			out[3].CT = recs[1].CT
			return out
		}(), ErrCipher},
		"signature from another key":   {forge(4, attacker, s.Public()), ErrSignature},
		"signed by an untrusted key":   {forge(4, attacker, attacker.Public()), ErrUntrusted},
		"signature dropped":            {func() []Sealed { out := append([]Sealed(nil), recs...); out[0].Sig = ""; return out }(), ErrSignature},
		"chain spliced from elsewhere": {append(append([]Sealed(nil), recs[:2]...), runs(t, &Recorder{Signer: s, Store: NewMemStore()}, to, 2)[2:]...), ErrChain},
	}
	for name, c := range cases {
		if _, err := VerifyChain(c.recs, ok, nil); !errors.Is(err, c.want) {
			t.Errorf("%s: got %v, want %v", name, err, c.want)
		}
	}
	if _, err := VerifyChain(recs, ok, nil); err != nil {
		t.Fatalf("untouched chain: %v", err)
	}
	// A truncated tail can't be seen from the records alone: the head the VM reports (in a run's meta) is what
	// catches it.
	end, _ := VerifyChain(recs[:4], ok, nil)
	_, head, _ := rec.Head("s_chat", to)
	if end == head {
		t.Fatal("a truncated chain ends at the head")
	}
}

// A body sealed for one place can't be opened under another header, even one the VM itself signed.
func TestBodyBoundToHeader(t *testing.T) {
	s := signer(t, 7)
	priv, to := recipient(t)
	pt, _ := json.Marshal(&Run{Type: BodyType, Event: EventStart, Chain: ChainID("s", to), Seq: 2, Run: "t_x", Space: "s"})
	a, _, err := s.seal(ChainID("s", to), 2, strings.Repeat("0", 64), 1, to, pt)
	if err != nil {
		t.Fatal(err)
	}
	b, _, err := s.seal(ChainID("s", to), 3, strings.Repeat("0", 64), 1, to, pt)
	if err != nil {
		t.Fatal(err)
	}
	// Put a's ciphertext under a header for seq 3 that names it correctly (as a buggy or hostile signer could).
	hb, _ := b64.DecodeString(b.Header)
	var h Header
	json.Unmarshal(hb, &h)
	ah, _ := b64.DecodeString(a.Header)
	var ha Header
	json.Unmarshal(ah, &ha)
	h.Enc, h.CTHash, h.CTLen = ha.Enc, ha.CTHash, ha.CTLen
	nb, _ := json.Marshal(&h)
	moved := Sealed{Header: b64.EncodeToString(nb), Sig: b64.EncodeToString(ed25519.Sign(s.priv, signedBytes(nb))), CT: a.CT}
	if _, _, err := Open(moved, priv, nil); !errors.Is(err, ErrCipher) {
		t.Fatalf("moved body opened: %v", err)
	}
	if _, _, err := Open(a, priv, nil); err != nil {
		t.Fatal(err)
	}
}

func TestRecoverAndRefused(t *testing.T) {
	s := signer(t, 7)
	priv, to := recipient(t)
	store := NewMemStore()
	rec := &Recorder{Signer: s, Store: store}
	if _, err := rec.Begin(Start{Run: "t_1", Space: "s_chat", To: to}); err != nil {
		t.Fatal(err)
	}
	if _, err := rec.Refused(Start{Run: "t_2", Space: "s_chat", To: to}, Status{Code: "stopped"}); err != nil {
		t.Fatal(err)
	}
	// The process dies; the next one ends t_1 as interrupted.
	next := &Recorder{Signer: s, Store: store}
	if n, err := next.Recover(); err != nil || n != 1 {
		t.Fatalf("recover: %d %v", n, err)
	}
	if n, _ := next.Recover(); n != 0 {
		t.Fatal("recovered twice")
	}
	recs, _ := store.Records(ChainID("s_chat", to), 0, 10)
	if _, err := VerifyChain(recs, trust(s.Public()), nil); err != nil || len(recs) != 3 {
		t.Fatalf("%d records: %v", len(recs), err)
	}
	_, refused, _ := Open(recs[1], priv, nil)
	_, ended, _ := Open(recs[2], priv, nil)
	if refused.Event != EventRefused || refused.Status.State != "refused" || refused.Status.Code != "stopped" ||
		ended.Event != EventInterrupted || ended.Run != "t_1" || ended.StartSeq != 1 {
		t.Fatalf("%+v / %+v", refused, ended)
	}
	// No recipient: nothing is written.
	if _, err := rec.Begin(Start{Run: "t_3", Space: "s_chat"}); !errors.Is(err, ErrNoRecipient) {
		t.Fatal(err)
	}
	if _, err := rec.Begin(Start{Run: "t_3", Space: "s_chat", To: "x25519:" + b64.EncodeToString(make([]byte, 32))}); err == nil {
		t.Fatal("zero recipient key taken")
	}
}

func TestSQLStore(t *testing.T) {
	path := filepath.Join(t.TempDir(), "activity.db")
	st, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	s := signer(t, 7)
	_, to := recipient(t)
	rec := &Recorder{Signer: s, Store: st}
	recs := runs(t, rec, to, 2)
	if _, err := rec.Begin(Start{Run: "t_open", Space: "s_chat", To: to}); err != nil {
		t.Fatal(err)
	}
	st.Close()
	// Reopened (a restart): the head, the records and the open run are still there.
	st, err = OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	rec = &Recorder{Signer: s, Store: st}
	if n, err := rec.Recover(); err != nil || n != 1 {
		t.Fatalf("recover %d %v", n, err)
	}
	all, err := st.Records(ChainID("s_chat", to), 0, 100)
	if err != nil || len(all) != len(recs)+2 {
		t.Fatalf("%d %v", len(all), err)
	}
	if _, err := VerifyChain(all, trust(s.Public()), nil); err != nil {
		t.Fatal(err)
	}
	// One writer: an append against an old head is refused.
	if err := st.Append(ChainID("s_chat", to), Link{}, Link{Seq: 1, Hash: "x"}, Sealed{}, time.Now(), nil, ""); !errors.Is(err, errHeadMoved) {
		t.Fatalf("stale append: %v", err)
	}
	// Pruning drops records, never the head: the next record still links.
	if err := st.Prune(time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if left, _ := st.Records(ChainID("s_chat", to), 0, 100); len(left) != 0 {
		t.Fatal("not pruned")
	}
	runs2 := func() []Sealed {
		rec.Begin(Start{Run: "t_after", Space: "s_chat", To: to})
		rec.Finish("t_after", End{Status: Status{State: "succeeded"}})
		r, _ := st.Records(ChainID("s_chat", to), 0, 100)
		return r
	}()
	last, _ := VerifyChain(all, trust(s.Public()), nil)
	if _, err := VerifyChain(runs2, trust(s.Public()), &last); err != nil {
		t.Fatalf("after prune: %v", err)
	}
}

func TestRecordProof(t *testing.T) {
	vm, _ := ecdh.X25519().GenerateKey(rand.Reader)
	priv, to := recipient(t)
	p, err := RecordProof(priv, vm.PublicKey(), to, vm.PublicKey().Bytes())
	if err != nil || CheckRecordProof(vm, to, p) != nil {
		t.Fatalf("valid proof refused: %v", err)
	}
	// Someone who only knows the public key, another boot's VM key, another recipient, a flipped bit.
	other, _ := recipient(t)
	vm2, _ := ecdh.X25519().GenerateKey(rand.Reader)
	forged, _ := RecordProof(other, vm.PublicKey(), to, vm.PublicKey().Bytes())
	otherBoot, _ := RecordProof(priv, vm2.PublicKey(), to, vm2.PublicKey().Bytes())
	flipped := append([]byte(nil), p...)
	flipped[0] ^= 1
	for name, bad := range map[string][]byte{"forged": forged, "other boot": otherBoot, "flipped": flipped, "empty": nil} {
		if CheckRecordProof(vm, to, bad) == nil {
			t.Errorf("%s proof accepted", name)
		}
	}
	_, to2 := recipient(t)
	if CheckRecordProof(vm, to2, p) == nil {
		t.Error("proof for another recipient accepted")
	}
}

func TestDeriveSigner(t *testing.T) {
	ikm := bytes.Repeat([]byte{1}, 32)
	a, _ := DeriveSigner(ikm, "f_chat")
	b, _ := DeriveSigner(ikm, "f_chat")
	c, _ := DeriveSigner(ikm, "f_other")
	if a.Public() != b.Public() || a.Public() == c.Public() {
		t.Fatal("derivation isn't stable per firm")
	}
	if _, err := DeriveSigner(ikm[:16], "f"); err == nil {
		t.Fatal("short key material taken")
	}
}

// vector is a fixed chain the chat's tests verify and open (its test fixtures: activity-vector.json).
type vector struct {
	Signer    string   `json:"signer"`
	Recipient string   `json:"recipient_private"` // hex X25519 private key (test only)
	Records   []Sealed `json:"records"`
	Head      Link     `json:"head"`
	// A record_to proof: the recipient's, against a VM key (hex public key), for the browser's own computation.
	VMPublic string `json:"vm_public"`
	Proof    []byte `json:"proof"`
}

func TestVector(t *testing.T) {
	path := filepath.Join("testdata", "vector.json")
	if *update {
		s := signer(t, 7)
		priv, err := ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{3}, 32))
		if err != nil {
			t.Fatal(err)
		}
		to := RecipientString(priv.PublicKey())
		rec := &Recorder{Signer: s, Store: NewMemStore(), Now: func() time.Time { return time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC) }}
		recs := runs(t, rec, to, 2)
		_, head, _ := rec.Head("s_chat", to)
		vm, _ := ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{4}, 32))
		proof, _ := RecordProof(priv, vm.PublicKey(), to, vm.PublicKey().Bytes())
		b, _ := json.Marshal(vector{Signer: s.Public(), Recipient: hex.EncodeToString(priv.Bytes()), Records: recs, Head: head,
			VMPublic: hex.EncodeToString(vm.PublicKey().Bytes()), Proof: proof}, json.Deterministic(true))
		os.MkdirAll("testdata", 0o755)
		if err := os.WriteFile(path, b, 0o644); err != nil {
			t.Fatal(err)
		}
		os.WriteFile(filepath.Join("..", "..", "..", "apps", "chat", "test", "fixtures", "activity-vector.json"), b, 0o644)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var v vector
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	pk, _ := hex.DecodeString(v.Recipient)
	priv, err := ecdh.X25519().NewPrivateKey(pk)
	if err != nil {
		t.Fatal(err)
	}
	end, err := VerifyChain(v.Records, trust(v.Signer), nil)
	if err != nil || end != v.Head {
		t.Fatalf("vector: %+v %v", end, err)
	}
	if _, body, err := Open(v.Records[1], priv, nil); err != nil || body.Event != EventEnd {
		t.Fatalf("vector body: %v", err)
	}
	vm, _ := ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{4}, 32))
	if CheckRecordProof(vm, RecipientString(priv.PublicKey()), v.Proof) != nil || hex.EncodeToString(vm.PublicKey().Bytes()) != v.VMPublic {
		t.Fatal("vector proof")
	}
}
