package safety

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json/v2"
	"flag"
	"os"
	"testing"
	"time"
)

var updateGolden = flag.Bool("update", false, "rewrite testdata/heartbeat-golden.json")

// heartbeatCase is one golden heartbeat: the inputs and the exact envelope JSON (cmd/safetysign's output line).
// The operator's Worker signs heartbeats with WebCrypto, and its test must give these bytes from these inputs.
type heartbeatCase struct {
	Seed       string `json:"seed"` // base64, as cmd/safetysign keygen writes it
	Seq        uint64 `json:"seq"`
	NowMs      int64  `json:"now_ms"`
	TTLSeconds int64  `json:"ttl_seconds"`
	All        bool   `json:"all"`
	Envelope   string `json:"envelope"`
	Hash       string `json:"hash"`
}

func TestHeartbeatGolden(t *testing.T) {
	seed := bytes.Repeat([]byte{7}, ed25519.SeedSize)
	k := ed25519.NewKeyFromSeed(seed)
	ins := []heartbeatCase{
		{NowMs: time.Date(2026, 10, 18, 3, 30, 0, 0, time.UTC).UnixMilli(), TTLSeconds: 900},                   // whole second
		{NowMs: time.Date(2026, 10, 18, 3, 30, 1, 120e6, time.UTC).UnixMilli(), TTLSeconds: 900},               // .120 → ".12"
		{NowMs: time.Date(2026, 10, 18, 3, 30, 2, 7e6, time.UTC).UnixMilli(), TTLSeconds: 900, All: true},      // .007, a stop
		{NowMs: time.Date(2026, 12, 31, 23, 59, 59, 999e6, time.UTC).UnixMilli(), TTLSeconds: 3600, All: true}, // the ttl crosses a year
		{Seq: 1792294200001, NowMs: time.Date(2026, 10, 18, 3, 30, 0, 100e6, time.UTC).UnixMilli(), TTLSeconds: 60},
	}
	var got []heartbeatCase
	for _, c := range ins {
		e, err := Heartbeat(k, c.Seq, time.UnixMilli(c.NowMs), time.Duration(c.TTLSeconds)*time.Second, c.All)
		if err != nil {
			t.Fatal(err)
		}
		b, err := json.Marshal(e)
		if err != nil {
			t.Fatal(err)
		}
		c.Seed, c.Envelope, c.Hash = base64.StdEncoding.EncodeToString(seed), string(b), e.Hash()
		got = append(got, c)
		// What the VM takes: an operator list under the matching key, seq now in ms unless given.
		envs, err := DecodeEnvelopes(b)
		if err != nil {
			t.Fatal(err)
		}
		var l StopList
		if err := strict(envs[0].Payload, &l); err != nil || l.Validate() != nil || l.Issuer != IssuerOperator ||
			(c.Seq == 0 && l.Seq != uint64(c.NowMs)) || envs[0].signers([]ed25519.PublicKey{pub(k)}) != 1 {
			t.Fatalf("heartbeat %s: %+v %v", b, l, err)
		}
	}
	if _, err := Heartbeat(k, 0, time.UnixMilli(ins[0].NowMs), 61*time.Minute, false); err == nil {
		t.Fatal("a heartbeat living over an hour was signed")
	}
	want, err := json.Marshal(got, json.Deterministic(true))
	if err != nil {
		t.Fatal(err)
	}
	const path = "testdata/heartbeat-golden.json"
	if *updateGolden {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, append(want, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	have, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(bytes.TrimSpace(have), want) {
		t.Fatalf("heartbeats changed (go test ./safety -run Golden -update, then the Worker's test must still pass):\n%s\nwant\n%s", have, want)
	}
}
