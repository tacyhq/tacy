package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	jsonv2 "encoding/json/v2"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/tacyhq/tacy/activity"
	"github.com/tacyhq/tacy/identity"
	"github.com/tacyhq/tacy/runauth"
	"github.com/tacyhq/tacy/safety"
	"github.com/tacyhq/tacy/trigger"
)

// The chat's golden vectors for the schedule calls (the chat's test/golden/v2-schedule.json, made with node:crypto from
// v2-search.json's fixed seeds): every request body decodes strictly as the VM's handler reads it, its digest and
// identity signature check under its own label against the VM key, the definition envelope verifies with its hash,
// and the sealed result opens with the seal key to the plaintext the chat expects, in the VM's result shape.
func TestScheduleGoldenVectors(t *testing.T) {
	b, err := os.ReadFile("../runauth/testdata/v2-schedule.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		VMPrivate   string `json:"vm_private"`
		SealPrivate string `json:"seal_private"`
		Seal, Space string
		Identity    struct{ Seed, ID, Key string }
		Definition  struct {
			JSON     string          `json:"json"`
			Envelope safety.Envelope `json:"envelope"`
			Hash     string          `json:"hash"`
		}
		Requests []struct {
			Call, Name, Body, Digest string
			Own                      []string
		}
		Result struct{ Task, Enc, CT, Plaintext string }
	}
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	unhex := func(s string) []byte { x, _ := hex.DecodeString(s); return x }
	vm, _ := ecdh.X25519().NewPrivateKey(unhex(v.VMPrivate))
	seal, _ := ecdh.X25519().NewPrivateKey(unhex(v.SealPrivate))
	if runauth.SealString(seal.PublicKey()) != v.Seal {
		t.Fatal("seal key")
	}
	idKey := ed25519.NewKeyFromSeed(unhex(v.Identity.Seed))

	// The definition: its payload, hash and the identity's signature.
	env := v.Definition.Envelope
	if string(env.Payload) != v.Definition.JSON || env.Hash() != v.Definition.Hash {
		t.Fatalf("envelope payload or hash: %s", env.Hash())
	}
	var dir identity.Static
	dir.Add("f_chat", v.Identity.ID, idKey.Public().(ed25519.PublicKey), v.Space)
	var d trigger.Definition
	jsonv2.Unmarshal(env.Payload, &d)
	got, err := trigger.VerifyDefinition(&env, &dir, "f_chat", d.IssuedAt)
	if err != nil {
		t.Fatalf("definition: %v", err)
	}
	if err := trigger.Personal(got, v.Space, v.Seal, v.Identity.ID); err != nil {
		t.Fatalf("personal rules: %v", err)
	}

	labels := map[string]string{"install": runauth.InstallLabel, "list": runauth.ListLabel, "stop": runauth.StopLabel,
		"remove": runauth.RemoveLabel, "results": runauth.ResultsLabel, "result": runauth.ResultLabel,
		"results/delete": runauth.ResultsDeleteLabel}
	for _, r := range v.Requests {
		var where *runauth.Where
		var own []string
		strict := func(x any) {
			if err := jsonv2.Unmarshal([]byte(r.Body), x, jsonv2.RejectUnknownMembers(true)); err != nil {
				t.Fatalf("%s: body: %v", r.Name, err)
			}
		}
		switch r.Call {
		case "install":
			var x installRequest
			strict(&x)
			where, own = &x.Where, []string{x.Definition.Hash()}
		case "list":
			var x runauth.Where
			strict(&x)
			where = &x
		case "stop", "remove":
			var x agentRequest
			strict(&x)
			where, own = &x.Where, []string{x.Agent}
		case "results":
			var x resultsRequest
			strict(&x)
			where, own = &x.Where, []string{jsonNum(x.After)}
		case "result":
			var x taskRequest
			strict(&x)
			where, own = &x.Where, []string{x.Task}
		case "results/delete":
			var x tasksRequest
			strict(&x)
			where, own = &x.Where, []string{strings.Join(x.Tasks, ",")}
		default:
			t.Fatalf("unknown call %q", r.Call)
		}
		if strings.Join(own, "|") != strings.Join(r.Own, "|") {
			t.Fatalf("%s: own items %q, the vectors say %q", r.Name, own, r.Own)
		}
		label := labels[r.Call]
		dg := runauth.CallDigest(label, vm.PublicKey().Bytes(), where, own...)
		if hex.EncodeToString(dg[:]) != r.Digest {
			t.Fatalf("%s: digest %x", r.Name, dg)
		}
		who, err := runauth.CheckCall(vm, label, where, time.Unix(where.SignedAt, 0), own...)
		if err != nil || who.Space != v.Space || who.Identity != v.Identity.ID || who.Seal != v.Seal {
			t.Fatalf("%s: %+v %v", r.Name, who, err)
		}
		// Under another call's label it doesn't pass.
		other := runauth.ListLabel
		if label == other {
			other = runauth.StopLabel
		}
		if _, err := runauth.CheckCall(vm, other, where, time.Unix(where.SignedAt, 0), own...); err == nil {
			t.Fatalf("%s: passed under %s", r.Name, other)
		}
	}

	// The sealed result.
	b64 := func(s string) []byte { var x []byte; json.Unmarshal([]byte(`"`+s+`"`), &x); return x }
	pt, err := activity.OpenFrom(seal, []byte(resultInfo), resultAAD(v.Space, v.Result.Task), b64(v.Result.Enc), b64(v.Result.CT))
	if err != nil {
		t.Fatalf("result: %v", err)
	}
	if !bytes.HasPrefix(pt, []byte(v.Result.Plaintext)) || len(bytes.TrimRight(pt, " ")) != len(v.Result.Plaintext) || len(pt)%1024 != 0 {
		t.Fatalf("result plaintext (%d bytes) isn't the vectors' padded", len(pt))
	}
	var body resultBody
	if err := jsonv2.Unmarshal([]byte(v.Result.Plaintext), &body, jsonv2.RejectUnknownMembers(true)); err != nil {
		t.Fatalf("result shape: %v", err)
	}
	if body.Type != resultType || body.Task != v.Result.Task || body.Space != v.Space || len(body.Events) == 0 {
		t.Fatalf("result %+v", body)
	}
	if _, err := activity.OpenFrom(seal, []byte(resultInfo), resultAAD(v.Space, "tk_other"), b64(v.Result.Enc), b64(v.Result.CT)); err == nil {
		t.Fatal("opened under another task")
	}
}

func jsonNum(n int64) string { b, _ := json.Marshal(n); return string(b) }
