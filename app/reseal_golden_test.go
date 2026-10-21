package main

import (
	"crypto/ecdh"
	"encoding/hex"
	"encoding/json"
	jsonv2 "encoding/json/v2"
	"errors"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/tacyhq/tacy/runauth"
)

// The chat's golden vectors for POST /spaces/reseal (the chat's test/golden/v2-reseal.json, made with node:crypto; copied
// to runauth/testdata): what a data key rotation sends ("forward", old seal key to new) and what an interrupted one
// sends to reach what is still sealed to the old key ("back"). Each body decodes strictly as spaceReseal reads it,
// its digest and signature check under the reseal label over its own items, and runauth.CheckReseal accepts it; with
// a byte of either proof changed, the old key swapped or under another label it is refused. Then the pin: the forward
// move takes a pin held by the old key to the new one, after which the old key is refused and the same move again is
// seal_mismatch (the chat then checks the pin is already the new key); the move back takes it back.
func TestResealGoldenVectors(t *testing.T) {
	b, err := os.ReadFile("../runauth/testdata/v2-reseal.json")
	if err != nil {
		t.Fatal(err)
	}
	type key struct{ Seal, Proof string }
	var v struct {
		Constants struct {
			Labels struct {
				SpaceReseal string `json:"spaceReseal"`
			} `json:"labels"`
		} `json:"constants"`
		VMPrivate string `json:"vm_private"`
		Space     string `json:"space"`
		Identity  struct {
			ID  string `json:"id"`
			Key string `json:"key"`
		} `json:"identity"`
		Old      key `json:"old"`
		New      key `json:"new"`
		Requests []struct {
			Name, Body, Digest string
			Own                []string
		}
	}
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	if v.Constants.Labels.SpaceReseal != runauth.ResealLabel || len(v.Requests) != 2 || v.Old.Seal == v.New.Seal {
		t.Fatalf("vectors: %+v", v.Constants)
	}
	pk, _ := hex.DecodeString(v.VMPrivate)
	vm, err := ecdh.X25519().NewPrivateKey(pk)
	if err != nil {
		t.Fatal(err)
	}
	reqs := map[string]resealRequest{}
	whos := map[string]runauth.Who{}
	for _, r := range v.Requests {
		var req resealRequest
		if err := jsonv2.Unmarshal([]byte(r.Body), &req, jsonv2.RejectUnknownMembers(true)); err != nil {
			t.Fatalf("%s: %v", r.Name, err)
		}
		own := runauth.ResealItems(req.OldSeal, req.OldProof)
		if !slices.Equal(own, r.Own) {
			t.Fatalf("%s: own %q, vectors %q", r.Name, own, r.Own)
		}
		dg := runauth.CallDigest(runauth.ResealLabel, vm.PublicKey().Bytes(), &req.Where, own...)
		if hex.EncodeToString(dg[:]) != r.Digest {
			t.Fatalf("%s: digest %x", r.Name, dg)
		}
		at := time.Unix(req.SignedAt, 0)
		who, err := runauth.CheckReseal(vm, &req.Where, req.OldSeal, req.OldProof, at)
		if err != nil || who.Space != v.Space || who.Identity != v.Identity.ID || who.Key != v.Identity.Key || who.Seal != req.SpaceSeal {
			t.Fatalf("%s: %+v %v", r.Name, who, err)
		}
		// Refused: a changed old proof, a changed new proof, the old key swapped for the new one, or under another label.
		bad := req
		bad.OldProof = append([]byte(nil), req.OldProof...)
		bad.OldProof[0] ^= 1
		if _, err := runauth.CheckReseal(vm, &bad.Where, bad.OldSeal, bad.OldProof, at); err == nil {
			t.Fatalf("%s: passed with another old proof", r.Name)
		}
		bad = req
		bad.SpaceProof = append([]byte(nil), req.SpaceProof...)
		bad.SpaceProof[0] ^= 1
		if _, err := runauth.CheckReseal(vm, &bad.Where, bad.OldSeal, bad.OldProof, at); err == nil {
			t.Fatalf("%s: passed with another new proof", r.Name)
		}
		if _, err := runauth.CheckReseal(vm, &req.Where, req.SpaceSeal, req.OldProof, at); err == nil {
			t.Fatalf("%s: passed with the new key as the old one", r.Name)
		}
		if _, err := runauth.CheckCall(vm, runauth.ListLabel, &req.Where, at, own...); err == nil {
			t.Fatalf("%s: passed as a schedule list", r.Name)
		}
		reqs[r.Name], whos[r.Name] = req, who
	}
	fwd, back := reqs["forward"], reqs["back"]
	if fwd.OldSeal != v.Old.Seal || fwd.SpaceSeal != v.New.Seal || back.OldSeal != v.New.Seal || back.SpaceSeal != v.Old.Seal {
		t.Fatalf("forward %s -> %s, back %s -> %s", fwd.OldSeal, fwd.SpaceSeal, back.OldSeal, back.SpaceSeal)
	}

	// The pin, as spaceReseal moves it (RepinSeal from the request's old key to its own).
	pins := &runauth.MemPins{}
	now := time.Now()
	oldWho := runauth.Who{Space: v.Space, Seal: v.Old.Seal, Identity: v.Identity.ID, Key: v.Identity.Key}
	if err := runauth.CheckPin(pins, oldWho, now); err != nil {
		t.Fatal(err) // the old key, pinned on first use (before the rotation)
	}
	if err := runauth.CheckPin(pins, whos["forward"], now); !errors.Is(err, runauth.ErrSealPinned) {
		t.Fatalf("the new key before the move: %v", err)
	}
	if err := pins.RepinSeal(v.Space, fwd.OldSeal, whos["forward"].Seal, now); err != nil {
		t.Fatalf("forward: %v", err)
	}
	if err := runauth.CheckPin(pins, oldWho, now); !errors.Is(err, runauth.ErrSealPinned) {
		t.Fatalf("the old key after the move: %v", err)
	}
	if err := runauth.CheckPin(pins, whos["forward"], now); err != nil {
		t.Fatalf("the new key after the move: %v", err)
	}
	if err := pins.RepinSeal(v.Space, fwd.OldSeal, whos["forward"].Seal, now); !errors.Is(err, runauth.ErrSealPinned) {
		t.Fatalf("forward again: %v", err)
	}
	if err := pins.RepinSeal(v.Space, back.OldSeal, whos["back"].Seal, now); err != nil {
		t.Fatalf("back: %v", err)
	}
	if err := runauth.CheckPin(pins, oldWho, now); err != nil {
		t.Fatalf("the old key after the move back: %v", err)
	}
}
