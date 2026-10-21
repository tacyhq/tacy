package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/tacyhq/tacy/guard"
	"github.com/tacyhq/tacy/proto"
)

// A signed run with the person's image through agentd (v0.12.0): the model gets it on the person's message, and the
// activity record says that an image was given and its size, never what it is: no record (opened) holds any of it.
func TestRunWithImageRecordsCountAndSize(t *testing.T) {
	raw := make([]byte, 5000)
	rand.Read(raw)
	copy(raw, []byte{0xff, 0xd8, 0xff, 0xe0})
	b64 := base64.StdEncoding.EncodeToString(raw)
	img := proto.ImageURLPrefix + b64
	e := newSafeEnvBrain(t, false, pText("A red espresso machine."))
	e.mustPost(e.policy(1, nil), e.heartbeat())
	priv, _ := recipientKey(t)
	evs := runParity(t, e.s, e.recorded(priv, proto.RunRequest{Model: "deepseek-v4-1-flash", Permissions: guard.AllowAll(),
		Messages: []proto.Message{{Role: "user", Content: "what is this?", Images: []string{img}}}}))
	if evs[len(evs)-1].Type != "done" {
		t.Fatalf("events %s: %+v", types(evs), evs[len(evs)-1])
	}
	e.model.mu.Lock()
	bodies := append([]string(nil), e.model.bodies...)
	e.model.mu.Unlock()
	if len(bodies) != 1 || !strings.Contains(bodies[0], `"image_url":{"url":"`+img+`"}`) {
		t.Fatalf("the model's request lacks the image (%d requests)", len(bodies))
	}
	runs := openedActivity(t, evs, priv, e.rec.Signer.Public())
	if len(runs) != 2 || runs[0].Input == nil || runs[0].Input.Images != 1 || runs[0].Input.ImageBytes != 5000 || runs[0].Input.Messages != 1 {
		t.Fatalf("start record input %+v", runs[0].Input)
	}
	for _, r := range runs {
		b, _ := json.Marshal(r)
		if strings.Contains(string(b), "base64") || strings.Contains(string(b), b64[100:140]) {
			t.Fatalf("a record holds the image: %s", b)
		}
	}
}
