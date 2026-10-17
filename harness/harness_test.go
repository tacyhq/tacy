package harness

import (
	"bytes"
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

// The protocol scenarios are in ./conformance; these cover the pieces underneath.

func TestFrames(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteFrame(&buf, []byte(`{"a":1}`), MinFrame); err != nil {
		t.Fatal(err)
	}
	b, err := ReadFrame(&buf, MinFrame)
	if err != nil || string(b) != `{"a":1}` {
		t.Fatalf("%q %v", b, err)
	}
	if WriteFrame(&buf, make([]byte, MinFrame+1), MinFrame) == nil {
		t.Error("wrote an oversize frame")
	}
	// A header over the limit is refused before the body is read (there is none here).
	_, err = ReadFrame(bytes.NewReader([]byte{0, 0x10, 0, 1}), MinFrame)
	var pe *Error
	if !errors.As(err, &pe) || pe.Code != CodeBadFrame {
		t.Errorf("oversize header: %v", err)
	}
}

func TestRequestHash(t *testing.T) {
	a := RequestHash(TypeAction, jsontext.Value(`{"name":"x","args":{"k":1}}`))
	b := RequestHash(TypeAction, jsontext.Value(`{ "name" : "x", "args" : { "k" : 1 } }`))
	c := RequestHash(TypeAction, jsontext.Value(`{"name":"x","args":{"k":2}}`))
	d := RequestHash(TypeExec, jsontext.Value(`{"name":"x","args":{"k":1}}`))
	if a != b || a == c || a == d {
		t.Error("hash must ignore whitespace only")
	}
}

func TestNames(t *testing.T) {
	for _, s := range []string{"t1", "s_7k2q9x", "s3.a0", "a:b-c"} {
		if !ValidID(s) {
			t.Errorf("ValidID(%q) = false", s)
		}
	}
	for _, s := range []string{"", ".x", "../etc", "a b", "a/b", strings.Repeat("a", 65), "é"} {
		if ValidID(s) {
			t.Errorf("ValidID(%q) = true", s)
		}
	}
	for _, s := range []string{"mail.send", "web_search", "task.spawn"} {
		if !ValidName(s) {
			t.Errorf("ValidName(%q) = false", s)
		}
	}
	for _, s := range []string{"Mail.send", "mail..send", "mail.", "1mail", "mail-send"} {
		if ValidName(s) {
			t.Errorf("ValidName(%q) = true", s)
		}
	}
	if s := capText("ab€", 4); s != "ab" {
		t.Errorf("capText cut a rune: %q", s)
	}
}

// The model sees tool names without dots; two tools it would see under one name can't be in one task.
func TestModelToolNames(t *testing.T) {
	if n := ModelToolName("web.search"); n != "web_search" {
		t.Errorf("ModelToolName = %q", n)
	}
	tool := func(n string) Tool { return Tool{Name: n, Parameters: jsontext.Value(`{}`)} }
	s := Start{Space: "s1", Attempt: 1, Agent: AgentRef{ID: "a", Version: "1", Digest: "00"}, Models: []string{"m"},
		Tools: []Tool{tool("web.search"), tool("web.fetch")}, Limits: TaskLimits{MaxSteps: 1, MaxModelCalls: 1}}
	if err := s.validate(); err != nil {
		t.Fatal(err)
	}
	s.Tools = append(s.Tools, tool("web_search"))
	if s.validate() == nil {
		t.Error("web.search and web_search in one task")
	}
	a := Action{Name: "web.search", Args: jsontext.Value(`{}`), Call: "call_1"}
	if err := a.validate(); err != nil {
		t.Error(err)
	}
	a.Call = "c\n1"
	if a.validate() == nil {
		t.Error("a control character in call")
	}
}

// A request the journal shows as started but never finished (the runtime stopped while it ran) comes back
// "interrupted" and isn't run again.
func TestInterrupted(t *testing.T) {
	f := NewFake()
	f.Model = Script(Calls(ToolCall{ID: "c1", Name: "test.echo", Args: jsontext.Value(`{}`)}))
	req := Action{Name: "test.echo", Args: jsontext.Value(`{}`), Call: "c1"}
	b, _ := json.Marshal(&req)
	f.Mem.Begin("t1", "a1", TypeAction, RequestHash(TypeAction, b), b)
	start := Start{Space: "s1", Attempt: 1, Agent: AgentRef{ID: "a", Version: "1", Digest: "00"}, Models: []string{"m"},
		Tools:  []Tool{{Name: "test.echo", Parameters: jsontext.Value(`{}`)}},
		Limits: TaskLimits{MaxSteps: 1, MaxModelCalls: 1}}
	if err := f.Start("t1", start); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	rc, bc := net.Pipe()
	go f.Serve(ctx, rc)
	c, err := Connect(bc, Hello{Brain: Info{Name: "test", Version: "1"}})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	task, err := c.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := task.ModelCall(ctx, "m1", ModelCall{Model: "m", Messages: []Message{{Role: "user", Content: "hi"}}}); err != nil {
		t.Fatal(err)
	}
	_, err = task.Action(ctx, "a1", req)
	var pe *Error
	if !errors.As(err, &pe) || pe.Code != CodeInterrupted {
		t.Fatalf("got %v, want interrupted", err)
	}
	if f.ActionRuns("t1", "test.echo") != 0 {
		t.Error("an interrupted action ran again")
	}
}

// The final v1 choices in the schema: raw_args is capped and only rides with bad_args, status is a note only, and a
// message list has no count cap (bytes cap it: the frame and the checkpoint).
func TestAmendment4Schema(t *testing.T) {
	if s := CapRawArgs("{\"q\": x"); s != "{\"q\": x" {
		t.Errorf("short raw args changed: %q", s)
	}
	long := CapRawArgs(strings.Repeat("€", MaxRawArgs))
	if len(long) > MaxRawArgs || !strings.HasSuffix(long, RawArgsCut) || !utf8.ValidString(long) {
		t.Errorf("long raw args: %d bytes, %q at the end", len(long), long[len(long)-20:])
	}
	if s := CapRawArgs("a\xffb"); !utf8.ValidString(s) {
		t.Errorf("invalid UTF-8 kept: %q", s)
	}
	m := Message{Role: "assistant", ToolCalls: []ToolCall{{ID: "c1", Name: "web.search", Args: jsontext.Value(`{}`), RawArgs: "{"}}}
	if m.validate() == nil {
		t.Error("raw_args without bad_args accepted")
	}
	m.ToolCalls[0].BadArgs = true
	if err := m.validate(); err != nil {
		t.Error(err)
	}
	if (&Status{}).validate() == nil || (&Status{Note: "thinking"}).validate() != nil {
		t.Error("status must carry a note")
	}
	ms := make([]Message, 5000)
	for i := range ms {
		ms[i] = Message{Role: "user", Content: "x"}
	}
	if err := (&ModelCall{Model: "m", Messages: ms}).validate(); err != nil {
		t.Errorf("5,000 messages refused: %v", err)
	}
}
