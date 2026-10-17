package harness

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"io"
	"time"
)

// HandshakeTimeout is how long either side waits for hello or welcome.
const HandshakeTimeout = 5 * time.Second

// writeTimeout bounds one frame write; a peer that stops reading is dropped.
const writeTimeout = 10 * time.Second

// Framing: a frame is a 4-byte big-endian length, then that many bytes holding one JSON object. A length of 0 or
// above the receiver's max_frame is refused from the header alone, before anything is allocated or read; the
// stream can't be resynchronized after a bad frame, so the receiver sends error (best effort) and closes.

// WriteFrame writes b as one frame in a single Write, refusing anything over max.
func WriteFrame(w io.Writer, b []byte, max int) error {
	if len(b) == 0 || len(b) > max {
		return Errf(CodeLimit, "frame of %d bytes (max %d)", len(b), max)
	}
	buf := make([]byte, 4+len(b))
	binary.BigEndian.PutUint32(buf, uint32(len(b)))
	copy(buf[4:], b)
	_, err := w.Write(buf)
	return err
}

// ReadFrame reads one frame of at most max bytes. A bad length is an *Error (bad_frame); I/O errors are returned
// as they are.
func ReadFrame(r io.Reader, max int) ([]byte, error) {
	b, _, err := readFrame(r, max)
	return b, err
}

// errPartial wraps an I/O error (a timeout, typically) that came after part of a frame was read: the stream is out
// of step and must be closed.
type errPartial struct{ error }

func (e errPartial) Unwrap() error { return e.error }

// readFrame is ReadFrame that also says whether any byte was read before an error.
func readFrame(r io.Reader, max int) ([]byte, bool, error) {
	var h [4]byte
	if n, err := io.ReadFull(r, h[:]); err != nil {
		if n > 0 {
			return nil, true, errPartial{err}
		}
		return nil, false, err
	}
	n := binary.BigEndian.Uint32(h[:])
	if n == 0 || uint64(n) > uint64(max) {
		return nil, true, Errf(CodeBadFrame, "frame length %d (max %d)", n, max)
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		return nil, true, errPartial{err}
	}
	return b, true, nil
}

// Strict JSON: encoding/json/v2 already rejects duplicate member names, invalid UTF-8, trailing data and names
// that differ only in case; unknown members are rejected too, and nesting is capped before parsing.
func unmarshalStrict(b []byte, v any) error {
	if err := checkDepth(b, MaxDepth); err != nil {
		return err
	}
	if err := json.Unmarshal(b, v, json.RejectUnknownMembers(true)); err != nil {
		return errf("%v", err)
	}
	return nil
}

// checkDepth refuses JSON nested deeper than max. Syntax errors are left to the parser.
func checkDepth(b []byte, max int) error {
	depth, inStr, esc := 0, false, false
	for _, c := range b {
		switch {
		case inStr:
			if esc {
				esc = false
			} else if c == '\\' {
				esc = true
			} else if c == '"' {
				inStr = false
			}
		case c == '"':
			inStr = true
		case c == '{' || c == '[':
			if depth++; depth > max {
				return errf("nested deeper than %d", max)
			}
		case c == '}' || c == ']':
			depth--
		}
	}
	return nil
}

// Side is who sent a frame.
type Side int

const (
	FromBrain Side = 1 << iota
	FromRuntime
)

type validator interface{ validate() error }

// rule is the shape of one message type: who sends it, which envelope fields it must have (the rest must be
// absent), and its body type (nil: result and error, which have their own rules).
type rule struct {
	from         Side
	task, id, re bool
	body         func() validator
}

var rules = map[string]rule{
	TypeHello:      {from: FromBrain, body: func() validator { return &Hello{} }},
	TypeModelCall:  {from: FromBrain, task: true, id: true, body: func() validator { return &ModelCall{} }},
	TypeAction:     {from: FromBrain, task: true, id: true, body: func() validator { return &Action{} }},
	TypeExec:       {from: FromBrain, task: true, id: true, body: func() validator { return &Exec{} }},
	TypeCheckpoint: {from: FromBrain, task: true, id: true, body: func() validator { return &Checkpoint{} }},
	TypeStatus:     {from: FromBrain, task: true, body: func() validator { return &Status{} }},
	TypeDone:       {from: FromBrain, task: true, id: true, body: func() validator { return &Done{} }},
	TypeWelcome:    {from: FromRuntime, body: func() validator { return &Welcome{} }},
	TypeStart:      {from: FromRuntime, task: true, body: func() validator { return &Start{} }},
	TypeSteer:      {from: FromRuntime, task: true, body: func() validator { return &Steer{} }},
	TypeCancel:     {from: FromRuntime, task: true, body: func() validator { return &Cancel{} }},
	TypeResult:     {from: FromRuntime, task: true, re: true},
	TypeError:      {from: FromBrain | FromRuntime},
}

// Decode parses one frame sent by from, strictly: JSON rules above, a known type sent by that side, exactly the
// envelope fields the type has, well-formed ids, and a body that decodes into the type's struct and passes its
// checks. It returns the envelope and the validated body (a pointer, e.g. *Action); result and error bodies are
// left to DecodeResult. Every error is an *Error: bad_frame, or protocol for a type the other side sends.
func Decode(frame []byte, from Side) (*Envelope, any, error) {
	var e Envelope
	if err := unmarshalStrict(frame, &e); err != nil {
		return nil, nil, err
	}
	r, ok := rules[e.Type]
	if !ok {
		return nil, nil, errf("unknown type")
	}
	if r.from&from == 0 {
		return nil, nil, Errf(CodeProtocol, "%s isn't sent by this side", e.Type)
	}
	if (e.Task != "") != r.task || (e.ID != "") != r.id || (e.Re != "") != r.re {
		return nil, nil, errf("%s: wrong envelope fields", e.Type)
	}
	for _, id := range []string{e.Task, e.ID, e.Re} {
		if id != "" && !ValidID(id) {
			return nil, nil, errf("bad id")
		}
	}
	if e.Error != nil && (e.Error.Code == "" || !printable(e.Error.Code, 32) || len(e.Error.Message) > MaxErrorText) {
		return nil, nil, errf("bad error")
	}
	switch e.Type {
	case TypeError:
		if e.Error == nil || e.Body != nil {
			return nil, nil, errf("error carries an error and no body")
		}
		return &e, nil, nil
	case TypeResult:
		if (e.Error == nil) == (e.Body == nil) || (e.Body != nil && e.Body.Kind() != '{') {
			return nil, nil, errf("result carries an object body or an error")
		}
		return &e, nil, nil
	}
	if e.Error != nil || e.Body.Kind() != '{' {
		return nil, nil, errf("%s needs an object body", e.Type)
	}
	v := r.body()
	if err := unmarshalStrict(e.Body, v); err != nil {
		return nil, nil, err
	}
	if err := v.validate(); err != nil {
		return nil, nil, err
	}
	return &e, v, nil
}

// DecodeResult decodes a result body into out (*ModelResult, *ActionResult, *ExecResult or *Empty) and checks it.
func DecodeResult(body jsontext.Value, out any) error {
	v, ok := out.(validator)
	if !ok {
		return errors.New("harness: not a result type")
	}
	if err := unmarshalStrict(body, out); err != nil {
		return err
	}
	return v.validate()
}

// Encode marshals an envelope with body (nil for none).
func Encode(e *Envelope, body any) ([]byte, error) {
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		e.Body = b
	}
	return json.Marshal(e)
}

// RequestHash identifies a request's content for the journal: sha256(type || 0x00 || body without whitespace).
// The same id with another hash is an id_conflict, so a brain must re-send a replayed request byte for byte (its
// encoder is deterministic; tool arguments come back from the journal unchanged).
func RequestHash(typ string, body jsontext.Value) [32]byte {
	v := body.Clone()
	_ = v.Compact() // body was validated already
	h := sha256.New()
	h.Write([]byte(typ))
	h.Write([]byte{0})
	h.Write(v)
	var out [32]byte
	h.Sum(out[:0])
	return out
}
