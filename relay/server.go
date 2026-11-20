package relay

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/tacyhq/tacy/proto"
)

// Server opens envelopes and serves what they ask for from Inner. Its ServeHTTP must sit behind agentd's EHBP
// middleware (the outer body is decrypted and every write is encrypted there) and behind a check that the request
// was encrypted at all (the middleware passes plaintext through).
type Server struct {
	Key   ed25519.PublicKey // the relay-auth public key the compose pins; nil: every envelope is refused
	Inner http.Handler
	// Now is agentd's clock (nil: time.Now). Trusted, when set and known, is the operator's latest signed time
	// (safety.State.OperatorTime): an envelope must not be older than it by more than TrustedSlack, so a host that
	// sets the VM's clock back can't make an old envelope fresh again. The operator's list and the envelopes are
	// signed by the same Worker (one clock), so the slack only covers delivery: Window plus a minute. What this
	// can't cover: while the host withholds newer operator lists (at most safety.DefaultMaxStopAge, then the VM
	// counts them stale and sends nothing out), the VM's clock is the host's.
	Now          func() time.Time
	Trusted      func() (time.Time, bool)
	TrustedSlack time.Duration // 0: Window + 1 minute

	mu   sync.Mutex
	seen map[string]time.Time // nonce -> when it may be forgotten (its envelope's time + Window, on agentd's clock)
}

// MaxNonces bounds the replay cache: past it, envelopes are refused (busy) rather than old nonces forgotten early.
const MaxNonces = 1 << 17

type relayedKey struct{}

// Relayed says ctx is a request that came in a valid envelope: the relay signed it. What the bearer token meant.
func Relayed(ctx context.Context) bool { v, _ := ctx.Value(relayedKey{}).(bool); return v }

// WithRelayed marks ctx as relayed (Server does it for each opened envelope; tests of the inner handlers too).
func WithRelayed(ctx context.Context) context.Context {
	return context.WithValue(ctx, relayedKey{}, true)
}

func (s *Server) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// Errors an envelope gets, inside the encrypted answer (nothing reaches the gateway but a 200).
var (
	ErrReplay  = errors.New("relay_replay")
	ErrExpired = errors.New("relay_expired")
	ErrAuth    = errors.New("relay_auth")
	ErrBusy    = errors.New("relay_busy")
)

// Open reads and checks one envelope: its form, its signature, its time and its nonce (remembered once accepted).
// It returns the header and the inner body.
func (s *Server) Open(body io.Reader) (*Header, []byte, error) {
	var n [4]byte
	if _, err := io.ReadFull(body, n[:]); err != nil {
		return nil, nil, ErrAuth
	}
	hl := binary.BigEndian.Uint32(n[:])
	if hl == 0 || hl > MaxHeader {
		return nil, nil, ErrAuth
	}
	hb := make([]byte, hl)
	if _, err := io.ReadFull(body, hb); err != nil {
		return nil, nil, ErrAuth
	}
	var h Header
	dec := json.NewDecoder(bytes.NewReader(hb))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&h); err != nil || h.Check() != nil {
		return nil, nil, ErrAuth
	}
	inner := make([]byte, h.Len)
	if _, err := io.ReadFull(body, inner); err != nil {
		return nil, nil, ErrAuth
	}
	// The padding: zeros, at most a size class.
	if _, err := io.Copy(io.Discard, io.LimitReader(body, int64(proto.PadPow2(4+int(hl)+h.Len, proto.AnswerMin, proto.AnswerMax)))); err != nil {
		return nil, nil, ErrAuth
	}
	if s.Key == nil || h.Verify(s.Key, inner) != nil {
		return nil, nil, ErrAuth
	}
	now, t := s.now(), time.Unix(h.Time, 0)
	if t.Before(now.Add(-Window)) || t.After(now.Add(Window)) {
		return nil, nil, ErrExpired
	}
	if s.Trusted != nil {
		if op, ok := s.Trusted(); ok && t.Before(op.Add(-s.slack())) {
			return nil, nil, ErrExpired
		}
	}
	if err := s.remember(h.Nonce, t.Add(Window), now); err != nil {
		return nil, nil, err
	}
	return &h, inner, nil
}

func (s *Server) slack() time.Duration {
	if s.TrustedSlack > 0 {
		return s.TrustedSlack
	}
	return Window + time.Minute
}

// remember records nonce until forget, refusing one already seen.
func (s *Server) remember(nonce string, forget, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.seen == nil {
		s.seen = map[string]time.Time{}
	}
	if _, ok := s.seen[nonce]; ok {
		return ErrReplay
	}
	if len(s.seen) >= MaxNonces/2 {
		for k, at := range s.seen {
			if now.After(at) {
				delete(s.seen, k)
			}
		}
	}
	if len(s.seen) >= MaxNonces {
		return ErrBusy
	}
	s.seen[nonce] = forget
	return nil
}

// ServeHTTP opens the envelope in r's (decrypted) body and serves the inner request into frames on w.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	fw := newFrameWriter(w)
	defer fw.finish()
	h, inner, err := s.Open(http.MaxBytesReader(w, r.Body, MaxHeader+MaxBody+proto.AnswerMax+4))
	if err != nil {
		code := 401
		switch err {
		case ErrReplay, ErrExpired:
			code = 409
		case ErrBusy:
			code = 503
		}
		fw.Header().Set("Content-Type", "application/json")
		fw.WriteHeader(code)
		b, _ := json.Marshal(map[string]string{"error": err.Error()})
		fw.Write(proto.PadJSON(b))
		return
	}
	req, err := http.NewRequestWithContext(WithRelayed(r.Context()), h.Method, h.Path, bytes.NewReader(inner))
	if err != nil {
		fw.WriteHeader(400)
		return
	}
	for k, v := range h.Headers {
		req.Header.Set(canonical(k), v)
	}
	req.ContentLength = int64(len(inner))
	if len(inner) == 0 {
		req.Body = http.NoBody
	}
	req.RemoteAddr, req.Host = r.RemoteAddr, r.Host
	s.Inner.ServeHTTP(fw, req)
}

// frameWriter is the inner handler's ResponseWriter: it sends the status and headers as the 'H' frame and the body
// as 'D' frames, each Flush (or a full buffer, or the end) one write to the outer (encrypted) writer, and at the end
// an 'E' frame with the body's length (u64), so a reader tells a whole answer from one cut at a frame's edge (EHBP
// ends cleanly at a chunk edge, so a host that drops the rest would otherwise go unnoticed).
type frameWriter struct {
	out     http.ResponseWriter
	flusher http.Flusher
	header  http.Header
	status  int
	sent    bool // the 'H' frame
	buf     []byte
	n       uint64 // body bytes sent
	err     error
}

const frameFlushAt = 32 << 10

func newFrameWriter(out http.ResponseWriter) *frameWriter {
	f := &frameWriter{out: out, header: http.Header{}}
	f.flusher, _ = out.(http.Flusher)
	return f
}

func (f *frameWriter) Header() http.Header { return f.header }

func (f *frameWriter) WriteHeader(code int) {
	if f.status == 0 {
		f.status = code
	}
}

func (f *frameWriter) Write(b []byte) (int, error) {
	if f.status == 0 {
		f.status = 200
	}
	if f.err != nil {
		return 0, f.err
	}
	f.buf = append(f.buf, b...)
	if len(f.buf) >= frameFlushAt {
		f.Flush()
	}
	return len(b), f.err
}

// Flush sends the head (first time) and what's buffered, as one outer write.
func (f *frameWriter) Flush() {
	if f.err != nil {
		return
	}
	if f.status == 0 {
		f.status = 200
	}
	var out []byte
	if !f.sent {
		head := ResponseHead{Status: f.status, Headers: map[string]string{}}
		for k, v := range f.header {
			if len(v) > 0 && k != "Content-Length" && k != "Transfer-Encoding" {
				head.Headers[k] = v[0]
			}
		}
		hb, _ := json.Marshal(head)
		hb = append(hb, bytes.Repeat([]byte{' '}, proto.PadBucket(len(hb)+5, proto.StreamBucket)-len(hb)-5)...)
		out = appendFrame(out, 'H', hb)
		f.sent = true
	}
	if len(f.buf) > 0 {
		out = appendFrame(out, 'D', f.buf)
		f.n += uint64(len(f.buf))
		f.buf = f.buf[:0]
	}
	if len(out) == 0 {
		return
	}
	if _, err := f.out.Write(out); err != nil {
		f.err = err
		return
	}
	if f.flusher != nil {
		f.flusher.Flush()
	}
}

// finish sends what's left and the 'E' frame.
func (f *frameWriter) finish() {
	f.Flush()
	if f.err != nil {
		return
	}
	if _, err := f.out.Write(appendFrame(nil, 'E', binary.BigEndian.AppendUint64(nil, f.n))); err != nil {
		f.err = err
		return
	}
	if f.flusher != nil {
		f.flusher.Flush()
	}
}

func appendFrame(out []byte, typ byte, data []byte) []byte {
	out = append(out, typ)
	out = binary.BigEndian.AppendUint32(out, uint32(len(data)))
	return append(out, data...)
}

// ReadResponse reads a response's frames from r (the decrypted outer body): the inner status and headers, and a body
// that yields the 'D' frames' bytes.
func ReadResponse(r io.ReadCloser) (*http.Response, error) {
	fr := &frameReader{r: r}
	typ, data, err := fr.next()
	if err != nil || typ != 'H' {
		r.Close()
		return nil, errors.New("relay: no response head")
	}
	var head ResponseHead
	if err := json.Unmarshal(data, &head); err != nil || head.Status < 100 || head.Status > 599 {
		r.Close()
		return nil, errors.New("relay: bad response head")
	}
	res := &http.Response{StatusCode: head.Status, Status: strconv.Itoa(head.Status) + " " + http.StatusText(head.Status),
		Header: http.Header{}, Body: fr, ContentLength: -1, Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1}
	for k, v := range head.Headers {
		res.Header.Set(k, v)
	}
	return res, nil
}

// maxFrame bounds one frame a reader takes.
const maxFrame = MaxBody + proto.AnswerMax

type frameReader struct {
	r    io.ReadCloser
	data []byte
	n    uint64 // body bytes read
	done bool   // the 'E' frame came, and its length matched
}

func (f *frameReader) next() (byte, []byte, error) {
	var h [5]byte
	if _, err := io.ReadFull(f.r, h[:]); err != nil {
		if err == io.ErrUnexpectedEOF {
			return 0, nil, errors.New("relay: cut frame")
		}
		return 0, nil, err
	}
	n := binary.BigEndian.Uint32(h[1:])
	if n > maxFrame {
		return 0, nil, errors.New("relay: frame too large")
	}
	data := make([]byte, n)
	if _, err := io.ReadFull(f.r, data); err != nil {
		return 0, nil, errors.New("relay: cut frame")
	}
	return h[0], data, nil
}

func (f *frameReader) Read(p []byte) (int, error) {
	for len(f.data) == 0 {
		if f.done {
			return 0, io.EOF
		}
		typ, data, err := f.next()
		if err == io.EOF {
			return 0, errors.New("relay: the answer ended without its end frame (cut)")
		}
		if err != nil {
			return 0, err
		}
		switch typ {
		case 'D':
			f.data = data
			f.n += uint64(len(data))
		case 'E':
			if len(data) != 8 || binary.BigEndian.Uint64(data) != f.n {
				return 0, errors.New("relay: the answer's length isn't what was sent")
			}
			var x [1]byte
			if m, _ := f.r.Read(x[:]); m > 0 {
				return 0, errors.New("relay: data after the end frame")
			}
			f.done = true
		}
	}
	n := copy(p, f.data)
	f.data = f.data[n:]
	return n, nil
}

func (f *frameReader) Close() error { return f.r.Close() }
