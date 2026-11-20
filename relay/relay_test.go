package relay

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/tacyhq/tacy/proto"
)

var (
	testSeed = bytes.Repeat([]byte{7}, 32)
	testKey  = ed25519.NewKeyFromSeed(testSeed)
	testPub  = testKey.Public().(ed25519.PublicKey)
	t0       = time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
)

func sealed(t *testing.T, method, path string, headers map[string]string, body []byte, at time.Time) []byte {
	t.Helper()
	b, _, err := Seal(method, path, headers, body, testKey, at)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func server(inner http.Handler) *Server {
	return &Server{Key: testPub, Inner: inner, Now: func() time.Time { return t0 }}
}

// L10 (security review 2026-11-20): a host that sets agentd's clock back can't make an envelope older than the
// operator's latest signed time (less Window and a minute) fresh again; the slack was 10 minutes.
func TestTrustedTimeSlack(t *testing.T) {
	op := t0
	for _, c := range []struct {
		age time.Duration
		ok  bool
	}{{0, true}, {2 * time.Minute, true}, {Window + 50*time.Second, true}, {4 * time.Minute, false}, {9 * time.Minute, false}} {
		at := op.Add(-c.age)
		s := &Server{Key: testPub, Now: func() time.Time { return at }, Trusted: func() (time.Time, bool) { return op, true }}
		if _, _, err := s.Open(bytes.NewReader(sealed(t, "GET", "/tasks/open", nil, nil, at))); (err == nil) != c.ok {
			t.Errorf("an envelope %s before the operator's time, the clock set back to it: %v", c.age, err)
		}
	}
}

func TestOpen(t *testing.T) {
	s := server(nil)
	body := []byte("the browser's EHBP ciphertext")
	h, inner, err := s.Open(bytes.NewReader(sealed(t, "POST", "/tasks", map[string]string{"X-Agent-User": "abc", "Ehbp-Encapsulated-Key": "ff"}, body, t0)))
	if err != nil || h.Path != "/tasks" || !bytes.Equal(inner, body) || h.Headers["X-Agent-User"] != "abc" {
		t.Fatalf("%v %+v", err, h)
	}
	// The request is padded to a size class.
	if n := len(sealed(t, "GET", "/tasks/open", nil, nil, t0)); n != proto.AnswerMin {
		t.Fatalf("a small envelope is %d bytes", n)
	}
}

// Anything changed after signing is refused: the path, a header, the body, the time; and a signature by another key.
func TestOpenRefusesTampering(t *testing.T) {
	s := server(nil)
	edit := func(f func(h *Header, body *[]byte)) []byte {
		b := sealed(t, "POST", "/schedules/install", map[string]string{"X-Schedule-Charge": "v1 a_x daily=1"}, []byte("body"), t0)
		hl := binary.BigEndian.Uint32(b)
		var h Header
		json.Unmarshal(b[4:4+hl], &h)
		inner := append([]byte{}, b[4+hl:4+int(hl)+h.Len]...)
		f(&h, &inner)
		hb, _ := json.Marshal(h)
		out := binary.BigEndian.AppendUint32(nil, uint32(len(hb)))
		return append(append(out, hb...), inner...)
	}
	other := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{8}, 32))
	for name, b := range map[string][]byte{
		"path":         edit(func(h *Header, _ *[]byte) { h.Path = "/schedules/remove" }),
		"method":       edit(func(h *Header, _ *[]byte) { h.Method = "GET" }),
		"header value": edit(func(h *Header, _ *[]byte) { h.Headers["X-Schedule-Charge"] = "v1 a_x daily=0" }),
		"header added": edit(func(h *Header, _ *[]byte) { h.Headers["X-Agent-User"] = "abc" }),
		"body":         edit(func(_ *Header, body *[]byte) { (*body)[0] = 'B' }),
		"body hash":    edit(func(h *Header, body *[]byte) { *body = []byte("other"); h.Len = 5 }),
		"time":         edit(func(h *Header, _ *[]byte) { h.Time++ }),
		"nonce":        edit(func(h *Header, _ *[]byte) { h.Nonce = strings.Repeat("0", 32) }),
		"another key": edit(func(h *Header, body *[]byte) {
			Sign(h, *body, other, t0, h.Nonce)
		}),
		"empty":   {},
		"garbage": []byte("\x00\x00\x00\x05hello"),
	} {
		if _, _, err := s.Open(bytes.NewReader(b)); err != ErrAuth {
			t.Errorf("%s: %v", name, err)
		}
	}
	// No key pinned: nothing opens.
	if _, _, err := (&Server{Now: s.Now}).Open(bytes.NewReader(sealed(t, "GET", "/tasks/open", nil, nil, t0))); err != ErrAuth {
		t.Fatalf("no key: %v", err)
	}
}

func TestCheck(t *testing.T) {
	ok := Header{V: 1, Method: "GET", Path: "/activity?chain=c_ab&after=3", Len: 0, BodySHA: strings.Repeat("a", 64), Nonce: strings.Repeat("b", 32)}
	if err := ok.Check(); err != nil {
		t.Fatal(err)
	}
	for name, f := range map[string]func(h *Header){
		"version":    func(h *Header) { h.V = 2 },
		"method":     func(h *Header) { h.Method = "DELETE" },
		"no slash":   func(h *Header) { h.Path = "tasks" },
		"dot dot":    func(h *Header) { h.Path = "/a/../v" },
		"double":     func(h *Header) { h.Path = "//tasks" },
		"itself":     func(h *Header) { h.Path = "/v" },
		"itself q":   func(h *Header) { h.Path = "/v?x=1" },
		"space":      func(h *Header) { h.Path = "/tasks open" },
		"too big":    func(h *Header) { h.Len = MaxBody + 1 },
		"nonce":      func(h *Header) { h.Nonce = "short" },
		"newline":    func(h *Header) { h.Headers = map[string]string{"X-A": "a\nb"} },
		"bad name":   func(h *Header) { h.Headers = map[string]string{"X A": "a"} },
		"duplicates": func(h *Header) { h.Headers = map[string]string{"X-A": "1", "x-a": "2"} },
	} {
		h := ok
		f(&h)
		if h.Check() == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

// The inner handler's status, headers and body come back as frames, the head padded; Flush makes a frame each.
func TestFrames(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !Relayed(r.Context()) || r.Header.Get("X-Agent-Model") != "m" || r.Method != "POST" || r.URL.Path != "/tasks" {
			t.Errorf("inner request: %v %s %s", r.Header, r.Method, r.URL)
		}
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("X-Agent-Bill", "0123")
		w.WriteHeader(201)
		w.Write([]byte("first:" + string(body)))
		w.(http.Flusher).Flush()
		w.Write([]byte("second"))
	})
	s := server(inner)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", Path, bytes.NewReader(sealed(t, "POST", "/tasks", map[string]string{"X-Agent-Model": "m"}, []byte("in"), t0)))
	s.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("outer %d", rec.Code)
	}
	raw := rec.Body.Bytes()
	if raw[0] != 'H' || (5+int(binary.BigEndian.Uint32(raw[1:])))%proto.StreamBucket != 0 {
		t.Fatalf("head frame isn't padded: %q", raw[:5])
	}
	res, err := ReadResponse(io.NopCloser(bytes.NewReader(raw)))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(res.Body)
	if res.StatusCode != 201 || res.Header.Get("X-Agent-Bill") != "0123" || string(body) != "first:insecond" {
		t.Fatalf("%d %v %q", res.StatusCode, res.Header, body)
	}
	// A cut stream is an error, not a clean end: in a frame, and (L2, security review 2026-11-20) at a frame's edge,
	// where EHBP itself would end cleanly.
	if raw[len(raw)-13] != 'E' {
		t.Fatalf("no end frame: %q", raw[len(raw)-13:])
	}
	for name, cut := range map[string][]byte{"in a frame": raw[:len(raw)-2], "at the end frame": raw[:len(raw)-13],
		"after the head": raw[:5+int(binary.BigEndian.Uint32(raw[1:]))]} {
		res, _ = ReadResponse(io.NopCloser(bytes.NewReader(cut)))
		if _, err := io.ReadAll(res.Body); err == nil {
			t.Fatalf("cut %s: read as the end", name)
		}
	}
	// A frame dropped from the middle leaves the end frame's length wrong.
	headLen := 5 + int(binary.BigEndian.Uint32(raw[1:]))
	firstD := 5 + int(binary.BigEndian.Uint32(raw[headLen+1:]))
	dropped := append(append([]byte{}, raw[:headLen]...), raw[headLen+firstD:]...)
	res, _ = ReadResponse(io.NopCloser(bytes.NewReader(dropped)))
	if _, err := io.ReadAll(res.Body); err == nil {
		t.Fatal("a dropped frame went unnoticed")
	}
	// A refused envelope answers inside, with its own status.
	rec = httptest.NewRecorder()
	s.ServeHTTP(rec, httptest.NewRequest("POST", Path, bytes.NewReader(sealed(t, "GET", "/tasks/open", nil, nil, t0.Add(-time.Hour)))))
	res, _ = ReadResponse(io.NopCloser(bytes.NewReader(rec.Body.Bytes())))
	if rec.Code != 200 || res.StatusCode != 409 {
		t.Fatalf("expired: outer %d inner %d", rec.Code, res.StatusCode)
	}
}

func TestReplayCache(t *testing.T) {
	s := server(nil)
	b := sealed(t, "GET", "/tasks/open", nil, nil, t0)
	if _, _, err := s.Open(bytes.NewReader(b)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Open(bytes.NewReader(b)); err != ErrReplay {
		t.Fatalf("replay: %v", err)
	}
	// Expired nonces are forgotten (their envelopes are refused by time anyway); a full cache refuses, not forgets.
	s.seen = map[string]time.Time{}
	for i := range MaxNonces {
		s.seen[strconv.Itoa(i)] = t0.Add(time.Hour)
	}
	if _, _, err := s.Open(bytes.NewReader(sealed(t, "GET", "/tasks/open", nil, nil, t0))); err != ErrBusy {
		t.Fatalf("full cache: %v", err)
	}
	for k := range s.seen {
		s.seen[k] = t0.Add(-time.Second)
	}
	if _, _, err := s.Open(bytes.NewReader(sealed(t, "GET", "/tasks/open", nil, nil, t0))); err != nil || len(s.seen) != 1 {
		t.Fatalf("after expiry: %v %d", err, len(s.seen))
	}
}

func TestParseKey(t *testing.T) {
	for _, s := range []string{base64.StdEncoding.EncodeToString(testSeed), base64.RawURLEncoding.EncodeToString(testSeed), " " + base64.URLEncoding.EncodeToString(testSeed) + "\n"} {
		k, err := ParseKey(s)
		if err != nil || !bytes.Equal(k, testKey) {
			t.Fatalf("%q: %v", s, err)
		}
	}
	for _, s := range []string{"", "tok", base64.StdEncoding.EncodeToString(testSeed[:31])} {
		if _, err := ParseKey(s); err == nil {
			t.Fatalf("%q accepted", s)
		}
	}
}

// The golden vector (../testdata/relay-auth-v1.json): the chat's Worker (the chat's src/worker/vm-relay.ts) signs the same
// bytes the same way; its test checks against this file. UPDATE_GOLDEN=1 writes it.
func TestGolden(t *testing.T) {
	type vec struct {
		Seed        string            `json:"seed"`
		PublicKey   string            `json:"public_key"`
		Method      string            `json:"method"`
		Path        string            `json:"path"`
		Headers     map[string]string `json:"headers"`
		Body        []byte            `json:"body"`
		Nonce       string            `json:"nonce"`
		Time        int64             `json:"time"`
		Signed      string            `json:"signed"`
		Sig         string            `json:"sig"`
		Plaintext   []byte            `json:"plaintext"` // the whole envelope plaintext, padded
		BucketSizes [][2]int          `json:"bucket_sizes"`
	}
	headers := map[string]string{"X-Agent-User": "0123456789abcdef", "Ehbp-Encapsulated-Key": strings.Repeat("ab", 32), "Content-Type": "application/json", "X-Agent-Model": "kimi-k3"}
	body := []byte("opaque inner body")
	nonce := strings.Repeat("0f", 16)
	plain, h, err := SealNonce("POST", "/tasks", headers, body, testKey, t0, nonce)
	if err != nil {
		t.Fatal(err)
	}
	got := vec{Seed: base64.RawURLEncoding.EncodeToString(testSeed), PublicKey: PublicKeyString(testPub), Method: "POST", Path: "/tasks",
		Headers: headers, Body: body, Nonce: nonce, Time: t0.Unix(), Signed: string(h.Signed()), Sig: h.Sig, Plaintext: plain}
	for _, n := range []int{0, 1, 512, 513, 5000, 70000} {
		got.BucketSizes = append(got.BucketSizes, [2]int{n, proto.PadPow2(n, proto.AnswerMin, proto.AnswerMax)})
	}
	path := filepath.Join("..", "testdata", "relay-auth-v1.json")
	if os.Getenv("UPDATE_GOLDEN") == "1" {
		b, _ := json.MarshalIndent(got, "", "  ")
		if err := os.WriteFile(path, append(b, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var want vec
	if err := json.Unmarshal(b, &want); err != nil {
		t.Fatal(err)
	}
	if want.Signed != got.Signed || want.Sig != got.Sig || !bytes.Equal(want.Plaintext, got.Plaintext) || want.PublicKey != got.PublicKey {
		t.Fatalf("golden vector changed: %+v", got)
	}
	if _, _, err := server(nil).Open(bytes.NewReader(want.Plaintext)); err != nil {
		t.Fatalf("the golden envelope doesn't open: %v", err)
	}
}
