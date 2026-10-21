// Package storedfilestest is a stand-in for the files bucket (R2's S3 API with presigned GETs) and the chat Worker's
// read-URL route, for tests, labs and cmd/e2e's local runs. Never in a release binary.
package storedfilestest

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"

	"github.com/tacyhq/tacy/proto"
	"github.com/tacyhq/tacy/storedfiles"
)

// Store serves objects at /<bucket>/f/<owner>/<object> with one byte range per GET, only with the query signature it
// handed out; and POST /api/vm/files/read-urls for grants it made. Counts what it served.
type Store struct {
	Srv    *httptest.Server
	Bucket string
	Owner  string

	mu      sync.Mutex
	objects map[string][]byte // key -> sealed bytes
	sigs    map[string]string // key -> the signature its URLs carry
	grants  map[string][]string
	Gets    map[string]int   // object -> GETs served
	Bytes   int64            // bytes served
	Ranges  map[string][]int // object -> the first byte of each range served
	URLAsks int              // read-URL calls
	// OnGet, when set, runs before each object GET is answered (a test looks at its VM while a fetch is under way).
	OnGet func()
}

// NewStore starts a stand-in over TLS. Its URLs name the production hosts (storedfiles.R2Host for objects,
// storedfiles.ChatHost for read URLs), so the release's own checks (https, the host, the policy's fetch hosts) apply
// unchanged; Client reaches the stand-in whatever host a request names.
func NewStore() *Store {
	s := &Store{Bucket: storedfiles.Bucket, Owner: ID("ow"), objects: map[string][]byte{}, sigs: map[string]string{},
		grants: map[string][]string{}, Gets: map[string]int{}, Ranges: map[string][]int{}}
	s.Srv = httptest.NewTLSServer(http.HandlerFunc(s.serve))
	return s
}

func (s *Store) Close() { s.Srv.Close() }

// Client dials the stand-in for every host and trusts its certificate (httptest's, for example.com).
func (s *Store) Client() *http.Client {
	addr := s.Srv.Listener.Addr().String()
	t := s.Srv.Client().Transport.(*http.Transport).Clone()
	t.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}
	t.TLSClientConfig.ServerName = "example.com"
	c := storedfiles.DefaultClient()
	c.Transport = t
	return c
}

// Fetcher reads from the stand-in.
func (s *Store) Fetcher() *storedfiles.Fetcher { return &storedfiles.Fetcher{Client: s.Client()} }

// URLSource asks the stand-in's read-URL route.
func (s *Store) URLSource() *storedfiles.WorkerURLs {
	return &storedfiles.WorkerURLs{Client: s.Client()}
}

// Config is a guard's way to the stand-in (guard.StoredConfig takes these two).
func (s *Store) Config() (*storedfiles.Fetcher, storedfiles.URLSource) {
	return s.Fetcher(), s.URLSource()
}

// ID is a random file-storage id with prefix ("fl", "ob", "ow").
func ID(prefix string) string {
	var b [16]byte
	rand.Read(b[:]) // 128 bits: 26 base32 characters, the last one's two low bits zero
	return prefix + "_" + strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b[:]))
}

// Put stores data as a new object of a new file, encrypted under a fresh key, and returns its ref with a read URL.
func (s *Store) Put(name, typ string, data []byte) proto.StoredFile {
	key := make([]byte, 32)
	rand.Read(key)
	f := proto.StoredFile{Object: ID("ob"), File: ID("fl"), Owner: s.Owner, Epoch: 1, Size: int64(len(data)), Name: name, Type: typ, Key: key}
	sealed, padded, err := storedfiles.Encrypt(key, f.File, f.Object, f.Epoch, data, nil)
	if err != nil {
		panic(err)
	}
	f.Padded = padded
	s.PutSealed(f, sealed)
	f.URL = s.URL(f)
	return f
}

// PutSealed stores sealed bytes as f's object (a test's own, tampered or not).
func (s *Store) PutSealed(f proto.StoredFile, sealed []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := storedfiles.ObjectKey(f.Owner, f.Object)
	s.objects[k] = sealed
	if s.sigs[k] == "" {
		s.sigs[k] = ID("sg")[3:]
	}
}

// Delete drops an object (a purged file).
func (s *Store) Delete(f proto.StoredFile) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.objects, storedfiles.ObjectKey(f.Owner, f.Object))
}

// URL is a "presigned" GET for f's object on the stand-in.
func (s *Store) URL(f proto.StoredFile) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := storedfiles.ObjectKey(f.Owner, f.Object)
	return "https://" + storedfiles.R2Host + "/" + s.Bucket + "/" + k + "?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Expires=3600&X-Amz-Signature=" + s.sigs[k]
}

// Grant makes a read grant for these objects (opaque to the VM).
func (s *Store) Grant(objects ...string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	g := "g1." + ID("gr")[3:] + "." + ID("mc")[3:] // the Worker's shape: g1.<payload>.<mac>, opaque here
	s.grants[g] = objects
	return g
}

func (s *Store) serve(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost && r.URL.Path == storedfiles.URLsPath {
		s.urls(w, r)
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return
	}
	k := strings.TrimPrefix(r.URL.Path, "/"+s.Bucket+"/")
	s.mu.Lock()
	body, ok := s.objects[k]
	sig := s.sigs[k]
	hook := s.OnGet
	s.mu.Unlock()
	if hook != nil {
		hook()
	}
	if !ok || r.URL.Query().Get("X-Amz-Signature") != sig {
		http.Error(w, "NoSuchKey", http.StatusNotFound)
		return
	}
	from, to := int64(0), int64(len(body))
	if rg := r.Header.Get("Range"); rg != "" {
		a, b, ok := strings.Cut(strings.TrimPrefix(rg, "bytes="), "-")
		x, err1 := strconv.ParseInt(a, 10, 64)
		y, err2 := strconv.ParseInt(b, 10, 64)
		if !ok || err1 != nil || err2 != nil || x < 0 || y < x || y >= int64(len(body)) {
			http.Error(w, "range", http.StatusRequestedRangeNotSatisfiable)
			return
		}
		from, to = x, y+1
		w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", from, to-1, len(body)))
		w.Header().Set("Content-Length", strconv.FormatInt(to-from, 10))
		w.WriteHeader(http.StatusPartialContent)
	}
	w.Write(body[from:to])
	obj := k[strings.LastIndexByte(k, '/')+1:]
	s.mu.Lock()
	s.Gets[obj]++
	s.Bytes += to - from
	s.Ranges[obj] = append(s.Ranges[obj], int(from))
	s.mu.Unlock()
}

func (s *Store) urls(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Grant   string   `json:"grant"`
		Objects []string `json:"objects"`
	}
	if json.NewDecoder(r.Body).Decode(&req) != nil {
		http.Error(w, `{"error":"bad_request"}`, http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	s.URLAsks++
	allowed, ok := s.grants[req.Grant]
	s.mu.Unlock()
	if !ok {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"error":"bad_grant"}`))
		return
	}
	out := map[string]string{}
	for _, o := range req.Objects {
		in := false
		for _, a := range allowed {
			in = in || a == o
		}
		s.mu.Lock()
		_, live := s.objects[storedfiles.ObjectKey(s.Owner, o)]
		s.mu.Unlock()
		if !in || !live {
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte(`{"error":"not_found"}`))
			return
		}
		out[o] = s.URL(proto.StoredFile{Owner: s.Owner, Object: o})
	}
	json.NewEncoder(w).Encode(map[string]any{"owner": s.Owner, "expires": 0, "urls": out})
}
