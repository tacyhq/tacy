package kmsvm

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/tacyhq/tacy/kms"
	"github.com/tacyhq/tacy/kms/client"
	"github.com/tacyhq/tacy/sealstate"
)

// StateAPI is the chat Worker's sealed-state API (the chat's src/worker/vm-state.ts) in Go, for tests and local runs:
// the same checks, blobs in memory. A request is the VM's when its X-Tacy-Cert is a StoreCert the pinned KMS id
// signed and its X-Tacy-Auth a signature by that certificate's key over StateMessage within AuthWindow of now;
// each app and purpose has its own namespace; a put is compare-and-set on the generation.
//
//	GET {base}/api/vm/state/{name}  200 blob, X-Tacy-Gen | 404 none | 401 not the VM's
//	PUT {base}/api/vm/state/{name}  204 stored | 409 the held generation isn't X-Tacy-Prev-Gen | 400 not a sealed blob
//	                                of that name and generation | 413 too large | 401
type StateAPI struct {
	KMSID ed25519.PublicKey
	Now   func() time.Time // nil: time.Now

	mu    sync.Mutex
	blobs map[string][]byte // app/tag/name -> blob
	// Puts counts the stored puts (tests).
	Puts int
}

// AuthWindow is how far a request's time may be from the Worker's.
const AuthWindow = 2 * time.Minute

// Blobs is a copy of what is held, by "app/tag/name".
func (a *StateAPI) Blobs() map[string][]byte {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := map[string][]byte{}
	for k, v := range a.blobs {
		out[k] = append([]byte(nil), v...)
	}
	return out
}

// Set replaces what is held at key ("app/tag/name"; tests: an operator handing back an old blob).
func (a *StateAPI) Set(key string, blob []byte) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.blobs == nil {
		a.blobs = map[string][]byte{}
	}
	a.blobs[key] = append([]byte(nil), blob...)
}

// CheckAuth checks a sealed-state request's two headers and returns its namespace ("app/tag"), or "".
func CheckAuth(kmsID ed25519.PublicKey, now time.Time, method, name, certH, authH, gen, prev string, body []byte) string {
	cb, err := base64.RawURLEncoding.DecodeString(certH)
	if err != nil {
		return ""
	}
	var c kms.StoreCert
	if kms.Strict(cb, &c) != nil || client.CheckStoreCert(c, kmsID) != nil {
		return ""
	}
	pub, err := kms.ParseID(c.Key)
	if err != nil {
		return ""
	}
	ts, sig, ok := strings.Cut(strings.TrimPrefix(authH, "t="), ",s=")
	at, err := strconv.ParseInt(ts, 10, 64)
	sb, serr := base64.RawURLEncoding.DecodeString(sig)
	if !ok || !strings.HasPrefix(authH, "t=") || err != nil || serr != nil {
		return ""
	}
	if d := now.Sub(time.Unix(at, 0)); d > AuthWindow || d < -AuthWindow {
		return ""
	}
	if !ed25519.Verify(pub, StateMessage(method, name, at, gen, prev, body), sb) {
		return ""
	}
	return c.App + "/" + Tag(c.Purpose)
}

func (a *StateAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	name, ok := strings.CutPrefix(r.URL.Path, "/api/vm/state/")
	if !ok || !sealstate.ValidName(name) || (r.Method != "GET" && r.Method != "PUT") {
		w.WriteHeader(404)
		return
	}
	now := time.Now
	if a.Now != nil {
		now = a.Now
	}
	var body []byte
	if r.Method == "PUT" {
		b, err := io.ReadAll(io.LimitReader(r.Body, sealstate.MaxBlob+1))
		if err != nil {
			w.WriteHeader(400)
			return
		}
		if len(b) > sealstate.MaxBlob {
			w.WriteHeader(413)
			return
		}
		body = b
	}
	gen, prev := r.Header.Get("X-Tacy-Gen"), r.Header.Get("X-Tacy-Prev-Gen")
	ns := CheckAuth(a.KMSID, now(), r.Method, name, r.Header.Get("X-Tacy-Cert"), r.Header.Get("X-Tacy-Auth"), gen, prev, body)
	if ns == "" {
		w.WriteHeader(401)
		json.NewEncoder(w).Encode(map[string]string{"error": "unauthorized"})
		return
	}
	key := ns + "/" + name
	a.mu.Lock()
	defer a.mu.Unlock()
	if r.Method == "GET" {
		b, ok := a.blobs[key]
		if !ok {
			w.WriteHeader(404)
			return
		}
		_, g, _ := sealstate.Header(b)
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("X-Tacy-Gen", strconv.FormatUint(g, 10))
		w.Write(b)
		return
	}
	n, g, err := sealstate.Header(body)
	p, perr := strconv.ParseUint(prev, 10, 64)
	if err != nil || perr != nil || n != name || gen != strconv.FormatUint(g, 10) || g != p+1 {
		w.WriteHeader(400)
		return
	}
	var cur uint64
	if held, ok := a.blobs[key]; ok {
		_, cur, _ = sealstate.Header(held)
	}
	if cur != p {
		w.WriteHeader(409)
		return
	}
	if a.blobs == nil {
		a.blobs = map[string][]byte{}
	}
	a.blobs[key] = body
	a.Puts++
	w.WriteHeader(204)
}
