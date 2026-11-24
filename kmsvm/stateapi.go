package kmsvm

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
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
	// leases: the sealed state's writer lease rows, app/tag/name -> row (the Worker's vm-lease.ts, in memory).
	leases map[string]leaseRow
	// Puts counts the stored puts (tests).
	Puts int
}

type leaseRow struct {
	Holder string `json:"holder"`
	Until  int64  `json:"until"`
}

// legacyHolder: the row of a VM built before the lease (unlock.LegacyHolder).
const legacyHolder = "legacy"

// leaseOf is the app's writer lease row (unlock.LeaseName("state/all")), if any (a.mu held).
func (a *StateAPI) leaseOf(ns string) (leaseRow, bool) {
	r, ok := a.leases[ns+"/"+LeaseAllName]
	return r, ok
}

// LeaseAllName is unlock.LeaseName("state/all") (unlock imports this package; checked in unlock/lease_test.go).
var LeaseAllName = func() string {
	h := sha256.Sum256([]byte("tacy/state-lease/v1\x00state/all"))
	return "o" + hex.EncodeToString(h[:24])
}()

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

// serveLease is POST /api/vm/lease/{name} as the Worker serves it (apps/chat vm-lease.ts): a claim takes the row
// when there is none, it is the claimant's, or it lapsed and was the same app's (never the legacy row); a takeover
// ("from": the Worker's switch's order, carried by the VM) only from the holder it names.
func (a *StateAPI) serveLease(w http.ResponseWriter, r *http.Request, name string, now time.Time) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 4096))
	if err != nil || r.Method != "POST" {
		w.WriteHeader(400)
		return
	}
	ns := CheckAuth(a.KMSID, now, "POST", name, r.Header.Get("X-Tacy-Cert"), r.Header.Get("X-Tacy-Auth"), "", "", body)
	if ns == "" || !strings.HasSuffix(ns, "/state") {
		w.WriteHeader(401)
		return
	}
	var c struct {
		Holder string `json:"holder"`
		TTL    int64  `json:"ttl"`
		From   string `json:"from"`
	}
	if json.Unmarshal(body, &c) != nil || c.Holder == "" || c.TTL < 1 || c.TTL > 300 || (c.Holder == legacyHolder && c.From == "") {
		w.WriteHeader(400)
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.leases == nil {
		a.leases = map[string]leaseRow{}
	}
	key, nowS := ns+"/"+name, now.Unix()
	row, ok := a.leases[key]
	app := func(h string) string { s, _, _ := strings.Cut(h, "/"); return s }
	take := !ok || row.Holder == c.Holder
	if c.From != "" {
		take = !ok || row.Holder == c.From || row.Holder == c.Holder // or already its own (an undo whose takeover never landed)
	} else if ok && row.Until < nowS && row.Holder != legacyHolder && app(row.Holder) == app(c.Holder) {
		take = true
	}
	if take {
		row = leaseRow{Holder: c.Holder, Until: nowS + c.TTL}
		a.leases[key] = row
	}
	status := 409
	if row.Holder == c.Holder && (row.Holder == legacyHolder || row.Until > nowS) {
		status = 200
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(row)
}

func (a *StateAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if name, ok := strings.CutPrefix(r.URL.Path, "/api/vm/lease/"); ok {
		now := time.Now
		if a.Now != nil {
			now = a.Now
		}
		a.serveLease(w, r, name, now())
		return
	}
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
	// The writer lease's fence (the Worker's vm-lease.ts): once the app has a lease row, only its holder saves; a VM
	// built before the lease (no X-Tacy-Writer) makes the legacy row with its first save.
	writer := r.Header.Get("X-Tacy-Writer")
	leased := strings.HasSuffix(ns, "/state") // agentd's state only, never vaultd's connections (go-live review L1)
	if a.leases == nil {
		a.leases = map[string]leaseRow{}
	}
	lr, has := a.leaseOf(ns)
	if leased && writer == "" && !has {
		lr, has = leaseRow{Holder: legacyHolder}, true
		a.leases[ns+"/"+LeaseAllName] = lr
	}
	if leased && has && lr.Holder != writer && !(writer == "" && lr.Holder == legacyHolder) {
		w.WriteHeader(409)
		json.NewEncoder(w).Encode(map[string]string{"error": "not_writer"})
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
