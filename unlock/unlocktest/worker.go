package unlocktest

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"time"

	"github.com/tacyhq/tacy/gateway"
	"github.com/tacyhq/tacy/kms"
	"github.com/tacyhq/tacy/kmsvm"
	"github.com/tacyhq/tacy/unlock"
)

// Worker is the chat Worker as the VM sees it, in this process: the sealed-state API (its Go twin,
// kmsvm.StateAPI), the unlock routes (the newest policy, secrets.sealed, unlock reports) and the schedule ownership
// rows (unlock/owner.go), with the Worker's checks.
type Worker struct {
	State *kmsvm.StateAPI
	Now   func() time.Time

	mu      sync.Mutex
	policy  []byte
	secrets []byte
	reports []unlock.SignedReport
	owners  map[string]unlock.OwnerRow
	gets    map[string]int
}

// NewWorker is a Worker for kmsID.
func NewWorker(kmsID ed25519.PublicKey, now func() time.Time) *Worker {
	return &Worker{State: &kmsvm.StateAPI{KMSID: kmsID, Now: now}, Now: now, owners: map[string]unlock.OwnerRow{}, gets: map[string]int{}}
}

// SetPolicy is what GET /api/vm/unlock/policy serves (nil: 404).
func (k *Worker) SetPolicy(b []byte) { k.mu.Lock(); k.policy = b; k.mu.Unlock() }

// SetSecrets is what GET /api/vm/unlock/secrets serves (nil: 404).
func (k *Worker) SetSecrets(b []byte) { k.mu.Lock(); k.secrets = b; k.mu.Unlock() }

// Reports are the unlock reports received.
func (k *Worker) Reports() []unlock.SignedReport {
	k.mu.Lock()
	defer k.mu.Unlock()
	return append([]unlock.SignedReport(nil), k.reports...)
}

// Gets counts the GETs of an unlock route.
func (k *Worker) Gets(path string) int { k.mu.Lock(); defer k.mu.Unlock(); return k.gets[path] }

// Owners are the ownership rows by "app/tag/name".
func (k *Worker) Owners() map[string]unlock.OwnerRow {
	k.mu.Lock()
	defer k.mu.Unlock()
	out := map[string]unlock.OwnerRow{}
	for n, r := range k.owners {
		out[n] = r
	}
	return out
}

func (k *Worker) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	now := time.Now
	if k.Now != nil {
		now = k.Now
	}
	switch p := r.URL.Path; {
	case p == gateway.UnlockPolicyPath || p == gateway.UnlockSecretsPath:
		k.mu.Lock()
		k.gets[p]++
		b := k.policy
		if p == gateway.UnlockSecretsPath {
			b = k.secrets
		}
		k.mu.Unlock()
		if r.Method != http.MethodGet || b == nil {
			w.WriteHeader(404)
			return
		}
		w.Write(b)
	case p == gateway.UnlockReportPath && r.Method == http.MethodPost:
		var sr unlock.SignedReport
		if json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&sr) != nil {
			w.WriteHeader(400)
			return
		}
		k.mu.Lock()
		k.reports = append(k.reports, sr)
		k.mu.Unlock()
		w.WriteHeader(204)
	case strings.HasPrefix(p, "/api/vm/owner/") && r.Method == http.MethodPost:
		name := strings.TrimPrefix(p, "/api/vm/owner/")
		body, _ := io.ReadAll(io.LimitReader(r.Body, 4096))
		ns := kmsvm.CheckAuth(k.State.KMSID, now(), r.Method, name, r.Header.Get("X-Tacy-Cert"), r.Header.Get("X-Tacy-Auth"), "", "", body)
		var c unlock.OwnerClaim
		if ns == "" || json.Unmarshal(body, &c) != nil || c.Owner == "" || c.TTL <= 0 || c.TTL > 900 {
			w.WriteHeader(401)
			return
		}
		key := ns + "/" + name
		k.mu.Lock()
		row := k.owners[key]
		status := 200
		if row.Owner == c.Owner || row.Until < now().Unix() {
			row = unlock.OwnerRow{Owner: c.Owner, Until: now().Add(time.Duration(c.TTL) * time.Second).Unix()}
			k.owners[key] = row
		} else {
			status = 409
		}
		k.mu.Unlock()
		w.WriteHeader(status)
		json.NewEncoder(w).Encode(row)
	default:
		k.State.ServeHTTP(w, r)
	}
}

// Routes is an HTTP transport to in-process handlers by host (the holders at their policy URLs, the Worker), so
// gatewayd's fixed calls run their production path with names that resolve nowhere.
type Routes struct {
	mu    sync.Mutex
	hosts map[string]http.Handler
	calls map[string]int
}

// Set routes host to h (nil: the host doesn't answer: a holder down).
func (rt *Routes) Set(host string, h http.Handler) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if rt.hosts == nil {
		rt.hosts, rt.calls = map[string]http.Handler{}, map[string]int{}
	}
	rt.hosts[host] = h
}

// Calls counts the requests that reached host.
func (rt *Routes) Calls(host string) int { rt.mu.Lock(); defer rt.mu.Unlock(); return rt.calls[host] }

// RoundTrip implements http.RoundTripper.
func (rt *Routes) RoundTrip(req *http.Request) (*http.Response, error) {
	rt.mu.Lock()
	h := rt.hosts[req.URL.Host]
	if h != nil {
		rt.calls[req.URL.Host]++
	}
	rt.mu.Unlock()
	if h == nil {
		return nil, fmt.Errorf("dial %s: connection refused", req.URL.Host)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w.Result(), nil
}

// WorkerHost is the Worker's host in the world's gateway.
const WorkerHost = "chat.tacy.test"

// HolderHost is holder h's host (its URL in the world's policy).
func HolderHost(h string) string { return "keys-" + h + ".tacy.io" }

// Gateway is gatewayd's fixed calls as unlockd, agentd and vaultd reach them, over rt: each holder at its policy
// URL, the Worker at WorkerHost; holder URLs from the Worker's newest policy, under tacy.io.
func (w *World) Gateway(rt *Routes, worker http.Handler) *gateway.Fixed {
	f, err := gateway.NewFixed(nil, "https://"+WorkerHost, false)
	if err != nil {
		w.t.Fatal(err)
	}
	f.Client = &http.Client{Transport: rt, Timeout: 10 * time.Second}
	rt.Set(WorkerHost, worker)
	for _, h := range w.IDs {
		rt.Set(HolderHost(h), w.Handler(h))
	}
	f.NewUnlockHosts(w.IDPub, kms.AdminKeys{Keys: []ed25519.PublicKey{w.AdminPub}, Threshold: 1}, "tacy.io").MinRefetch = time.Nanosecond
	return f
}
