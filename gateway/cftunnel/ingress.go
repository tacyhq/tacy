package cftunnel

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
)

// Ingress is the only origin cloudflared's pinned config names (unix:<Dir>/ingress.sock): it forwards the routes the
// Worker uses to agentd's HTTP socket and refuses the rest before anything reaches agentd. It reads request heads
// only; bodies (EHBP ciphertext) are streamed through unread.
type Ingress struct {
	Agent string // agentd's HTTP unix socket (-forward)
	Spike bool   // the spike's test routes (/spike/*): throwaway composes only
	// Diag is the e2e diag route (DiagPrefix; gatewayd -e2e-diag, the e2e overlay's only: NewDiag). nil: no route.
	Diag http.Handler
	Sup  *Supervisor // for /spike/cfd
	Boot time.Time   // gatewayd's start (for /spike/cfd)

	proxy *httputil.ReverseProxy
	seen  atomic.Int64 // every request that reached this socket (the spike: did a refused one get here?)
	fwd   atomic.Int64 // forwarded to agentd
}

// forwardHeaders are the request headers agentd may see (everything else, Cloudflare's included, is dropped).
var forwardHeaders = []string{"Content-Type", "Accept", "Content-Length", "Ehbp-Encapsulated-Key"}

// Allowed is the route allowlist: a pure function of the method, the path and the raw query.
func Allowed(method, path, rawQuery string) bool {
	switch {
	case method == http.MethodGet && path == "/health":
		return rawQuery == ""
	case method == http.MethodGet && path == "/attest":
		q, err := url.ParseQuery(rawQuery)
		if err != nil || len(q) != 1 || len(q["nonce"]) != 1 {
			return false
		}
		n := q.Get("nonce")
		_, err = hex.DecodeString(n)
		return len(n) == 64 && err == nil
	case method == http.MethodPost && path == "/v":
		return rawQuery == ""
	}
	return false
}

func (in *Ingress) init() {
	if in.proxy != nil {
		return
	}
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", in.Agent)
		},
		MaxIdleConns: 16, IdleConnTimeout: 60 * time.Second, DisableCompression: true,
	}
	in.proxy = &httputil.ReverseProxy{
		Transport:     tr,
		FlushInterval: -1, // stream every write (the answers are framed H/D/E; tasks stream)
		Rewrite: func(r *httputil.ProxyRequest) {
			r.Out.URL.Scheme, r.Out.URL.Host, r.Out.Host = "http", "agentd", "agentd"
			h := http.Header{}
			for _, k := range forwardHeaders {
				if v := r.In.Header.Values(k); len(v) > 0 {
					h[k] = v
				}
			}
			r.Out.Header = h
		},
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, err error) {
			http.Error(w, "agentd unavailable", http.StatusBadGateway)
		},
	}
}

func (in *Ingress) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	in.init()
	in.seen.Add(1)
	if Allowed(r.Method, r.URL.Path, r.URL.RawQuery) {
		in.fwd.Add(1)
		in.proxy.ServeHTTP(w, r)
		return
	}
	if in.Diag != nil && strings.HasPrefix(r.URL.Path, DiagPrefix) {
		in.Diag.ServeHTTP(w, r)
		return
	}
	if in.Spike && r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/spike/") {
		in.spike(w, r)
		return
	}
	http.NotFound(w, r)
}

// spike serves the throwaway's test routes: they measure the tunnel, not agentd.
//
//	/spike/ping                       "pong <unix ns>" (latency)
//	/spike/stream?secs=180&every=20   an SSE stream: a comment every `every` s, a final "done" event after `secs` s
//	/spike/cfd                        the supervisor's events and cloudflared's pid
func (in *Ingress) spike(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/spike/ping":
		w.Header().Set("Cache-Control", "no-store")
		fmt.Fprintf(w, "pong %d\n", time.Now().UnixNano())
	case "/spike/stream":
		secs, _ := strconv.Atoi(r.URL.Query().Get("secs"))
		every, _ := strconv.Atoi(r.URL.Query().Get("every"))
		if secs <= 0 || secs > 3600 || every <= 0 || every > 600 {
			http.Error(w, "secs 1-3600, every 1-600", http.StatusBadRequest)
			return
		}
		fl, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "no flush", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-store")
		t0 := time.Now()
		fmt.Fprintf(w, "event: open\ndata: {\"t\":%d}\n\n", t0.UnixNano())
		fl.Flush()
		tick := time.NewTicker(time.Duration(every) * time.Second)
		defer tick.Stop()
		end := time.After(time.Duration(secs) * time.Second)
		n := 0
		for {
			select {
			case <-r.Context().Done():
				return
			case <-end:
				fmt.Fprintf(w, "event: done\ndata: {\"n\":%d,\"ms\":%d}\n\n", n, time.Since(t0).Milliseconds())
				fl.Flush()
				return
			case <-tick.C:
				n++
				fmt.Fprintf(w, ": keepalive %d %d\n\n", n, time.Now().UnixNano())
				fl.Flush()
			}
		}
	case "/spike/cfd":
		var ev []Event
		pid := 0
		if in.Sup != nil {
			ev, pid = in.Sup.Events()
		}
		w.Header().Set("Content-Type", "application/json")
		out := map[string]any{"pid": pid, "events": ev, "gatewayd_start": in.Boot, "now": time.Now().UTC(),
			"requests_seen": in.seen.Load(), "forwarded": in.fwd.Load()}
		// The confinement evidence (review H1; throwaways only): the launcher's last probe as cloudflared's uid, and
		// the running cloudflared's credentials as /proc shows them (world-readable lines: uid, groups, capabilities).
		if b, err := os.ReadFile(ProbeFile); err == nil {
			out["confinement"] = json.RawMessage(b)
		}
		if pid > 0 {
			st, _ := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
			var lines []string
			for _, ln := range strings.Split(string(st), "\n") {
				for _, k := range []string{"Uid:", "Gid:", "Groups:", "CapInh:", "CapPrm:", "CapEff:", "CapBnd:", "CapAmb:", "NoNewPrivs:", "Seccomp:"} {
					if strings.HasPrefix(ln, k) {
						lines = append(lines, ln)
					}
				}
			}
			out["cloudflared_status"] = lines
			out["self_status_dumpable_proc_owner"] = procOwner(fmt.Sprintf("/proc/%d/environ", os.Getpid()))
		}
		json.NewEncoder(w).Encode(out)
	default:
		http.NotFound(w, r)
	}
}

// procOwner is the owner uid of a /proc file ("root" when the process is non-dumpable: the kernel shows its /proc
// entries as root's).
func procOwner(p string) string {
	fi, err := os.Stat(p)
	if err != nil {
		return err.Error()
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return fmt.Sprint(st.Uid)
	}
	return "?"
}
