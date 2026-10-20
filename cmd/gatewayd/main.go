// gatewayd is the agent VM's gateway (docs/21-gateway-v0.md): the only process in the CVM with a network. It
// runs the model gateway (Tinfoil's router, verified, bodies EHBP-encrypted) and the web connector (search, page
// fetch, images, site icons) for agentd's tasks, over gateway/v0 on a unix socket (../../gateway). For each call
// it leases the key it needs from vaultd (one lease per call, no cache) and wipes it afterwards; it scans the
// brain's arguments for credentials before anything is sent (blocks) and redacts what comes back before the brain
// sees it, recording pattern ids only.
//
// It also carries the published port: agentd has no network at all (its container's network_mode is none), so
// gatewayd accepts the VM's inbound connections on -listen and copies the bytes to and from agentd's HTTP socket,
// unread (the bodies are EHBP-encrypted to agentd's key). It never connects to agentd any other way, and agentd
// can't make it connect anywhere except through a typed request.
//
//	go run ./cmd/gatewayd --socket /run/tacy/agent/gateway.sock --agent-uid 10003 --vault-socket /run/tacy/vault/vault.sock \
//	    --listen :8080 --forward /run/tacy/agent/http.sock
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"io"
	"log"
	"net"
	"os"
	"runtime/debug"
	"slices"
	"sync"
	"time"

	"github.com/tacyhq/tacy/gateway"
	"github.com/tacyhq/tacy/guard"
	"github.com/tacyhq/tacy/internal/procinfo"
	"github.com/tacyhq/tacy/internal/tinfoil"
	"github.com/tacyhq/tacy/safety"
	"github.com/tacyhq/tacy/vault"
)

func main() {
	socket := flag.String("socket", "", "gateway/v0 unix socket agentd connects to")
	agentUID := flag.Int("agent-uid", -1, "the only uid allowed to connect to -socket (agentd's); -1: no check")
	vaultSocket := flag.String("vault-socket", "", "vaultd's unix socket")
	listen := flag.String("listen", "", "TCP address of the published port to forward to -forward (empty: none)")
	forward := flag.String("forward", "", "agentd's HTTP unix socket")
	memLimit := flag.Int("mem-limit-mib", 900, "Go soft memory limit (GOMEMLIMIT), MiB; 0 = none")
	safetyURL := flag.String("safety-url", "", "https URL to pull the signed stop lists and policies from (empty: agentd's pushes only)")
	safetyEvery := flag.Duration("safety-every", 10*time.Second, "how often to pull -safety-url (and -keylog-url)")
	keylogURL := flag.String("keylog-url", "", "https URL to pull the firm key log from (a JSON array of entries; empty: POST /keylog only)")
	// Test only: cmd/e2e's overlay is the only thing that sets it (a release compose never does, and the attested
	// compose hash covers the command line, so the verifier would see another compose).
	modelFault := flag.String("e2e-model-fault", "", "e2e test only: <model>=slow|overloaded,... makes calls to those models slow (no byte before the slow threshold) or answer 503 overloaded")
	var sf safety.Flags
	sf.Register(flag.CommandLine)
	flag.Parse()
	log.Printf("gatewayd: %s", procinfo.Line())
	if *socket == "" || *vaultSocket == "" {
		log.Fatal("gatewayd: --socket and --vault-socket are required")
	}
	if (*listen == "") != (*forward == "") {
		log.Fatal("gatewayd: --listen and --forward go together")
	}
	if *memLimit > 0 {
		debug.SetMemoryLimit(int64(*memLimit) << 20)
	}

	// The vault says which keys are set (names, never values): the search provider depends on it.
	vc := &vault.Client{Path: *vaultSocket}
	var names []string
	for start := time.Now(); ; {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		n, err := vc.Names(ctx)
		cancel()
		if err == nil {
			names = n
			break
		}
		if time.Since(start) > 10*time.Minute {
			log.Fatalf("gatewayd: vault: %v", err)
		}
		time.Sleep(time.Second)
	}
	// Step 6: gatewayd checks the signed controls itself (memory only: agentd, which keeps the floors on disk,
	// sends its documents with every session and every 10 s; the vault gets what gatewayd takes).
	scfg, err := sf.Config(guard.ReleasePolicy(sf.Firm, os.Getenv("TINFOIL_ENCLAVE")), "")
	if err != nil {
		log.Fatal(err)
	}
	st, err := safety.NewState(scfg)
	if err != nil {
		log.Fatal(err)
	}
	toVault := vaultPusher(vc, st)
	lease := guard.RecordLeases(retryLease(guard.VaultLease(vc), toVault)) // every decision goes on the activity record
	tc := tinfoil.NewClient(os.Getenv("TINFOIL_ENCLAVE"), "")
	faults, err := guard.ParseModelFaults(*modelFault)
	if err != nil {
		log.Fatalf("gatewayd: -e2e-model-fault: %v", err)
	}
	if len(faults) > 0 {
		log.Printf("gatewayd: E2E TEST MODEL FAULTS ON (never in a release): %v", faults)
	}
	search := guard.NewSearch(os.Getenv("SEARCH_PROVIDER"), func(n string) bool { return slices.Contains(names, n) }, lease)
	fetcher := guard.NewFetcher(false)
	lim := guard.DefaultLimits
	var logMu sync.Mutex
	enc := json.NewEncoder(os.Stdout)
	// The quarantined reader (docs/27 section 5): pages and search results reach the acting model only as the
	// reader's fields and quote references.
	reader := guard.DefaultReader
	g := guard.New(guard.Config{Up: guard.WithModelFaults(guard.NewTinfoilUpstream(tc, lease), faults), Search: search, Fetcher: fetcher, Reader: &reader,
		Icons: fetcher, Limits: &lim, CacheSecret: randomHex(32), Now: func() time.Time { return time.Now().UTC() }, Safety: st,
		Record: func(e guard.Egress) { // metadata only: ids, operation, decision, pattern ids
			logMu.Lock()
			defer logMu.Unlock()
			enc.Encode(struct {
				Egress guard.Egress `json:"egress"`
			}{e})
		}})

	// Verify Tinfoil's router now, so the first request doesn't wait for it.
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		if _, _, err := tc.Current(ctx); err != nil {
			log.Printf("tinfoil verification failed (will retry on first request): %v", err)
			return
		}
		log.Printf("tinfoil router verified")
	}()

	l, err := gateway.Listen(*socket, 0o660)
	if err != nil {
		log.Fatalf("gatewayd: %v", err)
	}
	if *listen != "" {
		go forwardPort(*listen, *forward)
	}
	log.Printf("gatewayd %s on %s (search %s, keys set %v, forwarding %s to %s)", gateway.Version, *socket,
		search.Name(), names, *listen, *forward)
	go func() { // the vault gets gatewayd's documents on every change and every 10 s (a restarted vault starts empty)
		for {
			toVault()
			ch := st.Changed()
			select {
			case <-ch:
				s := st.StatusOf("") // the firm's; hashes and numbers only
				log.Printf("safety: controls now policy %v, operator seq %d, firm seq %d, fresh %v, stopped %q", s.Policy,
					s.OperatorSeq, s.FirmSeq, s.Fresh, s.Stopped)
			case <-time.After(10 * time.Second):
			}
		}
	}()
	if *safetyURL != "" || *keylogURL != "" {
		if *forward == "" {
			log.Fatal("gatewayd: -safety-url and -keylog-url need -forward (what is pulled goes to agentd)")
		}
		if *keylogURL != "" && sf.Genesis == "" {
			log.Fatal("gatewayd: -keylog-url without -keylog-genesis")
		}
		go pullSafety(*safetyURL, *keylogURL, *safetyEvery, *forward)
	}
	log.Fatal((&gateway.Server{G: g, Safety: st}).Serve(l, *agentUID))
}

// forwardPort copies each inbound connection on addr to and from agentd's HTTP socket. The bytes aren't read:
// /run bodies are EHBP-encrypted to agentd's key; headers (the relay's bearer token, the model) pass through.
func forwardPort(addr, to string) {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("gatewayd: listen %s: %v", addr, err)
	}
	for {
		c, err := l.Accept()
		if err != nil {
			log.Printf("gatewayd: accept: %v", err)
			time.Sleep(100 * time.Millisecond)
			continue
		}
		go func() {
			defer c.Close()
			a, err := net.DialTimeout("unix", to, 5*time.Second)
			if err != nil {
				return // agentd isn't up: the client sees the connection close
			}
			defer a.Close()
			done := make(chan struct{}, 2)
			go func() { io.Copy(a, c); a.(*net.UnixConn).CloseWrite(); done <- struct{}{} }()
			go func() { io.Copy(c, a); c.(*net.TCPConn).CloseWrite(); done <- struct{}{} }()
			<-done
			<-done
		}()
	}
}

func randomHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}
