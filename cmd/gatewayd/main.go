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
	"net/http"
	"os"
	"path/filepath"
	"runtime/debug"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/tacyhq/tacy/gateway"
	"github.com/tacyhq/tacy/gateway/cftunnel"
	"github.com/tacyhq/tacy/guard"
	"github.com/tacyhq/tacy/internal/procinfo"
	"github.com/tacyhq/tacy/internal/tinfoil"
	"github.com/tacyhq/tacy/kms"
	"github.com/tacyhq/tacy/safety"
	"github.com/tacyhq/tacy/vault"
)

func main() {
	// The confinement probe (gateway/cftunnel): run by gatewayd's launcher as cloudflared's uid, before anything else.
	if len(os.Args) == 3 && os.Args[1] == cftunnel.ProbeArg {
		cftunnel.RunProbe(os.Args[2])
	}
	if len(os.Args) == 3 && os.Args[1] == cftunnel.Vsock32Arg { // the probe's 32-bit child (gateway/cftunnel seccomp.go)
		cftunnel.RunVsock32(os.Args[2])
	}
	if len(os.Args) == 2 && os.Args[1] == cftunnel.ReapArg { // the reaper, as cloudflared's uid (review 2, L1)
		cftunnel.RunReap()
	}
	socket := flag.String("socket", "", "gateway/v0 unix socket agentd connects to")
	agentUID := flag.Int("agent-uid", -1, "the only uid allowed to connect to -socket (agentd's); -1: no check")
	vaultSocket := flag.String("vault-socket", "", "vaultd's unix socket")
	listen := flag.String("listen", "", "TCP address of the published port to forward to -forward (empty: none)")
	forward := flag.String("forward", "", "agentd's HTTP unix socket")
	// The tunnel (gateway/cftunnel): the compose pins all of these.
	cfdBin := flag.String("cloudflared", "", "run this cloudflared (started by the launcher as -tunnel-uid), its only origin gatewayd's ingress socket (forwarding to -forward)")
	cfdSHA := flag.String("cloudflared-sha256", "", "the cloudflared binary's pinned sha256")
	cfdConfig := flag.String("cloudflared-config", "", "spike and development composes: cloudflared's locally-managed config, a file in the image (in place of -cloudflared-access)")
	cfdAccess := flag.String("cloudflared-access", "", "the Access app cloudflared checks the JWT of, team,aud: the launcher hands cloudflared the locally-managed config (cftunnel.Config) in a memfd; the release pins it (in place of -cloudflared-config)")
	e2eDiag := flag.String(cftunnel.DiagFlag, "", "e2e test only: the overlay's diag service (http://<service>:<port>) on the tunnel's ingress at "+cftunnel.DiagPrefix+" (the verifier refuses the flag in every compose but an e2e overlay's)")
	tunnelSecret := flag.String("tunnel-secret", "", "the vault secret name of the tunnel token (leased for each start)")
	tunnelConfined := flag.String("tunnel-confined", "", "spike, confined variant: the volume shared with the cftunnel container (ingress socket and token file)")
	tunnelConfinedGID := flag.Int("tunnel-confined-gid", 10006, "spike, confined variant: cloudflared's gid (it may connect and read the token)")
	tunnelSpike := flag.Bool("tunnel-spike-routes", false, "spike: the /spike/* test routes on the ingress socket (throwaways only)")
	tunnelUID := flag.Int("tunnel-uid", 0, "cloudflared's uid and gid: gatewayd's container starts as root with SETUID and SETGID only, and its launcher starts gatewayd as -gatewayd-uid and cloudflared as this uid (gateway/cftunnel launch_linux.go; needed for -cloudflared)")
	gatewaydUID := flag.Int("gatewayd-uid", cftunnel.GatewaydUID, "with -tunnel-uid: the uid and gid the launcher starts gatewayd as")
	memLimit := flag.Int("mem-limit-mib", 900, "Go soft memory limit (GOMEMLIMIT), MiB; 0 = none")
	safetyURL := flag.String("safety-url", "", "https URL to pull the signed stop lists and policies from (empty: agentd's pushes only)")
	safetyEvery := flag.Duration("safety-every", 10*time.Second, "how often to pull -safety-url (and -keylog-url)")
	keylogURL := flag.String("keylog-url", "", "https URL to pull the firm key log from (a JSON array of entries; empty: POST /keylog only)")
	// Test only: cmd/e2e's overlay is the only thing that sets it (a release compose never does, and the attested
	// compose hash covers the command line, so the verifier would see another compose).
	modelFault := flag.String("e2e-model-fault", "", "e2e test only: <model>=slow|overloaded,... makes calls to those models slow (no byte before the slow threshold) or answer 503 overloaded")
	searchProvider := flag.String("search-provider", "", "exa | tavily | brave (empty: by the keys set)")
	expectedKeys := flag.String("expected-keys", "", "comma-separated names of the keys vaultd gets from the key service after boot (vault/secrets.go): the search provider is chosen as if they were set")
	stateURL := flag.String("state-url", "", "the chat Worker's https base URL: its sealed-state API for agentd and vaultd, the unlock policy and secrets.sealed for unlockd (gateway/fixed.go)")
	opsSocket := flag.String("ops-socket", "", "a unix socket for vaultd's fixed calls (and nothing else)")
	vaultUID := flag.Int("vault-uid", -1, "the only uid allowed to connect to -ops-socket (vaultd's); -1: no check")
	kmsKey := flag.String("kms-key", "", "the pinned KMS id, ed25519:<base64>: the unlock policy's share sets must be signed by it (its holders' URLs are unlockd's only hosts)")
	unlockDomain := flag.String("unlock-domain", "", "every holder URL (url and alt_urls) must be https on one of these comma-separated domains or under it (the compose pins it)")
	unlockAdminKeys := flag.String("unlock-admin-keys", "", "the admin keys the unlock policy must be signed by, comma-separated ed25519:<base64> (the compose pins them, as unlockd's)")
	unlockAdminThreshold := flag.Int("unlock-admin-threshold", 1, "how many of -unlock-admin-keys must sign the unlock policy")
	unlockSocket := flag.String("unlock-socket", "", "a unix socket for unlockd's fixed calls (holders, the Worker's unlock routes; nothing else)")
	unlockdUID := flag.Int("unlockd-uid", -1, "the only uid allowed to connect to -unlock-socket (unlockd's); -1: no check")
	devFixedHTTP := flag.Bool("dev-fixed-http", false, "local only: allow http:// fixed hosts (a development key service and Worker)")
	dnsTLS := flag.String("dns-tls", "", "every DNS lookup over TLS to this resolver, <tls name>@<ip>:<port>[,<ip>:<port>] (gateway/dot.go; the compose pins it); empty: the system's resolver (local only)")
	var sf safety.Flags
	sf.Register(flag.CommandLine)
	flag.Parse()
	if flag.NArg() != 0 { // the attested command line is flags only (review 2, M1)
		log.Fatalf("gatewayd: unexpected arguments %q", flag.Args())
	}
	if os.Getuid() == 0 {
		// gatewayd's launcher (review H1): the container's first process, root with SETUID and SETGID only. It starts
		// gatewayd (this binary, these flags) as -gatewayd-uid and cloudflared as -tunnel-uid; it never returns.
		if *tunnelUID <= 0 {
			log.Fatal("gatewayd: never as root, except as the launcher (-tunnel-uid)")
		}
		deny := []string{"/var/run/dstack.sock", "/run/dstack.sock", "/tmp/"}
		for _, p := range []string{*socket, *vaultSocket, *forward, *opsSocket, *unlockSocket} {
			if p != "" {
				deny = append(deny, p, filepath.Dir(p)+"/")
			}
		}
		cfg := cftunnel.LaunchConfig{GatewaydUID: *gatewaydUID, GatewaydGID: *gatewaydUID, TunnelUID: *tunnelUID,
			Bin: *cfdBin, BinSHA256: *cfdSHA, Config: *cfdConfig, Access: *cfdAccess, Deny: deny}
		if *cfdBin != "" {
			cfg.Allow = []string{cftunnel.SocketPath}
		}
		cftunnel.Launch(cfg, os.Args, os.Environ())
	}
	// Non-dumpable before anything is read (review H1): no core, no ptrace, no /proc/<pid>/mem or environ for any uid
	// without CAP_SYS_PTRACE, gatewayd's own included.
	hs, err := cftunnel.Harden()
	if err != nil {
		log.Fatalf("gatewayd: %v", err)
	}
	if hs.Launched && (hs.CapEff != "0000000000000000" || hs.CapPrm != "0000000000000000") {
		log.Fatalf("gatewayd: started by the launcher with capabilities (eff %s, prm %s): refusing", hs.CapEff, hs.CapPrm)
	}
	log.Printf("gatewayd: %s; dumpable %d, ptrace_scope %s, launched %v", procinfo.Line(), hs.Dumpable, hs.YamaPtraceScope, hs.Launched)
	if *dnsTLS != "" { // before anything looks a name up
		d, err := gateway.ParseDoT(*dnsTLS)
		if err != nil {
			log.Fatalf("gatewayd: %v", err)
		}
		gateway.UseDoT(d)
		log.Printf("gatewayd: DNS over TLS to %s (%d addresses)", d.Name, len(d.Addrs))
	}
	if *socket == "" || *vaultSocket == "" {
		log.Fatal("gatewayd: --socket and --vault-socket are required")
	}
	// --forward alone is the cloudflared spike's no-listen form (go-condition 3): the tunnel is the only way in.
	if *listen != "" && *forward == "" || *forward != "" && *listen == "" && *cfdBin == "" && *tunnelConfined == "" {
		log.Fatal("gatewayd: --listen and --forward go together (--forward alone only with the tunnel)")
	}
	if *memLimit > 0 {
		debug.SetMemoryLimit(int64(*memLimit) << 20)
	}
	// The fixed hosts (the chat Worker's sealed-state API and unlock routes, the split key's holders): served first,
	// since every process's keys come through them (the keys plan §11.2). No key service (kmsd): the holders are named by
	// the newest unlock policy, checked against -kms-key, on -unlock-domain only.
	fixed, err := gateway.NewFixed(nil, *stateURL, *devFixedHTTP)
	if err != nil {
		log.Fatalf("gatewayd: %v", err)
	}
	if *unlockSocket != "" {
		id, err := kms.ParseID(*kmsKey)
		if err != nil {
			log.Fatalf("gatewayd: -unlock-socket needs -kms-key: %v", err)
		}
		if *unlockDomain == "" && !*devFixedHTTP {
			log.Fatal("gatewayd: -unlock-socket needs -unlock-domain (the holders are on our domains only)")
		}
		admin, err := safety.ParseKeys(*unlockAdminKeys)
		if (err != nil || len(admin) == 0) && !*devFixedHTTP {
			log.Fatal("gatewayd: -unlock-socket needs -unlock-admin-keys (the unlock policy's signers)")
		}
		fixed.NewUnlockHosts(id, kms.AdminKeys{Keys: admin, Threshold: *unlockAdminThreshold}, *unlockDomain)
		ul, err := gateway.Listen(*unlockSocket, 0o660)
		if err != nil {
			log.Fatalf("gatewayd: %v", err)
		}
		go func() {
			log.Fatal((&gateway.Server{Fixed: gateway.FixedGate{D: fixed, Allow: gateway.UnlockCalls}}).ServeOps(ul, *unlockdUID))
		}()
	}
	if *opsSocket != "" {
		ol, err := gateway.Listen(*opsSocket, 0o660)
		if err != nil {
			log.Fatalf("gatewayd: %v", err)
		}
		go func() {
			log.Fatal((&gateway.Server{Fixed: gateway.FixedGate{D: fixed, Allow: gateway.VaultCalls}}).ServeOps(ol, *vaultUID))
		}()
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
	// The keys arrive by push after boot (none is set yet when this runs): the compose names the ones that will.
	expected := strings.Split(*expectedKeys, ",")
	search := guard.NewSearch(*searchProvider, func(n string) bool { return slices.Contains(names, n) || slices.Contains(expected, n) }, lease)
	fetcher := guard.NewFetcher(false)
	lim := guard.DefaultLimits
	var logMu sync.Mutex
	enc := json.NewEncoder(os.Stdout)
	// The quarantined reader (docs/27 section 5): pages and search results reach the acting model only as the
	// reader's fields and quote references.
	reader := guard.DefaultReader
	g := guard.New(guard.Config{Up: guard.WithModelFaults(guard.NewTinfoilUpstream(tc, lease), faults), Search: search, Fetcher: fetcher, Reader: &reader,
		Icons: fetcher, Limits: &lim, CacheSecret: randomHex(32), Now: func() time.Time { return time.Now().UTC() }, Safety: st,
		Stored: guard.NewStoredConfig(), // the person's stored files (guard/stored.go; the policy must allow files.fetch)
		// The person's own email (guard/mail.go, v0.19.0): connections held by vaultd, each password leased per call to
		// the account's own server; the policy must have the mail connector.
		Mail: &guard.MailConfig{Vault: retryVault{Client: vc, push: toVault}},
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
	if *tunnelConfined != "" {
		if *forward == "" || *tunnelSecret == "" || *cfdBin != "" {
			log.Fatal("gatewayd: -tunnel-confined needs -forward and -tunnel-secret, and no -cloudflared")
		}
		go runConfined(vc, *tunnelConfined, *tunnelConfinedGID, *tunnelSecret, *forward, *tunnelSpike)
	}
	var diag http.Handler
	if *e2eDiag != "" {
		if *cfdBin == "" {
			log.Fatalf("gatewayd: -%s needs -cloudflared (the route is on the tunnel's ingress)", cftunnel.DiagFlag)
		}
		if diag, err = cftunnel.NewDiag(*e2eDiag); err != nil {
			log.Fatalf("gatewayd: %v", err)
		}
		log.Printf("gatewayd: E2E TEST DIAG ROUTE ON at %s (never in a release): %s", cftunnel.DiagPrefix, *e2eDiag)
	}
	if *cfdBin != "" {
		if *forward == "" || (*cfdConfig == "") == (*cfdAccess == "") || *tunnelSecret == "" || *tunnelUID <= 0 {
			log.Fatal("gatewayd: -cloudflared needs -forward, one of -cloudflared-config and -cloudflared-access, -tunnel-secret and -tunnel-uid")
		}
		go runTunnel(vc, *cfdBin, *cfdSHA, *tunnelSecret, *forward, *tunnelUID, hs, *tunnelSpike, diag)
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
	log.Fatal((&gateway.Server{G: g, Safety: st, Secrets: vc.Secrets,
		Fixed: gateway.FixedGate{D: fixed, Allow: gateway.AgentCalls}}).Serve(l, *agentUID))
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

// multiFlag is a repeatable string flag.
type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(s string) error { *m = append(*m, s); return nil }
