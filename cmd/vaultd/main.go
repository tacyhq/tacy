// vaultd is the agent VM's vault (../../vault, docs/21-gateway-v0.md): it holds the chat agent's secrets in
// memory and answers gatewayd's lease requests on a unix socket: one secret per call, for a granted connector and
// exact host, to gatewayd's uid only. The secrets never come from the environment (Phala's encrypted env is under
// Phala's keys: "Keys: never a provider's") and never from the chat Worker: vaultd asks the Tacy key
// service for its own release (conn/v1 and the app's API keys from the admin-signed secrets bundle) with a fresh
// attestation, through gatewayd's ops socket (the keys plan §2.4, §3.6); the reply is signed by the KMS id the compose pins
// (-kms-key) and sealed to this boot's key. Until it arrives nothing is leased and agentd answers "starting".
//
// People's email connections (the connections contract) are kept as the "connections" sealed state under conn/v1,
// stored at the chat Worker (ciphertext only, its sealed-state API, signed with the store-auth key the KMS id
// certified), with the key service's generation register: a fresh CVM, a new app id or a new instance finds them
// again, and nothing about them is on the provider's disk (the keys plan Stage D).
//
// It has no network (its container's network_mode is none). Records (names, ids and decisions, never values) go to
// stdout as JSON lines.
//
// vaultd has dstack's socket for its own quote (GetQuote and Info, never GetKey), so it could make a quote for any
// report_data; what it may ask the key service for is held by gatewayd, its only way out: the ops socket passes a
// release of conn/v1 for holder vaultd and nothing else (gateway.KMSGate).
//
//	go run ./cmd/vaultd --socket /run/tacy/vault/vault.sock --gateway-uid 10001 --group-mode \
//	    --kms-key ed25519:… --kms-hosts 3 --ops-socket /run/tacy/ops/gateway.sock
package main

import (
	"context"
	"encoding/json"
	"flag"
	"log"
	"os"
	"os/signal"
	"runtime"
	"sync"
	"syscall"
	"time"

	"github.com/tacyhq/tacy/gateway"
	"github.com/tacyhq/tacy/internal/dstackev"
	"github.com/tacyhq/tacy/internal/procinfo"
	"github.com/tacyhq/tacy/kms"
	"github.com/tacyhq/tacy/kms/client"
	"github.com/tacyhq/tacy/kmsvm"
	"github.com/tacyhq/tacy/safety"
	"github.com/tacyhq/tacy/sealstate"
	"github.com/tacyhq/tacy/vault"
)

// connPurpose is vaultd's only key purpose.
const connPurpose = "conn/v1"

func main() {
	socket := flag.String("socket", "", "the vault's unix socket")
	uid := flag.Int("gateway-uid", -1, "the only uid allowed to connect (required on Linux)")
	group := flag.Bool("group-mode", false, "socket mode 0660: gatewayd connects through the socket's group (vaultd's primary group is gatewayd's)")
	conns := flag.Bool("conns", false, "without -kms-key (local only): connections in memory")
	connWipe := flag.String("conn-wipe", "", "at start, overwrite with zeros and remove this connections file a release before the keys plan kept on the disk")
	kmsKey := flag.String("kms-key", "", "the Tacy key service's id, ed25519:<base64> (the compose pins it): vaultd's API keys and conn/v1 come from it")
	kmsHosts := flag.Int("kms-hosts", 1, "how many key service replicas gatewayd knows (its -kms-url, in order)")
	opsSocket := flag.String("ops-socket", "", "gatewayd's ops socket: the key service and the sealed-state API are reached through it")
	dstackSock := flag.String("dstack-sock", "/var/run/dstack.sock", "dstack guest agent socket (GetQuote and Info only)")
	platform := flag.String("platform", "dstack", "dstack | local (a development key service only)")
	var sf safety.Flags
	sf.Register(flag.CommandLine)
	flag.Parse()
	log.Printf("vaultd: %s", procinfo.Line())
	if *socket == "" {
		log.Fatal("vault: --socket is required")
	}
	if *uid < 0 && runtime.GOOS == "linux" {
		log.Fatal("vault: --gateway-uid is required on Linux")
	}
	grants := vault.ChatGrants("")
	enc := json.NewEncoder(os.Stdout)
	var mu sync.Mutex // records come from concurrent connections
	v, err := vault.New(nil, grants, func(r vault.Record) {
		mu.Lock()
		defer mu.Unlock()
		enc.Encode(struct {
			Lease vault.Record `json:"lease"`
		}{r})
	})
	if err != nil {
		log.Fatal(err)
	}
	// Step 6: the vault checks the signed controls itself (memory only; gatewayd passes them on).
	scfg, err := sf.Config(safety.ChatRelease(sf.Firm, "", nil, 300), "")
	if err != nil {
		log.Fatal(err)
	}
	st, err := safety.NewState(scfg)
	if err != nil {
		log.Fatal(err)
	}
	v.SetSafety(st)
	// The stored email logins of v0.19.x (plaintext on the Phala-keyed disk) go first, whatever else happens.
	if *connWipe != "" {
		n, err := vault.WipeConnFile(*connWipe)
		log.Printf("vaultd: wiped %d stored connection files (err %v)", n, err)
	}
	switch {
	case *kmsKey != "":
		id, err := kms.ParseID(*kmsKey)
		if err != nil {
			log.Fatalf("vault: -kms-key: %v", err)
		}
		if *opsSocket == "" {
			log.Fatal("vault: -kms-key needs -ops-socket (vaultd has no network: gatewayd carries its calls)")
		}
		ev := client.Evidence(dstackev.New(*dstackSock).Evidence)
		if *platform == "local" {
			host, _ := os.Hostname()
			ev = kmsvm.LocalEvidence("local-" + host)
		} else if *platform != "dstack" {
			log.Fatalf("vault: unknown -platform %q", *platform)
		}
		go fromKeyService(v, id, *kmsHosts, &gateway.Client{Path: *opsSocket}, ev, *platform)
	case *conns:
		// Local runs only (the compose always names a key service): connections in this process's memory.
		if err := v.EnableConns(nil); err != nil {
			log.Printf("vaultd: connections off: %v", err)
		}
	}
	mode := os.FileMode(0o600)
	if *group {
		mode = 0o660
	}
	l, err := vault.ListenMode(*socket, mode)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("vaultd on %s (key service %v)", *socket, *kmsKey != "")
	log.Fatal(v.Serve(l, *uid))
}

// fromKeyService is vaultd's boot with the key service: its release (the API keys and conn/v1), then the people's
// connections from their sealed state. A failure here is fatal: the container restarts and tries again, and
// nothing is leased meanwhile.
func fromKeyService(v *vault.Vault, id []byte, hosts int, gw *gateway.Client, ev client.Evidence, platform string) {
	ctx := context.Background()
	k, err := kmsvm.Boot(ctx, kmsvm.Config{KMSID: id, Hosts: hosts, Platform: platform, Purposes: []string{connPurpose}, Holder: "vaultd",
		Transport: func(h int) client.Transport { return gateway.KMSTransport{D: gw, Host: h} }, Evidence: ev})
	if err != nil {
		log.Fatalf("vaultd: key service: %v", err)
	}
	go k.Renew(ctx, 0)
	if r, err := v.SetSecrets(k.Secrets()); err != nil {
		log.Fatalf("vaultd: the key service's secrets: %v", err)
	} else {
		log.Printf("vaultd: API keys from the key service: %v", r.Names)
	}
	auth, err := k.StoreAuth(connPurpose)
	if err != nil {
		log.Fatalf("vaultd: %v", err)
	}
	ck, err := k.Key(ctx, connPurpose)
	if err != nil {
		log.Fatalf("vaultd: %v", err)
	}
	backend := &sealstate.Relay{Base: "https://state", Client: gateway.StateHTTP{D: gw}, Auth: auth}
	p, keeper, err := vault.SealedConns(ctx, backend, ck, k.App(), k.Register(connPurpose))
	clear(ck)
	if err != nil {
		log.Fatalf("vaultd: %v", err)
	}
	if err := v.EnableConns(p); err != nil {
		log.Fatalf("vaultd: connections: %v", err)
	}
	log.Printf("vaultd: connections on (sealed under the key service's conn/v1, stored at the chat Worker)")
	// Another instance holds the connections now (a refused reservation, a conflict at the Worker): stop.
	keeper.OnFatal = func(err error) { log.Fatalf("vaultd: connections: %v", err) }
	kctx, stop := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { keeper.Run(kctx); close(done) }()
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	<-sig
	stop()
	<-done // the last save, then vaultd's own lease goes (the next boot takes it at once)
	dctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	if err := k.Drop(dctx); err != nil {
		log.Printf("vaultd: lease drop: %v (the next boot waits for it to expire)", err)
	}
	cancel()
	os.Exit(0)
}
