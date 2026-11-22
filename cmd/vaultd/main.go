// vaultd is the agent VM's vault (../../vault, docs/21-gateway-v0.md): it holds the chat agent's secrets in
// memory and answers gatewayd's lease requests on a unix socket: one secret per call, for a granted connector and
// exact host, to gatewayd's uid only. The secrets never come from the environment (Phala's encrypted env is under
// Phala's keys: "Keys: never a provider's") and never from the chat Worker: vaultd asks unlockd for its own
// keys (conn/v1 and our API keys from the epoch's secrets bundle, the keys plan §11.2) over its own socket, which serves
// vaultd's role only. Until they arrive nothing is leased and agentd answers "starting".
//
// People's email connections (the connections contract) are kept as the "connections" sealed state under conn/v1,
// stored at the chat Worker (ciphertext only, its sealed-state API, signed with the store-auth key the KMS id
// certified). The Worker's compare-and-set on the generation (D1) is the only register: a second writer's save
// conflicts and that vaultd stops (fail closed).
//
// It has no network (its container's network_mode is none) and no dstack socket (only unlockd makes quotes).
// Records (names, ids and decisions, never values) go to stdout as JSON lines.
//
//	go run ./cmd/vaultd --socket /run/tacy/vault/vault.sock --gateway-uid 10001 --group-mode \
//	    --unlock-socket /run/tacy/unlockv/vaultd.sock --ops-socket /run/tacy/ops/gateway.sock
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

	"github.com/tacyhq/tacy/gateway"
	"github.com/tacyhq/tacy/internal/procinfo"
	"github.com/tacyhq/tacy/safety"
	"github.com/tacyhq/tacy/sealstate"
	"github.com/tacyhq/tacy/unlock"
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
	unlockSocket := flag.String("unlock-socket", "", "unlockd's socket for vaultd: conn/v1 and the API keys come from it")
	opsSocket := flag.String("ops-socket", "", "gatewayd's ops socket: the sealed-state API is reached through it")
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
	case *unlockSocket != "":
		if *opsSocket == "" {
			log.Fatal("vault: -unlock-socket needs -ops-socket (vaultd has no network: gatewayd carries its sealed state)")
		}
		go fromUnlockd(v, &unlock.Client{Path: *unlockSocket}, &gateway.Client{Path: *opsSocket})
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
	log.Printf("vaultd on %s (keys from unlockd %v)", *socket, *unlockSocket != "")
	log.Fatal(v.Serve(l, *uid))
}

// fromUnlockd is vaultd's boot: its keys from unlockd (conn/v1 and the API keys; it waits while unlockd unlocks),
// then the connections' sealed state (v1: kept empty). A failure after the keys is fatal: the container restarts
// and asks unlockd again (which serves the same keys from its memory), and nothing is leased meanwhile.
func fromUnlockd(v *vault.Vault, uc *unlock.Client, gw *gateway.Client) {
	ctx := context.Background()
	k, err := uc.Wait(ctx, log.Printf, connPurpose)
	if err != nil {
		log.Fatalf("vaultd: unlockd: %v", err)
	}
	if r, err := v.SetSecrets(k.Secrets); err != nil {
		log.Fatalf("vaultd: the API keys: %v", err)
	} else {
		log.Printf("vaultd: API keys from unlockd: %v", r.Names)
	}
	auth, err := k.StoreAuth(connPurpose, nil)
	if err != nil {
		log.Fatalf("vaultd: %v", err)
	}
	ck, err := k.Key(ctx, connPurpose)
	if err != nil {
		log.Fatalf("vaultd: %v", err)
	}
	backend := &sealstate.Relay{Base: "https://state", Client: gateway.StateHTTP{D: gw}, Auth: auth}
	p, keeper, err := vault.SealedConns(ctx, backend, ck, k.App, nil) // the Worker's compare-and-set is the register
	clear(ck)
	if err != nil {
		log.Fatalf("vaultd: %v", err)
	}
	if err := v.EnableConns(p); err != nil {
		log.Fatalf("vaultd: connections: %v", err)
	}
	// v1 (the v1 design §5): no login is kept; each task's comes sealed with it and stays in this process's memory.
	// The state stays, empty; what an older release kept there was wiped just now (a count only).
	log.Printf("vaultd: connections on (per-task logins in memory only; %d kept accounts wiped)", v.Wiped())
	// Another VM holds the connections now (a conflict at the Worker): stop.
	keeper.OnFatal = func(err error) { log.Fatalf("vaultd: connections: %v", err) }
	kctx, stop := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { keeper.Run(kctx); close(done) }()
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	<-sig
	stop()
	<-done // the last save
	os.Exit(0)
}
