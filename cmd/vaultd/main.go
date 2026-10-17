// vaultd is the agent VM's vault (../../vault, docs/21-gateway-v0.md): it takes the chat agent's secrets
// (dstack's encrypted env vars, given only to its container) out of its environment, then answers gatewayd's lease
// requests on a unix socket: one secret per call, for a granted connector and exact host, to gatewayd's uid only.
// It has no network (its container's network_mode is none). Records (names, ids and decisions, never values) go to
// stdout as JSON lines.
//
//	go run ./cmd/vaultd --socket /run/tacy/vault/vault.sock --gateway-uid 10001 --group-mode
package main

import (
	"encoding/json"
	"flag"
	"log"
	"os"
	"runtime"
	"sync"

	"github.com/tacyhq/tacy/internal/procinfo"
	"github.com/tacyhq/tacy/safety"
	"github.com/tacyhq/tacy/vault"
)

func main() {
	socket := flag.String("socket", "", "the vault's unix socket")
	uid := flag.Int("gateway-uid", -1, "the only uid allowed to connect (required on Linux)")
	group := flag.Bool("group-mode", false, "socket mode 0660: gatewayd connects through the socket's group (vaultd's primary group is gatewayd's)")
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
	grants := vault.ChatGrants(os.Getenv("TINFOIL_ENCLAVE"))
	secrets := vault.FromEnv(grants)
	enc := json.NewEncoder(os.Stdout)
	var mu sync.Mutex // records come from concurrent connections
	v, err := vault.New(secrets, grants, func(r vault.Record) {
		mu.Lock()
		defer mu.Unlock()
		enc.Encode(struct {
			Lease vault.Record `json:"lease"`
		}{r})
	})
	for _, s := range secrets {
		clear(s)
	}
	if err != nil {
		log.Fatal(err)
	}
	// Step 6: the vault checks the signed controls itself (memory only; gatewayd passes them on).
	scfg, err := sf.Config(safety.ChatRelease(sf.Firm, os.Getenv("TINFOIL_ENCLAVE"), nil, 300), "")
	if err != nil {
		log.Fatal(err)
	}
	st, err := safety.NewState(scfg)
	if err != nil {
		log.Fatal(err)
	}
	v.SetSafety(st)
	mode := os.FileMode(0o600)
	if *group {
		mode = 0o660
	}
	l, err := vault.ListenMode(*socket, mode)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("vaultd on %s (secrets set %v)", *socket, v.Names())
	log.Fatal(v.Serve(l, *uid))
}
