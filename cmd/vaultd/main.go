// vaultd is the agent VM's vault (../../vault, docs/21-gateway-v0.md): it holds the chat agent's secrets in
// memory and answers gatewayd's lease requests on a unix socket: one secret per call, for a granted connector and
// exact host, to gatewayd's uid only. The secrets never come from the environment (Phala's encrypted env is under
// Phala's keys: "Keys: never a provider's"): the chat Worker verifies the VM and pushes them sealed to
// this boot's key, signed by the operator key the compose pins (vault/secrets.go); until then nothing is leased.
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
	conns := flag.Bool("conns", false, "connections (email accounts), memory only; off until sealed state under the Tacy key service (the keys plan Stage D)")
	connWipe := flag.String("conn-wipe", "", "at start, overwrite with zeros and remove this connections file a release before the keys plan kept on the disk")
	secretsSigner := flag.String("secrets-signer", "", "the only key (ed25519:<base64>) whose secrets pushes are taken; empty: -operator-key's")
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
	// The secrets push: only boxes signed by -secrets-signer, or else the operator key the compose pins for the
	// heartbeat (both are the chat Worker's).
	signer := scfg.Operator
	if *secretsSigner != "" {
		if signer, err = safety.ParseKey(*secretsSigner); err != nil {
			log.Fatalf("vault: -secrets-signer: %v", err)
		}
	}
	if signer != nil {
		if err := v.EnableSecretsPush(signer); err != nil {
			log.Fatal(err)
		}
	} else {
		log.Printf("vaultd: no -secrets-signer or -operator-key: secrets pushes are refused")
	}
	// A connections file an older release kept on the disk goes first, whatever else happens.
	if *connWipe != "" {
		n, err := vault.WipeConnFile(*connWipe)
		log.Printf("vaultd: wiped %d stored connection files (err %v)", n, err)
	}
	// Connections (the connections contract, v0.19.0): a per-boot seal key, memory only. Off in the quick path: email
	// comes back with sealed state (the keys plan Stage D).
	if *conns {
		if err := v.EnableConns(""); err != nil {
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
	log.Printf("vaultd on %s (secrets set %v)", *socket, v.Names())
	log.Fatal(v.Serve(l, *uid))
}
