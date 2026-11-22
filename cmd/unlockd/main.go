// unlockd is the agent VM's split-key unlock (the keys plan §11.2, ../../unlock): at a real boot it rebuilds the root key
// from t of the holders the newest signed unlock policy names (each checks this VM's TDX quote, its own nonce and the
// admin's policy, then seals its share to the quote's key), derives agentd's and vaultd's keys, opens our API keys
// (secrets.sealed from the chat Worker), drops the root key, and serves each process its own keys over its own
// socket. Its keyring stays in a host tmpfs only it mounts (TD memory), so dstack's watchdog restarts (about hourly)
// don't unlock again; a reboot does.
//
// It is the only process with dstack's socket: it makes agentd's quotes too, under agentd's own report_data label
// (proto.VersionAgent), so no other process can make an attestation a holder would answer. It has no network: its
// calls to the holders and the Worker go through gatewayd (-gateway-socket, gatewayd's unlock socket: the unlock
// target and the Worker's unlock routes only, gateway.UnlockCalls).
//
//	go run ./cmd/unlockd -kms-key ed25519:… -gateway-socket /run/tacy/unlockgw/gateway.sock \
//	    -agent-socket /run/tacy/unlock/agentd.sock -agent-uid 10003 -vault-socket /run/tacy/unlockv/vaultd.sock \
//	    -vault-uid 10002 -cache-dir /run/tacy-unlock
package main

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"runtime"
	"strings"

	"github.com/tacyhq/tacy/gateway"
	"github.com/tacyhq/tacy/internal/dstackev"
	"github.com/tacyhq/tacy/internal/procinfo"
	"github.com/tacyhq/tacy/kms"
	"github.com/tacyhq/tacy/kms/client"
	"github.com/tacyhq/tacy/kmsvm"
	"github.com/tacyhq/tacy/unlock"
)

func main() {
	kmsKey := flag.String("kms-key", "", "the pinned KMS id, ed25519:<base64> (the compose pins it): share sets and epoch certificates must be signed by it")
	adminKeys := flag.String("unlock-admin-keys", "", "the admin keys, comma-separated ed25519:<base64> (the compose pins them): the unlock policy must carry their signatures")
	adminThreshold := flag.Int("unlock-admin-threshold", 1, "admin signatures the unlock policy needs")
	minEpoch := flag.Uint("min-epoch", 1, "the lowest epoch unlockd takes (raised by the release after a re-split)")
	gwSocket := flag.String("gateway-socket", "", "gatewayd's unlock socket (the holders and the Worker's unlock routes)")
	agentSocket := flag.String("agent-socket", "", "agentd's socket (its keys and its quotes)")
	agentUID := flag.Int("agent-uid", -1, "the only uid allowed on -agent-socket (required on Linux)")
	vaultSocket := flag.String("vault-socket", "", "vaultd's socket (conn/v1 and the API keys)")
	vaultUID := flag.Int("vault-uid", -1, "the only uid allowed on -vault-socket (required on Linux)")
	dstackSock := flag.String("dstack-sock", "/var/run/dstack.sock", "dstack guest agent socket (GetQuote and Info only)")
	cacheDir := flag.String("cache-dir", "", "the host tmpfs the keyring survives container restarts in (dstack: "+verifierCacheDir+"; empty: none)")
	keyMode := keyModeFlag(flag.CommandLine)
	release := flag.String("release", "", "this VM's release (vX.Y.Z), sent to the holders as a claim")
	platform := flag.String("platform", "dstack", "dstack | local (a development VM: -dev-seed, no holders)")
	devSeed := flag.String("dev-seed", "", "-platform local only: 64 hex, the development root key (nothing attested, never a holder's)")
	devSecrets := flag.String("dev-secrets-file", "", "-platform local only: a JSON object of API keys (the dev keys) vaultd gets")
	flag.Parse()
	log.Printf("unlockd: %s", procinfo.Line())
	id, err := kms.ParseID(*kmsKey)
	if err != nil {
		log.Fatalf("unlockd: -kms-key: %v", err)
	}
	if *gwSocket == "" || *agentSocket == "" || *vaultSocket == "" {
		log.Fatal("unlockd: -gateway-socket, -agent-socket and -vault-socket are required")
	}
	if runtime.GOOS == "linux" && (*agentUID < 0 || *vaultUID < 0) {
		log.Fatal("unlockd: -agent-uid and -vault-uid are required on Linux")
	}
	cfg := unlock.Config{KMSID: id, Fixed: &gateway.Client{Path: *gwSocket}, Platform: *platform, Release: *release, MinEpoch: uint32(*minEpoch)}
	if *adminKeys != "" {
		a := &kms.AdminKeys{Threshold: *adminThreshold}
		for _, s := range strings.Split(*adminKeys, ",") {
			k, err := kms.ParseID(s)
			if err != nil {
				log.Fatalf("unlockd: -unlock-admin-keys: %v", err)
			}
			a.Keys = append(a.Keys, k)
		}
		cfg.Admin = a
	} else if *platform == "dstack" {
		log.Fatal("unlockd: -unlock-admin-keys is required on dstack")
	}
	var ev client.Evidence
	switch *platform {
	case "dstack":
		if *devSeed != "" || *devSecrets != "" {
			log.Fatal("unlockd: -dev-* flags are for -platform local only")
		}
		if *cacheDir == "" {
			log.Fatal("unlockd: -cache-dir is required on dstack (the memory-root marker is there)")
		}
		ev = dstackev.New(*dstackSock).Evidence
		if cfg.RequireMemoryRoot, err = requireMemoryRoot(*keyMode); err != nil {
			log.Fatalf("unlockd: %v", err)
		}
	case "local":
		host, _ := os.Hostname()
		ev = kmsvm.LocalEvidence("local-" + host)
		seed, err := hex.DecodeString(*devSeed)
		if err != nil || len(seed) != kms.MasterSize {
			log.Fatal("unlockd: -platform local needs -dev-seed <64 hex>")
		}
		var secrets map[string]string
		if *devSecrets != "" {
			b, err := os.ReadFile(*devSecrets)
			if err != nil || json.Unmarshal(b, &secrets) != nil {
				log.Fatalf("unlockd: -dev-secrets-file: %v", err)
			}
		}
		cfg.DevRoot = func() (unlock.Root, unlock.Grant, error) { return unlock.DevRoot(seed, secrets) }
	default:
		log.Fatalf("unlockd: unknown -platform %q", *platform)
	}
	cfg.Evidence = ev
	if *cacheDir != "" {
		cfg.Cache = &unlock.Cache{Dir: *cacheDir}
	}
	u, err := unlock.New(cfg)
	if err != nil {
		log.Fatal(err)
	}
	s := &unlock.Server{U: u, Evidence: ev, Platform: *platform}
	serve := func(path string, uid int, role string) {
		l, err := gateway.Listen(path, 0o660)
		if err != nil {
			log.Fatalf("unlockd: %v", err)
		}
		log.Fatal(s.Serve(l, uid, role))
	}
	// The sockets first: agentd's quotes don't wait for the keys, and both peers learn the state while it unlocks.
	go serve(*agentSocket, *agentUID, unlock.RoleAgent)
	go serve(*vaultSocket, *vaultUID, unlock.RoleVault)
	log.Printf("unlockd: KMS id %s, platform %s, cache %q", kms.IDString(ed25519.PublicKey(id)), *platform, *cacheDir)
	if err := u.Run(context.Background()); err != nil {
		log.Fatalf("unlockd: %v", err)
	}
	select {}
}

// defaultKeyMode is -key-mode's default: the KMS fallback's, the strict one (wait for the memory-root marker). A KMS
// fallback compose must omit the flag (verifier.UnlockdRules), so a default of "none" would let such a VM unlock
// with its images on the provider-keyed disk.
const defaultKeyMode = "kms"

// keyModeFlag registers -key-mode on fs.
func keyModeFlag(fs *flag.FlagSet) *string {
	return fs.String("key-mode", defaultKeyMode, "the VM's disk key: kms (the KMS fallback: unlock only once the memory-root pre-launch script's marker is this boot's) or none (key_provider none: the disk key is made in the TD at boot, no script, no marker)")
}

// requireMemoryRoot is unlock.Config.RequireMemoryRoot for a -key-mode on dstack: kms waits for the memory-root
// marker; none doesn't (the data disk is under a key made in this TD, dstack key_provider none, so the images on it
// can't be edited into a binary of someone else's choosing, and there is no script to wait for). Anything else is
// refused: unlockd doesn't start.
func requireMemoryRoot(mode string) (bool, error) {
	switch mode {
	case "kms":
		return true, nil
	case "none":
		return false, nil
	default:
		return false, fmt.Errorf("-key-mode %q (kms or none)", mode)
	}
}

// verifierCacheDir is verifier.UnlockCacheDir (not imported: unlockd doesn't link the verifier).
const verifierCacheDir = "/run/tacy-unlock"
