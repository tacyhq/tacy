package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/tacyhq/tacy/gateway"
	"github.com/tacyhq/tacy/gateway/cftunnel"
	"github.com/tacyhq/tacy/vault"
)

// runTunnel is the in-container tunnel (gateway/cftunnel): the ingress socket in the tunnel's tmpfs (group
// cloudflared's uid: the one thing it may connect to), and cloudflared started (and started again) by gatewayd's
// launcher as its own uid, with the tunnel token leased from vaultd for each start. The vault has the token only
// after the split-key unlock (the epoch's sealed secrets bundle), so cloudflared starts after it. Each launcher
// probe result goes to cftunnel.ProbeFile (0600, gatewayd's) with gatewayd's own hardening status. diag is the e2e
// overlay's diag route (gatewayd -e2e-diag; nil in every other compose).
func runTunnel(vc *vault.Client, bin, sum, secret, agentSock string, tunnelUID int, hs cftunnel.HardenStatus, spike bool, diag http.Handler) {
	boot := time.Now()
	n := 0
	sup := &cftunnel.Supervisor{Bin: bin, BinSHA256: sum, Logf: log.Printf,
		Token: func(ctx context.Context) ([]byte, error) {
			n++
			s, err := vc.Lease(ctx, vault.Request{Secret: secret, Connector: "tunnel", Host: "argotunnel.com", Task: "tunnel",
				Action: "start-" + itoa(n)})
			if err != nil {
				return nil, err
			}
			defer s.Wipe()
			return append([]byte(nil), s.Bytes()...), nil
		}}
	starter, err := cftunnel.LauncherFromEnv(func(raw []byte) {
		var r cftunnel.ProbeResult
		json.Unmarshal(raw, &r)
		sup.Record(cftunnel.Event{Kind: "probe", Detail: fmt.Sprintf("ok %v, %d checks", r.OK, len(r.Checks))})
		b, _ := json.Marshal(map[string]any{"at": time.Now().UTC(), "gatewayd": hs, "probe": json.RawMessage(raw)})
		tmp := cftunnel.ProbeFile + ".tmp"
		if os.WriteFile(tmp, b, 0o600) == nil {
			os.Rename(tmp, cftunnel.ProbeFile)
		}
		log.Printf("gatewayd: tunnel: confinement probe ok %v (%d checks)", r.OK, len(r.Checks))
	})
	if err != nil {
		log.Fatalf("gatewayd: tunnel: %v", err)
	}
	sup.Start = starter
	if err := os.MkdirAll(cftunnel.Dir, 0o750); err != nil {
		log.Fatalf("gatewayd: tunnel: %v", err)
	}
	l, err := gateway.Listen(cftunnel.SocketPath, 0o660)
	if err != nil {
		log.Fatalf("gatewayd: tunnel: %v", err)
	}
	if err := os.Chown(cftunnel.SocketPath, -1, tunnelUID); err != nil {
		log.Fatalf("gatewayd: tunnel: %v", err)
	}
	in := &cftunnel.Ingress{Agent: agentSock, Spike: spike, Sup: sup, Boot: boot, Diag: diag}
	go func() { log.Fatal((&http.Server{Handler: in, ReadHeaderTimeout: 30 * time.Second}).Serve(l)) }()
	log.Fatal(sup.Run(context.Background()))
}

// runConfined is the confined variant's gatewayd side: the ingress socket in the volume shared with the cftunnel
// container (group gid may connect), and the token published there once the vault has it.
func runConfined(vc *vault.Client, dir string, gid int, secret, agentSock string, spike bool) {
	boot := time.Now()
	lease := func(ctx context.Context) ([]byte, error) {
		s, err := vc.Lease(ctx, vault.Request{Secret: secret, Connector: "tunnel", Host: "argotunnel.com", Task: "tunnel", Action: "publish"})
		if err != nil {
			return nil, err
		}
		defer s.Wipe()
		return append([]byte(nil), s.Bytes()...), nil
	}
	sock := filepath.Join(dir, "ingress.sock")
	l, err := gateway.Listen(sock, 0o660)
	if err != nil {
		log.Fatalf("gatewayd: tunnel: %v", err)
	}
	if err := os.Chown(sock, -1, gid); err != nil {
		log.Fatalf("gatewayd: tunnel: %v", err)
	}
	in := &cftunnel.Ingress{Agent: agentSock, Spike: spike, Boot: boot}
	go func() { log.Fatal((&http.Server{Handler: in, ReadHeaderTimeout: 30 * time.Second}).Serve(l)) }()
	if err := cftunnel.PublishToken(context.Background(), dir, gid, lease, log.Printf); err != nil {
		log.Fatalf("gatewayd: tunnel: %v", err)
	}
}

func itoa(n int) string {
	b := []byte{}
	for n > 0 || len(b) == 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
