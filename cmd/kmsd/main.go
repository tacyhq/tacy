// kmsd is the Tacy key service (package kms/server; wire format package kms). It runs alone in an Intel TDX VM,
// from a compose that pins it by digest (cmd/compose --kms): no volumes but dstack's socket (for its own quotes),
// no environment, logging off, no swap. It keeps everything in memory and writes no file.
//
//	kmsd -admin-keys ed25519:…[,…] [-admin-threshold N] [-role primary|standby] [-kms-id ed25519:…] [-floor vX.Y.Z] [-peers URL,…]
//
// Without -kms-id it starts empty and takes one genesis (kmsctl genesis). With it, it starts locked and waits for
// the offline shares (kmsctl unlock) or a peer's M (-peers: it asks each in turn until one gives it). The primary
// (the default) holds the instance leases and the generation register; a standby only keeps M (package kms, "One
// primary"). The admin threshold defaults to 1 (one admin key to start); 2-of-n is supported and
// is the plan once there is a second admin key.
// Every setting is a flag in the attested compose; nothing comes from the environment.
package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/tacyhq/tacy/kms"
	"github.com/tacyhq/tacy/kms/client"
	"github.com/tacyhq/tacy/kms/server"
	"github.com/tacyhq/tacy/safety"
)

func main() {
	listen := flag.String("listen", ":8000", "address to serve the key service on")
	adminKeys := flag.String("admin-keys", "", "the offline admin keys (ed25519:<base64>, comma-separated)")
	adminThreshold := flag.Int("admin-threshold", 1, "admin signatures an admin document needs")
	kmsID := flag.String("kms-id", "", "the pinned KMS id (ed25519:<base64>): start locked; empty: start empty (genesis)")
	floor := flag.String("floor", "", "lowest release (vX.Y.Z) any policy may allow")
	sock := flag.String("dstack-socket", "/var/run/dstack.sock", "dstack guest agent socket (GetQuote, Info)")
	devLocal := flag.Bool("dev-local", false, "development only: no TDX (platform local) and accept local attestations")
	peers := flag.String("peers", "", "replica URLs to get M from while locked (comma-separated)")
	joinEvery := flag.Duration("join-every", 30*time.Second, "how often to ask the peers while locked")
	role := flag.String("role", kms.RolePrimary, "primary (leases and the generation register) or standby (keeps M only)")
	staging := flag.Bool("staging", false, "a staging key service for throwaways: a policy may let e2e overlays in (never production's)")
	flag.Parse()

	noCoreDumps()
	keys, err := safety.ParseKeys(*adminKeys)
	if err != nil || len(keys) == 0 {
		log.Fatalf("kmsd: -admin-keys: %v", errOr(err, "required"))
	}
	cfg := server.Config{Admin: kms.AdminKeys{Keys: keys, Threshold: *adminThreshold}, FloorMin: *floor, DevLocal: *devLocal,
		Role: *role, Logf: log.Printf, Staging: *staging}
	if *kmsID != "" {
		if cfg.KMSID, err = kms.ParseID(*kmsID); err != nil {
			log.Fatalf("kmsd: -kms-id: %v", err)
		}
	}
	if *devLocal {
		cfg.Platform = local{}
	} else {
		cfg.Platform = newDstack(*sock)
	}
	s, err := server.New(cfg)
	if err != nil {
		log.Fatal(err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	if *peers != "" && cfg.KMSID != nil {
		go joinLoop(ctx, s, strings.Split(*peers, ","), *joinEvery)
	}
	srv := &http.Server{Addr: *listen, Handler: s.Handler(), ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second,
		WriteTimeout: 60 * time.Second, IdleTimeout: 120 * time.Second, MaxHeaderBytes: 16 << 10,
		ErrorLog: log.New(io.Discard, "", 0)}
	go func() {
		<-ctx.Done()
		c, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(c)
	}()
	log.Printf("kmsd: %s, listening on %s", s.Status().State, *listen)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}

func errOr(err error, s string) string {
	if err != nil {
		return err.Error()
	}
	return s
}

// noCoreDumps: a crash never writes this process's memory (M) to a file.
func noCoreDumps() {
	if err := syscall.Setrlimit(syscall.RLIMIT_CORE, &syscall.Rlimit{Cur: 0, Max: 0}); err != nil {
		log.Printf("kmsd: core dump limit: %v", err)
	}
}

func joinLoop(ctx context.Context, s *server.Server, peers []string, every time.Duration) {
	for ctx.Err() == nil && s.Status().State == "locked" {
		for _, p := range peers {
			p = strings.TrimSpace(p)
			if p == "" || s.Status().State != "locked" {
				continue
			}
			c, cancel := context.WithTimeout(ctx, time.Minute)
			err := s.JoinFrom(c, client.HTTP{Base: p})
			cancel()
			if err == nil {
				log.Printf("kmsd: joined from %s", p)
				return
			}
		}
		select {
		case <-ctx.Done():
		case <-time.After(every):
		}
	}
}

// dstack is the guest agent over its unix socket: GetQuote with our 64-byte report_data, and Info (app-compose,
// instance id).
type dstack struct{ http *http.Client }

func newDstack(sock string) *dstack {
	return &dstack{http: &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", sock)
		},
	}}}
}

func (d *dstack) Name() string { return "dstack" }

func (d *dstack) call(ctx context.Context, method, path string, body any) (json.RawMessage, error) {
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, "http://dstack"+path, rd)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := d.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	b, err := io.ReadAll(io.LimitReader(res.Body, 4<<20))
	if err != nil {
		return nil, err
	}
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("dstack %s: %d", path, res.StatusCode)
	}
	return b, nil
}

func (d *dstack) Evidence(ctx context.Context, reportData []byte) (json.RawMessage, json.RawMessage, error) {
	if len(reportData) != 64 {
		return nil, nil, errors.New("report_data must be 64 bytes")
	}
	q, err := d.call(ctx, http.MethodPost, "/GetQuote", map[string]string{"report_data": hex.EncodeToString(reportData)})
	if err != nil {
		return nil, nil, err
	}
	info, err := d.call(ctx, http.MethodGet, "/Info", nil)
	if err != nil {
		return nil, nil, err
	}
	return q, info, nil
}

// local is development without TDX: no quote, and an info that says so.
type local struct{}

func (local) Name() string { return "local" }

func (local) Evidence(context.Context, []byte) (json.RawMessage, json.RawMessage, error) {
	host, _ := os.Hostname()
	return nil, server.LocalInfo("local-" + host), nil
}
